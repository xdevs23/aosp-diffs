```diff
diff --git a/Android.bp b/Android.bp
index ac85d76..8880675 100644
--- a/Android.bp
+++ b/Android.bp
@@ -25,10 +25,10 @@ java_library {
     srcs: ["java/**/*.java"],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
 
     libs: [
         "framework-annotations-lib",
-    ]
+    ],
 }
diff --git a/OWNERS b/OWNERS
index 0b3cfb7..90cc6f0 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
-pirozzoj@google.com
 johnshao@google.com
diff --git a/java/com/android/vcard/VCardComposer.java b/java/com/android/vcard/VCardComposer.java
index c243b3d..201cc34 100644
--- a/java/com/android/vcard/VCardComposer.java
+++ b/java/com/android/vcard/VCardComposer.java
@@ -139,6 +139,8 @@ public class VCardComposer {
     private boolean mFirstVCardEmittedInDoCoMoCase;
 
     private Cursor mCursor;
+    private EntityIterator mEntityIterator;
+    private Method mGetEntityIteratorMethod;
     private boolean mCursorSuppliedFromOutside;
     private int mIdColumn;
     private Uri mContentUriForRawContactsEntity;
@@ -366,9 +368,20 @@ public class VCardComposer {
         if (!initInterMainPart()) {
             return false;
         }
+        initEntityIterator();
+
         return initInterLastPart();
     }
 
+    /**
+     * Just for testing for now. Do not use.
+     * Execute before init.
+     * @hide
+     */
+    public void setGetEntityIteratorMethod(Method getEntityIteratorMethod) {
+        mGetEntityIteratorMethod = getEntityIteratorMethod;
+    }
+
     /**
      * Just for testing for now. Do not use.
      * @hide
@@ -395,6 +408,7 @@ public class VCardComposer {
         if (!initInterMainPart()) {
             return false;
         }
+        initEntityIterator();
         return initInterLastPart();
     }
 
@@ -440,6 +454,62 @@ public class VCardComposer {
         return mIdColumn >= 0;
     }
 
+    // Testing with 500 Contacts IDs, the export time using an EntityIterator containing all
+    // Contacts IDs is approximately 120ms (each EntityIterator containing one Contacts ID takes
+    // about 700ms).
+    // Initializing an EntityIterator with 500 Contacts IDs takes about 10ms.
+    private void initEntityIterator() {
+        StringBuilder selection = new StringBuilder();
+        StringBuilder contactIds = new StringBuilder();
+        Uri uri = mContentUriForRawContactsEntity;
+
+        if (mRawContactEntitlesInfoCallback != null) {
+            RawContactEntitlesInfo rawContactEntitlesInfo =
+                    mRawContactEntitlesInfoCallback.getRawContactEntitlesInfo(
+                            mCursor.getLong(mIdColumn));
+            uri = rawContactEntitlesInfo.rawContactEntitlesUri;
+            contactIds.append(rawContactEntitlesInfo.contactId);
+        } else {
+            do {
+                contactIds.append(mCursor.getString(mIdColumn));
+                if (!mCursor.isLast()) {
+                    contactIds.append(",");
+                } else {
+                    break;
+                }
+            } while (mCursor.moveToNext());
+            // There are some callers that assume that the cursor is at its first position after
+            // init.
+            // See b/402311014
+            mCursor.moveToFirst();
+        }
+
+        selection.append(Data.CONTACT_ID).append(" IN (");
+        selection.append(contactIds);
+        selection.append(")");
+
+        if (mGetEntityIteratorMethod != null) {
+            // Please note that this code is executed by unit tests only
+            try {
+                mEntityIterator = (EntityIterator) mGetEntityIteratorMethod.invoke(null,
+                        mContentResolver, uri, selection.toString(), null, null);
+            } catch (IllegalArgumentException e) {
+                Log.e(LOG_TAG, "IllegalArgumentException has been thrown: " +
+                        e.getMessage());
+            } catch (IllegalAccessException e) {
+                Log.e(LOG_TAG, "IllegalAccessException has been thrown: " +
+                        e.getMessage());
+            } catch (InvocationTargetException e) {
+                Log.e(LOG_TAG, "InvocationTargetException has been thrown: ", e);
+                throw new RuntimeException("InvocationTargetException has been thrown");
+            }
+        } else {
+            mEntityIterator = RawContacts
+                    .newEntityIterator(mContentResolver.query(uri, null,
+                            selection.toString(), null, Data.CONTACT_ID));
+        }
+    }
+
     private boolean initInterLastPart() {
         mInitDone = true;
         mTerminateCalled = false;
@@ -450,13 +520,11 @@ public class VCardComposer {
      * @return a vCard string.
      */
     public String createOneEntry() {
-        return createOneEntry(null);
-    }
+        if (!mInitDone) {
+            Log.w(LOG_TAG, "This object is not ready yet.");
+            return "";
+        }
 
-    /**
-     * @hide
-     */
-    public String createOneEntry(Method getEntityIteratorMethod) {
         if (mIsDoCoMo && !mFirstVCardEmittedInDoCoMoCase) {
             mFirstVCardEmittedInDoCoMoCase = true;
             // Previously we needed to emit empty data for this specific case, but actually
@@ -466,12 +534,7 @@ public class VCardComposer {
             // return createOneEntryInternal("-1", getEntityIteratorMethod);
         }
 
-        final String vcard = createOneEntryInternal(mCursor.getLong(mIdColumn),
-                getEntityIteratorMethod);
-        if (!mCursor.moveToNext()) {
-            Log.i(LOG_TAG, "Cursor#moveToNext() returned false");
-        }
-        return vcard;
+        return createOneEntryInternal();
     }
 
     /**
@@ -499,73 +562,24 @@ public class VCardComposer {
         RawContactEntitlesInfo getRawContactEntitlesInfo(long contactId);
     }
 
-    private String createOneEntryInternal(long contactId,
-            final Method getEntityIteratorMethod) {
+    private String createOneEntryInternal() {
+        if (!mEntityIterator.hasNext()) {
+            Log.w(LOG_TAG, "EntityIterator#hasNext() returned false");
+            return "";
+        }
         final Map<String, List<ContentValues>> contentValuesListMap =
                 new HashMap<String, List<ContentValues>>();
-        // The resolver may return the entity iterator with no data. It is possible.
-        // e.g. If all the data in the contact of the given contact id are not exportable ones,
-        //      they are hidden from the view of this method, though contact id itself exists.
-        EntityIterator entityIterator = null;
-        try {
-            Uri uri = mContentUriForRawContactsEntity;
-            if (mRawContactEntitlesInfoCallback != null) {
-                RawContactEntitlesInfo rawContactEntitlesInfo =
-                        mRawContactEntitlesInfoCallback.getRawContactEntitlesInfo(contactId);
-                uri = rawContactEntitlesInfo.rawContactEntitlesUri;
-                contactId = rawContactEntitlesInfo.contactId;
-            }
-            final String selection = Data.CONTACT_ID + "=?";
-            final String[] selectionArgs = new String[] {String.valueOf(contactId)};
-            if (getEntityIteratorMethod != null) {
-                // Please note that this branch is executed by unit tests only
-                try {
-                    entityIterator = (EntityIterator)getEntityIteratorMethod.invoke(null,
-                            mContentResolver, uri, selection, selectionArgs, null);
-                } catch (IllegalArgumentException e) {
-                    Log.e(LOG_TAG, "IllegalArgumentException has been thrown: " +
-                            e.getMessage());
-                } catch (IllegalAccessException e) {
-                    Log.e(LOG_TAG, "IllegalAccessException has been thrown: " +
-                            e.getMessage());
-                } catch (InvocationTargetException e) {
-                    Log.e(LOG_TAG, "InvocationTargetException has been thrown: ", e);
-                    throw new RuntimeException("InvocationTargetException has been thrown");
-                }
-            } else {
-                entityIterator = RawContacts.newEntityIterator(mContentResolver.query(
-                        uri, null, selection, selectionArgs, null));
-            }
-
-            if (entityIterator == null) {
-                Log.e(LOG_TAG, "EntityIterator is null");
-                return "";
-            }
-
-            if (!entityIterator.hasNext()) {
-                Log.w(LOG_TAG, "Data does not exist. contactId: " + contactId);
-                return "";
-            }
-
-            while (entityIterator.hasNext()) {
-                Entity entity = entityIterator.next();
-                for (NamedContentValues namedContentValues : entity.getSubValues()) {
-                    ContentValues contentValues = namedContentValues.values;
-                    String key = contentValues.getAsString(Data.MIMETYPE);
-                    if (key != null) {
-                        List<ContentValues> contentValuesList =
-                                contentValuesListMap.get(key);
-                        if (contentValuesList == null) {
-                            contentValuesList = new ArrayList<ContentValues>();
-                            contentValuesListMap.put(key, contentValuesList);
-                        }
-                        contentValuesList.add(contentValues);
-                    }
+        Entity entity = mEntityIterator.next();
+        for (NamedContentValues namedContentValues : entity.getSubValues()) {
+            ContentValues contentValues = namedContentValues.values;
+            String key = contentValues.getAsString(Data.MIMETYPE);
+            if (key != null) {
+                List<ContentValues> contentValuesList = contentValuesListMap.get(key);
+                if (contentValuesList == null) {
+                    contentValuesList = new ArrayList<ContentValues>();
+                    contentValuesListMap.put(key, contentValuesList);
                 }
-            }
-        } finally {
-            if (entityIterator != null) {
-                entityIterator.close();
+                contentValuesList.add(contentValues);
             }
         }
 
@@ -652,6 +666,14 @@ public class VCardComposer {
             }
             mCursor = null;
         }
+        if (mEntityIterator != null) {
+            try{
+                mEntityIterator.close();
+            } catch (SQLiteException e) {
+                Log.e(LOG_TAG, "SQLiteException on EntityIterator#close(): " + e.getMessage());
+            }
+            mEntityIterator = null;
+        }
     }
 
     @Override
@@ -683,11 +705,11 @@ public class VCardComposer {
      * when this object is not ready yet.
      */
     public boolean isAfterLast() {
-        if (mCursor == null) {
+        if (mEntityIterator == null) {
             Log.w(LOG_TAG, "This object is not ready yet.");
             return false;
         }
-        return mCursor.isAfterLast();
+        return !mEntityIterator.hasNext();
     }
 
     /**
diff --git a/java/com/android/vcard/VCardEntryCommitter.java b/java/com/android/vcard/VCardEntryCommitter.java
index 7f8e885..8c49da7 100644
--- a/java/com/android/vcard/VCardEntryCommitter.java
+++ b/java/com/android/vcard/VCardEntryCommitter.java
@@ -42,7 +42,8 @@ public class VCardEntryCommitter implements VCardEntryHandler {
 
     private final ContentResolver mContentResolver;
     private long mTimeToCommit;
-    private int mCounter;
+    // Set the default maximum batch size to 20
+    private int mMaxBatchSize = 20;
     private ArrayList<ContentProviderOperation> mOperationList;
     private final ArrayList<Uri> mCreatedUris = new ArrayList<Uri>();
 
@@ -65,14 +66,24 @@ public class VCardEntryCommitter implements VCardEntryHandler {
         }
     }
 
+    //because the max batch size is 500 defined in ContactsProvider,so we can enlarge this batch
+    //size to reduce db open/close times. From testing results, we can see performance better
+    //when batch size is more bigger.And also each vcardEntry may have some operation records.
+    //So we can set threshold as 450, batch operations will be executed when threshold reached.
+    //Testing result.
+    //batch size                  : 100    200    300    400    450    490    20
+    //consume time(10000 contacts): 178s   143s   127s   124s   119s   117s   195s
+    //consume time (1000 contacts): 17.3s  13.9s  12.6s  12.2s  11.8s  11.6s  19.8s
+    public void setMaxBatchSize(int batchSize) {
+        mMaxBatchSize = batchSize;
+    }
+
     @Override
     public void onEntryCreated(final VCardEntry vcardEntry) {
         final long start = System.currentTimeMillis();
         mOperationList = vcardEntry.constructInsertOperations(mContentResolver, mOperationList);
-        mCounter++;
-        if (mCounter >= 20) {
+        if (mOperationList != null && mOperationList.size() >= mMaxBatchSize) {
             mCreatedUris.add(pushIntoContentResolver(mOperationList));
-            mCounter = 0;
             mOperationList = null;
         }
         mTimeToCommit += System.currentTimeMillis() - start;
diff --git a/java/com/android/vcard/VCardParserImpl_V21.java b/java/com/android/vcard/VCardParserImpl_V21.java
index 07695a5..cb5c76a 100644
--- a/java/com/android/vcard/VCardParserImpl_V21.java
+++ b/java/com/android/vcard/VCardParserImpl_V21.java
@@ -305,7 +305,13 @@ import java.util.Set;
         mCurrentEncoding = DEFAULT_ENCODING;
 
         final String line = getNonEmptyLine();
-        final VCardProperty propertyData = constructPropertyData(line);
+        final VCardProperty propertyData;
+        try {
+            propertyData = constructPropertyData(line);
+        } catch (VCardInvalidLineException e) {
+            Log.w(LOG_TAG, "VCardInvalidLineException: ignoring", e);
+            return false;
+        }
 
         final String propertyNameUpper = propertyData.getName().toUpperCase();
         final String propertyRawValue = propertyData.getRawValue();
@@ -341,7 +347,7 @@ import java.util.Set;
             }
             handlePropertyValue(property, propertyNameUpper);
         } else {
-            throw new VCardException("Unknown property name: \"" + propertyNameUpper + "\"");
+            Log.w(LOG_TAG, "Unknown property name: \"" + propertyNameUpper + "\", ignoring");
         }
     }
 
diff --git a/tests/src/com/android/vcard/tests/testutils/ExportTestProvider.java b/tests/src/com/android/vcard/tests/testutils/ExportTestProvider.java
index edf02f1..0b2bc7f 100644
--- a/tests/src/com/android/vcard/tests/testutils/ExportTestProvider.java
+++ b/tests/src/com/android/vcard/tests/testutils/ExportTestProvider.java
@@ -42,14 +42,17 @@ public class ExportTestProvider extends MockContentProvider {
         private final List<Entity> mEntityList;
         private Iterator<Entity> mIterator;
 
-        public MockEntityIterator(List<ContentValues> contentValuesList) {
+        public MockEntityIterator() {
             mEntityList = new ArrayList<Entity>();
+            mIterator = mEntityList.iterator();
+        }
+
+        public void add(List<ContentValues> contentValuesList) {
             Entity entity = new Entity(new ContentValues());
             for (ContentValues contentValues : contentValuesList) {
-                    entity.addSubValue(Data.CONTENT_URI, contentValues);
+                entity.addSubValue(Data.CONTENT_URI, contentValues);
             }
             mEntityList.add(entity);
-            mIterator = mEntityList.iterator();
         }
 
         @Override
@@ -101,13 +104,16 @@ public class ExportTestProvider extends MockContentProvider {
         TestCase.assertTrue(ContentResolver.SCHEME_CONTENT.equals(uri.getScheme()));
         final String authority = uri.getAuthority();
         TestCase.assertTrue(RawContacts.CONTENT_URI.getAuthority().equals(authority));
-        TestCase.assertTrue((Data.CONTACT_ID + "=?").equals(selection));
-        TestCase.assertEquals(1, selectionArgs.length);
-        final int id = Integer.parseInt(selectionArgs[0]);
-        TestCase.assertTrue(id >= 0);
-        TestCase.assertTrue(id < mContactEntryList.size());
+        TestCase.assertTrue(selection != null);
+        TestCase.assertTrue((selection.contains(Data.CONTACT_ID + " IN ")));
+        TestCase.assertNull(selectionArgs);
 
-        return new MockEntityIterator(mContactEntryList.get(id).getList());
+        MockEntityIterator iterator = new MockEntityIterator();
+        for (ContactEntry contactEntry : mContactEntryList) {
+            iterator.add(contactEntry.getList());
+        }
+        iterator.reset();
+        return iterator;
     }
 
     @Override
@@ -135,7 +141,7 @@ public class ExportTestProvider extends MockContentProvider {
 
             @Override
             public boolean moveToNext() {
-                if (mCurrentPosition < mContactEntryList.size()) {
+                if (mCurrentPosition < mContactEntryList.size() - 1) {
                     mCurrentPosition++;
                     return true;
                 } else {
@@ -148,6 +154,11 @@ public class ExportTestProvider extends MockContentProvider {
                 return mCurrentPosition < 0;
             }
 
+            @Override
+            public boolean isLast() {
+                return mCurrentPosition == mContactEntryList.size() - 1;
+            }
+
             @Override
             public boolean isAfterLast() {
                 return mCurrentPosition >= mContactEntryList.size();
diff --git a/tests/src/com/android/vcard/tests/testutils/VCardVerifier.java b/tests/src/com/android/vcard/tests/testutils/VCardVerifier.java
index 7c40382..9c4f629 100644
--- a/tests/src/com/android/vcard/tests/testutils/VCardVerifier.java
+++ b/tests/src/com/android/vcard/tests/testutils/VCardVerifier.java
@@ -348,20 +348,21 @@ public class VCardVerifier {
         final VCardComposer composer = new VCardComposer(context, mVCardType, mCharset);
         // projection is ignored.
         final Cursor cursor = resolver.query(CONTACTS_TEST_CONTENT_URI, null, null, null, null);
+        Method mockGetEntityIteratorMethod = null;
+        try {
+            mockGetEntityIteratorMethod = getMockGetEntityIteratorMethod();
+        } catch (Exception e) {
+            AndroidTestCase.fail("Exception thrown: " + e);
+        }
+        AndroidTestCase.assertNotNull(mockGetEntityIteratorMethod);
+        composer.setGetEntityIteratorMethod(mockGetEntityIteratorMethod);
         if (!composer.init(cursor)) {
             AndroidTestCase.fail("init() failed. Reason: " + composer.getErrorReason());
         }
         AndroidTestCase.assertFalse(composer.isAfterLast());
         try {
             while (!composer.isAfterLast()) {
-                Method mockGetEntityIteratorMethod = null;
-                try {
-                    mockGetEntityIteratorMethod = getMockGetEntityIteratorMethod();
-                } catch (Exception e) {
-                    AndroidTestCase.fail("Exception thrown: " + e);
-                }
-                AndroidTestCase.assertNotNull(mockGetEntityIteratorMethod);
-                final String vcard = composer.createOneEntry(mockGetEntityIteratorMethod);
+                final String vcard = composer.createOneEntry();
                 AndroidTestCase.assertNotNull(vcard);
                 if (mLineVerifier != null) {
                     mLineVerifier.verify(vcard);
@@ -379,11 +380,6 @@ public class VCardVerifier {
         final VCardComposer composer = new VCardComposer(context, mVCardType, mCharset);
         // projection is ignored.
         final Cursor cursor = resolver.query(CONTACTS_TEST_CONTENT_URI, null, null, null, null);
-        if (!composer.init(cursor)) {
-            AndroidTestCase.fail("init() failed. Reason: " + composer.getErrorReason());
-        }
-        AndroidTestCase.assertFalse(composer.isAfterLast());
-
         Method mockGetEntityIteratorMethod = null;
         try {
             mockGetEntityIteratorMethod = getMockGetEntityIteratorMethod();
@@ -391,7 +387,12 @@ public class VCardVerifier {
             AndroidTestCase.fail("Exception thrown: " + e);
         }
         AndroidTestCase.assertNotNull(mockGetEntityIteratorMethod);
-        final String vcard = composer.createOneEntry(mockGetEntityIteratorMethod);
+        composer.setGetEntityIteratorMethod(mockGetEntityIteratorMethod);
+        if (!composer.init(cursor)) {
+            AndroidTestCase.fail("init() failed. Reason: " + composer.getErrorReason());
+        }
+        AndroidTestCase.assertFalse(composer.isAfterLast());
+        final String vcard = composer.createOneEntry();
         AndroidTestCase.assertNotNull(vcard);
         composer.terminate();
         return vcard;
```

