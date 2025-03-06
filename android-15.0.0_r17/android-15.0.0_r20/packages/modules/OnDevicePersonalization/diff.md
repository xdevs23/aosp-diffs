```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index e5f1877f..e33b85dc 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,2 +1,5 @@
+[Builtin Hooks]
+bpfmt = true
+
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
\ No newline at end of file
diff --git a/common/java/com/android/odp/module/common/EventLogger.java b/common/java/com/android/odp/module/common/EventLogger.java
new file mode 100644
index 00000000..5765cc11
--- /dev/null
+++ b/common/java/com/android/odp/module/common/EventLogger.java
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.odp.module.common;
+
+
+
+/** The helper interface to log events in statsd. */
+public interface EventLogger {
+
+    /** Logs encryption keys fetch fail training event kind. */
+    void logEncryptionKeyFetchFailEventKind();
+
+    /** Logs encryption keys fetch start training event kind. */
+    void logEncryptionKeyFetchStartEventKind();
+
+    /** Logs encryption keys fetch timeout training event kind. */
+    void logEncryptionKeyFetchTimeoutEventKind();
+
+    /** Logs encryption keys fetch empty URI training event kind. */
+    void logEncryptionKeyFetchEmptyUriEventKind();
+
+    /** Logs encryption keys fetch failed to create request training event kind. */
+    void logEncryptionKeyFetchRequestFailEventKind();
+
+    /** Logs encryption keys fetch failed to parse response training event kind. */
+    void logEncryptionKeyFetchInvalidPayloadEventKind();
+}
diff --git a/common/java/com/android/odp/module/common/FileUtils.java b/common/java/com/android/odp/module/common/FileUtils.java
index 9e9a8107..a280cd03 100644
--- a/common/java/com/android/odp/module/common/FileUtils.java
+++ b/common/java/com/android/odp/module/common/FileUtils.java
@@ -108,4 +108,6 @@ public class FileUtils {
         }
         return outputStream.toByteArray();
     }
+
+    private FileUtils() {}
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java b/common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java
similarity index 77%
rename from federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java
rename to common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java
index 7e6dec97..ec923b3e 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java
+++ b/common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
 import android.annotation.NonNull;
 
@@ -37,12 +37,12 @@ public class ODPAuthorizationToken {
     // CHECKSTYLE:OFF Generated code
     //
     // To regenerate run:
-    // $ codegen $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java
+    // $ codegen
+    // $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java
     //
     // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
     //   Settings > Editor > Code Style > Formatter Control
-    //@formatter:off
-
+    // @formatter:off
 
     @DataClass.Generated.Member
     /* package-private */ ODPAuthorizationToken(
@@ -51,17 +51,13 @@ public class ODPAuthorizationToken {
             @NonNull long creationTime,
             @NonNull long expiryTime) {
         this.mOwnerIdentifier = ownerIdentifier;
-        AnnotationValidations.validate(
-                NonNull.class, null, mOwnerIdentifier);
+        AnnotationValidations.validate(NonNull.class, null, mOwnerIdentifier);
         this.mAuthorizationToken = authorizationToken;
-        AnnotationValidations.validate(
-                NonNull.class, null, mAuthorizationToken);
+        AnnotationValidations.validate(NonNull.class, null, mAuthorizationToken);
         this.mCreationTime = creationTime;
-        AnnotationValidations.validate(
-                NonNull.class, null, mCreationTime);
+        AnnotationValidations.validate(NonNull.class, null, mCreationTime);
         this.mExpiryTime = expiryTime;
-        AnnotationValidations.validate(
-                NonNull.class, null, mExpiryTime);
+        AnnotationValidations.validate(NonNull.class, null, mExpiryTime);
 
         // onConstructed(); // You can define this method to get a callback
     }
@@ -121,6 +117,7 @@ public class ODPAuthorizationToken {
 
     /**
      * A builder for {@link ODPAuthorizationToken}
+     *
      * @hide
      */
     @SuppressWarnings("WeakerAccess")
@@ -142,17 +139,13 @@ public class ODPAuthorizationToken {
                 @NonNull long creationTime,
                 @NonNull long expiryTime) {
             mOwnerIdentifier = ownerIdentifier;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mOwnerIdentifier);
+            AnnotationValidations.validate(NonNull.class, null, mOwnerIdentifier);
             mAuthorizationToken = authorizationToken;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mAuthorizationToken);
+            AnnotationValidations.validate(NonNull.class, null, mAuthorizationToken);
             mCreationTime = creationTime;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mCreationTime);
+            AnnotationValidations.validate(NonNull.class, null, mCreationTime);
             mExpiryTime = expiryTime;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mExpiryTime);
+            AnnotationValidations.validate(NonNull.class, null, mExpiryTime);
         }
 
         @DataClass.Generated.Member
@@ -192,11 +185,9 @@ public class ODPAuthorizationToken {
             checkNotUsed();
             mBuilderFieldsSet |= 0x10; // Mark builder used
 
-            ODPAuthorizationToken o = new ODPAuthorizationToken(
-                    mOwnerIdentifier,
-                    mAuthorizationToken,
-                    mCreationTime,
-                    mExpiryTime);
+            ODPAuthorizationToken o =
+                    new ODPAuthorizationToken(
+                            mOwnerIdentifier, mAuthorizationToken, mCreationTime, mExpiryTime);
             return o;
         }
 
@@ -211,13 +202,21 @@ public class ODPAuthorizationToken {
     @DataClass.Generated(
             time = 1705438009708L,
             codegenVersion = "1.0.23",
-            sourceFile = "packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java",
-            inputSignatures = "private final @android.annotation.NonNull java.lang.String mOwnerIdentifier\nprivate final @android.annotation.NonNull java.lang.String mAuthorizationToken\nprivate final @android.annotation.NonNull long mCreationTime\nprivate final @android.annotation.NonNull long mExpiryTime\nclass ODPAuthorizationToken extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genHiddenBuilder=true, genEqualsHashCode=true)")
+            sourceFile =
+                    "packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationToken.java",
+            inputSignatures =
+                    "private final @android.annotation.NonNull java.lang.String mOwnerIdentifier\n"
+                        + "private final @android.annotation.NonNull java.lang.String"
+                        + " mAuthorizationToken\n"
+                        + "private final @android.annotation.NonNull long mCreationTime\n"
+                        + "private final @android.annotation.NonNull long mExpiryTime\n"
+                        + "class ODPAuthorizationToken extends java.lang.Object implements []\n"
+                        + "@com.android.ondevicepersonalization.internal.util.DataClass(genHiddenBuilder=true,"
+                        + " genEqualsHashCode=true)")
     @Deprecated
     private void __metadata() {}
 
-
-    //@formatter:on
+    // @formatter:on
     // End of generated code
 
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenContract.java b/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java
similarity index 67%
rename from federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenContract.java
rename to common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java
index 3c905bc4..bdb63a61 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenContract.java
+++ b/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java
@@ -14,10 +14,22 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
 public final class ODPAuthorizationTokenContract {
     public static final String ODP_AUTHORIZATION_TOKEN_TABLE = "odp_authorization_tokens";
+    public static final String CREATE_ODP_AUTHORIZATION_TOKEN_TABLE =
+            "CREATE TABLE "
+                    + ODP_AUTHORIZATION_TOKEN_TABLE
+                    + " ( "
+                    + ODPAuthorizationTokenColumns.OWNER_IDENTIFIER
+                    + " TEXT PRIMARY KEY, "
+                    + ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN
+                    + " TEXT NOT NULL, "
+                    + ODPAuthorizationTokenColumns.CREATION_TIME
+                    + " INTEGER NOT NULL, "
+                    + ODPAuthorizationTokenColumns.EXPIRY_TIME
+                    + " INTEGER NOT NULL)";
 
     private ODPAuthorizationTokenContract() {}
 
@@ -30,9 +42,7 @@ public final class ODPAuthorizationTokenContract {
          */
         public static final String OWNER_IDENTIFIER = "owner_identifier";
 
-        /**
-         * The authorization token received from the server.
-         */
+        /** The authorization token received from the server. */
         public static final String AUTHORIZATION_TOKEN = "authorization_token";
 
         /** Create time of the authorization token in the database in milliseconds. */
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDao.java b/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java
similarity index 73%
rename from federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDao.java
rename to common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java
index 963f843a..ad43ac2a 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDao.java
+++ b/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java
@@ -14,34 +14,33 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
-import static com.android.federatedcompute.services.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
+import static com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
 
 import android.annotation.NonNull;
 import android.content.ContentValues;
-import android.content.Context;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenContract.ODPAuthorizationTokenColumns;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODPAuthorizationTokenColumns;
 
 import com.google.common.annotations.VisibleForTesting;
 
 public class ODPAuthorizationTokenDao {
     private static final String TAG = ODPAuthorizationTokenDao.class.getSimpleName();
 
-    private final FederatedComputeDbHelper mDbHelper;
+    private final OdpSQLiteOpenHelper mDbHelper;
 
     private final Clock mClock;
 
     private static volatile ODPAuthorizationTokenDao sSingletonInstance;
 
-    private ODPAuthorizationTokenDao(FederatedComputeDbHelper dbHelper, Clock clock) {
+    private ODPAuthorizationTokenDao(OdpSQLiteOpenHelper dbHelper, Clock clock) {
         mDbHelper = dbHelper;
         mClock = clock;
     }
@@ -50,14 +49,12 @@ public class ODPAuthorizationTokenDao {
      * @return an instance of ODPAuthorizationTokenDao given a context
      */
     @NonNull
-    public static ODPAuthorizationTokenDao getInstance(Context context) {
+    public static ODPAuthorizationTokenDao getInstance(OdpSQLiteOpenHelper dbHelper) {
         if (sSingletonInstance == null) {
             synchronized (ODPAuthorizationTokenDao.class) {
                 if (sSingletonInstance == null) {
-                    sSingletonInstance = new ODPAuthorizationTokenDao(
-                            FederatedComputeDbHelper.getInstance(context),
-                            MonotonicClock.getInstance()
-                    );
+                    sSingletonInstance =
+                            new ODPAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
                 }
             }
         }
@@ -66,14 +63,12 @@ public class ODPAuthorizationTokenDao {
 
     /** Return a test instance with in-memory database. It is for test only. */
     @VisibleForTesting
-    public static ODPAuthorizationTokenDao getInstanceForTest(Context context) {
+    public static ODPAuthorizationTokenDao getInstanceForTest(OdpSQLiteOpenHelper dbHelper) {
         if (sSingletonInstance == null) {
             synchronized (ODPAuthorizationTokenDao.class) {
                 if (sSingletonInstance == null) {
-                    sSingletonInstance = new ODPAuthorizationTokenDao(
-                            FederatedComputeDbHelper.getInstanceForTest(context),
-                            MonotonicClock.getInstance()
-                    );
+                    sSingletonInstance =
+                            new ODPAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
                 }
             }
         }
@@ -88,15 +83,15 @@ public class ODPAuthorizationTokenDao {
         }
 
         ContentValues values = new ContentValues();
-        values.put(ODPAuthorizationTokenColumns.OWNER_IDENTIFIER,
+        values.put(
+                ODPAuthorizationTokenColumns.OWNER_IDENTIFIER,
                 authorizationToken.getOwnerIdentifier());
-        values.put(ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN,
+        values.put(
+                ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN,
                 authorizationToken.getAuthorizationToken());
-        values.put(ODPAuthorizationTokenColumns.CREATION_TIME,
-                authorizationToken.getCreationTime());
-        values.put(ODPAuthorizationTokenColumns.EXPIRY_TIME,
-                authorizationToken.getExpiryTime());
-
+        values.put(
+                ODPAuthorizationTokenColumns.CREATION_TIME, authorizationToken.getCreationTime());
+        values.put(ODPAuthorizationTokenColumns.EXPIRY_TIME, authorizationToken.getExpiryTime());
 
         long jobId =
                 db.insertWithOnConflict(
@@ -104,18 +99,28 @@ public class ODPAuthorizationTokenDao {
         return jobId != -1;
     }
 
-    /** Get an ODP adopter's unexpired authorization token.
-     * @return an unexpired authorization token. */
+    /**
+     * Get an ODP adopter's unexpired authorization token.
+     *
+     * @return an unexpired authorization token.
+     */
     public ODPAuthorizationToken getUnexpiredAuthorizationToken(String ownerIdentifier) {
-        String selection = ODPAuthorizationTokenColumns.EXPIRY_TIME + " > ? " + "AND "
-                + ODPAuthorizationTokenColumns.OWNER_IDENTIFIER + " = ?";
+        String selection =
+                ODPAuthorizationTokenColumns.EXPIRY_TIME
+                        + " > ? "
+                        + "AND "
+                        + ODPAuthorizationTokenColumns.OWNER_IDENTIFIER
+                        + " = ?";
         String[] selectionArgs = {String.valueOf(mClock.currentTimeMillis()), ownerIdentifier};
         String orderBy = ODPAuthorizationTokenColumns.EXPIRY_TIME + " DESC";
         return readTokenFromDatabase(selection, selectionArgs, orderBy);
     }
 
-    /** Delete an ODP adopter's authorization token.
-     * @return the number of rows deleted. */
+    /**
+     * Delete an ODP adopter's authorization token.
+     *
+     * @return the number of rows deleted.
+     */
     public int deleteAuthorizationToken(String ownerIdentifier) {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
@@ -124,28 +129,31 @@ public class ODPAuthorizationTokenDao {
         String whereClause = ODPAuthorizationTokenColumns.OWNER_IDENTIFIER + " = ?";
         String[] whereArgs = {ownerIdentifier};
         int deletedRows = db.delete(ODP_AUTHORIZATION_TOKEN_TABLE, whereClause, whereArgs);
-        LogUtil.d(TAG, "Deleted %d expired tokens for %s from database", deletedRows,
+        LogUtil.d(
+                TAG,
+                "Deleted %d expired tokens for %s from database",
+                deletedRows,
                 ownerIdentifier);
         return deletedRows;
     }
 
-
-    /** Batch delete all expired authorization tokens.
-     * @return the number of rows deleted. */
+    /**
+     * Batch delete all expired authorization tokens.
+     *
+     * @return the number of rows deleted.
+     */
     public int deleteExpiredAuthorizationTokens() {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
             throw new SQLiteException(TAG + ": Failed to open database.");
         }
         String whereClause = ODPAuthorizationTokenColumns.EXPIRY_TIME + " < ?";
-        String[] whereArgs = { String.valueOf(mClock.currentTimeMillis()) };
+        String[] whereArgs = {String.valueOf(mClock.currentTimeMillis())};
         int deletedRows = db.delete(ODP_AUTHORIZATION_TOKEN_TABLE, whereClause, whereArgs);
         LogUtil.d(TAG, "Deleted %d expired tokens", deletedRows);
         return deletedRows;
     }
 
-
-
     private ODPAuthorizationToken readTokenFromDatabase(
             String selection, String[] selectionArgs, String orderBy) {
         SQLiteDatabase db = mDbHelper.safeGetReadableDatabase();
@@ -154,10 +162,10 @@ public class ODPAuthorizationTokenDao {
         }
 
         String[] selectColumns = {
-                ODPAuthorizationTokenColumns.OWNER_IDENTIFIER,
-                ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN,
-                ODPAuthorizationTokenColumns.CREATION_TIME,
-                ODPAuthorizationTokenColumns.EXPIRY_TIME,
+            ODPAuthorizationTokenColumns.OWNER_IDENTIFIER,
+            ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN,
+            ODPAuthorizationTokenColumns.CREATION_TIME,
+            ODPAuthorizationTokenColumns.EXPIRY_TIME,
         };
 
         Cursor cursor = null;
@@ -187,8 +195,7 @@ public class ODPAuthorizationTokenDao {
                                                 ODPAuthorizationTokenColumns.CREATION_TIME)),
                                 cursor.getLong(
                                         cursor.getColumnIndexOrThrow(
-                                                ODPAuthorizationTokenColumns.EXPIRY_TIME))
-                        );
+                                                ODPAuthorizationTokenColumns.EXPIRY_TIME)));
                 authToken = encryptionKeyBuilder.build();
             }
         } finally {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDao.java b/common/java/com/android/odp/module/common/data/OdpEncryptionKeyDao.java
similarity index 51%
rename from federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDao.java
rename to common/java/com/android/odp/module/common/data/OdpEncryptionKeyDao.java
index 82cf9699..05c19642 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDao.java
+++ b/common/java/com/android/odp/module/common/data/OdpEncryptionKeyDao.java
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
+import static com.android.odp.module.common.encryption.OdpEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 
 import android.annotation.NonNull;
 import android.content.ContentValues;
@@ -26,60 +26,39 @@ import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.FederatedComputeEncryptionColumns;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyContract.OdpEncryptionColumns;
 
 import com.google.common.annotations.VisibleForTesting;
 
 import java.util.ArrayList;
 import java.util.List;
 
-/** DAO for accessing encryption key table that stores {@link FederatedComputeEncryptionKey}s. */
-public class FederatedComputeEncryptionKeyDao {
-    private static final String TAG = FederatedComputeEncryptionKeyDao.class.getSimpleName();
+/** DAO for accessing encryption key table that stores {@link OdpEncryptionKey}s. */
+public class OdpEncryptionKeyDao {
+    private static final String TAG = OdpEncryptionKeyDao.class.getSimpleName();
 
-    private final FederatedComputeDbHelper mDbHelper;
+    private final OdpSQLiteOpenHelper mDbHelper;
 
     private final Clock mClock;
 
-    private static volatile FederatedComputeEncryptionKeyDao sSingletonInstance;
+    private static volatile OdpEncryptionKeyDao sSingletonInstance;
 
-    private FederatedComputeEncryptionKeyDao(FederatedComputeDbHelper dbHelper, Clock clock) {
+    private OdpEncryptionKeyDao(OdpSQLiteOpenHelper dbHelper, Clock clock) {
         mDbHelper = dbHelper;
         mClock = clock;
     }
 
-    /** Returns an instance of {@link FederatedComputeEncryptionKeyDao} given a context. */
+    /** Returns an instance of {@link OdpEncryptionKeyDao} given a context. */
     @NonNull
-    public static FederatedComputeEncryptionKeyDao getInstance(Context context) {
+    public static OdpEncryptionKeyDao getInstance(Context context, OdpSQLiteOpenHelper dbHelper) {
         if (sSingletonInstance == null) {
-            synchronized (FederatedComputeEncryptionKeyDao.class) {
+            synchronized (OdpEncryptionKeyDao.class) {
                 if (sSingletonInstance == null) {
                     sSingletonInstance =
-                            new FederatedComputeEncryptionKeyDao(
-                                    FederatedComputeDbHelper.getInstance(context),
-                                    MonotonicClock.getInstance());
-                }
-            }
-        }
-        return sSingletonInstance;
-    }
-
-    /**
-     * Helper method to get instance of {@link FederatedComputeEncryptionKeyDao} for use in tests.
-     *
-     * <p>Public for use in unit tests.
-     */
-    @VisibleForTesting
-    public static FederatedComputeEncryptionKeyDao getInstanceForTest(Context context) {
-        if (sSingletonInstance == null) {
-            synchronized (FederatedComputeEncryptionKeyDao.class) {
-                if (sSingletonInstance == null) {
-                    FederatedComputeDbHelper dbHelper =
-                            FederatedComputeDbHelper.getInstanceForTest(context);
-                    Clock clk = MonotonicClock.getInstance();
-                    sSingletonInstance = new FederatedComputeEncryptionKeyDao(dbHelper, clk);
+                            new OdpEncryptionKeyDao(dbHelper, MonotonicClock.getInstance());
                 }
             }
         }
@@ -89,21 +68,21 @@ public class FederatedComputeEncryptionKeyDao {
     /**
      * Insert a key to the encryption_key table.
      *
-     * @param key the {@link FederatedComputeEncryptionKey} to insert into DB.
+     * @param key the {@link OdpEncryptionKey} to insert into DB.
      * @return Whether the key was inserted successfully.
      */
-    public boolean insertEncryptionKey(FederatedComputeEncryptionKey key) {
+    public boolean insertEncryptionKey(OdpEncryptionKey key) {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
             throw new SQLiteException(TAG + ": Failed to open database.");
         }
 
         ContentValues values = new ContentValues();
-        values.put(FederatedComputeEncryptionColumns.KEY_IDENTIFIER, key.getKeyIdentifier());
-        values.put(FederatedComputeEncryptionColumns.PUBLIC_KEY, key.getPublicKey());
-        values.put(FederatedComputeEncryptionColumns.KEY_TYPE, key.getKeyType());
-        values.put(FederatedComputeEncryptionColumns.CREATION_TIME, key.getCreationTime());
-        values.put(FederatedComputeEncryptionColumns.EXPIRY_TIME, key.getExpiryTime());
+        values.put(OdpEncryptionColumns.KEY_IDENTIFIER, key.getKeyIdentifier());
+        values.put(OdpEncryptionColumns.PUBLIC_KEY, key.getPublicKey());
+        values.put(OdpEncryptionColumns.KEY_TYPE, key.getKeyType());
+        values.put(OdpEncryptionColumns.CREATION_TIME, key.getCreationTime());
+        values.put(OdpEncryptionColumns.EXPIRY_TIME, key.getExpiryTime());
 
         long insertedRowId =
                 db.insertWithOnConflict(
@@ -114,23 +93,23 @@ public class FederatedComputeEncryptionKeyDao {
     /**
      * Read from encryption key table given selection, order and limit conditions.
      *
-     * @return a list of matching {@link FederatedComputeEncryptionKey}s.
+     * @return a list of matching {@link OdpEncryptionKey}s.
      */
     @VisibleForTesting
-    public List<FederatedComputeEncryptionKey> readFederatedComputeEncryptionKeysFromDatabase(
+    public List<OdpEncryptionKey> readEncryptionKeysFromDatabase(
             String selection, String[] selectionArgs, String orderBy, int count) {
-        List<FederatedComputeEncryptionKey> keyList = new ArrayList<>();
+        List<OdpEncryptionKey> keyList = new ArrayList<>();
         SQLiteDatabase db = mDbHelper.safeGetReadableDatabase();
         if (db == null) {
             throw new SQLiteException(TAG + ": Failed to open database.");
         }
 
         String[] selectColumns = {
-            FederatedComputeEncryptionColumns.KEY_IDENTIFIER,
-            FederatedComputeEncryptionColumns.PUBLIC_KEY,
-            FederatedComputeEncryptionColumns.KEY_TYPE,
-            FederatedComputeEncryptionColumns.CREATION_TIME,
-            FederatedComputeEncryptionColumns.EXPIRY_TIME
+            OdpEncryptionColumns.KEY_IDENTIFIER,
+            OdpEncryptionColumns.PUBLIC_KEY,
+            OdpEncryptionColumns.KEY_TYPE,
+            OdpEncryptionColumns.CREATION_TIME,
+            OdpEncryptionColumns.EXPIRY_TIME
         };
 
         Cursor cursor = null;
@@ -146,33 +125,28 @@ public class FederatedComputeEncryptionKeyDao {
                             /* orderBy= */ orderBy,
                             /* limit= */ String.valueOf(count));
             while (cursor.moveToNext()) {
-                FederatedComputeEncryptionKey.Builder encryptionKeyBuilder =
-                        new FederatedComputeEncryptionKey.Builder()
+                OdpEncryptionKey.Builder encryptionKeyBuilder =
+                        new OdpEncryptionKey.Builder()
                                 .setKeyIdentifier(
                                         cursor.getString(
                                                 cursor.getColumnIndexOrThrow(
-                                                        FederatedComputeEncryptionColumns
-                                                                .KEY_IDENTIFIER)))
+                                                        OdpEncryptionColumns.KEY_IDENTIFIER)))
                                 .setPublicKey(
                                         cursor.getString(
                                                 cursor.getColumnIndexOrThrow(
-                                                        FederatedComputeEncryptionColumns
-                                                                .PUBLIC_KEY)))
+                                                        OdpEncryptionColumns.PUBLIC_KEY)))
                                 .setKeyType(
                                         cursor.getInt(
                                                 cursor.getColumnIndexOrThrow(
-                                                        FederatedComputeEncryptionColumns
-                                                                .KEY_TYPE)))
+                                                        OdpEncryptionColumns.KEY_TYPE)))
                                 .setCreationTime(
                                         cursor.getLong(
                                                 cursor.getColumnIndexOrThrow(
-                                                        FederatedComputeEncryptionColumns
-                                                                .CREATION_TIME)))
+                                                        OdpEncryptionColumns.CREATION_TIME)))
                                 .setExpiryTime(
                                         cursor.getLong(
                                                 cursor.getColumnIndexOrThrow(
-                                                        FederatedComputeEncryptionColumns
-                                                                .EXPIRY_TIME)));
+                                                        OdpEncryptionColumns.EXPIRY_TIME)));
                 keyList.add(encryptionKeyBuilder.build());
             }
         } finally {
@@ -186,13 +160,12 @@ public class FederatedComputeEncryptionKeyDao {
     /**
      * @return latest expired keys (order by expiry time).
      */
-    public List<FederatedComputeEncryptionKey> getLatestExpiryNKeys(int count) {
-        String selection = FederatedComputeEncryptionColumns.EXPIRY_TIME + " > ?";
+    public List<OdpEncryptionKey> getLatestExpiryNKeys(int count) {
+        String selection = OdpEncryptionColumns.EXPIRY_TIME + " > ?";
         String[] selectionArgs = {String.valueOf(mClock.currentTimeMillis())};
         // reverse order of expiry time
-        String orderBy = FederatedComputeEncryptionColumns.EXPIRY_TIME + " DESC";
-        return readFederatedComputeEncryptionKeysFromDatabase(
-                selection, selectionArgs, orderBy, count);
+        String orderBy = OdpEncryptionColumns.EXPIRY_TIME + " DESC";
+        return readEncryptionKeysFromDatabase(selection, selectionArgs, orderBy, count);
     }
 
     /**
@@ -205,10 +178,23 @@ public class FederatedComputeEncryptionKeyDao {
         if (db == null) {
             throw new SQLiteException(TAG + ": Failed to open database.");
         }
-        String whereClause = FederatedComputeEncryptionColumns.EXPIRY_TIME + " < ?";
+        String whereClause = OdpEncryptionColumns.EXPIRY_TIME + " < ?";
         String[] whereArgs = {String.valueOf(mClock.currentTimeMillis())};
         int deletedRows = db.delete(ENCRYPTION_KEY_TABLE, whereClause, whereArgs);
         LogUtil.d(TAG, "Deleted %s expired keys from database", deletedRows);
         return deletedRows;
     }
+
+    /** Test only method to clear the database of all keys, independent of expiry time etc. */
+    @VisibleForTesting
+    public int deleteAllKeys() {
+        SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
+        if (db == null) {
+            throw new SQLiteException(TAG + ": Failed to open database.");
+        }
+        int deletedRows =
+                db.delete(ENCRYPTION_KEY_TABLE, /* whereClause= */ null, /* whereArgs= */ null);
+        LogUtil.d(TAG, "Force deleted %s keys from database", deletedRows);
+        return deletedRows;
+    }
 }
diff --git a/common/java/com/android/odp/module/common/data/OdpSQLiteOpenHelper.java b/common/java/com/android/odp/module/common/data/OdpSQLiteOpenHelper.java
new file mode 100644
index 00000000..e43e94e9
--- /dev/null
+++ b/common/java/com/android/odp/module/common/data/OdpSQLiteOpenHelper.java
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.odp.module.common.data;
+
+import android.annotation.Nullable;
+import android.content.Context;
+import android.database.sqlite.SQLiteDatabase;
+import android.database.sqlite.SQLiteOpenHelper;
+
+public abstract class OdpSQLiteOpenHelper extends SQLiteOpenHelper {
+
+    public OdpSQLiteOpenHelper(
+            @Nullable Context context,
+            @Nullable String name,
+            @Nullable SQLiteDatabase.CursorFactory factory,
+            int version) {
+        super(context, name, factory, version);
+    }
+
+    /**
+     * Wraps {@link SQLiteOpenHelper#getReadableDatabase()} to catch {@code SQLiteException} and log
+     * error.
+     */
+    @Nullable
+    public abstract SQLiteDatabase safeGetReadableDatabase();
+
+    /**
+     * Wraps {@link SQLiteOpenHelper#getReadableDatabase()} to catch {@code SQLiteException} and log
+     * error.
+     */
+    @Nullable
+    public abstract SQLiteDatabase safeGetWritableDatabase();
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/Encrypter.java b/common/java/com/android/odp/module/common/encryption/Encrypter.java
similarity index 90%
rename from federatedcompute/src/com/android/federatedcompute/services/encryption/Encrypter.java
rename to common/java/com/android/odp/module/common/encryption/Encrypter.java
index 3c4adaa8..8c01b049 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/Encrypter.java
+++ b/common/java/com/android/odp/module/common/encryption/Encrypter.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption;
+package com.android.odp.module.common.encryption;
 
 /** Interface for crypto libraries to encrypt data */
 public interface Encrypter {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/HpkeJniEncrypter.java b/common/java/com/android/odp/module/common/encryption/HpkeJniEncrypter.java
similarity index 74%
rename from federatedcompute/src/com/android/federatedcompute/services/encryption/HpkeJniEncrypter.java
rename to common/java/com/android/odp/module/common/encryption/HpkeJniEncrypter.java
index dd6040c1..54f34441 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/HpkeJniEncrypter.java
+++ b/common/java/com/android/odp/module/common/encryption/HpkeJniEncrypter.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,14 +14,11 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption;
+package com.android.odp.module.common.encryption;
 
-import com.android.federatedcompute.services.encryption.jni.HpkeJni;
+import com.android.odp.module.common.encryption.jni.HpkeJni;
 
-
-/**
- * The implementation of HPKE (Hybrid Public Key Encryption) using BoringSSL JNI.
- */
+/** The implementation of HPKE (Hybrid Public Key Encryption) using BoringSSL JNI. */
 public class HpkeJniEncrypter implements Encrypter {
 
     @Override
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKey.java
similarity index 68%
rename from federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java
rename to common/java/com/android/odp/module/common/encryption/OdpEncryptionKey.java
index 6d0d7b7f..f1e0de25 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java
+++ b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKey.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.encryption;
 
 import android.annotation.NonNull;
 
@@ -25,12 +25,11 @@ import java.io.Serializable;
 
 /** The details of a federated compute encryption key. */
 @DataClass(genHiddenBuilder = true, genEqualsHashCode = true)
-public class FederatedComputeEncryptionKey implements Serializable {
+public class OdpEncryptionKey implements Serializable {
 
-
-    /** Define the key type as enum.
-     * Currently keys are used to encrypt results only. Keys might be used to
-     * sign (and verify on server) in the future.
+    /**
+     * Define the key type as enum. Currently keys are used to encrypt results only. Keys might be
+     * used to sign (and verify on server) in the future.
      */
     public static final int KEY_TYPE_UNDEFINED = 0;
 
@@ -61,25 +60,22 @@ public class FederatedComputeEncryptionKey implements Serializable {
      */
     private final long mExpiryTime;
 
-
-
     // Code below generated by codegen v1.0.23.
     //
     // DO NOT MODIFY!
     // CHECKSTYLE:OFF Generated code
     //
     // To regenerate run:
-    // $ codegen $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java
+    // $ codegen
+    // $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java
     //
     // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
     //   Settings > Editor > Code Style > Formatter Control
-    //@formatter:off
+    // @formatter:off
 
-
-    @android.annotation.IntDef(prefix = "KEY_TYPE_", value = {
-        KEY_TYPE_UNDEFINED,
-        KEY_TYPE_ENCRYPTION
-    })
+    @android.annotation.IntDef(
+            prefix = "KEY_TYPE_",
+            value = {KEY_TYPE_UNDEFINED, KEY_TYPE_ENCRYPTION})
     @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.SOURCE)
     @DataClass.Generated.Member
     public @interface KeyType {}
@@ -88,34 +84,38 @@ public class FederatedComputeEncryptionKey implements Serializable {
     public static String keyTypeToString(@KeyType int value) {
         switch (value) {
             case KEY_TYPE_UNDEFINED:
-                    return "KEY_TYPE_UNDEFINED";
+                return "KEY_TYPE_UNDEFINED";
             case KEY_TYPE_ENCRYPTION:
-                    return "KEY_TYPE_ENCRYPTION";
-            default: return Integer.toHexString(value);
+                return "KEY_TYPE_ENCRYPTION";
+            default:
+                return Integer.toHexString(value);
         }
     }
 
     @DataClass.Generated.Member
-    /* package-private */ FederatedComputeEncryptionKey(
+    /* package-private */ OdpEncryptionKey(
             @NonNull String keyIdentifier,
             @NonNull String publicKey,
             @KeyType int keyType,
             long creationTime,
             long expiryTime) {
         this.mKeyIdentifier = keyIdentifier;
-        AnnotationValidations.validate(
-                NonNull.class, null, mKeyIdentifier);
+        AnnotationValidations.validate(NonNull.class, null, mKeyIdentifier);
         this.mPublicKey = publicKey;
-        AnnotationValidations.validate(
-                NonNull.class, null, mPublicKey);
+        AnnotationValidations.validate(NonNull.class, null, mPublicKey);
         this.mKeyType = keyType;
 
-        if (!(mKeyType == KEY_TYPE_UNDEFINED)
-                && !(mKeyType == KEY_TYPE_ENCRYPTION)) {
+        if (!(mKeyType == KEY_TYPE_UNDEFINED) && !(mKeyType == KEY_TYPE_ENCRYPTION)) {
             throw new java.lang.IllegalArgumentException(
-                    "keyType was " + mKeyType + " but must be one of: "
-                            + "KEY_TYPE_UNDEFINED(" + KEY_TYPE_UNDEFINED + "), "
-                            + "KEY_TYPE_ENCRYPTION(" + KEY_TYPE_ENCRYPTION + ")");
+                    "keyType was "
+                            + mKeyType
+                            + " but must be one of: "
+                            + "KEY_TYPE_UNDEFINED("
+                            + KEY_TYPE_UNDEFINED
+                            + "), "
+                            + "KEY_TYPE_ENCRYPTION("
+                            + KEY_TYPE_ENCRYPTION
+                            + ")");
         }
 
         this.mCreationTime = creationTime;
@@ -174,7 +174,7 @@ public class FederatedComputeEncryptionKey implements Serializable {
         if (this == o) return true;
         if (o == null || getClass() != o.getClass()) return false;
         @SuppressWarnings("unchecked")
-        FederatedComputeEncryptionKey that = (FederatedComputeEncryptionKey) o;
+        OdpEncryptionKey that = (OdpEncryptionKey) o;
         //noinspection PointlessBooleanExpression
         return true
                 && java.util.Objects.equals(mKeyIdentifier, that.mKeyIdentifier)
@@ -200,7 +200,8 @@ public class FederatedComputeEncryptionKey implements Serializable {
     }
 
     /**
-     * A builder for {@link FederatedComputeEncryptionKey}
+     * A builder for {@link OdpEncryptionKey}
+     *
      * @hide
      */
     @SuppressWarnings("WeakerAccess")
@@ -217,10 +218,7 @@ public class FederatedComputeEncryptionKey implements Serializable {
 
         public Builder() {}
 
-        /**
-         * Creates a new Builder.
-         *
-         */
+        /** Creates a new Builder. */
         public Builder(
                 @NonNull String keyIdentifier,
                 @NonNull String publicKey,
@@ -228,19 +226,22 @@ public class FederatedComputeEncryptionKey implements Serializable {
                 long creationTime,
                 long expiryTime) {
             mKeyIdentifier = keyIdentifier;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mKeyIdentifier);
+            AnnotationValidations.validate(NonNull.class, null, mKeyIdentifier);
             mPublicKey = publicKey;
-            AnnotationValidations.validate(
-                    NonNull.class, null, mPublicKey);
+            AnnotationValidations.validate(NonNull.class, null, mPublicKey);
             mKeyType = keyType;
 
-            if (!(mKeyType == KEY_TYPE_UNDEFINED)
-                    && !(mKeyType == KEY_TYPE_ENCRYPTION)) {
+            if (!(mKeyType == KEY_TYPE_UNDEFINED) && !(mKeyType == KEY_TYPE_ENCRYPTION)) {
                 throw new java.lang.IllegalArgumentException(
-                        "keyType was " + mKeyType + " but must be one of: "
-                                + "KEY_TYPE_UNDEFINED(" + KEY_TYPE_UNDEFINED + "), "
-                                + "KEY_TYPE_ENCRYPTION(" + KEY_TYPE_ENCRYPTION + ")");
+                        "keyType was "
+                                + mKeyType
+                                + " but must be one of: "
+                                + "KEY_TYPE_UNDEFINED("
+                                + KEY_TYPE_UNDEFINED
+                                + "), "
+                                + "KEY_TYPE_ENCRYPTION("
+                                + KEY_TYPE_ENCRYPTION
+                                + ")");
             }
 
             mCreationTime = creationTime;
@@ -303,16 +304,13 @@ public class FederatedComputeEncryptionKey implements Serializable {
         }
 
         /** Builds the instance. This builder should not be touched after calling this! */
-        public @NonNull FederatedComputeEncryptionKey build() {
+        public @NonNull OdpEncryptionKey build() {
             checkNotUsed();
             mBuilderFieldsSet |= 0x20; // Mark builder used
 
-            FederatedComputeEncryptionKey o = new FederatedComputeEncryptionKey(
-                    mKeyIdentifier,
-                    mPublicKey,
-                    mKeyType,
-                    mCreationTime,
-                    mExpiryTime);
+            OdpEncryptionKey o =
+                    new OdpEncryptionKey(
+                            mKeyIdentifier, mPublicKey, mKeyType, mCreationTime, mExpiryTime);
             return o;
         }
 
@@ -327,13 +325,27 @@ public class FederatedComputeEncryptionKey implements Serializable {
     @DataClass.Generated(
             time = 1698371312320L,
             codegenVersion = "1.0.23",
-            sourceFile = "packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java",
-            inputSignatures = "public static final  int KEY_TYPE_UNDEFINED\npublic static final  int KEY_TYPE_ENCRYPTION\nprivate final @android.annotation.NonNull java.lang.String mKeyIdentifier\nprivate final @android.annotation.NonNull java.lang.String mPublicKey\nprivate final @com.android.federatedcompute.services.data.FederatedComputeEncryptionKey.KeyType int mKeyType\nprivate final  long mCreationTime\nprivate final  long mExpiryTime\nclass FederatedComputeEncryptionKey extends java.lang.Object implements [java.io.Serializable]\n@com.android.ondevicepersonalization.internal.util.DataClass(genHiddenBuilder=true, genEqualsHashCode=true)")
+            sourceFile =
+                    "packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKey.java",
+            inputSignatures =
+                    "public static final  int KEY_TYPE_UNDEFINED\n"
+                        + "public static final  int KEY_TYPE_ENCRYPTION\n"
+                        + "private final @android.annotation.NonNull java.lang.String"
+                        + " mKeyIdentifier\n"
+                        + "private final @android.annotation.NonNull java.lang.String mPublicKey\n"
+                        + "private final"
+                        + " @com.android.odp.module.common.encryption.FederatedComputeEncryptionKey.KeyType"
+                        + " int mKeyType\n"
+                        + "private final  long mCreationTime\n"
+                        + "private final  long mExpiryTime\n"
+                        + "class FederatedComputeEncryptionKey extends java.lang.Object implements"
+                        + " [java.io.Serializable]\n"
+                        + "@com.android.ondevicepersonalization.internal.util.DataClass(genHiddenBuilder=true,"
+                        + " genEqualsHashCode=true)")
     @Deprecated
     private void __metadata() {}
 
-
-    //@formatter:on
+    // @formatter:on
     // End of generated code
 
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyContract.java b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyContract.java
similarity index 51%
rename from federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyContract.java
rename to common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyContract.java
index 81148ec2..e66ca430 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyContract.java
+++ b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyContract.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,18 +14,32 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.encryption;
 
-public final class FederatedComputeEncryptionKeyContract {
+public final class OdpEncryptionKeyContract {
     public static final String ENCRYPTION_KEY_TABLE = "encryption_keys";
-
-    private FederatedComputeEncryptionKeyContract() {}
-
-    static final class FederatedComputeEncryptionColumns {
-        private FederatedComputeEncryptionColumns() {}
+    public static final String CREATE_ENCRYPTION_KEY_TABLE =
+            "CREATE TABLE "
+                    + ENCRYPTION_KEY_TABLE
+                    + " ( "
+                    + OdpEncryptionColumns.KEY_IDENTIFIER
+                    + " TEXT PRIMARY KEY, "
+                    + OdpEncryptionColumns.PUBLIC_KEY
+                    + " TEXT NOT NULL, "
+                    + OdpEncryptionColumns.KEY_TYPE
+                    + " INTEGER, "
+                    + OdpEncryptionColumns.CREATION_TIME
+                    + " INTEGER NOT NULL, "
+                    + OdpEncryptionColumns.EXPIRY_TIME
+                    + " INTEGER NOT NULL)";
+
+    private OdpEncryptionKeyContract() {}
+
+    public static final class OdpEncryptionColumns {
+        private OdpEncryptionColumns() {}
 
         /**
-         * A unique identifier of the key, in thd form of UUID. FCP server uses key_identifier to
+         * A unique identifier of the key, in the form of a UUID. FCP server uses key_identifier to
          * get private key.
          */
         public static final String KEY_IDENTIFIER = "key_identifier";
@@ -34,8 +48,8 @@ public final class FederatedComputeEncryptionKeyContract {
         public static final String PUBLIC_KEY = "public_key";
 
         /**
-         * The type of the key in @link {com.android.federatedcompute.services.data.fbs.KeyType}
-         * Currently only encryption key is allowed.
+         * The type of the key in {@link OdpEncryptionKey.KeyType}. Currently only encryption key is
+         * allowed.
          */
         public static final String KEY_TYPE = "key_type";
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManager.java b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
similarity index 56%
rename from federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManager.java
rename to common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
index af728d9e..c488fc53 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManager.java
+++ b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
@@ -14,28 +14,27 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption;
+package com.android.odp.module.common.encryption;
 
+import android.annotation.Nullable;
 import android.content.Context;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.common.FederatedComputeExecutors;
-import com.android.federatedcompute.services.common.Flags;
-import com.android.federatedcompute.services.common.FlagsFactory;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyDao;
-import com.android.federatedcompute.services.http.HttpClientUtil;
 import com.android.odp.module.common.Clock;
-import com.android.odp.module.common.HttpClient;
-import com.android.odp.module.common.HttpClientUtils;
+import com.android.odp.module.common.EventLogger;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.OdpHttpRequest;
-import com.android.odp.module.common.OdpHttpResponse;
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
+import com.android.odp.module.common.http.OdpHttpResponse;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.collect.ImmutableList;
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListeningExecutorService;
 
 import org.json.JSONArray;
 import org.json.JSONException;
@@ -46,13 +45,37 @@ import java.util.List;
 import java.util.Locale;
 import java.util.Map;
 import java.util.Objects;
-import java.util.concurrent.ExecutorService;
+import java.util.Optional;
+import java.util.Random;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
 
 /** Class to manage key fetch. */
-public class FederatedComputeEncryptionKeyManager {
-    private static final String TAG = "FederatedComputeEncryptionKeyManager";
+public class OdpEncryptionKeyManager {
+    private static final String TAG = OdpEncryptionKeyManager.class.getSimpleName();
+
+    // Helper class to allow injection of flags from either ODP or FCP code.
+    public interface KeyManagerConfig {
+
+        /** Url from which to get encryption keys. */
+        String getEncryptionKeyFetchUrl();
+
+        /** Retry limit for encryption key http requests. */
+        int getHttpRequestRetryLimit();
+
+        /** Max age in seconds for federated compute encryption keys. */
+        long getEncryptionKeyMaxAgeSeconds();
+
+        /** The {@link OdpSQLiteOpenHelper} instance for use by the encryption DAO. */
+        OdpSQLiteOpenHelper getSQLiteOpenHelper();
+
+        /** Background executor for use in key fetch and DB updates etc. */
+        ListeningExecutorService getBackgroundExecutor();
+
+        /** Blocking executor for use in http connection. */
+        ListeningExecutorService getBlockingExecutor();
+
+    }
 
     private interface EncryptionKeyResponseContract {
         String RESPONSE_HEADER_CACHE_CONTROL_LABEL = "cache-control";
@@ -67,67 +90,82 @@ public class FederatedComputeEncryptionKeyManager {
         String RESPONSE_PUBLIC_KEY = "key";
     }
 
-    @VisibleForTesting private final FederatedComputeEncryptionKeyDao mEncryptionKeyDao;
+    private final OdpEncryptionKeyDao mEncryptionKeyDao;
 
-    private static volatile FederatedComputeEncryptionKeyManager sBackgroundKeyManager;
+    private static volatile OdpEncryptionKeyManager sBackgroundKeyManager;
 
     private final Clock mClock;
 
-    private final Flags mFlags;
+    private final KeyManagerConfig mKeyManagerConfig;
 
     private final HttpClient mHttpClient;
 
-    private final ExecutorService mBackgroundExecutor;
+    private final ListeningExecutorService mBackgroundExecutor;
 
-    public FederatedComputeEncryptionKeyManager(
+    private OdpEncryptionKeyManager(
             Clock clock,
-            FederatedComputeEncryptionKeyDao encryptionKeyDao,
-            Flags flags,
+            OdpEncryptionKeyDao encryptionKeyDao,
+            KeyManagerConfig keyManagerConfig,
             HttpClient httpClient,
-            ExecutorService backgroundExecutor) {
+            ListeningExecutorService backgroundExecutor) {
         mClock = clock;
         mEncryptionKeyDao = encryptionKeyDao;
-        mFlags = flags;
+        mKeyManagerConfig = keyManagerConfig;
         mHttpClient = httpClient;
         mBackgroundExecutor = backgroundExecutor;
     }
 
-    /** Returns a singleton instance for the {@link FederatedComputeEncryptionKeyManager}. */
-    public static FederatedComputeEncryptionKeyManager getInstance(Context context) {
+    @VisibleForTesting
+    static synchronized void resetForTesting() {
+        sBackgroundKeyManager = null;
+    }
+
+    /**
+     * Test only getter that allows injection of test/mock versions of clock, DAO etc.
+     *
+     * <p>Should be used in conjunction with {@link #resetForTesting()}
+     */
+    @VisibleForTesting
+    public static OdpEncryptionKeyManager getInstanceForTesting(
+            Clock clock,
+            OdpEncryptionKeyDao encryptionKeyDao,
+            KeyManagerConfig keyManagerConfig,
+            HttpClient httpClient,
+            ListeningExecutorService backgroundExecutor) {
         if (sBackgroundKeyManager == null) {
-            synchronized (FederatedComputeEncryptionKeyManager.class) {
+            synchronized (OdpEncryptionKeyManager.class) {
                 if (sBackgroundKeyManager == null) {
-                    FederatedComputeEncryptionKeyDao encryptionKeyDao =
-                            FederatedComputeEncryptionKeyDao.getInstance(context);
                     sBackgroundKeyManager =
-                            new FederatedComputeEncryptionKeyManager(
-                                    MonotonicClock.getInstance(),
+                            new OdpEncryptionKeyManager(
+                                    clock,
                                     encryptionKeyDao,
-                                    FlagsFactory.getFlags(),
-                                    new HttpClient(
-                                            FlagsFactory.getFlags().getHttpRequestRetryLimit(),
-                                            FederatedComputeExecutors.getBlockingExecutor()),
-                                    FederatedComputeExecutors.getBackgroundExecutor());
+                                    keyManagerConfig,
+                                    httpClient,
+                                    backgroundExecutor);
                 }
             }
         }
         return sBackgroundKeyManager;
     }
 
-    /** For testing only, returns an instance of key manager for test. */
-    @VisibleForTesting
-    static FederatedComputeEncryptionKeyManager getInstanceForTest(
-            Clock clock,
-            FederatedComputeEncryptionKeyDao encryptionKeyDao,
-            Flags flags,
-            HttpClient client,
-            ExecutorService executor) {
+    /** Returns a singleton instance for the {@link OdpEncryptionKeyManager}. */
+    public static OdpEncryptionKeyManager getInstance(
+            Context context, KeyManagerConfig keyManagerConfig) {
         if (sBackgroundKeyManager == null) {
-            synchronized (FederatedComputeEncryptionKeyManager.class) {
+            synchronized (OdpEncryptionKeyManager.class) {
                 if (sBackgroundKeyManager == null) {
+                    OdpEncryptionKeyDao encryptionKeyDao =
+                            OdpEncryptionKeyDao.getInstance(
+                                    context, keyManagerConfig.getSQLiteOpenHelper());
                     sBackgroundKeyManager =
-                            new FederatedComputeEncryptionKeyManager(
-                                    clock, encryptionKeyDao, flags, client, executor);
+                            new OdpEncryptionKeyManager(
+                                    MonotonicClock.getInstance(),
+                                    encryptionKeyDao,
+                                    keyManagerConfig,
+                                    new HttpClient(
+                                            keyManagerConfig.getHttpRequestRetryLimit(),
+                                            keyManagerConfig.getBlockingExecutor()),
+                                    keyManagerConfig.getBackgroundExecutor());
                 }
             }
         }
@@ -138,12 +176,16 @@ public class FederatedComputeEncryptionKeyManager {
      * Fetch the active key from the server, persists the fetched key to encryption_key table, and
      * deletes expired keys
      */
-    FluentFuture<List<FederatedComputeEncryptionKey>> fetchAndPersistActiveKeys(
-            @FederatedComputeEncryptionKey.KeyType int keyType, boolean isScheduledJob) {
-        String fetchUri = mFlags.getEncryptionKeyFetchUrl();
+    public FluentFuture<List<OdpEncryptionKey>> fetchAndPersistActiveKeys(
+            @OdpEncryptionKey.KeyType int keyType, boolean isScheduledJob,
+            Optional<EventLogger> loggerOptional) {
+        String fetchUri = mKeyManagerConfig.getEncryptionKeyFetchUrl();
         if (fetchUri == null) {
-            return FluentFuture.from(Futures.immediateFailedFuture(
-                    new IllegalArgumentException("Url to fetch active encryption keys is null")));
+            loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchEmptyUriEventKind);
+            return FluentFuture.from(
+                    Futures.immediateFailedFuture(
+                            new IllegalArgumentException(
+                                    "Url to fetch active encryption keys is null")));
         }
 
         OdpHttpRequest request;
@@ -153,8 +195,9 @@ public class FederatedComputeEncryptionKeyManager {
                             fetchUri,
                             HttpClientUtils.HttpMethod.GET,
                             new HashMap<>(),
-                            HttpClientUtil.EMPTY_BODY);
+                            HttpClientUtils.EMPTY_BODY);
         } catch (Exception e) {
+            loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchRequestFailEventKind);
             return FluentFuture.from(Futures.immediateFailedFuture(e));
         }
 
@@ -162,7 +205,10 @@ public class FederatedComputeEncryptionKeyManager {
                 .transform(
                         response ->
                                 parseFetchEncryptionKeyPayload(
-                                        response, keyType, mClock.currentTimeMillis()),
+                                        response,
+                                        keyType,
+                                        mClock.currentTimeMillis(),
+                                        loggerOptional),
                         mBackgroundExecutor)
                 .transform(
                         result -> {
@@ -177,28 +223,28 @@ public class FederatedComputeEncryptionKeyManager {
                         mBackgroundExecutor); // TODO: Add timeout controlled by Ph flags
     }
 
-    private ImmutableList<FederatedComputeEncryptionKey> parseFetchEncryptionKeyPayload(
+    private ImmutableList<OdpEncryptionKey> parseFetchEncryptionKeyPayload(
             OdpHttpResponse keyFetchResponse,
-            @FederatedComputeEncryptionKey.KeyType int keyType,
-            Long fetchTime) {
+            @OdpEncryptionKey.KeyType int keyType,
+            Long fetchTime,
+            Optional<EventLogger> loggerOptional) {
         String payload = new String(Objects.requireNonNull(keyFetchResponse.getPayload()));
         Map<String, List<String>> headers = keyFetchResponse.getHeaders();
         long ttlInSeconds = getTTL(headers);
         if (ttlInSeconds <= 0) {
-            ttlInSeconds = mFlags.getFederatedComputeEncryptionKeyMaxAgeSeconds();
+            ttlInSeconds = mKeyManagerConfig.getEncryptionKeyMaxAgeSeconds();
         }
 
         try {
             JSONObject responseObj = new JSONObject(payload);
             JSONArray keysArr =
                     responseObj.getJSONArray(EncryptionKeyResponseContract.RESPONSE_KEYS_LABEL);
-            ImmutableList.Builder<FederatedComputeEncryptionKey> encryptionKeys =
-                    ImmutableList.builder();
+            ImmutableList.Builder<OdpEncryptionKey> encryptionKeys = ImmutableList.builder();
 
             for (int i = 0; i < keysArr.length(); i++) {
                 JSONObject keyObj = keysArr.getJSONObject(i);
-                FederatedComputeEncryptionKey key =
-                        new FederatedComputeEncryptionKey.Builder()
+                OdpEncryptionKey key =
+                        new OdpEncryptionKey.Builder()
                                 .setKeyIdentifier(
                                         keyObj.getString(
                                                 EncryptionKeyResponseContract
@@ -215,6 +261,7 @@ public class FederatedComputeEncryptionKeyManager {
             }
             return encryptionKeys.build();
         } catch (JSONException e) {
+            loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchInvalidPayloadEventKind);
             LogUtil.e(TAG, "Invalid Json response: " + e.getMessage());
             return ImmutableList.of();
         }
@@ -289,6 +336,17 @@ public class FederatedComputeEncryptionKeyManager {
         return maxAge - cachedAge;
     }
 
+    /**
+     * Helper method that returns one key at random from provided list of active {@link
+     * OdpEncryptionKey}s.
+     */
+    @Nullable
+    public static OdpEncryptionKey getRandomKey(List<OdpEncryptionKey> activeKeys) {
+        return activeKeys.isEmpty()
+                ? null
+                : activeKeys.get(new Random().nextInt(activeKeys.size()));
+    }
+
     /**
      * Get active keys, if there is no active key, then force a fetch from the key service. In the
      * case of key fetching from the key service, the http call is executed on a {@code
@@ -296,26 +354,39 @@ public class FederatedComputeEncryptionKeyManager {
      *
      * @return The list of active keys.
      */
-    public List<FederatedComputeEncryptionKey> getOrFetchActiveKeys(int keyType, int keyCount) {
-        List<FederatedComputeEncryptionKey> activeKeys = mEncryptionKeyDao
-                .getLatestExpiryNKeys(keyCount);
+    public List<OdpEncryptionKey> getOrFetchActiveKeys(int keyType, int keyCount,
+            Optional<EventLogger> loggerOptional) {
+        List<OdpEncryptionKey> activeKeys = mEncryptionKeyDao.getLatestExpiryNKeys(keyCount);
         if (activeKeys.size() > 0) {
+            LogUtil.d(TAG, "Existing active keys present, number of keys : " + activeKeys.size());
             return activeKeys;
         }
+
+        loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchStartEventKind);
+        LogUtil.d(TAG, "No existing active keys present, fetching new encryption keys.");
         try {
-            var fetchedKeysUnused = fetchAndPersistActiveKeys(keyType,
-                    /* isScheduledJob= */ false).get(/* timeout= */ 5, TimeUnit.SECONDS);
+            var fetchedKeysUnused =
+                    fetchAndPersistActiveKeys(keyType, /* isScheduledJob= */ false, loggerOptional)
+                            .get(/* timeout= */ 5, TimeUnit.SECONDS);
             activeKeys = mEncryptionKeyDao.getLatestExpiryNKeys(keyCount);
             if (activeKeys.size() > 0) {
                 return activeKeys;
             }
         } catch (TimeoutException e) {
-            LogUtil.e(TAG, "Time out when forcing encryption key fetch: "
-                    + e.getMessage());
+            LogUtil.d(TAG, "Time out when forcing encryption key fetch: " + e.getMessage());
+            loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchTimeoutEventKind);
         } catch (Exception e) {
-            LogUtil.e(TAG, "Exception encountered when forcing encryption key fetch: "
-                    + e.getMessage());
+            LogUtil.d(
+                    TAG,
+                    "Exception encountered when forcing encryption key fetch: " + e.getMessage());
+            loggerOptional.ifPresent(EventLogger::logEncryptionKeyFetchFailEventKind);
         }
         return activeKeys;
     }
+
+    /** Helper method to allow testing of injected {@link KeyManagerConfig}. */
+    @VisibleForTesting
+    public KeyManagerConfig getKeyManagerConfigForTesting() {
+        return mKeyManagerConfig;
+    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/jni/HpkeJni.java b/common/java/com/android/odp/module/common/encryption/jni/HpkeJni.java
similarity index 94%
rename from federatedcompute/src/com/android/federatedcompute/services/encryption/jni/HpkeJni.java
rename to common/java/com/android/odp/module/common/encryption/jni/HpkeJni.java
index b8becb69..5dddc4f1 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/jni/HpkeJni.java
+++ b/common/java/com/android/odp/module/common/encryption/jni/HpkeJni.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption.jni;
+package com.android.odp.module.common.encryption.jni;
 
 import androidx.annotation.NonNull;
 
diff --git a/common/java/com/android/odp/module/common/HttpClient.java b/common/java/com/android/odp/module/common/http/HttpClient.java
similarity index 96%
rename from common/java/com/android/odp/module/common/HttpClient.java
rename to common/java/com/android/odp/module/common/http/HttpClient.java
index aae4f8a2..6d35a3ee 100644
--- a/common/java/com/android/odp/module/common/HttpClient.java
+++ b/common/java/com/android/odp/module/common/http/HttpClient.java
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
-import static com.android.odp.module.common.HttpClientUtils.HTTP_OK_STATUS;
+import static com.android.odp.module.common.http.HttpClientUtils.HTTP_OK_STATUS;
 
 import android.annotation.NonNull;
 
diff --git a/common/java/com/android/odp/module/common/HttpClientUtils.java b/common/java/com/android/odp/module/common/http/HttpClientUtils.java
similarity index 99%
rename from common/java/com/android/odp/module/common/HttpClientUtils.java
rename to common/java/com/android/odp/module/common/http/HttpClientUtils.java
index f6b51388..dd6b0953 100644
--- a/common/java/com/android/odp/module/common/HttpClientUtils.java
+++ b/common/java/com/android/odp/module/common/http/HttpClientUtils.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
 import static com.android.odp.module.common.FileUtils.createTempFile;
 import static com.android.odp.module.common.FileUtils.writeToFile;
@@ -67,7 +67,6 @@ public class HttpClientUtils {
     public static final String OCTET_STREAM = "application/octet-stream";
     public static final ImmutableSet<Integer> HTTP_OK_STATUS = ImmutableSet.of(200, 201);
 
-
     public static final int DEFAULT_BUFFER_SIZE = 1024;
     public static final byte[] EMPTY_BODY = new byte[0];
 
diff --git a/common/java/com/android/odp/module/common/OdpHttpRequest.java b/common/java/com/android/odp/module/common/http/OdpHttpRequest.java
similarity index 92%
rename from common/java/com/android/odp/module/common/OdpHttpRequest.java
rename to common/java/com/android/odp/module/common/http/OdpHttpRequest.java
index 894ae8c0..30a2e8ba 100644
--- a/common/java/com/android/odp/module/common/OdpHttpRequest.java
+++ b/common/java/com/android/odp/module/common/http/OdpHttpRequest.java
@@ -14,11 +14,11 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
-import static com.android.odp.module.common.HttpClientUtils.CONTENT_LENGTH_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_LENGTH_HDR;
 
-import com.android.odp.module.common.HttpClientUtils.HttpMethod;
+import com.android.odp.module.common.http.HttpClientUtils.HttpMethod;
 
 import java.util.Map;
 
diff --git a/common/java/com/android/odp/module/common/OdpHttpResponse.java b/common/java/com/android/odp/module/common/http/OdpHttpResponse.java
similarity index 94%
rename from common/java/com/android/odp/module/common/OdpHttpResponse.java
rename to common/java/com/android/odp/module/common/http/OdpHttpResponse.java
index 494e33cb..16710766 100644
--- a/common/java/com/android/odp/module/common/OdpHttpResponse.java
+++ b/common/java/com/android/odp/module/common/http/OdpHttpResponse.java
@@ -14,10 +14,10 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
-import static com.android.odp.module.common.HttpClientUtils.CONTENT_ENCODING_HDR;
-import static com.android.odp.module.common.HttpClientUtils.GZIP_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_HDR;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
diff --git a/federatedcompute/Android.bp b/federatedcompute/Android.bp
index b0df7789..f30008d5 100644
--- a/federatedcompute/Android.bp
+++ b/federatedcompute/Android.bp
@@ -38,7 +38,7 @@ java_genrule {
     cmd: "$(location flatc) -o $(genDir) --java $(in) " +
         "&& $(location soong_zip) -o $(out) -C $(genDir) -D $(genDir)",
     visibility: [
-      "//packages/modules/OnDevicePersonalization:__subpackages__"
+        "//packages/modules/OnDevicePersonalization:__subpackages__",
     ],
 }
 
@@ -50,7 +50,7 @@ filegroup {
     ],
     path: "src",
     visibility: [
-      "//packages/modules/OnDevicePersonalization:__subpackages__"
+        "//packages/modules/OnDevicePersonalization:__subpackages__",
     ],
 }
 
@@ -72,7 +72,7 @@ cc_library_shared {
     whole_static_libs: [
         "libfederatedcompute",
     ],
-    static_libs:[
+    static_libs: [
         "federated-compute-cc-proto-lite",
         "libprotobuf-cpp-lite-ndk",
     ],
@@ -103,7 +103,7 @@ cc_library_shared {
         "jni/cpp/hpke_jni.cc",
     ],
     include_dirs: [
-        "packages/modules/OnDevicePersonalization/federatedcompute/jni/include"
+        "packages/modules/OnDevicePersonalization/federatedcompute/jni/include",
     ],
     version_script: "jni/jni.lds",
     header_libs: [
diff --git a/federatedcompute/PREUPLOAD.cfg b/federatedcompute/PREUPLOAD.cfg
index a6e6d60a..bddc5139 100644
--- a/federatedcompute/PREUPLOAD.cfg
+++ b/federatedcompute/PREUPLOAD.cfg
@@ -1,5 +1,6 @@
 [Builtin Hooks]
 google_java_format = true
+bpfmt = true
 
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
\ No newline at end of file
diff --git a/federatedcompute/apk/Android.bp b/federatedcompute/apk/Android.bp
index b0f474e2..4e978121 100644
--- a/federatedcompute/apk/Android.bp
+++ b/federatedcompute/apk/Android.bp
@@ -78,4 +78,4 @@ android_app {
     optimize: {
         proguard_flags_files: ["proguard.flags"],
     },
-}
\ No newline at end of file
+}
diff --git a/federatedcompute/jni/cpp/hpke_jni.cc b/federatedcompute/jni/cpp/hpke_jni.cc
index f6fc8680..affcb61a 100644
--- a/federatedcompute/jni/cpp/hpke_jni.cc
+++ b/federatedcompute/jni/cpp/hpke_jni.cc
@@ -25,7 +25,7 @@
 //
 // Based from chromium's boringSSL implementation
 // https://source.chromium.org/chromium/chromium/src/+/main:content/browser/aggregation_service/aggregatable_report.cc;l=211
-JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encryption_jni_HpkeJni_encrypt
+JNIEXPORT jbyteArray JNICALL Java_com_android_odp_module_common_encryption_jni_HpkeJni_encrypt
         (JNIEnv* env, jobject object,
          jbyteArray publicKey, jbyteArray plainText, jbyteArray associatedData) {
 
@@ -101,7 +101,7 @@ JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encrypti
 //
 // Based from chromium's boringSSL implementation
 // https://source.chromium.org/chromium/chromium/src/+/main:content/browser/aggregation_service/aggregation_service_test_utils.cc;l=305
-JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encryption_jni_HpkeJni_decrypt
+JNIEXPORT jbyteArray JNICALL Java_com_android_odp_module_common_encryption_jni_HpkeJni_decrypt
         (JNIEnv* env, jobject object,
          jbyteArray privateKey, jbyteArray ciphertext, jbyteArray associatedData) {
 
diff --git a/federatedcompute/jni/cpp/more_jni_util.h b/federatedcompute/jni/cpp/more_jni_util.h
index c7789570..34aace03 100644
--- a/federatedcompute/jni/cpp/more_jni_util.h
+++ b/federatedcompute/jni/cpp/more_jni_util.h
@@ -18,6 +18,8 @@
 
 #include <jni.h>
 
+#include "absl/status/status.h"
+#include "absl/strings/str_cat.h"
 #include "fcp/base/monitoring.h"
 #include "fcp/jni/jni_util.h"
 #include "fcp/protos/federatedcompute/common.pb.h"
diff --git a/federatedcompute/jni/include/hpke_jni.h b/federatedcompute/jni/include/hpke_jni.h
index 645670cd..c15a99ea 100644
--- a/federatedcompute/jni/include/hpke_jni.h
+++ b/federatedcompute/jni/include/hpke_jni.h
@@ -28,7 +28,7 @@ extern "C" {
  * Method:    encrypt
  * Signature: ([B[B[B)[B
  */
-JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encryption_jni_HpkeJni_encrypt
+JNIEXPORT jbyteArray JNICALL Java_com_android_odp_module_common_encryption_jni_HpkeJni_encrypt
         (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);
 
 /*
@@ -36,7 +36,7 @@ JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encrypti
  * Method:    decrypt
  * Signature: ([B[B[B)[B
  */
-JNIEXPORT jbyteArray JNICALL Java_com_android_federatedcompute_services_encryption_jni_HpkeJni_decrypt
+JNIEXPORT jbyteArray JNICALL Java_com_android_odp_module_common_encryption_jni_HpkeJni_decrypt
         (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);
 
 #ifdef __cplusplus
diff --git a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
index 2dab783f..d79e12c0 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
@@ -88,7 +88,6 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
         try {
             long origId = Binder.clearCallingIdentity();
             if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
-                trainingOptions.getOwnerComponentName().getPackageName();
                 ApiCallStats.Builder apiCallStatsBuilder = new ApiCallStats.Builder()
                         .setApiName(FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE)
                         .setResponseCode(STATUS_KILL_SWITCH_ENABLED);
@@ -124,7 +123,6 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
                                     sendResult(callback, resultCode);
                                     int serviceLatency =
                                             (int) (mClock.elapsedRealtime() - startServiceTime);
-                                    trainingOptions.getOwnerComponentName().getPackageName();
                                     ApiCallStats.Builder apiCallStatsBuilder =
                                             new ApiCallStats.Builder()
                                                     .setApiName(
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java b/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
index f9541a23..c84382d5 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
@@ -28,6 +28,11 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_NO_TASK_AVAILABLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHENTICATED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHORIZED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_FAILED_EMPTY_URI;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_INVALID_PAYLOAD;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_REQUEST_CREATION_FAILED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_START;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_TIMEOUT_ERROR;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_FAILURE_UPLOADED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_FAILURE_UPLOAD_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_INITIATE_REPORT_RESULT_AUTH_SUCCEEDED;
@@ -37,17 +42,19 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RESULT_UPLOAD_SERVER_ABORTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RESULT_UPLOAD_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_CONDITIONS_FAILED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_TASK_ASSIGNMENT_AUTH_SUCCEEDED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_TASK_ASSIGNMENT_UNAUTHORIZED;
 
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.statsd.FederatedComputeStatsdLogger;
 import com.android.federatedcompute.services.statsd.TrainingEventReported;
+import com.android.odp.module.common.EventLogger;
 
 import com.google.internal.federatedcompute.v1.RejectionInfo;
 
 /** The helper function to log {@link TrainingEventReported} in statsd. */
-public class TrainingEventLogger {
+public class TrainingEventLogger implements EventLogger {
     private static final String TAG = TrainingEventLogger.class.getSimpleName();
     private long mTaskId = 0;
     private long mVersion = 0;
@@ -209,6 +216,55 @@ public class TrainingEventLogger {
         logEvent(event);
     }
 
+    /** Logs training event kind. */
+    @Override
+    public void logEncryptionKeyFetchFailEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED);
+        logEvent(event);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchStartEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_START);
+        logEvent(event);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchTimeoutEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_TIMEOUT_ERROR);
+        logEvent(event);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchEmptyUriEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_FAILED_EMPTY_URI);
+        logEvent(event);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchInvalidPayloadEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_INVALID_PAYLOAD);
+        logEvent(event);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchRequestFailEventKind() {
+        TrainingEventReported.Builder event =
+                new TrainingEventReported.Builder().setEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_REQUEST_CREATION_FAILED);
+        logEvent(event);
+    }
+
     /** Logs when device starts to upload computation result. */
     public void logResultUploadStarted() {
         TrainingEventReported.Builder event =
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
index f82a9f1e..bf0d4e00 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
@@ -19,9 +19,7 @@ package com.android.federatedcompute.services.data;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_READ_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_WRITE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__FEDERATED_COMPUTE;
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
-import static com.android.federatedcompute.services.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
 import static com.android.federatedcompute.services.data.TaskHistoryContract.TaskHistoryEntry.CREATE_TASK_HISTORY_TABLE_STATEMENT;
 
 import android.annotation.Nullable;
@@ -30,17 +28,17 @@ import android.content.Context;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
-import android.database.sqlite.SQLiteOpenHelper;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.FederatedComputeEncryptionColumns;
 import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenContract.ODPAuthorizationTokenColumns;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.data.ODPAuthorizationTokenContract;
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyContract;
 
 /** Helper to manage FederatedTrainingTask database. */
-public class FederatedComputeDbHelper extends SQLiteOpenHelper {
+public class FederatedComputeDbHelper extends OdpSQLiteOpenHelper {
 
     private static final String TAG = FederatedComputeDbHelper.class.getSimpleName();
 
@@ -92,33 +90,6 @@ public class FederatedComputeDbHelper extends SQLiteOpenHelper {
                     + FederatedTrainingTaskColumns.JOB_SCHEDULER_JOB_ID
                     + "))";
 
-    private static final String CREATE_ENCRYPTION_KEY_TABLE =
-            "CREATE TABLE "
-                    + ENCRYPTION_KEY_TABLE
-                    + " ( "
-                    + FederatedComputeEncryptionColumns.KEY_IDENTIFIER
-                    + " TEXT PRIMARY KEY, "
-                    + FederatedComputeEncryptionColumns.PUBLIC_KEY
-                    + " TEXT NOT NULL, "
-                    + FederatedComputeEncryptionColumns.KEY_TYPE
-                    + " INTEGER, "
-                    + FederatedComputeEncryptionColumns.CREATION_TIME
-                    + " INTEGER NOT NULL, "
-                    + FederatedComputeEncryptionColumns.EXPIRY_TIME
-                    + " INTEGER NOT NULL)";
-
-    private static final String CREATE_ODP_AUTHORIZATION_TOKEN_TABLE =
-            "CREATE TABLE "
-                    + ODP_AUTHORIZATION_TOKEN_TABLE
-                    + " ( "
-                    + ODPAuthorizationTokenColumns.OWNER_IDENTIFIER
-                    + " TEXT PRIMARY KEY, "
-                    + ODPAuthorizationTokenColumns.AUTHORIZATION_TOKEN
-                    + " TEXT NOT NULL, "
-                    + ODPAuthorizationTokenColumns.CREATION_TIME
-                    + " INTEGER NOT NULL, "
-                    + ODPAuthorizationTokenColumns.EXPIRY_TIME
-                    + " INTEGER NOT NULL)";
     public static final String CREATE_TRAINING_TASK_OWNER_PACKAGE_INDEX =
             "CREATE INDEX IF NOT EXISTS idx_package_name ON " + FEDERATED_TRAINING_TASKS_TABLE
                     + "(" + FederatedTrainingTaskColumns.OWNER_PACKAGE + ")";
@@ -170,8 +141,8 @@ public class FederatedComputeDbHelper extends SQLiteOpenHelper {
     public void onCreate(SQLiteDatabase db) {
         db.execSQL(CREATE_TRAINING_TASK_TABLE);
         db.execSQL(CREATE_TRAINING_TASK_OWNER_PACKAGE_INDEX);
-        db.execSQL(CREATE_ENCRYPTION_KEY_TABLE);
-        db.execSQL(CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
+        db.execSQL(OdpEncryptionKeyContract.CREATE_ENCRYPTION_KEY_TABLE);
+        db.execSQL(ODPAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
         db.execSQL(CREATE_TASK_HISTORY_TABLE_STATEMENT);
     }
 
@@ -269,6 +240,7 @@ public class FederatedComputeDbHelper extends SQLiteOpenHelper {
     }
 
     /** Wraps getReadableDatabase to catch SQLiteException and log error. */
+    @Override
     @Nullable
     public SQLiteDatabase safeGetReadableDatabase() {
         try {
@@ -285,6 +257,7 @@ public class FederatedComputeDbHelper extends SQLiteOpenHelper {
     }
 
     /** Wraps getWritableDatabase to catch SQLiteException and log error. */
+    @Override
     @Nullable
     public SQLiteDatabase safeGetWritableDatabase() {
         try {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java
new file mode 100644
index 00000000..0664f9a3
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.federatedcompute.services.data;
+
+import android.annotation.NonNull;
+import android.content.Context;
+
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+
+import com.google.common.annotations.VisibleForTesting;
+
+/**
+ * Wrapper class that manages the creation of the underlying {@link OdpEncryptionKeyDao} with the
+ * appropriate {@link com.android.odp.module.common.data.OdpSQLiteOpenHelper}.
+ */
+public class FederatedComputeEncryptionKeyDaoUtils {
+    private static final String TAG = FederatedComputeEncryptionKeyDaoUtils.class.getSimpleName();
+
+    /** Class is not meant to be instantiated, thin wrapper over {@link OdpEncryptionKeyDao} */
+    private FederatedComputeEncryptionKeyDaoUtils() {}
+
+    /** Returns an instance of {@link FederatedComputeEncryptionKeyDaoUtils} given a context. */
+    @NonNull
+    public static OdpEncryptionKeyDao getInstance(Context context) {
+        return OdpEncryptionKeyDao.getInstance(
+                context, FederatedComputeDbHelper.getInstance(context));
+    }
+
+    /**
+     * Helper method to get instance of {@link FederatedComputeEncryptionKeyDaoUtils} for use in
+     * tests.
+     *
+     * <p>Public for use in unit tests.
+     */
+    @VisibleForTesting
+    public static OdpEncryptionKeyDao getInstanceForTest(Context context) {
+        return OdpEncryptionKeyDao.getInstance(
+                context, FederatedComputeDbHelper.getInstanceForTest(context));
+    }
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobEventLogger.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobEventLogger.java
new file mode 100644
index 00000000..01dcdb4e
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobEventLogger.java
@@ -0,0 +1,80 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.federatedcompute.services.encryption;
+
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRACE_EVENT_REPORTED;
+
+import com.android.federatedcompute.services.statsd.FederatedComputeStatsdLogger;
+import com.android.federatedcompute.services.statsd.TraceEventStats;
+import com.android.odp.module.common.EventLogger;
+
+/** The helper function to log {@link TraceEventStats} in statsd. */
+public class BackgroundKeyFetchJobEventLogger implements EventLogger {
+    public static int ENCRYPTION_KEY_FETCH_START_EVENT = 1;
+    public static int ENCRYPTION_KEY_FETCH_FAIL_EVENT = 2;
+    public static int ENCRYPTION_KEY_FETCH_TIMEOUT_EVENT = 3;
+    public static int ENCRYPTION_KEY_FETCH_EMPTY_URI_EVENT = 4;
+    public static int ENCRYPTION_KEY_FETCH_REQUEST_FAIL_EVENT = 5;
+    public static int ENCRYPTION_KEY_FETCH_INVALID_PAYLOAD_EVENT = 6;
+    @Override
+    public void logEncryptionKeyFetchFailEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_FAIL_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchStartEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_START_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchTimeoutEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_TIMEOUT_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchEmptyUriEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_EMPTY_URI_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchRequestFailEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_REQUEST_FAIL_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+
+    @Override
+    public void logEncryptionKeyFetchInvalidPayloadEventKind() {
+        TraceEventStats traceEventStats = new TraceEventStats.Builder().setEventType(
+                FEDERATED_COMPUTE_TRACE_EVENT_REPORTED).setStatus(
+                ENCRYPTION_KEY_FETCH_INVALID_PAYLOAD_EVENT).build();
+        FederatedComputeStatsdLogger.getInstance().logTraceEventStats(traceEventStats);
+    }
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
index 91ad4efb..5a1e5076 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
@@ -31,15 +31,18 @@ import com.android.federatedcompute.services.common.FederatedComputeJobInfo;
 import com.android.federatedcompute.services.common.FederatedComputeJobUtil;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
 import com.android.federatedcompute.services.statsd.joblogging.FederatedComputeJobServiceLogger;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.EventLogger;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListeningExecutorService;
 
 import java.util.List;
+import java.util.Optional;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.TimeoutException;
 
@@ -59,8 +62,12 @@ public class BackgroundKeyFetchJobService extends JobService {
             return FederatedComputeExecutors.getLightweightExecutor();
         }
 
-        FederatedComputeEncryptionKeyManager getEncryptionKeyManager(Context context) {
-            return FederatedComputeEncryptionKeyManager.getInstance(context);
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return FederatedComputeEncryptionKeyManagerUtils.getInstance(context);
+        }
+
+        EventLogger getEventLogger() {
+            return new BackgroundKeyFetchJobEventLogger();
         }
     }
 
@@ -92,24 +99,25 @@ public class BackgroundKeyFetchJobService extends JobService {
                     ENCRYPTION_KEY_FETCH_JOB_ID,
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON);
         }
+        EventLogger eventLogger = mInjector.getEventLogger();
+        eventLogger.logEncryptionKeyFetchStartEventKind();
         mInjector
                 .getEncryptionKeyManager(this)
-                .fetchAndPersistActiveKeys(FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION,
-                        /* isScheduledJob= */ true)
+                .fetchAndPersistActiveKeys(
+                        OdpEncryptionKey.KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
+                        Optional.of(eventLogger))
                 .addCallback(
-                        new FutureCallback<List<FederatedComputeEncryptionKey>>() {
+                        new FutureCallback<List<OdpEncryptionKey>>() {
                             @Override
-                            public void onSuccess(
-                                    List<FederatedComputeEncryptionKey>
-                                            federatedComputeEncryptionKeys) {
+                            public void onSuccess(List<OdpEncryptionKey> odpEncryptionKeys) {
                                 LogUtil.d(
                                         TAG,
                                         "BackgroundKeyFetchJobService %d is done, fetched %d keys",
                                         params.getJobId(),
-                                        federatedComputeEncryptionKeys.size());
+                                        odpEncryptionKeys.size());
                                 boolean wantsReschedule = false;
                                 FederatedComputeJobServiceLogger.getInstance(
-                                        BackgroundKeyFetchJobService.this)
+                                                BackgroundKeyFetchJobService.this)
                                         .recordJobFinished(
                                                 ENCRYPTION_KEY_FETCH_JOB_ID,
                                                 /* isSuccessful= */ true,
@@ -135,12 +143,12 @@ public class BackgroundKeyFetchJobService extends JobService {
                                     LogUtil.e(
                                             TAG,
                                             "Background key fetch failed due to interruption "
-                                            + "error");
+                                                    + "error");
                                 } else if (throwable instanceof IllegalArgumentException) {
                                     LogUtil.e(
                                             TAG,
                                             "Background key fetch failed due to illegal argument "
-                                            + "error");
+                                                    + "error");
                                 } else {
                                     LogUtil.e(
                                             TAG,
@@ -148,7 +156,7 @@ public class BackgroundKeyFetchJobService extends JobService {
                                 }
                                 boolean wantsReschedule = false;
                                 FederatedComputeJobServiceLogger.getInstance(
-                                        BackgroundKeyFetchJobService.this)
+                                                BackgroundKeyFetchJobService.this)
                                         .recordJobFinished(
                                                 ENCRYPTION_KEY_FETCH_JOB_ID,
                                                 /* isSuccessful= */ false,
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java
new file mode 100644
index 00000000..c657d826
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java
@@ -0,0 +1,109 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.federatedcompute.services.encryption;
+
+import android.content.Context;
+
+import com.android.federatedcompute.services.common.FederatedComputeExecutors;
+import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
+import com.android.odp.module.common.Clock;
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.odp.module.common.http.HttpClient;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+/**
+ * Wrapper class that manages the creation of the underlying {@link OdpEncryptionKeyManager} with
+ * the appropriate {@link OdpEncryptionKeyManager.KeyManagerConfig} and {@link OdpSQLiteOpenHelper}.
+ */
+public class FederatedComputeEncryptionKeyManagerUtils {
+
+    public static class FlagKeyManagerConfig implements OdpEncryptionKeyManager.KeyManagerConfig {
+
+        private final Flags mFlags;
+        private final FederatedComputeDbHelper mFederatedComputeDbHelper;
+
+        FlagKeyManagerConfig(Flags flags, FederatedComputeDbHelper federatedComputeDbHelper) {
+            mFlags = flags;
+            this.mFederatedComputeDbHelper = federatedComputeDbHelper;
+        }
+
+        @Override
+        public String getEncryptionKeyFetchUrl() {
+            return mFlags.getEncryptionKeyFetchUrl();
+        }
+
+        @Override
+        public int getHttpRequestRetryLimit() {
+            return mFlags.getHttpRequestRetryLimit();
+        }
+
+        @Override
+        public long getEncryptionKeyMaxAgeSeconds() {
+            return mFlags.getFederatedComputeEncryptionKeyMaxAgeSeconds();
+        }
+
+        @Override
+        public OdpSQLiteOpenHelper getSQLiteOpenHelper() {
+            return mFederatedComputeDbHelper;
+        }
+
+        @Override
+        public ListeningExecutorService getBackgroundExecutor() {
+            return FederatedComputeExecutors.getBackgroundExecutor();
+        }
+
+        @Override
+        public ListeningExecutorService getBlockingExecutor() {
+            return FederatedComputeExecutors.getBlockingExecutor();
+        }
+    }
+
+    /** Class is not meant to be instantiated, thin wrapper over {@link OdpEncryptionKeyManager} */
+    private FederatedComputeEncryptionKeyManagerUtils() {}
+
+    /** Returns a singleton instance for the {@link FederatedComputeEncryptionKeyManagerUtils}. */
+    public static OdpEncryptionKeyManager getInstance(Context context) {
+        return OdpEncryptionKeyManager.getInstance(
+                context,
+                new FlagKeyManagerConfig(
+                        FlagsFactory.getFlags(), FederatedComputeDbHelper.getInstance(context)));
+    }
+
+    /** For testing only, returns an instance of key manager for test. */
+    @VisibleForTesting
+    static OdpEncryptionKeyManager getInstanceForTest(
+            Clock clock,
+            OdpEncryptionKeyDao encryptionKeyDao,
+            Flags flags,
+            HttpClient client,
+            ListeningExecutorService executor,
+            Context context) {
+        return OdpEncryptionKeyManager.getInstanceForTesting(
+                clock,
+                encryptionKeyDao,
+                new FlagKeyManagerConfig(
+                        flags, FederatedComputeDbHelper.getInstanceForTest(context)),
+                client,
+                executor);
+    }
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/HttpClientUtil.java b/federatedcompute/src/com/android/federatedcompute/services/http/HttpClientUtil.java
index b1925f1b..bdfe1d16 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/HttpClientUtil.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/HttpClientUtil.java
@@ -22,15 +22,10 @@ import org.json.JSONObject;
 
 /** Utility class containing http related variable e.g. headers, method. */
 public final class HttpClientUtil {
-    private static final String TAG = HttpClientUtil.class.getSimpleName();
     public static final String CONTENT_ENCODING_HDR = "Content-Encoding";
 
     public static final String ACCEPT_ENCODING_HDR = "Accept-Encoding";
-    public static final String CONTENT_LENGTH_HDR = "Content-Length";
-    public static final String GZIP_ENCODING_HDR = "gzip";
-    public static final String CONTENT_TYPE_HDR = "Content-Type";
-    public static final String PROTOBUF_CONTENT_TYPE = "application/x-protobuf";
-    public static final String OCTET_STREAM = "application/octet-stream";
+
     public static final ImmutableSet<Integer> HTTP_OK_STATUS = ImmutableSet.of(200, 201);
 
     public static final Integer HTTP_UNAUTHENTICATED_STATUS = 401;
@@ -50,10 +45,9 @@ public final class HttpClientUtil {
 
     public static final String FCP_OWNER_ID_DIGEST = "fcp-owner-id-digest";
 
-    public static final int DEFAULT_BUFFER_SIZE = 1024;
     public static final byte[] EMPTY_BODY = new byte[0];
 
-    public static final class FederatedComputePayloadDataContract {
+    static final class FederatedComputePayloadDataContract {
         public static final String KEY_ID = "keyId";
 
         public static final String ENCRYPTED_PAYLOAD = "encryptedPayload";
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
index fc7ce1f2..7d436f3c 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
@@ -24,7 +24,6 @@ import static com.android.federatedcompute.services.common.FederatedComputeExecu
 import static com.android.federatedcompute.services.common.TrainingEventLogger.getTaskIdForLogging;
 import static com.android.federatedcompute.services.http.HttpClientUtil.ACCEPT_ENCODING_HDR;
 import static com.android.federatedcompute.services.http.HttpClientUtil.FCP_OWNER_ID_DIGEST;
-import static com.android.federatedcompute.services.http.HttpClientUtil.GZIP_ENCODING_HDR;
 import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_OK_OR_UNAUTHENTICATED_STATUS;
 import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_OK_STATUS;
 import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_UNAUTHORIZED_STATUS;
@@ -32,10 +31,11 @@ import static com.android.federatedcompute.services.http.HttpClientUtil.ODP_IDEM
 import static com.android.odp.module.common.FileUtils.createTempFile;
 import static com.android.odp.module.common.FileUtils.readFileAsByteArray;
 import static com.android.odp.module.common.FileUtils.writeToFile;
-import static com.android.odp.module.common.HttpClientUtils.compressWithGzip;
-import static com.android.odp.module.common.HttpClientUtils.getTotalReceivedBytes;
-import static com.android.odp.module.common.HttpClientUtils.getTotalSentBytes;
-import static com.android.odp.module.common.HttpClientUtils.uncompressWithGzip;
+import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.compressWithGzip;
+import static com.android.odp.module.common.http.HttpClientUtils.getTotalReceivedBytes;
+import static com.android.odp.module.common.http.HttpClientUtils.getTotalSentBytes;
+import static com.android.odp.module.common.http.HttpClientUtils.uncompressWithGzip;
 
 import android.os.Trace;
 import android.util.Base64;
@@ -44,15 +44,15 @@ import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.NetworkStats;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
-import com.android.federatedcompute.services.encryption.Encrypter;
 import com.android.federatedcompute.services.http.HttpClientUtil.FederatedComputePayloadDataContract;
 import com.android.federatedcompute.services.security.AuthorizationContext;
 import com.android.federatedcompute.services.training.util.ComputationResult;
-import com.android.odp.module.common.HttpClient;
-import com.android.odp.module.common.HttpClientUtils;
-import com.android.odp.module.common.OdpHttpRequest;
-import com.android.odp.module.common.OdpHttpResponse;
+import com.android.odp.module.common.encryption.Encrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
+import com.android.odp.module.common.http.OdpHttpResponse;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.base.Preconditions;
@@ -64,13 +64,13 @@ import com.google.internal.federatedcompute.v1.ClientVersion;
 import com.google.internal.federatedcompute.v1.RejectionInfo;
 import com.google.internal.federatedcompute.v1.Resource;
 import com.google.internal.federatedcompute.v1.ResourceCompressionFormat;
-import com.google.internal.federatedcompute.v1.UploadInstruction;
 import com.google.ondevicepersonalization.federatedcompute.proto.CreateTaskAssignmentRequest;
 import com.google.ondevicepersonalization.federatedcompute.proto.CreateTaskAssignmentResponse;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultRequest;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultRequest.Result;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultResponse;
 import com.google.ondevicepersonalization.federatedcompute.proto.TaskAssignment;
+import com.google.ondevicepersonalization.federatedcompute.proto.UploadInstruction;
 import com.google.protobuf.InvalidProtocolBufferException;
 
 import org.json.JSONObject;
@@ -171,7 +171,7 @@ public final class HttpFederatedProtocol {
     /** Helper functions to report and upload result. */
     public FluentFuture<RejectionInfo> reportResult(
             ComputationResult computationResult,
-            FederatedComputeEncryptionKey encryptionKey,
+            OdpEncryptionKey encryptionKey,
             AuthorizationContext authContext) {
         Trace.beginAsyncSection(TRACE_HTTP_REPORT_RESULT, 0);
         NetworkStats reportResultStats = new NetworkStats();
@@ -446,7 +446,7 @@ public final class HttpFederatedProtocol {
     private ListenableFuture<OdpHttpResponse> processReportResultResponseAndUploadResult(
             ReportResultResponse reportResultResponse,
             ComputationResult computationResult,
-            FederatedComputeEncryptionKey encryptionKey,
+            OdpEncryptionKey encryptionKey,
             NetworkStats networkStats) {
         try {
             Preconditions.checkArgument(
@@ -487,8 +487,8 @@ public final class HttpFederatedProtocol {
         }
     }
 
-    private byte[] createEncryptedRequestBody(
-            String filePath, FederatedComputeEncryptionKey encryptionKey) throws Exception {
+    private byte[] createEncryptedRequestBody(String filePath, OdpEncryptionKey encryptionKey)
+            throws Exception {
         byte[] fileOutputBytes = readFileAsByteArray(filePath);
         if (!FlagsFactory.getFlags().isEncryptionEnabled()) {
             // encryption not enabled, upload the file contents directly
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/ProtocolRequestCreator.java b/federatedcompute/src/com/android/federatedcompute/services/http/ProtocolRequestCreator.java
index a01b71d4..28535db9 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/ProtocolRequestCreator.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/ProtocolRequestCreator.java
@@ -16,9 +16,9 @@
 
 package com.android.federatedcompute.services.http;
 
-import com.android.odp.module.common.HttpClientUtils;
-import com.android.odp.module.common.HttpClientUtils.HttpMethod;
-import com.android.odp.module.common.OdpHttpRequest;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.HttpClientUtils.HttpMethod;
+import com.android.odp.module.common.http.OdpHttpRequest;
 
 import com.google.internal.federatedcompute.v1.ForwardingInfo;
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
index 16f42dab..ec5609e0 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
@@ -33,13 +33,14 @@ import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobServiceFactory;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
@@ -69,7 +70,8 @@ public final class DeleteExpiredJob implements JobWorker {
         }
 
         ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
-            return ODPAuthorizationTokenDao.getInstance(context);
+            return ODPAuthorizationTokenDao.getInstance(
+                    FederatedComputeDbHelper.getInstance(context));
         }
 
         FederatedTrainingTaskDao getTrainingTaskDao(Context context) {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
index 310e9328..a5aff02a 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
@@ -35,12 +35,13 @@ import com.android.federatedcompute.services.common.FederatedComputeJobInfo;
 import com.android.federatedcompute.services.common.FederatedComputeJobUtil;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.federatedcompute.services.statsd.joblogging.FederatedComputeJobServiceLogger;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
@@ -72,7 +73,8 @@ public class DeleteExpiredJobService extends JobService {
         }
 
         ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
-            return ODPAuthorizationTokenDao.getInstance(context);
+            return ODPAuthorizationTokenDao.getInstance(
+                    FederatedComputeDbHelper.getInstance(context));
         }
 
         FederatedTrainingTaskDao getTrainingTaskDao(Context context) {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java b/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
index c2e072d2..cb61e1d6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
@@ -27,11 +27,12 @@ import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
-import com.android.federatedcompute.services.data.ODPAuthorizationToken;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
+import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationToken;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
@@ -49,6 +50,7 @@ import java.util.concurrent.BlockingQueue;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicInteger;
 
+/** Manages the details of authenticating with remote server. */
 public class AuthorizationContext {
 
     private static final String TAG = AuthorizationContext.class.getSimpleName();
@@ -85,7 +87,7 @@ public class AuthorizationContext {
         return new AuthorizationContext(
                 ownerId,
                 ownerCert,
-                ODPAuthorizationTokenDao.getInstance(context),
+                ODPAuthorizationTokenDao.getInstance(FederatedComputeDbHelper.getInstance(context)),
                 KeyAttestation.getInstance(context),
                 MonotonicClock.getInstance());
     }
@@ -130,55 +132,61 @@ public class AuthorizationContext {
         }
     }
 
-    /** Generates authentication header used for http request. */
+    /**
+     * Generates authentication headers used for http request.
+     *
+     * <p>Returns empty headers if the call to get {@link ODPAuthorizationToken} from the {@link
+     * ODPAuthorizationTokenDao} fails or times out.
+     */
     public Map<String, String> generateAuthHeaders() {
         Map<String, String> headers = new HashMap<>();
+        if (mAttestationRecord != null) {
+            // Only when the device is solving challenge, the attestation record is not null.
+            JSONArray attestationArr = new JSONArray(mAttestationRecord);
+            headers.put(ODP_AUTHENTICATION_KEY, attestationArr.toString());
+            // Generate a UUID that will serve as the authorization token.
+            String authTokenUUID = UUID.randomUUID().toString();
+            headers.put(ODP_AUTHORIZATION_KEY, authTokenUUID);
+            ODPAuthorizationToken authToken =
+                    new ODPAuthorizationToken.Builder()
+                            .setAuthorizationToken(authTokenUUID)
+                            .setOwnerIdentifier(mOwnerId)
+                            .setCreationTime(mClock.currentTimeMillis())
+                            .setExpiryTime(
+                                    mClock.currentTimeMillis()
+                                            + FlagsFactory.getFlags().getOdpAuthorizationTokenTtl())
+                            .build();
+            var unused =
+                    Futures.submit(
+                            () -> mAuthorizationTokenDao.insertAuthorizationToken(authToken),
+                            FederatedComputeExecutors.getBackgroundExecutor());
+            return headers;
+        }
+
+        // Get existing OdpAuthorizationToken from the Dao.
         try {
-            if (mAttestationRecord != null) {
-                // Only when the device is solving challenge, the attestation record is not null.
-                JSONArray attestationArr = new JSONArray(mAttestationRecord);
-                headers.put(ODP_AUTHENTICATION_KEY, attestationArr.toString());
-                // generate a UUID and the UUID would serve as the authorization token.
-                String authTokenUUID = UUID.randomUUID().toString();
-                headers.put(ODP_AUTHORIZATION_KEY, authTokenUUID);
-                ODPAuthorizationToken authToken =
-                        new ODPAuthorizationToken.Builder()
-                                .setAuthorizationToken(authTokenUUID)
-                                .setOwnerIdentifier(mOwnerId)
-                                .setCreationTime(mClock.currentTimeMillis())
-                                .setExpiryTime(
-                                        mClock.currentTimeMillis()
-                                                + FlagsFactory.getFlags()
-                                                        .getOdpAuthorizationTokenTtl())
-                                .build();
-                var unused =
-                        Futures.submit(
-                                () -> mAuthorizationTokenDao.insertAuthorizationToken(authToken),
-                                FederatedComputeExecutors.getBackgroundExecutor());
+            BlockingQueue<AuthTokenCallbackResult> authTokenBlockingQueue =
+                    new ArrayBlockingQueue<>(1);
+            ListenableFuture<AuthTokenCallbackResult> authTokenFuture =
+                    Futures.submit(
+                            () ->
+                                    convertODPAuthToken(
+                                            mAuthorizationTokenDao.getUnexpiredAuthorizationToken(
+                                                    mOwnerId)),
+                            FederatedComputeExecutors.getBackgroundExecutor());
+            Futures.addCallback(
+                    authTokenFuture,
+                    createCallbackForBlockingQueue(authTokenBlockingQueue),
+                    FederatedComputeExecutors.getLightweightExecutor());
+            AuthTokenCallbackResult callbackResult =
+                    authTokenBlockingQueue.poll(
+                            BLOCKING_QUEUE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
+            if (callbackResult.isEmpty()) {
+                LogUtil.e(TAG, "Timed out waiting for  blocking queue.");
             } else {
-                BlockingQueue<AuthTokenCallbackResult> authTokenBlockingQueue =
-                        new ArrayBlockingQueue<>(1);
-                ListenableFuture<AuthTokenCallbackResult> authTokenFuture =
-                        Futures.submit(
-                                () ->
-                                        convertODPAuthToken(
-                                                mAuthorizationTokenDao
-                                                        .getUnexpiredAuthorizationToken(mOwnerId)),
-                                FederatedComputeExecutors.getBackgroundExecutor());
-                Futures.addCallback(
-                        authTokenFuture,
-                        createCallbackForBlockingQueue(authTokenBlockingQueue),
-                        FederatedComputeExecutors.getLightweightExecutor());
-                AuthTokenCallbackResult callbackResult =
-                        authTokenBlockingQueue.poll(
-                                BLOCKING_QUEUE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
-                if (callbackResult.isEmpty()) {
-                    LogUtil.e(TAG, "Timed out waiting for  blocking queue.");
-                } else {
-                    headers.put(
-                            ODP_AUTHORIZATION_KEY,
-                            callbackResult.getAuthToken().getAuthorizationToken());
-                }
+                headers.put(
+                        ODP_AUTHORIZATION_KEY,
+                        callbackResult.getAuthToken().getAuthorizationToken());
             }
         } catch (InterruptedException exception) {
             LogUtil.e(
diff --git a/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java b/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
index 39cbda8a..59072bae 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
@@ -37,7 +37,6 @@ import java.util.ArrayList;
 import java.util.List;
 
 public class KeyAttestation {
-
     private static final String TAG = "KeyAttestation";
     private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
 
@@ -47,6 +46,7 @@ public class KeyAttestation {
 
     private final boolean mUseStrongBox;
 
+    @VisibleForTesting
     static class Injector {
         KeyStore getKeyStore() throws KeyStoreException {
             return KeyStore.getInstance(ANDROID_KEY_STORE);
@@ -60,7 +60,7 @@ public class KeyAttestation {
 
     private final Injector mInjector;
 
-    KeyAttestation(boolean useStrongBox, Injector injector) {
+    private KeyAttestation(boolean useStrongBox, Injector injector) {
         this.mUseStrongBox = useStrongBox;
         this.mInjector = injector;
     }
@@ -68,7 +68,7 @@ public class KeyAttestation {
     /**
      * @return a singleton instance for KeyAttestation.
      */
-    public static KeyAttestation getInstance(Context context) {
+    static KeyAttestation getInstance(Context context) {
         if (sSingletonInstance == null) {
             synchronized (KeyAttestation.class) {
                 if (sSingletonInstance == null) {
@@ -102,13 +102,19 @@ public class KeyAttestation {
     }
 
     /**
-     * Given a challenge, return a list of base64 encoded strings as the attestation record. The
-     * attestation is performed using a 256-bit Elliptical Curve (EC) key-pair generated by the
-     * secure keymaster.
+     * Given a challenge, return a list of base64 encoded strings as the attestation record.
+     *
+     * <p>The attestation is performed using a 256-bit Elliptical Curve (EC) key-pair generated by
+     * the secure keymaster.
+     *
+     * <p>Returned list is empty in case of failure.
      */
     public List<String> generateAttestationRecord(
             final byte[] challenge, final String callingPackage) {
-        final String keyAlias = callingPackage + "-" + ODP_KEY_ALIAS;
+        final String keyAlias = getKeyAlias(callingPackage);
+        // Generate the key pair and attestation certificate using the provided challenge.
+        // The key-pair is unused, but the attestation certs will be used (via certificate chain)
+        // by subsequent getAttestationRecordFromKeyAlias call to generate the attestation record.
         KeyPair kp = generateHybridKey(challenge, keyAlias);
         if (kp == null) {
             return new ArrayList<>();
@@ -140,22 +146,28 @@ public class KeyAttestation {
 
     @VisibleForTesting
     List<String> getAttestationRecordFromKeyAlias(String keyAlias) {
+        ArrayList<String> attestationRecord = new ArrayList<>();
         try {
             KeyStore keyStore = mInjector.getKeyStore();
             keyStore.load(null);
             Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
             if (certificateChain == null) {
-                return new ArrayList<>();
+                return attestationRecord;
             }
-            ArrayList<String> attestationRecord = new ArrayList<>();
+
             for (Certificate certificate : certificateChain) {
                 attestationRecord.add(
                         Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP));
             }
             return attestationRecord;
         } catch (Exception e) {
-            LogUtil.e(TAG, e, "Got exception when generate attestation record");
+            LogUtil.e(TAG, e, "Got exception when generating attestation record.");
         }
-        return new ArrayList<>();
+        return attestationRecord;
+    }
+
+    @VisibleForTesting
+    static String getKeyAlias(String callingPackage) {
+        return callingPackage + "-" + ODP_KEY_ALIAS;
     }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/statsd/FederatedComputeStatsdLogger.java b/federatedcompute/src/com/android/federatedcompute/services/statsd/FederatedComputeStatsdLogger.java
index 21ceec96..f4ccc4e6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/statsd/FederatedComputeStatsdLogger.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/statsd/FederatedComputeStatsdLogger.java
@@ -18,6 +18,7 @@ package com.android.federatedcompute.services.statsd;
 
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.EXAMPLE_ITERATOR_NEXT_LATENCY_REPORTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_API_CALLED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRACE_EVENT_REPORTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED;
 
 import com.android.federatedcompute.services.stats.FederatedComputeStatsLog;
@@ -64,6 +65,17 @@ public class FederatedComputeStatsdLogger {
         }
     }
 
+    /** Log trace event stats. */
+    public void logTraceEventStats(TraceEventStats traceEventStats) {
+        if (mRateLimiter.tryAcquire()) {
+            FederatedComputeStatsLog.write(
+                    FEDERATED_COMPUTE_TRACE_EVENT_REPORTED,
+                    traceEventStats.getEventType(),
+                    traceEventStats.getStatus(),
+                    traceEventStats.getLatencyMillis());
+        }
+    }
+
     /**
      * Log FederatedComputeTrainingEventReported to track each stage of federated computation job
      * execution.
diff --git a/federatedcompute/src/com/android/federatedcompute/services/statsd/TraceEventStats.java b/federatedcompute/src/com/android/federatedcompute/services/statsd/TraceEventStats.java
new file mode 100644
index 00000000..ef23a312
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/statsd/TraceEventStats.java
@@ -0,0 +1,189 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.federatedcompute.services.statsd;
+
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRACE_EVENT_REPORTED__TRACE_KIND__TRACE_EVENT_KIND_UNSPECIFIED;
+
+import com.android.ondevicepersonalization.internal.util.DataClass;
+
+/**
+ * Class holds FederatedComputeTraceEventReported defined at
+ * frameworks/proto_logging/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
+ */
+@DataClass(genBuilder = true, genEqualsHashCode = true)
+public class TraceEventStats {
+    private int mEventType =
+            FEDERATED_COMPUTE_TRACE_EVENT_REPORTED__TRACE_KIND__TRACE_EVENT_KIND_UNSPECIFIED;
+    private int mStatus = 0;
+    private int mLatencyMillis = 0;
+
+
+
+    // Code below generated by codegen v1.0.23.
+    //
+    // DO NOT MODIFY!
+    // CHECKSTYLE:OFF Generated code
+    //
+    // To regenerate run:
+    // $ codegen $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/federatedcompute/src
+    // /com/android/federatedcompute/services/statsd/TraceEventStats.java
+    //
+    // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
+    //   Settings > Editor > Code Style > Formatter Control
+    //@formatter:off
+
+
+    @DataClass.Generated.Member
+    /* package-private */ TraceEventStats(
+            int eventType,
+            int status,
+            int latencyMillis) {
+        this.mEventType = eventType;
+        this.mStatus = status;
+        this.mLatencyMillis = latencyMillis;
+
+        // onConstructed(); // You can define this method to get a callback
+    }
+
+    @DataClass.Generated.Member
+    public int getEventType() {
+        return mEventType;
+    }
+
+    @DataClass.Generated.Member
+    public int getStatus() {
+        return mStatus;
+    }
+
+    @DataClass.Generated.Member
+    public int getLatencyMillis() {
+        return mLatencyMillis;
+    }
+
+    @Override
+    @DataClass.Generated.Member
+    public boolean equals(@android.annotation.Nullable Object o) {
+        // You can override field equality logic by defining either of the methods like:
+        // boolean fieldNameEquals(TraceEventStats other) { ... }
+        // boolean fieldNameEquals(FieldType otherValue) { ... }
+
+        if (this == o) return true;
+        if (o == null || getClass() != o.getClass()) return false;
+        @SuppressWarnings("unchecked")
+        TraceEventStats that = (TraceEventStats) o;
+        //noinspection PointlessBooleanExpression
+        return true
+                && mEventType == that.mEventType
+                && mStatus == that.mStatus
+                && mLatencyMillis == that.mLatencyMillis;
+    }
+
+    @Override
+    @DataClass.Generated.Member
+    public int hashCode() {
+        // You can override field hashCode logic by defining methods like:
+        // int fieldNameHashCode() { ... }
+
+        int _hash = 1;
+        _hash = 31 * _hash + mEventType;
+        _hash = 31 * _hash + mStatus;
+        _hash = 31 * _hash + mLatencyMillis;
+        return _hash;
+    }
+
+    /**
+     * A builder for {@link TraceEventStats}
+     */
+    @SuppressWarnings("WeakerAccess")
+    @DataClass.Generated.Member
+    public static class Builder {
+
+        private int mEventType;
+        private int mStatus;
+        private int mLatencyMillis;
+
+        private long mBuilderFieldsSet = 0L;
+
+        public Builder() {
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setEventType(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x1;
+            mEventType = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setStatus(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x2;
+            mStatus = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setLatencyMillis(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x4;
+            mLatencyMillis = value;
+            return this;
+        }
+
+        /** Builds the instance. This builder should not be touched after calling this! */
+        public @android.annotation.NonNull TraceEventStats build() {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x8; // Mark builder used
+
+            if ((mBuilderFieldsSet & 0x1) == 0) {
+                mEventType = FEDERATED_COMPUTE_TRACE_EVENT_REPORTED__TRACE_KIND__TRACE_EVENT_KIND_UNSPECIFIED;
+            }
+            if ((mBuilderFieldsSet & 0x2) == 0) {
+                mStatus = 0;
+            }
+            if ((mBuilderFieldsSet & 0x4) == 0) {
+                mLatencyMillis = 0;
+            }
+            TraceEventStats o = new TraceEventStats(
+                    mEventType,
+                    mStatus,
+                    mLatencyMillis);
+            return o;
+        }
+
+        private void checkNotUsed() {
+            if ((mBuilderFieldsSet & 0x8) != 0) {
+                throw new IllegalStateException(
+                        "This Builder should not be reused. Use a new Builder instance instead");
+            }
+        }
+    }
+
+    @DataClass.Generated(
+            time = 1732659830128L,
+            codegenVersion = "1.0.23",
+            sourceFile = "packages/modules/OnDevicePersonalization/federatedcompute/src/com/android/federatedcompute/services/statsd/TraceEventStats.java",
+            inputSignatures = "private  int mEventType\nprivate  int mStatus\nprivate  int mLatencyMillis\nclass TraceEventStats extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genEqualsHashCode=true)")
+    @Deprecated
+    private void __metadata() {}
+
+
+    //@formatter:on
+    // End of generated code
+
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java b/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
index 8a66c3d5..3c2ba0e5 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
@@ -83,16 +83,18 @@ public class EligibilityDecider {
                 eligibilityTaskInfo.getEligibilityPoliciesList()) {
             switch (policyEvalSpec.getPolicyTypeCase()) {
                 case MIN_SEP_POLICY:
+                    LogUtil.d(TAG, "MIN_SEP_POLICY used in eligibility check");
                     eligible =
-                            computePerTaskMinSeparation(
+                            isTaskEligibleUnderMinSeparationPolicy(
                                     policyEvalSpec.getMinSepPolicy(),
                                     task.populationName(),
                                     taskId,
                                     task.jobId());
                     break;
                 case DATA_AVAILABILITY_POLICY:
+                    LogUtil.d(TAG, "DATA_AVAILABILITY_POLICY used in eligibility check");
                     eligible =
-                            computePerTaskDataAvailability(
+                            isTaskEligibleUnderDataAvailabilityPolicy(
                                     task,
                                     policyEvalSpec.getDataAvailabilityPolicy(),
                                     taskId,
@@ -132,7 +134,7 @@ public class EligibilityDecider {
         return new EligibilityResult.Builder().setEligible(false).build();
     }
 
-    private boolean computePerTaskMinSeparation(
+    private boolean isTaskEligibleUnderMinSeparationPolicy(
             MinimumSeparationPolicy minSepPolicy, String populationName, String taskId, int jobId) {
         TaskHistory taskHistory = mTaskDao.getLatestTaskHistory(jobId, populationName, taskId);
         // Treat null as the task never run before, then device is qualified.
@@ -145,11 +147,16 @@ public class EligibilityDecider {
                     jobId);
             return true;
         }
-        return minSepPolicy.getMinimumSeparation()
+        boolean result = minSepPolicy.getMinimumSeparation()
                 <= minSepPolicy.getCurrentIndex() - taskHistory.getContributionRound();
+        LogUtil.d(TAG, "min sep policy eligible: %s, minSepPolicy.getMinimumSeparation(): %d, "
+                + "minSepPolicy.getCurrentIndex(): %d, taskHistory.getContributionRound(): %d",
+                result, minSepPolicy.getMinimumSeparation(), minSepPolicy.getCurrentIndex(),
+                taskHistory.getContributionRound());
+        return result;
     }
 
-    private boolean computePerTaskDataAvailability(
+    private boolean isTaskEligibleUnderDataAvailabilityPolicy(
             FederatedTrainingTask task,
             DataAvailabilityPolicy dataAvailabilityPolicy,
             String taskId,
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java b/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
index 6c5b0ff5..0bd13aad 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
@@ -28,6 +28,7 @@ import static com.android.federatedcompute.services.common.FederatedComputeExecu
 import static com.android.federatedcompute.services.common.FederatedComputeExecutors.getLightweightExecutor;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_COMPUTATION_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_NOT_CONFIGURED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_SUCCESS;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_ERROR;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS;
@@ -35,7 +36,6 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_COMPLETE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_COMPUTATION_FAILED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_DOWNLOAD_FAILED;
-import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_NOT_ELIGIBLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_REPORT_FAILED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_WITH_EXCEPTION;
@@ -66,14 +66,12 @@ import com.android.federatedcompute.services.common.ExampleStats;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
 import com.android.federatedcompute.services.data.FederatedTrainingTask;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
 import com.android.federatedcompute.services.data.fbs.TrainingConstraints;
 import com.android.federatedcompute.services.data.fbs.TrainingFlags;
 import com.android.federatedcompute.services.data.fbs.TrainingIntervalOptions;
-import com.android.federatedcompute.services.encryption.FederatedComputeEncryptionKeyManager;
-import com.android.federatedcompute.services.encryption.HpkeJniEncrypter;
+import com.android.federatedcompute.services.encryption.FederatedComputeEncryptionKeyManagerUtils;
 import com.android.federatedcompute.services.examplestore.ExampleConsumptionRecorder;
 import com.android.federatedcompute.services.examplestore.ExampleStoreServiceProvider;
 import com.android.federatedcompute.services.http.CheckinResult;
@@ -92,6 +90,9 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.internal.util.Preconditions;
 import com.android.odp.module.common.FileUtils;
 import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.encryption.HpkeJniEncrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.util.concurrent.FluentFuture;
@@ -117,7 +118,7 @@ import java.io.IOException;
 import java.util.ArrayList;
 import java.util.List;
 import java.util.Objects;
-import java.util.Random;
+import java.util.Optional;
 import java.util.Set;
 import java.util.concurrent.atomic.AtomicBoolean;
 
@@ -144,7 +145,7 @@ public class FederatedComputeWorker {
     private HttpFederatedProtocol mHttpFederatedProtocol;
     private final ExampleStoreServiceProvider mExampleStoreServiceProvider;
     private AbstractServiceBinder<IIsolatedTrainingService> mIsolatedTrainingServiceBinder;
-    private final FederatedComputeEncryptionKeyManager mEncryptionKeyManager;
+    private final OdpEncryptionKeyManager mEncryptionKeyManager;
 
     @VisibleForTesting
     FederatedComputeWorker(
@@ -153,7 +154,7 @@ public class FederatedComputeWorker {
             TrainingConditionsChecker trainingConditionsChecker,
             ComputationRunner computationRunner,
             ResultCallbackHelper resultCallbackHelper,
-            FederatedComputeEncryptionKeyManager keyManager,
+            OdpEncryptionKeyManager keyManager,
             ExampleStoreServiceProvider exampleStoreServiceProvider,
             Injector injector) {
         this.mContext = context.getApplicationContext();
@@ -179,7 +180,7 @@ public class FederatedComputeWorker {
                                     TrainingConditionsChecker.getInstance(context),
                                     new ComputationRunner(context),
                                     new ResultCallbackHelper(context),
-                                    FederatedComputeEncryptionKeyManager.getInstance(context),
+                                    FederatedComputeEncryptionKeyManagerUtils.getInstance(context),
                                     new ExampleStoreServiceProvider(),
                                     new Injector());
                 }
@@ -513,22 +514,20 @@ public class FederatedComputeWorker {
     private ListenableFuture<FLRunnerResult> doFederatedComputation(
             TrainingRun run, CheckinResult checkinResult, EligibilityResult eligibilityResult) {
         // 3. Fetch Active keys to encrypt the computation result.
-        List<FederatedComputeEncryptionKey> activeKeys =
+        List<OdpEncryptionKey> activeKeys =
                 mEncryptionKeyManager.getOrFetchActiveKeys(
-                        FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION,
-                        NUM_ACTIVE_KEYS_TO_CHOOSE_FROM);
+                        OdpEncryptionKey.KEY_TYPE_ENCRYPTION, NUM_ACTIVE_KEYS_TO_CHOOSE_FROM,
+                        Optional.of(run.mTrainingEventLogger));
         // select a random key
-        FederatedComputeEncryptionKey encryptionKey =
-                activeKeys.isEmpty()
-                        ? null
-                        : activeKeys.get(new Random().nextInt(activeKeys.size()));
+        OdpEncryptionKey encryptionKey = OdpEncryptionKeyManager.getRandomKey(activeKeys);
         if (encryptionKey == null) {
             // no active keys to encrypt the FL/FA computation results, stop the computation run.
-            run.mTrainingEventLogger.logEventKind(
-                    FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED);
             reportFailureResultToServer(run, null);
             return Futures.immediateFailedFuture(
                     new IllegalStateException("No active key available on device."));
+        } else {
+            run.mTrainingEventLogger.logEventKind(
+                    FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_SUCCESS);
         }
 
         // 4. Bind to client app implemented ExampleStoreService based on ExampleSelector if we
@@ -1162,37 +1161,37 @@ public class FederatedComputeWorker {
 
     private FluentFuture<RejectionInfo> reportResultWithAuthentication(
             ComputationResult computationResult,
-            FederatedComputeEncryptionKey encryptionKey,
+            OdpEncryptionKey encryptionKey,
             AuthorizationContext authContext,
             TrainingEventLogger trainingEventLogger) {
         // At most this function will make two calls to mHttpFederatedProtocol.reportResult
-        // The first call would allowUnauthenticated, uplon receiving 401 (UNAUTHENTICATED), the
+        // The first call would allowUnauthenticated, upon receiving 401 (UNAUTHENTICATED), the
         // device would solve the challenge and make a second call.
-        return FluentFuture.from(
-                        mHttpFederatedProtocol.reportResult(
-                                computationResult, encryptionKey, authContext))
+        return mHttpFederatedProtocol
+                .reportResult(computationResult, encryptionKey, authContext)
                 .transformAsync(
                         resp -> {
-                            if (resp != null) {
-                                if (authContext.isFirstAuthTry() && resp.hasAuthMetadata()) {
-                                    authContext.updateAuthState(
-                                            resp.getAuthMetadata(), trainingEventLogger);
-                                    return reportResultWithAuthentication(
-                                            computationResult,
-                                            encryptionKey,
-                                            authContext,
-                                            trainingEventLogger);
-                                } else if (resp.hasRetryWindow()) {
-                                    return Futures.immediateFuture(resp);
-                                } else {
-                                    // TODO(b/322880077): cancel job when it fails authentication
-                                    return Futures.immediateFailedFuture(
-                                            new IllegalStateException(
-                                                    "Unknown rejection Info from FCP server when "
-                                                            + "solving authentication challenge"));
-                                }
+                            if (resp == null) {
+                                // No RejectionInfo, report result was successful
+                                return Futures.immediateFuture(null);
+                            }
+                            if (authContext.isFirstAuthTry() && resp.hasAuthMetadata()) {
+                                authContext.updateAuthState(
+                                        resp.getAuthMetadata(), trainingEventLogger);
+                                return reportResultWithAuthentication(
+                                        computationResult,
+                                        encryptionKey,
+                                        authContext,
+                                        trainingEventLogger);
+                            } else if (resp.hasRetryWindow()) {
+                                return Futures.immediateFuture(resp);
+                            } else {
+                                // TODO(b/322880077): cancel job when it fails authentication
+                                return Futures.immediateFailedFuture(
+                                        new IllegalStateException(
+                                                "Unknown rejection Info from FCP server when "
+                                                        + "solving authentication challenge"));
                             }
-                            return Futures.immediateFuture(resp);
                         },
                         getLightweightExecutor());
     }
diff --git a/flags/ondevicepersonalization_flags.aconfig b/flags/ondevicepersonalization_flags.aconfig
index 9a006886..f3215b44 100644
--- a/flags/ondevicepersonalization_flags.aconfig
+++ b/flags/ondevicepersonalization_flags.aconfig
@@ -17,6 +17,7 @@ flag {
     bug: "335080565"
     description: "Enable model version support for federated compute"
     is_fixed_read_only: true
+    is_exported: true
 }
 
 flag {
@@ -25,6 +26,7 @@ flag {
     bug: "353356413"
     description: "Add missing ctors and getters to certain data classes"
     is_fixed_read_only: true
+    is_exported: true
 }
 
 flag {
@@ -33,6 +35,7 @@ flag {
     bug: "336801193"
     description: "Enable executeInIsolatedService API"
     is_fixed_read_only: true
+    is_exported: true
 }
 
 flag {
@@ -41,4 +44,23 @@ flag {
     bug: "343848473"
     description: "Enable the federated compute schedule API that accepts an OutcomeReceiver."
     is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "executorch_inference_api_enabled"
+    namespace: "ondevicepersonalization_aconfig"
+    bug: "376942125"
+    description: "Enable executorch inference API."
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "is_feature_enabled_api_enabled"
+    namespace: "ondevicepersonalization_aconfig"
+    bug: "368695570"
+    description: "Enable the isFeatureEnabled API."
+    is_fixed_read_only: true
+    is_exported: true
 }
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 8b2ad032..7a4ce655 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -1,7 +1,7 @@
 // Signature format: 2.0
 package android.adservices.ondevicepersonalization {
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class AppInfo implements android.os.Parcelable {
+  public final class AppInfo implements android.os.Parcelable {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public AppInfo(boolean);
     method public int describeContents();
     method @NonNull public boolean isInstalled();
@@ -9,12 +9,12 @@ package android.adservices.ondevicepersonalization {
     field @NonNull public static final android.os.Parcelable.Creator<android.adservices.ondevicepersonalization.AppInfo> CREATOR;
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class DownloadCompletedInput {
+  public final class DownloadCompletedInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public DownloadCompletedInput(@NonNull android.adservices.ondevicepersonalization.KeyValueStore);
     method @NonNull public android.adservices.ondevicepersonalization.KeyValueStore getDownloadedContents();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class DownloadCompletedOutput {
+  public final class DownloadCompletedOutput {
     method @NonNull public java.util.List<java.lang.String> getRetainedKeys();
   }
 
@@ -25,13 +25,13 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.DownloadCompletedOutput.Builder setRetainedKeys(@NonNull java.util.List<java.lang.String>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class EventInput {
+  public final class EventInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public EventInput(@Nullable android.adservices.ondevicepersonalization.RequestLogRecord, @NonNull android.os.PersistableBundle);
     method @NonNull public android.os.PersistableBundle getParameters();
     method @Nullable public android.adservices.ondevicepersonalization.RequestLogRecord getRequestLogRecord();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class EventLogRecord implements android.os.Parcelable {
+  public final class EventLogRecord implements android.os.Parcelable {
     method public int describeContents();
     method @Nullable public android.content.ContentValues getData();
     method @Nullable public android.adservices.ondevicepersonalization.RequestLogRecord getRequestLogRecord();
@@ -51,7 +51,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.EventLogRecord.Builder setType(@IntRange(from=1, to=127) int);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class EventOutput {
+  public final class EventOutput {
     method @Nullable public android.adservices.ondevicepersonalization.EventLogRecord getEventLogRecord();
   }
 
@@ -61,7 +61,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.EventOutput.Builder setEventLogRecord(@Nullable android.adservices.ondevicepersonalization.EventLogRecord);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class EventUrlProvider {
+  public class EventUrlProvider {
     method @NonNull @WorkerThread public android.net.Uri createEventTrackingUrlWithRedirect(@NonNull android.os.PersistableBundle, @Nullable android.net.Uri);
     method @NonNull @WorkerThread public android.net.Uri createEventTrackingUrlWithResponse(@NonNull android.os.PersistableBundle, @Nullable byte[], @Nullable String);
   }
@@ -95,13 +95,13 @@ package android.adservices.ondevicepersonalization {
     field public static final int DEFAULT_BEST_VALUE = -1; // 0xffffffff
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class ExecuteInput {
+  public final class ExecuteInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public ExecuteInput(@NonNull String, @NonNull android.os.PersistableBundle);
     method @NonNull public String getAppPackageName();
     method @NonNull public android.os.PersistableBundle getAppParams();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class ExecuteOutput {
+  public final class ExecuteOutput {
     method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") @IntRange(from=android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceResponse.DEFAULT_BEST_VALUE) public int getBestValue();
     method @NonNull public java.util.List<android.adservices.ondevicepersonalization.EventLogRecord> getEventLogRecords();
     method @Nullable public byte[] getOutputData();
@@ -120,7 +120,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.ExecuteOutput.Builder setRequestLogRecord(@Nullable android.adservices.ondevicepersonalization.RequestLogRecord);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class FederatedComputeInput {
+  public final class FederatedComputeInput {
     method @NonNull public String getPopulationName();
   }
 
@@ -141,7 +141,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.FederatedComputeScheduleRequest getFederatedComputeScheduleRequest();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class FederatedComputeScheduler {
+  public class FederatedComputeScheduler {
     method @WorkerThread public void cancel(@NonNull android.adservices.ondevicepersonalization.FederatedComputeInput);
     method @WorkerThread public void schedule(@NonNull android.adservices.ondevicepersonalization.FederatedComputeScheduler.Params, @NonNull android.adservices.ondevicepersonalization.FederatedComputeInput);
     method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.fcp_schedule_with_outcome_receiver_enabled") @WorkerThread public void schedule(@NonNull android.adservices.ondevicepersonalization.FederatedComputeScheduleRequest, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.FederatedComputeScheduleResponse,java.lang.Exception>);
@@ -152,8 +152,9 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.TrainingInterval getTrainingInterval();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class InferenceInput {
+  public final class InferenceInput {
     method public int getBatchSize();
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") @NonNull public byte[] getData();
     method @NonNull public android.adservices.ondevicepersonalization.InferenceOutput getExpectedOutputStructure();
     method @NonNull public Object[] getInputData();
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Params getParams();
@@ -161,9 +162,11 @@ package android.adservices.ondevicepersonalization {
 
   public static final class InferenceInput.Builder {
     ctor public InferenceInput.Builder(@NonNull android.adservices.ondevicepersonalization.InferenceInput.Params, @NonNull Object[], @NonNull android.adservices.ondevicepersonalization.InferenceOutput);
+    ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") public InferenceInput.Builder(@NonNull android.adservices.ondevicepersonalization.InferenceInput.Params, @NonNull byte[]);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput build();
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Builder setBatchSize(int);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Builder setExpectedOutputStructure(@NonNull android.adservices.ondevicepersonalization.InferenceOutput);
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Builder setInputData(@NonNull byte[]);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Builder setInputData(@NonNull java.lang.Object...);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Builder setParams(@NonNull android.adservices.ondevicepersonalization.InferenceInput.Params);
   }
@@ -175,6 +178,7 @@ package android.adservices.ondevicepersonalization {
     method public int getModelType();
     method @IntRange(from=1) public int getRecommendedNumThreads();
     field public static final int DELEGATE_CPU = 1; // 0x1
+    field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") public static final int MODEL_TYPE_EXECUTORCH = 2; // 0x2
     field public static final int MODEL_TYPE_TENSORFLOW_LITE = 1; // 0x1
   }
 
@@ -188,7 +192,8 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.InferenceInput.Params.Builder setRecommendedNumThreads(@IntRange(from=1) int);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class InferenceOutput {
+  public final class InferenceOutput {
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") @NonNull public byte[] getData();
     method @NonNull public java.util.Map<java.lang.Integer,java.lang.Object> getDataOutputs();
   }
 
@@ -196,10 +201,11 @@ package android.adservices.ondevicepersonalization {
     ctor public InferenceOutput.Builder();
     method @NonNull public android.adservices.ondevicepersonalization.InferenceOutput.Builder addDataOutput(int, @NonNull Object);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceOutput build();
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.executorch_inference_api_enabled") @NonNull public android.adservices.ondevicepersonalization.InferenceOutput.Builder setData(@NonNull byte[]);
     method @NonNull public android.adservices.ondevicepersonalization.InferenceOutput.Builder setDataOutputs(@NonNull java.util.Map<java.lang.Integer,java.lang.Object>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public abstract class IsolatedService extends android.app.Service {
+  public abstract class IsolatedService extends android.app.Service {
     ctor public IsolatedService();
     method @NonNull public final android.adservices.ondevicepersonalization.EventUrlProvider getEventUrlProvider(@NonNull android.adservices.ondevicepersonalization.RequestToken);
     method @NonNull public final android.adservices.ondevicepersonalization.FederatedComputeScheduler getFederatedComputeScheduler(@NonNull android.adservices.ondevicepersonalization.RequestToken);
@@ -212,14 +218,14 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public abstract android.adservices.ondevicepersonalization.IsolatedWorker onRequest(@NonNull android.adservices.ondevicepersonalization.RequestToken);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class IsolatedServiceException extends java.lang.Exception {
+  public final class IsolatedServiceException extends java.lang.Exception {
     ctor public IsolatedServiceException(int);
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public IsolatedServiceException(int, @Nullable Throwable);
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public IsolatedServiceException(int, @Nullable String, @Nullable Throwable);
     method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public int getErrorCode();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public interface IsolatedWorker {
+  public interface IsolatedWorker {
     method public default void onDownloadCompleted(@NonNull android.adservices.ondevicepersonalization.DownloadCompletedInput, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.DownloadCompletedOutput,android.adservices.ondevicepersonalization.IsolatedServiceException>);
     method public default void onEvent(@NonNull android.adservices.ondevicepersonalization.EventInput, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.EventOutput,android.adservices.ondevicepersonalization.IsolatedServiceException>);
     method public default void onExecute(@NonNull android.adservices.ondevicepersonalization.ExecuteInput, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.ExecuteOutput,android.adservices.ondevicepersonalization.IsolatedServiceException>);
@@ -228,26 +234,26 @@ package android.adservices.ondevicepersonalization {
     method public default void onWebTrigger(@NonNull android.adservices.ondevicepersonalization.WebTriggerInput, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.WebTriggerOutput,android.adservices.ondevicepersonalization.IsolatedServiceException>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public interface KeyValueStore {
+  public interface KeyValueStore {
     method @Nullable @WorkerThread public byte[] get(@NonNull String);
     method @NonNull @WorkerThread public java.util.Set<java.lang.String> keySet();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class LogReader {
+  public class LogReader {
     method @NonNull @WorkerThread public java.util.List<android.adservices.ondevicepersonalization.EventLogRecord> getJoinedEvents(@NonNull java.time.Instant, @NonNull java.time.Instant);
     method @NonNull @WorkerThread public java.util.List<android.adservices.ondevicepersonalization.RequestLogRecord> getRequests(@NonNull java.time.Instant, @NonNull java.time.Instant);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class ModelManager {
+  public class ModelManager {
     method @WorkerThread public void run(@NonNull android.adservices.ondevicepersonalization.InferenceInput, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.InferenceOutput,java.lang.Exception>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public interface MutableKeyValueStore extends android.adservices.ondevicepersonalization.KeyValueStore {
+  public interface MutableKeyValueStore extends android.adservices.ondevicepersonalization.KeyValueStore {
     method @Nullable @WorkerThread public byte[] put(@NonNull String, @NonNull byte[]);
     method @Nullable @WorkerThread public byte[] remove(@NonNull String);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class OnDevicePersonalizationException extends java.lang.Exception {
+  public class OnDevicePersonalizationException extends java.lang.Exception {
     method public int getErrorCode();
     field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public static final int ERROR_INFERENCE_FAILED = 9; // 0x9
     field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public static final int ERROR_INFERENCE_MODEL_NOT_FOUND = 8; // 0x8
@@ -260,10 +266,14 @@ package android.adservices.ondevicepersonalization {
     field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public static final int ERROR_SCHEDULE_TRAINING_FAILED = 6; // 0x6
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class OnDevicePersonalizationManager {
+  public class OnDevicePersonalizationManager {
     method public void execute(@NonNull android.content.ComponentName, @NonNull android.os.PersistableBundle, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.OnDevicePersonalizationManager.ExecuteResult,java.lang.Exception>);
     method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public void executeInIsolatedService(@NonNull android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceRequest, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceResponse,java.lang.Exception>);
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.is_feature_enabled_api_enabled") public void queryFeatureAvailability(@NonNull String, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Integer,java.lang.Exception>);
     method public void requestSurfacePackage(@NonNull android.adservices.ondevicepersonalization.SurfacePackageToken, @NonNull android.os.IBinder, int, int, int, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.view.SurfaceControlViewHost.SurfacePackage,java.lang.Exception>);
+    field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.is_feature_enabled_api_enabled") public static final int FEATURE_DISABLED = 1; // 0x1
+    field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.is_feature_enabled_api_enabled") public static final int FEATURE_ENABLED = 0; // 0x0
+    field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.is_feature_enabled_api_enabled") public static final int FEATURE_UNSUPPORTED = 2; // 0x2
   }
 
   public static class OnDevicePersonalizationManager.ExecuteResult {
@@ -271,14 +281,14 @@ package android.adservices.ondevicepersonalization {
     method @Nullable public android.adservices.ondevicepersonalization.SurfacePackageToken getSurfacePackageToken();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class RenderInput {
+  public final class RenderInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public RenderInput(int, int, @Nullable android.adservices.ondevicepersonalization.RenderingConfig);
     method public int getHeight();
     method @Nullable public android.adservices.ondevicepersonalization.RenderingConfig getRenderingConfig();
     method public int getWidth();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class RenderOutput {
+  public final class RenderOutput {
     method @Nullable public String getContent();
     method @Nullable public String getTemplateId();
     method @NonNull public android.os.PersistableBundle getTemplateParams();
@@ -292,7 +302,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.RenderOutput.Builder setTemplateParams(@NonNull android.os.PersistableBundle);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class RenderingConfig implements android.os.Parcelable {
+  public final class RenderingConfig implements android.os.Parcelable {
     method public int describeContents();
     method @NonNull public java.util.List<java.lang.String> getKeys();
     method public void writeToParcel(@NonNull android.os.Parcel, int);
@@ -306,7 +316,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.RenderingConfig.Builder setKeys(@NonNull java.util.List<java.lang.String>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class RequestLogRecord implements android.os.Parcelable {
+  public final class RequestLogRecord implements android.os.Parcelable {
     method public int describeContents();
     method @NonNull public java.util.List<android.content.ContentValues> getRows();
     method @NonNull public java.time.Instant getTime();
@@ -321,13 +331,13 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.RequestLogRecord.Builder setRows(@NonNull java.util.List<android.content.ContentValues>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class RequestToken {
+  public class RequestToken {
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class SurfacePackageToken {
+  public class SurfacePackageToken {
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class TrainingExampleRecord implements android.os.Parcelable {
+  public final class TrainingExampleRecord implements android.os.Parcelable {
     method public int describeContents();
     method @Nullable public byte[] getResumptionToken();
     method @Nullable public byte[] getTrainingExample();
@@ -342,7 +352,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.TrainingExampleRecord.Builder setTrainingExample(@Nullable byte...);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class TrainingExamplesInput {
+  public final class TrainingExamplesInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public TrainingExamplesInput(@NonNull String, @NonNull String, @Nullable byte[], @Nullable String);
     method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.fcp_model_version_enabled") @Nullable public String getCollectionName();
     method @NonNull public String getPopulationName();
@@ -350,7 +360,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public String getTaskName();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class TrainingExamplesOutput {
+  public final class TrainingExamplesOutput {
     method @NonNull public java.util.List<android.adservices.ondevicepersonalization.TrainingExampleRecord> getTrainingExampleRecords();
   }
 
@@ -361,7 +371,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.TrainingExamplesOutput.Builder setTrainingExampleRecords(@NonNull java.util.List<android.adservices.ondevicepersonalization.TrainingExampleRecord>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class TrainingInterval {
+  public final class TrainingInterval {
     method @NonNull public java.time.Duration getMinimumInterval();
     method public int getSchedulingMode();
     field public static final int SCHEDULING_MODE_ONE_TIME = 1; // 0x1
@@ -375,7 +385,7 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.TrainingInterval.Builder setSchedulingMode(int);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class UserData implements android.os.Parcelable {
+  public final class UserData implements android.os.Parcelable {
     method public int describeContents();
     method @NonNull public java.util.Map<java.lang.String,android.adservices.ondevicepersonalization.AppInfo> getAppInfos();
     method @IntRange(from=0) public long getAvailableStorageBytes();
@@ -389,14 +399,14 @@ package android.adservices.ondevicepersonalization {
     field @NonNull public static final android.os.Parcelable.Creator<android.adservices.ondevicepersonalization.UserData> CREATOR;
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class WebTriggerInput {
+  public final class WebTriggerInput {
     ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled") public WebTriggerInput(@NonNull android.net.Uri, @NonNull String, @NonNull byte[]);
     method @NonNull public String getAppPackageName();
     method @NonNull public byte[] getData();
     method @NonNull public android.net.Uri getDestinationUrl();
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class WebTriggerOutput {
+  public final class WebTriggerOutput {
     method @NonNull public java.util.List<android.adservices.ondevicepersonalization.EventLogRecord> getEventLogRecords();
     method @Nullable public android.adservices.ondevicepersonalization.RequestLogRecord getRequestLogRecord();
   }
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index 18919c8f..221fefb2 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -1,7 +1,7 @@
 // Signature format: 2.0
 package android.adservices.ondevicepersonalization {
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public final class MeasurementWebTriggerEventParams {
+  public final class MeasurementWebTriggerEventParams {
     method @NonNull public String getAppPackageName();
     method @Nullable public String getCertDigest();
     method @NonNull public android.net.Uri getDestinationUrl();
@@ -19,16 +19,16 @@ package android.adservices.ondevicepersonalization {
     method @NonNull public android.adservices.ondevicepersonalization.MeasurementWebTriggerEventParams.Builder setIsolatedService(@NonNull android.content.ComponentName);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class OnDevicePersonalizationConfigManager {
+  public class OnDevicePersonalizationConfigManager {
     method @RequiresPermission(android.adservices.ondevicepersonalization.OnDevicePersonalizationPermissions.MODIFY_ONDEVICEPERSONALIZATION_STATE) public void setPersonalizationEnabled(boolean, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class OnDevicePersonalizationPermissions {
+  public class OnDevicePersonalizationPermissions {
     field public static final String MODIFY_ONDEVICEPERSONALIZATION_STATE = "android.permission.ondevicepersonalization.MODIFY_ONDEVICEPERSONALIZATION_STATE";
     field public static final String NOTIFY_MEASUREMENT_EVENT = "android.permission.ondevicepersonalization.NOTIFY_MEASUREMENT_EVENT";
   }
 
-  @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled") public class OnDevicePersonalizationSystemEventManager {
+  public class OnDevicePersonalizationSystemEventManager {
     method @RequiresPermission(android.adservices.ondevicepersonalization.OnDevicePersonalizationPermissions.NOTIFY_MEASUREMENT_EVENT) public void notifyMeasurementEvent(@NonNull android.adservices.ondevicepersonalization.MeasurementWebTriggerEventParams, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
   }
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/AppInfo.java b/framework/java/android/adservices/ondevicepersonalization/AppInfo.java
index 4d462b83..bdec7a75 100644
--- a/framework/java/android/adservices/ondevicepersonalization/AppInfo.java
+++ b/framework/java/android/adservices/ondevicepersonalization/AppInfo.java
@@ -28,7 +28,6 @@ import com.android.ondevicepersonalization.internal.util.DataClass;
  * Information about apps.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genHiddenBuilder = true, genEqualsHashCode = true)
 public final class AppInfo implements Parcelable {
     /** Whether the app is installed. */
diff --git a/framework/java/android/adservices/ondevicepersonalization/Constants.java b/framework/java/android/adservices/ondevicepersonalization/Constants.java
index 09ad701f..c5d5a806 100644
--- a/framework/java/android/adservices/ondevicepersonalization/Constants.java
+++ b/framework/java/android/adservices/ondevicepersonalization/Constants.java
@@ -54,7 +54,7 @@ public class Constants {
     /** Internal error code that tracks error when the FCP manifest is invalid or missing. */
     public static final int STATUS_FCP_MANIFEST_INVALID = 110;
 
-    /** Internal code that tracks empty result returned from data storage. */
+    /** Internal code that tracks empty result returned from data storage or example store. */
     public static final int STATUS_SUCCESS_EMPTY_RESULT = 111;
 
     /** Internal code that tracks timeout exception when run operation. */
@@ -62,9 +62,37 @@ public class Constants {
 
     /** Internal code that tracks remote exception when run operation. */
     public static final int STATUS_REMOTE_EXCEPTION = 113;
+
     /** Internal code that tracks method not found. */
     public static final int STATUS_METHOD_NOT_FOUND = 114;
+
     public static final int STATUS_CALLER_NOT_ALLOWED = 115;
+    public static final int STATUS_NULL_ADSERVICES_COMMON_MANAGER = 116;
+
+    // Internal code that tracks data access not included result returned from data storage.
+    public static final int STATUS_PERMISSION_DENIED = 117;
+    // Internal code that tracks local data read only result returned from data storage.
+    public static final int STATUS_LOCAL_DATA_READ_ONLY = 118;
+    // Internal code that tracks thread interrupted exception errors.
+    public static final int STATUS_EXECUTION_INTERRUPTED = 119;
+    // Internal code that tracks request timestamps invalid.
+    public static final int STATUS_REQUEST_TIMESTAMPS_INVALID = 120;
+    // Internal code that tracks request model table id invalid.
+    public static final int STATUS_MODEL_TABLE_ID_INVALID = 122;
+    // Internal code that tracks request model DB lookup failed.
+    public static final int STATUS_MODEL_DB_LOOKUP_FAILED = 123;
+    // Internal code that tracks request model lookup generic failure.
+    public static final int STATUS_MODEL_LOOKUP_FAILURE = 124;
+    // Internal code that tracks unsupported operation failure.
+    public static final int STATUS_DATA_ACCESS_UNSUPPORTED_OP = 125;
+    // Internal code that tracks generic data access failure.
+    public static final int STATUS_DATA_ACCESS_FAILURE = 126;
+    // Internal code that tracks local data access failure.
+    public static final int STATUS_LOCAL_WRITE_DATA_ACCESS_FAILURE = 127;
+    // Internal code that tracks parsing error.
+    public static final int STATUS_PARSE_ERROR = 128;
+    // Internal code that tracks non-empty but not enough data from data storage or example store.
+    public static final int STATUS_SUCCESS_NOT_ENOUGH_DATA = 129;
 
     // Operations implemented by IsolatedService.
     public static final int OP_EXECUTE = 1;
@@ -141,6 +169,7 @@ public class Constants {
     public static final int API_NAME_FEDERATED_COMPUTE_CANCEL = 21;
     public static final int API_NAME_NOTIFY_MEASUREMENT_EVENT = 22;
     public static final int API_NAME_ADSERVICES_GET_COMMON_STATES = 23;
+    public static final int API_NAME_IS_FEATURE_ENABLED = 24;
 
     // Data Access Service operations.
     public static final int DATA_ACCESS_OP_REMOTE_DATA_LOOKUP = 1;
@@ -157,5 +186,33 @@ public class Constants {
     // Measurement event types for measurement events received from the OS.
     public static final int MEASUREMENT_EVENT_TYPE_WEB_TRIGGER = 1;
 
+    // Task type for trace event logging. Must match the values in
+    // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+    public static final int TASK_TYPE_EXECUTE = 1;
+    public static final int TASK_TYPE_RENDER = 2;
+    public static final int TASK_TYPE_DOWNLOAD = 3;
+    public static final int TASK_TYPE_WEBVIEW = 4;
+    public static final int TASK_TYPE_TRAINING = 5;
+    public static final int TASK_TYPE_MAINTENANCE = 6;
+    public static final int TASK_TYPE_WEB_TRIGGER = 7;
+
+    // Event type for trace event logging. Must match the values in
+    // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+    public static final int EVENT_TYPE_UNKNOWN = 1;
+    public static final int EVENT_TYPE_WRITE_REQUEST_LOG = 2;
+    public static final int EVENT_TYPE_WRITE_EVENT_LOG = 3;
+
+    // Status for trace event logging. Must match the values in
+    // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+    public static final int STATUS_REQUEST_LOG_DB_SUCCESS = 1;
+    public static final int STATUS_EVENT_LOG_DB_SUCCESS = 2;
+    public static final int STATUS_LOG_DB_FAILURE = 3;
+    public static final int STATUS_LOG_EXCEPTION = 4;
+    public static final int STATUS_REQUEST_LOG_IS_NULL = 5;
+    public static final int STATUS_REQUEST_LOG_IS_EMPTY = 6;
+    public static final int STATUS_EVENT_LOG_IS_NULL = 7;
+    public static final int STATUS_EVENT_LOG_NOT_EXIST = 8;
+    public static final int STATUS_EVENT_LOG_QUERY_NOT_EXIST = 9;
+
     private Constants() {}
 }
diff --git a/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedInput.java b/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedInput.java
index 05714b0f..24e04eb4 100644
--- a/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedInput.java
@@ -29,7 +29,6 @@ import java.util.Objects;
  * IsolatedWorker#onDownloadCompleted(DownloadCompletedInput, android.os.OutcomeReceiver)}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class DownloadCompletedInput {
     /**
      * A {@link KeyValueStore} that contains the downloaded content.
diff --git a/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedOutput.java b/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedOutput.java
index 538e17cc..d847a810 100644
--- a/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/DownloadCompletedOutput.java
@@ -16,10 +16,8 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -31,7 +29,6 @@ import java.util.List;
  * IsolatedWorker#onDownloadCompleted(DownloadCompletedInput, android.os.OutcomeReceiver)}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class DownloadCompletedOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/EventInput.java b/framework/java/android/adservices/ondevicepersonalization/EventInput.java
index f3f0bee8..a4939ff6 100644
--- a/framework/java/android/adservices/ondevicepersonalization/EventInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/EventInput.java
@@ -29,7 +29,6 @@ import java.util.Objects;
  * The input data for {@link
  * IsolatedWorker#onEvent(EventInput, android.os.OutcomeReceiver)}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class EventInput {
     /**
      * The {@link RequestLogRecord} that was returned as a result of
diff --git a/framework/java/android/adservices/ondevicepersonalization/EventLogRecord.java b/framework/java/android/adservices/ondevicepersonalization/EventLogRecord.java
index 54ab70c6..e8ab7dde 100644
--- a/framework/java/android/adservices/ondevicepersonalization/EventLogRecord.java
+++ b/framework/java/android/adservices/ondevicepersonalization/EventLogRecord.java
@@ -16,14 +16,12 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.IntRange;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.ContentValues;
 import android.os.Parcelable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -42,7 +40,6 @@ import java.time.Instant;
  * consumed by Federated Learning facilitated model training, or Federated Analytics facilitated
  * cross-device statistical analysis.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class EventLogRecord implements Parcelable {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/EventOutput.java b/framework/java/android/adservices/ondevicepersonalization/EventOutput.java
index d44031e7..f0b09f79 100644
--- a/framework/java/android/adservices/ondevicepersonalization/EventOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/EventOutput.java
@@ -16,16 +16,13 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.Nullable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /**
  *  The result returned by {@link IsolatedWorker#onEvent(EventInput, android.os.OutcomeReceiver)}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class EventOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/EventUrlProvider.java b/framework/java/android/adservices/ondevicepersonalization/EventUrlProvider.java
index 5abd17b0..4bf42149 100644
--- a/framework/java/android/adservices/ondevicepersonalization/EventUrlProvider.java
+++ b/framework/java/android/adservices/ondevicepersonalization/EventUrlProvider.java
@@ -18,7 +18,6 @@ package android.adservices.ondevicepersonalization;
 
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.WorkerThread;
@@ -27,7 +26,6 @@ import android.os.Bundle;
 import android.os.PersistableBundle;
 import android.os.RemoteException;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 
 import java.util.Objects;
@@ -42,7 +40,6 @@ import java.util.concurrent.BlockingQueue;
  * output in the EVENTS table.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class EventUrlProvider {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = EventUrlProvider.class.getSimpleName();
diff --git a/framework/java/android/adservices/ondevicepersonalization/ExecuteInput.java b/framework/java/android/adservices/ondevicepersonalization/ExecuteInput.java
index e3c93ea4..fcd1ca88 100644
--- a/framework/java/android/adservices/ondevicepersonalization/ExecuteInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/ExecuteInput.java
@@ -31,7 +31,6 @@ import java.util.Objects;
  * The input data for {@link IsolatedWorker#onExecute(ExecuteInput, android.os.OutcomeReceiver)}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class ExecuteInput {
     @NonNull private final String mAppPackageName;
     @NonNull private final Object mAppParamsLock = new Object();
diff --git a/framework/java/android/adservices/ondevicepersonalization/ExecuteOutput.java b/framework/java/android/adservices/ondevicepersonalization/ExecuteOutput.java
index 7c8468fa..043f551b 100644
--- a/framework/java/android/adservices/ondevicepersonalization/ExecuteOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/ExecuteOutput.java
@@ -38,7 +38,6 @@ import java.util.List;
  * in response to a call to {@code OnDevicePersonalizationManager#execute(ComponentName,
  * PersistableBundle, java.util.concurrent.Executor, OutcomeReceiver)} from a client app.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class ExecuteOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeInput.java b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeInput.java
index b2051e6b..6dbef84f 100644
--- a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeInput.java
@@ -16,16 +16,13 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /** The input data for {@link FederatedComputeScheduler#schedule}. */
 @DataClass(genBuilder = true, genEqualsHashCode = true)
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class FederatedComputeInput {
     // TODO(b/300461799): add federated compute server document.
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
index 17bddc24..a338494e 100644
--- a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
+++ b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
@@ -36,7 +36,6 @@ import java.util.concurrent.TimeUnit;
  * Handles scheduling federated compute jobs. See {@link
  * IsolatedService#getFederatedComputeScheduler}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class FederatedComputeScheduler {
     private static final String TAG = FederatedComputeScheduler.class.getSimpleName();
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java b/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java
index 24f3f4ff..0d7f5e16 100644
--- a/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java
@@ -16,6 +16,9 @@
 
 package android.adservices.ondevicepersonalization;
 
+import static com.android.ondevicepersonalization.internal.util.ByteArrayUtil.deserializeObject;
+import static com.android.ondevicepersonalization.internal.util.ByteArrayUtil.serializeObject;
+
 import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.IntRange;
@@ -23,37 +26,39 @@ import android.annotation.NonNull;
 import android.annotation.SuppressLint;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
-import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
-import com.android.ondevicepersonalization.internal.util.DataClass;
+import com.android.internal.util.Preconditions;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.util.Objects;
 
 /**
  * Contains all the information needed for a run of model inference. The input of {@link
  * ModelManager#run}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
-@DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class InferenceInput {
     /** The configuration that controls runtime interpreter behavior. */
     @NonNull private Params mParams;
 
     /**
-     * An array of input data. The inputs should be in the same order as inputs of the model.
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
      *
-     * <p>For example, if a model takes multiple inputs:
+     * <p>For LiteRT, this field is mapped to inputs of runForMultipleInputsOutputs:
+     * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
      *
      * <pre>{@code
      * String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
      * int[] input1 = new int[]{3, 2, 1}; // int tensor shape is [3].
      * Object[] inputData = {input0, input1, ...};
+     * byte[] data = serializeObject(inputData);
      * }</pre>
      *
-     * For TFLite, this field is mapped to inputs of runForMultipleInputsOutputs:
-     * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     * <p>For Executorch model, this field is a serialized EValue array.
+     *
+     * @hide
      */
-    @NonNull private Object[] mInputData;
+    @NonNull private byte[] mData;
 
     /**
      * The number of input examples. Adopter can set this field to run batching inference. The batch
@@ -62,7 +67,7 @@ public final class InferenceInput {
     private int mBatchSize = 1;
 
     /**
-     * The empty InferenceOutput representing the expected output structure. For TFLite, the
+     * The empty InferenceOutput representing the expected output structure. For LiteRT, the
      * inference code will verify whether this expected output structure matches model output
      * signature.
      *
@@ -77,18 +82,11 @@ public final class InferenceInput {
      */
     @NonNull private InferenceOutput mExpectedOutputStructure;
 
-    @DataClass(genBuilder = true, genHiddenConstructor = true, genEqualsHashCode = true)
     public static class Params {
-        /**
-         * A {@link KeyValueStore} where pre-trained model is stored. Only supports TFLite model
-         * now.
-         */
+        /** A {@link KeyValueStore} where pre-trained model is stored. */
         @NonNull private KeyValueStore mKeyValueStore;
 
-        /**
-         * The key of the table where the corresponding value stores a pre-trained model. Only
-         * supports TFLite model now.
-         */
+        /** The key of the table where the corresponding value stores a pre-trained model. */
         @NonNull private String mModelKey;
 
         /** The model inference will run on CPU. */
@@ -114,6 +112,10 @@ public final class InferenceInput {
         /** The model is a tensorflow lite model. */
         public static final int MODEL_TYPE_TENSORFLOW_LITE = 1;
 
+        /** The model is an executorch model. */
+        @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+        public static final int MODEL_TYPE_EXECUTORCH = 2;
+
         /**
          * The type of the model.
          *
@@ -121,13 +123,13 @@ public final class InferenceInput {
          */
         @IntDef(
                 prefix = "MODEL_TYPE",
-                value = {MODEL_TYPE_TENSORFLOW_LITE})
+                value = {MODEL_TYPE_TENSORFLOW_LITE, MODEL_TYPE_EXECUTORCH})
         @Retention(RetentionPolicy.SOURCE)
         public @interface ModelType {}
 
         /**
          * The type of the pre-trained model. If not set, the default value is {@link
-         * #MODEL_TYPE_TENSORFLOW_LITE} . Only supports {@link #MODEL_TYPE_TENSORFLOW_LITE} for now.
+         * #MODEL_TYPE_TENSORFLOW_LITE} .
          */
         private @ModelType int mModelType = MODEL_TYPE_TENSORFLOW_LITE;
 
@@ -138,71 +140,58 @@ public final class InferenceInput {
          */
         private @IntRange(from = 1) int mRecommendedNumThreads = 1;
 
-        // Code below generated by codegen v1.0.23.
-        //
-        // DO NOT MODIFY!
-        // CHECKSTYLE:OFF Generated code
-        //
-        // To regenerate run:
-        // $ codegen
-        // $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java
-        //
-        // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
-        //   Settings > Editor > Code Style > Formatter Control
-        // @formatter:off
-
         /**
          * Creates a new Params.
          *
-         * @param keyValueStore A {@link KeyValueStore} where pre-trained model is stored. Only
-         *     supports TFLite model now.
+         * @param keyValueStore A {@link KeyValueStore} where pre-trained model is stored.
          * @param modelKey The key of the table where the corresponding value stores a pre-trained
-         *     model. Only supports TFLite model now.
+         *     model.
          * @param delegateType The delegate to run model inference. If not set, the default value is
          *     {@link #DELEGATE_CPU}.
          * @param modelType The type of the pre-trained model. If not set, the default value is
-         *     {@link #MODEL_TYPE_TENSORFLOW_LITE} . Only supports {@link
-         *     #MODEL_TYPE_TENSORFLOW_LITE} for now.
+         *     {@link #MODEL_TYPE_TENSORFLOW_LITE} .
          * @param recommendedNumThreads The number of threads used for intraop parallelism on CPU,
          *     must be positive number. Adopters can set this field based on model architecture. The
          *     actual thread number depends on system resources and other constraints.
          * @hide
          */
-        @DataClass.Generated.Member
         public Params(
                 @NonNull KeyValueStore keyValueStore,
                 @NonNull String modelKey,
                 @Delegate int delegateType,
                 @ModelType int modelType,
                 @IntRange(from = 1) int recommendedNumThreads) {
-            this.mKeyValueStore = keyValueStore;
-            AnnotationValidations.validate(NonNull.class, null, mKeyValueStore);
-            this.mModelKey = modelKey;
-            AnnotationValidations.validate(NonNull.class, null, mModelKey);
+            this.mKeyValueStore = Objects.requireNonNull(keyValueStore);
+            this.mModelKey = Objects.requireNonNull(modelKey);
             this.mDelegateType = delegateType;
-            AnnotationValidations.validate(Delegate.class, null, mDelegateType);
             this.mModelType = modelType;
-            AnnotationValidations.validate(ModelType.class, null, mModelType);
-            this.mRecommendedNumThreads = recommendedNumThreads;
-            AnnotationValidations.validate(IntRange.class, null, mRecommendedNumThreads, "from", 1);
 
-            // onConstructed(); // You can define this method to get a callback
+            if (!(mModelType == MODEL_TYPE_TENSORFLOW_LITE)
+                    && !(mModelType == MODEL_TYPE_EXECUTORCH)) {
+                throw new java.lang.IllegalArgumentException(
+                        "modelType was "
+                                + mModelType
+                                + " but must be one of: "
+                                + "MODEL_TYPE_TENSORFLOW_LITE("
+                                + MODEL_TYPE_TENSORFLOW_LITE
+                                + "), "
+                                + "MODEL_TYPE_EXECUTORCH("
+                                + MODEL_TYPE_EXECUTORCH
+                                + ")");
+            }
+
+            this.mRecommendedNumThreads = recommendedNumThreads;
+            Preconditions.checkState(
+                    recommendedNumThreads >= 1,
+                    "recommend thread number should be large or equal to 1");
         }
 
-        /**
-         * A {@link KeyValueStore} where pre-trained model is stored. Only supports TFLite model
-         * now.
-         */
-        @DataClass.Generated.Member
+        /** A {@link KeyValueStore} where pre-trained model is stored. */
         public @NonNull KeyValueStore getKeyValueStore() {
             return mKeyValueStore;
         }
 
-        /**
-         * The key of the table where the corresponding value stores a pre-trained model. Only
-         * supports TFLite model now.
-         */
-        @DataClass.Generated.Member
+        /** The key of the table where the corresponding value stores a pre-trained model. */
         public @NonNull String getModelKey() {
             return mModelKey;
         }
@@ -211,16 +200,14 @@ public final class InferenceInput {
          * The delegate to run model inference. If not set, the default value is {@link
          * #DELEGATE_CPU}.
          */
-        @DataClass.Generated.Member
         public @Delegate int getDelegateType() {
             return mDelegateType;
         }
 
         /**
          * The type of the pre-trained model. If not set, the default value is {@link
-         * #MODEL_TYPE_TENSORFLOW_LITE} . Only supports {@link #MODEL_TYPE_TENSORFLOW_LITE} for now.
+         * #MODEL_TYPE_TENSORFLOW_LITE} .
          */
-        @DataClass.Generated.Member
         public @ModelType int getModelType() {
             return mModelType;
         }
@@ -230,13 +217,11 @@ public final class InferenceInput {
          * Adopters can set this field based on model architecture. The actual thread number depends
          * on system resources and other constraints.
          */
-        @DataClass.Generated.Member
         public @IntRange(from = 1) int getRecommendedNumThreads() {
             return mRecommendedNumThreads;
         }
 
         @Override
-        @DataClass.Generated.Member
         public boolean equals(@android.annotation.Nullable Object o) {
             // You can override field equality logic by defining either of the methods like:
             // boolean fieldNameEquals(Params other) { ... }
@@ -256,7 +241,6 @@ public final class InferenceInput {
         }
 
         @Override
-        @DataClass.Generated.Member
         public int hashCode() {
             // You can override field hashCode logic by defining methods like:
             // int fieldNameHashCode() { ... }
@@ -272,7 +256,6 @@ public final class InferenceInput {
 
         /** A builder for {@link Params} */
         @SuppressWarnings("WeakerAccess")
-        @DataClass.Generated.Member
         public static final class Builder {
 
             private @NonNull KeyValueStore mKeyValueStore;
@@ -286,34 +269,23 @@ public final class InferenceInput {
             /**
              * Creates a new Builder.
              *
-             * @param keyValueStore A {@link KeyValueStore} where pre-trained model is stored. Only
-             *     supports TFLite model now.
-             * @param modelKey The key of the table where the corresponding value stores a
-             *     pre-trained model. Only supports TFLite model now.
+             * @param keyValueStore a {@link KeyValueStore} where pre-trained model is stored.
+             * @param modelKey key of the table where the corresponding value stores a pre-trained
+             *     model.
              */
             public Builder(@NonNull KeyValueStore keyValueStore, @NonNull String modelKey) {
-                mKeyValueStore = keyValueStore;
-                AnnotationValidations.validate(NonNull.class, null, mKeyValueStore);
-                mModelKey = modelKey;
-                AnnotationValidations.validate(NonNull.class, null, mModelKey);
+                mKeyValueStore = Objects.requireNonNull(keyValueStore);
+                mModelKey = Objects.requireNonNull(modelKey);
             }
 
-            /**
-             * A {@link KeyValueStore} where pre-trained model is stored. Only supports TFLite model
-             * now.
-             */
-            @DataClass.Generated.Member
+            /** A {@link KeyValueStore} where pre-trained model is stored. */
             public @NonNull Builder setKeyValueStore(@NonNull KeyValueStore value) {
                 mBuilderFieldsSet |= 0x1;
                 mKeyValueStore = value;
                 return this;
             }
 
-            /**
-             * The key of the table where the corresponding value stores a pre-trained model. Only
-             * supports TFLite model now.
-             */
-            @DataClass.Generated.Member
+            /** The key of the table where the corresponding value stores a pre-trained model. */
             public @NonNull Builder setModelKey(@NonNull String value) {
                 mBuilderFieldsSet |= 0x2;
                 mModelKey = value;
@@ -324,7 +296,6 @@ public final class InferenceInput {
              * The delegate to run model inference. If not set, the default value is {@link
              * #DELEGATE_CPU}.
              */
-            @DataClass.Generated.Member
             public @NonNull Builder setDelegateType(@Delegate int value) {
                 mBuilderFieldsSet |= 0x4;
                 mDelegateType = value;
@@ -333,10 +304,8 @@ public final class InferenceInput {
 
             /**
              * The type of the pre-trained model. If not set, the default value is {@link
-             * #MODEL_TYPE_TENSORFLOW_LITE} . Only supports {@link #MODEL_TYPE_TENSORFLOW_LITE} for
-             * now.
+             * #MODEL_TYPE_TENSORFLOW_LITE} .
              */
-            @DataClass.Generated.Member
             public @NonNull Builder setModelType(@ModelType int value) {
                 mBuilderFieldsSet |= 0x8;
                 mModelType = value;
@@ -348,14 +317,13 @@ public final class InferenceInput {
              * Adopters can set this field based on model architecture. The actual thread number
              * depends on system resources and other constraints.
              */
-            @DataClass.Generated.Member
             public @NonNull Builder setRecommendedNumThreads(@IntRange(from = 1) int value) {
                 mBuilderFieldsSet |= 0x10;
                 mRecommendedNumThreads = value;
                 return this;
             }
 
-            /** Builds the instance. */
+            /** Builds the instance. This builder should not be touched after calling this! */
             public @NonNull Params build() {
                 mBuilderFieldsSet |= 0x20; // Mark builder used
 
@@ -378,60 +346,49 @@ public final class InferenceInput {
                 return o;
             }
         }
-
-        @DataClass.Generated(
-                time = 1709250081597L,
-                codegenVersion = "1.0.23",
-                sourceFile =
-                        "packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java",
-                inputSignatures =
-                        "private @android.annotation.NonNull android.adservices.ondevicepersonalization.KeyValueStore mKeyValueStore\nprivate @android.annotation.NonNull java.lang.String mModelKey\npublic static final  int DELEGATE_CPU\nprivate @android.adservices.ondevicepersonalization.Params.Delegate int mDelegateType\npublic static final  int MODEL_TYPE_TENSORFLOW_LITE\nprivate @android.adservices.ondevicepersonalization.Params.ModelType int mModelType\nprivate @android.annotation.IntRange int mRecommendedNumThreads\nclass Params extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genHiddenConstructor=true, genEqualsHashCode=true)")
-        @Deprecated
-        private void __metadata() {}
-
-        // @formatter:on
-        // End of generated code
-
     }
 
-    // Code below generated by codegen v1.0.23.
-    //
-    // DO NOT MODIFY!
-    // CHECKSTYLE:OFF Generated code
-    //
-    // To regenerate run:
-    // $ codegen
-    // $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java
-    //
-    // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
-    //   Settings > Editor > Code Style > Formatter Control
-    // @formatter:off
-
-    @DataClass.Generated.Member
     /* package-private */ InferenceInput(
             @NonNull Params params,
-            @NonNull Object[] inputData,
+            @NonNull byte[] data,
             int batchSize,
             @NonNull InferenceOutput expectedOutputStructure) {
-        this.mParams = params;
-        AnnotationValidations.validate(NonNull.class, null, mParams);
-        this.mInputData = inputData;
-        AnnotationValidations.validate(NonNull.class, null, mInputData);
+        this.mParams = Objects.requireNonNull(params);
+        this.mData = Objects.requireNonNull(data);
         this.mBatchSize = batchSize;
-        this.mExpectedOutputStructure = expectedOutputStructure;
-        AnnotationValidations.validate(NonNull.class, null, mExpectedOutputStructure);
-
-        // onConstructed(); // You can define this method to get a callback
+        this.mExpectedOutputStructure = Objects.requireNonNull(expectedOutputStructure);
     }
 
     /** The configuration that controls runtime interpreter behavior. */
-    @DataClass.Generated.Member
     public @NonNull Params getParams() {
         return mParams;
     }
 
     /**
-     * An array of input data. The inputs should be in the same order as inputs of the model.
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     *
+     * <p>For LiteRT, this field is mapped to inputs of runForMultipleInputsOutputs:
+     * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *
+     * <pre>{@code
+     * String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
+     * int[] input1 = new int[]{3, 2, 1}; // int tensor shape is [3].
+     * Object[] inputData = {input0, input1, ...};
+     * byte[] data = serializeObject(inputData);
+     * }</pre>
+     *
+     * <p>For Executorch model, this field is a serialized EValue array.
+     */
+    @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+    public @NonNull byte[] getData() {
+        return mData;
+    }
+
+    /**
+     * Note: use {@link InferenceInput#getData()} instead.
+     *
+     * <p>An array of input data. The inputs should be in the same order as inputs of the model.
      *
      * <p>For example, if a model takes multiple inputs:
      *
@@ -441,26 +398,24 @@ public final class InferenceInput {
      * Object[] inputData = {input0, input1, ...};
      * }</pre>
      *
-     * For TFLite, this field is mapped to inputs of runForMultipleInputsOutputs:
+     * For LiteRT, this field is mapped to inputs of runForMultipleInputsOutputs:
      * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
      */
     @SuppressLint("ArrayReturn")
-    @DataClass.Generated.Member
     public @NonNull Object[] getInputData() {
-        return mInputData;
+        return (Object[]) deserializeObject(mData);
     }
 
     /**
      * The number of input examples. Adopter can set this field to run batching inference. The batch
      * size is 1 by default. The batch size should match the input data size.
      */
-    @DataClass.Generated.Member
     public int getBatchSize() {
         return mBatchSize;
     }
 
     /**
-     * The empty InferenceOutput representing the expected output structure. For TFLite, the
+     * The empty InferenceOutput representing the expected output structure. For LiteRT, the
      * inference code will verify whether this expected output structure matches model output
      * signature.
      *
@@ -473,13 +428,11 @@ public final class InferenceInput {
      * expectedOutputStructure = new InferenceOutput.Builder().setDataOutputs(outputs).build();
      * }</pre>
      */
-    @DataClass.Generated.Member
     public @NonNull InferenceOutput getExpectedOutputStructure() {
         return mExpectedOutputStructure;
     }
 
     @Override
-    @DataClass.Generated.Member
     public boolean equals(@android.annotation.Nullable Object o) {
         // You can override field equality logic by defining either of the methods like:
         // boolean fieldNameEquals(InferenceInput other) { ... }
@@ -492,21 +445,20 @@ public final class InferenceInput {
         //noinspection PointlessBooleanExpression
         return true
                 && java.util.Objects.equals(mParams, that.mParams)
-                && java.util.Arrays.equals(mInputData, that.mInputData)
+                && java.util.Arrays.equals(mData, that.mData)
                 && mBatchSize == that.mBatchSize
                 && java.util.Objects.equals(
                         mExpectedOutputStructure, that.mExpectedOutputStructure);
     }
 
     @Override
-    @DataClass.Generated.Member
     public int hashCode() {
         // You can override field hashCode logic by defining methods like:
         // int fieldNameHashCode() { ... }
 
         int _hash = 1;
         _hash = 31 * _hash + java.util.Objects.hashCode(mParams);
-        _hash = 31 * _hash + java.util.Arrays.hashCode(mInputData);
+        _hash = 31 * _hash + java.util.Arrays.hashCode(mData);
         _hash = 31 * _hash + mBatchSize;
         _hash = 31 * _hash + java.util.Objects.hashCode(mExpectedOutputStructure);
         return _hash;
@@ -514,57 +466,85 @@ public final class InferenceInput {
 
     /** A builder for {@link InferenceInput} */
     @SuppressWarnings("WeakerAccess")
-    @DataClass.Generated.Member
     public static final class Builder {
 
         private @NonNull Params mParams;
-        private @NonNull Object[] mInputData;
+        private @NonNull byte[] mData;
         private int mBatchSize;
-        private @NonNull InferenceOutput mExpectedOutputStructure;
+        private @NonNull InferenceOutput mExpectedOutputStructure =
+                new InferenceOutput.Builder().build();
 
         private long mBuilderFieldsSet = 0L;
 
         /**
-         * Creates a new Builder.
+         * Note: use {@link InferenceInput.Builder#Builder(Params, byte[])} instead.
          *
-         * @param params The configuration that controls runtime interpreter behavior.
-         * @param inputData An array of input data. The inputs should be in the same order as inputs
-         *     of the model.
-         *     <p>For example, if a model takes multiple inputs:
-         *     <pre>{@code
-         * String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
+         * <p>Creates a new Builder for LiteRT model inference input. For LiteRT, inputData field is
+         * mapped to inputs of runForMultipleInputsOutputs:
+         * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+         * The inputs should be in the same order as inputs * of the model. *
+         *
+         * <p>For example, if a model takes multiple inputs: *
+         *
+         * <pre>{@code
+         *  String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
          * int[] input1 = new int[]{3, 2, 1}; // int tensor shape is [3].
          * Object[] inputData = {input0, input1, ...};
-         *
          * }</pre>
-         *     For TFLite, this field is mapped to inputs of runForMultipleInputsOutputs:
-         *     https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
-         * @param expectedOutputStructure The empty InferenceOutput representing the expected output
-         *     structure. For TFLite, the inference code will verify whether this expected output
-         *     structure matches model output signature.
-         *     <p>If a model produce string tensors:
-         *     <pre>{@code
+         *
+         * For LiteRT, the inference code will verify whether the expected output structure matches
+         * model output signature.
+         *
+         * <p>If a model produce string tensors:
+         *
+         * <pre>{@code
          * String[] output = new String[3][2];  // Output tensor shape is [3, 2].
          * HashMap<Integer, Object> outputs = new HashMap<>();
          * outputs.put(0, output);
          * expectedOutputStructure = new InferenceOutput.Builder().setDataOutputs(outputs).build();
          *
          * }</pre>
+         *
+         * @param params configuration that controls runtime interpreter behavior.
+         * @param inputData an array of input data.
+         * @param expectedOutputStructure an empty InferenceOutput representing the expected output
+         *     structure.
          */
         public Builder(
                 @NonNull Params params,
                 @SuppressLint("ArrayReturn") @NonNull Object[] inputData,
                 @NonNull InferenceOutput expectedOutputStructure) {
-            mParams = params;
-            AnnotationValidations.validate(NonNull.class, null, mParams);
-            mInputData = inputData;
-            AnnotationValidations.validate(NonNull.class, null, mInputData);
-            mExpectedOutputStructure = expectedOutputStructure;
-            AnnotationValidations.validate(NonNull.class, null, mExpectedOutputStructure);
+            mParams = Objects.requireNonNull(params);
+            mData = serializeObject(Objects.requireNonNull(inputData));
+            mExpectedOutputStructure = Objects.requireNonNull(expectedOutputStructure);
+        }
+
+        /**
+         * Creates a new Builder with provided runtime parameters and input data.
+         *
+         * <p>For LiteRT, inputData field is mapped to inputs of runForMultipleInputsOutputs:
+         * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+         * For example, if a model takes multiple inputs:
+         *
+         * <pre>{@code
+         * String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
+         * int[] input1 = new int[]{3, 2, 1}; // int tensor shape is [3].
+         * Object[] data = {input0, input1, ...};
+         * byte[] inputData = serializeObject(data);
+         * }</pre>
+         *
+         * <p>For Executorch, inputData field is mapped to a serialized EValue array.
+         *
+         * @param params configuration that controls runtime interpreter behavior.
+         * @param inputData byte array that holds serialized input data.
+         */
+        @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+        public Builder(@NonNull Params params, @NonNull byte[] inputData) {
+            mParams = Objects.requireNonNull(params);
+            mData = Objects.requireNonNull(inputData);
         }
 
         /** The configuration that controls runtime interpreter behavior. */
-        @DataClass.Generated.Member
         public @NonNull Builder setParams(@NonNull Params value) {
             mBuilderFieldsSet |= 0x1;
             mParams = value;
@@ -572,7 +552,32 @@ public final class InferenceInput {
         }
 
         /**
-         * An array of input data. The inputs should be in the same order as inputs of the model.
+         * A byte array that holds input data. The inputs should be in the same order as inputs of
+         * the model.
+         *
+         * <p>For LiteRT, this field is mapped to inputs of runForMultipleInputsOutputs:
+         * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+         *
+         * <pre>{@code
+         * String[] input0 = {"foo", "bar"}; // string tensor shape is [2].
+         * int[] input1 = new int[]{3, 2, 1}; // int tensor shape is [3].
+         * Object[] data = {input0, input1, ...};
+         * byte[] inputData = serializeObject(data);
+         * }</pre>
+         *
+         * <p>For Executorch model, this field is a serialized EValue array.
+         */
+        @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+        public @NonNull Builder setInputData(@NonNull byte[] value) {
+            mBuilderFieldsSet |= 0x2;
+            mData = value;
+            return this;
+        }
+
+        /**
+         * Note: use {@link InferenceInput.Builder#setInputData(byte[])} instead.
+         *
+         * <p>An array of input data. The inputs should be in the same order as inputs of the model.
          *
          * <p>For example, if a model takes multiple inputs:
          *
@@ -582,13 +587,12 @@ public final class InferenceInput {
          * Object[] inputData = {input0, input1, ...};
          * }</pre>
          *
-         * For TFLite, this field is mapped to inputs of runForMultipleInputsOutputs:
+         * For LiteRT, this field is mapped to inputs of runForMultipleInputsOutputs:
          * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
          */
-        @DataClass.Generated.Member
         public @NonNull Builder setInputData(@NonNull Object... value) {
             mBuilderFieldsSet |= 0x2;
-            mInputData = value;
+            mData = serializeObject(value);
             return this;
         }
 
@@ -596,7 +600,6 @@ public final class InferenceInput {
          * The number of input examples. Adopter can set this field to run batching inference. The
          * batch size is 1 by default. The batch size should match the input data size.
          */
-        @DataClass.Generated.Member
         public @NonNull Builder setBatchSize(int value) {
             mBuilderFieldsSet |= 0x4;
             mBatchSize = value;
@@ -604,9 +607,9 @@ public final class InferenceInput {
         }
 
         /**
-         * The empty InferenceOutput representing the expected output structure. For TFLite, the
-         * inference code will verify whether this expected output structure matches model output
-         * signature.
+         * The empty InferenceOutput representing the expected output structure. It's only required
+         * by LiteRT model. For LiteRT, the inference code will verify whether this expected output
+         * structure matches model output signature.
          *
          * <p>If a model produce string tensors:
          *
@@ -617,37 +620,43 @@ public final class InferenceInput {
          * expectedOutputStructure = new InferenceOutput.Builder().setDataOutputs(outputs).build();
          * }</pre>
          */
-        @DataClass.Generated.Member
         public @NonNull Builder setExpectedOutputStructure(@NonNull InferenceOutput value) {
             mBuilderFieldsSet |= 0x8;
             mExpectedOutputStructure = value;
             return this;
         }
 
-        /** Builds the instance. */
+        /** @hide */
+        private void validateInputData() {
+            Preconditions.checkArgument(
+                    mData.length > 0, "Input data should not be empty for InferenceInput.");
+        }
+
+        /** @hide */
+        private void validateOutputStructure() {
+            // ExecuTorch model doesn't require set output structure.
+            if (mParams.getModelType() != Params.MODEL_TYPE_TENSORFLOW_LITE) {
+                return;
+            }
+            Preconditions.checkArgument(
+                    !mExpectedOutputStructure.getDataOutputs().isEmpty()
+                            || mExpectedOutputStructure.getData().length > 0,
+                    "ExpectedOutputStructure field is required for TensorflowLite model.");
+        }
+
+        /** Builds the instance. This builder should not be touched after calling this! */
         public @NonNull InferenceInput build() {
+
             mBuilderFieldsSet |= 0x10; // Mark builder used
 
             if ((mBuilderFieldsSet & 0x4) == 0) {
                 mBatchSize = 1;
             }
+            validateInputData();
+            validateOutputStructure();
             InferenceInput o =
-                    new InferenceInput(mParams, mInputData, mBatchSize, mExpectedOutputStructure);
+                    new InferenceInput(mParams, mData, mBatchSize, mExpectedOutputStructure);
             return o;
         }
     }
-
-    @DataClass.Generated(
-            time = 1709250081618L,
-            codegenVersion = "1.0.23",
-            sourceFile =
-                    "packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceInput.java",
-            inputSignatures =
-                    "private @android.annotation.NonNull android.adservices.ondevicepersonalization.Params mParams\nprivate @android.annotation.NonNull java.lang.Object[] mInputData\nprivate  int mBatchSize\nprivate @android.annotation.NonNull android.adservices.ondevicepersonalization.InferenceOutput mExpectedOutputStructure\nclass InferenceInput extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genEqualsHashCode=true)")
-    @Deprecated
-    private void __metadata() {}
-
-    // @formatter:on
-    // End of generated code
-
 }
diff --git a/framework/java/android/adservices/ondevicepersonalization/InferenceInputParcel.java b/framework/java/android/adservices/ondevicepersonalization/InferenceInputParcel.java
index ad7ff562..5cb3d2fc 100644
--- a/framework/java/android/adservices/ondevicepersonalization/InferenceInputParcel.java
+++ b/framework/java/android/adservices/ondevicepersonalization/InferenceInputParcel.java
@@ -21,7 +21,6 @@ import android.annotation.NonNull;
 import android.os.Parcelable;
 
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
-import com.android.ondevicepersonalization.internal.util.ByteArrayParceledListSlice;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /**
@@ -47,8 +46,11 @@ public class InferenceInputParcel implements Parcelable {
      */
     private @IntRange(from = 1) int mCpuNumThread;
 
-    /** An array of input data. The inputs should be in the same order as inputs of the model. */
-    @NonNull private ByteArrayParceledListSlice mInputData;
+    /**
+     * The byte array holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     */
+    @NonNull private byte[] mInputData;
 
     /**
      * The number of input examples. Adopter can set this field to run batching inference. The batch
@@ -75,7 +77,7 @@ public class InferenceInputParcel implements Parcelable {
                         .build(),
                 value.getParams().getDelegateType(),
                 value.getParams().getRecommendedNumThreads(),
-                ByteArrayParceledListSlice.create(value.getInputData()),
+                value.getData(),
                 value.getBatchSize(),
                 value.getParams().getModelType(),
                 new InferenceOutputParcel(value.getExpectedOutputStructure()));
@@ -106,8 +108,8 @@ public class InferenceInputParcel implements Parcelable {
      *     disable multithreading, which is equivalent to setting cpuNumThread to 1. If set to the
      *     value -1, the number of threads used will be implementation-defined and
      *     platform-dependent.
-     * @param inputData An array of input data. The inputs should be in the same order as inputs of
-     *     the model.
+     * @param inputData The byte array holds input data. The inputs should be in the same order as
+     *     inputs of the model.
      * @param batchSize The number of input examples. Adopter can set this field to run batching
      *     inference. The batch size is 1 by default.
      * @param expectedOutputStructure The empty InferenceOutput representing the expected output
@@ -119,7 +121,7 @@ public class InferenceInputParcel implements Parcelable {
             @NonNull ModelId modelId,
             @InferenceInput.Params.Delegate int delegate,
             @IntRange(from = 1) int cpuNumThread,
-            @NonNull ByteArrayParceledListSlice inputData,
+            @NonNull byte[] inputData,
             int batchSize,
             @InferenceInput.Params.ModelType int modelType,
             @NonNull InferenceOutputParcel expectedOutputStructure) {
@@ -165,9 +167,12 @@ public class InferenceInputParcel implements Parcelable {
         return mCpuNumThread;
     }
 
-    /** An array of input data. The inputs should be in the same order as inputs of the model. */
+    /**
+     * The byte array holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     */
     @DataClass.Generated.Member
-    public @NonNull ByteArrayParceledListSlice getInputData() {
+    public @NonNull byte[] getInputData() {
         return mInputData;
     }
 
@@ -204,7 +209,7 @@ public class InferenceInputParcel implements Parcelable {
         dest.writeTypedObject(mModelId, flags);
         dest.writeInt(mDelegate);
         dest.writeInt(mCpuNumThread);
-        dest.writeTypedObject(mInputData, flags);
+        dest.writeByteArray(mInputData);
         dest.writeInt(mBatchSize);
         dest.writeInt(mModelType);
         dest.writeTypedObject(mExpectedOutputStructure, flags);
@@ -226,8 +231,7 @@ public class InferenceInputParcel implements Parcelable {
         ModelId modelId = (ModelId) in.readTypedObject(ModelId.CREATOR);
         int delegate = in.readInt();
         int cpuNumThread = in.readInt();
-        ByteArrayParceledListSlice inputData =
-                (ByteArrayParceledListSlice) in.readTypedObject(ByteArrayParceledListSlice.CREATOR);
+        byte[] inputData = in.createByteArray();
         int batchSize = in.readInt();
         int modelType = in.readInt();
         InferenceOutputParcel expectedOutputStructure =
@@ -265,12 +269,12 @@ public class InferenceInputParcel implements Parcelable {
             };
 
     @DataClass.Generated(
-            time = 1708579683131L,
+            time = 1730482564983L,
             codegenVersion = "1.0.23",
             sourceFile =
                     "packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceInputParcel.java",
             inputSignatures =
-                    "private @android.annotation.NonNull android.adservices.ondevicepersonalization.ModelId mModelId\nprivate @android.adservices.ondevicepersonalization.InferenceInput.Params.Delegate int mDelegate\nprivate @android.annotation.IntRange int mCpuNumThread\nprivate @android.annotation.NonNull com.android.ondevicepersonalization.internal.util.ByteArrayParceledListSlice mInputData\nprivate  int mBatchSize\nprivate @android.adservices.ondevicepersonalization.InferenceInput.Params.ModelType int mModelType\nprivate @android.annotation.NonNull android.adservices.ondevicepersonalization.InferenceOutputParcel mExpectedOutputStructure\nclass InferenceInputParcel extends java.lang.Object implements [android.os.Parcelable]\n@com.android.ondevicepersonalization.internal.util.DataClass(genAidl=false, genBuilder=false)")
+                    "private @android.annotation.NonNull android.adservices.ondevicepersonalization.ModelId mModelId\nprivate @android.adservices.ondevicepersonalization.InferenceInput.Params.Delegate int mDelegate\nprivate @android.annotation.IntRange int mCpuNumThread\nprivate @android.annotation.NonNull byte[] mInputData\nprivate  int mBatchSize\nprivate @android.adservices.ondevicepersonalization.InferenceInput.Params.ModelType int mModelType\nprivate @android.annotation.NonNull android.adservices.ondevicepersonalization.InferenceOutputParcel mExpectedOutputStructure\nclass InferenceInputParcel extends java.lang.Object implements [android.os.Parcelable]\n@com.android.ondevicepersonalization.internal.util.DataClass(genAidl=false, genBuilder=false)")
     @Deprecated
     private void __metadata() {}
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/InferenceOutput.java b/framework/java/android/adservices/ondevicepersonalization/InferenceOutput.java
index 104a9aed..70e0cbfc 100644
--- a/framework/java/android/adservices/ondevicepersonalization/InferenceOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/InferenceOutput.java
@@ -27,7 +27,6 @@ import java.util.Collections;
 import java.util.Map;
 
 /** The result returned by {@link ModelManager#run}. */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class InferenceOutput {
     /**
@@ -38,6 +37,19 @@ public final class InferenceOutput {
      */
     @NonNull private Map<Integer, Object> mDataOutputs = Collections.emptyMap();
 
+    /**
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     *
+     * <p>For LiteRT, this field is mapped to outputs of runForMultipleInputsOutputs:
+     * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *
+     * <p>For ExecuTorch model, this field is a serialized EValue array.
+     *
+     * @hide
+     */
+    @NonNull private byte[] mData = new byte[] {};
+
     // Code below generated by codegen v1.0.23.
     //
     // DO NOT MODIFY!
@@ -52,15 +64,20 @@ public final class InferenceOutput {
     // @formatter:off
 
     @DataClass.Generated.Member
-    /* package-private */ InferenceOutput(@NonNull Map<Integer, Object> dataOutputs) {
+    /* package-private */ InferenceOutput(
+            @NonNull Map<Integer, Object> dataOutputs, @NonNull byte[] data) {
         this.mDataOutputs = dataOutputs;
         AnnotationValidations.validate(NonNull.class, null, mDataOutputs);
+        this.mData = data;
+        AnnotationValidations.validate(NonNull.class, null, mData);
 
         // onConstructed(); // You can define this method to get a callback
     }
 
     /**
-     * A map mapping output indices to multidimensional arrays of output.
+     * Note: use {@link InferenceOutput#getData()} instead.
+     *
+     * <p>A map mapping output indices to multidimensional arrays of output.
      *
      * <p>For TFLite, this field is mapped to outputs of runForMultipleInputsOutputs:
      * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
@@ -70,6 +87,22 @@ public final class InferenceOutput {
         return mDataOutputs;
     }
 
+    /**
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     *
+     * <p>For LiteRT, this field is a serialized Map<Integer, Object> that is mapped to outputs of
+     * runForMultipleInputsOutputs:
+     * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *
+     * <p>For ExecuTorch model, this field is a serialized EValue array.
+     */
+    @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+    @DataClass.Generated.Member
+    public @NonNull byte[] getData() {
+        return mData;
+    }
+
     @Override
     @DataClass.Generated.Member
     public boolean equals(@android.annotation.Nullable Object o) {
@@ -82,7 +115,9 @@ public final class InferenceOutput {
         @SuppressWarnings("unchecked")
         InferenceOutput that = (InferenceOutput) o;
         //noinspection PointlessBooleanExpression
-        return true && java.util.Objects.equals(mDataOutputs, that.mDataOutputs);
+        return true
+                && java.util.Objects.equals(mDataOutputs, that.mDataOutputs)
+                && java.util.Arrays.equals(mData, that.mData);
     }
 
     @Override
@@ -93,6 +128,7 @@ public final class InferenceOutput {
 
         int _hash = 1;
         _hash = 31 * _hash + java.util.Objects.hashCode(mDataOutputs);
+        _hash = 31 * _hash + java.util.Arrays.hashCode(mData);
         return _hash;
     }
 
@@ -102,13 +138,16 @@ public final class InferenceOutput {
     public static final class Builder {
 
         private @NonNull Map<Integer, Object> mDataOutputs;
+        private @NonNull byte[] mData;
 
         private long mBuilderFieldsSet = 0L;
 
         public Builder() {}
 
         /**
-         * A map mapping output indices to multidimensional arrays of output.
+         * Note: use {@link InferenceOutput.Builder#setData(byte[])} instead.
+         *
+         * <p>A map mapping output indices to multidimensional arrays of output.
          *
          * <p>For TFLite, this field is mapped to outputs of runForMultipleInputsOutputs:
          * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
@@ -134,20 +173,42 @@ public final class InferenceOutput {
             return this;
         }
 
+        /**
+         * A byte array that holds input data. The inputs should be in the same order as inputs of
+         * the model.
+         *
+         * <p>For LiteRT, this field is a serialized Map<Integer, Object> that is mapped to outputs
+         * of runForMultipleInputsOutputs:
+         * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+         *
+         * <p>For ExecuTorch model, this field is a serialized EValue array.
+         */
+        @FlaggedApi(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+        @DataClass.Generated.Member
+        public @NonNull Builder setData(@NonNull byte[] value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x2;
+            mData = value;
+            return this;
+        }
+
         /** Builds the instance. This builder should not be touched after calling this! */
         public @NonNull InferenceOutput build() {
             checkNotUsed();
-            mBuilderFieldsSet |= 0x2; // Mark builder used
+            mBuilderFieldsSet |= 0x4; // Mark builder used
 
             if ((mBuilderFieldsSet & 0x1) == 0) {
                 mDataOutputs = Collections.emptyMap();
             }
-            InferenceOutput o = new InferenceOutput(mDataOutputs);
+            if ((mBuilderFieldsSet & 0x2) == 0) {
+                mData = new byte[] {};
+            }
+            InferenceOutput o = new InferenceOutput(mDataOutputs, mData);
             return o;
         }
 
         private void checkNotUsed() {
-            if ((mBuilderFieldsSet & 0x2) != 0) {
+            if ((mBuilderFieldsSet & 0x4) != 0) {
                 throw new IllegalStateException(
                         "This Builder should not be reused. Use a new Builder instance instead");
             }
@@ -155,12 +216,12 @@ public final class InferenceOutput {
     }
 
     @DataClass.Generated(
-            time = 1707187954917L,
+            time = 1730515027336L,
             codegenVersion = "1.0.23",
             sourceFile =
                     "packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceOutput.java",
             inputSignatures =
-                    "private @android.annotation.NonNull java.util.Map<java.lang.Integer,java.lang.Object> mDataOutputs\nclass InferenceOutput extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genEqualsHashCode=true)")
+                    "private static final  java.lang.String TAG\nprivate static final  com.android.ondevicepersonalization.internal.util.LoggerFactory.Logger sLogger\nprivate @android.annotation.NonNull java.util.Map<java.lang.Integer,java.lang.Object> mDataOutputs\nprivate @android.annotation.NonNull byte[] mData\nclass InferenceOutput extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genEqualsHashCode=true)")
     @Deprecated
     private void __metadata() {}
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/InferenceOutputParcel.java b/framework/java/android/adservices/ondevicepersonalization/InferenceOutputParcel.java
index 89f857b0..c80409b6 100644
--- a/framework/java/android/adservices/ondevicepersonalization/InferenceOutputParcel.java
+++ b/framework/java/android/adservices/ondevicepersonalization/InferenceOutputParcel.java
@@ -20,11 +20,9 @@ import android.annotation.NonNull;
 import android.os.Parcelable;
 
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
-import java.util.Collections;
-import java.util.Map;
-
 /**
  * Parcelable version of {@link InferenceOutput}.
  *
@@ -33,15 +31,22 @@ import java.util.Map;
 @DataClass(genAidl = false, genBuilder = false)
 public final class InferenceOutputParcel implements Parcelable {
     /**
-     * A map mapping output indices to multidimensional arrays of output. For TFLite, this field is
-     * mapped to outputs of runForMultipleInputsOutputs:
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     *
+     * <p>For LiteRT, this field is mapped to outputs of runForMultipleInputsOutputs:
      * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *
+     * <p>For ExecuTorch model, this field is a serialized EValue array. TODO: add EValue link.
      */
-    @NonNull private Map<Integer, Object> mData = Collections.emptyMap();
+    @NonNull private byte[] mData;
 
     /** @hide */
     public InferenceOutputParcel(@NonNull InferenceOutput value) {
-        this(value.getDataOutputs());
+        this(
+                value.getData().length > 0
+                        ? value.getData()
+                        : ByteArrayUtil.serializeObject(value.getDataOutputs()));
     }
 
     // Code below generated by codegen v1.0.23.
@@ -60,12 +65,14 @@ public final class InferenceOutputParcel implements Parcelable {
     /**
      * Creates a new InferenceOutputParcel.
      *
-     * @param data A map mapping output indices to multidimensional arrays of output. For TFLite,
-     *     this field is mapped to outputs of runForMultipleInputsOutputs:
+     * @param data A byte array that holds input data. The inputs should be in the same order as
+     *     inputs of the model.
+     *     <p>For LiteRT, this field is mapped to outputs of runForMultipleInputsOutputs:
      *     https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *     <p>For ExecuTorch model, this field is a serialized EValue array. TODO: add EValue link.
      */
     @DataClass.Generated.Member
-    public InferenceOutputParcel(@NonNull Map<Integer, Object> data) {
+    public InferenceOutputParcel(@NonNull byte[] data) {
         this.mData = data;
         AnnotationValidations.validate(NonNull.class, null, mData);
 
@@ -73,12 +80,16 @@ public final class InferenceOutputParcel implements Parcelable {
     }
 
     /**
-     * A map mapping output indices to multidimensional arrays of output. For TFLite, this field is
-     * mapped to outputs of runForMultipleInputsOutputs:
+     * A byte array that holds input data. The inputs should be in the same order as inputs of the
+     * model.
+     *
+     * <p>For LiteRT, this field is mapped to outputs of runForMultipleInputsOutputs:
      * https://www.tensorflow.org/lite/api_docs/java/org/tensorflow/lite/InterpreterApi#parameters_9
+     *
+     * <p>For ExecuTorch model, this field is a serialized EValue array. TODO: add EValue link.
      */
     @DataClass.Generated.Member
-    public @NonNull Map<Integer, Object> getData() {
+    public @NonNull byte[] getData() {
         return mData;
     }
 
@@ -88,7 +99,7 @@ public final class InferenceOutputParcel implements Parcelable {
         // You can override field parcelling by defining methods like:
         // void parcelFieldName(Parcel dest, int flags) { ... }
 
-        dest.writeMap(mData);
+        dest.writeByteArray(mData);
     }
 
     @Override
@@ -100,12 +111,11 @@ public final class InferenceOutputParcel implements Parcelable {
     /** @hide */
     @SuppressWarnings({"unchecked", "RedundantCast"})
     @DataClass.Generated.Member
-    protected InferenceOutputParcel(@NonNull android.os.Parcel in) {
+    /* package-private */ InferenceOutputParcel(@NonNull android.os.Parcel in) {
         // You can override field unparcelling by defining methods like:
         // static FieldType unparcelFieldName(Parcel in) { ... }
 
-        Map<Integer, Object> data = new java.util.LinkedHashMap<>();
-        in.readMap(data, Object.class.getClassLoader());
+        byte[] data = in.createByteArray();
 
         this.mData = data;
         AnnotationValidations.validate(NonNull.class, null, mData);
@@ -128,12 +138,12 @@ public final class InferenceOutputParcel implements Parcelable {
             };
 
     @DataClass.Generated(
-            time = 1706291599206L,
+            time = 1730498385180L,
             codegenVersion = "1.0.23",
             sourceFile =
                     "packages/modules/OnDevicePersonalization/framework/java/android/adservices/ondevicepersonalization/InferenceOutputParcel.java",
             inputSignatures =
-                    "private @android.annotation.NonNull java.util.Map<java.lang.Integer,java.lang.Object> mData\nclass InferenceOutputParcel extends java.lang.Object implements [android.os.Parcelable]\n@com.android.ondevicepersonalization.internal.util.DataClass(genAidl=false, genBuilder=false)")
+                    "private @android.annotation.NonNull byte[] mData\nclass InferenceOutputParcel extends java.lang.Object implements [android.os.Parcelable]\n@com.android.ondevicepersonalization.internal.util.DataClass(genAidl=false, genBuilder=false)")
     @Deprecated
     private void __metadata() {}
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java b/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
index 47a45f5c..649e4190 100644
--- a/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
+++ b/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
@@ -21,7 +21,6 @@ import android.adservices.ondevicepersonalization.aidl.IFederatedComputeService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedModelService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedServiceCallback;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.Service;
@@ -34,7 +33,6 @@ import android.os.Parcelable;
 import android.os.RemoteException;
 import android.os.SystemClock;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.ExceptionInfo;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.internal.util.OdpParceledListSlice;
@@ -56,7 +54,6 @@ import java.util.function.Function;
  * Client apps use {@link OnDevicePersonalizationManager} to interact with an {@link
  * IsolatedService}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public abstract class IsolatedService extends Service {
     private static final String TAG = IsolatedService.class.getSimpleName();
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
diff --git a/framework/java/android/adservices/ondevicepersonalization/IsolatedServiceException.java b/framework/java/android/adservices/ondevicepersonalization/IsolatedServiceException.java
index 03e9544e..de492416 100644
--- a/framework/java/android/adservices/ondevicepersonalization/IsolatedServiceException.java
+++ b/framework/java/android/adservices/ondevicepersonalization/IsolatedServiceException.java
@@ -27,7 +27,6 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
  * the {@link IsolatedService} in order to prevent data leakage from the {@link IsolatedService} to
  * an app. The platform does not interpret the error code, it only logs and aggregates it.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class IsolatedServiceException extends Exception {
     private final int mErrorCode;
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/IsolatedWorker.java b/framework/java/android/adservices/ondevicepersonalization/IsolatedWorker.java
index 1b37b692..70f6e4fe 100644
--- a/framework/java/android/adservices/ondevicepersonalization/IsolatedWorker.java
+++ b/framework/java/android/adservices/ondevicepersonalization/IsolatedWorker.java
@@ -16,12 +16,9 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.os.OutcomeReceiver;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 /**
  * Interface with methods that need to be implemented to handle requests from the
  * OnDevicePersonalization service to an {@link IsolatedService}. The {@link IsolatedService}
@@ -33,7 +30,6 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
  * platform treats it as an unrecoverable error in the {@link IsolatedService} and ends processing
  * the request.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public interface IsolatedWorker {
 
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/KeyValueStore.java b/framework/java/android/adservices/ondevicepersonalization/KeyValueStore.java
index 198af7c6..db8d4153 100644
--- a/framework/java/android/adservices/ondevicepersonalization/KeyValueStore.java
+++ b/framework/java/android/adservices/ondevicepersonalization/KeyValueStore.java
@@ -16,13 +16,10 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.WorkerThread;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 import java.util.Set;
 
 /**
@@ -33,7 +30,6 @@ import java.util.Set;
  * @see IsolatedService#getRemoteData(RequestToken)
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public interface KeyValueStore {
     /**
      * Looks up a key in a read-only store.
diff --git a/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java b/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
index e09c4c4e..250d785a 100644
--- a/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
+++ b/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
@@ -83,12 +83,20 @@ public class LocalDataImpl implements MutableKeyValueStore {
             int op, Bundle params, int apiName, long startTimeMillis) {
         int responseCode = Constants.STATUS_SUCCESS;
         try {
-            Bundle result = handleAsyncRequest(op, params);
-            ByteArrayParceledSlice data = result.getParcelable(
-                    Constants.EXTRA_RESULT, ByteArrayParceledSlice.class);
-            if (null == data) {
+            CallbackResult callbackResult = handleAsyncRequest(op, params);
+            if (callbackResult.mErrorCode != 0) {
+                responseCode = callbackResult.mErrorCode;
                 return null;
             }
+            Bundle result = callbackResult.mResult;
+            if (result == null
+                    || result.getParcelable(Constants.EXTRA_RESULT, ByteArrayParceledSlice.class)
+                    == null) {
+                responseCode = Constants.STATUS_SUCCESS_EMPTY_RESULT;
+                return null;
+            }
+            ByteArrayParceledSlice data =
+                    result.getParcelable(Constants.EXTRA_RESULT, ByteArrayParceledSlice.class);
             return data.getByteArray();
         } catch (RuntimeException e) {
             responseCode = Constants.STATUS_INTERNAL_ERROR;
@@ -110,14 +118,19 @@ public class LocalDataImpl implements MutableKeyValueStore {
         final long startTimeMillis = System.currentTimeMillis();
         int responseCode = Constants.STATUS_SUCCESS;
         try {
-            Bundle result = handleAsyncRequest(Constants.DATA_ACCESS_OP_LOCAL_DATA_KEYSET,
-                    Bundle.EMPTY);
-            HashSet<String> resultSet =
-                    result.getSerializable(Constants.EXTRA_RESULT, HashSet.class);
-            if (null == resultSet) {
+            CallbackResult callbackResult =
+                    handleAsyncRequest(Constants.DATA_ACCESS_OP_LOCAL_DATA_KEYSET, Bundle.EMPTY);
+            if (callbackResult.mErrorCode != 0) {
+                responseCode = callbackResult.mErrorCode;
+                return Collections.emptySet();
+            }
+            Bundle result = callbackResult.mResult;
+            if (result == null
+                    || result.getSerializable(Constants.EXTRA_RESULT, HashSet.class) == null) {
+                responseCode = Constants.STATUS_SUCCESS_EMPTY_RESULT;
                 return Collections.emptySet();
             }
-            return resultSet;
+            return result.getSerializable(Constants.EXTRA_RESULT, HashSet.class);
         } catch (RuntimeException e) {
             responseCode = Constants.STATUS_INTERNAL_ERROR;
             throw e;
@@ -138,25 +151,21 @@ public class LocalDataImpl implements MutableKeyValueStore {
         return ModelId.TABLE_ID_LOCAL_DATA;
     }
 
-    private Bundle handleAsyncRequest(int op, Bundle params) {
+    private CallbackResult handleAsyncRequest(int op, Bundle params) {
         try {
-            BlockingQueue<Bundle> asyncResult = new ArrayBlockingQueue<>(1);
+            BlockingQueue<CallbackResult> asyncResult = new ArrayBlockingQueue<>(1);
             mDataAccessService.onRequest(
                     op,
                     params,
                     new IDataAccessServiceCallback.Stub() {
                         @Override
                         public void onSuccess(@NonNull Bundle result) {
-                            if (result != null) {
-                                asyncResult.add(result);
-                            } else {
-                                asyncResult.add(Bundle.EMPTY);
-                            }
+                            asyncResult.add(new CallbackResult(result, 0));
                         }
 
                         @Override
                         public void onError(int errorCode) {
-                            asyncResult.add(Bundle.EMPTY);
+                            asyncResult.add(new CallbackResult(null, errorCode));
                         }
                     });
             return asyncResult.take();
@@ -165,4 +174,14 @@ public class LocalDataImpl implements MutableKeyValueStore {
             throw new IllegalStateException(e);
         }
     }
+
+    private static class CallbackResult {
+        final Bundle mResult;
+        final int mErrorCode;
+
+        CallbackResult(Bundle result, int errorCode) {
+            mResult = result;
+            mErrorCode = errorCode;
+        }
+    }
 }
diff --git a/framework/java/android/adservices/ondevicepersonalization/LogReader.java b/framework/java/android/adservices/ondevicepersonalization/LogReader.java
index 04b603ec..43d8c7a6 100644
--- a/framework/java/android/adservices/ondevicepersonalization/LogReader.java
+++ b/framework/java/android/adservices/ondevicepersonalization/LogReader.java
@@ -18,14 +18,12 @@ package android.adservices.ondevicepersonalization;
 
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.WorkerThread;
 import android.os.Bundle;
 import android.os.Parcelable;
 import android.os.RemoteException;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.internal.util.OdpParceledListSlice;
 
@@ -43,7 +41,6 @@ import java.util.concurrent.BlockingQueue;
  * @see IsolatedService#getLogReader(RequestToken)
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class LogReader {
     private static final String TAG = "LogReader";
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
diff --git a/framework/java/android/adservices/ondevicepersonalization/MeasurementWebTriggerEventParams.java b/framework/java/android/adservices/ondevicepersonalization/MeasurementWebTriggerEventParams.java
index 118c4226..9390c969 100644
--- a/framework/java/android/adservices/ondevicepersonalization/MeasurementWebTriggerEventParams.java
+++ b/framework/java/android/adservices/ondevicepersonalization/MeasurementWebTriggerEventParams.java
@@ -16,14 +16,12 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
 import android.content.ComponentName;
 import android.net.Uri;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -44,7 +42,6 @@ import com.android.ondevicepersonalization.internal.util.DataClass;
  * @hide
  */
 @SystemApi
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class MeasurementWebTriggerEventParams {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/ModelManager.java b/framework/java/android/adservices/ondevicepersonalization/ModelManager.java
index a83e910c..d6e0e29e 100644
--- a/framework/java/android/adservices/ondevicepersonalization/ModelManager.java
+++ b/framework/java/android/adservices/ondevicepersonalization/ModelManager.java
@@ -20,16 +20,17 @@ import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedModelService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedModelServiceCallback;
 import android.annotation.CallbackExecutor;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.WorkerThread;
 import android.os.Bundle;
 import android.os.OutcomeReceiver;
 import android.os.RemoteException;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 
+import java.util.HashMap;
+import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.Executor;
 
@@ -37,7 +38,6 @@ import java.util.concurrent.Executor;
  * Handles model inference and only support TFLite model inference now. See {@link
  * IsolatedService#getModelManager}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class ModelManager {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = ModelManager.class.getSimpleName();
@@ -67,12 +67,6 @@ public class ModelManager {
             @NonNull OutcomeReceiver<InferenceOutput, Exception> receiver) {
         final long startTimeMillis = System.currentTimeMillis();
         Objects.requireNonNull(input);
-        if (input.getInputData().length == 0) {
-            throw new IllegalArgumentException("Input data can not be empty");
-        }
-        if (input.getExpectedOutputStructure().getDataOutputs().isEmpty()) {
-            throw new IllegalArgumentException("Expected output data structure can not be empty");
-        }
         Bundle bundle = new Bundle();
         bundle.putBinder(Constants.EXTRA_DATA_ACCESS_SERVICE_BINDER, mDataService.asBinder());
         bundle.putParcelable(Constants.EXTRA_INFERENCE_INPUT, new InferenceInputParcel(input));
@@ -92,8 +86,20 @@ public class ModelManager {
                                                             result.getParcelable(
                                                                     Constants.EXTRA_RESULT,
                                                                     InferenceOutputParcel.class));
+                                            // Set output result to both fields for LiteRT model
+                                            // before Map field is deprecated.
+                                            Map<Integer, Object> outputMap = new HashMap<>();
+                                            try {
+                                                outputMap =
+                                                        (Map<Integer, Object>)
+                                                                ByteArrayUtil.deserializeObject(
+                                                                        outputParcel.getData());
+                                            } catch (ClassCastException e) {
+                                                // TODO: add logging
+                                            }
                                             InferenceOutput output =
-                                                    new InferenceOutput(outputParcel.getData());
+                                                    new InferenceOutput(
+                                                            outputMap, outputParcel.getData());
                                             endTimeMillis = System.currentTimeMillis();
                                             receiver.onResult(output);
                                         } catch (Exception e) {
diff --git a/framework/java/android/adservices/ondevicepersonalization/MutableKeyValueStore.java b/framework/java/android/adservices/ondevicepersonalization/MutableKeyValueStore.java
index d20fc312..3cfcb86b 100644
--- a/framework/java/android/adservices/ondevicepersonalization/MutableKeyValueStore.java
+++ b/framework/java/android/adservices/ondevicepersonalization/MutableKeyValueStore.java
@@ -16,13 +16,10 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.WorkerThread;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 /**
  * An interface to a read-write key-value store.
  *
@@ -31,7 +28,6 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
  * @see IsolatedService#getLocalData(RequestToken)
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public interface MutableKeyValueStore extends KeyValueStore {
     /**
      * Associates the specified value with the specified key.
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationConfigManager.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationConfigManager.java
index 92dba02e..9ee02028 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationConfigManager.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationConfigManager.java
@@ -19,15 +19,12 @@ package android.adservices.ondevicepersonalization;
 import static android.adservices.ondevicepersonalization.OnDevicePersonalizationPermissions.MODIFY_ONDEVICEPERSONALIZATION_STATE;
 
 import android.annotation.CallbackExecutor;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.RequiresPermission;
 import android.annotation.SystemApi;
 import android.content.Context;
 import android.os.OutcomeReceiver;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 import java.util.concurrent.Executor;
 
 /**
@@ -37,7 +34,6 @@ import java.util.concurrent.Executor;
  * @hide
  */
 @SystemApi
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class OnDevicePersonalizationConfigManager {
     /** @hide */
     public static final String ON_DEVICE_PERSONALIZATION_CONFIG_SERVICE =
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
index 9abea593..84a30083 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
@@ -28,7 +28,6 @@ import java.util.Set;
  * Exception thrown by OnDevicePersonalization APIs.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class OnDevicePersonalizationException extends Exception {
     /**
      * The {@link IsolatedService} that was invoked failed to run.
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
index 28f8b7e5..452a51d2 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
@@ -17,11 +17,15 @@
 package android.adservices.ondevicepersonalization;
 
 
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
 import android.annotation.CallbackExecutor;
 import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.ComponentName;
@@ -44,6 +48,7 @@ import com.android.ondevicepersonalization.internal.util.ExceptionInfo;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.internal.util.PersistableBundleUtils;
 
+import java.lang.annotation.Retention;
 import java.util.List;
 import java.util.Objects;
 import java.util.concurrent.Executor;
@@ -59,7 +64,6 @@ import java.util.concurrent.Executor;
  * cross-device statistical analysis or by Federated Learning for model training. The displayed
  * content and the persistent output are both not directly accessible by the calling app.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class OnDevicePersonalizationManager {
     /** @hide */
     public static final String ON_DEVICE_PERSONALIZATION_SERVICE =
@@ -91,6 +95,22 @@ public class OnDevicePersonalizationManager {
 
     private static final String TAG = OnDevicePersonalizationManager.class.getSimpleName();
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+
+    /** @hide */
+    @Retention(SOURCE)
+    @IntDef({FEATURE_ENABLED, FEATURE_DISABLED, FEATURE_UNSUPPORTED})
+    public @interface FeatureStatus {}
+    /** Indicates that a feature is present and enabled on the device.  */
+    @FlaggedApi(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public static final int FEATURE_ENABLED = 0;
+    /** Indicates that a feature is present but disabled on the device.  */
+    @FlaggedApi(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public static final int FEATURE_DISABLED = 1;
+
+    /** Indicates that a feature is not supported on the device. */
+    @FlaggedApi(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public static final int FEATURE_UNSUPPORTED = 2;
+
     private final AbstractServiceBinder<IOnDevicePersonalizationManagingService> mServiceBinder;
     private final Context mContext;
 
@@ -616,6 +636,76 @@ public class OnDevicePersonalizationManager {
         }
     }
 
+    /**
+     * Get the status of a specific OnDevicePersonalization feature.
+     *
+     * @param featureName the name of the specific feature to check the availability of.
+     * @param executor the {@link Executor} on which to invoke the callback
+     * @param receiver this either returns a value of {@code FeatureStatus}
+     *                 on success or {@link Exception} on failure.  The exception type is
+     *                 {@link IllegalStateException} if the service is not available.
+     */
+    @FlaggedApi(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public void queryFeatureAvailability(
+            @NonNull String featureName,
+            @NonNull @CallbackExecutor Executor executor,
+            @NonNull OutcomeReceiver<Integer, Exception> receiver) {
+
+        Objects.requireNonNull(featureName);
+        Objects.requireNonNull(executor);
+        Objects.requireNonNull(receiver);
+
+        long startTimeMillis = SystemClock.elapsedRealtime();
+
+        try {
+            final IOnDevicePersonalizationManagingService service =
+                    Objects.requireNonNull(mServiceBinder.getService(executor));
+
+            try {
+                IIsFeatureEnabledCallback callbackWrapper = new IIsFeatureEnabledCallback.Stub() {
+                    @Override
+                    public void onResult(int result, CalleeMetadata calleeMetadata) {
+                        final long token = Binder.clearCallingIdentity();
+                        try {
+                            executor.execute(
+                                    () -> {
+                                        receiver.onResult(result);
+                                    });
+                        } finally {
+                            Binder.restoreCallingIdentity(token);
+                            logApiCallStats(
+                                    service,
+                                    "",
+                                    Constants.API_NAME_IS_FEATURE_ENABLED,
+                                    SystemClock.elapsedRealtime() - startTimeMillis,
+                                    calleeMetadata.getServiceEntryTimeMillis()
+                                            - startTimeMillis,
+                                    SystemClock.elapsedRealtime()
+                                            - calleeMetadata.getCallbackInvokeTimeMillis(),
+                                    Constants.STATUS_SUCCESS);
+                        }
+                    }
+                };
+                service.isFeatureEnabled(
+                        featureName,
+                        new CallerMetadata.Builder().setStartTimeMillis(startTimeMillis).build(),
+                        callbackWrapper);
+            } catch (Exception e) {
+                logApiCallStats(
+                        service,
+                        "",
+                        Constants.API_NAME_IS_FEATURE_ENABLED,
+                        SystemClock.elapsedRealtime() - startTimeMillis,
+                        0,
+                        0,
+                        Constants.STATUS_INTERNAL_ERROR);
+                receiver.onError(e);
+            }
+        } catch (Exception e) {
+            receiver.onError(e);
+        }
+    }
+
     private static void validateRequest(ExecuteInIsolatedServiceRequest request) {
         Objects.requireNonNull(request.getService());
         ComponentName service = request.getService();
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationPermissions.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationPermissions.java
index ecf3b9c2..cefdb379 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationPermissions.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationPermissions.java
@@ -16,18 +16,14 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.SystemApi;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 /**
  * OnDevicePersonalization permission settings.
  *
  * @hide
 */
 @SystemApi
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class OnDevicePersonalizationPermissions {
     private OnDevicePersonalizationPermissions() {}
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManager.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManager.java
index acd1376d..2cff8dae 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManager.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManager.java
@@ -21,7 +21,6 @@ import static android.adservices.ondevicepersonalization.OnDevicePersonalization
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.annotation.CallbackExecutor;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.RequiresPermission;
 import android.annotation.SystemApi;
@@ -31,7 +30,6 @@ import android.os.Bundle;
 import android.os.OutcomeReceiver;
 import android.os.SystemClock;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.federatedcompute.internal.util.AbstractServiceBinder;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
@@ -45,7 +43,6 @@ import java.util.concurrent.Executor;
  * @hide
  */
 @SystemApi
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class OnDevicePersonalizationSystemEventManager {
     /** @hide */
     public static final String ON_DEVICE_PERSONALIZATION_SYSTEM_EVENT_SERVICE =
diff --git a/framework/java/android/adservices/ondevicepersonalization/RemoteDataImpl.java b/framework/java/android/adservices/ondevicepersonalization/RemoteDataImpl.java
index fabc9b74..fdbcb718 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RemoteDataImpl.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RemoteDataImpl.java
@@ -71,7 +71,7 @@ public class RemoteDataImpl implements KeyValueStore {
 
             CallbackResult callbackResult = asyncResult.take();
             if (callbackResult.mErrorCode != 0) {
-                responseCode = Constants.STATUS_INTERNAL_ERROR;
+                responseCode = callbackResult.mErrorCode;
                 return null;
             }
             Bundle result = callbackResult.mResult;
diff --git a/framework/java/android/adservices/ondevicepersonalization/RenderInput.java b/framework/java/android/adservices/ondevicepersonalization/RenderInput.java
index aabb94f9..b36c5285 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RenderInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RenderInput.java
@@ -27,7 +27,6 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
  * {@link IsolatedWorker#onRender(RenderInput, android.os.OutcomeReceiver)}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class RenderInput {
     /** The width of the slot. */
     private int mWidth = 0;
diff --git a/framework/java/android/adservices/ondevicepersonalization/RenderOutput.java b/framework/java/android/adservices/ondevicepersonalization/RenderOutput.java
index 213084a5..4f5fd90c 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RenderOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RenderOutput.java
@@ -16,12 +16,10 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.os.PersistableBundle;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -30,7 +28,6 @@ import com.android.ondevicepersonalization.internal.util.DataClass;
  * {@link IsolatedWorker#onRender(RenderInput, android.os.OutcomeReceiver)}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class RenderOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/RenderingConfig.java b/framework/java/android/adservices/ondevicepersonalization/RenderingConfig.java
index 5e26adf6..fdc6fb17 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RenderingConfig.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RenderingConfig.java
@@ -16,11 +16,9 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.os.Parcelable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -35,7 +33,6 @@ import java.util.List;
  * content to be displayed in a single {@link android.view.View}.
  *
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class RenderingConfig implements Parcelable {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/RequestLogRecord.java b/framework/java/android/adservices/ondevicepersonalization/RequestLogRecord.java
index 8ec34092..74eabf94 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RequestLogRecord.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RequestLogRecord.java
@@ -16,12 +16,10 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.content.ContentValues;
 import android.os.Parcelable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -38,7 +36,6 @@ import java.util.List;
  * The contents of the REQUESTS table can be consumed by Federated Learning facilitated model
  * training, or Federated Analytics facilitated cross-device statistical analysis.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class RequestLogRecord implements Parcelable {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/RequestToken.java b/framework/java/android/adservices/ondevicepersonalization/RequestToken.java
index 89f45125..793d1953 100644
--- a/framework/java/android/adservices/ondevicepersonalization/RequestToken.java
+++ b/framework/java/android/adservices/ondevicepersonalization/RequestToken.java
@@ -19,20 +19,16 @@ package android.adservices.ondevicepersonalization;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IFederatedComputeService;
 import android.adservices.ondevicepersonalization.aidl.IIsolatedModelService;
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.os.SystemClock;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-
 import java.util.Objects;
 
 /**
  * An opaque token that identifies the current request to an {@link IsolatedService}. This token
  * must be passed as a parameter to all service methods that depend on per-request state.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class RequestToken {
     @NonNull
     private final IDataAccessService mDataAccessService;
diff --git a/framework/java/android/adservices/ondevicepersonalization/SurfacePackageToken.java b/framework/java/android/adservices/ondevicepersonalization/SurfacePackageToken.java
index 93d93e00..5cfb513a 100644
--- a/framework/java/android/adservices/ondevicepersonalization/SurfacePackageToken.java
+++ b/framework/java/android/adservices/ondevicepersonalization/SurfacePackageToken.java
@@ -16,17 +16,14 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 
 /**
  * An opaque reference to content that can be displayed in a {@link android.view.SurfaceView}. This
  * maps to a {@link RenderingConfig} returned by an {@link IsolatedService}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public class SurfacePackageToken {
     @NonNull private final String mTokenString;
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/TrainingExampleRecord.java b/framework/java/android/adservices/ondevicepersonalization/TrainingExampleRecord.java
index f9bfa4ab..ec7218ed 100644
--- a/framework/java/android/adservices/ondevicepersonalization/TrainingExampleRecord.java
+++ b/framework/java/android/adservices/ondevicepersonalization/TrainingExampleRecord.java
@@ -16,17 +16,14 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.Nullable;
 import android.os.Parcelable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /**
  * One record of {@link TrainingExamplesOutput}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genAidl = false)
 public final class TrainingExampleRecord implements Parcelable {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
index ddd332e0..69ec0cde 100644
--- a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
@@ -25,7 +25,6 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
 import java.util.Objects;
 
 /** The input data for {@link IsolatedWorker#onTrainingExamples}. */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class TrainingExamplesInput {
     /**
      * The name of the federated compute population. It should match the population name in {@link
diff --git a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesOutput.java b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesOutput.java
index 662c0118..55a221a9 100644
--- a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesOutput.java
@@ -16,11 +16,8 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
-import com.android.internal.util.Preconditions;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -28,7 +25,6 @@ import java.util.Collections;
 import java.util.List;
 
 /** The output data of {@link IsolatedWorker#onTrainingExamples} */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class TrainingExamplesOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/TrainingInterval.java b/framework/java/android/adservices/ondevicepersonalization/TrainingInterval.java
index 89c5b6db..8003aa31 100644
--- a/framework/java/android/adservices/ondevicepersonalization/TrainingInterval.java
+++ b/framework/java/android/adservices/ondevicepersonalization/TrainingInterval.java
@@ -16,17 +16,14 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 import java.time.Duration;
 
 /** Training interval settings required for federated computation jobs. */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genHiddenConstDefs = true, genEqualsHashCode = true)
 public final class TrainingInterval {
     /** The scheduling mode for a one-off task. */
diff --git a/framework/java/android/adservices/ondevicepersonalization/UserData.java b/framework/java/android/adservices/ondevicepersonalization/UserData.java
index a3a84a0f..35165258 100644
--- a/framework/java/android/adservices/ondevicepersonalization/UserData.java
+++ b/framework/java/android/adservices/ondevicepersonalization/UserData.java
@@ -20,7 +20,6 @@ import static android.content.res.Configuration.ORIENTATION_LANDSCAPE;
 import static android.content.res.Configuration.ORIENTATION_PORTRAIT;
 import static android.content.res.Configuration.ORIENTATION_UNDEFINED;
 
-import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.IntRange;
 import android.annotation.NonNull;
@@ -29,7 +28,6 @@ import android.net.NetworkCapabilities;
 import android.os.Parcelable;
 import android.telephony.TelephonyManager;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -45,7 +43,6 @@ import java.util.Map;
  */
 // This class should be updated with the Kotlin mirror
 // {@link com.android.ondevicepersonalization.services.policyengine.data.UserData}.
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genHiddenBuilder = true, genEqualsHashCode = true, genConstDefs = false)
 public final class UserData implements Parcelable {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/WebTriggerInput.java b/framework/java/android/adservices/ondevicepersonalization/WebTriggerInput.java
index b73bedbe..657f0d8d 100644
--- a/framework/java/android/adservices/ondevicepersonalization/WebTriggerInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/WebTriggerInput.java
@@ -28,7 +28,6 @@ import java.util.Objects;
  * The input data for
  * {@link IsolatedWorker#onWebTrigger(WebTriggerInput, android.os.OutcomeReceiver)}.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 public final class WebTriggerInput {
     /** The destination URL (landing page) where the trigger event occurred. */
     @NonNull private Uri mDestinationUrl;
diff --git a/framework/java/android/adservices/ondevicepersonalization/WebTriggerOutput.java b/framework/java/android/adservices/ondevicepersonalization/WebTriggerOutput.java
index 4dea0ab4..1b91872d 100644
--- a/framework/java/android/adservices/ondevicepersonalization/WebTriggerOutput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/WebTriggerOutput.java
@@ -16,11 +16,9 @@
 
 package android.adservices.ondevicepersonalization;
 
-import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 
-import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
@@ -34,7 +32,6 @@ import java.util.List;
  * The contents of these tables can be consumed by Federated Learning facilitated model training,
  * or Federated Analytics facilitated cross-device statistical analysis.
  */
-@FlaggedApi(Flags.FLAG_ON_DEVICE_PERSONALIZATION_APIS_ENABLED)
 @DataClass(genBuilder = true, genEqualsHashCode = true)
 public final class WebTriggerOutput {
     /**
diff --git a/framework/java/android/adservices/ondevicepersonalization/aidl/IIsFeatureEnabledCallback.aidl b/framework/java/android/adservices/ondevicepersonalization/aidl/IIsFeatureEnabledCallback.aidl
new file mode 100644
index 00000000..cc511199
--- /dev/null
+++ b/framework/java/android/adservices/ondevicepersonalization/aidl/IIsFeatureEnabledCallback.aidl
@@ -0,0 +1,25 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.adservices.ondevicepersonalization.aidl;
+
+import android.adservices.ondevicepersonalization.CalleeMetadata;
+import android.os.Bundle;
+
+/** @hide */
+oneway interface IIsFeatureEnabledCallback {
+    void onResult(in int result, in CalleeMetadata calleeMetadata);
+}
\ No newline at end of file
diff --git a/framework/java/android/adservices/ondevicepersonalization/aidl/IOnDevicePersonalizationManagingService.aidl b/framework/java/android/adservices/ondevicepersonalization/aidl/IOnDevicePersonalizationManagingService.aidl
index eac9a769..23437fe0 100644
--- a/framework/java/android/adservices/ondevicepersonalization/aidl/IOnDevicePersonalizationManagingService.aidl
+++ b/framework/java/android/adservices/ondevicepersonalization/aidl/IOnDevicePersonalizationManagingService.aidl
@@ -20,6 +20,7 @@ import android.content.ComponentName;
 import android.adservices.ondevicepersonalization.CallerMetadata;
 import android.adservices.ondevicepersonalization.ExecuteOptionsParcel;
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
 import android.os.Bundle;
@@ -52,6 +53,11 @@ interface IOnDevicePersonalizationManagingService {
         in CallerMetadata metadata,
         in IRegisterMeasurementEventCallback callback);
 
+    void isFeatureEnabled(
+        in String featureName,
+        in CallerMetadata metadata,
+        in IIsFeatureEnabledCallback callback);
+
     void logApiCallStats(
         in String sdkPackageName,
         in int apiName,
diff --git a/framework/java/android/ondevicepersonalization/IOnDevicePersonalizationSystemService.aidl b/framework/java/android/ondevicepersonalization/IOnDevicePersonalizationSystemService.aidl
index c6915279..7ab14ed3 100644
--- a/framework/java/android/ondevicepersonalization/IOnDevicePersonalizationSystemService.aidl
+++ b/framework/java/android/ondevicepersonalization/IOnDevicePersonalizationSystemService.aidl
@@ -25,11 +25,4 @@ interface IOnDevicePersonalizationSystemService {
             in Bundle params,
             in IOnDevicePersonalizationSystemServiceCallback callback
     );
-
-    void setPersonalizationStatus(
-            in boolean enabled,
-            in IOnDevicePersonalizationSystemServiceCallback callback
-    );
-
-    void readPersonalizationStatus(in IOnDevicePersonalizationSystemServiceCallback callback);
 }
diff --git a/framework/java/com/android/federatedcompute/internal/util/AndroidServiceBinder.java b/framework/java/com/android/federatedcompute/internal/util/AndroidServiceBinder.java
index 91490df1..a88a7742 100644
--- a/framework/java/com/android/federatedcompute/internal/util/AndroidServiceBinder.java
+++ b/framework/java/com/android/federatedcompute/internal/util/AndroidServiceBinder.java
@@ -334,14 +334,14 @@ class AndroidServiceBinder<T> extends AbstractServiceBinder<T> {
 
         @Override
         public void onBindingDied(ComponentName name) {
-            LogUtil.e(TAG, "onBindingDied " + mServiceIntentActionOrName);
+            LogUtil.w(TAG, "onBindingDied " + mServiceIntentActionOrName);
             unbindFromService();
             mConnectionCountDownLatch.countDown();
         }
 
         @Override
         public void onNullBinding(ComponentName name) {
-            LogUtil.e(TAG, "onNullBinding shouldn't happen. " + mServiceIntentActionOrName);
+            LogUtil.w(TAG, "onNullBinding shouldn't happen. " + mServiceIntentActionOrName);
             unbindFromService();
             mConnectionCountDownLatch.countDown();
         }
diff --git a/framework/java/com/android/ondevicepersonalization/internal/util/BaseOdpParceledListSlice.java b/framework/java/com/android/ondevicepersonalization/internal/util/BaseOdpParceledListSlice.java
index 267a4de8..138d9b05 100644
--- a/framework/java/com/android/ondevicepersonalization/internal/util/BaseOdpParceledListSlice.java
+++ b/framework/java/com/android/ondevicepersonalization/internal/util/BaseOdpParceledListSlice.java
@@ -21,7 +21,6 @@ import android.os.IBinder;
 import android.os.Parcel;
 import android.os.Parcelable;
 import android.os.RemoteException;
-import android.util.Log;
 
 import java.util.ArrayList;
 import java.util.List;
@@ -39,13 +38,9 @@ import java.util.List;
  * See b/17671747.
  */
 abstract class BaseOdpParceledListSlice<T> implements Parcelable {
-    private static final String TAG = "OdpParceledListSlice";
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final boolean DEBUG = false;
-
-    /*
-     * TODO get this number from somewhere else. For now set it to a quarter of
-     * the 1MB limit.
-     */
+    private static final String TAG = BaseOdpParceledListSlice.class.getSimpleName();
     private static final int MAX_IPC_SIZE = IBinder.getSuggestedMaxIpcSizeBytes();
 
     private final List<T> mList;
@@ -60,7 +55,7 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
     BaseOdpParceledListSlice(Parcel p, ClassLoader loader) {
         final int numItems = p.readInt();
         mList = new ArrayList<T>(numItems);
-        if (DEBUG) Log.d(TAG, "Retrieving " + numItems + " items");
+        if (DEBUG) sLogger.d(TAG + ": Retrieving " + numItems + " items");
         if (numItems <= 0) {
             return;
         }
@@ -83,7 +78,7 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
 
             mList.add(parcelable);
 
-            if (DEBUG) Log.d(TAG, "Read inline #" + i + ": " + mList.get(mList.size() - 1));
+            if (DEBUG) sLogger.d(TAG + ": Read inline #" + i + ": " + mList.get(mList.size() - 1));
             i++;
         }
         if (i >= numItems) {
@@ -92,8 +87,8 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
         final IBinder retriever = p.readStrongBinder();
         while (i < numItems) {
             if (DEBUG) {
-                Log.d(TAG,
-                        "Reading more @" + i + " of " + numItems + ": retriever=" + retriever);
+                sLogger.d(TAG
+                        + ": Reading more @" + i + " of " + numItems + ": retriever=" + retriever);
             }
             Parcel data = Parcel.obtain();
             Parcel reply = Parcel.obtain();
@@ -101,7 +96,8 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
             try {
                 retriever.transact(IBinder.FIRST_CALL_TRANSACTION, data, reply, 0);
             } catch (RemoteException e) {
-                Log.w(TAG, "Failure retrieving array; only received " + i + " of " + numItems, e);
+                sLogger.w(e, TAG + ": Failure retrieving array; only received " + i + " of "
+                        + numItems);
                 return;
             }
             while (i < numItems && reply.readInt() != 0) {
@@ -110,7 +106,9 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
 
                 mList.add(parcelable);
 
-                if (DEBUG) Log.d(TAG, "Read extra #" + i + ": " + mList.get(mList.size() - 1));
+                if (DEBUG) {
+                    sLogger.d(TAG + ": Read extra #" + i + ": " + mList.get(mList.size() - 1));
+                }
                 i++;
             }
             reply.recycle();
@@ -157,7 +155,7 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
         final int numItems = mList.size();
         final int callFlags = flags;
         dest.writeInt(numItems);
-        if (DEBUG) Log.d(TAG, "Writing " + numItems + " items");
+        if (DEBUG) sLogger.d(TAG + ": Writing " + numItems + " items");
         if (numItems > 0) {
             final Class<?> listElementClass = mList.get(0).getClass();
             writeParcelableCreator(mList.get(0), dest);
@@ -169,7 +167,7 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
                 verifySameType(listElementClass, parcelable.getClass());
                 writeElement(parcelable, dest, callFlags);
 
-                if (DEBUG) Log.d(TAG, "Wrote inline #" + i + ": " + mList.get(i));
+                if (DEBUG) sLogger.d(TAG + ": Wrote inline #" + i + ": " + mList.get(i));
                 i++;
             }
             if (i < numItems) {
@@ -182,7 +180,7 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
                             return super.onTransact(code, data, reply, flags);
                         }
                         int i = data.readInt();
-                        if (DEBUG) Log.d(TAG, "Writing more @" + i + " of " + numItems);
+                        if (DEBUG) sLogger.d(TAG + ": Writing more @" + i + " of " + numItems);
                         while (i < numItems && reply.dataSize() < MAX_IPC_SIZE) {
                             reply.writeInt(1);
 
@@ -190,19 +188,21 @@ abstract class BaseOdpParceledListSlice<T> implements Parcelable {
                             verifySameType(listElementClass, parcelable.getClass());
                             writeElement(parcelable, reply, callFlags);
 
-                            if (DEBUG) Log.d(TAG, "Wrote extra #" + i + ": " + mList.get(i));
+                            if (DEBUG) {
+                                sLogger.d(TAG + ": Wrote extra #" + i + ": " + mList.get(i));
+                            }
                             i++;
                         }
                         if (i < numItems) {
-                            if (DEBUG) Log.d(TAG, "Breaking @" + i + " of " + numItems);
+                            if (DEBUG) sLogger.d(TAG + ": Breaking @" + i + " of " + numItems);
                             reply.writeInt(0);
                         }
                         return true;
                     }
                 };
                 if (DEBUG) {
-                    Log.d(TAG,
-                            "Breaking @" + i + " of " + numItems + ": retriever=" + retriever);
+                    sLogger.d(TAG
+                            + ": Breaking @" + i + " of " + numItems + ": retriever=" + retriever);
                 }
                 dest.writeStrongBinder(retriever);
             }
diff --git a/framework/java/com/android/ondevicepersonalization/internal/util/ByteArrayUtil.java b/framework/java/com/android/ondevicepersonalization/internal/util/ByteArrayUtil.java
new file mode 100644
index 00000000..4d998187
--- /dev/null
+++ b/framework/java/com/android/ondevicepersonalization/internal/util/ByteArrayUtil.java
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.internal.util;
+
+import java.io.ByteArrayInputStream;
+import java.io.ByteArrayOutputStream;
+import java.io.IOException;
+import java.io.ObjectInputStream;
+import java.io.ObjectOutputStream;
+
+/**
+ * Util class to handle different object conversion from/to byte array.
+ *
+ * @hide
+ */
+public class ByteArrayUtil {
+    /** serialize an object to byte array. The object need implement Serializable. */
+    public static byte[] serializeObject(Object input) {
+        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
+                ObjectOutputStream out = new ObjectOutputStream(bos)) {
+            out.writeObject(input);
+            return bos.toByteArray();
+        } catch (IOException e) {
+            throw new IllegalArgumentException("Failed to serialize inputData field", e);
+        }
+    }
+
+    /** Deserialize a byte array to Object. The object need implement Serializable. */
+    public static Object deserializeObject(byte[] bytes) {
+        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
+                ObjectInputStream in = new ObjectInputStream(bis)) {
+            return in.readObject();
+        } catch (IOException | ClassNotFoundException e) {
+            throw new IllegalArgumentException("Failed to deserialize inputData field", e);
+        }
+    }
+}
diff --git a/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginArchiveManager.java b/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginArchiveManager.java
index 57b84a9d..bc677bd5 100644
--- a/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginArchiveManager.java
+++ b/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginArchiveManager.java
@@ -58,7 +58,7 @@ import java.util.concurrent.TimeoutException;
 public final class PluginArchiveManager {
     private static final String TAG = "PluginArchiveManager";
     private static final String CHECKSUM_SUFFIX = ".md5";
-    private static final long BIND_TIMEOUT_MS = 2_000;
+    private static final long BIND_TIMEOUT_MS = 5_000;
     private final Context mApplicationContext;
 
     public PluginArchiveManager(Context applicationContext) {
@@ -159,9 +159,10 @@ public final class PluginArchiveManager {
                     TAG,
                     String.format(
                             "Error trying to call %s for the plugin: %s",
-                            serviceName, pluginArchives));
+                            serviceName, pluginArchives),
+                    e);
         } catch (IOException e) {
-            Log.e(TAG, String.format("Error trying to load the plugin: %s", pluginArchives));
+            Log.e(TAG, String.format("Error trying to load the plugin: %s", pluginArchives), e);
         }
         return false;
     }
@@ -207,7 +208,7 @@ public final class PluginArchiveManager {
                 return readiness.get(BIND_TIMEOUT_MS, MILLISECONDS);
             }
         } catch (InterruptedException | ExecutionException | TimeoutException e) {
-            Log.e(TAG, String.format("Error binding to %s", serviceName));
+            Log.e(TAG, String.format("Error binding to %s", serviceName), e);
             return false;
         }
         return true;
@@ -230,7 +231,8 @@ public final class PluginArchiveManager {
             try {
                 assetManager = packageAssetManager(pluginArchive.packageName());
             } catch (NameNotFoundException e) {
-                Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()));
+                Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()),
+                        e);
                 return DEFAULT_CHECKSUM;
             }
         } else {
@@ -278,12 +280,12 @@ public final class PluginArchiveManager {
                 FileUtils.copy(pluginSrc, pluginDst);
                 return true;
             } catch (IOException e) {
-                Log.e(TAG, String.format("Error copying %s to cache dir", pluginArchive));
+                Log.e(TAG, String.format("Error copying %s to cache dir", pluginArchive), e);
             }
             return false;
 
         } catch (NameNotFoundException e) {
-            Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()));
+            Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()), e);
         }
         return false;
     }
@@ -293,7 +295,7 @@ public final class PluginArchiveManager {
             AssetManager assetManager = packageAssetManager(pluginArchive.packageName());
             return copyPluginToCacheDir(pluginArchive.filename(), assetManager);
         } catch (NameNotFoundException e) {
-            Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()));
+            Log.e(TAG, String.format("Unknown package name %s", pluginArchive.packageName()), e);
         }
         return false;
     }
@@ -332,7 +334,8 @@ public final class PluginArchiveManager {
         } catch (IOException e) {
             Log.e(
                     TAG,
-                    String.format("Error copying %s/%s to cache dir", pluginArchive, checksumFile));
+                    String.format("Error copying %s/%s to cache dir", pluginArchive, checksumFile),
+                    e);
         }
         return false;
     }
diff --git a/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginExecutorService.java b/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginExecutorService.java
index cc93ceed..90e423aa 100644
--- a/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginExecutorService.java
+++ b/pluginlib/src/com/android/ondevicepersonalization/libraries/plugin/internal/PluginExecutorService.java
@@ -89,9 +89,10 @@ public class PluginExecutorService extends Service {
                             info, publicPluginCallback, pluginHost, pluginContextInitData);
                 } catch (RemoteException e) {
                     try {
+                        Log.e(TAG, "PluginExecutor.load failed", e);
                         pluginCallback.onFailure(FailureType.ERROR_LOADING_PLUGIN);
                     } catch (RemoteException e2) {
-                        Log.e(TAG, "load() failed to call pluginCallback.onFailure()");
+                        Log.e(TAG, "load() failed to call pluginCallback.onFailure()", e2);
                     }
                 }
             }
@@ -108,9 +109,10 @@ public class PluginExecutorService extends Service {
                     mPluginExecutor.execute(input, pluginName, publicPluginCallback);
                 } catch (RemoteException e) {
                     try {
+                        Log.e(TAG, "PluginExecutor.execute failed", e);
                         pluginCallback.onFailure(FailureType.ERROR_EXECUTING_PLUGIN);
                     } catch (RemoteException e2) {
-                        Log.e(TAG, "execute() failed to call pluginCallback.onFailure()");
+                        Log.e(TAG, "execute() failed to call pluginCallback.onFailure()", e2);
                     }
                 }
             }
@@ -123,9 +125,10 @@ public class PluginExecutorService extends Service {
                     mPluginExecutor.unload(pluginName, publicPluginCallback);
                 } catch (RemoteException e) {
                     try {
+                        Log.e(TAG, "PluginExecutor.unload failed", e);
                         pluginCallback.onFailure(FailureType.ERROR_UNLOADING_PLUGIN);
                     } catch (RemoteException e2) {
-                        Log.e(TAG, "unload() failed to call pluginCallback.onFailure()");
+                        Log.e(TAG, "unload() failed to call pluginCallback.onFailure()", e2);
                     }
                 }
             }
@@ -136,9 +139,11 @@ public class PluginExecutorService extends Service {
                     mPluginExecutor.checkPluginState(pluginName, stateCallback);
                 } catch (RemoteException e) {
                     try {
+                        Log.e(TAG, "PluginExecutor.checkPluginState failed", e);
                         stateCallback.onState(PluginState.STATE_EXCEPTION_THROWN);
                     } catch (RemoteException e2) {
-                        Log.e(TAG, "checkPluginState() failed to call stateCallback.onState()");
+                        Log.e(TAG, "checkPluginState() failed to call stateCallback.onState()",
+                                e2);
                     }
                 }
             }
diff --git a/samples/odpclient/src/main/java/com/example/odpclient/MainActivity.java b/samples/odpclient/src/main/java/com/example/odpclient/MainActivity.java
index 258f1f12..d3cf012f 100644
--- a/samples/odpclient/src/main/java/com/example/odpclient/MainActivity.java
+++ b/samples/odpclient/src/main/java/com/example/odpclient/MainActivity.java
@@ -29,6 +29,8 @@ import android.os.Handler;
 import android.os.Looper;
 import android.os.OutcomeReceiver;
 import android.os.PersistableBundle;
+import android.os.Process;
+import android.os.StrictMode;
 import android.os.Trace;
 import android.text.method.ScrollingMovementMethod;
 import android.util.Log;
@@ -42,12 +44,17 @@ import android.widget.TextView;
 import android.widget.ViewSwitcher;
 
 import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+import com.google.common.util.concurrent.ThreadFactoryBuilder;
 
 import java.io.PrintWriter;
 import java.io.StringWriter;
+import java.util.Optional;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.Executor;
 import java.util.concurrent.Executors;
+import java.util.concurrent.ThreadFactory;
 import java.util.concurrent.atomic.AtomicReference;
 
 public class MainActivity extends Activity {
@@ -72,6 +79,43 @@ public class MainActivity extends Activity {
     private Context mContext;
     private static Executor sCallbackExecutor = Executors.newSingleThreadExecutor();
 
+    private static final ListeningExecutorService sLightweightExecutor =
+            MoreExecutors.listeningDecorator(
+                    Executors.newSingleThreadExecutor(
+                            createThreadFactory(
+                                    "Lite Thread",
+                                    Process.THREAD_PRIORITY_DEFAULT,
+                                    Optional.of(getAsyncThreadPolicy()))));
+
+    private static ThreadFactory createThreadFactory(
+            final String name, final int priority, final Optional<StrictMode.ThreadPolicy> policy) {
+        return new ThreadFactoryBuilder()
+                .setDaemon(true)
+                .setNameFormat(name + " #%d")
+                .setThreadFactory(
+                        new ThreadFactory() {
+                            @Override
+                            public Thread newThread(final Runnable runnable) {
+                                return new Thread(new Runnable() {
+                                    @Override
+                                    public void run() {
+                                        if (policy.isPresent()) {
+                                            StrictMode.setThreadPolicy(policy.get());
+                                        }
+                                        // Process class operates on the current thread.
+                                        Process.setThreadPriority(priority);
+                                        runnable.run();
+                                    }
+                                });
+                            }
+                        })
+                .build();
+    }
+
+    private static StrictMode.ThreadPolicy getAsyncThreadPolicy() {
+        return new StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build();
+    }
+
     class SurfaceCallback implements SurfaceHolder.Callback {
         @Override public void surfaceCreated(SurfaceHolder holder) {
             Log.d(TAG, "surfaceCreated");
@@ -117,11 +161,16 @@ public class MainActivity extends Activity {
 
     private void registerGetAdButton() {
         mGetAdButton.setOnClickListener(
-                v -> makeRequest());
+                v -> {
+                    var unused = sLightweightExecutor.submit(() -> makeRequest());
+                });
     }
 
     private void registerReportConversionButton() {
-        mReportConversionButton.setOnClickListener(v -> reportConversion());
+        mReportConversionButton.setOnClickListener(
+                v -> {
+                    var unused = sLightweightExecutor.submit(() -> reportConversion());
+                });
     }
 
     private OnDevicePersonalizationManager getOdpManager() throws NoClassDefFoundError {
@@ -219,7 +268,9 @@ public class MainActivity extends Activity {
 
     private void registerScheduleTrainingButton() {
         mScheduleTrainingButton.setOnClickListener(
-                v -> scheduleTraining());
+                v -> {
+                    var unused = sLightweightExecutor.submit(() -> scheduleTraining());
+                });
     }
 
     private void scheduleTraining() {
@@ -278,7 +329,9 @@ public class MainActivity extends Activity {
 
     private void registerCancelTrainingButton() {
         mCancelTrainingButton.setOnClickListener(
-                v -> cancelTraining());
+                v -> {
+                    var unused = sLightweightExecutor.submit(() -> cancelTraining());
+                });
     }
 
     private void cancelTraining() {
diff --git a/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java b/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
index cfbd60ce..2dedcdb9 100644
--- a/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
+++ b/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
@@ -111,7 +111,12 @@ public class SampleHandler implements IsolatedWorker {
             "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAA"
                     + "AAXNSR0IArs4c6QAAAAtJREFUGFdjYAACAAAFAAGq1chRAAAAAElFTkSuQmCC";
     private static final byte[] TRANSPARENT_PNG_BYTES = Base64.decode(TRANSPARENT_PNG_BASE64, 0);
-    private static final int ERROR_CODE = 10;
+    private static final int ERROR_CODE_INJECT_ERROR = 10;
+    private static final int ERROR_CODE_ILLEGAL_ARGUMENT = 11;
+    private static final int ERROR_CODE_WORKER_ON_EXECUTE_ERROR = 12;
+    private static final int ERROR_CODE_WORKER_ON_RENDER_ERROR = 13;
+    private static final int ERROR_CODE_WORKER_ON_EVENT_ERROR = 14;
+    private static final int ERROR_CODE_WORKER_ON_WEB_TRIGGER_ERROR = 15;
 
     private static final ListeningExecutorService sBackgroundExecutor =
             MoreExecutors.listeningDecorator(
@@ -455,7 +460,7 @@ public class SampleHandler implements IsolatedWorker {
                     && input.getAppParams() != null
                     && input.getAppParams().getString("keyword") != null
                     && input.getAppParams().getString("keyword").equalsIgnoreCase("error")) {
-                receiver.onError(new IsolatedServiceException(ERROR_CODE));
+                receiver.onError(new IsolatedServiceException(ERROR_CODE_INJECT_ERROR));
                 return;
             }
             if (input != null
@@ -463,7 +468,7 @@ public class SampleHandler implements IsolatedWorker {
                     && input.getAppParams().getString("schedule_training") != null) {
                 Log.d(TAG, "onExecute() performing schedule training.");
                 if (input.getAppParams().getString("schedule_training").isEmpty()) {
-                    receiver.onResult(null);
+                    receiver.onError(new IsolatedServiceException(ERROR_CODE_ILLEGAL_ARGUMENT));
                     return;
                 }
                 TrainingInterval interval;
@@ -503,7 +508,7 @@ public class SampleHandler implements IsolatedWorker {
                     && input.getAppParams().getString("cancel_training") != null) {
                 Log.d(TAG, "onExecute() performing cancel training.");
                 if (input.getAppParams().getString("cancel_training").isEmpty()) {
-                    receiver.onResult(null);
+                    receiver.onError(new IsolatedServiceException(ERROR_CODE_ILLEGAL_ARGUMENT));
                     return;
                 }
                 FederatedComputeInput fcInput =
@@ -518,12 +523,11 @@ public class SampleHandler implements IsolatedWorker {
             } else if (input != null
                     && input.getAppParams() != null
                     && input.getAppParams().getString("conversion_ad_id") != null) {
-                try {
-                    receiver.onResult(handleConversion(input));
-                } catch (Exception e) {
-                    receiver.onResult(null);
+                if (input.getAppParams().getString("conversion_ad_id").isEmpty()) {
+                    receiver.onError(new IsolatedServiceException(ERROR_CODE_ILLEGAL_ARGUMENT));
                     return;
                 }
+                receiver.onResult(handleConversion(input));
             } else {
                 ListenableFuture<List<Ad>> matchAdsFuture =
                         FluentFuture.from(readAds(mRemoteData))
@@ -553,14 +557,15 @@ public class SampleHandler implements IsolatedWorker {
                                         Exception.class,
                                         e -> {
                                             Log.e(TAG, "Execution failed.", e);
-                                            receiver.onResult(null);
+                                            receiver.onError(new IsolatedServiceException(
+                                                    ERROR_CODE_WORKER_ON_EXECUTE_ERROR));
                                             return null;
                                         },
                                         MoreExecutors.directExecutor());
             }
         } catch (Exception e) {
             Log.e(TAG, "handleOnExecute() failed", e);
-            receiver.onResult(null);
+            receiver.onError(new IsolatedServiceException(ERROR_CODE_WORKER_ON_EXECUTE_ERROR));
         }
     }
 
@@ -627,9 +632,11 @@ public class SampleHandler implements IsolatedWorker {
     }
 
     private ExecuteOutput handleConversion(ExecuteInput input) {
-        String adId = input.getAppParams().getString("conversion_ad_id");
-        if (adId.isEmpty()) {
-            return null;
+        String adId = input.getAppParams().getString("conversion_ad_id").strip();
+        var builder = new ExecuteOutput.Builder();
+        if (adId == null || adId.isEmpty()) {
+            Log.d(TAG, "SourceAdId should not be empty");
+            return builder.build();
         }
         long now = System.currentTimeMillis();
         List<EventLogRecord> logRecords =
@@ -652,7 +659,6 @@ public class SampleHandler implements IsolatedWorker {
                 }
             }
         }
-        var builder = new ExecuteOutput.Builder();
         if (found != null) {
             ContentValues values = new ContentValues();
             values.put(SOURCE_TYPE_KEY, found.getType());
@@ -664,6 +670,8 @@ public class SampleHandler implements IsolatedWorker {
                             .setRequestLogRecord(found.getRequestLogRecord())
                             .build();
             builder.addEventLogRecord(conv);
+        } else {
+            Log.d(TAG, String.format("SourceAdId %s not find matched record", adId));
         }
         return builder.build();
     }
@@ -702,14 +710,15 @@ public class SampleHandler implements IsolatedWorker {
                                     Exception.class,
                                     e -> {
                                         Log.e(TAG, "Execution failed.", e);
-                                        receiver.onResult(null);
+                                        receiver.onError(new IsolatedServiceException(
+                                                ERROR_CODE_WORKER_ON_RENDER_ERROR));
                                         return null;
                                     },
                                     MoreExecutors.directExecutor());
 
         } catch (Exception e) {
             Log.e(TAG, "handleOnRender failed.", e);
-            receiver.onResult(null);
+            receiver.onError(new IsolatedServiceException(ERROR_CODE_WORKER_ON_RENDER_ERROR));
         }
     }
 
@@ -752,7 +761,7 @@ public class SampleHandler implements IsolatedWorker {
             receiver.onResult(result);
         } catch (Exception e) {
             Log.e(TAG, "handleOnEvent failed.", e);
-            receiver.onResult(null);
+            receiver.onError(new IsolatedServiceException(ERROR_CODE_WORKER_ON_EVENT_ERROR));
         }
     }
 
@@ -810,7 +819,8 @@ public class SampleHandler implements IsolatedWorker {
             receiver.onResult(output);
         } catch (Exception e) {
             Log.e(TAG, "handleOnWebTrigger failed.", e);
-            receiver.onResult(null);
+            receiver.onError(new IsolatedServiceException(
+                    ERROR_CODE_WORKER_ON_WEB_TRIGGER_ERROR));
         }
     }
 
diff --git a/src/com/android/ondevicepersonalization/services/FeatureStatusManager.java b/src/com/android/ondevicepersonalization/services/FeatureStatusManager.java
new file mode 100644
index 00000000..38b9c710
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/FeatureStatusManager.java
@@ -0,0 +1,117 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services;
+
+import android.adservices.ondevicepersonalization.CalleeMetadata;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
+import android.os.Binder;
+import android.os.RemoteException;
+import android.os.SystemClock;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.function.Supplier;
+
+public class FeatureStatusManager {
+    private static final Object sLock = new Object();
+
+    private static final String TAG = FeatureStatusManager.class.getSimpleName();
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static volatile FeatureStatusManager sFeatureStatusManager = null;
+
+    private final Map<String, Supplier<Boolean>> mFlaggedFeaturesMap = new HashMap<>();
+
+    private final Set<String> mNonFlaggedFeaturesSet = new HashSet<>();
+
+    private Flags mFlags;
+
+    /** Returns the status of the feature. */
+    public static void getFeatureStatusAndSendResult(
+            String featureName,
+            long serviceEntryTime,
+            IIsFeatureEnabledCallback callback) {
+        int result = getInstance().isFeatureEnabled(featureName);
+        try {
+            callback.onResult(
+                    result,
+                    new CalleeMetadata.Builder()
+                            .setServiceEntryTimeMillis(serviceEntryTime)
+                            .setCallbackInvokeTimeMillis(
+                                    SystemClock.elapsedRealtime()).build());
+        } catch (RemoteException e) {
+            sLogger.w(TAG + ": Callback error", e);
+        }
+    }
+
+    /** Returns the singleton instance of FeatureManager. */
+    public static FeatureStatusManager getInstance() {
+        if (sFeatureStatusManager == null) {
+            synchronized (sLock) {
+                if (sFeatureStatusManager == null) {
+                    long origId = Binder.clearCallingIdentity();
+                    sFeatureStatusManager = new FeatureStatusManager(FlagsFactory.getFlags());
+                    Binder.restoreCallingIdentity(origId);
+                }
+            }
+        }
+        return sFeatureStatusManager;
+    }
+
+    @VisibleForTesting
+    FeatureStatusManager(Flags flags) {
+        mFlags = flags;
+        // Add flagged features here, for example:
+        // mFlaggedFeaturesMap.put("featureName", mFlags::isFeatureEnabled);
+
+        // Add non-flagged features here, for example:
+        // mNonFlaggedFeaturesSet.add("featureName");
+    }
+
+    @VisibleForTesting
+    FeatureStatusManager(Flags flags,
+            Map<String, Supplier<Boolean>> flaggedFeaturesMap,
+            Set<String> nonFlaggedFeaturesSet) {
+        mFlags = flags;
+
+        // Add flagged features here
+        mFlaggedFeaturesMap.putAll(flaggedFeaturesMap);
+
+        // Add non-flagged features here
+        mNonFlaggedFeaturesSet.addAll(nonFlaggedFeaturesSet);
+    }
+
+    @VisibleForTesting
+    int isFeatureEnabled(String featureName) {
+        if (mNonFlaggedFeaturesSet.contains(featureName)) {
+            return OnDevicePersonalizationManager.FEATURE_ENABLED;
+        }
+
+        if (mFlaggedFeaturesMap.containsKey(featureName)) {
+            boolean flagValue = mFlaggedFeaturesMap.get(featureName).get();
+            return flagValue ? OnDevicePersonalizationManager.FEATURE_ENABLED
+                    : OnDevicePersonalizationManager.FEATURE_DISABLED;
+        }
+
+        return OnDevicePersonalizationManager.FEATURE_UNSUPPORTED;
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/Flags.java b/src/com/android/ondevicepersonalization/services/Flags.java
index 5e641271..98f48d0d 100644
--- a/src/com/android/ondevicepersonalization/services/Flags.java
+++ b/src/com/android/ondevicepersonalization/services/Flags.java
@@ -23,6 +23,8 @@ import com.android.adservices.shared.common.flags.ConfigFlag;
 import com.android.adservices.shared.common.flags.FeatureFlag;
 import com.android.adservices.shared.common.flags.ModuleSharedFlags;
 
+import java.util.concurrent.TimeUnit;
+
 /**
  * OnDevicePersonalization Feature Flags interface. This Flags interface hold the default values
  * of flags. The default values in this class must match with the default values in PH since we
@@ -99,6 +101,9 @@ public interface Flags extends ModuleSharedFlags {
     /** Default deadline for data reset. */
     int DEFAULT_RESET_DATA_DEADLINE_SECONDS = 30 * 60 * 60; // 30 hours
 
+    /** Default value for the plugin runner flag. */
+    boolean DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED = false;
+
     String DEFAULT_CALLER_APP_ALLOW_LIST =
             "android.ondevicepersonalization,"
                     + "android.ondevicepersonalization.test.scenario,"
@@ -286,7 +291,7 @@ public interface Flags extends ModuleSharedFlags {
     }
 
     String DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH =
-            "debugreporting/v1/exceptions:report-exceptions";
+            "/debugreporting/v1/exceptions:report-exceptions";
 
     /**
      * URL suffix that the reporting job will use to send adopters daily aggregated counts of {@link
@@ -320,6 +325,53 @@ public interface Flags extends ModuleSharedFlags {
         return DEFAULT_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
     }
 
+    boolean DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD = false;
+
+    /**
+     * Whether to disable encryption for aggregated error data reporting.
+     *
+     * <p>Only {@code true} for testing etc.
+     */
+    default boolean getAllowUnencryptedAggregatedErrorReportingPayload() {
+        return DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD;
+    }
+
+    String DEFAULT_ENCRYPTION_KEY_URL = "https://fake-coordinator/v1alpha/publicKeys";
+
+    /**
+     * The URL from which to fetch encryption keys.
+     *
+     * <p>Currently encryption keys are only used for aggregate error reporting encryption.
+     *
+     * @return Url to fetch encryption key for ODP.
+     */
+    default String getEncryptionKeyFetchUrl() {
+        return DEFAULT_ENCRYPTION_KEY_URL;
+    }
+
+    long DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS = TimeUnit.DAYS.toSeconds(/* duration= */ 14);
+
+    /**
+     * @return default max age in seconds for ODP encryption keys.
+     */
+    default long getEncryptionKeyMaxAgeSeconds() {
+        return DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS;
+    }
+
+    int DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS = 30;
+
+    /** Timeout for http reporting of aggregated error data. */
+    default int getAggregatedErrorReportingHttpTimeoutSeconds() {
+        return DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS;
+    }
+
+    int DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT = 3;
+
+    /** Timeout for http reporting of aggregated error data. */
+    default int getAggregatedErrorReportingHttpRetryLimit() {
+        return DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT;
+    }
+
     /**
      * Default value for maximum int value caller can set in {@link
      * ExecuteInIsolatedServiceRequest.OutputSpec#buildBestValueSpec}.
@@ -356,4 +408,14 @@ public interface Flags extends ModuleSharedFlags {
     default String getLogIsolatedServiceErrorCodeNonAggregatedAllowlist() {
         return DEFAULT_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST;
     }
+
+    default boolean isPluginProcessRunnerEnabled() {
+        return DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED;
+    }
+
+    boolean DEFAULT_IS_FEATURE_ENABLED_API_ENABLED = false;
+
+    default boolean isFeatureEnabledApiEnabled() {
+        return DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
index fef41b9a..c17586c3 100644
--- a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
+++ b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
@@ -16,6 +16,7 @@
 
 package com.android.ondevicepersonalization.services;
 
+import static android.content.Intent.ACTION_BOOT_COMPLETED;
 import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
 
 import android.content.BroadcastReceiver;
@@ -27,6 +28,7 @@ import android.content.pm.PackageManager;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.DeviceUtils;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingService;
 import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJobService;
 import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
@@ -34,21 +36,23 @@ import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonal
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
 
+import java.util.List;
 import java.util.concurrent.Executor;
 
 /** BroadcastReceiver used to schedule OnDevicePersonalization jobs/workers. */
 public class OnDevicePersonalizationBroadcastReceiver extends BroadcastReceiver {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = "OnDevicePersonalizationBroadcastReceiver";
-    private final Executor mExecutor;
+    private final ListeningExecutorService mExecutor;
 
     public OnDevicePersonalizationBroadcastReceiver() {
-        this.mExecutor = OnDevicePersonalizationExecutors.getLightweightExecutor();
+        this(OnDevicePersonalizationExecutors.getLightweightExecutor());
     }
 
     @VisibleForTesting
-    public OnDevicePersonalizationBroadcastReceiver(Executor executor) {
+    OnDevicePersonalizationBroadcastReceiver(ListeningExecutorService executor) {
         this.mExecutor = executor;
     }
 
@@ -68,7 +72,10 @@ public class OnDevicePersonalizationBroadcastReceiver extends BroadcastReceiver
         return true;
     }
 
-    /** Called when the broadcast is received. OnDevicePersonalization jobs will be started here. */
+    /**
+     * Called when the {@link ACTION_BOOT_COMPLETED} broadcast is received. OnDevicePersonalization
+     * jobs will be started here.
+     */
     public void onReceive(Context context, Intent intent) {
         if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
             sLogger.d(TAG + ": GlobalKillSwitch on, skipped broadcast.");
@@ -82,49 +89,53 @@ public class OnDevicePersonalizationBroadcastReceiver extends BroadcastReceiver
 
         sLogger.d(TAG + ": onReceive() with intent + " + intent.getAction());
 
-        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
+        if (!ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
             sLogger.d(TAG + ": Received unexpected intent " + intent.getAction());
             return;
         }
         final PendingResult pendingResult = goAsync();
-        // Schedule MDD to download scripts periodically.
+        // Schedule maintenance and MDD tasks to download scripts periodically etc.
         Futures.addCallback(
                 restoreOdpJobs(context, mExecutor),
-                new FutureCallback<Void>() {
+                new FutureCallback<List<Void>>() {
                     @Override
-                    public void onSuccess(Void result) {
-                        sLogger.d(TAG + ": Successfully scheduled MDD tasks.");
+                    public void onSuccess(List<Void> result) {
+                        sLogger.d(TAG + ": handled job scheduling tasks successfully");
                         pendingResult.finish();
                     }
+
                     @Override
                     public void onFailure(Throwable t) {
-                        sLogger.e(TAG + ": Failed to schedule MDD tasks.", t);
+                        sLogger.e(t, TAG + ": failed to handle all job scheduling tasks.");
                         pendingResult.finish();
                     }
                 },
                 mExecutor);
     }
 
-    /**
-     * Restores periodic jobs scheduling.
-     */
-    public static ListenableFuture<Void> restoreOdpJobs(Context context, Executor executor) {
+    /** Restores periodic jobs scheduling. */
+    static ListenableFuture<List<Void>> restoreOdpJobs(Context context, Executor executor) {
         if (FlagsFactory.getFlags().getGlobalKillSwitch() || !DeviceUtils.isOdpSupported(context)) {
             sLogger.d(TAG + ": ODP disabled or unsupported device");
             return null;
         }
 
-        var unused =
+        ListenableFuture<Void> maintenanceFuture =
                 Futures.submit(
                         () -> {
                             // Schedule maintenance task
                             OnDevicePersonalizationMaintenanceJob.schedule(context);
                             // Schedule user data collection task
                             UserDataCollectionJobService.schedule(context);
+                            // Schedule regular ODP aggregated error reporting task if the flag
+                            // is enabled etc.
+                            AggregateErrorDataReportingService.scheduleIfNeeded(context);
                         },
                         executor);
 
         // Schedule MDD to download scripts periodically.
-        return MobileDataDownloadFactory.getMdd(context).schedulePeriodicBackgroundTasks();
+        ListenableFuture<Void> mddFuture =
+                MobileDataDownloadFactory.getMdd(context).schedulePeriodicBackgroundTasks();
+        return Futures.successfulAsList(maintenanceFuture, mddFuture);
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
index 4d5d7ac2..d6f51e26 100644
--- a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
+++ b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
@@ -23,6 +23,7 @@ import android.adservices.ondevicepersonalization.Constants;
 import android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceRequest;
 import android.adservices.ondevicepersonalization.ExecuteOptionsParcel;
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
@@ -210,6 +211,33 @@ public class OnDevicePersonalizationManagingServiceDelegate
         Trace.endSection();
     }
 
+    @Override
+    public void isFeatureEnabled(
+            @NonNull String featureName,
+            @NonNull CallerMetadata metadata,
+            @NonNull IIsFeatureEnabledCallback callback) {
+        if (getGlobalKillSwitch()) {
+            throw new IllegalStateException("Service skipped as the global kill switch is on.");
+        }
+
+        if (!DeviceUtils.isOdpSupported(mContext)) {
+            throw new IllegalStateException("Device not supported.");
+        }
+
+        if (!getOdpIsFeatureEnabledFlagEnabled()) {
+            throw new IllegalStateException("isFeatureEnabled flag is not enabled.");
+        }
+
+        long serviceEntryTimeMillis = SystemClock.elapsedRealtime();
+        Trace.beginSection("OdpManagingServiceDelegate#IsFeatureEnabled");
+
+        FeatureStatusManager.getFeatureStatusAndSendResult(featureName,
+                serviceEntryTimeMillis,
+                callback);
+
+        Trace.endSection();
+    }
+
     @Override
     public void logApiCallStats(
             String sdkPackageName, int apiName, long latencyMillis, long rpcCallLatencyMillis,
@@ -249,6 +277,13 @@ public class OnDevicePersonalizationManagingServiceDelegate
         return globalKillSwitch;
     }
 
+    private boolean getOdpIsFeatureEnabledFlagEnabled() {
+        long origId = Binder.clearCallingIdentity();
+        boolean flagEnabled = mInjector.getFlags().isFeatureEnabledApiEnabled();
+        Binder.restoreCallingIdentity(origId);
+        return flagEnabled;
+    }
+
     private void enforceCallingPackageBelongsToUid(@NonNull String packageName, int uid) {
         int packageUid;
         PackageManager pm = mContext.getPackageManager();
diff --git a/src/com/android/ondevicepersonalization/services/PhFlags.java b/src/com/android/ondevicepersonalization/services/PhFlags.java
index 00d89a26..ab963829 100644
--- a/src/com/android/ondevicepersonalization/services/PhFlags.java
+++ b/src/com/android/ondevicepersonalization/services/PhFlags.java
@@ -97,20 +97,32 @@ public final class PhFlags implements Flags {
     public static final String EXECUTE_BEST_VALUE_NOISE = "noise_for_execute_best_value";
 
     public static final String KEY_ENABLE_AGGREGATED_ERROR_REPORTING =
-            "enable_aggregated_error_reporting";
+            "Odp__enable_aggregated_error_reporting";
 
     public static final String KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS =
-            "aggregated_error_report_ttl_days";
+            "Odp__aggregated_error_report_ttl_days";
 
     public static final String KEY_AGGREGATED_ERROR_REPORTING_PATH =
-            "aggregated_error_reporting_path";
+            "Odp__aggregated_error_reporting_path";
 
     public static final String KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD =
-            "aggregated_error_reporting_threshold";
+            "Odp__aggregated_error_reporting_threshold";
 
     public static final String KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS =
-            "aggregated_error_reporting_interval_hours";
+            "Odp__aggregated_error_reporting_interval_hours";
+    public static final String KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING =
+            "Odp__aggregated_error_allow_unencrypted_aggregated_error_reporting";
 
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS =
+            "Odp__aggregated_error_reporting_http_timeout_seconds";
+
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT =
+            "Odp__aggregated_error_reporting_http_retry_limit";
+
+    public static final String KEY_ENCRYPTION_KEY_URL = "Odp__encryption_key_download_url";
+
+    public static final String KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS =
+            "Odp__encryption_key_max_age_seconds";
     public static final String MAX_INT_VALUES_LIMIT = "max_int_values_limit";
 
     public static final String KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS =
@@ -123,6 +135,12 @@ public final class PhFlags implements Flags {
     public static final String KEY_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST =
             "log_isolated_service_error_code_non_aggregated_allowlist";
 
+    public static final String KEY_PLUGIN_PROCESS_RUNNER_ENABLED =
+            "Odp__enable_plugin_process_runner";
+
+    public static final String KEY_IS_FEATURE_ENABLED_API_ENABLED =
+            "Odp__enable_is_feature_enabled";
+
     // OnDevicePersonalization Namespace String from DeviceConfig class
     public static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
 
@@ -434,6 +452,46 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ DEFAULT_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS);
     }
 
+    @Override
+    public boolean getAllowUnencryptedAggregatedErrorReportingPayload() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
+                /* defaultValue= */ DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD);
+    }
+
+    @Override
+    public int getAggregatedErrorReportingHttpTimeoutSeconds() {
+        return DeviceConfig.getInt(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS,
+                /* defaultValue= */ DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS);
+    }
+
+    @Override
+    public int getAggregatedErrorReportingHttpRetryLimit() {
+        return DeviceConfig.getInt(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT,
+                /* defaultValue= */ DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT);
+    }
+
+    @Override
+    public String getEncryptionKeyFetchUrl() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ENCRYPTION_KEY_URL,
+                /* defaultValue= */ DEFAULT_ENCRYPTION_KEY_URL);
+    }
+
+    @Override
+    public long getEncryptionKeyMaxAgeSeconds() {
+        return DeviceConfig.getLong(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS,
+                /* defaultValue= */ DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS);
+    }
+
     @Override
     public int getMaxIntValuesLimit() {
         return DeviceConfig.getInt(
@@ -474,4 +532,20 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */
                 DEFAULT_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST);
     }
+
+    @Override
+    public boolean isPluginProcessRunnerEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_PLUGIN_PROCESS_RUNNER_ENABLED,
+                /* defaultValue= */ DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED);
+    }
+
+    @Override
+    public boolean isFeatureEnabledApiEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                /* defaultValue= */ DEFAULT_IS_FEATURE_ENABLED_API_ENABLED);
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/StableFlags.java b/src/com/android/ondevicepersonalization/services/StableFlags.java
index 3a7141ea..22cb30c5 100644
--- a/src/com/android/ondevicepersonalization/services/StableFlags.java
+++ b/src/com/android/ondevicepersonalization/services/StableFlags.java
@@ -79,6 +79,8 @@ public class StableFlags {
                 flags.getPersonalizationStatusOverrideValue());
         mStableFlagsMap.put(PhFlags.KEY_USER_CONTROL_CACHE_IN_MILLIS,
                 flags.getUserControlCacheInMillis());
+        mStableFlagsMap.put(PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED,
+                flags.isPluginProcessRunnerEnabled());
     }
 
     private Object getStableFlag(String flagName) {
diff --git a/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java b/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
index 380159be..281aeea1 100644
--- a/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
@@ -158,7 +158,9 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
             case Constants.DATA_ACCESS_OP_REMOTE_DATA_LOOKUP:
                 String lookupKey = params.getString(Constants.EXTRA_LOOKUP_KEYS);
                 if (lookupKey == null || lookupKey.isEmpty()) {
-                    throw new IllegalArgumentException("Missing lookup key.");
+                    sLogger.w(TAG + "Missing lookup key.");
+                    sendError(callback, Constants.STATUS_KEY_NOT_FOUND);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> remoteDataLookup(
@@ -170,11 +172,15 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                 break;
             case Constants.DATA_ACCESS_OP_LOCAL_DATA_LOOKUP:
                 if (mLocalDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException("LocalData is not included for this instance.");
+                    sLogger.w(TAG + "LocalData is not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 lookupKey = params.getString(Constants.EXTRA_LOOKUP_KEYS);
                 if (lookupKey == null || lookupKey.isEmpty()) {
-                    throw new IllegalArgumentException("Missing lookup key.");
+                    sLogger.w(TAG + "Missing lookup key.");
+                    sendError(callback, Constants.STATUS_KEY_NOT_FOUND);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> localDataLookup(
@@ -182,17 +188,23 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                 break;
             case Constants.DATA_ACCESS_OP_LOCAL_DATA_KEYSET:
                 if (mLocalDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException("LocalData is not included for this instance.");
+                    sLogger.w(TAG + "LocalData is not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> localDataKeyset(callback));
                 break;
             case Constants.DATA_ACCESS_OP_LOCAL_DATA_PUT:
                 if (mLocalDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException("LocalData is not included for this instance.");
+                    sLogger.w(TAG + "LocalData is not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 if (mLocalDataPermission == DataAccessPermission.READ_ONLY) {
-                    throw new IllegalStateException("LocalData is read-only for this instance.");
+                    sLogger.w(TAG + "LocalData is read-only for this instance.");
+                    sendError(callback, Constants.STATUS_LOCAL_DATA_READ_ONLY);
+                    break;
                 }
                 String putKey = params.getString(Constants.EXTRA_LOOKUP_KEYS);
                 ByteArrayParceledSlice parceledValue = params.getParcelable(
@@ -206,14 +218,20 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                 break;
             case Constants.DATA_ACCESS_OP_LOCAL_DATA_REMOVE:
                 if (mLocalDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException("LocalData is not included for this instance.");
+                    sLogger.w(TAG + "LocalData is not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 if (mLocalDataPermission == DataAccessPermission.READ_ONLY) {
-                    throw new IllegalStateException("LocalData is read-only for this instance.");
+                    sLogger.w(TAG + "LocalData is read-only for this instance.");
+                    sendError(callback, Constants.STATUS_LOCAL_DATA_READ_ONLY);
+                    break;
                 }
                 String deleteKey = params.getString(Constants.EXTRA_LOOKUP_KEYS);
                 if (deleteKey == null || deleteKey.isEmpty()) {
-                    throw new IllegalArgumentException("Invalid key provided for delete.");
+                    sLogger.w(TAG + "Missing delete key.");
+                    sendError(callback, Constants.STATUS_KEY_NOT_FOUND);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> localDataDelete(deleteKey, callback));
@@ -231,38 +249,47 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                 break;
             case Constants.DATA_ACCESS_OP_GET_REQUESTS:
                 if (mEventDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException(
-                            "request and event data are not included for this instance.");
+                    sLogger.w(TAG + "Request and event data are not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 long[] requestTimes = Objects.requireNonNull(params.getLongArray(
                         Constants.EXTRA_LOOKUP_KEYS));
                 if (requestTimes.length != 2) {
-                    throw new IllegalArgumentException("Invalid request timestamps provided.");
+                    sLogger.w(TAG + "Invalid request timestamps provided.");
+                    sendError(callback, Constants.STATUS_REQUEST_TIMESTAMPS_INVALID);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> getRequests(requestTimes[0], requestTimes[1], callback));
                 break;
             case Constants.DATA_ACCESS_OP_GET_JOINED_EVENTS:
                 if (mEventDataPermission == DataAccessPermission.DENIED) {
-                    throw new IllegalStateException(
-                            "request and event data are not included for this instance.");
+                    sLogger.w(TAG + "Request and event data are not included for this instance.");
+                    sendError(callback, Constants.STATUS_PERMISSION_DENIED);
+                    break;
                 }
                 long[] eventTimes = Objects.requireNonNull(params.getLongArray(
                         Constants.EXTRA_LOOKUP_KEYS));
                 if (eventTimes.length != 2) {
-                    throw new IllegalArgumentException("Invalid event timestamps provided.");
+                    sLogger.w(TAG + "Invalid request timestamps provided.");
+                    sendError(callback, Constants.STATUS_REQUEST_TIMESTAMPS_INVALID);
+                    break;
                 }
                 mInjector.getExecutor().execute(
                         () -> getJoinedEvents(eventTimes[0], eventTimes[1], callback));
                 break;
             case Constants.DATA_ACCESS_OP_GET_MODEL:
-                ModelId modelId =
-                        Objects.requireNonNull(
-                                params.getParcelable(Constants.EXTRA_MODEL_ID, ModelId.class));
+                ModelId modelId = params.getParcelable(Constants.EXTRA_MODEL_ID, ModelId.class);
+                if (modelId == null) {
+                    sLogger.w(TAG + "Model Id is not provided.");
+                    sendError(callback, Constants.STATUS_KEY_NOT_FOUND);
+                    break;
+                }
                 mInjector.getExecutor().execute(() -> getModelFileDescriptor(modelId, callback));
                 break;
             default:
-                sendError(callback);
+                sendError(callback, Constants.STATUS_DATA_ACCESS_UNSUPPORTED_OP);
         }
     }
 
@@ -321,7 +348,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     Constants.EXTRA_RESULT, new ByteArrayParceledSlice(data));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -333,7 +360,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     Constants.EXTRA_RESULT, new ByteArrayParceledSlice(data));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -344,14 +371,14 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
             byte[] existingData = mLocalDataDao.readSingleLocalDataRow(key);
             if (!mLocalDataDao.updateOrInsertLocalData(
                     new LocalData.Builder().setKey(key).setData(data).build())) {
-                sendError(callback);
+                sendError(callback, Constants.STATUS_LOCAL_WRITE_DATA_ACCESS_FAILURE);
             }
             Bundle result = new Bundle();
             result.putParcelable(
                     Constants.EXTRA_RESULT, new ByteArrayParceledSlice(existingData));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -364,7 +391,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     Constants.EXTRA_RESULT, new ByteArrayParceledSlice(existingData));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -390,7 +417,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
             sendResult(result, callback);
         } catch (Exception e) {
             sLogger.d(TAG + ": getEventUrl() failed.", e);
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -414,7 +441,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     new OdpParceledListSlice<>(requestLogRecords));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -446,7 +473,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     new OdpParceledListSlice<>(joinedLogRecords));
             sendResult(result, callback);
         } catch (Exception e) {
-            sendError(callback);
+            sendError(callback, Constants.STATUS_DATA_ACCESS_FAILURE);
         }
     }
 
@@ -462,13 +489,14 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
                     modelData = mLocalDataDao.readSingleLocalDataRow(modelId.getKey());
                     break;
                 default:
-                    throw new IllegalStateException(
-                            "Unsupported table name " + modelId.getTableId());
+                    sLogger.e(TAG + "Unsupported model table Id %d", modelId.getTableId());
+                    sendError(callback, Constants.STATUS_MODEL_TABLE_ID_INVALID);
+                    return;
             }
 
             if (modelData == null) {
                 sLogger.e(TAG + " Failed to find model data from database: " + modelId.getKey());
-                sendError(callback);
+                sendError(callback, Constants.STATUS_MODEL_DB_LOOKUP_FAILED);
                 return;
             }
             String modelFile =
@@ -481,8 +509,8 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
             result.putParcelable(Constants.EXTRA_RESULT, modelFd);
             sendResult(result, callback);
         } catch (Exception e) {
-            sLogger.e(TAG + " Failed to find model data: " + modelId.getKey(), e);
-            sendError(callback);
+            sLogger.e(e, TAG + " Failed to find model data: %s ", modelId.getKey());
+            sendError(callback, Constants.STATUS_MODEL_LOOKUP_FAILURE);
         }
     }
 
@@ -496,11 +524,11 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
         }
     }
 
-    private void sendError(@NonNull IDataAccessServiceCallback callback) {
+    private void sendError(@NonNull IDataAccessServiceCallback callback, int errorCode) {
         try {
-            callback.onError(Constants.STATUS_INTERNAL_ERROR);
+            callback.onError(errorCode);
         } catch (RemoteException e) {
-            sLogger.e(TAG + ": Callback error", e);
+            sLogger.e(e, TAG + ": Callback error! Failed to set error code %d", errorCode);
         }
     }
 
diff --git a/src/com/android/ondevicepersonalization/services/data/EncryptionUtils.java b/src/com/android/ondevicepersonalization/services/data/EncryptionUtils.java
new file mode 100644
index 00000000..f376eab6
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/EncryptionUtils.java
@@ -0,0 +1,96 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data;
+
+import android.content.Context;
+
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+/**
+ * Utility class that configures and provides appropriate {@link OdpEncryptionKeyManager} instance
+ * for use by ODP code.
+ */
+public class EncryptionUtils {
+    /**
+     * Flag based implementation of {@link
+     * com.android.odp.module.common.encryption.OdpEncryptionKeyManager.KeyManagerConfig}.
+     */
+    public static class FlagKeyManagerConfig implements OdpEncryptionKeyManager.KeyManagerConfig {
+
+        private final Flags mFlags;
+        private final OnDevicePersonalizationDbHelper mDbHelper;
+
+        FlagKeyManagerConfig(Flags flags, OnDevicePersonalizationDbHelper dbHelper) {
+            mFlags = flags;
+            this.mDbHelper = dbHelper;
+        }
+
+        @Override
+        public String getEncryptionKeyFetchUrl() {
+            return mFlags.getEncryptionKeyFetchUrl();
+        }
+
+        @Override
+        public int getHttpRequestRetryLimit() {
+            return mFlags.getAggregatedErrorReportingHttpRetryLimit();
+        }
+
+        @Override
+        public long getEncryptionKeyMaxAgeSeconds() {
+            return mFlags.getEncryptionKeyMaxAgeSeconds();
+        }
+
+        @Override
+        public OdpSQLiteOpenHelper getSQLiteOpenHelper() {
+            return mDbHelper;
+        }
+
+        @Override
+        public ListeningExecutorService getBackgroundExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        @Override
+        public ListeningExecutorService getBlockingExecutor() {
+            return OnDevicePersonalizationExecutors.getBlockingExecutor();
+        }
+    }
+
+    private EncryptionUtils() {}
+
+    /**
+     * Returns an instance of the {@link OdpEncryptionKeyManager}.
+     *
+     * <p>Creates a {@link FlagKeyManagerConfig} for use by the {@link OdpEncryptionKeyManager} that
+     * reflects current relevant flag values.
+     *
+     * @param context calling context.
+     */
+    public static OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+        return OdpEncryptionKeyManager.getInstance(
+                context,
+                new FlagKeyManagerConfig(
+                        FlagsFactory.getFlags(),
+                        OnDevicePersonalizationDbHelper.getInstance(context)));
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/OnDevicePersonalizationDbHelper.java b/src/com/android/ondevicepersonalization/services/data/OnDevicePersonalizationDbHelper.java
index c068f9fc..0bcd5ddb 100644
--- a/src/com/android/ondevicepersonalization/services/data/OnDevicePersonalizationDbHelper.java
+++ b/src/com/android/ondevicepersonalization/services/data/OnDevicePersonalizationDbHelper.java
@@ -24,9 +24,9 @@ import android.annotation.Nullable;
 import android.content.Context;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
-import android.database.sqlite.SQLiteOpenHelper;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.data.events.EventStateContract;
 import com.android.ondevicepersonalization.services.data.events.EventsContract;
@@ -38,7 +38,7 @@ import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientEr
 import java.util.List;
 
 /** Helper to manage the OnDevicePersonalization database. */
-public class OnDevicePersonalizationDbHelper extends SQLiteOpenHelper {
+public class OnDevicePersonalizationDbHelper extends OdpSQLiteOpenHelper {
 
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = "OnDevicePersonalizationDbHelper";
@@ -143,6 +143,7 @@ public class OnDevicePersonalizationDbHelper extends SQLiteOpenHelper {
     }
 
     /** Wraps getWritableDatabase to catch SQLiteException and log error. */
+    @Override
     @Nullable
     public SQLiteDatabase safeGetWritableDatabase() {
         try {
@@ -159,6 +160,7 @@ public class OnDevicePersonalizationDbHelper extends SQLiteOpenHelper {
     }
 
     /** Wraps getReadableDatabase to catch SQLiteException and log error. */
+    @Override
     @Nullable
     public SQLiteDatabase safeGetReadableDatabase() {
         try {
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
index 075290d8..4e3eb451 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
@@ -30,23 +30,33 @@ import android.content.ComponentName;
 import android.content.Context;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.data.EncryptionUtils;
 import com.android.ondevicepersonalization.services.statsd.joblogging.OdpJobServiceLogger;
 
+import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
-import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
 
-/** {@link JobService} to perform daily reporting of aggregated error codes. */
+import java.util.List;
+import java.util.Optional;
+
+/**
+ * The {@link JobService} to perform daily reporting of aggregated error codes.
+ *
+ * <p>The actual reporting task is offloaded to {@link AggregatedErrorReportingWorker}.
+ */
 public class AggregateErrorDataReportingService extends JobService {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = AggregateErrorDataReportingService.class.getSimpleName();
 
-    private ListenableFuture<Void> mFuture;
+    private FluentFuture<Void> mFuture;
 
     private final Injector mInjector;
 
@@ -59,6 +69,7 @@ public class AggregateErrorDataReportingService extends JobService {
         mInjector = injector;
     }
 
+    @VisibleForTesting
     static class Injector {
         ListeningExecutorService getExecutor() {
             return OnDevicePersonalizationExecutors.getBackgroundExecutor();
@@ -67,6 +78,14 @@ public class AggregateErrorDataReportingService extends JobService {
         Flags getFlags() {
             return FlagsFactory.getFlags();
         }
+
+        AggregatedErrorReportingWorker getErrorReportingWorker() {
+            return AggregatedErrorReportingWorker.createWorker();
+        }
+
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return EncryptionUtils.getEncryptionKeyManager(context);
+        }
     }
 
     /** Schedules a unique instance of the {@link AggregateErrorDataReportingService} to be run. */
@@ -126,16 +145,24 @@ public class AggregateErrorDataReportingService extends JobService {
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_JOB_NOT_CONFIGURED);
         }
 
+        OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(/* context= */ this);
+        // By default, the aggregated error data payload is encrypted.
+        FluentFuture<List<OdpEncryptionKey>> encryptionKeyFuture =
+                mInjector.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload()
+                        ? FluentFuture.from(Futures.immediateFuture(List.of()))
+                        : keyManager.fetchAndPersistActiveKeys(
+                                OdpEncryptionKey.KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
+                                Optional.empty());
+
+        AggregatedErrorReportingWorker worker = mInjector.getErrorReportingWorker();
         mFuture =
-                Futures.submit(
-                        new Runnable() {
-                            @Override
-                            public void run() {
-                                // TODO(b/329921267): Add logic for reporting new data from DAO.
-                                sLogger.d(
-                                        TAG + ": Running the aggregate error data collection job");
-                            }
-                        },
+                encryptionKeyFuture.transformAsync(
+                        encryptionKeys ->
+                                FluentFuture.from(
+                                        worker.reportAggregateErrors(
+                                                /* context= */ this,
+                                                OdpEncryptionKeyManager.getRandomKey(
+                                                        encryptionKeys))),
                         mInjector.getExecutor());
 
         Futures.addCallback(
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java
new file mode 100644
index 00000000..2bfb217e
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java
@@ -0,0 +1,354 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_TYPE_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.PROTOBUF_CONTENT_TYPE;
+
+import android.annotation.Nullable;
+import android.content.Context;
+import android.util.Base64;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.encryption.Encrypter;
+import com.android.odp.module.common.encryption.HpkeJniEncrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
+import com.android.odp.module.common.http.OdpHttpResponse;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+
+import com.google.common.base.Preconditions;
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.ListeningScheduledExecutorService;
+import com.google.internal.federatedcompute.v1.ResourceCompressionFormat;
+import com.google.ondevicepersonalization.federatedcompute.proto.ReportExceptionRequest;
+import com.google.ondevicepersonalization.federatedcompute.proto.ReportExceptionResponse;
+import com.google.ondevicepersonalization.federatedcompute.proto.UploadInstruction;
+import com.google.protobuf.Timestamp;
+
+import org.json.JSONException;
+import org.json.JSONObject;
+
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Manages the http connection and request/response from client->server for one error report.
+ *
+ * <p>Called into by the {@link AggregatedErrorReportingWorker} to offload the details of http
+ * connection and request/response.
+ *
+ * <p>The {@link ErrorData} to be reported and the vendor URL/path are set at creation time, refer
+ * to {@link #createAggregatedErrorReportingProtocol(ImmutableList, String, Context)} for details.
+ */
+class AggregatedErrorReportingProtocol implements ReportingProtocol {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = AggregatedErrorReportingProtocol.class.getSimpleName();
+
+    /** Data to be reported. */
+    private final ImmutableList<ErrorData> mErrorData;
+
+    private final String mRequestBaseUri;
+    private final ImmutableMap<String, String> mHeaderList;
+
+    // TODO(b/329921267): update proto to include client version.
+    private final long mClientVersion;
+
+    private final HttpClient mHttpClient;
+
+    private final Injector mInjector;
+
+    private final Encrypter mEncrypter;
+
+    @VisibleForTesting
+    static class Injector {
+        ListeningExecutorService getBlockingExecutor() {
+            return OnDevicePersonalizationExecutors.getBlockingExecutor();
+        }
+
+        ListeningExecutorService getBackgroundExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        ListeningScheduledExecutorService getScheduledExecutor() {
+            return OnDevicePersonalizationExecutors.getScheduledExecutor();
+        }
+
+        Flags getFlags() {
+            return FlagsFactory.getFlags();
+        }
+
+        // Allows for easier injection a mock client in tests.
+        HttpClient getClient() {
+            return new HttpClient(
+                    getFlags().getAggregatedErrorReportingHttpRetryLimit(), getBlockingExecutor());
+        }
+
+        Encrypter getEncrypter() {
+            return new HpkeJniEncrypter();
+        }
+    }
+
+    private AggregatedErrorReportingProtocol(
+            ImmutableList<ErrorData> errorData,
+            String requestBaseUri,
+            ImmutableMap<String, String> headerList,
+            long clientVersion,
+            Injector injector) {
+        this.mErrorData = errorData;
+        this.mRequestBaseUri = requestBaseUri;
+        this.mHeaderList = headerList;
+        this.mClientVersion = clientVersion;
+        this.mInjector = injector;
+        this.mHttpClient = injector.getClient();
+        this.mEncrypter = injector.getEncrypter();
+    }
+
+    /**
+     * Creates and returns a new {@link AggregatedErrorReportingProtocol} object to manage the
+     * lifecycle of reporting for one vendor's data based on given {@link ErrorData} and the vendors
+     * server URL.
+     */
+    static AggregatedErrorReportingProtocol createAggregatedErrorReportingProtocol(
+            ImmutableList<ErrorData> errorData, String requestBaseUri, Context context) {
+        return createAggregatedErrorReportingProtocol(
+                errorData, requestBaseUri, PackageUtils.getApexVersion(context), new Injector());
+    }
+
+    @VisibleForTesting
+    static AggregatedErrorReportingProtocol createAggregatedErrorReportingProtocol(
+            ImmutableList<ErrorData> errorData,
+            String requestBaseUri,
+            long clientVersion,
+            Injector injector) {
+        // Test only version of creator method.
+        return new AggregatedErrorReportingProtocol(
+                errorData, requestBaseUri, ImmutableMap.of(), clientVersion, injector);
+    }
+
+    /**
+     * Report the exception data for this vendor based on error data and URL provided during
+     * construction.
+     *
+     * @param encryptionKey key used to encrypt payload. If key is {@code null} then un-encrypted
+     *     data is sent, which is only used in tests etc.
+     * @return a {@link ListenableFuture} that resolves with true/false when reporting is
+     *     successful/failed.
+     */
+    public ListenableFuture<Boolean> reportExceptionData(@Nullable OdpEncryptionKey encryptionKey) {
+        // TODO(b/329921267): add authorization support
+        // First report ReportExceptionRequest, then upload result
+        try {
+            Preconditions.checkState(!mErrorData.isEmpty() && !mRequestBaseUri.isEmpty());
+            String requestUri = getRequestUri(mRequestBaseUri, mInjector.getFlags());
+
+            // Report exception request, to get upload location from server.
+            ListenableFuture<OdpHttpResponse> reportRequest =
+                    mHttpClient.performRequestAsyncWithRetry(
+                            getHttpRequest(
+                                    requestUri,
+                                    new HashMap<>(mHeaderList),
+                                    getReportRequest().toByteArray()));
+
+            // Perform upload based on server provided response.
+            ListenableFuture<Boolean> reportFuture =
+                    FluentFuture.from(reportRequest)
+                            .transformAsync(
+                                    response1 -> uploadExceptionData(response1, encryptionKey),
+                                    mInjector.getBackgroundExecutor())
+                            .transform(
+                                    response ->
+                                            validateHttpResponseStatus(
+                                                    /* stage= */ "uploadRequest", response),
+                                    mInjector.getBackgroundExecutor());
+
+            return FluentFuture.from(reportFuture)
+                    .withTimeout(
+                            mInjector.getFlags().getAggregatedErrorReportingHttpTimeoutSeconds(),
+                            TimeUnit.SECONDS,
+                            mInjector.getScheduledExecutor());
+        } catch (Exception e) {
+            sLogger.e(TAG + " : failed to  report exception data.", e);
+            return Futures.immediateFailedFuture(e);
+        }
+    }
+
+    @VisibleForTesting
+    ListenableFuture<OdpHttpResponse> uploadExceptionData(
+            OdpHttpResponse response, @Nullable OdpEncryptionKey encryptionKey) {
+        try {
+            validateHttpResponseStatus(/* stage= */ "reportRequest", response);
+            ReportExceptionResponse uploadResponse =
+                    ReportExceptionResponse.parseFrom(response.getPayload());
+            UploadInstruction uploadInstruction = uploadResponse.getUploadInstruction();
+            Preconditions.checkArgument(
+                    !uploadInstruction.getUploadLocation().isEmpty(),
+                    "UploadInstruction.upload_location must not be empty");
+            byte[] outputBytes =
+                    encryptionKey == null
+                            ? createEncryptedRequestBody(
+                                    mErrorData, /* encryptionKey= */ null, /* encrypter= */ null)
+                            : createEncryptedRequestBody(mErrorData, encryptionKey, mEncrypter);
+            // Apply a top-level compression to the payload.
+            if (uploadInstruction.getCompressionFormat()
+                    == ResourceCompressionFormat.RESOURCE_COMPRESSION_FORMAT_GZIP) {
+                outputBytes = HttpClientUtils.compressWithGzip(outputBytes);
+            }
+            HashMap<String, String> requestHeader =
+                    new HashMap<>(uploadInstruction.getExtraRequestHeadersMap());
+            OdpHttpRequest httpUploadRequest =
+                    getHttpRequest(
+                            uploadInstruction.getUploadLocation(), requestHeader, outputBytes);
+            return mHttpClient.performRequestAsyncWithRetry(httpUploadRequest);
+        } catch (Exception e) {
+            sLogger.e(
+                    TAG
+                            + " : failed to receive response for report request for URI : "
+                            + mRequestBaseUri,
+                    e);
+            return Futures.immediateFailedFuture(e);
+        }
+    }
+
+    @VisibleForTesting
+    static byte[] createEncryptedRequestBody(
+            ImmutableList<ErrorData> errorData,
+            @Nullable OdpEncryptionKey encryptionKey,
+            @Nullable Encrypter encrypter)
+            throws JSONException {
+        // Creates and encrypts the error data that is uploaded to the server.
+        // create payload. If the encryptionKey/encrypter are null then un-encrypted data is
+        // returned.
+        com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList errorDataList =
+                convertToProto(errorData);
+        byte[] output = errorDataList.toByteArray();
+        final JSONObject body = new JSONObject();
+
+        if (encryptionKey != null && encrypter != null) {
+            // Send encrypted payload
+            byte[] publicKey = Base64.decode(encryptionKey.getPublicKey(), Base64.NO_WRAP);
+
+            byte[] encryptedOutput =
+                    encrypter.encrypt(
+                            publicKey, output, AggregatedErrorDataPayloadContract.ASSOCIATED_DATA);
+
+            body.put(AggregatedErrorDataPayloadContract.KEY_ID, encryptionKey.getKeyIdentifier());
+            body.put(
+                    AggregatedErrorDataPayloadContract.ENCRYPTED_PAYLOAD,
+                    Base64.encodeToString(encryptedOutput, Base64.NO_WRAP));
+        } else {
+            // If the encryption-key is null then unencrypted data is sent. This is only used
+            // in tests etc. and not in production.
+            body.put(
+                    AggregatedErrorDataPayloadContract.ENCRYPTED_PAYLOAD,
+                    Base64.encodeToString(output, Base64.NO_WRAP));
+        }
+
+        // TODO(b/329921267): investigate removal of associated data from aggregated error data
+        // payload.
+        body.put(
+                AggregatedErrorDataPayloadContract.ASSOCIATED_DATA_KEY,
+                Base64.encodeToString(
+                        AggregatedErrorDataPayloadContract.ASSOCIATED_DATA, Base64.NO_WRAP));
+        return body.toString().getBytes();
+    }
+
+    private static boolean validateHttpResponseStatus(String stage, OdpHttpResponse httpResponse) {
+        if (!HttpClientUtils.HTTP_OK_STATUS.contains(httpResponse.getStatusCode())) {
+            throw new IllegalStateException(stage + " failed: " + httpResponse.getStatusCode());
+        }
+        // Automated testing would rely on this log.
+        sLogger.i(TAG, stage + " success.");
+        return true;
+    }
+
+    @VisibleForTesting
+    /* Gets the full request URI based on the */
+    static String getRequestUri(String requestBaseUri, Flags flags) {
+        // By default https://{host}/debugreporting/v1/exceptions:report-exceptions
+        return HttpClientUtils.joinBaseUriWithSuffix(
+                requestBaseUri, flags.getAggregatedErrorReportingServerPath());
+    }
+
+    @VisibleForTesting
+    static ReportExceptionRequest getReportRequest() {
+        Timestamp requestTime =
+                Timestamp.newBuilder().setSeconds(DateTimeUtils.epochSecondsUtc()).build();
+        return ReportExceptionRequest.newBuilder()
+                .setRequestTimestamp(requestTime)
+                .setResourceCapabilities(HttpClientUtils.getResourceCapabilities())
+                .build();
+    }
+
+    @VisibleForTesting
+    static com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList convertToProto(
+            List<ErrorData> errorDataList) {
+        com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList.Builder builder =
+                com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList
+                        .newBuilder();
+        for (ErrorData errorData : errorDataList) {
+            builder.addErrorData(convertToProto(errorData));
+        }
+        return builder.build();
+    }
+
+    private static com.google.ondevicepersonalization.federatedcompute.proto.ErrorData
+            convertToProto(ErrorData errorDataPojo) {
+        // convert from pojo to proto error data
+        com.google.ondevicepersonalization.federatedcompute.proto.ErrorData.Builder builder =
+                com.google.ondevicepersonalization.federatedcompute.proto.ErrorData.newBuilder();
+        builder.setErrorCode(errorDataPojo.getErrorCode())
+                .setErrorCount(errorDataPojo.getErrorCount())
+                .setEpochDay(errorDataPojo.getEpochDay())
+                .setServicePackageVersion(errorDataPojo.getServicePackageVersion());
+        return builder.build();
+    }
+
+    @VisibleForTesting
+    static OdpHttpRequest getHttpRequest(
+            String uri, Map<String, String> requestHeaders, byte[] body) {
+        // Helper method for http request that contains serialized proto payload.
+        HashMap<String, String> headers = new HashMap<>(requestHeaders);
+        headers.put(CONTENT_TYPE_HDR, PROTOBUF_CONTENT_TYPE);
+        return OdpHttpRequest.create(uri, HttpClientUtils.HttpMethod.PUT, headers, body);
+    }
+
+    @VisibleForTesting
+    static final class AggregatedErrorDataPayloadContract {
+        public static final String KEY_ID = "keyId";
+
+        public static final String ENCRYPTED_PAYLOAD = "encryptedPayload";
+
+        public static final String ASSOCIATED_DATA_KEY = "associatedData";
+
+        // TODO(b/329921267): can remove associated data for odp purposes.
+        public static final byte[] ASSOCIATED_DATA = new JSONObject().toString().getBytes();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
new file mode 100644
index 00000000..73ac8149
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
@@ -0,0 +1,277 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import android.annotation.Nullable;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.pm.PackageManager;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+import com.android.ondevicepersonalization.services.util.DebugUtils;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.util.concurrent.FutureCallback;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.atomic.AtomicBoolean;
+
+/**
+ * Manages the various subtasks in reporting the aggregate error data for each vendor.
+ *
+ * <p>Called into by the {@link AggregateErrorDataReportingService} to offload the details of
+ * accumulating and reporting the error counts in the per vendor tables.
+ *
+ * <p>When there is a pending reporting request, subsequent requests will return a failed future.
+ */
+class AggregatedErrorReportingWorker {
+    private static final String TAG = AggregatedErrorReportingWorker.class.getSimpleName();
+    private static final AtomicBoolean sOnGoingReporting = new AtomicBoolean(false);
+
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private final Injector mInjector;
+
+    /** Helper class to allow injection of mocks/test-objects in test. */
+    static class Injector {
+        ListeningExecutorService getLightweightExecutor() {
+            return OnDevicePersonalizationExecutors.getLightweightExecutor();
+        }
+
+        ListeningExecutorService getBackgroundExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        Flags getFlags() {
+            return FlagsFactory.getFlags();
+        }
+
+        ReportingProtocol getAggregatedErrorReportingProtocol(
+                ImmutableList<ErrorData> errorData, String requestBaseUri, Context context) {
+            return AggregatedErrorReportingProtocol.createAggregatedErrorReportingProtocol(
+                    errorData, requestBaseUri, context);
+        }
+
+        String getServerUrl(Context context, String packageName) {
+            return AggregatedErrorReportingWorker.getFcRemoteServerUrl(context, packageName);
+        }
+    }
+
+    private AggregatedErrorReportingWorker(Injector injector) {
+        this.mInjector = injector;
+    }
+
+    public static AggregatedErrorReportingWorker createWorker() {
+        // Telescope into test-only method and provide default injector instance.
+        return createWorker(new Injector());
+    }
+
+    @VisibleForTesting
+    static AggregatedErrorReportingWorker createWorker(Injector injector) {
+        return new AggregatedErrorReportingWorker(injector);
+    }
+
+    @VisibleForTesting
+    static void resetForTesting() {
+        sOnGoingReporting.set(false);
+    }
+
+    /**
+     * Reports existing aggregated error data to the adopter servers.
+     *
+     * @param context the calling context.
+     *     <p>Returns a {@link ListenableFuture} that resolves when the reporting succeeds or fails.
+     * @param encryptionKey key to use for encrypting payload. If key is {@code null} then
+     *     un-encrypted aggregated error data is sent, only used in tests etc.
+     */
+    public ListenableFuture<Void> reportAggregateErrors(
+            Context context, @Nullable OdpEncryptionKey encryptionKey) {
+        if (!sOnGoingReporting.compareAndSet(false, true)) {
+            sLogger.e(TAG + ": aggregate reporting is already ongoing.");
+            return Futures.immediateFailedFuture(
+                    new IllegalStateException("Duplicate report request"));
+        }
+
+        sLogger.d(TAG + ": beginning aggregate error reporting.");
+        return Futures.submitAsync(
+                () -> reportAggregateErrorsHelper(context, encryptionKey),
+                mInjector.getBackgroundExecutor());
+    }
+
+    @VisibleForTesting
+    ListenableFuture<Void> reportAggregateErrorsHelper(
+            Context context, @Nullable OdpEncryptionKey encryptionKey) {
+        try {
+            List<ComponentName> odpServices =
+                    AppManifestConfigHelper.getOdpServices(context, /* enrolledOnly= */ true);
+            if (odpServices.isEmpty()) {
+                sLogger.d(TAG + ": No odp services installed on device, skipping reporting");
+                cleanup();
+                return Futures.immediateVoidFuture();
+            }
+
+            List<ListenableFuture<Boolean>> futureList = new ArrayList<>();
+            for (ComponentName componentName : odpServices) {
+                String certDigest = getCertDigest(context, componentName.getPackageName());
+                if (certDigest.isEmpty()) {
+                    sLogger.d(
+                            TAG
+                                    + ": Skipping reporting for package :"
+                                    + componentName.getPackageName());
+                    continue;
+                }
+
+                String fcServerUrl =
+                        mInjector.getServerUrl(context, componentName.getPackageName());
+                if (fcServerUrl.isEmpty()) {
+                    sLogger.d(
+                            TAG
+                                    + ": Skipping reporting for package, missing server url : "
+                                    + componentName.getPackageName());
+                    continue;
+                }
+
+                OnDevicePersonalizationAggregatedErrorDataDao errorDataDao =
+                        OnDevicePersonalizationAggregatedErrorDataDao.getInstance(
+                                context, componentName, certDigest);
+                if (errorDataDao == null) {
+                    sLogger.d(
+                            TAG
+                                    + ": Skipping reporting no table found for component :"
+                                    + componentName);
+                    continue;
+                }
+
+                ImmutableList<ErrorData> errorDataList = errorDataDao.getExceptionData();
+                if (errorDataList.isEmpty()) {
+                    sLogger.d(
+                            TAG
+                                    + ": Skipping reporting no data found for component :"
+                                    + componentName);
+                    continue;
+                }
+
+                ReportingProtocol errorReportingProtocol =
+                        mInjector.getAggregatedErrorReportingProtocol(
+                                errorDataList, fcServerUrl, context);
+                ListenableFuture<Boolean> reportingFuture =
+                        errorReportingProtocol.reportExceptionData(encryptionKey);
+                Futures.addCallback(
+                        reportingFuture,
+                        new FutureCallback<Boolean>() {
+                            // TODO(b/367773359): add WW logging for success/failure etc.
+                            @Override
+                            public void onSuccess(Boolean result) {
+                                if (result) {
+                                    sLogger.d(
+                                            TAG
+                                                    + ": reporting successful for component : "
+                                                    + componentName);
+                                } else {
+                                    sLogger.d(
+                                            TAG
+                                                    + ": reporting failed for component : "
+                                                    + componentName);
+                                }
+                            }
+
+                            @Override
+                            public void onFailure(Throwable t) {
+                                sLogger.e(
+                                        TAG + ": reporting failed for component :" + componentName,
+                                        t);
+                            }
+                        },
+                        mInjector.getLightweightExecutor());
+
+                futureList.add(reportingFuture);
+            }
+
+            sLogger.d(TAG + " :waiting for " + futureList.size() + " futures to complete.");
+            // Wait for all the futures to complete or time-out, logging of successful/failure etc.
+            // is performed in the callback of each individual future.
+            return Futures.whenAllComplete(futureList)
+                    .call(
+                            () -> {
+                                cleanup();
+                                return null;
+                            },
+                            mInjector.getLightweightExecutor());
+        } catch (Exception e) {
+            sLogger.e(TAG + " : failed to  report exception data.", e);
+            cleanup();
+            return Futures.immediateFailedFuture(e);
+        }
+    }
+
+    @VisibleForTesting
+    static void cleanup() {
+        // Helper method to clean-up at the end of reporting.
+        sOnGoingReporting.set(false);
+    }
+
+    private static String getCertDigest(Context context, String packageName) {
+        // Helper method that catches the exception and returns an empty cert digest
+        try {
+            return PackageUtils.getCertDigest(context, packageName);
+        } catch (PackageManager.NameNotFoundException nne) {
+            sLogger.e(TAG + " : failed to query cert digest for package : " + packageName, nne);
+        }
+        return "";
+    }
+
+    private static String getFcRemoteServerUrl(Context context, String packageName) {
+        // Helper method that catches any runtime exceptions thrown by parsing failures and returns
+        // an empty URL
+        try {
+            String manifestUrl =
+                    AppManifestConfigHelper.getFcRemoteServerUrlFromOdpSettings(
+                            context, packageName);
+            String overrideUrl = DebugUtils.getFcServerOverrideUrl(context, packageName);
+            return overrideUrl.isEmpty() ? manifestUrl : overrideUrl;
+        } catch (Exception e) {
+            sLogger.e(TAG + " : failed to extract server URL for package : " + packageName, e);
+        }
+        return "";
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtils.java b/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtils.java
index 91c8a7a0..2664499c 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtils.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtils.java
@@ -52,6 +52,27 @@ final class DateTimeUtils {
         }
     }
 
+    /**
+     * Gets the seconds since epoch the UTC timezone.
+     *
+     * <p>Returns {@code -1} if unsuccessful.
+     */
+    public static long epochSecondsUtc() {
+        return epochSecondsUtc(MonotonicClock.getInstance());
+    }
+
+    @VisibleForTesting
+    static long epochSecondsUtc(Clock clock) {
+        // Package-private method for easier testing, allows injecting a clock in tests.
+        Instant currentInstant = getCurrentInstant(clock);
+        try {
+            return currentInstant.atZone(ZoneOffset.UTC).toEpochSecond();
+        } catch (DateTimeException e) {
+            sLogger.e(TAG + " : failed to get epoch seconds.", e);
+            return -1;
+        }
+    }
+
     /**
      * Get the day index in the local device's timezone.
      *
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java b/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
index e7a996d4..139ca733 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
@@ -286,6 +286,7 @@ class OnDevicePersonalizationAggregatedErrorDataDao {
         }
 
         int existingExceptionCount = getExceptionCount(isolatedServiceErrorCode, epochDay);
+        sLogger.d(TAG + ": existing exception count " + existingExceptionCount);
         if (!createTableIfNotExists(mTableName)) {
             sLogger.e(TAG + ": failed to create table " + mTableName);
             return false;
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/ReportingProtocol.java b/src/com/android/ondevicepersonalization/services/data/errors/ReportingProtocol.java
new file mode 100644
index 00000000..9e5da673
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/errors/ReportingProtocol.java
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import android.annotation.Nullable;
+
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+interface ReportingProtocol {
+    /**
+     * Report the exception data for this vendor based on error data and URL provided during
+     * construction.
+     *
+     * @return a {@link ListenableFuture} that resolves with true/false when reporting is
+     *     successful/failed.
+     */
+    ListenableFuture<Boolean> reportExceptionData(@Nullable OdpEncryptionKey encryptionKey);
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapper.java b/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapper.java
index afd7031e..99677412 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapper.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapper.java
@@ -46,4 +46,7 @@ public interface AdServicesCommonStatesWrapper {
 
     /** Returns the wrapped CommonStatesResult */
     ListenableFuture<CommonStatesResult> getCommonStates();
+
+    /** Thrown when the AdServicesCommonManager system service is null. */
+    class NullAdServiceCommonManagerException extends Exception {}
 }
diff --git a/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapperImpl.java b/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapperImpl.java
index d08c8abf..c6c88162 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapperImpl.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/AdServicesCommonStatesWrapperImpl.java
@@ -53,8 +53,10 @@ class AdServicesCommonStatesWrapperImpl implements AdServicesCommonStatesWrapper
 
     @Override public ListenableFuture<CommonStatesResult> getCommonStates() {
         try {
-            AdServicesCommonManager manager =
-                    Objects.requireNonNull(getAdServicesCommonManager());
+            AdServicesCommonManager manager = getAdServicesCommonManager();
+            if (manager == null) {
+                throw new NullAdServiceCommonManagerException();
+            }
             sLogger.d(TAG + ": IPC getAdServicesCommonStates() started");
             long origId = Binder.clearCallingIdentity();
             long timeoutInMillis = FlagsFactory.getFlags().getAdservicesIpcCallTimeoutInMillis();
@@ -70,17 +72,13 @@ class AdServicesCommonStatesWrapperImpl implements AdServicesCommonStatesWrapper
                     .transform(
                             v -> getResultFromResponse(v),
                             MoreExecutors.newDirectExecutorService());
-        } catch (Exception e) {
+        } catch (Throwable e) {
             return Futures.immediateFailedFuture(e);
         }
     }
 
-    private AdServicesCommonManager getAdServicesCommonManager() {
-        try {
-            return mContext.getSystemService(AdServicesCommonManager.class);
-        } catch (NoClassDefFoundError e) {
-            throw new IllegalStateException("Cannot find AdServicesCommonManager.", e);
-        }
+    private AdServicesCommonManager getAdServicesCommonManager() throws NoClassDefFoundError {
+        return mContext.getSystemService(AdServicesCommonManager.class);
     }
 
     private static CommonStatesResult getResultFromResponse(
diff --git a/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java b/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
index a27a0aab..7b0a2266 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
@@ -18,12 +18,17 @@ package com.android.ondevicepersonalization.services.data.user;
 
 import static android.adservices.ondevicepersonalization.Constants.API_NAME_ADSERVICES_GET_COMMON_STATES;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_CALLER_NOT_ALLOWED;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_CLASS_NOT_FOUND;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_EXECUTION_INTERRUPTED;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_INTERNAL_ERROR;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_METHOD_NOT_FOUND;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_NULL_ADSERVICES_COMMON_MANAGER;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_REMOTE_EXCEPTION;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_SUCCESS;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_TIMEOUT;
 
+import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION;
+import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_USER_CONTROL_CACHE_IN_MILLIS;
@@ -35,6 +40,7 @@ import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationApplication;
 import com.android.ondevicepersonalization.services.StableFlags;
 import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
+import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 import com.android.ondevicepersonalization.services.util.DebugUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
 
@@ -235,6 +241,11 @@ public final class UserPrivacyStatus {
                     mClock,
                     statusCode,
                     startTime);
+            ClientErrorLogger.getInstance()
+                    .logError(
+                            e,
+                            AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION,
+                            AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP);
         }
     }
 
@@ -246,18 +257,38 @@ public final class UserPrivacyStatus {
 
     @VisibleForTesting
     int getExceptionStatus(Exception e) {
-        if (e instanceof ExecutionException && e.getCause() instanceof TimeoutException) {
+        if (e instanceof InterruptedException) {
+            return STATUS_EXECUTION_INTERRUPTED;
+        }
+
+        Throwable cause = e;
+        if (e instanceof ExecutionException) {
+            cause = e.getCause(); // Unwrap the cause
+        }
+        if (cause instanceof TimeoutException) {
             return STATUS_TIMEOUT;
         }
-        if (e instanceof NoSuchMethodException) {
+        if (cause instanceof NoSuchMethodException) {
             return STATUS_METHOD_NOT_FOUND;
         }
-        if (e instanceof SecurityException) {
+        if (cause instanceof SecurityException) {
             return STATUS_CALLER_NOT_ALLOWED;
         }
-        if (e instanceof IllegalArgumentException) {
+        if (cause instanceof IllegalStateException) {
+            return STATUS_INTERNAL_ERROR;
+        }
+        if (cause instanceof IllegalArgumentException) {
             return STATUS_INTERNAL_ERROR;
         }
+        if (cause instanceof NoClassDefFoundError) {
+            return STATUS_CLASS_NOT_FOUND;
+        }
+        if (cause instanceof AdServicesCommonStatesWrapper.NullAdServiceCommonManagerException) {
+            return STATUS_NULL_ADSERVICES_COMMON_MANAGER;
+        }
+        if (cause instanceof InterruptedException) {
+            return STATUS_EXECUTION_INTERRUPTED;
+        }
         return STATUS_REMOTE_EXCEPTION;
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/display/WebViewFlow.java b/src/com/android/ondevicepersonalization/services/display/WebViewFlow.java
index c5892fe0..605d749e 100644
--- a/src/com/android/ondevicepersonalization/services/display/WebViewFlow.java
+++ b/src/com/android/ondevicepersonalization/services/display/WebViewFlow.java
@@ -43,6 +43,7 @@ import com.android.ondevicepersonalization.services.data.events.EventsDao;
 import com.android.ondevicepersonalization.services.inference.IsolatedModelServiceProvider;
 import com.android.ondevicepersonalization.services.policyengine.UserDataAccessor;
 import com.android.ondevicepersonalization.services.serviceflow.ServiceFlow;
+import com.android.ondevicepersonalization.services.util.LogUtils;
 import com.android.ondevicepersonalization.services.util.OnDevicePersonalizationFlatbufferUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
 
@@ -53,6 +54,7 @@ import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.ListeningScheduledExecutorService;
 
+import java.util.Collections;
 import java.util.Objects;
 import java.util.concurrent.TimeUnit;
 
@@ -239,6 +241,14 @@ public class WebViewFlow implements ServiceFlow<EventOutputParcel> {
             if (result == null || result.getEventLogRecord() == null
                     || mLogRecord == null || mLogRecord.getRows() == null) {
                 sLogger.d(TAG + "no EventLogRecord or RequestLogRecord");
+                LogUtils.writeLogRecords(
+                        Constants.TASK_TYPE_WEBVIEW,
+                        mContext,
+                        mService.getPackageName(),
+                        mService,
+                        mLogRecord,
+                        result == null ? null : Collections.singletonList(
+                                result.getEventLogRecord()));
                 return Futures.immediateFuture(null);
             }
             EventLogRecord eventData = result.getEventLogRecord();
@@ -246,6 +256,13 @@ public class WebViewFlow implements ServiceFlow<EventOutputParcel> {
             if (eventData.getType() <= 0 || eventData.getRowIndex() < 0
                     || eventData.getRowIndex() >= rowCount) {
                 sLogger.w(TAG + ": rowOffset out of range");
+                LogUtils.writeLogRecords(
+                        Constants.TASK_TYPE_WEBVIEW,
+                        mContext,
+                        mService.getPackageName(),
+                        mService,
+                        mLogRecord,
+                        Collections.singletonList(eventData));
                 return Futures.immediateFuture(null);
             }
 
@@ -267,12 +284,27 @@ public class WebViewFlow implements ServiceFlow<EventOutputParcel> {
                         mQueryId, eventData.getType(), eventData.getRowIndex(), mService)) {
                     if (-1 == dao.insertEvent(event)) {
                         sLogger.e(TAG + ": Failed to insert event: " + event);
+                        LogUtils.writeLogRecords(
+                                Constants.TASK_TYPE_WEBVIEW,
+                                mContext,
+                                mService.getPackageName(),
+                                mService,
+                                mLogRecord,
+                                Collections.singletonList(eventData));
                     }
                 }
             }
             return Futures.immediateFuture(null);
         } catch (Exception e) {
             sLogger.e(TAG + ": writeEvent() failed", e);
+            LogUtils.writeLogRecords(
+                    Constants.TASK_TYPE_WEBVIEW,
+                    mContext,
+                    mService.getPackageName(),
+                    mService,
+                    mLogRecord,
+                    result == null ? null : Collections.singletonList(
+                            result.getEventLogRecord()));
             return Futures.immediateFailedFuture(e);
         }
     }
diff --git a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
index 118e66af..a92b5fee 100644
--- a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
+++ b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
@@ -96,7 +96,7 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
     }
 
     public DownloadFlow(String packageName,
-            Context context, FutureCallback<DownloadCompletedOutputParcel> callback) {
+                        Context context, FutureCallback<DownloadCompletedOutputParcel> callback) {
         mPackageName = packageName;
         mContext = context;
         mCallback = callback;
@@ -129,22 +129,22 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
                     }
                     reader.endObject();
                 }
-            } catch (IOException e) {
-                sLogger.d(TAG + mPackageName + " Failed to process downloaded JSON file");
-                mCallback.onFailure(e);
+            } catch (IOException ie) {
+                sLogger.e(ie, TAG + mPackageName + " Failed to process downloaded JSON file");
+                onSuccess(null);
                 return false;
             }
 
             if (syncToken == -1 || !validateSyncToken(syncToken)) {
                 sLogger.d(TAG + mPackageName
                         + " downloaded JSON file has invalid syncToken provided");
-                mCallback.onFailure(new IllegalArgumentException("Invalid syncToken provided."));
+                onSuccess(null);
                 return false;
             }
 
-            if (vendorDataMap == null || vendorDataMap.size() == 0) {
+            if (vendorDataMap == null || vendorDataMap.isEmpty()) {
                 sLogger.d(TAG + mPackageName + " downloaded JSON file has no content provided");
-                mCallback.onFailure(new IllegalArgumentException("No content provided."));
+                onSuccess(null);
                 return false;
             }
 
@@ -156,7 +156,7 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
             // no new data. Mark success to upstream caller for reporting purpose
             if (existingSyncToken >= syncToken) {
                 sLogger.d(TAG + ": syncToken is not newer than existing token.");
-                mCallback.onSuccess(null);
+                onSuccess(null);
                 return false;
             }
 
@@ -291,39 +291,21 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
                         mInjector.getExecutor());
     }
 
+    private ListenableFuture<Boolean> removeFileGroup() throws Exception {
+        MobileDataDownload mdd = MobileDataDownloadFactory.getMdd(mContext);
+        String fileGroupName =
+                OnDevicePersonalizationFileGroupPopulator.createPackageFileGroupName(
+                        mPackageName, mContext);
+
+        return mdd.removeFileGroup(RemoveFileGroupRequest.newBuilder()
+                .setGroupName(fileGroupName).build());
+    }
+
     @Override
     public void returnResultThroughCallback(
             ListenableFuture<DownloadCompletedOutputParcel> serviceFlowResultFuture) {
         try {
-            MobileDataDownload mdd = MobileDataDownloadFactory.getMdd(mContext);
-            String fileGroupName =
-                    OnDevicePersonalizationFileGroupPopulator.createPackageFileGroupName(
-                            mPackageName, mContext);
-
-            ListenableFuture<Boolean> removeFileGroupFuture =
-                    FluentFuture.from(serviceFlowResultFuture)
-                            .transformAsync(
-                                    result -> mdd.removeFileGroup(
-                                            RemoveFileGroupRequest.newBuilder()
-                                                    .setGroupName(fileGroupName).build()),
-                                    mInjector.getExecutor());
-
-            Futures.addCallback(removeFileGroupFuture,
-                    new FutureCallback<>() {
-                        @Override
-                        public void onSuccess(Boolean result) {
-                            try {
-                                mCallback.onSuccess(serviceFlowResultFuture.get());
-                            } catch (Exception e) {
-                                mCallback.onFailure(e);
-                            }
-                        }
-
-                        @Override
-                        public void onFailure(Throwable t) {
-                            mCallback.onFailure(t);
-                        }
-                    }, mInjector.getExecutor());
+            onSuccess(serviceFlowResultFuture.get());
         } catch (Exception e) {
             mCallback.onFailure(e);
         }
@@ -404,7 +386,7 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
             sLogger.d(TAG + ": package : "
                     + mPackageName + " has "
                     + cfg.getFileCount() + " files in the fileGroup");
-            mCallback.onFailure(new IllegalArgumentException("Invalid file count."));
+            onFailure(new IllegalArgumentException("Invalid file count."));
             return null;
         }
 
@@ -416,4 +398,42 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
         // TODO(b/249813538) Add any additional requirements
         return syncToken % 3600 == 0;
     }
+
+    private void onFailure(Exception exception) throws Exception {
+        Futures.addCallback(removeFileGroup(),
+                new FutureCallback<>() {
+                    @Override
+                    public void onSuccess(Boolean result) {
+                        try {
+                            mCallback.onFailure(exception);
+                        } catch (Exception e) {
+                            mCallback.onFailure(e);
+                        }
+                    }
+
+                    @Override
+                    public void onFailure(Throwable t) {
+                        mCallback.onFailure(t);
+                    }
+                }, mInjector.getExecutor());
+    }
+
+    private void onSuccess(DownloadCompletedOutputParcel output) throws Exception {
+        Futures.addCallback(removeFileGroup(),
+                new FutureCallback<>() {
+                    @Override
+                    public void onSuccess(Boolean result) {
+                        try {
+                            mCallback.onSuccess(output);
+                        } catch (Exception e) {
+                            mCallback.onFailure(e);
+                        }
+                    }
+
+                    @Override
+                    public void onFailure(Throwable t) {
+                        mCallback.onFailure(t);
+                    }
+                }, mInjector.getExecutor());
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
index 36a36694..5829083f 100644
--- a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
+++ b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
@@ -31,9 +31,12 @@ import android.content.Context;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
 import com.android.ondevicepersonalization.services.statsd.joblogging.OdpJobServiceLogger;
 
+import com.google.android.libraries.mobiledatadownload.MobileDataDownload;
+import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 
@@ -86,68 +89,65 @@ public class OnDevicePersonalizationDownloadProcessingJobService extends JobServ
             return true;
         }
 
-        OnDevicePersonalizationExecutors.getHighPriorityBackgroundExecutor()
-                .execute(
-                        () -> {
-                            mFutures = new ArrayList<>();
-                            // Processing installed packages
-                            for (String packageName :
-                                    AppManifestConfigHelper.getOdpPackages(
-                                            /* context= */ this, /* enrolledOnly= */ true)) {
-                                mFutures.add(
-                                        Futures.submitAsync(
-                                                new OnDevicePersonalizationDataProcessingAsyncCallable(
-                                                        packageName, /* context= */ this),
-                                                OnDevicePersonalizationExecutors
-                                                        .getBackgroundExecutor()));
-                            }
-
-                            // Handling task completion asynchronously
-                            var unused =
-                                    Futures.whenAllComplete(mFutures)
-                                            .call(
-                                                    () -> {
-                                                        boolean wantsReschedule = false;
-                                                        boolean allSuccess = true;
-                                                        int successTaskCount = 0;
-                                                        int failureTaskCount = 0;
-                                                        for (ListenableFuture<Void> future :
-                                                                mFutures) {
-                                                            try {
-                                                                future.get();
-                                                                successTaskCount++;
-                                                            } catch (Exception e) {
-                                                                sLogger.e(
-                                                                        e,
-                                                                        TAG
-                                                                                + ": Error"
-                                                                                + " processing"
-                                                                                + " future");
-                                                                failureTaskCount++;
-                                                                allSuccess = false;
-                                                            }
-                                                        }
-                                                        sLogger.d(
-                                                                TAG
-                                                                        + ": all download"
-                                                                        + " processing tasks"
-                                                                        + " finished, %d succeeded,"
-                                                                        + " %d failed",
-                                                                successTaskCount,
-                                                                failureTaskCount);
-                                                        OdpJobServiceLogger.getInstance(
-                                                                        OnDevicePersonalizationDownloadProcessingJobService
-                                                                                .this)
-                                                                .recordJobFinished(
-                                                                        DOWNLOAD_PROCESSING_TASK_JOB_ID,
-                                                                        /* isSuccessful= */ allSuccess,
-                                                                        wantsReschedule);
-                                                        jobFinished(params, wantsReschedule);
-                                                        return null;
-                                                    },
-                                                    OnDevicePersonalizationExecutors
-                                                            .getLightweightExecutor());
-                        });
+        OnDevicePersonalizationExecutors.getHighPriorityBackgroundExecutor().execute(() -> {
+            mFutures = new ArrayList<>();
+            // Processing installed packages
+            for (String packageName : AppManifestConfigHelper.getOdpPackages(
+                    /* context= */ this, /* enrolledOnly= */ true)) {
+                mFutures.add(Futures.submitAsync(
+                        new OnDevicePersonalizationDataProcessingAsyncCallable(
+                                packageName, /* context= */ this),
+                        OnDevicePersonalizationExecutors.getBackgroundExecutor()));
+            }
+
+            // Handling task completion asynchronously
+            var unused = Futures.whenAllComplete(mFutures).call(() -> {
+                boolean wantsReschedule = false;
+                boolean allSuccess = true;
+                int successTaskCount = 0;
+                int failureTaskCount = 0;
+                for (ListenableFuture<Void> future : mFutures) {
+                    try {
+                        future.get();
+                        successTaskCount++;
+                    } catch (Exception e) {
+                        sLogger.e(e, TAG + ": Error" + " processing" + " future");
+                        failureTaskCount++;
+                        allSuccess = false;
+                    }
+                }
+                sLogger.d(TAG + ": all download" + " processing tasks"
+                        + " finished, %d succeeded,"
+                        + " %d failed", successTaskCount, failureTaskCount);
+                // Manually trigger MDD garbage collection after finishing processing all downloads.
+                MobileDataDownload mdd = MobileDataDownloadFactory.getMdd(this);
+                boolean isSuccessful = allSuccess;
+                Futures.addCallback(mdd.collectGarbage(), new FutureCallback<Void>() {
+                    @Override
+                    public void onSuccess(Void result) {
+                        OdpJobServiceLogger.getInstance(
+                                OnDevicePersonalizationDownloadProcessingJobService.this)
+                                .recordJobFinished(
+                                    DOWNLOAD_PROCESSING_TASK_JOB_ID,
+                                    /* isSuccessful= */ isSuccessful,
+                                    wantsReschedule);
+                        jobFinished(params, wantsReschedule);
+                    }
+
+                    @Override
+                    public void onFailure(Throwable t) {
+                        OdpJobServiceLogger.getInstance(
+                                OnDevicePersonalizationDownloadProcessingJobService.this)
+                                    .recordJobFinished(
+                                        DOWNLOAD_PROCESSING_TASK_JOB_ID,
+                                        /* isSuccessful= */ false,
+                                        wantsReschedule);
+                        jobFinished(params, wantsReschedule);
+                    }
+                }, OnDevicePersonalizationExecutors.getLightweightExecutor());
+                return null;
+            }, OnDevicePersonalizationExecutors.getLightweightExecutor());
+        });
 
         return true;
     }
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MddLogger.java b/src/com/android/ondevicepersonalization/services/download/mdd/MddLogger.java
new file mode 100644
index 00000000..862928cb
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MddLogger.java
@@ -0,0 +1,127 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.download.mdd;
+
+import com.android.adservices.service.stats.AdServicesStatsLog;
+
+import com.google.android.libraries.mobiledatadownload.Logger;
+import com.google.android.libraries.mobiledatadownload.internal.logging.LogUtil;
+import com.google.mobiledatadownload.LogEnumsProto.MddClientEvent.Code;
+import com.google.mobiledatadownload.LogProto;
+import com.google.mobiledatadownload.LogProto.DataDownloadFileGroupStats;
+import com.google.mobiledatadownload.LogProto.MddDownloadResultLog;
+import com.google.mobiledatadownload.LogProto.MddFileGroupStatus;
+import com.google.mobiledatadownload.LogProto.MddLogData;
+import com.google.mobiledatadownload.MobileDataDownloadFileGroupStats;
+import com.google.mobiledatadownload.MobileDataDownloadFileGroupStorageStats;
+import com.google.mobiledatadownload.MobileDataDownloadStorageStats;
+import com.google.protobuf.MessageLite;
+
+/** A MDD {@link Logger} which uses {@link AdServicesStatsLog} to write logs. */
+public class MddLogger implements Logger {
+    private static final String TAG = "MddLogger";
+
+    @Override
+    public void log(MessageLite log, int eventCode) {
+
+        switch (Code.forNumber(eventCode)) {
+            case DATA_DOWNLOAD_FILE_GROUP_STATUS:
+                logFileGroupStatus(log);
+                break;
+            case DATA_DOWNLOAD_RESULT_LOG:
+                logDownloadResult(log);
+                break;
+            case DATA_DOWNLOAD_STORAGE_STATS:
+                logStorageStats(log);
+                break;
+            default:
+                LogUtil.d("%s: Received unsupported event code %d, skipping log", TAG, eventCode);
+                break;
+        }
+    }
+
+    /** Helper method to handle logging File Group Status events. */
+    private void logFileGroupStatus(MessageLite log) {
+        // NOTE: log will always be MddLogData
+        MddLogData logData = (MddLogData) log;
+        DataDownloadFileGroupStats mddGroupStats = logData.getDataDownloadFileGroupStats();
+        MddFileGroupStatus mddFileGroupStatus = logData.getMddFileGroupStatus();
+        MobileDataDownloadFileGroupStats groupStats =
+                buildGroupStats((int) logData.getSamplingInterval(), mddGroupStats);
+
+        AdServicesStatsLog.write(
+                AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_FILE_GROUP_STATUS_REPORTED,
+                /* file_group_download_status = */ mddFileGroupStatus
+                        .getFileGroupDownloadStatus()
+                        .getNumber(),
+                /* group_added_timestamp = */ mddFileGroupStatus.getGroupAddedTimestampInSeconds(),
+                /* group_downloaded_timestamp = */ mddFileGroupStatus
+                        .getGroupDownloadedTimestampInSeconds(),
+                /* file_group_stats = */ groupStats.toByteArray(),
+                /* days_since_last_log = */ mddFileGroupStatus.getDaysSinceLastLog());
+    }
+
+    private void logDownloadResult(MessageLite log) {
+        MddLogData logData = (MddLogData) log;
+        MddDownloadResultLog mddDownloadResult = logData.getMddDownloadResultLog();
+        MobileDataDownloadFileGroupStats groupStats =
+                buildGroupStats(
+                        (int) logData.getSamplingInterval(),
+                        mddDownloadResult.getDataDownloadFileGroupStats());
+        AdServicesStatsLog.write(
+                AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_DOWNLOAD_RESULT_REPORTED,
+                /* download_result = */ mddDownloadResult.getResult().getNumber(),
+                /* file_group_stats = */ groupStats.toByteArray());
+    }
+
+    private void logStorageStats(MessageLite log) {
+        MddLogData logData = (MddLogData) log;
+        LogProto.MddStorageStats mddStorageStats = logData.getMddStorageStats();
+        MobileDataDownloadStorageStats.Builder storageStats =
+                MobileDataDownloadStorageStats.newBuilder();
+        for (int i = 0; i < mddStorageStats.getDataDownloadFileGroupStatsCount(); i++) {
+            storageStats.addMobileDataDownloadFileGroupStorageStats(
+                    MobileDataDownloadFileGroupStorageStats.newBuilder()
+                            .setTotalBytesUsed(mddStorageStats.getTotalBytesUsed(i))
+                            .setTotalInlineBytesUsed(mddStorageStats.getTotalInlineBytesUsed(i))
+                            .setDownloadedGroupBytesUsed(
+                                    mddStorageStats.getDownloadedGroupBytesUsed(i))
+                            .setFileGroupStats(
+                                    buildGroupStats(
+                                            (int) logData.getSamplingInterval(),
+                                            mddStorageStats.getDataDownloadFileGroupStats(i)))
+                            .build());
+        }
+        AdServicesStatsLog.write(
+                AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_FILE_GROUP_STORAGE_STATS_REPORTED,
+                storageStats.build().toByteArray(),
+                mddStorageStats.getTotalMddBytesUsed(),
+                mddStorageStats.getTotalMddDirectoryBytesUsed());
+    }
+
+    private static MobileDataDownloadFileGroupStats buildGroupStats(
+            int samplingInterval, DataDownloadFileGroupStats mddGroupStats) {
+        return MobileDataDownloadFileGroupStats.newBuilder()
+                .setSamplingInterval(samplingInterval)
+                .setFileGroupName(mddGroupStats.getFileGroupName())
+                .setVariantId(mddGroupStats.getVariantId())
+                .setBuildId(mddGroupStats.getBuildId())
+                .setFileCount(mddGroupStats.getFileCount())
+                .setHasAccount(mddGroupStats.getHasAccount())
+                .build();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MobileDataDownloadFactory.java b/src/com/android/ondevicepersonalization/services/download/mdd/MobileDataDownloadFactory.java
index 849bb9be..21b969e2 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/MobileDataDownloadFactory.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MobileDataDownloadFactory.java
@@ -24,6 +24,7 @@ import androidx.annotation.NonNull;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 
 import com.google.android.libraries.mobiledatadownload.Flags;
+import com.google.android.libraries.mobiledatadownload.Logger;
 import com.google.android.libraries.mobiledatadownload.MobileDataDownload;
 import com.google.android.libraries.mobiledatadownload.MobileDataDownloadBuilder;
 import com.google.android.libraries.mobiledatadownload.TimeSource;
@@ -66,11 +67,6 @@ public class MobileDataDownloadFactory {
             if (sSingleton == null) {
                 SynchronousFileStorage fileStorage = getFileStorage(context);
 
-                // TODO(b/241009783): This only adds the core MDD code. We still need other
-                //  components:
-                // 1) Add Logger
-                // 2) Set Flags
-                // 3) Add Configurator.
                 sSingleton =
                         MobileDataDownloadBuilder.newBuilder()
                                 .setContext(context)
@@ -82,6 +78,7 @@ public class MobileDataDownloadFactory {
                                         () -> getFileDownloader(context, downloadExecutor))
                                 .addFileGroupPopulator(
                                         new OnDevicePersonalizationFileGroupPopulator(context))
+                                .setLoggerOptional(Optional.of(getMddLogger()))
                                 .setFlagsOptional(Optional.of(getFlags()))
                                 .build();
             }
@@ -143,4 +140,9 @@ public class MobileDataDownloadFactory {
     private static Flags getFlags() {
         return new OnDevicePersonalizationMddFlags();
     }
+
+    @NonNull
+    private static Logger getMddLogger() {
+        return new MddLogger();
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
index 476eec16..04cbf78b 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
@@ -203,7 +203,7 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
                             for (ClientConfigProto.ClientFileGroup fileGroup : fileGroupList) {
                                 fileGroupsToRemove.add(fileGroup.getGroupName());
                             }
-                            List<ListenableFuture<Boolean>> mFutures = new ArrayList<>();
+                            List<ListenableFuture<Boolean>> futureList = new ArrayList<>();
                             for (String packageName :
                                     AppManifestConfigHelper.getOdpPackages(
                                             mContext, /* enrolledOnly= */ true)) {
@@ -229,7 +229,7 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
                                                     new ChecksumType[] {checksumType},
                                                     new String[] {downloadUrl},
                                                     deviceNetworkPolicy);
-                                    mFutures.add(
+                                    futureList.add(
                                             mobileDataDownload.addFileGroup(
                                                     AddFileGroupRequest.newBuilder()
                                                             .setDataFileGroup(dataFileGroup)
@@ -245,7 +245,7 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
 
                             for (String group : fileGroupsToRemove) {
                                 sLogger.d(TAG + ": Removing file group: " + group);
-                                mFutures.add(
+                                futureList.add(
                                         mobileDataDownload.removeFileGroup(
                                                 RemoveFileGroupRequest.newBuilder()
                                                         .setGroupName(group)
@@ -253,7 +253,7 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
                             }
 
                             return PropagatedFutures.transform(
-                                    Futures.successfulAsList(mFutures),
+                                    Futures.successfulAsList(futureList),
                                     result -> {
                                         if (result.contains(null)) {
                                             sLogger.d(
diff --git a/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreService.java b/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreService.java
index d6c23b52..8c19fdce 100644
--- a/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreService.java
+++ b/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreService.java
@@ -48,9 +48,8 @@ import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
 import com.android.ondevicepersonalization.services.policyengine.UserDataAccessor;
 import com.android.ondevicepersonalization.services.process.IsolatedServiceInfo;
-import com.android.ondevicepersonalization.services.process.PluginProcessRunner;
 import com.android.ondevicepersonalization.services.process.ProcessRunner;
-import com.android.ondevicepersonalization.services.process.SharedIsolatedProcessRunner;
+import com.android.ondevicepersonalization.services.process.ProcessRunnerFactory;
 import com.android.ondevicepersonalization.services.util.AllowListUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
 
@@ -61,6 +60,7 @@ import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningScheduledExecutorService;
 
 import java.util.Objects;
+import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
 
@@ -85,9 +85,7 @@ public final class OdpExampleStoreService extends ExampleStoreService {
         }
 
         ProcessRunner getProcessRunner() {
-            return FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled()
-                    ? SharedIsolatedProcessRunner.getInstance()
-                    : PluginProcessRunner.getInstance();
+            return ProcessRunnerFactory.getProcessRunner();
         }
     }
 
@@ -228,6 +226,7 @@ public final class OdpExampleStoreService extends ExampleStoreService {
                                     TimeUnit.SECONDS,
                                     mInjector.getScheduledExecutor());
 
+            CountDownLatch latch = new CountDownLatch(1);
             Futures.addCallback(
                     resultFuture,
                     new FutureCallback<Bundle>() {
@@ -250,12 +249,18 @@ public final class OdpExampleStoreService extends ExampleStoreService {
                                                 trainingExamplesOutputParcel
                                                         .getTrainingExampleRecords();
                                 if (trainingExampleRecordList == null
-                                        || trainingExampleRecordList.getList().isEmpty()
-                                        || trainingExampleRecordList.getList().size()
-                                                < eligibilityMinExample) {
+                                        || trainingExampleRecordList.getList().isEmpty()) {
                                     status = Constants.STATUS_SUCCESS_EMPTY_RESULT;
                                     callback.onStartQueryFailure(
                                             ClientConstants.STATUS_NOT_ENOUGH_DATA);
+                                } else if (trainingExampleRecordList.getList().size()
+                                        < eligibilityMinExample) {
+                                    sLogger.d(TAG + ": not enough examples, requires %d got %d",
+                                            eligibilityMinExample,
+                                            trainingExampleRecordList.getList().size());
+                                    status = Constants.STATUS_SUCCESS_NOT_ENOUGH_DATA;
+                                    callback.onStartQueryFailure(
+                                            ClientConstants.STATUS_NOT_ENOUGH_DATA);
                                 } else {
                                     callback.onStartQuerySuccess(
                                             OdpExampleStoreIteratorFactory.getInstance()
@@ -263,6 +268,7 @@ public final class OdpExampleStoreService extends ExampleStoreService {
                                                             trainingExampleRecordList.getList()));
                                 }
                             } finally {
+                                latch.countDown();
                                 StatsUtils.writeServiceRequestMetrics(
                                         Constants.API_NAME_SERVICE_ON_TRAINING_EXAMPLE,
                                         packageName,
@@ -275,6 +281,7 @@ public final class OdpExampleStoreService extends ExampleStoreService {
 
                         @Override
                         public void onFailure(Throwable t) {
+                            latch.countDown();
                             int status = Constants.STATUS_INTERNAL_ERROR;
                             if (t instanceof TimeoutException) {
                                 status = Constants.STATUS_TIMEOUT;
@@ -304,13 +311,20 @@ public final class OdpExampleStoreService extends ExampleStoreService {
             var unused =
                     Futures.whenAllComplete(loadFuture, resultFuture)
                             .callAsync(
-                                    () ->
-                                            mInjector
-                                                    .getProcessRunner()
-                                                    .unloadIsolatedService(loadFuture.get()),
+                                    () -> {
+                                        try {
+                                            latch.await();
+                                        } catch (InterruptedException e) {
+                                            sLogger.e(e, "%s : Interrupted while "
+                                                    + "waiting for transaction complete", TAG);
+                                        }
+                                        return mInjector
+                                                .getProcessRunner()
+                                                .unloadIsolatedService(loadFuture.get());
+                                    },
                                     OnDevicePersonalizationExecutors.getBackgroundExecutor());
-        } catch (Exception e) {
-            sLogger.w(e, "%s : Start query failed.", TAG);
+        } catch (Throwable e) {
+            sLogger.e(e, "%s : Start query failed.", TAG);
             StatsUtils.writeServiceRequestMetrics(
                     Constants.API_NAME_SERVICE_ON_TRAINING_EXAMPLE,
                     Constants.STATUS_INTERNAL_ERROR);
diff --git a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
index 86d12038..c524687c 100644
--- a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
@@ -17,6 +17,7 @@
 package com.android.ondevicepersonalization.services.inference;
 
 import android.adservices.ondevicepersonalization.Constants;
+import android.adservices.ondevicepersonalization.InferenceInput;
 import android.adservices.ondevicepersonalization.InferenceInputParcel;
 import android.adservices.ondevicepersonalization.InferenceOutput;
 import android.adservices.ondevicepersonalization.InferenceOutputParcel;
@@ -33,6 +34,7 @@ import android.os.RemoteException;
 import android.os.Trace;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.util.IoUtils;
@@ -46,6 +48,7 @@ import java.io.ByteArrayInputStream;
 import java.io.IOException;
 import java.io.ObjectInputStream;
 import java.nio.ByteBuffer;
+import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
@@ -85,7 +88,16 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
                 Objects.requireNonNull(inputParcel.getExpectedOutputStructure());
         mInjector
                 .getExecutor()
-                .execute(() -> runTfliteInterpreter(inputParcel, outputParcel, binder, callback));
+                .execute(
+                        () -> {
+                            if (inputParcel.getModelType()
+                                    == InferenceInput.Params.MODEL_TYPE_EXECUTORCH) {
+                                throw new IllegalStateException(
+                                        "ExecuTorch model inference is not supported yet.");
+                            } else {
+                                runTfliteInterpreter(inputParcel, outputParcel, binder, callback);
+                            }
+                        });
     }
 
     private void runTfliteInterpreter(
@@ -96,12 +108,21 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
         try {
             Trace.beginSection("IsolatedModelService#RunInference");
             // We already validate requests in ModelManager and double check in case.
-            Object[] inputs = convertToObjArray(inputParcel.getInputData().getList());
+            Object[] inputs =
+                    (Object[]) ByteArrayUtil.deserializeObject(inputParcel.getInputData());
             if (inputs == null || inputs.length == 0) {
                 sLogger.e("Input data can not be empty for inference.");
                 sendError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
             }
-            Map<Integer, Object> outputs = outputParcel.getData();
+            Map<Integer, Object> outputs = new HashMap<>();
+            try {
+                outputs =
+                        (Map<Integer, Object>)
+                                ByteArrayUtil.deserializeObject(outputParcel.getData());
+            } catch (ClassCastException e) {
+                sendError(callback, Constants.STATUS_PARSE_ERROR);
+            }
+
             if (outputs.isEmpty()) {
                 sLogger.e("Output data can not be empty for inference.");
                 sendError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
diff --git a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
index ddde1b3c..c136c968 100644
--- a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
+++ b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.inference;
 
-import static com.android.ondevicepersonalization.services.process.SharedIsolatedProcessRunner.TRUSTED_PARTNER_APPS_SIP;
+import static com.android.ondevicepersonalization.services.process.IsolatedServiceBindingRunner.TRUSTED_PARTNER_APPS_SIP;
 
 import android.adservices.ondevicepersonalization.aidl.IIsolatedModelService;
 import android.content.Context;
diff --git a/src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunner.java b/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
similarity index 89%
rename from src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunner.java
rename to src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
index 81fe61e7..57850f60 100644
--- a/src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunner.java
+++ b/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
@@ -17,6 +17,7 @@
 package com.android.ondevicepersonalization.services.process;
 
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
 
 import android.adservices.ondevicepersonalization.Constants;
@@ -56,14 +57,16 @@ import com.google.common.util.concurrent.ListeningExecutorService;
 import java.util.Objects;
 import java.util.concurrent.TimeoutException;
 
-/** Utilities for running remote isolated services in a shared isolated process (SIP). Note that
- *  this runner is only selected when the shared_isolated_process_feature_enabled flag is enabled.
+/**
+ * A process runner that runs an isolated service by binding to it. It runs the service in a shared
+ * isolated process if the shared_isolated_process_feature_enabled flag is enabled and the selected
+ * isolated service opts in to running in a shared isolated process.
  */
-public class SharedIsolatedProcessRunner implements ProcessRunner  {
+public class IsolatedServiceBindingRunner implements ProcessRunner  {
 
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
 
-    private static final String TAG = SharedIsolatedProcessRunner.class.getSimpleName();
+    private static final String TAG = IsolatedServiceBindingRunner.class.getSimpleName();
 
     // SIP that hosts services from all trusted partners, as well as internal isolated services.
     public static final String TRUSTED_PARTNER_APPS_SIP = "trusted_partner_apps_sip";
@@ -85,25 +88,17 @@ public class SharedIsolatedProcessRunner implements ProcessRunner  {
         }
     }
 
+    /** Creates a ProcessRunner. */
+    IsolatedServiceBindingRunner() {
+        this(OnDevicePersonalizationApplication.getAppContext(), new Injector());
+    }
+
     @VisibleForTesting
-    SharedIsolatedProcessRunner(@NonNull Context applicationContext, @NonNull Injector injector) {
+    IsolatedServiceBindingRunner(@NonNull Context applicationContext, @NonNull Injector injector) {
         mApplicationContext = Objects.requireNonNull(applicationContext);
         mInjector = Objects.requireNonNull(injector);
     }
 
-    private static class LazyInstanceHolder {
-        static final SharedIsolatedProcessRunner LAZY_INSTANCE =
-                new SharedIsolatedProcessRunner(
-                        OnDevicePersonalizationApplication.getAppContext(),
-                        new Injector());
-    }
-
-    /** Returns the global ProcessRunner. */
-    @NonNull
-    public static SharedIsolatedProcessRunner getInstance() {
-        return SharedIsolatedProcessRunner.LazyInstanceHolder.LAZY_INSTANCE;
-    }
-
     /** Binds to a service and put it in one of ODP's shared isolated process. */
     @Override
     @NonNull public ListenableFuture<IsolatedServiceInfo> loadIsolatedService(
@@ -188,12 +183,12 @@ public class SharedIsolatedProcessRunner implements ProcessRunner  {
                                                 final long token = Binder.clearCallingIdentity();
                                                 try {
                                                     ListenableFuture<?> unused =
-                                                        AggregatedErrorCodesLogger
-                                                            .logIsolatedServiceErrorCode(
-                                                                isolatedServiceErrorCode,
-                                                                isolatedProcessInfo
-                                                                    .getComponentName(),
-                                                                mApplicationContext);
+                                                            AggregatedErrorCodesLogger
+                                                                .logIsolatedServiceErrorCode(
+                                                                    isolatedServiceErrorCode,
+                                                                    isolatedProcessInfo
+                                                                        .getComponentName(),
+                                                                    mApplicationContext);
                                                 } finally {
                                                     Binder.restoreCallingIdentity(token);
                                                 }
@@ -240,7 +235,11 @@ public class SharedIsolatedProcessRunner implements ProcessRunner  {
 
     private AbstractServiceBinder<IIsolatedService> getIsolatedServiceBinder(
             @NonNull ComponentName service) throws Exception {
-        boolean isSipRequested = isSharedIsolatedProcessRequested(service);
+        PackageManager pm = mApplicationContext.getPackageManager();
+        sLogger.d(TAG + ": Package manager = " + pm);
+        ServiceInfo si = pm.getServiceInfo(service, PackageManager.GET_META_DATA);
+        checkIsolatedService(service, si);
+        boolean isSipRequested = isSharedIsolatedProcessRequested(si);
 
         // null instance name results in regular isolated service being created.
         String instanceName = isSipRequested ? getSipInstanceName(service.getPackageName()) : null;
@@ -271,15 +270,9 @@ public class SharedIsolatedProcessRunner implements ProcessRunner  {
                     ? sipInstanceName + "_disable_art_image_" : sipInstanceName;
     }
 
-    private boolean isSharedIsolatedProcessRequested(ComponentName service) throws Exception {
-        if (!SdkLevel.isAtLeastU()) {
-            return false;
-        }
-
-        PackageManager pm = mApplicationContext.getPackageManager();
-        ServiceInfo si = pm.getServiceInfo(service, PackageManager.GET_META_DATA);
-
-        sLogger.d(TAG + "Package manager = " + pm);
+    @VisibleForTesting
+    static void checkIsolatedService(ComponentName service, ServiceInfo si)
+            throws OdpServiceException {
         if ((si.flags & si.FLAG_ISOLATED_PROCESS) == 0) {
             sLogger.e(
                     TAG, "ODP client service not configured to run in isolated process " + service);
@@ -287,6 +280,16 @@ public class SharedIsolatedProcessRunner implements ProcessRunner  {
                     Constants.STATUS_MANIFEST_PARSING_FAILED,
                     "ODP client services should run in isolated processes.");
         }
+    }
+
+    @VisibleForTesting
+    static boolean isSharedIsolatedProcessRequested(ServiceInfo si) {
+        if (!SdkLevel.isAtLeastU()) {
+            return false;
+        }
+        if (!(boolean) StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED)) {
+            return false;
+        }
 
         return (si.flags & si.FLAG_ALLOW_SHARED_ISOLATED_PROCESS) != 0;
     }
diff --git a/src/com/android/ondevicepersonalization/services/process/OnDevicePersonalizationPlugin.java b/src/com/android/ondevicepersonalization/services/process/OnDevicePersonalizationPlugin.java
index edddf1ac..e4c6df56 100644
--- a/src/com/android/ondevicepersonalization/services/process/OnDevicePersonalizationPlugin.java
+++ b/src/com/android/ondevicepersonalization/services/process/OnDevicePersonalizationPlugin.java
@@ -108,8 +108,8 @@ public class OnDevicePersonalizationPlugin implements Plugin {
                     }
             );
 
-        } catch (Exception e) {
-            sLogger.e(TAG + ": Plugin failed. ", e);
+        } catch (Throwable e) {
+            sLogger.e(e, TAG + ": Plugin failed.");
             sendErrorResult(FailureType.ERROR_EXECUTING_PLUGIN);
         }
     }
diff --git a/src/com/android/ondevicepersonalization/services/process/PluginProcessRunner.java b/src/com/android/ondevicepersonalization/services/process/PluginProcessRunner.java
index ab5c8c62..6d66c187 100644
--- a/src/com/android/ondevicepersonalization/services/process/PluginProcessRunner.java
+++ b/src/com/android/ondevicepersonalization/services/process/PluginProcessRunner.java
@@ -66,6 +66,11 @@ public class PluginProcessRunner implements ProcessRunner {
 
     private final Injector mInjector;
 
+    /** Creates a ProcessRunner. */
+    PluginProcessRunner() {
+        this(OnDevicePersonalizationApplication.getAppContext(), new Injector());
+    }
+
     /** Creates a ProcessRunner. */
     PluginProcessRunner(
             @NonNull Context applicationContext,
@@ -74,19 +79,6 @@ public class PluginProcessRunner implements ProcessRunner {
         mInjector = Objects.requireNonNull(injector);
     }
 
-
-    private static class PluginProcessRunnerLazyInstanceHolder {
-        static final PluginProcessRunner LAZY_INSTANCE =
-                new PluginProcessRunner(
-                        OnDevicePersonalizationApplication.getAppContext(),
-                        new Injector());
-    }
-
-    /** Returns the global ProcessRunner */
-    @NonNull public static PluginProcessRunner getInstance() {
-        return PluginProcessRunnerLazyInstanceHolder.LAZY_INSTANCE;
-    }
-
     /** Loads a service in an isolated process */
     @Override @NonNull public ListenableFuture<IsolatedServiceInfo> loadIsolatedService(
             @NonNull String taskName, @NonNull ComponentName componentName) {
diff --git a/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java b/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java
new file mode 100644
index 00000000..9ce154ac
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.process;
+
+import com.android.ondevicepersonalization.services.PhFlags;
+import com.android.ondevicepersonalization.services.StableFlags;
+
+/** Creates a ProcessRunner */
+public class ProcessRunnerFactory {
+
+    private static class ProcessRunnerLazyInstanceHolder {
+        static final ProcessRunner LAZY_INSTANCE = createProcessRunner();
+
+        private static ProcessRunner createProcessRunner() {
+            return (boolean) StableFlags.get(PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED)
+                    ? new PluginProcessRunner()
+                    : new IsolatedServiceBindingRunner();
+        }
+    }
+
+    /** Returns the default process runner. */
+    public static ProcessRunner getProcessRunner() {
+        return ProcessRunnerLazyInstanceHolder.LAZY_INSTANCE;
+    }
+
+    private ProcessRunnerFactory() {}
+}
diff --git a/src/com/android/ondevicepersonalization/services/request/AppRequestFlow.java b/src/com/android/ondevicepersonalization/services/request/AppRequestFlow.java
index 64d1b00e..7545e2ad 100644
--- a/src/com/android/ondevicepersonalization/services/request/AppRequestFlow.java
+++ b/src/com/android/ondevicepersonalization/services/request/AppRequestFlow.java
@@ -402,6 +402,7 @@ public class AppRequestFlow implements ServiceFlow<Bundle> {
             return Futures.immediateFuture(-1L);
         }
         return LogUtils.writeLogRecords(
+                Constants.TASK_TYPE_EXECUTE,
                 mContext,
                 mCallingPackageName,
                 mService,
diff --git a/src/com/android/ondevicepersonalization/services/serviceflow/ServiceFlowTask.java b/src/com/android/ondevicepersonalization/services/serviceflow/ServiceFlowTask.java
index 2c95c192..ff9722e1 100644
--- a/src/com/android/ondevicepersonalization/services/serviceflow/ServiceFlowTask.java
+++ b/src/com/android/ondevicepersonalization/services/serviceflow/ServiceFlowTask.java
@@ -16,17 +16,13 @@
 
 package com.android.ondevicepersonalization.services.serviceflow;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-
 import android.os.Bundle;
 
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
-import com.android.ondevicepersonalization.services.StableFlags;
 import com.android.ondevicepersonalization.services.process.IsolatedServiceInfo;
-import com.android.ondevicepersonalization.services.process.PluginProcessRunner;
 import com.android.ondevicepersonalization.services.process.ProcessRunner;
-import com.android.ondevicepersonalization.services.process.SharedIsolatedProcessRunner;
+import com.android.ondevicepersonalization.services.process.ProcessRunnerFactory;
 
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
@@ -45,7 +41,7 @@ public class ServiceFlowTask {
     private final ServiceFlow mServiceFlow;
     private final ProcessRunner mProcessRunner;
     private volatile boolean mIsCompleted;
-    private volatile Exception mExecutionException;
+    private volatile Throwable mExecutionThrowable;
 
     private final ListeningExecutorService mExecutor =
             OnDevicePersonalizationExecutors.getBackgroundExecutor();
@@ -54,10 +50,7 @@ public class ServiceFlowTask {
         mIsCompleted = false;
         mServiceFlowType = serviceFlowType;
         mServiceFlow = serviceFlow;
-        mProcessRunner =
-                (boolean) StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED)
-                        ? SharedIsolatedProcessRunner.getInstance()
-                        : PluginProcessRunner.getInstance();
+        mProcessRunner = ProcessRunnerFactory.getProcessRunner();
     }
 
     public ServiceFlowType getServiceFlowType() {
@@ -72,8 +65,8 @@ public class ServiceFlowTask {
         return mIsCompleted;
     }
 
-    public Exception getExecutionException() {
-        return mExecutionException;
+    public Throwable getExeuctionThrowable() {
+        return mExecutionThrowable;
     }
 
     /** Executes the given service flow. */
@@ -117,9 +110,9 @@ public class ServiceFlowTask {
                                         mIsCompleted = true;
                                         return unloadServiceFuture;
                                     }, mExecutor);
-        } catch (Exception e) {
-            sLogger.w(TAG + ": ServiceFlowTask " + mServiceFlowType + "failed. " + e);
-            mExecutionException = e;
+        } catch (Throwable e) {
+            sLogger.e(e, TAG + ": ServiceFlowTask " + mServiceFlowType + " failed.");
+            mExecutionThrowable = e;
         }
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/statsd/OdpStatsdLogger.java b/src/com/android/ondevicepersonalization/services/statsd/OdpStatsdLogger.java
index d958a33c..f7b70346 100644
--- a/src/com/android/ondevicepersonalization/services/statsd/OdpStatsdLogger.java
+++ b/src/com/android/ondevicepersonalization/services/statsd/OdpStatsdLogger.java
@@ -17,6 +17,7 @@
 package com.android.ondevicepersonalization.services.statsd;
 
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ONDEVICEPERSONALIZATION_API_CALLED;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ONDEVICEPERSONALIZATION_TRACE_EVENT;
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__ADSERVICES_GET_COMMON_STATES;
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__EVENT_URL_CREATE_WITH_REDIRECT;
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__EVENT_URL_CREATE_WITH_RESPONSE;
@@ -40,6 +41,16 @@ import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLo
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__SERVICE_ON_RENDER;
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__SERVICE_ON_TRAINING_EXAMPLE;
 import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__SERVICE_ON_WEB_TRIGGER;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__UNKNOWN;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__WRITE_REQUEST_LOG;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__WRITE_EVENT_LOG;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TASK_TYPE_UNKNOWN;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__EXECUTE;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__RENDER;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__DOWNLOAD;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__WEBVIEW;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TRAINING;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__MAINTENANCE;
 
 import com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog;
 
@@ -74,6 +85,22 @@ public class OdpStatsdLogger {
             ON_DEVICE_PERSONALIZATION_API_CALLED__API_NAME__SERVICE_ON_WEB_TRIGGER
     );
 
+    private static final Set<Integer> sTaskType = Set.of(
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TASK_TYPE_UNKNOWN,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__EXECUTE,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__RENDER,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__DOWNLOAD,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__WEBVIEW,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TRAINING,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__MAINTENANCE
+    );
+
+    private static final Set<Integer> sEventType = Set.of(
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__UNKNOWN,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__WRITE_REQUEST_LOG,
+            ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__WRITE_EVENT_LOG
+    );
+
     /** Returns an instance of {@link OdpStatsdLogger}. */
     public static OdpStatsdLogger getInstance() {
         if (sStatsdLogger == null) {
@@ -103,4 +130,30 @@ public class OdpStatsdLogger {
                 apiCallStats.getAppUid(),
                 apiCallStats.getSdkPackageName());
     }
+
+    /** Log trace event stats e.g. task type, event type, latency etc. */
+    public void logTraceEventStats(int taskType, int eventType, int status,
+            long latencyMillis, String servicePackageName) {
+        TraceEventStats traceEventStats =
+                new TraceEventStats.Builder()
+                        .setTaskType(taskType)
+                        .setEventType(eventType)
+                        .setStatus(status)
+                        .setLatencyMillis((int) latencyMillis)
+                        .setServicePackageName(servicePackageName)
+                        .build();
+        if (!sTaskType.contains(traceEventStats.getTaskType())) {
+            return;
+        }
+        if (!sEventType.contains(traceEventStats.getEventType())) {
+            return;
+        }
+        OnDevicePersonalizationStatsLog.write(
+                ONDEVICEPERSONALIZATION_TRACE_EVENT,
+                traceEventStats.getTaskType(),
+                traceEventStats.getEventType(),
+                traceEventStats.getStatus(),
+                traceEventStats.getLatencyMillis(),
+                traceEventStats.getServicePackageName());
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/statsd/TraceEventStats.java b/src/com/android/ondevicepersonalization/services/statsd/TraceEventStats.java
new file mode 100644
index 00000000..fcbe0273
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/statsd/TraceEventStats.java
@@ -0,0 +1,236 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.statsd;
+
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__UNKNOWN;
+import static com.android.ondevicepersonalization.OnDevicePersonalizationStatsLog.ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TASK_TYPE_UNKNOWN;
+
+import android.annotation.Nullable;
+
+import com.android.ondevicepersonalization.internal.util.DataClass;
+
+/**
+ * Class holds OnDevicePersonalizationApiCalled defined at
+ * frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+ */
+@DataClass(genBuilder = true, genEqualsHashCode = true)
+public class TraceEventStats {
+    private int mTaskType = ON_DEVICE_PERSONALIZATION_TRACE_EVENT__TASK_TYPE__TASK_TYPE_UNKNOWN;
+    private int mEventType = ON_DEVICE_PERSONALIZATION_TRACE_EVENT__EVENT_TYPE__UNKNOWN;
+    private int mStatus = 0;
+    private int mLatencyMillis = 0;
+    @Nullable private String mServicePackageName = "";
+
+
+
+    // Code below generated by codegen v1.0.23.
+    //
+    // DO NOT MODIFY!
+    // CHECKSTYLE:OFF Generated code
+    //
+    // To regenerate run:
+    // $ codegen $ANDROID_BUILD_TOP/packages/modules/OnDevicePersonalization/src/com/android/ondevicepersonalization/services/statsd/TraceEventStats.java
+    //
+    // To exclude the generated code from IntelliJ auto-formatting enable (one-time):
+    //   Settings > Editor > Code Style > Formatter Control
+    //@formatter:off
+
+
+    @DataClass.Generated.Member
+    /* package-private */ TraceEventStats(
+            int taskType,
+            int eventType,
+            int status,
+            int latencyMillis,
+            @Nullable String servicePackageName) {
+        this.mTaskType = taskType;
+        this.mEventType = eventType;
+        this.mStatus = status;
+        this.mLatencyMillis = latencyMillis;
+        this.mServicePackageName = servicePackageName;
+
+        // onConstructed(); // You can define this method to get a callback
+    }
+
+    @DataClass.Generated.Member
+    public int getTaskType() {
+        return mTaskType;
+    }
+
+    @DataClass.Generated.Member
+    public int getEventType() {
+        return mEventType;
+    }
+
+    @DataClass.Generated.Member
+    public int getStatus() {
+        return mStatus;
+    }
+
+    @DataClass.Generated.Member
+    public int getLatencyMillis() {
+        return mLatencyMillis;
+    }
+
+    @DataClass.Generated.Member
+    public @Nullable String getServicePackageName() {
+        return mServicePackageName;
+    }
+
+    @Override
+    @DataClass.Generated.Member
+    public boolean equals(@Nullable Object o) {
+        // You can override field equality logic by defining either of the methods like:
+        // boolean fieldNameEquals(TraceEventStats other) { ... }
+        // boolean fieldNameEquals(FieldType otherValue) { ... }
+
+        if (this == o) return true;
+        if (o == null || getClass() != o.getClass()) return false;
+        @SuppressWarnings("unchecked")
+        TraceEventStats that = (TraceEventStats) o;
+        //noinspection PointlessBooleanExpression
+        return true
+                && mTaskType == that.mTaskType
+                && mEventType == that.mEventType
+                && mStatus == that.mStatus
+                && mLatencyMillis == that.mLatencyMillis
+                && java.util.Objects.equals(mServicePackageName, that.mServicePackageName);
+    }
+
+    @Override
+    @DataClass.Generated.Member
+    public int hashCode() {
+        // You can override field hashCode logic by defining methods like:
+        // int fieldNameHashCode() { ... }
+
+        int _hash = 1;
+        _hash = 31 * _hash + mTaskType;
+        _hash = 31 * _hash + mEventType;
+        _hash = 31 * _hash + mStatus;
+        _hash = 31 * _hash + mLatencyMillis;
+        _hash = 31 * _hash + java.util.Objects.hashCode(mServicePackageName);
+        return _hash;
+    }
+
+    /**
+     * A builder for {@link TraceEventStats}
+     */
+    @SuppressWarnings("WeakerAccess")
+    @DataClass.Generated.Member
+    public static class Builder {
+
+        private int mTaskType;
+        private int mEventType;
+        private int mStatus;
+        private int mLatencyMillis;
+        private @Nullable String mServicePackageName;
+
+        private long mBuilderFieldsSet = 0L;
+
+        public Builder() {
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setTaskType(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x1;
+            mTaskType = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setEventType(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x2;
+            mEventType = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setStatus(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x4;
+            mStatus = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setLatencyMillis(int value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x8;
+            mLatencyMillis = value;
+            return this;
+        }
+
+        @DataClass.Generated.Member
+        public @android.annotation.NonNull Builder setServicePackageName(@android.annotation.NonNull String value) {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x10;
+            mServicePackageName = value;
+            return this;
+        }
+
+        /** Builds the instance. This builder should not be touched after calling this! */
+        public @android.annotation.NonNull TraceEventStats build() {
+            checkNotUsed();
+            mBuilderFieldsSet |= 0x20; // Mark builder used
+
+            if ((mBuilderFieldsSet & 0x1) == 0) {
+                mTaskType = 0;
+            }
+            if ((mBuilderFieldsSet & 0x2) == 0) {
+                mEventType = 0;
+            }
+            if ((mBuilderFieldsSet & 0x4) == 0) {
+                mStatus = 0;
+            }
+            if ((mBuilderFieldsSet & 0x8) == 0) {
+                mLatencyMillis = 0;
+            }
+            if ((mBuilderFieldsSet & 0x10) == 0) {
+                mServicePackageName = "";
+            }
+            TraceEventStats o = new TraceEventStats(
+                    mTaskType,
+                    mEventType,
+                    mStatus,
+                    mLatencyMillis,
+                    mServicePackageName);
+            return o;
+        }
+
+        private void checkNotUsed() {
+            if ((mBuilderFieldsSet & 0x20) != 0) {
+                throw new IllegalStateException(
+                        "This Builder should not be reused. Use a new Builder instance instead");
+            }
+        }
+    }
+
+    @DataClass.Generated(
+            time = 1728943962441L,
+            codegenVersion = "1.0.23",
+            sourceFile = "packages/modules/OnDevicePersonalization/src/com/android/ondevicepersonalization/services/statsd/TraceEventStats.java",
+            inputSignatures = "private  int mTaskType\nprivate  int mEventType\nprivate  int mStatus\nprivate  int mLatencyMillis\nprivate @android.annotation.Nullable java.lang.String mServicePackageName\nclass TraceEventStats extends java.lang.Object implements []\n@com.android.ondevicepersonalization.internal.util.DataClass(genBuilder=true, genEqualsHashCode=true)")
+    @Deprecated
+    private void __metadata() {}
+
+
+    //@formatter:on
+    // End of generated code
+
+}
diff --git a/src/com/android/ondevicepersonalization/services/util/LogUtils.java b/src/com/android/ondevicepersonalization/services/util/LogUtils.java
index 89be8b00..646e189b 100644
--- a/src/com/android/ondevicepersonalization/services/util/LogUtils.java
+++ b/src/com/android/ondevicepersonalization/services/util/LogUtils.java
@@ -16,6 +16,7 @@
 
 package com.android.ondevicepersonalization.services.util;
 
+import android.adservices.ondevicepersonalization.Constants;
 import android.adservices.ondevicepersonalization.EventLogRecord;
 import android.adservices.ondevicepersonalization.RequestLogRecord;
 import android.annotation.NonNull;
@@ -23,6 +24,7 @@ import android.annotation.Nullable;
 import android.content.ComponentName;
 import android.content.ContentValues;
 import android.content.Context;
+import android.os.SystemClock;
 
 import com.android.odp.module.common.PackageUtils;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
@@ -31,6 +33,7 @@ import com.android.ondevicepersonalization.services.data.DbUtils;
 import com.android.ondevicepersonalization.services.data.events.Event;
 import com.android.ondevicepersonalization.services.data.events.EventsDao;
 import com.android.ondevicepersonalization.services.data.events.Query;
+import com.android.ondevicepersonalization.services.statsd.OdpStatsdLogger;
 
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
@@ -45,11 +48,13 @@ public class LogUtils {
 
     /** Writes the provided records to the REQUESTS and EVENTS tables. */
     public static ListenableFuture<Long> writeLogRecords(
+            int taskType,
             @NonNull Context context,
             @NonNull String appPackageName,
             @NonNull ComponentName service,
             @Nullable RequestLogRecord requestLogRecord,
-            @NonNull List<EventLogRecord> eventLogRecords) {
+            @Nullable List<EventLogRecord> eventLogRecords) {
+        long logStartedTimeMills = SystemClock.elapsedRealtime();
         sLogger.d(TAG + ": writeLogRecords() started.");
         try {
             String serviceName = DbUtils.toTableValue(service);
@@ -64,6 +69,12 @@ public class LogUtils {
                 List<ContentValues> rows = requestLogRecord.getRows();
                 if (rows.isEmpty()) {
                     rows = List.of(new ContentValues());
+                    logTraceEventStats(
+                            taskType,
+                            Constants.EVENT_TYPE_WRITE_REQUEST_LOG,
+                            Constants.STATUS_REQUEST_LOG_IS_EMPTY,
+                            SystemClock.elapsedRealtime() - logStartedTimeMills,
+                            service.getPackageName());
                 }
                 byte[] queryData = OnDevicePersonalizationFlatbufferUtils.createQueryData(
                         serviceName, certDigest, rows);
@@ -75,12 +86,41 @@ public class LogUtils {
                         queryData).build();
                 queryId = eventsDao.insertQuery(query);
                 if (queryId == -1) {
+                    logTraceEventStats(
+                            taskType,
+                            Constants.EVENT_TYPE_WRITE_REQUEST_LOG,
+                            Constants.STATUS_LOG_DB_FAILURE,
+                            SystemClock.elapsedRealtime() - logStartedTimeMills,
+                            service.getPackageName());
                     return Futures.immediateFailedFuture(
-                            new RuntimeException("Failed to log query."));
+                            new RuntimeException("Failed to insert request log record."));
+                } else {
+                    logTraceEventStats(
+                            taskType,
+                            Constants.EVENT_TYPE_WRITE_REQUEST_LOG,
+                            Constants.STATUS_REQUEST_LOG_DB_SUCCESS,
+                            SystemClock.elapsedRealtime() - logStartedTimeMills,
+                            service.getPackageName());
                 }
+            } else {
+                logTraceEventStats(
+                        taskType,
+                        Constants.EVENT_TYPE_WRITE_REQUEST_LOG,
+                        Constants.STATUS_REQUEST_LOG_IS_NULL,
+                        SystemClock.elapsedRealtime() - logStartedTimeMills,
+                        service.getPackageName());
             }
 
             // Insert events
+            if (eventLogRecords == null || eventLogRecords.size() == 0) {
+                logTraceEventStats(
+                        taskType,
+                        Constants.EVENT_TYPE_WRITE_EVENT_LOG,
+                        Constants.STATUS_EVENT_LOG_IS_NULL,
+                        SystemClock.elapsedRealtime() - logStartedTimeMills,
+                        service.getPackageName());
+                return Futures.immediateFuture(queryId);
+            }
             List<Event> events = new ArrayList<>();
             for (EventLogRecord eventLogRecord : eventLogRecords) {
                 RequestLogRecord parent;
@@ -95,6 +135,12 @@ public class LogUtils {
                 // Verify requestLogRecord exists and has the corresponding rowIndex
                 if (parent == null || parentRequestId <= 0
                         || eventLogRecord.getRowIndex() >= parent.getRows().size()) {
+                    logTraceEventStats(
+                            taskType,
+                            Constants.EVENT_TYPE_WRITE_EVENT_LOG,
+                            Constants.STATUS_EVENT_LOG_NOT_EXIST,
+                            SystemClock.elapsedRealtime() - logStartedTimeMills,
+                            service.getPackageName());
                     continue;
                 }
                 // Make sure query exists for package in QUERY table and
@@ -104,6 +150,12 @@ public class LogUtils {
                         >= OnDevicePersonalizationFlatbufferUtils
                                 .getContentValuesLengthFromQueryData(
                                         queryRow.getQueryData())) {
+                    logTraceEventStats(
+                            taskType,
+                            Constants.EVENT_TYPE_WRITE_EVENT_LOG,
+                            Constants.STATUS_EVENT_LOG_QUERY_NOT_EXIST,
+                            SystemClock.elapsedRealtime() - logStartedTimeMills,
+                            service.getPackageName());
                     continue;
                 }
                 Event event = new Event.Builder()
@@ -118,15 +170,39 @@ public class LogUtils {
                 events.add(event);
             }
             if (!eventsDao.insertEvents(events)) {
+                logTraceEventStats(
+                        taskType,
+                        Constants.EVENT_TYPE_WRITE_EVENT_LOG,
+                        Constants.STATUS_LOG_DB_FAILURE,
+                        SystemClock.elapsedRealtime() - logStartedTimeMills,
+                        service.getPackageName());
                 return Futures.immediateFailedFuture(
-                        new RuntimeException("Failed to log events."));
+                        new RuntimeException("Failed to insert events log record."));
+            } else {
+                logTraceEventStats(
+                        taskType,
+                        Constants.EVENT_TYPE_WRITE_EVENT_LOG,
+                        Constants.STATUS_EVENT_LOG_DB_SUCCESS,
+                        SystemClock.elapsedRealtime() - logStartedTimeMills,
+                        service.getPackageName());
             }
-
             return Futures.immediateFuture(queryId);
         } catch (Exception e) {
+            logTraceEventStats(
+                    taskType,
+                    Constants.EVENT_TYPE_UNKNOWN,
+                    Constants.STATUS_LOG_EXCEPTION,
+                    SystemClock.elapsedRealtime() - logStartedTimeMills,
+                    service.getPackageName());
             return Futures.immediateFailedFuture(e);
         }
     }
 
+    private static void logTraceEventStats(int taskType, int eventType, int status,
+            long latencyMillis, String servicePackageName) {
+        OdpStatsdLogger.getInstance()
+                .logTraceEventStats(taskType, eventType, status, latencyMillis, servicePackageName);
+    }
+
     private LogUtils() {}
 }
diff --git a/src/com/android/ondevicepersonalization/services/webtrigger/WebTriggerFlow.java b/src/com/android/ondevicepersonalization/services/webtrigger/WebTriggerFlow.java
index 669b2f11..71e7688e 100644
--- a/src/com/android/ondevicepersonalization/services/webtrigger/WebTriggerFlow.java
+++ b/src/com/android/ondevicepersonalization/services/webtrigger/WebTriggerFlow.java
@@ -299,6 +299,7 @@ public class WebTriggerFlow implements ServiceFlow<WebTriggerOutputParcel> {
         sLogger.d(TAG + ": writeToLog() started.");
         var unused = FluentFuture.from(
                         LogUtils.writeLogRecords(
+                                Constants.TASK_TYPE_WEB_TRIGGER,
                                 mContext,
                                 mServiceParcel.getAppPackageName(),
                                 wtparams.getIsolatedService(),
diff --git a/systemservice/java/com/android/server/ondevicepersonalization/BooleanFileDataStore.java b/systemservice/java/com/android/server/ondevicepersonalization/BooleanFileDataStore.java
deleted file mode 100644
index 127e4778..00000000
--- a/systemservice/java/com/android/server/ondevicepersonalization/BooleanFileDataStore.java
+++ /dev/null
@@ -1,223 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.server.ondevicepersonalization;
-
-import android.annotation.NonNull;
-import android.annotation.Nullable;
-import android.os.PersistableBundle;
-import android.util.AtomicFile;
-
-import com.android.internal.annotations.GuardedBy;
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.internal.util.Preconditions;
-import com.android.ondevicepersonalization.internal.util.LoggerFactory;
-
-import java.io.ByteArrayInputStream;
-import java.io.ByteArrayOutputStream;
-import java.io.File;
-import java.io.FileNotFoundException;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.util.HashMap;
-import java.util.Map;
-import java.util.Objects;
-import java.util.Set;
-import java.util.concurrent.locks.Lock;
-import java.util.concurrent.locks.ReadWriteLock;
-import java.util.concurrent.locks.ReentrantReadWriteLock;
-
-/**
- * A generic key-value datastore utilizing {@link android.util.AtomicFile} and {@link
- * android.os.PersistableBundle} to read/write a simple key/value map to file.
- * This class is thread-safe.
- * @hide
- */
-public class BooleanFileDataStore {
-    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
-    private static final String TAG = "BooleanFileDataStore";
-    private final ReadWriteLock mReadWriteLock = new ReentrantReadWriteLock();
-    private final Lock mReadLock = mReadWriteLock.readLock();
-    private final Lock mWriteLock = mReadWriteLock.writeLock();
-
-    private final AtomicFile mAtomicFile;
-    private final Map<String, Boolean> mLocalMap = new HashMap<>();
-
-    // TODO (b/300993651): make the datastore access singleton.
-    // TODO (b/301131410): add version history feature.
-    public BooleanFileDataStore(@NonNull String parentPath, @NonNull String filename) {
-        Objects.requireNonNull(parentPath);
-        Objects.requireNonNull(filename);
-        Preconditions.checkStringNotEmpty(parentPath);
-        Preconditions.checkStringNotEmpty(filename);
-        mAtomicFile = new AtomicFile(new File(parentPath, filename));
-    }
-
-    /**
-     * Loads data from the datastore file on disk.
-     * @throws IOException if file read fails.
-     */
-    public void initialize() throws IOException {
-        sLogger.d(TAG + ": reading from file " + mAtomicFile.getBaseFile());
-        mReadLock.lock();
-        try {
-            readFromFile();
-        } finally {
-            mReadLock.unlock();
-        }
-    }
-
-    /**
-     * Stores a value to the datastore file, which is immediately committed.
-     * @param key A non-null, non-empty String to store the {@code value}.
-     * @param value A boolean to be stored.
-     * @throws IOException if file write fails.
-     * @throws NullPointerException if {@code key} is null.
-     * @throws IllegalArgumentException if (@code key) is an empty string.
-     */
-    public void put(@NonNull String key, boolean value) throws IOException {
-        Objects.requireNonNull(key);
-        Preconditions.checkStringNotEmpty(key, "Key must not be empty.");
-
-        mWriteLock.lock();
-        try {
-            mLocalMap.put(key, value);
-            writeToFile();
-        } finally {
-            mWriteLock.unlock();
-        }
-    }
-
-    /**
-     * Retrieves a boolean value from the loaded datastore file.
-     *
-     * @param key A non-null, non-empty String key to fetch a value from.
-     * @return The boolean value stored against a {@code key}, or null if it doesn't exist.
-     * @throws IllegalArgumentException if {@code key} is an empty string.
-     * @throws NullPointerException if {@code key} is null.
-     */
-    @Nullable
-    public Boolean get(@NonNull String key) {
-        Objects.requireNonNull(key);
-        Preconditions.checkStringNotEmpty(key);
-
-        mReadLock.lock();
-        try {
-            return mLocalMap.get(key);
-        } finally {
-            mReadLock.unlock();
-        }
-    }
-
-    /**
-     * Retrieves a {@link Set} of all keys loaded from the datastore file.
-     *
-     * @return A {@link Set} of {@link String} keys currently in the loaded datastore
-     */
-    @NonNull
-    public Set<String> keySet() {
-        mReadLock.lock();
-        try {
-            return Set.copyOf(mLocalMap.keySet());
-        } finally {
-            mReadLock.unlock();
-        }
-    }
-
-    /**
-     * Clears all entries from the datastore file and committed immediately.
-     *
-     * @throws IOException if file write fails.
-     */
-    public void clear() throws IOException {
-        sLogger.d(TAG + ": clearing all entries from datastore");
-
-        mWriteLock.lock();
-        try {
-            mLocalMap.clear();
-            writeToFile();
-        } finally {
-            mWriteLock.unlock();
-        }
-    }
-
-    @GuardedBy("mWriteLock")
-    private void writeToFile() throws IOException {
-        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
-        final PersistableBundle persistableBundle = new PersistableBundle();
-        for (Map.Entry<String, Boolean> entry: mLocalMap.entrySet()) {
-            persistableBundle.putBoolean(entry.getKey(), entry.getValue());
-        }
-
-        persistableBundle.writeToStream(outputStream);
-
-        FileOutputStream out = null;
-        try {
-            out = mAtomicFile.startWrite();
-            out.write(outputStream.toByteArray());
-            mAtomicFile.finishWrite(out);
-        } catch (IOException e) {
-            mAtomicFile.failWrite(out);
-            sLogger.e(TAG + ": write to file " + mAtomicFile.getBaseFile() + " failed.");
-            throw e;
-        }
-    }
-
-    @GuardedBy("mReadLock")
-    private void readFromFile() throws IOException {
-        try {
-            final ByteArrayInputStream inputStream = new ByteArrayInputStream(
-                            mAtomicFile.readFully());
-            final PersistableBundle persistableBundle = PersistableBundle.readFromStream(
-                            inputStream);
-
-            mLocalMap.clear();
-            for (String key: persistableBundle.keySet()) {
-                mLocalMap.put(key, persistableBundle.getBoolean(key));
-            }
-        } catch (FileNotFoundException e) {
-            sLogger.d(TAG + ": file not found exception.");
-            mLocalMap.clear();
-        } catch (IOException e) {
-            sLogger.e(TAG + ": read from " + mAtomicFile.getBaseFile() + " failed");
-            throw e;
-        }
-    }
-
-    /**
-     * Delete the datastore file for testing.
-     */
-    @VisibleForTesting
-    public void tearDownForTesting() {
-        mWriteLock.lock();
-        try {
-            mAtomicFile.delete();
-            mLocalMap.clear();
-        } finally {
-            mWriteLock.unlock();
-        }
-    }
-
-    /**
-     * Clear the loaded content from local map for testing.
-     */
-    @VisibleForTesting
-    public void clearLocalMapForTesting() {
-        mWriteLock.lock();
-        mLocalMap.clear();
-        mWriteLock.unlock();
-    }
-}
diff --git a/systemservice/java/com/android/server/ondevicepersonalization/OnDevicePersonalizationSystemService.java b/systemservice/java/com/android/server/ondevicepersonalization/OnDevicePersonalizationSystemService.java
index 466ebcec..29457093 100644
--- a/systemservice/java/com/android/server/ondevicepersonalization/OnDevicePersonalizationSystemService.java
+++ b/systemservice/java/com/android/server/ondevicepersonalization/OnDevicePersonalizationSystemService.java
@@ -15,10 +15,8 @@
  */
 package com.android.server.ondevicepersonalization;
 
-import static android.adservices.ondevicepersonalization.OnDevicePersonalizationPermissions.ACCESS_SYSTEM_SERVER_SERVICE;
 import static android.ondevicepersonalization.OnDevicePersonalizationSystemServiceManager.ON_DEVICE_PERSONALIZATION_SYSTEM_SERVICE;
 
-import android.adservices.ondevicepersonalization.Constants;
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.ondevicepersonalization.IOnDevicePersonalizationSystemService;
@@ -27,126 +25,30 @@ import android.os.Bundle;
 import android.os.RemoteException;
 import android.util.Log;
 
-import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.SystemService;
 
-import java.util.Objects;
-
 /**
  * @hide
  */
 public class OnDevicePersonalizationSystemService
         extends IOnDevicePersonalizationSystemService.Stub {
     private static final String TAG = "ondevicepersonalization";
-    // TODO(b/302991763): set up per-user directory if needed.
-    private static final String ODP_BASE_DIR = "/data/system/ondevicepersonalization/0/";
-    private static final String CONFIG_FILE_IDENTIFIER = "CONFIG";
-    public static final String PERSONALIZATION_STATUS_KEY = "PERSONALIZATION_STATUS";
     private final Context mContext;
-    private BooleanFileDataStore mDataStore = null;
-
-    // TODO(b/302992251): use a manager to access configs instead of directly exposing DataStore.
 
     OnDevicePersonalizationSystemService(Context context) {
-        this(context, new BooleanFileDataStore(ODP_BASE_DIR, CONFIG_FILE_IDENTIFIER));
-    }
-
-    @VisibleForTesting
-    OnDevicePersonalizationSystemService(Context context, BooleanFileDataStore dataStore) {
-        Objects.requireNonNull(context);
-        Objects.requireNonNull(dataStore);
         mContext = context;
-        try {
-            this.mDataStore = dataStore;
-            mDataStore.initialize();
-        } catch (Exception e) {
-            Log.e(TAG, "Cannot initialize system service datastore.", e);
-            mDataStore = null;
-        }
     }
 
     @Override public void onRequest(
             Bundle bundle,
             IOnDevicePersonalizationSystemServiceCallback callback) {
-        enforceCallingPermission();
-        sendResult(callback, null);
-    }
-
-    @Override
-    public void setPersonalizationStatus(
-            boolean enabled,
-            IOnDevicePersonalizationSystemServiceCallback callback) {
-        enforceCallingPermission();
-        Bundle result = new Bundle();
         try {
-            mDataStore.put(PERSONALIZATION_STATUS_KEY, enabled);
-            // Confirm the value was updated.
-            Boolean statusResult = mDataStore.get(PERSONALIZATION_STATUS_KEY);
-            if (statusResult == null || statusResult.booleanValue() != enabled) {
-                sendError(callback, Constants.STATUS_INTERNAL_ERROR);
-                return;
-            }
-            // Echo the result back
-            result.putBoolean(PERSONALIZATION_STATUS_KEY, statusResult);
-        } catch (Exception e) {
-            Log.e(TAG, "Unable to persist personalization status", e);
-            sendError(callback, Constants.STATUS_INTERNAL_ERROR);
-            return;
-        }
-
-        sendResult(callback, result);
-    }
-
-    @Override
-    public void readPersonalizationStatus(
-            IOnDevicePersonalizationSystemServiceCallback callback) {
-        enforceCallingPermission();
-        Boolean result = null;
-
-        try {
-            result = mDataStore.get(PERSONALIZATION_STATUS_KEY);
-        } catch (Exception e) {
-            Log.e(TAG, "Error reading datastore", e);
-            sendError(callback, Constants.STATUS_INTERNAL_ERROR);
-            return;
-        }
-
-        if (result == null) {
-            Log.d(TAG, "Unable to restore personalization status");
-            sendError(callback, Constants.STATUS_KEY_NOT_FOUND);
-        } else {
-            Bundle bundle = new Bundle();
-            bundle.putBoolean(PERSONALIZATION_STATUS_KEY, result.booleanValue());
-            sendResult(callback, bundle);
-        }
-    }
-
-    private void sendResult(
-            IOnDevicePersonalizationSystemServiceCallback callback, Bundle bundle) {
-        try {
-            callback.onResult(bundle);
-        } catch (RemoteException e) {
-            Log.e(TAG, "Callback error", e);
-        }
-    }
-
-    private void sendError(
-            IOnDevicePersonalizationSystemServiceCallback callback, int errorCode) {
-        try {
-            callback.onError(errorCode);
+            callback.onResult(Bundle.EMPTY);
         } catch (RemoteException e) {
             Log.e(TAG, "Callback error", e);
         }
     }
 
-    @VisibleForTesting
-    void enforceCallingPermission() {
-        if (mContext.checkCallingPermission(ACCESS_SYSTEM_SERVER_SERVICE)
-                != PackageManager.PERMISSION_GRANTED) {
-            throw new SecurityException("ODP System Service Permission denied");
-        }
-    }
-
     /** @hide */
     public static class Lifecycle extends SystemService {
         private OnDevicePersonalizationSystemService mService;
@@ -163,8 +65,8 @@ public class OnDevicePersonalizationSystemService
         /** @hide */
         @Override
         public void onStart() {
-            if (mService == null || mService.mDataStore == null) {
-                Log.e(TAG, "OnDevicePersonalizationSystemService not started!");
+            if (mService == null) {
+                Log.i(TAG, "OnDevicePersonalizationSystemService not started!");
                 return;
             }
             publishBinderService(ON_DEVICE_PERSONALIZATION_SYSTEM_SERVICE, mService);
@@ -176,7 +78,7 @@ public class OnDevicePersonalizationSystemService
             final PackageManager pm = context.getPackageManager();
             if (pm == null) {
                 Log.e(TAG, "PackageManager not found.");
-                return true;
+                return false;
             }
             return !pm.hasSystemFeature(PackageManager.FEATURE_WATCH)
                     && !pm.hasSystemFeature(PackageManager.FEATURE_AUTOMOTIVE)
diff --git a/tests/chronicletests/AndroidTest.xml b/tests/chronicletests/AndroidTest.xml
index 0dd519f1..74c3668b 100644
--- a/tests/chronicletests/AndroidTest.xml
+++ b/tests/chronicletests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OdpChronicleTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" /><!-- Allow hidden API uses -->
         <option name="package" value="com.android.libraries.pcc.chronicle.test"/>
diff --git a/tests/commontests/AndroidTest.xml b/tests/commontests/AndroidTest.xml
index 617277c1..fdd177d9 100644
--- a/tests/commontests/AndroidTest.xml
+++ b/tests/commontests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="CommonUtilsTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" />
         <option name="package" value="com.android.odp.module.commontests"/>
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDaoTest.java b/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java
similarity index 63%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDaoTest.java
rename to tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java
index 1f7c03b7..e14102fb 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenDaoTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -40,8 +40,9 @@ import java.util.UUID;
 @RunWith(AndroidJUnit4.class)
 public class ODPAuthorizationTokenDaoTest {
 
-    private ODPAuthorizationTokenDao mODPAuthorizationTokenDao;
-    private Context mContext;
+    private static final Context sTestContext = ApplicationProvider.getApplicationContext();
+    private static final OdpEncryptionKeyDaoTest.TestDbHelper sTestDbHelper =
+            new OdpEncryptionKeyDaoTest.TestDbHelper(sTestContext);
 
     private final Clock mClock = MonotonicClock.getInstance();
 
@@ -55,34 +56,32 @@ public class ODPAuthorizationTokenDaoTest {
 
     private static final long ONE_HOUR = 60 * 60 * 60 * 1000L;
 
+    private ODPAuthorizationTokenDao mDaoUnderTest;
+
     @Before
     public void setUp() {
-        mContext = ApplicationProvider.getApplicationContext();
-        mODPAuthorizationTokenDao = ODPAuthorizationTokenDao.getInstanceForTest(mContext);
+        mDaoUnderTest = ODPAuthorizationTokenDao.getInstanceForTest(sTestDbHelper);
     }
 
     @After
     public void cleanUp() throws Exception {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        sTestDbHelper.getWritableDatabase().close();
+        sTestDbHelper.getReadableDatabase().close();
+        sTestDbHelper.close();
     }
 
     @Test
     public void testInsertAuthToken_notExist_success() {
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
+        SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
         assertThat(
                         DatabaseUtils.queryNumEntries(
                                 db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(0);
-
         ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
         ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
 
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken1);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken2);
+        mDaoUnderTest.insertAuthorizationToken(authToken1);
+        mDaoUnderTest.insertAuthorizationToken(authToken2);
         assertThat(
                         DatabaseUtils.queryNumEntries(
                                 db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
@@ -91,20 +90,19 @@ public class ODPAuthorizationTokenDaoTest {
 
     @Test
     public void testInsertAuthToken_preExist_success() {
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
+        SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
         ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
         ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER1, TOKEN2, ONE_HOUR);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken1);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken2);
+
+        mDaoUnderTest.insertAuthorizationToken(authToken1);
+        mDaoUnderTest.insertAuthorizationToken(authToken2);
+        ODPAuthorizationToken storedToken =
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
 
         assertThat(
                         DatabaseUtils.queryNumEntries(
                                 db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(1);
-
-        ODPAuthorizationToken storedToken =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
         assertThat(storedToken).isEqualTo(authToken2);
     }
 
@@ -113,20 +111,20 @@ public class ODPAuthorizationTokenDaoTest {
         assertThrows(NullPointerException.class, this::insertNullAuthToken);
     }
 
-    private void insertNullAuthToken() throws Exception {
+    private void insertNullAuthToken() {
         ODPAuthorizationToken authToken =
                 new ODPAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER1)
                         .setCreationTime(mClock.currentTimeMillis())
                         .setExpiryTime(mClock.currentTimeMillis() + ONE_HOUR)
                         .build();
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken);
+        mDaoUnderTest.insertAuthorizationToken(authToken);
     }
 
     @Test
-    public void testGetAuthToken_notExist_success() {
+    public void testGetAuthToken_notExist_returnsNullToken() {
         ODPAuthorizationToken authToken =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
         assertThat(authToken).isEqualTo(null);
     }
 
@@ -134,29 +132,31 @@ public class ODPAuthorizationTokenDaoTest {
     public void testGetAuthToken_exist_success() {
         ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
         ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken1);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken2);
+        mDaoUnderTest.insertAuthorizationToken(authToken1);
+        mDaoUnderTest.insertAuthorizationToken(authToken2);
 
         ODPAuthorizationToken storedToken1 =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
         ODPAuthorizationToken storedToken2 =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
 
         assertThat(storedToken1).isEqualTo(authToken1);
         assertThat(storedToken2).isEqualTo(authToken2);
     }
 
     @Test
-    public void testGetAuthToken_expired_success() {
-        ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, 0L);
-        ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, 0L);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken1);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken2);
+    public void testGetAuthToken_expired_returnsNullToken() {
+        ODPAuthorizationToken authToken1 =
+                createAuthToken(OWNER_IDENTIFIER1, TOKEN1, /* ttl= */ 0L);
+        ODPAuthorizationToken authToken2 =
+                createAuthToken(OWNER_IDENTIFIER2, TOKEN2, /* ttl= */ 0L);
+        mDaoUnderTest.insertAuthorizationToken(authToken1);
+        mDaoUnderTest.insertAuthorizationToken(authToken2);
 
         ODPAuthorizationToken storedToken1 =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
         ODPAuthorizationToken storedToken2 =
-                mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
+                mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
 
         assertThat(storedToken1).isEqualTo(null);
         assertThat(storedToken2).isEqualTo(null);
@@ -164,12 +164,11 @@ public class ODPAuthorizationTokenDaoTest {
 
     @Test
     public void testDeleteAuthToken_exist_success() {
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
+        SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
         ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken1);
+        mDaoUnderTest.insertAuthorizationToken(authToken1);
 
-        int deletedRows = mODPAuthorizationTokenDao.deleteAuthorizationToken(OWNER_IDENTIFIER1);
+        int deletedRows = mDaoUnderTest.deleteAuthorizationToken(OWNER_IDENTIFIER1);
 
         assertThat(
                         DatabaseUtils.queryNumEntries(
@@ -180,36 +179,33 @@ public class ODPAuthorizationTokenDaoTest {
 
     @Test
     public void testDeleteAuthToken_notExist_success() {
-        int deletedRows = mODPAuthorizationTokenDao.deleteAuthorizationToken(OWNER_IDENTIFIER1);
+        int deletedRows = mDaoUnderTest.deleteAuthorizationToken(OWNER_IDENTIFIER1);
         assertThat(deletedRows).isEqualTo(0);
     }
 
     @Test
     public void testDeleteAuthTokensEmpty_success() {
-        long rowsDeleted = mODPAuthorizationTokenDao.deleteExpiredAuthorizationTokens();
-
+        long rowsDeleted = mDaoUnderTest.deleteExpiredAuthorizationTokens();
         assertThat(rowsDeleted).isEqualTo(0);
     }
 
     @Test
     public void testDeleteAuthTokens_success() throws Exception {
-        mODPAuthorizationTokenDao.insertAuthorizationToken(
+        mDaoUnderTest.insertAuthorizationToken(
                 createAuthToken(/* owner= */ "o1", UUID.randomUUID().toString(), /* ttl= */ 0L));
-        mODPAuthorizationTokenDao.insertAuthorizationToken(
+        mDaoUnderTest.insertAuthorizationToken(
                 createAuthToken(/* owner= */ "o2", UUID.randomUUID().toString(), /* ttl= */ 0L));
-        mODPAuthorizationTokenDao.insertAuthorizationToken(
+        mDaoUnderTest.insertAuthorizationToken(
                 createAuthToken(/* owner= */ "o3", UUID.randomUUID().toString(), ONE_HOUR));
 
         Thread.sleep(10L);
-        long rowsDeleted = mODPAuthorizationTokenDao.deleteExpiredAuthorizationTokens();
+        long rowsDeleted = mDaoUnderTest.deleteExpiredAuthorizationTokens();
 
         assertThat(rowsDeleted).isEqualTo(2);
     }
 
     private ODPAuthorizationToken createAuthToken(String owner, String token, Long ttl) {
         long now = mClock.currentTimeMillis();
-        return new ODPAuthorizationToken.Builder(
-                        owner, token, now, now + ttl)
-                .build();
+        return new ODPAuthorizationToken.Builder(owner, token, now, now + ttl).build();
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenTest.java b/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java
similarity index 53%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenTest.java
rename to tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java
index 2aee7cb3..60a1c6b7 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/ODPAuthorizationTokenTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java
@@ -14,8 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
-
+package com.android.odp.module.common.data;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
@@ -40,24 +39,30 @@ public class ODPAuthorizationTokenTest {
 
     @Test
     public void testBuilderAndEquals() {
-        ODPAuthorizationToken token1 = new ODPAuthorizationToken.Builder()
-                .setOwnerIdentifier(OWNER_IDENTIFIER)
-                .setAuthorizationToken(TOKEN)
-                .setCreationTime(NOW)
-                .setExpiryTime(NOW + ONE_HOUR).build();
-        ODPAuthorizationToken token2 = new ODPAuthorizationToken.Builder()
-                .setOwnerIdentifier(OWNER_IDENTIFIER)
-                .setAuthorizationToken(TOKEN)
-                .setCreationTime(NOW)
-                .setExpiryTime(NOW + ONE_HOUR).build();
+        ODPAuthorizationToken token1 =
+                new ODPAuthorizationToken.Builder()
+                        .setOwnerIdentifier(OWNER_IDENTIFIER)
+                        .setAuthorizationToken(TOKEN)
+                        .setCreationTime(NOW)
+                        .setExpiryTime(NOW + ONE_HOUR)
+                        .build();
+        ODPAuthorizationToken token2 =
+                new ODPAuthorizationToken.Builder()
+                        .setOwnerIdentifier(OWNER_IDENTIFIER)
+                        .setAuthorizationToken(TOKEN)
+                        .setCreationTime(NOW)
+                        .setExpiryTime(NOW + ONE_HOUR)
+                        .build();
 
         assertEquals(token1, token2);
 
-        ODPAuthorizationToken token3 = new ODPAuthorizationToken.Builder()
-                .setOwnerIdentifier(OWNER_IDENTIFIER2)
-                .setAuthorizationToken(TOKEN)
-                .setCreationTime(NOW)
-                .setExpiryTime(NOW + ONE_HOUR).build();
+        ODPAuthorizationToken token3 =
+                new ODPAuthorizationToken.Builder()
+                        .setOwnerIdentifier(OWNER_IDENTIFIER2)
+                        .setAuthorizationToken(TOKEN)
+                        .setCreationTime(NOW)
+                        .setExpiryTime(NOW + ONE_HOUR)
+                        .build();
 
         assertNotEquals(token3, token1);
         assertNotEquals(token3, token2);
@@ -65,14 +70,14 @@ public class ODPAuthorizationTokenTest {
 
     @Test
     public void testBuildTwiceThrows() {
-        ODPAuthorizationToken.Builder builder = new ODPAuthorizationToken.Builder()
-                .setOwnerIdentifier(OWNER_IDENTIFIER)
-                .setAuthorizationToken(TOKEN)
-                .setCreationTime(NOW)
-                .setExpiryTime(NOW + ONE_HOUR);
+        ODPAuthorizationToken.Builder builder =
+                new ODPAuthorizationToken.Builder()
+                        .setOwnerIdentifier(OWNER_IDENTIFIER)
+                        .setAuthorizationToken(TOKEN)
+                        .setCreationTime(NOW)
+                        .setExpiryTime(NOW + ONE_HOUR);
         builder.build();
 
         assertThrows(IllegalStateException.class, () -> builder.build());
-
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoTest.java b/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
similarity index 51%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoTest.java
rename to tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
index 2e8ea351..36d94723 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
@@ -14,25 +14,28 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.data;
 
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
+import static com.android.odp.module.common.encryption.OdpEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 
+import android.annotation.Nullable;
 import android.content.Context;
 import android.database.DatabaseUtils;
 import android.database.sqlite.SQLiteDatabase;
+import android.database.sqlite.SQLiteException;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.FederatedComputeEncryptionColumns;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyContract;
 
 import org.junit.After;
 import org.junit.Before;
@@ -44,64 +47,62 @@ import java.util.Random;
 import java.util.UUID;
 
 @RunWith(AndroidJUnit4.class)
-public class FederatedComputeEncryptionKeyDaoTest {
+public class OdpEncryptionKeyDaoTest {
     private static final String KEY_ID = "0962201a-5abd-4e25-a486-2c7bd1ee1887";
     private static final String PUBLICKEY = "GOcMAnY4WkDYp6R3WSw8IpYK6eVe2RGZ9Z0OBb3EbjQ\\u003d";
-    private static final int KEY_TYPE = FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION;
+    private static final int KEY_TYPE = OdpEncryptionKey.KEY_TYPE_ENCRYPTION;
     private static final long NOW = 1698193647L;
     private static final long TTL = 100L;
 
-    private FederatedComputeEncryptionKeyDao mEncryptionKeyDao;
-    private Context mContext;
+    private OdpEncryptionKeyDao mEncryptionKeyDao;
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+    ;
 
+    private static final TestDbHelper sTestDbHelper = new TestDbHelper(sContext);
     private final Clock mClock = MonotonicClock.getInstance();
 
     @Before
     public void setUp() {
-        mContext = ApplicationProvider.getApplicationContext();
-        mEncryptionKeyDao = FederatedComputeEncryptionKeyDao.getInstanceForTest(mContext);
+        mEncryptionKeyDao = OdpEncryptionKeyDao.getInstance(sContext, sTestDbHelper);
     }
 
     @After
     public void cleanUp() throws Exception {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        sTestDbHelper.getWritableDatabase().close();
+        sTestDbHelper.getReadableDatabase().close();
+        sTestDbHelper.close();
     }
 
     @Test
     public void testInsertEncryptionKey_success() throws Exception {
-        FederatedComputeEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(3600);
-        FederatedComputeEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(3600);
+        OdpEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(3600);
+        OdpEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(3600);
 
         assertTrue(mEncryptionKeyDao.insertEncryptionKey(key1));
         assertTrue(mEncryptionKeyDao.insertEncryptionKey(key2));
 
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
-
+        SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
         assertThat(DatabaseUtils.queryNumEntries(db, ENCRYPTION_KEY_TABLE)).isEqualTo(2);
     }
 
     @Test
     public void testInsertDuplicateEncryptionKey_success() {
-        FederatedComputeEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(3600);
+        OdpEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(3600);
 
         assertTrue(mEncryptionKeyDao.insertEncryptionKey(key1));
 
-        FederatedComputeEncryptionKey key2 =
-                new FederatedComputeEncryptionKey.Builder()
+        OdpEncryptionKey key2 =
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier(key1.getKeyIdentifier())
                         .setPublicKey(key1.getPublicKey())
                         .setKeyType(key1.getKeyType())
                         .setCreationTime(key1.getCreationTime())
-                        .setExpiryTime(key1.getExpiryTime() + 10000L).build();
+                        .setExpiryTime(key1.getExpiryTime() + 10000L)
+                        .build();
 
         assertTrue(mEncryptionKeyDao.insertEncryptionKey(key2));
 
-        List<FederatedComputeEncryptionKey> keyList = mEncryptionKeyDao
-                .getLatestExpiryNKeys(2);
+        List<OdpEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(2);
 
         assertThat(keyList.size()).isEqualTo(1);
         assertThat(keyList.get(0)).isEqualTo(key2);
@@ -109,44 +110,46 @@ public class FederatedComputeEncryptionKeyDaoTest {
 
     @Test
     public void testInsertNullPublicKeyFieldThrows() {
-        assertThrows(NullPointerException.class, () -> insertNullFieldEncryptionKey());
+        assertThrows(NullPointerException.class, this::insertNullFieldEncryptionKey);
     }
 
     @Test
     public void testQueryKeys_success() {
-        List<FederatedComputeEncryptionKey> keyList0 =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
-                        "" /* selection= */, new String[0] /* selectionArgs= */,
-                        "" /* orderBy= */, 5);
+        List<OdpEncryptionKey> keyList0 =
+                mEncryptionKeyDao.readEncryptionKeysFromDatabase(
+                        ""
+                        /* selection= */ ,
+                        new String[0]
+                        /* selectionArgs= */ ,
+                        ""
+                        /* orderBy= */ ,
+                        5);
 
         assertThat(keyList0.size()).isEqualTo(0);
 
-        FederatedComputeEncryptionKey key1 = createFixedPublicKey();
+        OdpEncryptionKey key1 = createFixedPublicKey();
         mEncryptionKeyDao.insertEncryptionKey(key1);
 
-        List<FederatedComputeEncryptionKey> keyList1 =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
-                        "" /* selection= */,
-                        new String[0] /* selectionArgs= */,
-                        FederatedComputeEncryptionColumns.EXPIRY_TIME + " DESC",
+        List<OdpEncryptionKey> keyList1 =
+                mEncryptionKeyDao.readEncryptionKeysFromDatabase(
+                        ""
+                        /* selection= */ ,
+                        new String[0]
+                        /* selectionArgs= */ ,
+                        OdpEncryptionKeyContract.OdpEncryptionColumns.EXPIRY_TIME + " DESC",
                         1);
 
         assertThat(keyList1.get(0)).isEqualTo(key1);
 
         // with selection args
-        String selection =
-                FederatedComputeEncryptionKeyContract.FederatedComputeEncryptionColumns
-                                .KEY_IDENTIFIER
-                        + " = ? ";
+        String selection = OdpEncryptionKeyContract.OdpEncryptionColumns.KEY_IDENTIFIER + " = ? ";
         String[] selectionArgs = {KEY_ID};
 
-        List<FederatedComputeEncryptionKey> keyList2 =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
+        List<OdpEncryptionKey> keyList2 =
+                mEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         selection,
                         selectionArgs,
-                        FederatedComputeEncryptionKeyContract.FederatedComputeEncryptionColumns
-                                        .EXPIRY_TIME
-                                + " DESC",
+                        OdpEncryptionKeyContract.OdpEncryptionColumns.EXPIRY_TIME + " DESC",
                         1);
 
         assertThat(keyList2.size()).isEqualTo(1);
@@ -155,14 +158,14 @@ public class FederatedComputeEncryptionKeyDaoTest {
 
     @Test
     public void findExpiryKeys_success() {
-        FederatedComputeEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(1000000L);
-        FederatedComputeEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(2000000L);
-        FederatedComputeEncryptionKey key3 = createRandomPublicKeyWithConstantTTL(3000000L);
+        OdpEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(1000000L);
+        OdpEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(2000000L);
+        OdpEncryptionKey key3 = createRandomPublicKeyWithConstantTTL(3000000L);
         mEncryptionKeyDao.insertEncryptionKey(key1);
         mEncryptionKeyDao.insertEncryptionKey(key2);
         mEncryptionKeyDao.insertEncryptionKey(key3);
 
-        List<FederatedComputeEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
+        List<OdpEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
 
         assertThat(keyList.size()).isEqualTo(3);
         assertThat(keyList.get(0)).isEqualTo(key3);
@@ -171,39 +174,39 @@ public class FederatedComputeEncryptionKeyDaoTest {
     }
 
     @Test
-    public void findExpiryKeysWithlimit_success() {
-        FederatedComputeEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(1000000L);
-        FederatedComputeEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(2000000L);
-        FederatedComputeEncryptionKey key3 = createRandomPublicKeyWithConstantTTL(3000000L);
+    public void findExpiryKeysWithLimit_success() {
+        OdpEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(1000000L);
+        OdpEncryptionKey key2 = createRandomPublicKeyWithConstantTTL(2000000L);
+        OdpEncryptionKey key3 = createRandomPublicKeyWithConstantTTL(3000000L);
         mEncryptionKeyDao.insertEncryptionKey(key1);
         mEncryptionKeyDao.insertEncryptionKey(key2);
         mEncryptionKeyDao.insertEncryptionKey(key3);
 
-        List<FederatedComputeEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(2);
+        List<OdpEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(2);
 
         assertThat(keyList.size()).isEqualTo(2);
         assertThat(keyList.get(0)).isEqualTo(key3);
         assertThat(keyList.get(1)).isEqualTo(key2);
 
         // limit = 0
-        List<FederatedComputeEncryptionKey> keyList0 = mEncryptionKeyDao.getLatestExpiryNKeys(0);
+        List<OdpEncryptionKey> keyList0 = mEncryptionKeyDao.getLatestExpiryNKeys(0);
         assertThat(keyList0.size()).isEqualTo(0);
     }
 
     @Test
     public void findExpiryKeys_empty_success() {
-        List<FederatedComputeEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
+        List<OdpEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
 
         assertThat(keyList.size()).isEqualTo(0);
 
-        List<FederatedComputeEncryptionKey> keyList0 = mEncryptionKeyDao.getLatestExpiryNKeys(0);
+        List<OdpEncryptionKey> keyList0 = mEncryptionKeyDao.getLatestExpiryNKeys(0);
 
         assertThat(keyList0.size()).isEqualTo(0);
     }
 
     @Test
     public void deleteExpiredKeys_success() throws Exception {
-        FederatedComputeEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(0);
+        OdpEncryptionKey key1 = createRandomPublicKeyWithConstantTTL(0);
         mEncryptionKeyDao.insertEncryptionKey(key1);
 
         int deletedRows = mEncryptionKeyDao.deleteExpiredKeys();
@@ -211,7 +214,7 @@ public class FederatedComputeEncryptionKeyDaoTest {
         assertThat(deletedRows).isEqualTo(1);
 
         // check current number of rows
-        List<FederatedComputeEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
+        List<OdpEncryptionKey> keyList = mEncryptionKeyDao.getLatestExpiryNKeys(3);
 
         assertThat(keyList.size()).isEqualTo(0);
     }
@@ -223,10 +226,10 @@ public class FederatedComputeEncryptionKeyDaoTest {
     }
 
     private void insertNullFieldEncryptionKey() throws Exception {
-        FederatedComputeEncryptionKey key1 =
-                new FederatedComputeEncryptionKey.Builder()
+        OdpEncryptionKey key1 =
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier(UUID.randomUUID().toString())
-                        .setKeyType(FederatedComputeEncryptionKey.KEY_TYPE_UNDEFINED)
+                        .setKeyType(OdpEncryptionKey.KEY_TYPE_UNDEFINED)
                         .setCreationTime(mClock.currentTimeMillis())
                         .setExpiryTime(mClock.currentTimeMillis() + TTL)
                         .build();
@@ -234,21 +237,21 @@ public class FederatedComputeEncryptionKeyDaoTest {
         mEncryptionKeyDao.insertEncryptionKey(key1);
     }
 
-    private FederatedComputeEncryptionKey createRandomPublicKeyWithConstantTTL(long ttl) {
+    private OdpEncryptionKey createRandomPublicKeyWithConstantTTL(long ttl) {
         byte[] bytes = new byte[32];
         Random generator = new Random();
         generator.nextBytes(bytes);
-        return new FederatedComputeEncryptionKey.Builder()
+        return new OdpEncryptionKey.Builder()
                 .setKeyIdentifier(UUID.randomUUID().toString())
                 .setPublicKey(new String(bytes, 0, bytes.length))
-                .setKeyType(FederatedComputeEncryptionKey.KEY_TYPE_UNDEFINED)
+                .setKeyType(OdpEncryptionKey.KEY_TYPE_UNDEFINED)
                 .setCreationTime(mClock.currentTimeMillis())
                 .setExpiryTime(mClock.currentTimeMillis() + ttl)
                 .build();
     }
 
-    private FederatedComputeEncryptionKey createFixedPublicKey() {
-        return new FederatedComputeEncryptionKey.Builder()
+    private static OdpEncryptionKey createFixedPublicKey() {
+        return new OdpEncryptionKey.Builder()
                 .setKeyIdentifier(KEY_ID)
                 .setPublicKey(PUBLICKEY)
                 .setKeyType(KEY_TYPE)
@@ -256,4 +259,49 @@ public class FederatedComputeEncryptionKeyDaoTest {
                 .setExpiryTime(NOW + TTL)
                 .build();
     }
+
+    /**
+     * Helper class that provides a {@link OdpSQLiteOpenHelper} for tests.
+     *
+     * <p>Creates the encryption and authorization tables.
+     */
+    public static final class TestDbHelper extends OdpSQLiteOpenHelper {
+        private static final int DB_VERSION = 1;
+
+        public TestDbHelper(Context context) {
+            // Setting name = null, to allow for in memory DB.
+            super(context, /* name= */ null, /* factory= */ null, DB_VERSION);
+        }
+
+        @Override
+        public void onCreate(SQLiteDatabase db) {
+            db.execSQL(OdpEncryptionKeyContract.CREATE_ENCRYPTION_KEY_TABLE);
+            db.execSQL(ODPAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
+        }
+
+        @Override
+        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
+            // No-op for test
+        }
+
+        @Override
+        @Nullable
+        public SQLiteDatabase safeGetReadableDatabase() {
+            try {
+                return super.getReadableDatabase();
+            } catch (SQLiteException e) {
+                return null;
+            }
+        }
+
+        @Override
+        @Nullable
+        public SQLiteDatabase safeGetWritableDatabase() {
+            try {
+                return super.getWritableDatabase();
+            } catch (SQLiteException e) {
+                return null;
+            }
+        }
+    }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeKeyFetchManagerTest.java b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
similarity index 58%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeKeyFetchManagerTest.java
rename to tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
index 8a1ca012..2bc071e3 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeKeyFetchManagerTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption;
+package com.android.odp.module.common.encryption;
 
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION;
+import static com.android.odp.module.common.encryption.OdpEncryptionKey.KEY_TYPE_ENCRYPTION;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -26,41 +26,47 @@ import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.verifyZeroInteractions;
 
 import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.federatedcompute.services.common.FederatedComputeExecutors;
-import com.android.federatedcompute.services.common.Flags;
-import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyDao;
 import com.android.odp.module.common.Clock;
-import com.android.odp.module.common.HttpClient;
+import com.android.odp.module.common.EventLogger;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.OdpHttpResponse;
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+import com.android.odp.module.common.data.OdpEncryptionKeyDaoTest;
+import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.OdpHttpResponse;
 
 import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
 
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
 
 import java.util.Collections;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
+import java.util.Optional;
 import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeUnit;
 import java.util.stream.Collectors;
 
 @RunWith(AndroidJUnit4.class)
-public class FederatedComputeKeyFetchManagerTest {
+public class OdpEncryptionKeyManagerTest {
+
+    private static final String DEFAULT_OVERRIDE_URL =
+            "https://real-coordinator/v1alpha/publicKeys";
 
     private static final Map<String, List<String>> SAMPLE_RESPONSE_HEADER =
             Map.of(
@@ -73,42 +79,52 @@ public class FederatedComputeKeyFetchManagerTest {
 { "keys": [{ "id": "0cc9b4c9-08bd", "key": "BQo+c1Tw6TaQ+VH/b+9PegZOjHuKAFkl8QdmS0IjRj8" """
                     + "} ] }";
 
-    private FederatedComputeEncryptionKeyManager mFederatedComputeEncryptionKeyManager;
+    private OdpEncryptionKeyManager mOdpEncryptionKeyManager;
 
     @Mock private HttpClient mMockHttpClient;
 
-    private FederatedComputeEncryptionKeyDao mEncryptionKeyDao;
+    @Mock private EventLogger mMockTrainingEventLogger;
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private static final Clock sClock = MonotonicClock.getInstance();
 
-    private Context mContext;
+    private static final TestKeyManagerConfig sKeyManagerConfig =
+            new TestKeyManagerConfig(DEFAULT_OVERRIDE_URL);
+    ;
+    private static final OdpEncryptionKeyDaoTest.TestDbHelper sTestDbHelper =
+            new OdpEncryptionKeyDaoTest.TestDbHelper(sContext);
+    ;
 
-    private Clock mClock;
+    private static final OdpEncryptionKeyDao sEncryptionKeyDao =
+            OdpEncryptionKeyDao.getInstance(sContext, sTestDbHelper);
 
-    private Flags mMockFlags;
+    private static final ListeningExecutorService sTestExecutor =
+            MoreExecutors.newDirectExecutorService();
 
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
-        mContext = ApplicationProvider.getApplicationContext();
-        mClock = MonotonicClock.getInstance();
-        mEncryptionKeyDao = FederatedComputeEncryptionKeyDao.getInstanceForTest(mContext);
-        mMockFlags = Mockito.mock(Flags.class);
-        mFederatedComputeEncryptionKeyManager =
-                new FederatedComputeEncryptionKeyManager(
-                        mClock,
-                        mEncryptionKeyDao,
-                        mMockFlags,
+
+        sKeyManagerConfig.mEncryptionFetchUrl = DEFAULT_OVERRIDE_URL;
+        mOdpEncryptionKeyManager =
+                OdpEncryptionKeyManager.getInstanceForTesting(
+                        sClock,
+                        sEncryptionKeyDao,
+                        sKeyManagerConfig,
                         mMockHttpClient,
-                        FederatedComputeExecutors.getBackgroundExecutor());
-        String overrideUrl = "https://real-coordinator/v1alpha/publicKeys";
-        doReturn(overrideUrl).when(mMockFlags).getEncryptionKeyFetchUrl();
+                        sTestExecutor);
     }
 
     @After
-    public void teadDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+    public void tearDown() {
+        // Delete all existing keys in the DAO along with resetting the singleton instance
+        // to allow each test to start from a clean slate.
+        sEncryptionKeyDao.deleteAllKeys();
+        OdpEncryptionKeyManager.resetForTesting();
+        sTestDbHelper.getWritableDatabase().close();
+        sTestDbHelper.getReadableDatabase().close();
+        sTestDbHelper.close();
     }
 
     @Test
@@ -117,7 +133,7 @@ public class FederatedComputeKeyFetchManagerTest {
         headers.put("Cache-Control", List.of("public,max-age=3600"));
         headers.put("Age", List.of("8"));
 
-        long ttl = FederatedComputeEncryptionKeyManager.getTTL(headers);
+        long ttl = OdpEncryptionKeyManager.getTTL(headers);
 
         assertThat(ttl).isEqualTo(3600 - 8);
     }
@@ -127,7 +143,7 @@ public class FederatedComputeKeyFetchManagerTest {
         Map<String, List<String>> headers = new HashMap<>();
         headers.put("Age", List.of("8"));
 
-        long ttl = FederatedComputeEncryptionKeyManager.getTTL(headers);
+        long ttl = OdpEncryptionKeyManager.getTTL(headers);
 
         assertThat(ttl).isEqualTo(0);
     }
@@ -137,7 +153,7 @@ public class FederatedComputeKeyFetchManagerTest {
         Map<String, List<String>> headers = new HashMap<>();
         headers.put("Cache-Control", List.of("public,max-age=3600"));
 
-        long ttl = FederatedComputeEncryptionKeyManager.getTTL(headers);
+        long ttl = OdpEncryptionKeyManager.getTTL(headers);
 
         assertThat(ttl).isEqualTo(3600);
     }
@@ -146,7 +162,7 @@ public class FederatedComputeKeyFetchManagerTest {
     public void testGetTTL_empty() {
         Map<String, List<String>> headers = Collections.EMPTY_MAP;
 
-        long ttl = FederatedComputeEncryptionKeyManager.getTTL(headers);
+        long ttl = OdpEncryptionKeyManager.getTTL(headers);
 
         assertThat(ttl).isEqualTo(0);
     }
@@ -157,7 +173,7 @@ public class FederatedComputeKeyFetchManagerTest {
         headers.put("Cache-Control", List.of("public,max-age==3600"));
         headers.put("Age", List.of("8"));
 
-        long ttl = FederatedComputeEncryptionKeyManager.getTTL(headers);
+        long ttl = OdpEncryptionKeyManager.getTTL(headers);
 
         assertThat(ttl).isEqualTo(0);
     }
@@ -174,11 +190,11 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        List<FederatedComputeEncryptionKey> keys =
-                mFederatedComputeEncryptionKeyManager
-                        .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
-                        .get();
+        List<OdpEncryptionKey> keys = mOdpEncryptionKeyManager.fetchAndPersistActiveKeys(
+                KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
+                Optional.of(mMockTrainingEventLogger)).get();
 
+        verifyZeroInteractions(mMockTrainingEventLogger);
         assertThat(keys.size()).isGreaterThan(0);
     }
 
@@ -194,48 +210,57 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        List<FederatedComputeEncryptionKey> keys =
-                mFederatedComputeEncryptionKeyManager
-                        .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false)
-                        .get();
+        List<OdpEncryptionKey> keys = mOdpEncryptionKeyManager.fetchAndPersistActiveKeys(
+                KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
+                Optional.of(mMockTrainingEventLogger)).get();
 
+        verifyZeroInteractions(mMockTrainingEventLogger);
         assertThat(keys.size()).isGreaterThan(0);
     }
 
     @Test
     public void testFetchAndPersistActiveKeys_EmptyUrl_throws() {
-        doReturn("").when(mMockFlags).getEncryptionKeyFetchUrl();
+        sKeyManagerConfig.mEncryptionFetchUrl = "";
         assertThrows(
                 ExecutionException.class,
                 () ->
-                        mFederatedComputeEncryptionKeyManager
+                        mOdpEncryptionKeyManager
                                 .fetchAndPersistActiveKeys(
-                                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
+                                        KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob= */ true,
+                                        Optional.of(mMockTrainingEventLogger))
                                 .get());
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchRequestFailEventKind();
     }
 
     @Test
     public void testFetchAndPersistActiveKeys_NullUrl_throws() {
-        doReturn(null).when(mMockFlags).getEncryptionKeyFetchUrl();
+        sKeyManagerConfig.mEncryptionFetchUrl = null;
         assertThrows(
                 ExecutionException.class,
                 () ->
-                        mFederatedComputeEncryptionKeyManager
+                        mOdpEncryptionKeyManager
                                 .fetchAndPersistActiveKeys(
-                                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
+                                        KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob= */ true,
+                                        Optional.of(mMockTrainingEventLogger))
                                 .get());
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchEmptyUriEventKind();
     }
 
     @Test
     public void testFetchAndPersistActiveKeys_InvalidUrl_throws() {
-        doReturn("1").when(mMockFlags).getEncryptionKeyFetchUrl();
+        sKeyManagerConfig.mEncryptionFetchUrl = "1";
         assertThrows(
                 ExecutionException.class,
                 () ->
-                        mFederatedComputeEncryptionKeyManager
+                        mOdpEncryptionKeyManager
                                 .fetchAndPersistActiveKeys(
-                                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
+                                        KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob= */ true,
+                                        Optional.of(mMockTrainingEventLogger))
                                 .get());
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchRequestFailEventKind();
     }
 
     @Test
@@ -251,10 +276,13 @@ public class FederatedComputeKeyFetchManagerTest {
         assertThrows(
                 ExecutionException.class,
                 () ->
-                        mFederatedComputeEncryptionKeyManager
+                        mOdpEncryptionKeyManager
                                 .fetchAndPersistActiveKeys(
-                                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
+                                        KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob= */ true,
+                                        Optional.of(mMockTrainingEventLogger))
                                 .get());
+        verifyZeroInteractions(mMockTrainingEventLogger);
     }
 
     @Test
@@ -270,10 +298,13 @@ public class FederatedComputeKeyFetchManagerTest {
         assertThrows(
                 ExecutionException.class,
                 () ->
-                        mFederatedComputeEncryptionKeyManager
+                        mOdpEncryptionKeyManager
                                 .fetchAndPersistActiveKeys(
-                                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false)
+                                        KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob= */ false,
+                                        Optional.of(mMockTrainingEventLogger))
                                 .get());
+        verifyZeroInteractions(mMockTrainingEventLogger);
     }
 
     @Test
@@ -288,11 +319,12 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        mFederatedComputeEncryptionKeyManager
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
-                .get();
-        List<FederatedComputeEncryptionKey> keys =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
+        mOdpEncryptionKeyManager
+                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
+                        Optional.of(mMockTrainingEventLogger)).get();
+        verifyZeroInteractions(mMockTrainingEventLogger);
+        List<OdpEncryptionKey> keys =
+                sEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         ""
                         /* selection= */ ,
                         new String[0]
@@ -300,12 +332,12 @@ public class FederatedComputeKeyFetchManagerTest {
                         ""
                         /* orderBy= */ ,
                         -1
-                        /* count= */);
+                        /* count= */ );
 
         assertThat(keys.size()).isEqualTo(1);
         assertThat(
                         keys.stream()
-                                .map(FederatedComputeEncryptionKey::getKeyIdentifier)
+                                .map(OdpEncryptionKey::getKeyIdentifier)
                                 .collect(Collectors.toList()))
                 .containsAtLeastElementsIn(List.of("0cc9b4c9-08bd"));
     }
@@ -322,11 +354,13 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        mFederatedComputeEncryptionKeyManager
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false)
-                .get();
-        List<FederatedComputeEncryptionKey> keys =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
+        mOdpEncryptionKeyManager
+                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
+                        Optional.of(mMockTrainingEventLogger)).get();
+        verifyZeroInteractions(mMockTrainingEventLogger);
+
+        List<OdpEncryptionKey> keys =
+                sEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         ""
                         /* selection= */ ,
                         new String[0]
@@ -334,12 +368,12 @@ public class FederatedComputeKeyFetchManagerTest {
                         ""
                         /* orderBy= */ ,
                         -1
-                        /* count= */);
+                        /* count= */ );
 
         assertThat(keys.size()).isEqualTo(1);
         assertThat(
                         keys.stream()
-                                .map(FederatedComputeEncryptionKey::getKeyIdentifier)
+                                .map(OdpEncryptionKey::getKeyIdentifier)
                                 .collect(Collectors.toList()))
                 .containsAtLeastElementsIn(List.of("0cc9b4c9-08bd"));
     }
@@ -355,9 +389,9 @@ public class FederatedComputeKeyFetchManagerTest {
                                         .build()))
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
-        long currentTime = mClock.currentTimeMillis();
-        mEncryptionKeyDao.insertEncryptionKey(
-                new FederatedComputeEncryptionKey.Builder()
+        long currentTime = sClock.currentTimeMillis();
+        sEncryptionKeyDao.insertEncryptionKey(
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier("5161e286-63e5")
                         .setPublicKey("YuOorP14obQLqASrvqbkNxyijjcAUIDx/xeMGZOyykc")
                         .setKeyType(KEY_TYPE_ENCRYPTION)
@@ -365,12 +399,13 @@ public class FederatedComputeKeyFetchManagerTest {
                         .setExpiryTime(currentTime)
                         .build());
 
-        mFederatedComputeEncryptionKeyManager
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true)
-                .get();
+        mOdpEncryptionKeyManager
+                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
+                        Optional.of(mMockTrainingEventLogger)).get();
+        verifyZeroInteractions(mMockTrainingEventLogger);
 
-        List<FederatedComputeEncryptionKey> keys =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
+        List<OdpEncryptionKey> keys =
+                sEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         ""
                         /* selection= */ ,
                         new String[0]
@@ -378,7 +413,7 @@ public class FederatedComputeKeyFetchManagerTest {
                         ""
                         /* orderBy= */ ,
                         -1
-                        /* count= */);
+                        /* count= */ );
 
         assertThat(keys.size()).isEqualTo(1);
     }
@@ -394,9 +429,9 @@ public class FederatedComputeKeyFetchManagerTest {
                                         .build()))
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
-        long currentTime = mClock.currentTimeMillis();
-        mEncryptionKeyDao.insertEncryptionKey(
-                new FederatedComputeEncryptionKey.Builder()
+        long currentTime = sClock.currentTimeMillis();
+        sEncryptionKeyDao.insertEncryptionKey(
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier("5161e286-63e5")
                         .setPublicKey("YuOorP14obQLqASrvqbkNxyijjcAUIDx/xeMGZOyykc")
                         .setKeyType(KEY_TYPE_ENCRYPTION)
@@ -404,12 +439,13 @@ public class FederatedComputeKeyFetchManagerTest {
                         .setExpiryTime(currentTime)
                         .build());
 
-        mFederatedComputeEncryptionKeyManager
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false)
-                .get();
+        mOdpEncryptionKeyManager.fetchAndPersistActiveKeys(
+                KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
+                Optional.of(mMockTrainingEventLogger)).get();
+        verifyZeroInteractions(mMockTrainingEventLogger);
 
-        List<FederatedComputeEncryptionKey> keys =
-                mEncryptionKeyDao.readFederatedComputeEncryptionKeysFromDatabase(
+        List<OdpEncryptionKey> keys =
+                sEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         ""
                         /* selection= */ ,
                         new String[0]
@@ -417,11 +453,11 @@ public class FederatedComputeKeyFetchManagerTest {
                         ""
                         /* orderBy= */ ,
                         -1
-                        /* count= */);
+                        /* count= */ );
 
         assertThat(keys.size()).isEqualTo(2);
 
-        List<FederatedComputeEncryptionKey> activeKeys = mEncryptionKeyDao.getLatestExpiryNKeys(2);
+        List<OdpEncryptionKey> activeKeys = sEncryptionKeyDao.getLatestExpiryNKeys(2);
         assertThat(activeKeys.size()).isEqualTo(1);
     }
 
@@ -437,19 +473,21 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        List<FederatedComputeEncryptionKey> keys =
-                mFederatedComputeEncryptionKeyManager.getOrFetchActiveKeys(
-                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2);
+        List<OdpEncryptionKey> keys =
+                mOdpEncryptionKeyManager.getOrFetchActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2,
+                        Optional.of(mMockTrainingEventLogger));
 
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchStartEventKind();
         verify(mMockHttpClient, times(1)).performRequestAsyncWithRetry(any());
         assertThat(keys.size()).isEqualTo(1);
     }
 
     @Test
     public void testGetOrFetchActiveKeys_noFetch() {
-        long currentTime = mClock.currentTimeMillis();
-        mEncryptionKeyDao.insertEncryptionKey(
-                new FederatedComputeEncryptionKey.Builder()
+        long currentTime = sClock.currentTimeMillis();
+        sEncryptionKeyDao.insertEncryptionKey(
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier("5161e286-63e5")
                         .setPublicKey("YuOorP14obQLqASrvqbkNxyijjcAUIDx/xeMGZOyykc")
                         .setKeyType(KEY_TYPE_ENCRYPTION)
@@ -466,10 +504,12 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        List<FederatedComputeEncryptionKey> keys =
-                mFederatedComputeEncryptionKeyManager.getOrFetchActiveKeys(
-                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2);
+        List<OdpEncryptionKey> keys =
+                mOdpEncryptionKeyManager.getOrFetchActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2,
+                        Optional.of(mMockTrainingEventLogger));
 
+        verifyZeroInteractions(mMockTrainingEventLogger);
         verify(mMockHttpClient, never()).performRequestAsyncWithRetry(any());
         assertThat(keys.size()).isEqualTo(1);
     }
@@ -480,11 +520,58 @@ public class FederatedComputeKeyFetchManagerTest {
                 .when(mMockHttpClient)
                 .performRequestAsyncWithRetry(any());
 
-        List<FederatedComputeEncryptionKey> keys =
-                mFederatedComputeEncryptionKeyManager.getOrFetchActiveKeys(
-                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2);
+        List<OdpEncryptionKey> keys =
+                mOdpEncryptionKeyManager.getOrFetchActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* keyCount= */ 2,
+                        Optional.of(mMockTrainingEventLogger));
 
-        assertThat(keys.size()).isEqualTo(0);
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchStartEventKind();
+        verify(mMockTrainingEventLogger, times(1)).logEncryptionKeyFetchFailEventKind();
         verify(mMockHttpClient, times(1)).performRequestAsyncWithRetry(any());
+        assertThat(keys.size()).isEqualTo(0);
+    }
+
+    private static final class TestKeyManagerConfig
+            implements OdpEncryptionKeyManager.KeyManagerConfig {
+
+        // Url to be configured by the tests
+        private volatile String mEncryptionFetchUrl;
+
+        private TestKeyManagerConfig(String encryptionFetchUrl) {
+            this.mEncryptionFetchUrl = encryptionFetchUrl;
+        }
+
+        @Override
+        public String getEncryptionKeyFetchUrl() {
+            return mEncryptionFetchUrl;
+        }
+
+        @Override
+        public int getHttpRequestRetryLimit() {
+            // Just some default value, not used by tests as the mock http client is used instead.
+            return 3;
+        }
+
+        /** Max age in seconds for federated compute encryption keys. */
+        public long getEncryptionKeyMaxAgeSeconds() {
+            // FC default value
+            return TimeUnit.DAYS.toSeconds(14/* duration= */ );
+        }
+
+        /** The {@link OdpSQLiteOpenHelper} instance for use by the encryption DAO. */
+        public OdpSQLiteOpenHelper getSQLiteOpenHelper() {
+            // Should not be used in tests as the TestDbHelper is used instead and injected directly
+            // into the EncryptionKeyDao.
+            return null;
+        }
+
+        /** Background executor for use in key fetch and DB updates etc. */
+        public ListeningExecutorService getBackgroundExecutor() {
+            return sTestExecutor;
+        }
+
+        public ListeningExecutorService getBlockingExecutor() {
+            return sTestExecutor;
+        }
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyTest.java b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyTest.java
similarity index 67%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyTest.java
rename to tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyTest.java
index be9785cb..dbe31938 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.data;
+package com.android.odp.module.common.encryption;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
@@ -25,14 +25,13 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
-
 @RunWith(AndroidJUnit4.class)
-public class FederatedComputeEncryptionKeyTest {
+public class OdpEncryptionKeyTest {
 
     private static final String KEY_ID = "0962201a-5abd-4e25-a486-2c7bd1ee1887";
     private static final String PUBLIC_KEY = "GOcMAnY4WkDYp6R3WSw8IpYK6eVe2RGZ9Z0OBb3EbjQ\\u003d";
 
-    private static final int KEY_TYPE = FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION;
+    private static final int KEY_TYPE = OdpEncryptionKey.KEY_TYPE_ENCRYPTION;
 
     private static final long NOW = 1698193647L;
 
@@ -40,13 +39,11 @@ public class FederatedComputeEncryptionKeyTest {
 
     @Test
     public void testBuilderAndEquals() {
-        FederatedComputeEncryptionKey key1 =
-                new FederatedComputeEncryptionKey.Builder(
-                                KEY_ID, PUBLIC_KEY, KEY_TYPE, NOW, NOW + TTL)
-                        .build();
+        OdpEncryptionKey key1 =
+                new OdpEncryptionKey.Builder(KEY_ID, PUBLIC_KEY, KEY_TYPE, NOW, NOW + TTL).build();
 
-        FederatedComputeEncryptionKey key2 =
-                new FederatedComputeEncryptionKey.Builder()
+        OdpEncryptionKey key2 =
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier(KEY_ID)
                         .setPublicKey(PUBLIC_KEY)
                         .setKeyType(KEY_TYPE)
@@ -56,11 +53,11 @@ public class FederatedComputeEncryptionKeyTest {
 
         assertEquals(key1, key2);
 
-        FederatedComputeEncryptionKey key3 =
-                new FederatedComputeEncryptionKey.Builder()
+        OdpEncryptionKey key3 =
+                new OdpEncryptionKey.Builder()
                         .setKeyIdentifier(KEY_ID)
                         .setPublicKey(PUBLIC_KEY)
-                        .setKeyType(FederatedComputeEncryptionKey.KEY_TYPE_UNDEFINED)
+                        .setKeyType(OdpEncryptionKey.KEY_TYPE_UNDEFINED)
                         .setCreationTime(NOW)
                         .setExpiryTime(NOW + TTL)
                         .build();
@@ -71,9 +68,8 @@ public class FederatedComputeEncryptionKeyTest {
 
     @Test
     public void testBuildTwiceThrows() {
-        FederatedComputeEncryptionKey.Builder builder =
-                new FederatedComputeEncryptionKey.Builder(
-                        KEY_ID, PUBLIC_KEY, KEY_TYPE, NOW, NOW + TTL);
+        OdpEncryptionKey.Builder builder =
+                new OdpEncryptionKey.Builder(KEY_ID, PUBLIC_KEY, KEY_TYPE, NOW, NOW + TTL);
         builder.build();
 
         assertThrows(IllegalStateException.class, () -> builder.build());
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/jni/HpkeJniTest.java b/tests/commontests/src/com/android/odp/module/common/encryption/jni/HpkeJniTest.java
similarity index 90%
rename from tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/jni/HpkeJniTest.java
rename to tests/commontests/src/com/android/odp/module/common/encryption/jni/HpkeJniTest.java
index 2cd2d282..4744c487 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/jni/HpkeJniTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/encryption/jni/HpkeJniTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.federatedcompute.services.encryption.jni;
+package com.android.odp.module.common.encryption.jni;
 
 import org.junit.Assert;
 import org.junit.Test;
@@ -24,8 +24,8 @@ import java.util.Base64;
 public class HpkeJniTest {
     private static final byte[] sAssociatedData = "associated_data".getBytes();
     private static final byte[] sPlaintext = "plaintext".getBytes();
-    private static final byte[] sCiphertext = decode(
-            "0Ie+jDZ/Hznx1IrIkS06V+kAHuD5RsybXWwrKRIbGEL5TJT4/HYny2SHfWbeXxMydwvS0FEZqvzs");
+    private static final byte[] sCiphertext =
+            decode("0Ie+jDZ/Hznx1IrIkS06V+kAHuD5RsybXWwrKRIbGEL5TJT4/HYny2SHfWbeXxMydwvS0FEZqvzs");
 
     private static final String PUBLIC_KEY_BASE64 = "rSJBSUYG0ebvfW1AXCWO0CMGMJhDzpfQm3eLyw1uxX8=";
     private static final String PRIVATE_KEY_BASE64 = "f86EzLmGaVmc+PwjJk5ADPE4ijQvliWf0CQyY/Zyy7I=";
@@ -82,7 +82,7 @@ public class HpkeJniTest {
 
     @Test
     public void testHpkeEncrypt_plainTextNull_fail() {
-        final byte[] result = HpkeJni.encrypt(sPublicKey, /* plainText = */ null, sAssociatedData);
+        final byte[] result = HpkeJni.encrypt(sPublicKey, /* plainText= */ null, sAssociatedData);
         Assert.assertNull(result);
     }
 
@@ -96,7 +96,7 @@ public class HpkeJniTest {
 
     @Test
     public void testHpkeEncrypt_associatedDataNull_fail() {
-        final byte[] result = HpkeJni.encrypt(sPublicKey, sPlaintext, /* associatedData = */ null);
+        final byte[] result = HpkeJni.encrypt(sPublicKey, sPlaintext, /* associatedData= */ null);
         Assert.assertNull(result);
     }
 
@@ -137,8 +137,7 @@ public class HpkeJniTest {
 
     @Test
     public void testHpkeDecrypt_ciphertextNull_fail() {
-        final byte[] result =
-                HpkeJni.encrypt(sPrivateKey, /* ciphertext = */ null, sAssociatedData);
+        final byte[] result = HpkeJni.encrypt(sPrivateKey, /* ciphertext= */ null, sAssociatedData);
         Assert.assertNull(result);
     }
 
@@ -151,8 +150,7 @@ public class HpkeJniTest {
 
     @Test
     public void testHpkeDecrypt_associatedDataNull_fail() {
-        final byte[] result =
-                HpkeJni.decrypt(sPrivateKey, sCiphertext, /* associatedData = */ null);
+        final byte[] result = HpkeJni.decrypt(sPrivateKey, sCiphertext, /* associatedData= */ null);
         Assert.assertNull(result);
     }
 
diff --git a/tests/commontests/src/com/android/odp/module/common/HttpClientTest.java b/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
similarity index 99%
rename from tests/commontests/src/com/android/odp/module/common/HttpClientTest.java
rename to tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
index fc306841..b923c0a7 100644
--- a/tests/commontests/src/com/android/odp/module/common/HttpClientTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/commontests/src/com/android/odp/module/common/HttpClientUtilsTest.java b/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
similarity index 96%
rename from tests/commontests/src/com/android/odp/module/common/HttpClientUtilsTest.java
rename to tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
index d3e8d17c..af0c6986 100644
--- a/tests/commontests/src/com/android/odp/module/common/HttpClientUtilsTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -27,8 +27,8 @@ import static org.mockito.Mockito.when;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
-import com.android.odp.module.common.HttpClientUtils.HttpMethod;
-import com.android.odp.module.common.HttpClientUtils.HttpURLConnectionSupplier;
+import com.android.odp.module.common.http.HttpClientUtils.HttpMethod;
+import com.android.odp.module.common.http.HttpClientUtils.HttpURLConnectionSupplier;
 
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
diff --git a/tests/commontests/src/com/android/odp/module/common/OdpHttpRequestTest.java b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
similarity index 95%
rename from tests/commontests/src/com/android/odp/module/common/OdpHttpRequestTest.java
rename to tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
index bbb71c9f..efd20278 100644
--- a/tests/commontests/src/com/android/odp/module/common/OdpHttpRequestTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,10 +14,10 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
-import static com.android.odp.module.common.HttpClientUtils.ACCEPT_ENCODING_HDR;
-import static com.android.odp.module.common.HttpClientUtils.GZIP_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.ACCEPT_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_HDR;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/commontests/src/com/android/odp/module/common/OdpHttpResponseTest.java b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpResponseTest.java
similarity index 94%
rename from tests/commontests/src/com/android/odp/module/common/OdpHttpResponseTest.java
rename to tests/commontests/src/com/android/odp/module/common/http/OdpHttpResponseTest.java
index cdccbd5e..fc8dc68b 100644
--- a/tests/commontests/src/com/android/odp/module/common/OdpHttpResponseTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpResponseTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.odp.module.common;
+package com.android.odp.module.common.http;
 
-import static com.android.odp.module.common.HttpClientUtils.OCTET_STREAM;
+import static com.android.odp.module.common.http.HttpClientUtils.OCTET_STREAM;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/cts/configtest/AndroidTest.xml b/tests/cts/configtest/AndroidTest.xml
index ef650bfa..18cacd5f 100644
--- a/tests/cts/configtest/AndroidTest.xml
+++ b/tests/cts/configtest/AndroidTest.xml
@@ -25,6 +25,19 @@
         <option name="test-file-name" value="CtsOnDevicePersonalizationConfigTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" /> <!-- Allow hidden API uses -->
         <option name="package" value="com.android.ondevicepersonalization.cts.configtest"/>
diff --git a/tests/cts/endtoend/AndroidTest.xml b/tests/cts/endtoend/AndroidTest.xml
index 5d312410..06ab578d 100644
--- a/tests/cts/endtoend/AndroidTest.xml
+++ b/tests/cts/endtoend/AndroidTest.xml
@@ -33,10 +33,22 @@
         <option name="run-command" value="device_config put on_device_personalization federated_compute_kill_switch false" />
         <option name="run-command" value="device_config put on_device_personalization enable_personalization_status_override true"/>
         <option name="run-command" value="device_config put on_device_personalization personalization_status_override_value true"/>
+        <option name="run-command" value="device_config put on_device_personalization isolated_service_debugging_enabled true"/>
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
         <option name="teardown-command" value="device_config delete on_device_personalization global_kill_switch" />
         <option name="teardown-command" value="device_config delete on_device_personalization federated_compute_kill_switch" />
         <option name="teardown-command" value="device_config delete on_device_personalization enable_personalization_status_override" />
         <option name="teardown-command" value="device_config delete on_device_personalization personalization_status_override_value" />
+        <option name="teardown-command" value="device_config delete on_device_personalization isolated_service_debugging_enabled" />
         <option name="teardown-command" value="device_config set_sync_disabled_for_tests none" />
     </target_preparer>
 
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
index 03707d4d..2e0ccd62 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
@@ -15,7 +15,6 @@
  */
 package com.android.ondevicepersonalization.cts.e2e;
 
-
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertEquals;
@@ -44,6 +43,7 @@ import androidx.test.core.app.ApplicationProvider;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.compatibility.common.util.ShellUtils;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
@@ -51,19 +51,18 @@ import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
 import org.junit.After;
 import org.junit.Assume;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 
 import java.io.ByteArrayOutputStream;
 import java.io.InputStream;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.Executors;
 
 /** CTS Test cases for OnDevicePersonalizationManager APIs. */
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class CtsOdpManagerTests {
 
     private static final String SERVICE_PACKAGE =
@@ -77,26 +76,19 @@ public class CtsOdpManagerTests {
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(new Object[][] {{true}, {false}});
-    }
-
     @Before
     public void setUp() {
         // Skip the test if it runs on unsupported platforms.
         Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
 
         ShellUtils.runShellCommand(
                 "device_config put on_device_personalization "
                         + "shared_isolated_process_feature_enabled "
-                        + mIsSipFeatureEnabled);
+                        + SdkLevel.isAtLeastU());
         ShellUtils.runShellCommand(
                 "device_config put on_device_personalization "
                         + "debug.validate_rendering_config_keys "
@@ -258,7 +250,6 @@ public class CtsOdpManagerTests {
         assertThat(receiver.getException()).isInstanceOf(NameNotFoundException.class);
     }
 
-
     @Test
     public void testExecuteReturnsClassNotFoundIfServiceClassNotFound()
             throws InterruptedException {
@@ -336,6 +327,7 @@ public class CtsOdpManagerTests {
     }
 
     @Test
+    @Ignore("b/377212275")
     public void testExecuteWithOutputDataDisabled() throws InterruptedException {
         OnDevicePersonalizationManager manager =
                 mContext.getSystemService(OnDevicePersonalizationManager.class);
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
index 89a8ae68..93ab78af 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
@@ -31,6 +31,7 @@ import android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceRespon
 import android.adservices.ondevicepersonalization.ExecuteOutput;
 import android.adservices.ondevicepersonalization.FederatedComputeInput;
 import android.adservices.ondevicepersonalization.FederatedComputeScheduleRequest;
+import android.adservices.ondevicepersonalization.FederatedComputeScheduleResponse;
 import android.adservices.ondevicepersonalization.FederatedComputeScheduler;
 import android.adservices.ondevicepersonalization.IsolatedServiceException;
 import android.adservices.ondevicepersonalization.MeasurementWebTriggerEventParams;
@@ -55,7 +56,10 @@ import androidx.test.filters.SmallTest;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
+import org.junit.Assume;
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -78,6 +82,13 @@ public class DataClassesTest {
     private static final String SERVICE_CLASS =
             "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
 
+    @Before
+    public void setUp() {
+        // Skip the test if it runs on unsupported platforms.
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+    }
+
     /**
      * Test builder and getters for ExecuteOutput.
      */
@@ -223,6 +234,28 @@ public class DataClassesTest {
                 testSchedulingMode, request.getParams().getTrainingInterval().getSchedulingMode());
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_FCP_SCHEDULE_WITH_OUTCOME_RECEIVER_ENABLED)
+    public void testFederatedComputeSchedulerResponse() {
+        // Test for Data classes associated with FederatedComputeScheduler's schedule API.
+        String testPopulation = "testPopulation";
+        Duration testInterval = Duration.ofSeconds(5);
+        int testSchedulingMode = TrainingInterval.SCHEDULING_MODE_RECURRENT;
+        TrainingInterval testData =
+                new TrainingInterval.Builder()
+                        .setSchedulingMode(testSchedulingMode)
+                        .setMinimumInterval(testInterval)
+                        .build();
+
+        FederatedComputeScheduler.Params params = new FederatedComputeScheduler.Params(testData);
+        FederatedComputeScheduleRequest request =
+                new FederatedComputeScheduleRequest(params, testPopulation);
+
+        FederatedComputeScheduleResponse response = new FederatedComputeScheduleResponse(request);
+
+        assertEquals(response.getFederatedComputeScheduleRequest(), request);
+    }
+
     /** Test for RequestLogRecord class. */
     @Test
     public void testRequestLogRecord() {
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
index 8bbf2360..a8c846f6 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
@@ -29,6 +29,9 @@ import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
 import android.os.Bundle;
 
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+
+import org.junit.Assume;
 import org.junit.Before;
 import org.junit.Test;
 
@@ -40,6 +43,8 @@ public class InferenceInputTest {
 
     @Before
     public void setup() {
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
         mRemoteData =
                 new RemoteDataImpl(
                         IDataAccessService.Stub.asInterface(new TestDataAccessService()));
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
index 5abe6c3e..0e8388cb 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
@@ -16,18 +16,28 @@
 
 package com.android.ondevicepersonalization.cts.e2e;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static junit.framework.Assert.assertEquals;
-import static junit.framework.Assert.assertTrue;
 
 import android.adservices.ondevicepersonalization.InferenceOutput;
 
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+
+import org.junit.Assume;
+import org.junit.Before;
 import org.junit.Test;
 
-import java.util.Arrays;
 import java.util.HashMap;
 import java.util.Map;
 
 public class InferenceOutputTest {
+    @Before
+    public void setUp() {
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+    }
+
     @Test
     public void build_success() {
         HashMap<Integer, Object> outputData = new HashMap<>();
@@ -47,6 +57,6 @@ public class InferenceOutputTest {
         Map<Integer, Object> data = output.getDataOutputs();
         float[] value = (float[]) data.get(0);
 
-        assertTrue(Arrays.equals(value, expected));
+        assertThat(value).isEqualTo(expected);
     }
 }
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
index 560716f5..7ca41202 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
@@ -53,7 +53,10 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
+import org.junit.Assume;
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -72,6 +75,12 @@ public class IsolatedWorkerTest {
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
+    @Before
+    public void setUp() {
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+    }
+
     @Test
     public void testOnExecute() throws Exception {
         IsolatedWorker worker = new TestWorker();
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/OdpSystemEventManagerTests.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/OdpSystemEventManagerTests.java
index 81650aff..ad397622 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/OdpSystemEventManagerTests.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/OdpSystemEventManagerTests.java
@@ -46,6 +46,7 @@ public class OdpSystemEventManagerTests {
     public void setUp() throws Exception {
         // Skip the test if it runs on unsupported platforms.
         Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
     }
 
     @Test
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/RequestSurfacePackageTests.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/RequestSurfacePackageTests.java
index e010c628..df8b1a30 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/RequestSurfacePackageTests.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/RequestSurfacePackageTests.java
@@ -44,6 +44,7 @@ import androidx.test.uiautomator.UiDevice;
 import androidx.test.uiautomator.UiObject2;
 
 import com.android.compatibility.common.util.ShellUtils;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
@@ -54,11 +55,8 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 
-
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.ArrayBlockingQueue;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.Executors;
@@ -66,13 +64,10 @@ import java.util.concurrent.Executors;
 /**
  * CTS Test cases for OnDevicePersonalizationManager#requestSurfacePackage.
  */
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 @ScreenRecordRule.ScreenRecord
 public class RequestSurfacePackageTests {
 
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
     @Rule public final ScreenRecordRule sScreenRecordRule = new ScreenRecordRule();
 
     private static final String SERVICE_PACKAGE =
@@ -86,24 +81,18 @@ public class RequestSurfacePackageTests {
 
     private UiDevice mDevice;
 
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
+    private static final int DELAY_MILLIS = 2000;
 
     @Before
     public void setUp() {
         // Skip the test if it runs on unsupported platforms.
         Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
 
         ShellUtils.runShellCommand(
                 "device_config put on_device_personalization "
                         + "shared_isolated_process_feature_enabled "
-                        + mIsSipFeatureEnabled);
+                        + SdkLevel.isAtLeastU());
         ShellUtils.runShellCommand(
                 "device_config put on_device_personalization "
                         + "debug.validate_rendering_config_keys "
@@ -141,6 +130,10 @@ public class RequestSurfacePackageTests {
         OnDevicePersonalizationManager manager =
                 mContext.getSystemService(OnDevicePersonalizationManager.class);
         SurfacePackageToken token = runExecute(manager);
+
+        Log.i(TAG, "Finished getting token");
+        Thread.sleep(DELAY_MILLIS);
+
         var receiver = new ResultReceiver<SurfacePackage>();
         SurfaceView surfaceView = createSurfaceView();
         manager.requestSurfacePackage(
@@ -154,6 +147,9 @@ public class RequestSurfacePackageTests {
         SurfacePackage surfacePackage = receiver.getResult();
         assertNotNull(surfacePackage);
 
+        Log.i(TAG, "Finished requesting surface package");
+        Thread.sleep(DELAY_MILLIS);
+
         CountDownLatch latch = new CountDownLatch(1);
         new Handler(Looper.getMainLooper()).post(
                 () -> {
@@ -164,6 +160,9 @@ public class RequestSurfacePackageTests {
                 });
         latch.await();
 
+        Log.i(TAG, "Finished posting surface view");
+        Thread.sleep(DELAY_MILLIS);
+
         for (int i = 0; i < 5; i++) {
             try {
                 UiObject2 clickableLink =
@@ -344,6 +343,8 @@ public class RequestSurfacePackageTests {
                 params,
                 Executors.newSingleThreadExecutor(),
                 receiver);
+        assertNotNull(receiver.getResult());
+        assertNotNull(receiver.getResult().getSurfacePackageToken());
         return receiver.getResult().getSurfacePackageToken();
     }
 }
diff --git a/tests/federatedcomputetests/AndroidTest.xml b/tests/federatedcomputetests/AndroidTest.xml
index 481ab1e9..9d1b6e21 100644
--- a/tests/federatedcomputetests/AndroidTest.xml
+++ b/tests/federatedcomputetests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="FederatedComputeServicesTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" />
         <option name="package" value="com.android.ondevicepersonalization.federatedcomputetests"/>
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
index eebc003d..ee8a990d 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
@@ -28,6 +28,9 @@ public class PhFlagsTestUtil {
     private static final String WRITE_DEVICE_CONFIG_PERMISSION =
             "android.permission.WRITE_DEVICE_CONFIG";
 
+    private static final String WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION =
+            "android.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG";
+
     private static final String READ_DEVICE_CONFIG_PERMISSION =
             "android.permission.READ_DEVICE_CONFIG";
 
@@ -40,6 +43,7 @@ public class PhFlagsTestUtil {
                 .getUiAutomation()
                 .adoptShellPermissionIdentity(
                         WRITE_DEVICE_CONFIG_PERMISSION,
+                        WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION,
                         READ_DEVICE_CONFIG_PERMISSION,
                         MONITOR_DEVICE_CONFIG_ACCESS);
     }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
index 4219deaf..bbe9a517 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
@@ -20,9 +20,9 @@ import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICE
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_WRITE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__FEDERATED_COMPUTE;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doThrow;
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
-import static com.android.federatedcompute.services.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
+import static com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
+import static com.android.odp.module.common.encryption.OdpEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java
new file mode 100644
index 00000000..207e531e
--- /dev/null
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java
@@ -0,0 +1,70 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.federatedcompute.services.data;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertNotNull;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+
+import org.junit.After;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class FederatedComputeEncryptionKeyDaoUtilsTest {
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    @Test
+    public void testGetInstance() {
+        OdpEncryptionKeyDao instanceUnderTest =
+                FederatedComputeEncryptionKeyDaoUtils.getInstance(sContext);
+        OdpEncryptionKeyDao secondInstance =
+                FederatedComputeEncryptionKeyDaoUtils.getInstance(sContext);
+
+        assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
+        assertNotNull(instanceUnderTest);
+        assertThat(instanceUnderTest).isInstanceOf(OdpEncryptionKeyDao.class);
+    }
+
+    @Test
+    public void testGetInstanceForTest() {
+        OdpEncryptionKeyDao instanceUnderTest =
+                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext);
+        OdpEncryptionKeyDao secondInstance =
+                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext);
+
+        assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
+        assertNotNull(instanceUnderTest);
+        assertThat(instanceUnderTest).isInstanceOf(OdpEncryptionKeyDao.class);
+    }
+
+    @After
+    public void cleanUp() throws Exception {
+        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(sContext);
+        dbHelper.getWritableDatabase().close();
+        dbHelper.getReadableDatabase().close();
+        dbHelper.close();
+    }
+}
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
index 7af11699..bc417e80 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
@@ -16,7 +16,7 @@
 
 package com.android.federatedcompute.services.encryption;
 
-import static com.android.federatedcompute.services.data.FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION;
+import static com.android.odp.module.common.encryption.OdpEncryptionKey.KEY_TYPE_ENCRYPTION;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -47,10 +47,13 @@ import com.android.federatedcompute.services.common.FederatedComputeJobInfo;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.PhFlagsTestUtil;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyDao;
-import com.android.odp.module.common.HttpClient;
+import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyDaoUtils;
+import com.android.odp.module.common.EventLogger;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.odp.module.common.http.HttpClient;
 
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
@@ -62,11 +65,13 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
 import java.util.List;
+import java.util.Optional;
 import java.util.concurrent.ExecutionException;
 
 // TODO: add tests with Ph flags
@@ -83,12 +88,15 @@ public class BackgroundKeyFetchJobServiceTest {
 
     private HttpClient mHttpClient;
 
-    public FederatedComputeEncryptionKeyDao mEncryptionDao;
+    public OdpEncryptionKeyDao mEncryptionDao;
 
-    public FederatedComputeEncryptionKeyManager mSpyKeyManager;
+    public OdpEncryptionKeyManager mSpyKeyManager;
 
     private TestInjector mInjector;
 
+    @Mock
+    private EventLogger mMockEventLogger;
+
     @Before
     public void setUp() throws Exception {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
@@ -97,7 +105,7 @@ public class BackgroundKeyFetchJobServiceTest {
         MockitoAnnotations.initMocks(this);
         mContext = ApplicationProvider.getApplicationContext();
         mInjector = new TestInjector();
-        mEncryptionDao = FederatedComputeEncryptionKeyDao.getInstanceForTest(mContext);
+        mEncryptionDao = FederatedComputeEncryptionKeyDaoUtils.getInstance(mContext);
         mHttpClient = new HttpClient(/* retryLimit= */ 3, MoreExecutors.newDirectExecutorService());
         mSpyService = spy(new BackgroundKeyFetchJobService(new TestInjector()));
         doReturn(mSpyService).when(mSpyService).getApplicationContext();
@@ -106,12 +114,13 @@ public class BackgroundKeyFetchJobServiceTest {
         mJobScheduler.cancel(FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID);
         mSpyKeyManager =
                 spy(
-                        new FederatedComputeEncryptionKeyManager(
+                        FederatedComputeEncryptionKeyManagerUtils.getInstanceForTest(
                                 MonotonicClock.getInstance(),
                                 mEncryptionDao,
                                 FlagsFactory.getFlags(),
                                 mHttpClient,
-                                MoreExecutors.newDirectExecutorService()));
+                                MoreExecutors.newDirectExecutorService(),
+                                mContext));
         mStaticMockSession =
                 ExtendedMockito.mockitoSession()
                         .initMocks(this)
@@ -139,23 +148,23 @@ public class BackgroundKeyFetchJobServiceTest {
 
     @Test
     public void testOnStartJob() {
-        FederatedComputeEncryptionKeyManager keyManager =
-                mInjector.getEncryptionKeyManager(mContext);
-        List<FederatedComputeEncryptionKey> emptyKeyList = List.of();
+        OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(mContext);
+        List<OdpEncryptionKey> emptyKeyList = List.of();
         doReturn(FluentFuture.from(Futures.immediateFuture(emptyKeyList)))
                 .when(keyManager)
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true);
+                .fetchAndPersistActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true, Optional.empty());
 
         mSpyService.run(mock(JobParameters.class));
 
         verify(mSpyService, times(1)).onStartJob(any());
         verify(mSpyService, times(1)).jobFinished(any(), anyBoolean());
+        verify(mMockEventLogger, times(1)).logEncryptionKeyFetchStartEventKind();
     }
 
     @Test
     public void testOnStartJob_onFailure() {
-        FederatedComputeEncryptionKeyManager keyManager =
-                mInjector.getEncryptionKeyManager(mContext);
+        OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(mContext);
         doReturn(
                         FluentFuture.from(
                                 Futures.immediateFailedFuture(
@@ -163,12 +172,14 @@ public class BackgroundKeyFetchJobServiceTest {
                                                 " Failed to fetch keys",
                                                 new IllegalStateException("http 404")))))
                 .when(keyManager)
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true);
+                .fetchAndPersistActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true, Optional.empty());
 
         mSpyService.run(mock(JobParameters.class));
 
         verify(mSpyService, times(1)).onStartJob(any());
         verify(mSpyService, times(1)).jobFinished(any(), anyBoolean());
+        verify(mMockEventLogger, times(1)).logEncryptionKeyFetchStartEventKind();
     }
 
     @Test
@@ -218,12 +229,12 @@ public class BackgroundKeyFetchJobServiceTest {
     @Test
     public void testOnStartJob_enableKillSwitch() {
         PhFlagsTestUtil.enableGlobalKillSwitch();
-        FederatedComputeEncryptionKeyManager keyManager =
-                mInjector.getEncryptionKeyManager(mContext);
-        List<FederatedComputeEncryptionKey> emptyKeyList = List.of();
+        OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(mContext);
+        List<OdpEncryptionKey> emptyKeyList = List.of();
         doReturn(FluentFuture.from(Futures.immediateFuture(emptyKeyList)))
                 .when(keyManager)
-                .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true);
+                .fetchAndPersistActiveKeys(
+                        KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true, Optional.empty());
         doReturn(mJobScheduler).when(mSpyService).getSystemService(JobScheduler.class);
         mSpyService.scheduleJobIfNeeded(mContext, FlagsFactory.getFlags());
         assertTrue(mJobScheduler.getPendingJob(
@@ -234,7 +245,7 @@ public class BackgroundKeyFetchJobServiceTest {
         assertTrue(result);
         verify(mSpyService, times(1)).jobFinished(any(), eq(false));
         verify(keyManager, never()).fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION,
-                /* isScheduledJob= */ true);
+                /* isScheduledJob= */ true, Optional.empty());
         assertTrue(mJobScheduler.getPendingJob(
                 FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID)
                 == null);
@@ -247,7 +258,7 @@ public class BackgroundKeyFetchJobServiceTest {
         assertThat(injector.getExecutor())
                 .isEqualTo(FederatedComputeExecutors.getBackgroundExecutor());
         assertThat(injector.getEncryptionKeyManager(mContext))
-                .isEqualTo(FederatedComputeEncryptionKeyManager.getInstance(mContext));
+                .isEqualTo(FederatedComputeEncryptionKeyManagerUtils.getInstance(mContext));
         assertThat(injector.getLightWeightExecutor())
                 .isEqualTo(FederatedComputeExecutors.getLightweightExecutor());
     }
@@ -264,8 +275,13 @@ public class BackgroundKeyFetchJobServiceTest {
         }
 
         @Override
-        FederatedComputeEncryptionKeyManager getEncryptionKeyManager(Context context) {
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
             return mSpyKeyManager;
         }
+
+        @Override
+        EventLogger getEventLogger() {
+            return mMockEventLogger;
+        }
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java
new file mode 100644
index 00000000..9421e3a4
--- /dev/null
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java
@@ -0,0 +1,130 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+package com.android.federatedcompute.services.encryption;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertNotNull;
+import static org.mockito.Mockito.doReturn;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
+import com.android.odp.module.common.Clock;
+import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.OdpEncryptionKeyDao;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.odp.module.common.http.HttpClient;
+
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.MockitoAnnotations;
+
+import java.util.List;
+import java.util.Map;
+
+@RunWith(AndroidJUnit4.class)
+public class FederatedComputeEncryptionKeyManagerUtilsTest {
+
+    private static final Map<String, List<String>> SAMPLE_RESPONSE_HEADER =
+            Map.of(
+                    "Cache-Control", List.of("public,max-age=6000"),
+                    "Age", List.of("1"),
+                    "Content-Type", List.of("json"));
+
+    private static final String SAMPLE_RESPONSE_PAYLOAD =
+                    """
+{ "keys": [{ "id": "0cc9b4c9-08bd", "key": "BQo+c1Tw6TaQ+VH/b+9PegZOjHuKAFkl8QdmS0IjRj8" """
+                    + "} ] }";
+
+    @Mock private HttpClient mMockHttpClient;
+
+    @Mock private OdpEncryptionKeyDao mMockEncryptionKeyDao;
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private Clock mClock;
+
+    private Flags mMockFlags;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mClock = MonotonicClock.getInstance();
+        mMockFlags = Mockito.mock(Flags.class);
+        String overrideUrl = "https://real-coordinator/v1alpha/publicKeys";
+        doReturn(overrideUrl).when(mMockFlags).getEncryptionKeyFetchUrl();
+    }
+
+    @After
+    public void tearDown() {
+        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(sContext);
+        dbHelper.getWritableDatabase().close();
+        dbHelper.getReadableDatabase().close();
+        dbHelper.close();
+    }
+
+    @Test
+    public void testGetInstance() {
+        OdpEncryptionKeyManager instanceUnderTest =
+                FederatedComputeEncryptionKeyManagerUtils.getInstance(sContext);
+        OdpEncryptionKeyManager secondInstance =
+                FederatedComputeEncryptionKeyManagerUtils.getInstance(sContext);
+
+        assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
+        assertNotNull(instanceUnderTest);
+        assertThat(instanceUnderTest).isInstanceOf(OdpEncryptionKeyManager.class);
+        assertThat(instanceUnderTest.getKeyManagerConfigForTesting().getSQLiteOpenHelper())
+                .isSameInstanceAs(FederatedComputeDbHelper.getInstance(sContext));
+    }
+
+    @Test
+    public void testGetInstanceForTesting() {
+        OdpEncryptionKeyManager instanceUnderTest =
+                FederatedComputeEncryptionKeyManagerUtils.getInstanceForTest(
+                        mClock,
+                        mMockEncryptionKeyDao,
+                        mMockFlags,
+                        mMockHttpClient,
+                        MoreExecutors.newDirectExecutorService(),
+                        sContext);
+        OdpEncryptionKeyManager secondInstance =
+                FederatedComputeEncryptionKeyManagerUtils.getInstanceForTest(
+                        mClock,
+                        mMockEncryptionKeyDao,
+                        mMockFlags,
+                        mMockHttpClient,
+                        MoreExecutors.newDirectExecutorService(),
+                        sContext);
+
+        assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
+        assertNotNull(instanceUnderTest);
+        assertThat(instanceUnderTest).isInstanceOf(OdpEncryptionKeyManager.class);
+        assertThat(instanceUnderTest.getKeyManagerConfigForTesting().getSQLiteOpenHelper())
+                .isSameInstanceAs(FederatedComputeDbHelper.getInstanceForTest(sContext));
+    }
+}
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpClientUtilTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpClientUtilTest.java
index 127ce138..bc097b20 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpClientUtilTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpClientUtilTest.java
@@ -24,7 +24,7 @@ import android.net.Uri;
 
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.odp.module.common.HttpClientUtils;
+import com.android.odp.module.common.http.HttpClientUtils;
 
 import org.junit.Test;
 
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
index b4c08734..c693084e 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
@@ -18,17 +18,17 @@ package com.android.federatedcompute.services.http;
 
 import static com.android.federatedcompute.services.http.HttpClientUtil.ACCEPT_ENCODING_HDR;
 import static com.android.federatedcompute.services.http.HttpClientUtil.CONTENT_ENCODING_HDR;
-import static com.android.federatedcompute.services.http.HttpClientUtil.CONTENT_LENGTH_HDR;
 import static com.android.federatedcompute.services.http.HttpClientUtil.FCP_OWNER_ID_DIGEST;
-import static com.android.federatedcompute.services.http.HttpClientUtil.GZIP_ENCODING_HDR;
 import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_UNAUTHENTICATED_STATUS;
 import static com.android.federatedcompute.services.http.HttpClientUtil.ODP_AUTHENTICATION_KEY;
 import static com.android.federatedcompute.services.http.HttpClientUtil.ODP_AUTHORIZATION_KEY;
 import static com.android.federatedcompute.services.http.HttpClientUtil.ODP_IDEMPOTENCY_KEY;
 import static com.android.odp.module.common.FileUtils.createTempFile;
-import static com.android.odp.module.common.HttpClientUtils.CONTENT_TYPE_HDR;
-import static com.android.odp.module.common.HttpClientUtils.PROTOBUF_CONTENT_TYPE;
-import static com.android.odp.module.common.HttpClientUtils.compressWithGzip;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_LENGTH_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_TYPE_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.PROTOBUF_CONTENT_TYPE;
+import static com.android.odp.module.common.http.HttpClientUtils.compressWithGzip;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.util.concurrent.Futures.immediateFuture;
@@ -57,21 +57,21 @@ import com.android.federatedcompute.services.common.NetworkStats;
 import com.android.federatedcompute.services.common.PhFlags;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
-import com.android.federatedcompute.services.data.ODPAuthorizationToken;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
-import com.android.federatedcompute.services.encryption.HpkeJniEncrypter;
 import com.android.federatedcompute.services.security.AuthorizationContext;
 import com.android.federatedcompute.services.security.KeyAttestation;
 import com.android.federatedcompute.services.testutils.TrainingTestUtil;
 import com.android.federatedcompute.services.training.util.ComputationResult;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.Clock;
-import com.android.odp.module.common.HttpClient;
-import com.android.odp.module.common.HttpClientUtils;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.OdpHttpRequest;
-import com.android.odp.module.common.OdpHttpResponse;
+import com.android.odp.module.common.data.ODPAuthorizationToken;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.encryption.HpkeJniEncrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
+import com.android.odp.module.common.http.OdpHttpResponse;
 
 import com.google.common.collect.BoundType;
 import com.google.common.collect.ImmutableList;
@@ -87,13 +87,13 @@ import com.google.internal.federatedcompute.v1.RejectionReason;
 import com.google.internal.federatedcompute.v1.Resource;
 import com.google.internal.federatedcompute.v1.ResourceCapabilities;
 import com.google.internal.federatedcompute.v1.ResourceCompressionFormat;
-import com.google.internal.federatedcompute.v1.UploadInstruction;
 import com.google.ondevicepersonalization.federatedcompute.proto.CreateTaskAssignmentRequest;
 import com.google.ondevicepersonalization.federatedcompute.proto.CreateTaskAssignmentResponse;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultRequest;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultRequest.Result;
 import com.google.ondevicepersonalization.federatedcompute.proto.ReportResultResponse;
 import com.google.ondevicepersonalization.federatedcompute.proto.TaskAssignment;
+import com.google.ondevicepersonalization.federatedcompute.proto.UploadInstruction;
 import com.google.protobuf.ByteString;
 
 import org.json.JSONArray;
@@ -161,11 +161,11 @@ public final class HttpFederatedProtocolTest {
                             KeyAttestationAuthMetadata.newBuilder()
                                     .setChallenge(ByteString.copyFrom(CHALLENGE)))
                     .build();
-    private static final FederatedComputeEncryptionKey ENCRYPTION_KEY =
-            new FederatedComputeEncryptionKey.Builder()
+    private static final OdpEncryptionKey ENCRYPTION_KEY =
+            new OdpEncryptionKey.Builder()
                     .setPublicKey("rSJBSUYG0ebvfW1AXCWO0CMGMJhDzpfQm3eLyw1uxX8=")
                     .setKeyIdentifier("0962201a-5abd-4e25-a486-2c7bd1ee1887")
-                    .setKeyType(FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION)
+                    .setKeyType(OdpEncryptionKey.KEY_TYPE_ENCRYPTION)
                     .setCreationTime(1L)
                     .setExpiryTime(1L)
                     .build();
@@ -213,6 +213,8 @@ public final class HttpFederatedProtocolTest {
             new OdpHttpResponse.Builder().setStatusCode(200).build();
     private static final long ODP_AUTHORIZATION_TOKEN_TTL = 30 * 24 * 60 * 60 * 1000L;
 
+    private static final Context sTestContent = ApplicationProvider.getApplicationContext();
+
     @Captor private ArgumentCaptor<OdpHttpRequest> mHttpRequestCaptor;
 
     @Mock private HttpClient mMockHttpClient;
@@ -233,7 +235,7 @@ public final class HttpFederatedProtocolTest {
 
     private ODPAuthorizationTokenDao mODPAuthorizationTokenDao;
 
-    private Clock mClock = MonotonicClock.getInstance();
+    private final Clock mClock = MonotonicClock.getInstance();
 
     @Mock private KeyAttestation mMockKeyAttestation;
 
@@ -243,7 +245,7 @@ public final class HttpFederatedProtocolTest {
     public void setUp() throws Exception {
         mODPAuthorizationTokenDao =
                 ODPAuthorizationTokenDao.getInstanceForTest(
-                        ApplicationProvider.getApplicationContext());
+                        FederatedComputeDbHelper.getInstanceForTest(sTestContent));
         mHttpFederatedProtocol =
                 new HttpFederatedProtocol(
                         TASK_ASSIGNMENT_TARGET_URI,
@@ -266,8 +268,7 @@ public final class HttpFederatedProtocolTest {
     @After
     public void cleanUp() {
         FederatedComputeDbHelper dbHelper =
-                FederatedComputeDbHelper.getInstanceForTest(
-                        ApplicationProvider.getApplicationContext());
+                FederatedComputeDbHelper.getInstanceForTest(sTestContent);
         dbHelper.getWritableDatabase().close();
         dbHelper.getReadableDatabase().close();
         dbHelper.close();
@@ -1164,9 +1165,8 @@ public final class HttpFederatedProtocolTest {
         String testUriPrefix =
                 "android.resource://com.android.ondevicepersonalization.federatedcomputetests/raw/";
         File outputCheckpointFile = File.createTempFile("output", ".ckp");
-        Context context = ApplicationProvider.getApplicationContext();
         Uri checkpointUri = Uri.parse(testUriPrefix + "federation_test_checkpoint_client");
-        InputStream in = context.getContentResolver().openInputStream(checkpointUri);
+        InputStream in = sTestContent.getContentResolver().openInputStream(checkpointUri);
         java.nio.file.Files.copy(in, outputCheckpointFile.toPath(), REPLACE_EXISTING);
         in.close();
         outputCheckpointFile.deleteOnExit();
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/ProtocolRequestCreatorTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/ProtocolRequestCreatorTest.java
index ce561730..1c5fa52b 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/ProtocolRequestCreatorTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/ProtocolRequestCreatorTest.java
@@ -16,16 +16,16 @@
 
 package com.android.federatedcompute.services.http;
 
-import static com.android.federatedcompute.services.http.HttpClientUtil.CONTENT_LENGTH_HDR;
-import static com.android.odp.module.common.HttpClientUtils.CONTENT_TYPE_HDR;
-import static com.android.odp.module.common.HttpClientUtils.PROTOBUF_CONTENT_TYPE;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_LENGTH_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_TYPE_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.PROTOBUF_CONTENT_TYPE;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
 
-import com.android.odp.module.common.HttpClientUtils;
-import com.android.odp.module.common.OdpHttpRequest;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
 
 import com.google.internal.federatedcompute.v1.ForwardingInfo;
 
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
index dcb005c8..d40ee5b1 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
@@ -52,15 +52,15 @@ import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.federatedcompute.services.data.ODPAuthorizationToken;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenContract;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.federatedcompute.services.data.TaskHistory;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationToken;
+import com.android.odp.module.common.data.ODPAuthorizationTokenContract;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
@@ -106,7 +106,10 @@ public class DeleteExpiredJobServiceTest {
         when(mClock.currentTimeMillis()).thenReturn(400L);
         when(mMockFlag.getTaskHistoryTtl()).thenReturn(200L);
         LogUtil.i(TAG, "mSpyAuthTokenDao " + mSpyAuthTokenDao);
-        mSpyAuthTokenDao = spy(ODPAuthorizationTokenDao.getInstanceForTest(mContext));
+        mSpyAuthTokenDao =
+                spy(
+                        ODPAuthorizationTokenDao.getInstanceForTest(
+                                FederatedComputeDbHelper.getInstanceForTest(mContext)));
         mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
         mSpyService = spy(new DeleteExpiredJobService(new TestInjector()));
 
@@ -250,7 +253,9 @@ public class DeleteExpiredJobServiceTest {
         assertThat(injector.getExecutor())
                 .isEqualTo(FederatedComputeExecutors.getBackgroundExecutor());
         assertThat(injector.getODPAuthorizationTokenDao(mContext))
-                .isEqualTo(ODPAuthorizationTokenDao.getInstance(mContext));
+                .isEqualTo(
+                        ODPAuthorizationTokenDao.getInstance(
+                                FederatedComputeDbHelper.getInstance(mContext)));
     }
 
     private ODPAuthorizationToken createExpiredAuthToken(String ownerId) {
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
index 8006c0b4..c1eadfe4 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
@@ -48,13 +48,13 @@ import com.android.adservices.shared.spe.scheduling.JobSpec;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob.Injector;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobServiceFactory;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.Clock;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
index 1d289b6b..429d6d96 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
@@ -44,10 +44,10 @@ import androidx.test.core.app.ApplicationProvider;
 
 import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
-import com.android.federatedcompute.services.data.ODPAuthorizationToken;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationToken;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
 
 import com.google.internal.federatedcompute.v1.AuthenticationMetadata;
 import com.google.internal.federatedcompute.v1.KeyAttestationAuthMetadata;
@@ -89,7 +89,10 @@ public class AuthorizationContextTest {
         MockitoAnnotations.initMocks(this);
         mContext = ApplicationProvider.getApplicationContext();
         doReturn(KA_RECORD).when(mMocKeyAttestation).generateAttestationRecord(any(), anyString());
-        mAuthTokenDao = spy(ODPAuthorizationTokenDao.getInstanceForTest(mContext));
+        mAuthTokenDao =
+                spy(
+                        ODPAuthorizationTokenDao.getInstanceForTest(
+                                FederatedComputeDbHelper.getInstanceForTest(mContext)));
         mClock = MonotonicClock.getInstance();
         doNothing().when(mMockTrainingEventLogger).logKeyAttestationLatencyEvent(anyLong());
     }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
index fde77554..cb80e4b8 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
@@ -21,6 +21,7 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
+import static org.mockito.Mockito.when;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
@@ -37,6 +38,7 @@ import java.security.KeyPairGenerator;
 import java.security.KeyStore;
 import java.security.KeyStoreException;
 import java.security.ProviderException;
+import java.security.cert.Certificate;
 import java.security.cert.CertificateException;
 import java.util.List;
 
@@ -49,9 +51,7 @@ public final class KeyAttestationTest {
 
     private static final String CALLING_APP = "sampleApp1";
 
-    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
-
-    private static final String KEY_ALIAS = CALLING_APP + "-ODPKeyAttestation";
+    private static final String KEY_ALIAS = KeyAttestation.getKeyAlias(CALLING_APP);
 
     private KeyAttestation mKeyAttestation;
 
@@ -59,6 +59,8 @@ public final class KeyAttestationTest {
 
     @Mock private KeyPairGenerator mMockKeyPairGenerator;
 
+    @Mock private Certificate mMockCert;
+
     @Before
     public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
@@ -67,14 +69,13 @@ public final class KeyAttestationTest {
                         ApplicationProvider.getApplicationContext(), new TestInjector());
     }
 
-    // TODO: add tests for success cases.
     @Test
     public void testGenerateAttestationRecord_nullKey() {
         doReturn(null).when(mMockKeyPairGenerator).generateKeyPair();
 
         List<String> record = mKeyAttestation.generateAttestationRecord(CHALLENGE, CALLING_APP);
 
-        assertThat(record.size()).isEqualTo(0);
+        assertThat(record).isEmpty();
     }
 
     @Test
@@ -95,7 +96,7 @@ public final class KeyAttestationTest {
         KeyPair unused = mKeyAttestation.generateHybridKey(CHALLENGE, KEY_ALIAS);
         List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(keyAlias2);
 
-        assertThat(record.size()).isEqualTo(0);
+        assertThat(record).isEmpty();
     }
 
     @Test
@@ -104,7 +105,7 @@ public final class KeyAttestationTest {
 
         List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
 
-        assertThat(record.size()).isEqualTo(0);
+        assertThat(record).isEmpty();
     }
 
     @Test
@@ -115,7 +116,26 @@ public final class KeyAttestationTest {
 
         List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
 
-        assertThat(record.size()).isEqualTo(0);
+        assertThat(record).isEmpty();
+    }
+
+    @Test
+    public void testGetAttestationRecordFromKeyAlias_nullCertificate() throws Exception {
+        when(mMockKeyStore.getCertificateChain(any())).thenReturn(null);
+
+        List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
+
+        assertThat(record).isEmpty();
+    }
+
+    @Test
+    public void testGetAttestationRecordFromKeyAlias_Certificate() throws Exception {
+        when(mMockKeyStore.getCertificateChain(any())).thenReturn(new Certificate[] {mMockCert});
+        when(mMockCert.getEncoded()).thenReturn(new byte[] {20});
+
+        List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
+
+        assertThat(record).hasSize(1);
     }
 
     @Test
@@ -129,7 +149,7 @@ public final class KeyAttestationTest {
         assertThat(keyPair).isNull();
     }
 
-    class TestInjector extends KeyAttestation.Injector {
+    private class TestInjector extends KeyAttestation.Injector {
         @Override
         KeyStore getKeyStore() {
             return mMockKeyStore;
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
index d151a3da..2f00547c 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
@@ -24,6 +24,7 @@ import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICE
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_COMPUTATION_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ELIGIBLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_SUCCESS;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START;
@@ -71,17 +72,13 @@ import com.android.federatedcompute.services.common.Constants;
 import com.android.federatedcompute.services.common.ExampleStats;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
-import com.android.federatedcompute.services.data.FederatedComputeEncryptionKey;
 import com.android.federatedcompute.services.data.FederatedTrainingTask;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.federatedcompute.services.data.ODPAuthorizationTokenDao;
 import com.android.federatedcompute.services.data.TaskHistory;
 import com.android.federatedcompute.services.data.fbs.SchedulingMode;
 import com.android.federatedcompute.services.data.fbs.SchedulingReason;
 import com.android.federatedcompute.services.data.fbs.TrainingConstraints;
 import com.android.federatedcompute.services.data.fbs.TrainingIntervalOptions;
-import com.android.federatedcompute.services.encryption.FederatedComputeEncryptionKeyManager;
-import com.android.federatedcompute.services.encryption.HpkeJniEncrypter;
 import com.android.federatedcompute.services.examplestore.ExampleConsumptionRecorder;
 import com.android.federatedcompute.services.examplestore.ExampleStoreServiceProvider;
 import com.android.federatedcompute.services.http.CheckinResult;
@@ -101,6 +98,10 @@ import com.android.federatedcompute.services.training.util.TrainingConditionsChe
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.MonotonicClock;
+import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.encryption.HpkeJniEncrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableSet;
@@ -325,7 +326,7 @@ public final class FederatedComputeWorkerTest {
     private ExampleStoreServiceProvider mSpyExampleStoreProvider;
     private FederatedTrainingTaskDao mTrainingTaskDao;
 
-    @Mock private FederatedComputeEncryptionKeyManager mMockKeyManager;
+    @Mock private OdpEncryptionKeyManager mMockKeyManager;
 
     @Mock private KeyAttestation mMockKeyAttestation;
 
@@ -333,11 +334,11 @@ public final class FederatedComputeWorkerTest {
 
     @Mock private FederatedJobService.OnJobFinishedCallback mMockJobServiceOnFinishCallback;
 
-    private static final FederatedComputeEncryptionKey ENCRYPTION_KEY =
-            new FederatedComputeEncryptionKey.Builder()
+    private static final OdpEncryptionKey ENCRYPTION_KEY =
+            new OdpEncryptionKey.Builder()
                     .setPublicKey("rSJBSUYG0ebvfW1AXCWO0CMGMJhDzpfQm3eLyw1uxX8=")
                     .setKeyIdentifier("0962201a-5abd-4e25-a486-2c7bd1ee1887")
-                    .setKeyType(FederatedComputeEncryptionKey.KEY_TYPE_ENCRYPTION)
+                    .setKeyType(OdpEncryptionKey.KEY_TYPE_ENCRYPTION)
                     .setCreationTime(1L)
                     .setExpiryTime(1L)
                     .build();
@@ -365,7 +366,7 @@ public final class FederatedComputeWorkerTest {
     }
 
     @Before
-    public void doBeforeEachTest() {
+    public void setUp() {
         mContext = ApplicationProvider.getApplicationContext();
         when(ClientErrorLogger.getInstance()).thenReturn(mMockClientErrorLogger);
         mSpyHttpFederatedProtocol =
@@ -409,7 +410,7 @@ public final class FederatedComputeWorkerTest {
                 .thenReturn(FL_RUNNER_SUCCESS_RESULT);
         doReturn(List.of(ENCRYPTION_KEY))
                 .when(mMockKeyManager)
-                .getOrFetchActiveKeys(anyInt(), anyInt());
+                .getOrFetchActiveKeys(anyInt(), anyInt(), any());
         doReturn(KA_RECORD).when(mMockKeyAttestation).generateAttestationRecord(any(), anyString());
     }
 
@@ -739,7 +740,7 @@ public final class FederatedComputeWorkerTest {
                         anyInt(), anyString(), any(), any(), eq(ContributionResult.FAIL), eq(true));
 
         ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
-        verify(mMockTrainingEventLogger, times(9)).logEventKind(captor.capture());
+        verify(mMockTrainingEventLogger, times(10)).logEventKind(captor.capture());
         assertThat(captor.getAllValues())
                 .containsExactlyElementsIn(
                         Arrays.asList(
@@ -751,7 +752,8 @@ public final class FederatedComputeWorkerTest {
                                 FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START,
                                 FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_SUCCESS,
                                 FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_COMPUTATION_FAILED,
-                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_STARTED));
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_STARTED,
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ENCRYPTION_KEY_FETCH_SUCCESS));
         verify(mMockTrainingEventLogger).logComputationInvalidArgument(any());
     }
 
@@ -1084,9 +1086,9 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testRunFLComputation_noKey_throws() throws Exception {
         setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
-        doReturn(new ArrayList<FederatedComputeEncryptionKey>() {})
+        doReturn(new ArrayList<OdpEncryptionKey>() {})
                 .when(mMockKeyManager)
-                .getOrFetchActiveKeys(anyInt(), anyInt());
+                .getOrFetchActiveKeys(anyInt(), anyInt(), any());
         setUpReportFailureToServerCallback();
 
         assertThrows(
@@ -1166,7 +1168,8 @@ public final class FederatedComputeWorkerTest {
             return new AuthorizationContext(
                     ownerId,
                     owerCert,
-                    ODPAuthorizationTokenDao.getInstanceForTest(mContext),
+                    ODPAuthorizationTokenDao.getInstanceForTest(
+                            FederatedComputeDbHelper.getInstanceForTest(context)),
                     mMockKeyAttestation,
                     MonotonicClock.getInstance());
         }
diff --git a/tests/frameworktests/AndroidTest.xml b/tests/frameworktests/AndroidTest.xml
index 278212a9..ef6fa5db 100644
--- a/tests/frameworktests/AndroidTest.xml
+++ b/tests/frameworktests/AndroidTest.xml
@@ -24,6 +24,19 @@
         <option name="test-file-name" value="FrameworkOnDevicePersonalizationTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" /> <!-- Allow hidden API uses -->
         <option name="package" value="android.ondevicepersonalization"/>
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/InferenceInputTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/InferenceInputTest.java
index 88a2e699..7e7a2f2e 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/InferenceInputTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/InferenceInputTest.java
@@ -16,6 +16,8 @@
 
 package android.adservices.ondevicepersonalization;
 
+import static com.android.ondevicepersonalization.internal.util.ByteArrayUtil.deserializeObject;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static junit.framework.Assert.assertEquals;
@@ -26,9 +28,12 @@ import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
 import android.os.Bundle;
 
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
+
 import org.junit.Before;
 import org.junit.Test;
 
+import java.io.NotSerializableException;
 import java.util.HashMap;
 
 public class InferenceInputTest {
@@ -146,9 +151,119 @@ public class InferenceInputTest {
                 () -> new InferenceInput.Params.Builder(mRemoteData, null).build());
     }
 
+    @Test
+    public void buildLiteRT_success() {
+        HashMap<Integer, Object> outputData = new HashMap<>();
+        outputData.put(0, new float[1]);
+        Object[] input = new Object[1];
+        input[0] = new float[] {1.2f};
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY).build();
+
+        InferenceInput result =
+                new InferenceInput.Builder(params, ByteArrayUtil.serializeObject(input))
+                        .setExpectedOutputStructure(
+                                new InferenceOutput.Builder().setDataOutputs(outputData).build())
+                        .build();
+
+        Object[] obj = (Object[]) deserializeObject(result.getData());
+        assertThat(obj).isEqualTo(input);
+    }
+
+    @Test
+    public void buildExecuTorch_success() {
+        // TODO(b/376902350): update input with EValue.
+        byte[] input = {1, 2, 3};
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY)
+                        .setModelType(InferenceInput.Params.MODEL_TYPE_EXECUTORCH)
+                        .build();
+
+        InferenceInput result = new InferenceInput.Builder(params, input).build();
+
+        assertThat(result.getData()).isEqualTo(input);
+    }
+
+    @Test
+    public void buildExecutorchInput_missingInputData() {
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY)
+                        .setModelType(InferenceInput.Params.MODEL_TYPE_EXECUTORCH)
+                        .build();
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> new InferenceInput.Builder(params, new byte[] {}).build());
+    }
+
+    @Test
+    public void buildLiteRTInput_missingInputData() {
+        HashMap<Integer, Object> outputData = new HashMap<>();
+        outputData.put(0, new float[1]);
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY).build();
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        new InferenceInput.Builder(params, new byte[] {})
+                                .setExpectedOutputStructure(
+                                        new InferenceOutput.Builder()
+                                                .setDataOutputs(outputData)
+                                                .build())
+                                .build());
+    }
+
+    @Test
+    public void buildLiteRTInput_missingOutputStructure() {
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY).build();
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        new InferenceInput.Builder(params, new byte[] {})
+                                .setExpectedOutputStructure(
+                                        new InferenceOutput.Builder()
+                                                .setDataOutputs(new HashMap<>())
+                                                .build())
+                                .build());
+    }
+
+    @Test
+    public void nonSerializable() {
+        NonSerializableObject obj = new NonSerializableObject(123);
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY).build();
+
+        IllegalArgumentException exp =
+                assertThrows(
+                        IllegalArgumentException.class,
+                        () ->
+                                new InferenceInput.Builder(
+                                                params,
+                                                new Object[] {obj},
+                                                new InferenceOutput.Builder()
+                                                        .setDataOutputs(new HashMap<>())
+                                                        .build())
+                                        .build());
+
+        assertThat(exp.getCause()).isInstanceOf(NotSerializableException.class);
+    }
+
+    /** A class used for serializable exception test. */
+    class NonSerializableObject {
+        private final int mData;
+
+        NonSerializableObject(int data) {
+            this.mData = data;
+        }
+    }
+
     static class TestDataAccessService extends IDataAccessService.Stub {
         @Override
         public void onRequest(int operation, Bundle params, IDataAccessServiceCallback callback) {}
+
         @Override
         public void logApiCallStats(int apiName, long latencyMillis, int responseCode) {}
     }
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/IsolatedServiceExceptionSafetyTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/IsolatedServiceExceptionSafetyTest.java
index 7a53369b..82bba521 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/IsolatedServiceExceptionSafetyTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/IsolatedServiceExceptionSafetyTest.java
@@ -43,6 +43,7 @@ import com.android.ondevicepersonalization.internal.util.ByteArrayParceledSlice;
 import com.android.ondevicepersonalization.internal.util.PersistableBundleUtils;
 
 import org.junit.After;
+import org.junit.AfterClass;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -60,7 +61,7 @@ public class IsolatedServiceExceptionSafetyTest {
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
     private IIsolatedService mIsolatedService;
-    private AbstractServiceBinder<IIsolatedService> mServiceBinder;
+    private static AbstractServiceBinder<IIsolatedService> sServiceBinder;
     private int mCallbackErrorCode;
     private int mIsolatedServiceErrorCode;
     private byte[] mSerializedExceptionInfo;
@@ -81,25 +82,33 @@ public class IsolatedServiceExceptionSafetyTest {
 
     @Before
     public void setUp() throws Exception {
-        mServiceBinder = AbstractServiceBinder.getIsolatedServiceBinderByServiceName(
-                mContext,
-                "android.adservices.ondevicepersonalization.IsolatedServiceExceptionSafetyTestImpl",
-                mContext.getPackageName(),
-                "testIsolatedProcess",
-                0,
-                IIsolatedService.Stub::asInterface);
-
-        mIsolatedService = mServiceBinder.getService(Runnable::run);
+        if (sServiceBinder == null) {
+            sServiceBinder =
+                    AbstractServiceBinder.getIsolatedServiceBinderByServiceName(
+                            mContext,
+                            "android.adservices.ondevicepersonalization."
+                                    + "IsolatedServiceExceptionSafetyTestImpl",
+                            mContext.getPackageName(),
+                            "testIsolatedProcess",
+                            0,
+                            IIsolatedService.Stub::asInterface);
+        }
+
+        mIsolatedService = sServiceBinder.getService(Runnable::run);
         mLatch = new CountDownLatch(1);
     }
 
     @After
     public void tearDown() {
-        mServiceBinder.unbindFromService();
         mIsolatedService = null;
         mCallbackErrorCode = 0;
     }
 
+    @AfterClass
+    public static void tearDownClass() {
+        sServiceBinder.unbindFromService();
+    }
+
     @Test
     public void testOnRequestExceptions() throws Exception {
         PersistableBundle appParams = new PersistableBundle();
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/LocalDataTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/LocalDataTest.java
index 091006b5..687bb253 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/LocalDataTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/LocalDataTest.java
@@ -16,9 +16,11 @@
 
 package android.adservices.ondevicepersonalization;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertArrayEquals;
-import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
@@ -38,6 +40,8 @@ import java.util.HashMap;
 import java.util.HashSet;
 import java.util.Objects;
 import java.util.Set;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
 
 /**
  * Unit Tests of LocalDataImpl API.
@@ -46,12 +50,13 @@ import java.util.Set;
 @RunWith(AndroidJUnit4.class)
 public class LocalDataTest {
     MutableKeyValueStore mLocalData;
+    LocalDataService mLocalDataService;
+    private static final long TIMEOUT_MILLI = 5000;
 
     @Before
     public void setup() {
-        mLocalData = new LocalDataImpl(
-                IDataAccessService.Stub.asInterface(
-                        new LocalDataService()));
+        mLocalDataService = new LocalDataService();
+        mLocalData = new LocalDataImpl(IDataAccessService.Stub.asInterface(mLocalDataService));
     }
 
     @Test
@@ -59,22 +64,48 @@ public class LocalDataTest {
         assertArrayEquals(new byte[] {1, 2, 3}, mLocalData.get("a"));
         assertArrayEquals(new byte[] {7, 8, 9}, mLocalData.get("c"));
         assertNull(mLocalData.get("e"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SUCCESS);
     }
 
     @Test
-    public void testLookupError() {
+    public void testLookupError() throws InterruptedException {
         // Triggers an expected error in the mock service.
         assertNull(mLocalData.get("z"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SERVICE_FAILED);
+    }
+
+    @Test
+    public void testLookupEmptyResult() throws Exception {
+        // Triggers an expected error in the mock service.
+        assertNull(mLocalData.get("empty"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode)
+                .isEqualTo(Constants.STATUS_SUCCESS_EMPTY_RESULT);
     }
 
     @Test
-    public void testKeysetSuccess() {
+    public void testKeysetSuccess() throws InterruptedException {
         Set<String> expectedResult = new HashSet<>();
         expectedResult.add("a");
         expectedResult.add("b");
         expectedResult.add("c");
 
-        assertEquals(expectedResult, mLocalData.keySet());
+        assertThat(expectedResult).isEqualTo(mLocalData.keySet());
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SUCCESS);
     }
 
     @Test
@@ -82,12 +113,22 @@ public class LocalDataTest {
         assertArrayEquals(new byte[] {1, 2, 3}, mLocalData.put("a", new byte[10]));
         assertNull(mLocalData.put("e", new byte[] {1, 2, 3}));
         assertArrayEquals(new byte[] {1, 2, 3}, mLocalData.get("e"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SUCCESS);
     }
 
     @Test
-    public void testPutError() {
+    public void testPutError() throws InterruptedException {
         // Triggers an expected error in the mock service.
         assertNull(mLocalData.put("z", new byte[10]));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SERVICE_FAILED);
     }
 
     @Test
@@ -95,16 +136,28 @@ public class LocalDataTest {
         assertArrayEquals(new byte[] {1, 2, 3}, mLocalData.remove("a"));
         assertNull(mLocalData.remove("e"));
         assertNull(mLocalData.get("a"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SUCCESS);
     }
 
     @Test
-    public void testRemoveError() {
+    public void testRemoveError() throws InterruptedException {
         // Triggers an expected error in the mock service.
         assertNull(mLocalData.remove("z"));
+
+        assertTrue(
+                "Failed to await countdown latch!",
+                mLocalDataService.mLatch.await(TIMEOUT_MILLI, TimeUnit.MILLISECONDS));
+        assertThat(mLocalDataService.mResponseCode).isEqualTo(Constants.STATUS_SERVICE_FAILED);
     }
 
     public static class LocalDataService extends IDataAccessService.Stub {
         HashMap<String, byte[]> mContents = new HashMap<String, byte[]>();
+        int mResponseCode;
+        CountDownLatch mLatch = new CountDownLatch(1);
 
         public LocalDataService() {
             mContents.put("a", new byte[] {1, 2, 3});
@@ -132,10 +185,19 @@ public class LocalDataTest {
 
             String key = params.getString(Constants.EXTRA_LOOKUP_KEYS);
             Objects.requireNonNull(key);
+            if (key.equals("empty")) {
+                // Raise expected error.
+                try {
+                    callback.onSuccess(null);
+                } catch (RemoteException e) {
+                    // Ignored.
+                }
+                return;
+            }
             if (key.equals("z")) {
                 // Raise expected error.
                 try {
-                    callback.onError(Constants.STATUS_INTERNAL_ERROR);
+                    callback.onError(Constants.STATUS_SERVICE_FAILED);
                 } catch (RemoteException e) {
                     // Ignored.
                 }
@@ -173,6 +235,9 @@ public class LocalDataTest {
         }
 
         @Override
-        public void logApiCallStats(int apiName, long latencyMillis, int responseCode) {}
+        public void logApiCallStats(int apiName, long latencyMillis, int responseCode) {
+            mLatch.countDown();
+            mResponseCode = responseCode;
+        }
     }
 }
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/ModelManagerTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/ModelManagerTest.java
index 2ea58852..5899e60c 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/ModelManagerTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/ModelManagerTest.java
@@ -33,6 +33,7 @@ import android.os.RemoteException;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
 import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
 
 import com.google.common.util.concurrent.MoreExecutors;
@@ -42,6 +43,7 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.util.HashMap;
+import java.util.Map;
 
 @SmallTest
 @RunWith(AndroidJUnit4.class)
@@ -55,6 +57,7 @@ public class ModelManagerTest {
     private static final String MODEL_KEY = "model_key";
     private static final String MISSING_OUTPUT_KEY = "missing-output-key";
     private boolean mRunInferenceCalled = false;
+    private static final int EXECUTORCH_RESULT = 10;
     private RemoteDataImpl mRemoteData;
 
     @Before
@@ -140,6 +143,53 @@ public class ModelManagerTest {
                 .isEqualTo(OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
     }
 
+    @Test
+    public void runExecutorchInference_success() throws Exception {
+        // TODO(b/376902350): update input with EValue.
+        byte[] input = new byte[] {1, 2, 3};
+        InferenceInput inferenceContext =
+                new InferenceInput.Builder(
+                                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY)
+                                        .setModelType(InferenceInput.Params.MODEL_TYPE_EXECUTORCH)
+                                        .build(),
+                                input)
+                        .build();
+
+        var callback = new ResultReceiver<InferenceOutput>();
+        mModelManager.run(inferenceContext, MoreExecutors.directExecutor(), callback);
+
+        assertTrue(callback.isSuccess());
+        int value = (int) ByteArrayUtil.deserializeObject(callback.getResult().getData());
+        assertThat(value).isEqualTo(EXECUTORCH_RESULT);
+    }
+
+    @Test
+    public void runLiteRTInferenceUsingByteArray_success() throws Exception {
+        HashMap<Integer, Object> outputData = new HashMap<>();
+        outputData.put(0, new float[1]);
+        Object[] input = new Object[1];
+        input[0] = new float[] {1.2f};
+        InferenceInput inferenceContext =
+                new InferenceInput.Builder(
+                                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY).build(),
+                                ByteArrayUtil.serializeObject(input))
+                        .setExpectedOutputStructure(
+                                new InferenceOutput.Builder()
+                                        .setData(ByteArrayUtil.serializeObject(outputData))
+                                        .build())
+                        .build();
+
+        var callback = new ResultReceiver<InferenceOutput>();
+        mModelManager.run(inferenceContext, MoreExecutors.directExecutor(), callback);
+
+        assertTrue(callback.isSuccess());
+        Map<Integer, Object> result =
+                (Map<Integer, Object>)
+                        ByteArrayUtil.deserializeObject(callback.getResult().getData());
+        float[] value = (float[]) result.get(0);
+        assertEquals(value[0], 5.0f, 0.01f);
+    }
+
     class TestIsolatedModelService extends IIsolatedModelService.Stub {
         @Override
         public void runInference(Bundle params, IIsolatedModelServiceCallback callback)
@@ -156,13 +206,24 @@ public class ModelManagerTest {
                 callback.onError(OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
                 return;
             }
-            HashMap<Integer, Object> result = new HashMap<>();
-            result.put(0, new float[] {5.0f});
+
             Bundle bundle = new Bundle();
-            bundle.putParcelable(
-                    Constants.EXTRA_RESULT,
-                    new InferenceOutputParcel(
-                            new InferenceOutput.Builder().setDataOutputs(result).build()));
+            if (inputParcel.getModelType() == InferenceInput.Params.MODEL_TYPE_EXECUTORCH) {
+                bundle.putParcelable(
+                        Constants.EXTRA_RESULT,
+                        new InferenceOutputParcel(
+                                new InferenceOutput.Builder()
+                                        .setData(ByteArrayUtil.serializeObject(EXECUTORCH_RESULT))
+                                        .build()));
+            } else {
+                HashMap<Integer, Object> result = new HashMap<>();
+                result.put(0, new float[] {5.0f});
+                bundle.putParcelable(
+                        Constants.EXTRA_RESULT,
+                        new InferenceOutputParcel(
+                                new InferenceOutput.Builder().setDataOutputs(result).build()));
+            }
+
             callback.onSuccess(bundle);
         }
     }
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationManagerTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationManagerTest.java
index 6193c7d0..9c96f36b 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationManagerTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationManagerTest.java
@@ -24,6 +24,7 @@ import static org.junit.Assert.assertTrue;
 
 import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager.ExecuteResult;
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
@@ -41,6 +42,7 @@ import androidx.test.core.app.ApplicationProvider;
 
 import com.android.compatibility.common.util.ShellUtils;
 import com.android.federatedcompute.internal.util.AbstractServiceBinder;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.ondevicepersonalization.internal.util.ByteArrayParceledSlice;
 import com.android.ondevicepersonalization.internal.util.ExceptionInfo;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
@@ -79,24 +81,23 @@ public final class OnDevicePersonalizationManagerTest {
     private volatile boolean mLogApiStatsCalled = false;
 
     @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameter(1)
     public boolean mRunExecuteInIsolatedService;
 
     @Parameterized.Parameters
     public static Collection<Object[]> data() {
         return Arrays.asList(
-                new Object[][] {{true, true}, {true, false}, {false, true}, {false, false}});
+                new Object[][] {
+                        {true}, {false}
+                }
+        );
     }
-
     @Before
     public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
         ShellUtils.runShellCommand(
                 "device_config put on_device_personalization "
                         + "shared_isolated_process_feature_enabled "
-                        + mIsSipFeatureEnabled);
+                        + SdkLevel.isAtLeastU());
     }
 
     @Test
@@ -492,6 +493,14 @@ public final class OnDevicePersonalizationManagerTest {
             throw new UnsupportedOperationException();
         }
 
+        @Override
+        public void isFeatureEnabled(
+                String featureName,
+                CallerMetadata metadata,
+                IIsFeatureEnabledCallback callback) {
+            throw new UnsupportedOperationException();
+        }
+
         @Override
         public void logApiCallStats(
                 String sdkPackageName,
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationQueryFeatureAvailabilityManagerTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationQueryFeatureAvailabilityManagerTest.java
new file mode 100644
index 00000000..f7dca46a
--- /dev/null
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationQueryFeatureAvailabilityManagerTest.java
@@ -0,0 +1,181 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.adservices.ondevicepersonalization;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
+import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
+import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
+import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
+import android.content.ComponentName;
+import android.content.Context;
+import android.os.Bundle;
+import android.os.IBinder;
+import android.os.RemoteException;
+import android.os.SystemClock;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.compatibility.common.util.ShellUtils;
+import com.android.federatedcompute.internal.util.AbstractServiceBinder;
+import com.android.modules.utils.build.SdkLevel;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+import java.util.concurrent.Executors;
+
+public class OnDevicePersonalizationQueryFeatureAvailabilityManagerTest {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = "OnDevicePersonalizationIsFeatureEnabledManagerTest";
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private final TestServiceBinder mTestBinder = new TestServiceBinder(
+                    IOnDevicePersonalizationManagingService.Stub.asInterface(new TestService()));
+    private final OnDevicePersonalizationManager mManager =
+            new OnDevicePersonalizationManager(mContext, mTestBinder);
+
+    private volatile boolean mLogApiStatsCalled = false;
+
+    @Before
+    public void setUp() throws Exception {
+        mLogApiStatsCalled = false;
+        MockitoAnnotations.initMocks(this);
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "shared_isolated_process_feature_enabled "
+                        + SdkLevel.isAtLeastU());
+    }
+
+    @Test
+    public void queryFeatureAvailabilitySuccess() throws Exception {
+        var receiver = new ResultReceiver<Integer>();
+
+        mManager.queryFeatureAvailability(
+                "success", Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.isSuccess());
+        assertFalse(receiver.isError());
+        assertNotNull(receiver.getResult());
+        assertTrue(mLogApiStatsCalled);
+        assertThat(receiver.getResult()).isEqualTo(OnDevicePersonalizationManager.FEATURE_DISABLED);
+    }
+
+    @Test
+    public void queryFeatureAvailabilityException() throws Exception {
+        var receiver = new ResultReceiver<Integer>();
+
+        mManager.queryFeatureAvailability(
+                "error", Executors.newSingleThreadExecutor(), receiver);
+        assertFalse(receiver.isSuccess());
+        assertTrue(receiver.isError());
+        assertTrue(receiver.getException() instanceof IllegalStateException);
+        assertTrue(mLogApiStatsCalled);
+    }
+
+    private class TestService extends IOnDevicePersonalizationManagingService.Stub {
+        @Override
+        public String getVersion() {
+            return "1.0";
+        }
+
+        @Override
+        public void execute(
+                String callingPackageName,
+                ComponentName handler,
+                Bundle wrappedParams,
+                CallerMetadata metadata,
+                ExecuteOptionsParcel options,
+                IExecuteCallback callback) {
+            throw new UnsupportedOperationException();
+        }
+
+        @Override
+        public void requestSurfacePackage(
+                String surfacePackageToken,
+                IBinder hostToken,
+                int displayId,
+                int width,
+                int height,
+                CallerMetadata metadata,
+                IRequestSurfacePackageCallback callback) {
+            throw new UnsupportedOperationException();
+        }
+
+        @Override
+        public void registerMeasurementEvent(
+                int eventType,
+                Bundle params,
+                CallerMetadata metadata,
+                IRegisterMeasurementEventCallback callback) {
+            throw new UnsupportedOperationException();
+        }
+
+        @Override
+        public void isFeatureEnabled(
+                String featureName,
+                CallerMetadata metadata,
+                IIsFeatureEnabledCallback callback) throws RemoteException {
+            if (featureName.equals("success")) {
+                callback.onResult(OnDevicePersonalizationManager.FEATURE_DISABLED,
+                        new CalleeMetadata.Builder()
+                        .setCallbackInvokeTimeMillis(SystemClock.elapsedRealtime())
+                        .build());
+            } else if (featureName.equals("error")) {
+                throw new IllegalStateException();
+            } else {
+                throw new UnsupportedOperationException();
+            }
+        }
+
+        @Override
+        public void logApiCallStats(
+                String sdkPackageName,
+                int apiName,
+                long latencyMillis,
+                long rpcCallLatencyMillis,
+                long rpcReturnLatencyMillis,
+                int responseCode) {
+            mLogApiStatsCalled = true;
+        }
+    }
+    private static class TestServiceBinder
+            extends AbstractServiceBinder<IOnDevicePersonalizationManagingService> {
+        private final IOnDevicePersonalizationManagingService mService;
+
+        TestServiceBinder(IOnDevicePersonalizationManagingService service) {
+            mService = service;
+        }
+
+        @Override
+        public IOnDevicePersonalizationManagingService getService(Executor executor) {
+            return mService;
+        }
+
+        @Override
+        public void unbindFromService() {}
+    }
+
+}
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManagerTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManagerTest.java
index 3698076a..d356c195 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManagerTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/OnDevicePersonalizationSystemEventManagerTest.java
@@ -21,6 +21,7 @@ import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
@@ -189,6 +190,14 @@ public final class OnDevicePersonalizationSystemEventManagerTest {
             }
         }
 
+        @Override
+        public void isFeatureEnabled(
+                String featureName,
+                CallerMetadata metadata,
+                IIsFeatureEnabledCallback callback) {
+            throw new UnsupportedOperationException();
+        }
+
         @Override
         public void logApiCallStats(
                 String sdkPackageName,
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/RemoteDataTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/RemoteDataTest.java
index 2334f3ff..a7cdcc09 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/RemoteDataTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/RemoteDataTest.java
@@ -72,7 +72,7 @@ public class RemoteDataTest {
         assertNull(mRemoteData.get("z"));
 
         mRemoteDataService.mLatch.await();
-        assertThat(mRemoteDataService.mResponseCode).isEqualTo(Constants.STATUS_INTERNAL_ERROR);
+        assertThat(mRemoteDataService.mResponseCode).isEqualTo(Constants.STATUS_SERVICE_FAILED);
     }
 
     @Test
@@ -148,7 +148,7 @@ public class RemoteDataTest {
             if (key.equals("z")) {
                 // Raise expected error.
                 try {
-                    callback.onError(Constants.STATUS_INTERNAL_ERROR);
+                    callback.onError(Constants.STATUS_SERVICE_FAILED);
                 } catch (RemoteException e) {
                     // Ignored.
                 }
diff --git a/tests/manualtests/AndroidTest.xml b/tests/manualtests/AndroidTest.xml
index abc35ef1..17aafecb 100644
--- a/tests/manualtests/AndroidTest.xml
+++ b/tests/manualtests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OnDevicePersonalizationManualTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false"/>
         <option name="package" value="com.android.ondevicepersonalization.manualtests"/>
diff --git a/tests/plugintests/AndroidTest.xml b/tests/plugintests/AndroidTest.xml
index fbd396c9..a5277db8 100644
--- a/tests/plugintests/AndroidTest.xml
+++ b/tests/plugintests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OnDevicePersonalizationPluginTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" /> <!-- Allow hidden API uses -->
         <option name="package" value="com.android.ondevicepersonalization.plugintests"/>
diff --git a/tests/servicetests/Android.bp b/tests/servicetests/Android.bp
index da853803..b3e8efff 100644
--- a/tests/servicetests/Android.bp
+++ b/tests/servicetests/Android.bp
@@ -48,6 +48,7 @@ android_test {
         "androidx.test.ext.truth",
         "androidx.test.rules",
         "federated-compute-java-proto-lite",
+        "guava",
         "mockito-target-extended-minus-junit4",
         "kotlin-stdlib",
         "kotlin-test",
diff --git a/tests/servicetests/AndroidTest.xml b/tests/servicetests/AndroidTest.xml
index ade3b5de..e1be4b31 100644
--- a/tests/servicetests/AndroidTest.xml
+++ b/tests/servicetests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OnDevicePersonalizationManagingServicesTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" /> <!-- Allow hidden API uses -->
         <option name="package" value="com.android.ondevicepersonalization.servicetests"/>
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/FeatureStatusManagerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/FeatureStatusManagerTest.java
new file mode 100644
index 00000000..f222dc5b
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/FeatureStatusManagerTest.java
@@ -0,0 +1,150 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.CalleeMetadata;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.quality.Strictness;
+
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.concurrent.CountDownLatch;
+import java.util.function.Supplier;
+
+@RunWith(JUnit4.class)
+public class FeatureStatusManagerTest {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = FeatureStatusManagerTest.class.getSimpleName();
+    private static final long SERVICE_ENTRY_TIME = 100L;
+    private final CountDownLatch mLatch = new CountDownLatch(1);
+    private volatile boolean mCallbackSuccess;
+    private volatile int mResult;
+
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this)
+                    .spyStatic(FlagsFactory.class)
+                    .setStrictness(Strictness.LENIENT)
+                    .build();
+
+    @Before
+    public void setUp() {
+        ExtendedMockito.doReturn(new TestFlags() {}).when(FlagsFactory::getFlags);
+    }
+
+    @Test
+    public void testEnabledNonFlaggedFeature() {
+        Set<String> nonFlaggedFeatures = new HashSet<>();
+        nonFlaggedFeatures.add("featureName");
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        new HashMap<>(),
+                        nonFlaggedFeatures);
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_ENABLED);
+    }
+
+    @Test
+    public void testEnabledFlaggedFeature() {
+        Map<String, Supplier<Boolean>> flaggedFeatures = new HashMap<>();
+
+        flaggedFeatures.put("featureName", (new TestFlags() {})::getEnabledFeature);
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        flaggedFeatures,
+                        new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_ENABLED);
+    }
+
+    @Test
+    public void testDisabledFlaggedFeature() {
+        Map<String, Supplier<Boolean>> flaggedFeatures = new HashMap<>();
+
+        flaggedFeatures.put("featureName", (new TestFlags() {})::getDisabledFeature);
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        flaggedFeatures,
+                        new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_DISABLED);
+    }
+
+    @Test
+    public void testUnsupportedFeature() {
+        FeatureStatusManager featureStatusManager = new FeatureStatusManager(
+                FlagsFactory.getFlags(),
+                new HashMap<>(),
+                new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_UNSUPPORTED);
+    }
+
+    @Test
+    public void testGetFeatureStatusAndSendResult() throws InterruptedException {
+        FeatureStatusManager.getFeatureStatusAndSendResult(
+                "featureName",
+                SERVICE_ENTRY_TIME,
+                new TestIsFeatureEnabledCallback());
+        mLatch.await();
+
+        assertTrue(mCallbackSuccess);
+        assertEquals(mResult, OnDevicePersonalizationManager.FEATURE_UNSUPPORTED);
+    }
+
+    class TestFlags implements Flags {
+
+        public boolean getDisabledFeature() {
+            return false;
+        }
+
+        public boolean getEnabledFeature() {
+            return true;
+        }
+    }
+
+    class TestIsFeatureEnabledCallback extends IIsFeatureEnabledCallback.Stub {
+        @Override
+        public void onResult(int result, CalleeMetadata calleeMetadata) {
+            sLogger.d(TAG + " : onResult callback.");
+            mCallbackSuccess = true;
+            mResult = result;
+            mLatch.countDown();
+        }
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
index 06ccd777..ba4e36ae 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
@@ -19,27 +19,36 @@ package com.android.ondevicepersonalization.services;
 import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
 
 import android.app.job.JobScheduler;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
-import android.content.pm.PackageManager;
 
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
-import com.android.modules.utils.testing.TestableDeviceConfig;
 import com.android.odp.module.common.DeviceUtils;
 import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
 
+import com.google.common.collect.ImmutableList;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
 
@@ -48,16 +57,43 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
 @RunWith(JUnit4.class)
 public class OnDevicePersonalizationBroadcastReceiverTests {
+    private static final Intent BOOT_COMPLETED_INTENT = new Intent(Intent.ACTION_BOOT_COMPLETED);
+
+    /** All the jobs that the BroadcastReceiver is responsible for scheduling. */
+    private static final ImmutableList<Integer> JOB_IDS =
+            ImmutableList.of(
+                    // Job Ids for ODP maintenance jobs that are scheduled/cancelled by the
+                    // receiver.
+                    MAINTENANCE_TASK_JOB_ID,
+                    AGGREGATE_ERROR_DATA_REPORTING_JOB_ID,
+                    USER_DATA_COLLECTION_ID,
+                    // Job Ids for various Mdd Jobs
+                    MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID,
+                    MDD_CHARGING_PERIODIC_TASK_JOB_ID,
+                    MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID,
+                    MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID);
+
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
+    // Use direct executor to keep all work sequential for the tests
+    private final ListeningExecutorService mDirectExecutorService =
+            MoreExecutors.newDirectExecutorService();
+
+    private final JobScheduler mJobScheduler = mContext.getSystemService(JobScheduler.class);
+
+    private final OnDevicePersonalizationBroadcastReceiver mReceiverUnderTest =
+            new OnDevicePersonalizationBroadcastReceiver(mDirectExecutorService);
+    @Mock private Flags mMockFlags;
+
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule =
             new ExtendedMockitoRule.Builder(this)
-                    .addStaticMockFixtures(TestableDeviceConfig::new)
+                    .spyStatic(FlagsFactory.class)
                     .spyStatic(DeviceUtils.class)
                     .spyStatic(OnDevicePersonalizationMaintenanceJob.class)
                     .setStrictness(Strictness.LENIENT)
@@ -65,188 +101,79 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
 
     @Before
     public void setup() throws Exception {
-        PhFlagsTestUtil.setUpDeviceConfigPermissions();
-        PhFlagsTestUtil.disableGlobalKillSwitch();
+        ExtendedMockito.doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
 
-        // By default, disable SPE.
-        PhFlagsTestUtil.setSpePilotJobEnabled(false);
+        // By default, disable SPE and aggregate error reporting.
+        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
 
         ExtendedMockito.doReturn(true).when(() -> DeviceUtils.isOdpSupported(any()));
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
-        jobScheduler.cancel(OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID);
-        jobScheduler.cancel(OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID);
-        jobScheduler.cancel(
-                OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID);
-        jobScheduler.cancel(OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID);
-        jobScheduler.cancel(OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID);
-        jobScheduler.cancel(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID);
+
+        // Cancel any pending maintenance and MDD jobs
+        for (int jobId : JOB_IDS) {
+            mJobScheduler.cancel(jobId);
+        }
     }
 
     @Test
     public void testOnReceive() {
-        // Use direct executor to keep all work sequential for the tests
-        ListeningExecutorService executorService = MoreExecutors.newDirectExecutorService();
-        MobileDataDownloadFactory.getMdd(mContext, executorService, executorService);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(true);
+        MobileDataDownloadFactory.getMdd(mContext, mDirectExecutorService, mDirectExecutorService);
 
-        OnDevicePersonalizationBroadcastReceiver receiver =
-                new OnDevicePersonalizationBroadcastReceiver(executorService);
+        mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
-        Intent intent = new Intent(Intent.ACTION_BOOT_COMPLETED);
-        receiver.onReceive(mContext, intent);
-
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
-
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID)
-                        != null);
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext));
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID)
-                        != null);
-        // MDD tasks
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID)
-                        != null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID)
-                        != null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig
-                                        .MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID)
-                        != null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig
-                                        .MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID)
-                        != null);
+        assertAllJobsScheduled();
     }
 
     @Test
     public void testOnReceiveKillSwitchOn() {
-        PhFlagsTestUtil.enableGlobalKillSwitch();
-        // Use direct executor to keep all work sequential for the tests
-        ListeningExecutorService executorService = MoreExecutors.newDirectExecutorService();
-        OnDevicePersonalizationBroadcastReceiver receiver =
-                new OnDevicePersonalizationBroadcastReceiver(executorService);
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
 
-        Intent intent = new Intent(Intent.ACTION_BOOT_COMPLETED);
-        receiver.onReceive(mContext, intent);
+        mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
-
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID)
-                        == null);
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID)
-                        == null);
-        // MDD tasks
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
+        assertNoJobsScheduled();
     }
 
     @Test
     public void testOnReceiveDeviceNotSupported() {
         ExtendedMockito.doReturn(false).when(() -> DeviceUtils.isOdpSupported(any()));
-        // Use direct executor to keep all work sequential for the tests
-        ListeningExecutorService executorService = MoreExecutors.newDirectExecutorService();
-        OnDevicePersonalizationBroadcastReceiver receiver =
-                new OnDevicePersonalizationBroadcastReceiver(executorService);
-
-        Intent intent = new Intent(Intent.ACTION_BOOT_COMPLETED);
-        receiver.onReceive(mContext, intent);
 
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
+        mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID)
-                        == null);
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID)
-                        == null);
-        // MDD tasks
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                        OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
+        assertNoJobsScheduled();
     }
 
     @Test
     public void testOnReceiveInvalidIntent() {
-        OnDevicePersonalizationBroadcastReceiver receiver =
-                new OnDevicePersonalizationBroadcastReceiver();
+        mReceiverUnderTest.onReceive(mContext, new Intent(Intent.ACTION_DIAL_EMERGENCY));
 
-        Intent intent = new Intent(Intent.ACTION_DIAL_EMERGENCY);
-        receiver.onReceive(mContext, intent);
-
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
-
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID)
-                        == null);
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
-        assertTrue(
-                jobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID)
-                        == null);
-        // MDD tasks
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig
-                                        .MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
-        assertTrue(
-                jobScheduler.getPendingJob(
-                                OnDevicePersonalizationConfig
-                                        .MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID)
-                        == null);
+        assertNoJobsScheduled();
     }
 
     @Test
     public void testEnableReceiver() {
-        assertTrue(OnDevicePersonalizationBroadcastReceiver.enableReceiver(mContext));
         ComponentName componentName =
                 new ComponentName(mContext, OnDevicePersonalizationBroadcastReceiver.class);
-        final PackageManager pm = mContext.getPackageManager();
-        final int result = pm.getComponentEnabledSetting(componentName);
+
+        assertTrue(OnDevicePersonalizationBroadcastReceiver.enableReceiver(mContext));
+        int result = mContext.getPackageManager().getComponentEnabledSetting(componentName);
         assertEquals(COMPONENT_ENABLED_STATE_ENABLED, result);
     }
+
+    private void assertAllJobsScheduled() {
+        for (int jobId : JOB_IDS) {
+            assertNotNull(mJobScheduler.getPendingJob(jobId));
+        }
+    }
+
+    private void assertNoJobsScheduled() {
+        for (int jobId : JOB_IDS) {
+            assertNull(mJobScheduler.getPendingJob(jobId));
+        }
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
index f6deec17..f3fdbcb2 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
@@ -38,6 +38,7 @@ import android.adservices.ondevicepersonalization.Constants;
 import android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceRequest;
 import android.adservices.ondevicepersonalization.ExecuteOptionsParcel;
 import android.adservices.ondevicepersonalization.aidl.IExecuteCallback;
+import android.adservices.ondevicepersonalization.aidl.IIsFeatureEnabledCallback;
 import android.adservices.ondevicepersonalization.aidl.IRegisterMeasurementEventCallback;
 import android.adservices.ondevicepersonalization.aidl.IRequestSurfacePackageCallback;
 import android.content.ComponentName;
@@ -48,6 +49,7 @@ import android.os.Binder;
 import android.os.Bundle;
 import android.os.IBinder;
 import android.os.PersistableBundle;
+import android.os.RemoteException;
 import android.view.SurfaceControlViewHost;
 
 import androidx.test.core.app.ApplicationProvider;
@@ -79,6 +81,11 @@ import java.util.concurrent.TimeoutException;
 
 @RunWith(JUnit4.class)
 public class OnDevicePersonalizationManagingServiceTest {
+    private static final ComponentName TEST_HANDLER_COMPONENT =
+            new ComponentName(
+                    ApplicationProvider.getApplicationContext(),
+                    "com.test.TestPersonalizationHandler");
+
     @Rule public final ServiceTestRule serviceRule = new ServiceTestRule();
     private final Context mContext = spy(ApplicationProvider.getApplicationContext());
     private OnDevicePersonalizationManagingServiceDelegate mService;
@@ -105,6 +112,9 @@ public class OnDevicePersonalizationManagingServiceTest {
         mService = new OnDevicePersonalizationManagingServiceDelegate(mContext);
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
         when(mMockFlags.getMaxIntValuesLimit()).thenReturn(100);
+        // Flags accessed within the maintenance job service.
+        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
         ExtendedMockito.doReturn(true).when(() -> DeviceUtils.isOdpSupported(any()));
         ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
         doReturn(true).when(mUserPrivacyStatus).isMeasurementEnabled();
@@ -139,9 +149,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -156,9 +164,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -170,11 +176,12 @@ public class OnDevicePersonalizationManagingServiceTest {
         var callback = new ExecuteCallback();
         mService.execute(
                 mContext.getPackageName(),
-                new ComponentName(mContext.getPackageName(), "com.test.TestPersonalizationHandler"),
+                TEST_HANDLER_COMPONENT,
                 createWrappedAppParams(),
                 new CallerMetadata.Builder().build(),
                 ExecuteOptionsParcel.DEFAULT,
                 callback);
+
         callback.await();
         assertTrue(callback.mWasInvoked);
     }
@@ -185,13 +192,15 @@ public class OnDevicePersonalizationManagingServiceTest {
         ExecuteOptionsParcel options =
                 new ExecuteOptionsParcel(
                         ExecuteInIsolatedServiceRequest.OutputSpec.OUTPUT_TYPE_BEST_VALUE, 50);
+
         mService.execute(
                 mContext.getPackageName(),
-                new ComponentName(mContext.getPackageName(), "com.test.TestPersonalizationHandler"),
+                TEST_HANDLER_COMPONENT,
                 createWrappedAppParams(),
                 new CallerMetadata.Builder().build(),
                 options,
                 callback);
+
         callback.await();
         assertTrue(callback.mWasInvoked);
     }
@@ -207,9 +216,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 options,
@@ -224,9 +231,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 "abc",
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -241,9 +246,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 null,
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -258,9 +261,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 "",
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -275,7 +276,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                null,
+                                /* handler= */ null,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -320,9 +321,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 null,
                                 ExecuteOptionsParcel.DEFAULT,
@@ -336,9 +335,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -356,9 +353,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -376,9 +371,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 () ->
                         mService.execute(
                                 mContext.getPackageName(),
-                                new ComponentName(
-                                        mContext.getPackageName(),
-                                        "com.test.TestPersonalizationHandler"),
+                                TEST_HANDLER_COMPONENT,
                                 createWrappedAppParams(),
                                 new CallerMetadata.Builder().build(),
                                 ExecuteOptionsParcel.DEFAULT,
@@ -430,6 +423,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 50,
                 new CallerMetadata.Builder().build(),
                 callback);
+
         callback.await();
         assertTrue(callback.mWasInvoked);
     }
@@ -587,6 +581,7 @@ public class OnDevicePersonalizationManagingServiceTest {
                 Bundle.EMPTY,
                 new CallerMetadata.Builder().build(),
                 callback);
+
         callback.await();
         assertTrue(callback.mWasInvoked);
     }
@@ -614,7 +609,55 @@ public class OnDevicePersonalizationManagingServiceTest {
         verify(mMockMdd).schedulePeriodicBackgroundTasks();
     }
 
-    private Bundle createWrappedAppParams() throws Exception {
+    @Test
+    public void testEnabledGlobalKillOnIsFeatureEnabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        assertThrows(
+                IllegalStateException.class,
+                () ->
+                        mService.isFeatureEnabled(
+                                "featureName",
+                                new CallerMetadata.Builder().build(),
+                                new IsFeatureEnabledCallback()));
+    }
+
+    @Test
+    public void testUnsupportedDeviceOnIsFeatureEnabled() {
+        ExtendedMockito.doReturn(false).when(() -> DeviceUtils.isOdpSupported(any()));
+        assertThrows(
+                IllegalStateException.class,
+                () ->
+                        mService.isFeatureEnabled(
+                                "featureName",
+                                new CallerMetadata.Builder().build(),
+                                new IsFeatureEnabledCallback()));
+    }
+
+    @Test
+    public void testDisabledFlagOnIsFeatureEnabled() {
+        when(mMockFlags.isFeatureEnabledApiEnabled()).thenReturn(false);
+        assertThrows(
+                IllegalStateException.class,
+                () ->
+                        mService.isFeatureEnabled(
+                                "featureName",
+                                new CallerMetadata.Builder().build(),
+                                new IsFeatureEnabledCallback()));
+    }
+
+    @Test
+    public void testIsFeatureEnabled() throws Exception {
+        when(mMockFlags.isFeatureEnabledApiEnabled()).thenReturn(true);
+        var callback = new IsFeatureEnabledCallback();
+        mService.isFeatureEnabled(
+                "featureName",
+                new CallerMetadata.Builder().build(),
+                callback);
+        callback.await();
+        assertTrue(callback.mWasInvoked);
+    }
+
+    private static Bundle createWrappedAppParams() throws Exception {
         Bundle wrappedParams = new Bundle();
         ByteArrayParceledSlice buffer =
                 new ByteArrayParceledSlice(
@@ -623,7 +666,7 @@ public class OnDevicePersonalizationManagingServiceTest {
         return wrappedParams;
     }
 
-    static class ExecuteCallback extends IExecuteCallback.Stub {
+    private static class ExecuteCallback extends IExecuteCallback.Stub {
         public boolean mWasInvoked = false;
         public boolean mSuccess = false;
         public boolean mError = false;
@@ -662,7 +705,7 @@ public class OnDevicePersonalizationManagingServiceTest {
         }
     }
 
-    static class RequestSurfacePackageCallback extends IRequestSurfacePackageCallback.Stub {
+    private static class RequestSurfacePackageCallback extends IRequestSurfacePackageCallback.Stub {
         public boolean mWasInvoked = false;
         public boolean mSuccess = false;
         public boolean mError = false;
@@ -698,7 +741,8 @@ public class OnDevicePersonalizationManagingServiceTest {
         }
     }
 
-    static class RegisterMeasurementEventCallback extends IRegisterMeasurementEventCallback.Stub {
+    private static class RegisterMeasurementEventCallback
+            extends IRegisterMeasurementEventCallback.Stub {
         public boolean mError = false;
         public boolean mSuccess = false;
         public boolean mWasInvoked = false;
@@ -724,4 +768,19 @@ public class OnDevicePersonalizationManagingServiceTest {
             mLatch.await();
         }
     }
+
+    private static class IsFeatureEnabledCallback extends IIsFeatureEnabledCallback.Stub {
+        public boolean mWasInvoked = false;
+        private final CountDownLatch mLatch = new CountDownLatch(1);
+
+        @Override
+        public void onResult(int result, CalleeMetadata calleeMetadata) throws RemoteException {
+            mWasInvoked = true;
+            mLatch.countDown();
+        }
+
+        public void await() throws Exception {
+            mLatch.await();
+        }
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
index 5069fe9c..dfe30d2b 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
@@ -24,13 +24,20 @@ import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGA
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_THRESHOLD;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_TTL_DAYS;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_APP_INSTALL_HISTORY_TTL_MILLIS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_CALLER_APP_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_CLIENT_ERROR_LOGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ISOLATED_SERVICE_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_MODULE_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_OUTPUT_DATA_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SPE_PILOT_JOB_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_TRUSTED_PARTNER_APPS_LIST;
@@ -45,20 +52,26 @@ import static com.android.ondevicepersonalization.services.Flags.WEB_TRIGGER_FLO
 import static com.android.ondevicepersonalization.services.Flags.WEB_VIEW_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.APP_INSTALL_HISTORY_TTL;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_PATH;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_CALLER_APP_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_GLOBAL_KILL_SWITCH;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
@@ -67,6 +80,7 @@ import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_MODUL
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_SPE_PILOT_JOB_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_OUTPUT_DATA_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_RENDER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
@@ -77,14 +91,20 @@ import static com.google.common.truth.Truth.assertThat;
 
 import android.provider.DeviceConfig;
 
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
 import com.android.modules.utils.build.SdkLevel;
 import com.android.modules.utils.testing.TestableDeviceConfig;
 
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
+import org.junit.runner.RunWith;
 
 /** Unit tests for {@link com.android.ondevicepersonalization.services.PhFlags} */
+@RunWith(AndroidJUnit4.class)
+@Ignore("b/375661140")
 public class PhFlagsTest {
     @Rule
     public final TestableDeviceConfig.TestableDeviceConfigRule mDeviceConfigRule =
@@ -700,7 +720,7 @@ public class PhFlagsTest {
     }
 
     @Test
-    public void testAggregateErrorReportingInterval() {
+    public void testAggregateErrorReportingIntervalInHours() {
         int testValue = 4;
 
         DeviceConfig.setProperty(
@@ -721,6 +741,114 @@ public class PhFlagsTest {
                 .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS);
     }
 
+    @Test
+    public void testAllowUnencryptedAggregatedErrorReportingPayload() {
+        boolean testValue = !DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
+                Boolean.toString(testValue),
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload())
+                .isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
+                Boolean.toString(DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload())
+                .isEqualTo(DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD);
+    }
+
+    @Test
+    public void testAggregatedErrorReportingHttpTimeoutSeconds() {
+        int testValue = 10;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS,
+                Integer.toString(testValue),
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingHttpTimeoutSeconds())
+                .isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS,
+                Integer.toString(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours())
+                .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS);
+    }
+
+    @Test
+    public void testAggregatedErrorReportingHttpRetryLimit() {
+        int testValue = 5;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT,
+                Integer.toString(testValue),
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingHttpRetryLimit())
+                .isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT,
+                Integer.toString(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours())
+                .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT);
+    }
+
+    @Test
+    public void testEncryptionKeyFetchUrl() {
+        String testValue = "foo/bar";
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ENCRYPTION_KEY_URL,
+                testValue,
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getEncryptionKeyFetchUrl()).isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ENCRYPTION_KEY_URL,
+                DEFAULT_ENCRYPTION_KEY_URL,
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getEncryptionKeyFetchUrl())
+                .isEqualTo(DEFAULT_ENCRYPTION_KEY_URL);
+    }
+
+    @Test
+    public void testEncryptionKeyMaxAgeSeconds() {
+        Long testValue = 100L;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS,
+                Long.toString(testValue),
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getEncryptionKeyMaxAgeSeconds()).isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS,
+                Long.toString(DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getEncryptionKeyMaxAgeSeconds())
+                .isEqualTo(DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS);
+    }
+
     @Test
     public void testGetAdservicesIpcCallTimeoutInMillis() {
         long testTimeoutValue = 100L;
@@ -742,4 +870,38 @@ public class PhFlagsTest {
         assertThat(FlagsFactory.getFlags().getAdservicesIpcCallTimeoutInMillis())
                 .isEqualTo(DEFAULT_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS);
     }
+
+    @Test
+    public void testIsPluginProcessRunnerEnabled() {
+        // read a stable flag value and verify it's equal to the default value.
+        boolean stableValue = FlagsFactory.getFlags().isPluginProcessRunnerEnabled();
+        assertThat(stableValue).isEqualTo(DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED);
+
+        // override the value in device config.
+        boolean overrideEnabled = !stableValue;
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_PLUGIN_PROCESS_RUNNER_ENABLED,
+                Boolean.toString(overrideEnabled),
+                /* makeDefault= */ false);
+
+        // the flag value remains stable
+        assertThat(FlagsFactory.getFlags().isPluginProcessRunnerEnabled()).isEqualTo(
+                overrideEnabled);
+    }
+
+    @Test
+    public void testIsFeatureEnabledApiEnabled() {
+        boolean stableValue = FlagsFactory.getFlags().isFeatureEnabledApiEnabled();
+        assertThat(stableValue).isEqualTo(DEFAULT_IS_FEATURE_ENABLED_API_ENABLED);
+
+        boolean overrideEnabled = !stableValue;
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                Boolean.toString(overrideEnabled),
+                /* makeDefault= */ false);
+
+        assertThat(FlagsFactory.getFlags().isFeatureEnabledApiEnabled()).isEqualTo(overrideEnabled);
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
index c4efe557..49c0d291 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
@@ -17,6 +17,7 @@
 package com.android.ondevicepersonalization.services;
 
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_CALLER_APP_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_GLOBAL_KILL_SWITCH;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_ALLOW_LIST;
@@ -32,6 +33,9 @@ public class PhFlagsTestUtil {
     private static final String WRITE_DEVICE_CONFIG_PERMISSION =
             "android.permission.WRITE_DEVICE_CONFIG";
 
+    private static final String WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION =
+            "android.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG";
+
     private static final String READ_DEVICE_CONFIG_PERMISSION =
             "android.permission.READ_DEVICE_CONFIG";
 
@@ -43,8 +47,8 @@ public class PhFlagsTestUtil {
      */
     public static void setUpDeviceConfigPermissions() throws Exception {
         InstrumentationRegistry.getInstrumentation().getUiAutomation().adoptShellPermissionIdentity(
-                WRITE_DEVICE_CONFIG_PERMISSION, READ_DEVICE_CONFIG_PERMISSION,
-                MONITOR_DEVICE_CONFIG_ACCESS);
+                WRITE_DEVICE_CONFIG_PERMISSION, WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION,
+                READ_DEVICE_CONFIG_PERMISSION, MONITOR_DEVICE_CONFIG_ACCESS);
     }
 
     public static void enableGlobalKillSwitch() {
@@ -109,7 +113,7 @@ public class PhFlagsTestUtil {
                 /* makeDefault */ false);
     }
 
-    /** Set up output data allow list in device config */
+    /** Set if shared isolated process feature is enabled. */
     public static void setSharedIsolatedProcessFeatureEnabled(boolean enabled) {
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -118,7 +122,7 @@ public class PhFlagsTestUtil {
                 /* makeDefault */ false);
     }
 
-    /** Sets up if SPE is enabled for pilot jobs. */
+    /** Sets if SPE is enabled for pilot jobs. */
     public static void setSpePilotJobEnabled(boolean enabled) {
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -126,4 +130,13 @@ public class PhFlagsTestUtil {
                 Boolean.toString(enabled),
                 /* makeDefault */ false);
     }
+
+    /** Sets if aggregate error reporting is enabled or not. */
+    public static void setAggregatedErrorReportingEnabled(boolean enabled) {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ENABLE_AGGREGATED_ERROR_REPORTING,
+                Boolean.toString(enabled),
+                /* makeDefault */ false);
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImplTest.java
index 35f8b144..aebc9f86 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImplTest.java
@@ -26,7 +26,6 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.verify;
 
@@ -81,6 +80,7 @@ import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Map;
+import java.util.Set;
 import java.util.concurrent.CountDownLatch;
 
 @RunWith(JUnit4.class)
@@ -134,6 +134,26 @@ public class DataAccessServiceImplTest {
         mServiceProxy = IDataAccessService.Stub.asInterface(mServiceImpl);
     }
 
+    @Test
+    public void testStatusCodes() {
+        Set<Integer> allDataAccessCodes = new HashSet<>();
+        //add them all and check size, insuring that there are no duplicates
+        allDataAccessCodes.add(STATUS_SUCCESS);
+        allDataAccessCodes.add(Constants.STATUS_KEY_NOT_FOUND);
+        allDataAccessCodes.add(Constants.STATUS_SUCCESS_EMPTY_RESULT);
+        allDataAccessCodes.add(Constants.STATUS_PERMISSION_DENIED);
+        allDataAccessCodes.add(Constants.STATUS_LOCAL_DATA_READ_ONLY);
+        allDataAccessCodes.add(Constants.STATUS_REQUEST_TIMESTAMPS_INVALID);
+        allDataAccessCodes.add(Constants.STATUS_MODEL_TABLE_ID_INVALID);
+        allDataAccessCodes.add(Constants.STATUS_MODEL_DB_LOOKUP_FAILED);
+        allDataAccessCodes.add(Constants.STATUS_MODEL_LOOKUP_FAILURE);
+        allDataAccessCodes.add(Constants.STATUS_DATA_ACCESS_UNSUPPORTED_OP);
+        allDataAccessCodes.add(Constants.STATUS_DATA_ACCESS_FAILURE);
+        allDataAccessCodes.add(Constants.STATUS_LOCAL_WRITE_DATA_ACCESS_FAILURE);
+
+        assertThat(allDataAccessCodes).hasSize(12);
+    }
+
     @Test
     public void testRemoteDataLookup() throws Exception {
         addTestData();
@@ -346,7 +366,7 @@ public class DataAccessServiceImplTest {
     }
 
     @Test
-    public void testLocalDataThrowsNotIncluded() {
+    public void testLocalDataNotIncludedErrorCode() throws Exception {
         mServiceImpl = new DataAccessServiceImpl(
                 mService, mApplicationContext, null,
                 /* localDataPermission */ DataAccessPermission.DENIED,
@@ -356,26 +376,42 @@ public class DataAccessServiceImplTest {
         Bundle params = new Bundle();
         params.putStringArray(Constants.EXTRA_LOOKUP_KEYS, new String[]{"localkey"});
         params.putByteArray(Constants.EXTRA_VALUE, new byte[100]);
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
+
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_LOCAL_DATA_LOOKUP,
                 params,
-                new TestCallback()));
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
+
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_LOCAL_DATA_KEYSET,
                 params,
-                new TestCallback()));
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
+
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_LOCAL_DATA_PUT,
                 params,
-                new TestCallback()));
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
+
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_LOCAL_DATA_REMOVE,
                 params,
-                new TestCallback()));
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
     }
 
     @Test
-    public void testLocalDataThrowsReadOnly() {
+    public void testLocalDataReadOnlyErrorCode() throws Exception {
         mServiceImpl = new DataAccessServiceImpl(
                 mService, mApplicationContext, null,
                 /* localDataPermission */ DataAccessPermission.READ_ONLY,
@@ -385,14 +421,17 @@ public class DataAccessServiceImplTest {
         Bundle params = new Bundle();
         params.putStringArray(Constants.EXTRA_LOOKUP_KEYS, new String[]{"localkey"});
         params.putByteArray(Constants.EXTRA_VALUE, new byte[100]);
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
-                Constants.DATA_ACCESS_OP_LOCAL_DATA_PUT,
-                params,
-                new TestCallback()));
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
-                Constants.DATA_ACCESS_OP_LOCAL_DATA_REMOVE,
-                params,
-                new TestCallback()));
+        mServiceProxy.onRequest(
+                Constants.DATA_ACCESS_OP_LOCAL_DATA_PUT, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_LOCAL_DATA_READ_ONLY);
+
+        mServiceProxy.onRequest(
+                Constants.DATA_ACCESS_OP_LOCAL_DATA_REMOVE, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_LOCAL_DATA_READ_ONLY);
     }
 
     @Test
@@ -415,14 +454,30 @@ public class DataAccessServiceImplTest {
     }
 
     @Test
-    public void testGetRequestsBadInput() {
+    public void testGetRequestsBadInput() throws Exception {
         addTestData();
         Bundle params = new Bundle();
         params.putLongArray(Constants.EXTRA_LOOKUP_KEYS, new long[]{0L});
-        assertThrows(IllegalArgumentException.class, () -> mServiceProxy.onRequest(
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_GET_REQUESTS,
                 params,
-                new TestCallback()));
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_REQUEST_TIMESTAMPS_INVALID);
+    }
+
+    @Test
+    public void testDataAccessBadOp() throws Exception {
+        addTestData();
+        Bundle params = new Bundle();
+        mServiceProxy.onRequest(
+                -1,
+                params,
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_DATA_ACCESS_UNSUPPORTED_OP);
     }
 
     @Test
@@ -448,18 +503,21 @@ public class DataAccessServiceImplTest {
     }
 
     @Test
-    public void testGetJoinedEventsBadInput() {
+    public void testGetJoinedEventsBadInput() throws Exception {
         addTestData();
         Bundle params = new Bundle();
         params.putLongArray(Constants.EXTRA_LOOKUP_KEYS, new long[]{0L});
-        assertThrows(IllegalArgumentException.class, () -> mServiceProxy.onRequest(
+        mServiceProxy.onRequest(
                 Constants.DATA_ACCESS_OP_GET_JOINED_EVENTS,
                 params,
-                new TestCallback()));
+                new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_REQUEST_TIMESTAMPS_INVALID);
     }
 
     @Test
-    public void testEventDataThrowsNotIncluded() {
+    public void testEventDataNotIncludedErrorCode() throws Exception {
         mServiceImpl = new DataAccessServiceImpl(
                 mService, mApplicationContext, null,
                 /* localDataPermission */ DataAccessPermission.READ_WRITE,
@@ -468,26 +526,28 @@ public class DataAccessServiceImplTest {
         mServiceProxy = IDataAccessService.Stub.asInterface(mServiceImpl);
         Bundle params = new Bundle();
         params.putLongArray(Constants.EXTRA_LOOKUP_KEYS, new long[]{1L, 2L});
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
-                Constants.DATA_ACCESS_OP_GET_REQUESTS,
-                params,
-                new TestCallback()));
-        assertThrows(IllegalStateException.class, () -> mServiceProxy.onRequest(
-                Constants.DATA_ACCESS_OP_GET_JOINED_EVENTS,
-                params,
-                new TestCallback()));
+
+        mServiceProxy.onRequest(Constants.DATA_ACCESS_OP_GET_REQUESTS, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
+
+        mServiceProxy.onRequest(
+                Constants.DATA_ACCESS_OP_GET_JOINED_EVENTS, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_PERMISSION_DENIED);
     }
 
     @Test
-    public void testGetModelFileDescriptor_badInput() {
+    public void testGetModelFileDescriptor_badInput() throws Exception {
         addTestData();
         Bundle params = new Bundle();
 
-        assertThrows(
-                NullPointerException.class,
-                () ->
-                        mServiceProxy.onRequest(
-                                Constants.DATA_ACCESS_OP_GET_MODEL, params, new TestCallback()));
+        mServiceProxy.onRequest(Constants.DATA_ACCESS_OP_GET_MODEL, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_KEY_NOT_FOUND);
     }
 
     @Test
@@ -509,6 +569,23 @@ public class DataAccessServiceImplTest {
         assertNotNull(modelFd);
     }
 
+    @Test
+    public void testGetModelFileDescriptor_tableId_fail() throws Exception {
+        addTestData();
+        Bundle params = new Bundle();
+        ModelId modelId =
+                new ModelId.Builder()
+                        .setTableId(-1)
+                        .setKey("bad-key2")
+                        .build();
+        params.putParcelable(Constants.EXTRA_MODEL_ID, modelId);
+
+        mServiceProxy.onRequest(Constants.DATA_ACCESS_OP_GET_MODEL, params, new TestCallback());
+        mLatch.await();
+        assertTrue(mOnErrorCalled);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_MODEL_TABLE_ID_INVALID);
+    }
+
     @Test
     public void testGetModelFileDescriptor_remoteTable_fail() throws Exception {
         addTestData();
@@ -523,7 +600,7 @@ public class DataAccessServiceImplTest {
         mServiceProxy.onRequest(Constants.DATA_ACCESS_OP_GET_MODEL, params, new TestCallback());
         mLatch.await();
         assertTrue(mOnErrorCalled);
-        assertThat(mErrorCode).isEqualTo(Constants.STATUS_INTERNAL_ERROR);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_MODEL_DB_LOOKUP_FAILED);
     }
 
     @Test
@@ -559,7 +636,7 @@ public class DataAccessServiceImplTest {
         mServiceProxy.onRequest(Constants.DATA_ACCESS_OP_GET_MODEL, params, new TestCallback());
         mLatch.await();
         assertTrue(mOnErrorCalled);
-        assertThat(mErrorCode).isEqualTo(Constants.STATUS_INTERNAL_ERROR);
+        assertThat(mErrorCode).isEqualTo(Constants.STATUS_MODEL_DB_LOOKUP_FAILED);
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
index 91fc9b26..ce11a8a3 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
@@ -39,53 +39,153 @@ import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig;
 
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
+import com.google.common.util.concurrent.SettableFuture;
 
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+import org.junit.runners.Parameterized;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
+import org.mockito.quality.Strictness;
 
-@RunWith(JUnit4.class)
+import java.util.Arrays;
+import java.util.Collection;
+import java.util.List;
+import java.util.Optional;
+
+@RunWith(Parameterized.class)
 public class AggregateErrorDataReportingServiceTest {
     private final Context mContext = ApplicationProvider.getApplicationContext();
     private final JobScheduler mJobScheduler = mContext.getSystemService(JobScheduler.class);
+    private boolean mGetGlobalKillSwitch = false;
+    private boolean mAggregateErrorReportingEnabled = true;
+
+    @Parameterized.Parameter(0)
+    public boolean mAllowUnEncryptedPayload = true;
+
+    @Parameterized.Parameters
+    public static Collection<Object[]> data() {
+        return Arrays.asList(new Object[][] {{false}, {true}});
+    }
 
     private AggregateErrorDataReportingService mService;
 
-    @Mock private Flags mMockFlags;
+    private final Flags mTestFlags = new TestFlags();
+
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
+            .mockStatic(FlagsFactory.class)
+            .setStrictness(Strictness.LENIENT)
+            .build();
+
+    @Mock private AggregatedErrorReportingWorker mMockReportingWorker;
+
+    @Mock private OdpEncryptionKeyManager mMockEncryptionKeyManager;
+
+    @Mock private OdpEncryptionKey mMockEncryptionKey;
 
     @Before
     public void setup() throws Exception {
+        ExtendedMockito.doReturn(mTestFlags).when(FlagsFactory::getFlags);
         MockitoAnnotations.initMocks(this);
 
         mService = spy(new AggregateErrorDataReportingService(new TestInjector()));
         doNothing().when(mService).jobFinished(any(), anyBoolean());
+        FluentFuture<List<OdpEncryptionKey>> fluentFuture =
+                FluentFuture.from(Futures.immediateFuture(List.of(mMockEncryptionKey)));
+        when(mMockEncryptionKeyManager.fetchAndPersistActiveKeys(
+                OdpEncryptionKey.KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true, Optional.empty()))
+                .thenReturn(fluentFuture);
 
         // Setup tests with the global kill switch is disabled and error reporting enabled.
-        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
-        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(true);
         if (mJobScheduler != null) {
             // Cleanup any pending jobs
             mJobScheduler.cancel(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID);
         }
     }
 
+    @Test
+    public void onStartJob_errorReportingEnabled_callsWorker() {
+        // Given that the aggregate error reporting is enabled and the job is
+        // scheduled successfully.
+        OdpEncryptionKey expectedEncryptionKey =
+                mAllowUnEncryptedPayload ? null : mMockEncryptionKey;
+        when(mMockReportingWorker.reportAggregateErrors(any(), any()))
+                .thenReturn(Futures.immediateVoidFuture());
+        assertEquals(
+                JobScheduler.RESULT_SUCCESS,
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+        assertNotNull(
+                mJobScheduler.getPendingJob(
+                        OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
+
+        // When the job is started.
+        boolean result = mService.onStartJob(mock(JobParameters.class));
+
+        // Expect that the worker is called once and the pending job is not cancelled.
+        assertTrue(result);
+        verify(mService, times(1)).jobFinished(any(), eq(false));
+        verify(mMockReportingWorker, times(1))
+                .reportAggregateErrors(mService, expectedEncryptionKey);
+        assertNotNull(
+                mJobScheduler.getPendingJob(
+                        OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
+    }
+
+    @Test
+    public void onStartJob_errorReportingEnabled_futureResolves_callsWorker() {
+        // Given that the aggregate error reporting is enabled and the job is
+        // scheduled successfully.
+        SettableFuture<Void> returnedFuture = SettableFuture.create();
+        mGetGlobalKillSwitch = false;
+        mAggregateErrorReportingEnabled = true;
+        when(mMockReportingWorker.reportAggregateErrors(any(), any())).thenReturn(returnedFuture);
+        assertEquals(
+                JobScheduler.RESULT_SUCCESS,
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+        assertNotNull(
+                mJobScheduler.getPendingJob(
+                        OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
+
+        // When the job is started.
+        boolean result = mService.onStartJob(mock(JobParameters.class));
+
+        // Expect that the worker is called once and the pending job is not cancelled.
+        // The job is marked finished only after the settable future resolves.
+        assertTrue(result);
+        verify(mService, times(0)).jobFinished(any(), eq(false));
+        verify(mMockReportingWorker, times(1)).reportAggregateErrors(any(), any());
+        assertNotNull(
+                mJobScheduler.getPendingJob(
+                        OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
+        // jobFinished called after the future resolves.
+        returnedFuture.set(null);
+        verify(mService, times(1)).jobFinished(any(), eq(false));
+    }
+
     @Test
     public void onStartJobTestKillSwitchEnabled_jobCancelled() {
         // Given that the aggregate error reporting job service is already scheduled and the global
         // kill switch is enabled (that is ODP is disabled).
-        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        mGetGlobalKillSwitch = true;
         doReturn(mJobScheduler).when(mService).getSystemService(JobScheduler.class);
         assertEquals(
                 JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mMockFlags));
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
@@ -108,13 +208,13 @@ public class AggregateErrorDataReportingServiceTest {
         doReturn(mJobScheduler).when(mService).getSystemService(JobScheduler.class);
         assertEquals(
                 JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mMockFlags));
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
 
         // When the job is started with error reporting disabled.
-        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
+        mAggregateErrorReportingEnabled = false;
         boolean result = mService.onStartJob(mock(JobParameters.class));
 
         // Expect that the job is cancelled and no more pending jobs.
@@ -132,20 +232,20 @@ public class AggregateErrorDataReportingServiceTest {
 
     @Test
     public void scheduleIfNeeded_AggregateErrorReportingDisabled() {
-        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
+        mAggregateErrorReportingEnabled = false;
 
         assertEquals(
                 JobScheduler.RESULT_FAILURE,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mMockFlags));
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
     }
 
     @Test
     public void scheduleIfNeeded_AggregateErrorReportingEnabled() {
-        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(true);
+        mAggregateErrorReportingEnabled = true;
 
         assertEquals(
                 JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mMockFlags));
+                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
     }
 
     private class TestInjector extends AggregateErrorDataReportingService.Injector {
@@ -156,7 +256,34 @@ public class AggregateErrorDataReportingServiceTest {
 
         @Override
         Flags getFlags() {
-            return mMockFlags;
+            return mTestFlags;
+        }
+
+        @Override
+        AggregatedErrorReportingWorker getErrorReportingWorker() {
+            return mMockReportingWorker;
+        }
+
+        @Override
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return mMockEncryptionKeyManager;
+        }
+    }
+
+    private class TestFlags implements Flags {
+        @Override
+        public boolean getGlobalKillSwitch() {
+            return mGetGlobalKillSwitch;
+        }
+
+        @Override
+        public boolean getAggregatedErrorReportingEnabled() {
+            return mAggregateErrorReportingEnabled;
+        }
+
+        @Override
+        public boolean getAllowUnencryptedAggregatedErrorReportingPayload() {
+            return mAllowUnEncryptedPayload;
         }
     }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
index b9439320..7650abfd 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
@@ -53,7 +53,7 @@ public class AggregatedErrorCodesLoggerTest {
     private static final String TEST_PACKAGE = "test_package";
     private static final String TEST_CLASS = "test_class";
 
-    private static final int TEST_ISOLATED_SERVICE_ERROR_CODE = 2;
+    static final int TEST_ISOLATED_SERVICE_ERROR_CODE = 2;
 
     private static final ComponentName TEST_COMPONENT_NAME =
             new ComponentName(TEST_PACKAGE, TEST_CLASS);
@@ -143,7 +143,7 @@ public class AggregatedErrorCodesLoggerTest {
         mSession.finishMocking();
     }
 
-    private static ErrorData getExpectedErrorData(int dayIndexUtc) {
+    static ErrorData getExpectedErrorData(int dayIndexUtc) {
         return new ErrorData.Builder(TEST_ISOLATED_SERVICE_ERROR_CODE, 1, dayIndexUtc, 0).build();
     }
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java
new file mode 100644
index 00000000..e0d40678
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java
@@ -0,0 +1,399 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import static com.android.odp.module.common.http.HttpClientUtils.CONTENT_TYPE_HDR;
+import static com.android.odp.module.common.http.HttpClientUtils.OCTET_STREAM;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorCodesLoggerTest.getExpectedErrorData;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorReportingProtocol.convertToProto;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorReportingProtocol.createAggregatedErrorReportingProtocol;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorReportingProtocol.getHttpRequest;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorReportingProtocol.getReportRequest;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorReportingProtocol.getRequestUri;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.when;
+
+import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
+
+import android.content.Context;
+import android.util.Base64;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.odp.module.common.encryption.Encrypter;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.http.HttpClient;
+import com.android.odp.module.common.http.HttpClientUtils;
+import com.android.odp.module.common.http.OdpHttpRequest;
+import com.android.odp.module.common.http.OdpHttpResponse;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.PhFlags;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.util.concurrent.FutureCallback;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.ListeningScheduledExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+import com.google.common.util.concurrent.SettableFuture;
+import com.google.ondevicepersonalization.federatedcompute.proto.ReportExceptionResponse;
+import com.google.ondevicepersonalization.federatedcompute.proto.UploadInstruction;
+
+import org.json.JSONException;
+import org.json.JSONObject;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+import org.mockito.quality.Strictness;
+
+import java.util.Arrays;
+import java.util.List;
+import java.util.Map;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
+
+@RunWith(JUnit4.class)
+public class AggregatedErrorReportingProtocolTest {
+    private static final String TEST_PACKAGE = "test_package";
+    private static final String TEST_CLASS = "test_class";
+    private static final String TEST_SERVER_URL = "https://google.com";
+    private static final long TEST_CLIENT_VERSION = 1;
+
+    private static final String UPLOAD_LOCATION_URI = "https://dataupload.uri";
+
+
+    private static final int HTTP_OK_STATUS = 200;
+
+    private static final byte[] TEST_ENCRYPTED_OUTPUT = new byte[] {1, 2, 3};
+
+    private static final String TEST_PUBLIC_KEY = "fooKey";
+
+    private static final byte[] PUBLIC_KEY = Base64.decode(TEST_PUBLIC_KEY, Base64.NO_WRAP);
+
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+
+    private int mDayIndexUtc;
+
+    private ErrorData mErrorData;
+
+    private AggregatedErrorReportingProtocol mInstanceUnderTest;
+
+    private CountDownLatch mCountDownLatch = new CountDownLatch(1);
+
+    @Mock private Flags mMockFlags;
+
+    @Mock private HttpClient mMockHttpClient;
+
+    @Mock private OdpEncryptionKey mMockEncryptionKey;
+
+    @Mock private Encrypter mMockEncrypter;
+
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    @Before
+    public void setup() throws Exception {
+        MockitoAnnotations.initMocks(this);
+
+        mDayIndexUtc = DateTimeUtils.dayIndexUtc();
+        mErrorData = getExpectedErrorData(mDayIndexUtc);
+        when(mMockFlags.getAggregatedErrorReportingServerPath())
+                .thenReturn(PhFlags.DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH);
+        // Inject mock flags and a test ReportingProtocol object
+    }
+
+    @Test
+    public void reportExceptionData_httpClientFails() {
+        Throwable error = new IllegalStateException("Random failure");
+        when(mMockHttpClient.performRequestAsyncWithRetry(any()))
+                .thenReturn(Futures.immediateFailedFuture(error));
+        mInstanceUnderTest =
+                createAggregatedErrorReportingProtocol(
+                        ImmutableList.of(mErrorData),
+                        TEST_SERVER_URL,
+                        TEST_CLIENT_VERSION,
+                        new TestInjector());
+
+        ListenableFuture<Boolean> reportingFuture =
+                mInstanceUnderTest.reportExceptionData(/* encryptionKey= */ null);
+
+        assertTrue(reportingFuture.isDone());
+        ExecutionException outException =
+                assertThrows(ExecutionException.class, reportingFuture::get);
+        assertThat(outException.getCause()).isInstanceOf(IllegalStateException.class);
+    }
+
+    @Test
+    public void reportExceptionData_httpClientFailedErrorCode() {
+        OdpHttpResponse response = createReportExceptionResponse(404);
+        when(mMockHttpClient.performRequestAsyncWithRetry(any()))
+                .thenReturn(Futures.immediateFuture(response));
+        mInstanceUnderTest =
+                createAggregatedErrorReportingProtocol(
+                        ImmutableList.of(mErrorData),
+                        TEST_SERVER_URL,
+                        TEST_CLIENT_VERSION,
+                        new TestInjector());
+
+        ListenableFuture<Boolean> reportingFuture =
+                mInstanceUnderTest.reportExceptionData(/* encryptionKey= */ null);
+
+        assertTrue(reportingFuture.isDone());
+        ExecutionException outException =
+                assertThrows(ExecutionException.class, reportingFuture::get);
+        assertThat(outException.getCause()).isInstanceOf(IllegalStateException.class);
+        assertThat(outException.getCause().getMessage()).containsMatch(".*reportRequest.failed.*");
+    }
+
+    @Test
+    public void reportExceptionData_httpClientMissingUploadLocation() {
+        OdpHttpResponse response = createReportExceptionResponse(HTTP_OK_STATUS);
+        when(mMockHttpClient.performRequestAsyncWithRetry(any()))
+                .thenReturn(Futures.immediateFuture(response));
+        mInstanceUnderTest =
+                createAggregatedErrorReportingProtocol(
+                        ImmutableList.of(mErrorData),
+                        TEST_SERVER_URL,
+                        TEST_CLIENT_VERSION,
+                        new TestInjector());
+
+        ListenableFuture<Boolean> reportingFuture =
+                mInstanceUnderTest.reportExceptionData(/* encryptionKey= */ null);
+
+        assertTrue(reportingFuture.isDone());
+        ExecutionException outException =
+                assertThrows(ExecutionException.class, reportingFuture::get);
+        assertThat(outException.getCause()).isInstanceOf(IllegalArgumentException.class);
+    }
+
+    @Test
+    public void reportExceptionData_httpClientSuccessful() throws Exception {
+        // Tests successful upload flow, validates the requests sent via the http client.
+        TestInjector testInjector = new TestInjector();
+        ArgumentCaptor<OdpHttpRequest> clientRequestCaptor =
+                ArgumentCaptor.forClass(OdpHttpRequest.class);
+        OdpHttpResponse serverResponse =
+                createReportExceptionResponse(HTTP_OK_STATUS, UPLOAD_LOCATION_URI);
+        OdpHttpRequest expectedClientReportRequest =
+                getHttpRequest(
+                        getRequestUri(TEST_SERVER_URL, testInjector.getFlags()),
+                        Map.of(),
+                        getReportRequest().toByteArray());
+        OdpHttpRequest expectedClientUploadRequest =
+                createExpectedUploadRequest(UPLOAD_LOCATION_URI, ImmutableList.of(mErrorData));
+        when(mMockHttpClient.performRequestAsyncWithRetry(any()))
+                .thenReturn(Futures.immediateFuture(serverResponse));
+        mInstanceUnderTest =
+                createAggregatedErrorReportingProtocol(
+                        ImmutableList.of(mErrorData),
+                        TEST_SERVER_URL,
+                        TEST_CLIENT_VERSION,
+                        testInjector);
+
+        ListenableFuture<Boolean> reportingFuture =
+                mInstanceUnderTest.reportExceptionData(/* encryptionKey= */ null);
+
+        assertTrue(reportingFuture.isDone());
+        assertTrue(reportingFuture.get());
+        verify(mMockHttpClient, times(2))
+                .performRequestAsyncWithRetry(clientRequestCaptor.capture());
+        List<OdpHttpRequest> clientRequests = clientRequestCaptor.getAllValues();
+        // Validate the report request
+        assertEquals(HttpClientUtils.HttpMethod.PUT, clientRequests.get(0).getHttpMethod());
+        assertEquals(expectedClientReportRequest.getUri(), clientRequests.get(0).getUri());
+        // Validate the subsequent upload request
+        assertEquals(HttpClientUtils.HttpMethod.PUT, clientRequests.get(1).getHttpMethod());
+        assertEquals(expectedClientUploadRequest.getUri(), clientRequests.get(1).getUri());
+        assertTrue(
+                Arrays.equals(
+                        expectedClientUploadRequest.getBody(), clientRequests.get(1).getBody()));
+        // No interactions with encrypter since the key was null
+        verifyZeroInteractions(mMockEncrypter);
+    }
+
+    @Test
+    public void reportExceptionData_httpClientTimeout() throws Exception {
+        // Set short timeout and don't return anything from the mock http client.
+        when(mMockFlags.getAggregatedErrorReportingHttpTimeoutSeconds()).thenReturn(5);
+        when(mMockHttpClient.performRequestAsyncWithRetry(any()))
+                .thenReturn(SettableFuture.create());
+        mInstanceUnderTest =
+                createAggregatedErrorReportingProtocol(
+                        ImmutableList.of(mErrorData),
+                        TEST_SERVER_URL,
+                        TEST_CLIENT_VERSION,
+                        new TestInjector());
+
+        ListenableFuture<Boolean> reportingFuture =
+                mInstanceUnderTest.reportExceptionData(/* encryptionKey= */ null);
+        Futures.addCallback(reportingFuture, new TestCallback(), MoreExecutors.directExecutor());
+
+        boolean countedDown = mCountDownLatch.await(10, TimeUnit.SECONDS);
+
+        assertTrue(countedDown);
+        assertTrue(reportingFuture.isDone());
+        ExecutionException outException =
+                assertThrows(ExecutionException.class, reportingFuture::get);
+        assertThat(outException.getCause()).isInstanceOf(TimeoutException.class);
+    }
+
+    @Test
+    public void createEncryptedRequestBody() throws JSONException {
+        // Set up the encrypter to reply with some test data when called with expected key and byte
+        // array etc.
+        String expectedEncryptedPayload =
+                Base64.encodeToString(TEST_ENCRYPTED_OUTPUT, Base64.NO_WRAP);
+        com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList errorDataList =
+                convertToProto(ImmutableList.of(mErrorData));
+        when(mMockEncryptionKey.getPublicKey()).thenReturn(TEST_PUBLIC_KEY);
+        when(mMockEncrypter.encrypt(
+                        PUBLIC_KEY,
+                        errorDataList.toByteArray(),
+                        AggregatedErrorReportingProtocol.AggregatedErrorDataPayloadContract
+                                .ASSOCIATED_DATA))
+                .thenReturn(TEST_ENCRYPTED_OUTPUT);
+
+        JSONObject jsonResponse =
+                new JSONObject(
+                        new String(
+                                AggregatedErrorReportingProtocol.createEncryptedRequestBody(
+                                        ImmutableList.of(mErrorData),
+                                        mMockEncryptionKey,
+                                        mMockEncrypter)));
+        assertEquals(
+                expectedEncryptedPayload,
+                jsonResponse.get(
+                        AggregatedErrorReportingProtocol.AggregatedErrorDataPayloadContract
+                                .ENCRYPTED_PAYLOAD));
+    }
+
+    @Test
+    public void createUnEncryptedRequestBody() throws JSONException {
+        com.google.ondevicepersonalization.federatedcompute.proto.ErrorDataList errorDataList =
+                convertToProto(ImmutableList.of(mErrorData));
+        String expectedErrorData =
+                Base64.encodeToString(errorDataList.toByteArray(), Base64.NO_WRAP);
+
+        JSONObject jsonResponse =
+                new JSONObject(
+                        new String(
+                                AggregatedErrorReportingProtocol.createEncryptedRequestBody(
+                                        ImmutableList.of(mErrorData),
+                                        /* encryptionKey= */ null,
+                                        /* encrypter= */ null)));
+        assertEquals(
+                expectedErrorData,
+                jsonResponse.get(
+                        AggregatedErrorReportingProtocol.AggregatedErrorDataPayloadContract
+                                .ENCRYPTED_PAYLOAD));
+    }
+
+    private static OdpHttpRequest createExpectedUploadRequest(
+            String uploadLocation, ImmutableList<ErrorData> errorData) throws JSONException {
+        // Test helper to create expected upload request sent from client -> server.
+        return getHttpRequest(
+                uploadLocation,
+                /* requestHeadersMap= */ Map.of(CONTENT_TYPE_HDR, OCTET_STREAM),
+                AggregatedErrorReportingProtocol.createEncryptedRequestBody(errorData, null, null));
+    }
+
+    private static OdpHttpResponse createReportExceptionResponse(int statusCode) {
+        // Create a response with only status code no upload instruction, payload etc.
+        return createReportExceptionResponse(statusCode, /* uploadLocation= */ "");
+    }
+
+    private static OdpHttpResponse createReportExceptionResponse(
+            int statusCode, String uploadLocation) {
+        UploadInstruction.Builder uploadInstruction =
+                UploadInstruction.newBuilder().setUploadLocation(uploadLocation);
+        uploadInstruction.putExtraRequestHeaders(CONTENT_TYPE_HDR, OCTET_STREAM);
+
+        ReportExceptionResponse response =
+                ReportExceptionResponse.newBuilder()
+                        .setUploadInstruction(uploadInstruction.build())
+                        .build();
+
+        return new OdpHttpResponse.Builder()
+                .setStatusCode(statusCode)
+                .setPayload(response.toByteArray())
+                .build();
+    }
+
+    class TestInjector extends AggregatedErrorReportingProtocol.Injector {
+        @Override
+        ListeningExecutorService getBlockingExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        ListeningExecutorService getBackgroundExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        ListeningScheduledExecutorService getScheduledExecutor() {
+            return MoreExecutors.listeningDecorator(newSingleThreadScheduledExecutor());
+        }
+
+        @Override
+        Flags getFlags() {
+            return mMockFlags;
+        }
+
+        @Override
+        HttpClient getClient() {
+            return mMockHttpClient;
+        }
+
+        @Override
+        Encrypter getEncrypter() {
+            return mMockEncrypter;
+        }
+    }
+
+    private class TestCallback implements FutureCallback<Boolean> {
+
+        @Override
+        public void onSuccess(Boolean result) {
+            mCountDownLatch.countDown();
+        }
+
+        @Override
+        public void onFailure(Throwable t) {
+            mCountDownLatch.countDown();
+        }
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
new file mode 100644
index 00000000..3367c3ad
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
@@ -0,0 +1,272 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorCodesLoggerTest.TEST_ISOLATED_SERVICE_ERROR_CODE;
+import static com.android.ondevicepersonalization.services.data.errors.AggregatedErrorCodesLoggerTest.getExpectedErrorData;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.Mockito.doReturn;
+
+import android.content.ComponentName;
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+import com.google.common.util.concurrent.SettableFuture;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+import org.mockito.quality.Strictness;
+
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeoutException;
+import java.util.concurrent.atomic.AtomicInteger;
+
+@RunWith(JUnit4.class)
+@ExtendedMockitoRule.MockStatic(PackageUtils.class)
+@ExtendedMockitoRule.MockStatic(AppManifestConfigHelper.class)
+public class AggregatedErrorReportingWorkerTest {
+    private static final String TEST_CERT_DIGEST = "test_cert_digest";
+    private static final String TEST_PACKAGE = "test_package";
+    private static final String TEST_CLASS = "test_class";
+    private static final String TEST_SERVER_URL = "https://google.com";
+
+    private static final ComponentName TEST_COMPONENT_NAME =
+            new ComponentName(TEST_PACKAGE, TEST_CLASS);
+
+    private static final ImmutableList<ComponentName> TEST_ODP_SERVICE_LIST =
+            ImmutableList.of(TEST_COMPONENT_NAME);
+
+    private static final ListenableFuture<Boolean> SUCCESSFUL_FUTURE =
+            Futures.immediateFuture(true);
+
+
+    private static final ImmutableList<ComponentName> EMPTY_ODP_SERVICE_LIST = ImmutableList.of();
+
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+
+    private TestInjector mTestInjector;
+
+    private int mDayIndexUtc;
+
+    private TestReportingProtocol mTestReportingProtocol;
+    private AggregatedErrorReportingWorker mInstanceUnderTest;
+
+    @Mock private Flags mMockFlags;
+
+    @Mock private OdpEncryptionKey mMockEncryptionKey;
+
+    private final OnDevicePersonalizationAggregatedErrorDataDao mErrorDataDao =
+            OnDevicePersonalizationAggregatedErrorDataDao.getInstance(
+                    mContext, TEST_COMPONENT_NAME, TEST_CERT_DIGEST);
+
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    @Before
+    public void setup() throws Exception {
+        MockitoAnnotations.initMocks(this);
+
+        // Setup package utils to return the test cert digest
+        doReturn(TEST_CERT_DIGEST).when(() -> PackageUtils.getCertDigest(mContext, TEST_PACKAGE));
+        mDayIndexUtc = DateTimeUtils.dayIndexUtc();
+        // Inject mock flags and a test ReportingProtocol object
+        mTestReportingProtocol = new TestReportingProtocol();
+        mTestInjector = new TestInjector(mTestReportingProtocol, mMockFlags);
+        mInstanceUnderTest = AggregatedErrorReportingWorker.createWorker(mTestInjector);
+    }
+
+    @After
+    public void cleanup() {
+        AggregatedErrorReportingWorker.resetForTesting();
+        mErrorDataDao.deleteExceptionData();
+    }
+
+    @Test
+    public void reportAggregateErrors_noOdpServices() {
+        // When no odp services installed, expect the report to early exit.
+        doReturn(EMPTY_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+
+        ListenableFuture<Void> returnedFuture =
+                mInstanceUnderTest.reportAggregateErrorsHelper(mContext, /* encryptionKey= */ null);
+
+        assertTrue(returnedFuture.isDone());
+        assertEquals(0, mTestInjector.mCallCount.get());
+    }
+
+    @Test
+    public void reportAggregateErrors_noErrorData() {
+        // When odp services are installed but no error data is present in the tables, expect
+        // the report to early exit.
+        doReturn(TEST_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+
+        ListenableFuture<Void> returnedFuture =
+                mInstanceUnderTest.reportAggregateErrorsHelper(mContext, /* encryptionKey= */ null);
+
+        assertTrue(returnedFuture.isDone());
+        assertEquals(0, mTestInjector.mCallCount.get());
+    }
+
+    @Test
+    public void reportAggregateErrors_withErrorData_succeeds() {
+        // When odp services are installed and there is error data present in the tables,
+        // expect there to be single interaction with the injector and the test reporting object.
+        doReturn(TEST_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+        mErrorDataDao.addExceptionCount(TEST_ISOLATED_SERVICE_ERROR_CODE, 1);
+
+        ListenableFuture<Void> returnedFuture =
+                mInstanceUnderTest.reportAggregateErrorsHelper(mContext, mMockEncryptionKey);
+
+        assertTrue(returnedFuture.isDone());
+        assertEquals(1, mTestInjector.mCallCount.get());
+        assertEquals(TEST_SERVER_URL, mTestInjector.mRequestUri);
+        assertEquals(getExpectedErrorData(mDayIndexUtc), mTestInjector.mErrorData.get(0));
+        assertEquals(1, mTestReportingProtocol.mCallCount.get());
+        assertThat(mTestReportingProtocol.mOdpEncryptionKey).isSameInstanceAs(mMockEncryptionKey);
+    }
+
+    @Test
+    public void reportAggregateErrors_withErrorData_reportingProtocolFails() {
+        // When odp services are installed and there is error data present in the tables,
+        // expect there to be single interaction with the injector and the test reporting object.
+        doReturn(TEST_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+        mErrorDataDao.addExceptionCount(TEST_ISOLATED_SERVICE_ERROR_CODE, 1);
+        mTestReportingProtocol.mReturnFuture =
+                Futures.immediateFailedFuture(new TimeoutException("Http time out!"));
+
+        ListenableFuture<Void> returnedFuture =
+                mInstanceUnderTest.reportAggregateErrorsHelper(mContext, /* encryptionKey= */ null);
+
+        assertTrue(returnedFuture.isDone());
+        assertEquals(1, mTestInjector.mCallCount.get());
+        assertEquals(TEST_SERVER_URL, mTestInjector.mRequestUri);
+        assertEquals(getExpectedErrorData(mDayIndexUtc), mTestInjector.mErrorData.get(0));
+        assertEquals(1, mTestReportingProtocol.mCallCount.get());
+    }
+
+    @Test
+    public void reportAggregateErrors_pendingRequest() {
+        // A second request when there is an existing request fails immediately.
+        doReturn(TEST_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+        mErrorDataDao.addExceptionCount(TEST_ISOLATED_SERVICE_ERROR_CODE, 1);
+        SettableFuture<Boolean> settableFuture = SettableFuture.create();
+        mTestReportingProtocol.mReturnFuture = settableFuture;
+
+        ListenableFuture<Void> firstRequest =
+                mInstanceUnderTest.reportAggregateErrors(mContext, /* encryptionKey= */ null);
+        ListenableFuture<Void> secondRequest =
+                mInstanceUnderTest.reportAggregateErrors(mContext, /* encryptionKey= */ null);
+
+        assertFalse(firstRequest.isDone());
+        assertTrue(secondRequest.isDone());
+        ExecutionException outException =
+                assertThrows(ExecutionException.class, secondRequest::get);
+        assertThat(outException.getCause()).isInstanceOf(IllegalStateException.class);
+        assertEquals(1, mTestInjector.mCallCount.get());
+        settableFuture.set(true);
+        assertTrue(firstRequest.isDone());
+    }
+
+    private static final class TestReportingProtocol implements ReportingProtocol {
+        private final AtomicInteger mCallCount = new AtomicInteger(0);
+        // Default instance returns the successful future.
+        private ListenableFuture<Boolean> mReturnFuture = SUCCESSFUL_FUTURE;
+        private OdpEncryptionKey mOdpEncryptionKey = null;
+
+        @Override
+        public ListenableFuture<Boolean> reportExceptionData(OdpEncryptionKey encryptionKey) {
+            mCallCount.incrementAndGet();
+            mOdpEncryptionKey = encryptionKey;
+            return mReturnFuture;
+        }
+    }
+
+    private static final class TestInjector extends AggregatedErrorReportingWorker.Injector {
+        private final ReportingProtocol mTestProtocol;
+        private final Flags mFlags;
+
+        private String mRequestUri;
+        private ImmutableList<ErrorData> mErrorData;
+        private final AtomicInteger mCallCount = new AtomicInteger(0);
+
+        TestInjector(ReportingProtocol testProtocol, Flags flags) {
+            this.mTestProtocol = testProtocol;
+            this.mFlags = flags;
+        }
+
+        @Override
+        ListeningExecutorService getBackgroundExecutor() {
+            // Use direct executor to keep all work sequential for the tests.
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        ListeningExecutorService getLightweightExecutor() {
+            // Use direct executor to keep all work sequential for the tests.
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        Flags getFlags() {
+            return mFlags;
+        }
+
+        @Override
+        ReportingProtocol getAggregatedErrorReportingProtocol(
+                ImmutableList<ErrorData> errorData, String requestBaseUri, Context context) {
+            mCallCount.incrementAndGet();
+            mErrorData = errorData;
+            mRequestUri = requestBaseUri;
+            return mTestProtocol;
+        }
+
+        @Override
+        String getServerUrl(Context context, String packageName) {
+            return TEST_SERVER_URL;
+        }
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtilsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtilsTest.java
index e07e1f4b..3b47a16c 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtilsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/DateTimeUtilsTest.java
@@ -45,6 +45,7 @@ public class DateTimeUtilsTest {
 
     // PST: Friday, August 23, 2024 10:59:11 PM
     private static final long DEFAULT_CURRENT_TIME_MILLIS = 1724479151000L;
+
     private static final int CURRENT_DAYS_EPOCH_PST = 19958;
     private Context mContext;
 
@@ -74,4 +75,13 @@ public class DateTimeUtilsTest {
 
         assertEquals(CURRENT_DAYS_EPOCH_PST, dayEpoch);
     }
+
+    @Test
+    public void testEpochSecondsUtc() {
+        long currentMillis = 1726812886190L;
+        long expectedUtcSeconds = 1726812886;
+        when(mMockClock.currentTimeMillis()).thenReturn(currentMillis);
+
+        assertEquals(expectedUtcSeconds, DateTimeUtils.epochSecondsUtc(mMockClock));
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
index fa2491f2..6c167ca4 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
@@ -17,12 +17,17 @@
 package com.android.ondevicepersonalization.services.data.user;
 
 import static android.adservices.ondevicepersonalization.Constants.STATUS_CALLER_NOT_ALLOWED;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_CLASS_NOT_FOUND;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_EXECUTION_INTERRUPTED;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_INTERNAL_ERROR;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_METHOD_NOT_FOUND;
+import static android.adservices.ondevicepersonalization.Constants.STATUS_NULL_ADSERVICES_COMMON_MANAGER;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_REMOTE_EXCEPTION;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_TIMEOUT;
 import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
+import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION;
+import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
@@ -34,19 +39,24 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.Clock;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.StableFlags;
 import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
+import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 import com.android.ondevicepersonalization.services.util.DebugUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
 
@@ -59,18 +69,21 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.TimeoutException;
 
 @RunWith(JUnit4.class)
+@MockStatic(ClientErrorLogger.class)
 public final class UserPrivacyStatusTest {
     private UserPrivacyStatus mUserPrivacyStatus;
     private static final int CONTROL_RESET_STATUS_CODE = 5;
     private static final long CACHE_TIMEOUT_MILLIS = 10000;
     private long mClockTime = 1000L;
     private boolean mCommonStatesWrapperCalled = false;
+    @Mock private ClientErrorLogger mMockClientErrorLogger;
     private AdServicesCommonStatesWrapper.CommonStatesResult mCommonStatesResult =
             new AdServicesCommonStatesWrapper.CommonStatesResult(
                     UserPrivacyStatus.CONTROL_GIVEN_STATUS_CODE,
@@ -123,6 +136,7 @@ public final class UserPrivacyStatusTest {
                 () -> StableFlags.get(KEY_USER_CONTROL_CACHE_IN_MILLIS));
         mUserPrivacyStatus = new UserPrivacyStatus(mCommonStatesWrapper, mTestClock);
         doReturn(RESULT_SUCCESS).when(ResetDataJobService::schedule);
+        when(ClientErrorLogger.getInstance()).thenReturn(mMockClientErrorLogger);
     }
 
     @Test
@@ -182,6 +196,30 @@ public final class UserPrivacyStatusTest {
         assertTrue(mCommonStatesWrapperCalled);
     }
 
+    @Test
+    public void testFetchesFromAdServicesException() {
+        AdServicesCommonStatesWrapper failingWrapper =
+                new AdServicesCommonStatesWrapper() {
+                    @Override public ListenableFuture<CommonStatesResult> getCommonStates() {
+                        return Futures.immediateFailedFuture(
+                                new IllegalStateException("remote err"));
+                    }
+                };
+        UserPrivacyStatus failingUserPrivacyStatus =
+                new UserPrivacyStatus(failingWrapper, mTestClock);
+
+        failingUserPrivacyStatus.invalidateUserControlCacheForTesting();
+        assertFalse(failingUserPrivacyStatus.isUserControlCacheValid());
+
+        var unused = failingUserPrivacyStatus.isMeasurementEnabled();
+        assertFalse(failingUserPrivacyStatus.isUserControlCacheValid());
+        verify(mMockClientErrorLogger)
+                .logError(
+                        any(),
+                        eq(AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION),
+                        eq(AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP));
+    }
+
     @Test
     public void testOverrideEnabledOnDeveloperModeOverrideTrue() {
         mUserPrivacyStatus.updateUserControlCache(
@@ -232,14 +270,32 @@ public final class UserPrivacyStatusTest {
     @Test
     public void testGetStatusCode() {
         assertThat(mUserPrivacyStatus.getExceptionStatus(
-                new ExecutionException("timeout testing", new TimeoutException())))
+                new ExecutionException("timeout exception", new TimeoutException())))
                 .isEqualTo(STATUS_TIMEOUT);
-        assertThat(mUserPrivacyStatus.getExceptionStatus(new NoSuchMethodException()))
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("no such method", new NoSuchMethodException())))
                 .isEqualTo(STATUS_METHOD_NOT_FOUND);
-        assertThat(mUserPrivacyStatus.getExceptionStatus(new SecurityException()))
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("security exception", new SecurityException())))
                 .isEqualTo(STATUS_CALLER_NOT_ALLOWED);
-        assertThat(mUserPrivacyStatus.getExceptionStatus(new IllegalArgumentException()))
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("illegal state", new IllegalStateException())))
+                .isEqualTo(STATUS_INTERNAL_ERROR);
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("illegal argument", new IllegalArgumentException())))
                 .isEqualTo(STATUS_INTERNAL_ERROR);
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("no class def found", new NoClassDefFoundError())))
+                .isEqualTo(STATUS_CLASS_NOT_FOUND);
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("null adservices common manager",
+                        new AdServicesCommonStatesWrapper.NullAdServiceCommonManagerException())))
+                .isEqualTo(STATUS_NULL_ADSERVICES_COMMON_MANAGER);
+        assertThat(mUserPrivacyStatus.getExceptionStatus(
+                new ExecutionException("thread interrupted", new InterruptedException())))
+                .isEqualTo(STATUS_EXECUTION_INTERRUPTED);
+        assertThat(mUserPrivacyStatus.getExceptionStatus(new InterruptedException()))
+                .isEqualTo(STATUS_EXECUTION_INTERRUPTED);
         assertThat(mUserPrivacyStatus.getExceptionStatus(new Exception()))
                 .isEqualTo(STATUS_REMOTE_EXCEPTION);
     }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
index 6460c9a3..6893bc5b 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
@@ -71,18 +71,16 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.quality.Strictness;
 
 import java.net.HttpURLConnection;
 import java.nio.ByteBuffer;
 import java.nio.charset.StandardCharsets;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.Map;
 import java.util.concurrent.CountDownLatch;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class OdpWebViewClientTests {
     public final String TAG = OdpWebViewClientTests.class.getSimpleName();
     private static final long QUERY_ID = 1L;
@@ -103,23 +101,10 @@ public class OdpWebViewClientTests {
     private String mOpenedUrl;
 
     private CountDownLatch mLatch;
-
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
     private FutureCallback mTestCallback;
     private boolean mCallbackSuccess;
     private boolean mCallbackFailure;
 
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
-
     private Flags mSpyFlags = new Flags() {
         int mIsolatedServiceDeadlineSeconds = 30;
         @Override public int getIsolatedServiceDeadlineSeconds() {
@@ -138,7 +123,7 @@ public class OdpWebViewClientTests {
     public void setup() throws Exception {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
         mDbHelper = OnDevicePersonalizationDbHelper.getInstanceForTest(mContext);
         mDao = EventsDao.getInstanceForTest(mContext);
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
index 5edf2627..00da3711 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
@@ -60,17 +60,15 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.quality.Strictness;
 
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.Base64;
-import java.util.Collection;
 import java.util.List;
 import java.util.concurrent.CountDownLatch;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class OnDevicePersonalizationDataProcessingAsyncCallableTests {
     private final Context mContext = ApplicationProvider.getApplicationContext();
     private OnDevicePersonalizationFileGroupPopulator mPopulator;
@@ -97,17 +95,6 @@ public class OnDevicePersonalizationDataProcessingAsyncCallableTests {
     private boolean mCallbackSuccess;
     private boolean mCallbackFailure;
     private CountDownLatch mLatch;
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
 
     private Flags mSpyFlags = new Flags() {
         int mIsolatedServiceDeadlineSeconds = 30;
@@ -143,7 +130,7 @@ public class OnDevicePersonalizationDataProcessingAsyncCallableTests {
 
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java
new file mode 100644
index 00000000..e00d1415
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java
@@ -0,0 +1,192 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.ondevicepersonalization.services.download.mdd;
+
+import static com.android.adservices.service.stats.AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_DOWNLOAD_RESULT_REPORTED;
+import static com.android.adservices.service.stats.AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_FILE_GROUP_STATUS_REPORTED;
+import static com.android.adservices.service.stats.AdServicesStatsLog.MOBILE_DATA_DOWNLOAD_FILE_GROUP_STORAGE_STATS_REPORTED;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.staticMockMarker;
+
+import static com.google.mobiledatadownload.LogEnumsProto.MddDownloadResult.Code.SUCCESS;
+import static com.google.mobiledatadownload.LogEnumsProto.MddDownloadResult.Code.SUCCESS_VALUE;
+import static com.google.mobiledatadownload.LogEnumsProto.MddFileGroupDownloadStatus.Code.COMPLETE;
+import static com.google.mobiledatadownload.LogEnumsProto.MddFileGroupDownloadStatus.Code.COMPLETE_VALUE;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
+import static org.mockito.Mockito.when;
+
+import com.android.adservices.service.stats.AdServicesStatsLog;
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.SpyStatic;
+
+import com.google.mobiledatadownload.LogProto.DataDownloadFileGroupStats;
+import com.google.mobiledatadownload.LogProto.MddDownloadResultLog;
+import com.google.mobiledatadownload.LogProto.MddFileGroupStatus;
+import com.google.mobiledatadownload.LogProto.MddLogData;
+import com.google.mobiledatadownload.LogProto.MddStorageStats;
+import com.google.protobuf.MessageLite;
+
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.Spy;
+import org.mockito.quality.Strictness;
+
+@SpyStatic(AdServicesStatsLog.class)
+public final class MddLoggerTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    // Enum code defined in log_enums.proto.
+    private static final int EVENT_CODE_UNSPECIFIED = 0;
+    private static final int DATA_DOWNLOAD_FILE_GROUP_STATUS = 1044;
+    private static final int DATA_DOWNLOAD_RESULT_LOG = 1068;
+    private static final int DATA_DOWNLOAD_STORAGE_STATS = 1055;
+    private static final long SAMPLE_INTERVAL = 1;
+    private static final long TEST_TIMESTAMP = 1L;
+    private static final int TEST_DAYS = 3;
+    private static final long TEST_BYTE_USED = 5;
+
+    private final MddLogger mMddLogger = new MddLogger();
+    private MessageLite mMessageLite;
+
+    @Mock private MessageLite mMockLog;
+    @Spy private MddDownloadResultLog mMockMddDownloadResultLog;
+    @Spy private MddFileGroupStatus mMockMddFileGroupStatus;
+    @Spy private DataDownloadFileGroupStats mSpyDataDownloadFileGroupStats;
+    @Spy private MddStorageStats mMockMddStorageStats;
+
+    @Test
+    public void mddLoggerTest_unspecified() {
+        mMddLogger.log(mMockLog, EVENT_CODE_UNSPECIFIED);
+        // Unspecified event does not trigger MDD logging.
+        ExtendedMockito.verifyZeroInteractions(staticMockMarker(AdServicesStatsLog.class));
+    }
+
+    @Test
+    public void mddLoggerTest_logFileGroupStatusComplete() {
+        // This test will not log any test data.
+        ExtendedMockito.doNothing()
+                .when(
+                        () ->
+                                AdServicesStatsLog.write(
+                                        anyInt(),
+                                        anyInt(),
+                                        anyLong(),
+                                        anyLong(),
+                                        any(byte[].class),
+                                        anyInt()));
+
+        // Create a MessageLite using mock or default value.
+        mMessageLite =
+                MddLogData.newBuilder()
+                        .setSamplingInterval(SAMPLE_INTERVAL)
+                        .setDataDownloadFileGroupStats(mSpyDataDownloadFileGroupStats)
+                        .setMddFileGroupStatus(mMockMddFileGroupStatus)
+                        .build();
+
+        when(mMockMddFileGroupStatus.getFileGroupDownloadStatus()).thenReturn(COMPLETE);
+        when(mMockMddFileGroupStatus.getGroupAddedTimestampInSeconds()).thenReturn(TEST_TIMESTAMP);
+        when(mMockMddFileGroupStatus.getGroupDownloadedTimestampInSeconds())
+                .thenReturn(TEST_TIMESTAMP);
+        when(mMockMddFileGroupStatus.getDaysSinceLastLog()).thenReturn(TEST_DAYS);
+
+        mMddLogger.log(mMessageLite, DATA_DOWNLOAD_FILE_GROUP_STATUS);
+
+        // Verify AdServicesStatsLog code and mocked value.
+        ExtendedMockito.verify(
+                () ->
+                        AdServicesStatsLog.write(
+                                eq(MOBILE_DATA_DOWNLOAD_FILE_GROUP_STATUS_REPORTED),
+                                /* file_group_download_status default value */ eq(COMPLETE_VALUE),
+                                /* group_added_timestamp default value  */ eq(TEST_TIMESTAMP),
+                                /* group_downloaded_timestamp default value */ eq(TEST_TIMESTAMP),
+                                /* file_group_stats */ any(byte[].class),
+                                /* days_since_last_log default value */ eq(TEST_DAYS)));
+
+        verifyNoMoreInteractions(staticMockMarker(AdServicesStatsLog.class));
+    }
+
+    @Test
+    public void mddLoggerTest_logDownloadResultSuccess() {
+        // This test will not log any test data.
+        ExtendedMockito.doNothing()
+                .when(() -> AdServicesStatsLog.write(anyInt(), anyInt(), any(byte[].class)));
+
+        // Create a MessageLite using mock or default value.
+        mMessageLite =
+                MddLogData.newBuilder()
+                        .setSamplingInterval(SAMPLE_INTERVAL)
+                        .setDataDownloadFileGroupStats(mSpyDataDownloadFileGroupStats)
+                        .setMddDownloadResultLog(mMockMddDownloadResultLog)
+                        .build();
+
+        when(mMockMddDownloadResultLog.getResult()).thenReturn(SUCCESS);
+        when(mMockMddDownloadResultLog.getDataDownloadFileGroupStats())
+                .thenReturn(mSpyDataDownloadFileGroupStats);
+
+        mMddLogger.log(mMessageLite, DATA_DOWNLOAD_RESULT_LOG);
+
+        // Verify AdServicesStatsLog code and mocked value.
+        ExtendedMockito.verify(
+                () ->
+                        AdServicesStatsLog.write(
+                                eq(MOBILE_DATA_DOWNLOAD_DOWNLOAD_RESULT_REPORTED),
+                                /* download_result */ eq(SUCCESS_VALUE),
+                                /* file_group_stats */ any(byte[].class)));
+
+        verifyNoMoreInteractions(staticMockMarker(AdServicesStatsLog.class));
+    }
+
+    @Test
+    public void mddLoggerTest_logStorageStats() {
+        // This test will not log any test data.
+        ExtendedMockito.doNothing()
+                .when(
+                        () ->
+                                AdServicesStatsLog.write(
+                                        anyInt(), any(byte[].class), anyLong(), anyLong()));
+
+        // Create a MessageLite using mock or default value.
+        mMessageLite =
+                MddLogData.newBuilder()
+                        .setSamplingInterval(SAMPLE_INTERVAL)
+                        .setMddStorageStats(mMockMddStorageStats)
+                        .build();
+
+        when(mMockMddStorageStats.getTotalMddBytesUsed()).thenReturn(TEST_BYTE_USED);
+        when(mMockMddStorageStats.getTotalMddDirectoryBytesUsed()).thenReturn(TEST_BYTE_USED);
+
+        mMddLogger.log(mMessageLite, DATA_DOWNLOAD_STORAGE_STATS);
+
+        // Verify AdServicesStatsLog code and mocked value.
+        ExtendedMockito.verify(
+                () ->
+                        AdServicesStatsLog.write(
+                                eq(MOBILE_DATA_DOWNLOAD_FILE_GROUP_STORAGE_STATS_REPORTED),
+                                /* storage status */ any(byte[].class),
+                                /* total mdd bytes used */ eq(TEST_BYTE_USED),
+                                /* total directory bytes used */ eq(TEST_BYTE_USED)));
+
+        verifyNoMoreInteractions(staticMockMarker(AdServicesStatsLog.class));
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/enrollment/PartnerEnrollmentCheckerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/enrollment/PartnerEnrollmentCheckerTest.java
index 046ce846..b1f8e6ad 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/enrollment/PartnerEnrollmentCheckerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/enrollment/PartnerEnrollmentCheckerTest.java
@@ -19,29 +19,48 @@ package com.android.ondevicepersonalization.services.enrollment;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 
-import com.android.modules.utils.testing.TestableDeviceConfig;
-import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.StableFlags;
 
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.quality.Strictness;
 
 @RunWith(JUnit4.class)
 public class PartnerEnrollmentCheckerTest {
     @Rule
-    public final TestableDeviceConfig.TestableDeviceConfigRule mDeviceConfigRule =
-            new TestableDeviceConfig.TestableDeviceConfigRule();
+    public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
+            .mockStatic(FlagsFactory.class)
+            .spyStatic(StableFlags.class)
+            .setStrictness(Strictness.LENIENT)
+            .build();
+
+    private String mCallerAppAllowList;
+    private String mIsolatedServiceAllowList;
+
+    private Flags mTestFlags = new Flags() {
+        @Override public String getCallerAppAllowList() {
+            return mCallerAppAllowList;
+        }
+        @Override public String getIsolatedServiceAllowList() {
+            return mIsolatedServiceAllowList;
+        }
+    };
 
     @Before
     public void setup() throws Exception {
-        PhFlagsTestUtil.setUpDeviceConfigPermissions();
+        ExtendedMockito.doReturn(mTestFlags).when(FlagsFactory::getFlags);
     }
 
     @Test
     public void testIsCallerAppEnrolled() {
-        PhFlagsTestUtil.setCallerAppAllowList("app1,app2,app3,app5:certapp5");
+        mCallerAppAllowList = "app1,app2,app3,app5:certapp5";
         assertTrue(PartnerEnrollmentChecker.isCallerAppEnrolled("app1"));
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled("app"));
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled("app4"));
@@ -49,12 +68,12 @@ public class PartnerEnrollmentCheckerTest {
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled(""));
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled(null));
 
-        PhFlagsTestUtil.setCallerAppAllowList("*");
+        mCallerAppAllowList = "*";
         assertTrue(PartnerEnrollmentChecker.isCallerAppEnrolled("random"));
         assertTrue(PartnerEnrollmentChecker.isCallerAppEnrolled(""));
         assertTrue(PartnerEnrollmentChecker.isCallerAppEnrolled(null));
 
-        PhFlagsTestUtil.setCallerAppAllowList("");
+        mCallerAppAllowList = "";
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled("random"));
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled(""));
         assertFalse(PartnerEnrollmentChecker.isCallerAppEnrolled(null));
@@ -62,7 +81,7 @@ public class PartnerEnrollmentCheckerTest {
 
     @Test
     public void testIsIsolatedServiceEnrolled() {
-        PhFlagsTestUtil.setIsolatedServiceAllowList("svc1,svc2,svc3,svc5:certsvc5");
+        mIsolatedServiceAllowList = "svc1,svc2,svc3,svc5:certsvc5";
         assertTrue(PartnerEnrollmentChecker.isIsolatedServiceEnrolled("svc1"));
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled("svc"));
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled("svc4"));
@@ -70,12 +89,12 @@ public class PartnerEnrollmentCheckerTest {
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(""));
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(null));
 
-        PhFlagsTestUtil.setIsolatedServiceAllowList("*");
+        mIsolatedServiceAllowList = "*";
         assertTrue(PartnerEnrollmentChecker.isIsolatedServiceEnrolled("random"));
         assertTrue(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(""));
         assertTrue(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(null));
 
-        PhFlagsTestUtil.setIsolatedServiceAllowList("");
+        mIsolatedServiceAllowList = "";
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled("random"));
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(""));
         assertFalse(PartnerEnrollmentChecker.isIsolatedServiceEnrolled(null));
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
index 682892c2..15bda2ea 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
@@ -41,8 +41,6 @@ import androidx.test.core.app.ApplicationProvider;
 import com.android.compatibility.common.util.ShellUtils;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
-import com.android.modules.utils.testing.TestableDeviceConfig;
-import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
 import com.android.ondevicepersonalization.services.data.events.EventState;
 import com.android.ondevicepersonalization.services.data.events.EventsDao;
@@ -99,7 +97,6 @@ public class FederatedComputeServiceImplTest {
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
-            .addStaticMockFixtures(TestableDeviceConfig::new)
             .spyStatic(UserPrivacyStatus.class)
             .setStrictness(Strictness.LENIENT)
             .build();
@@ -129,7 +126,6 @@ public class FederatedComputeServiceImplTest {
                         mApplicationContext,
                         mInjector);
         mServiceProxy = IFederatedComputeService.Stub.asInterface(mServiceImpl);
-        PhFlagsTestUtil.setUpDeviceConfigPermissions();
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
index 086d5600..40245087 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
@@ -20,6 +20,8 @@ import static android.federatedcompute.common.ClientConstants.EXAMPLE_STORE_ACTI
 import static android.federatedcompute.common.ClientConstants.EXTRA_EXAMPLE_ITERATOR_RESULT;
 import static android.federatedcompute.common.ClientConstants.EXTRA_EXAMPLE_ITERATOR_RESUMPTION_TOKEN;
 
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -48,9 +50,13 @@ import androidx.test.core.app.ApplicationProvider;
 
 import com.android.compatibility.common.util.ShellUtils;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
-import com.android.modules.utils.testing.TestableDeviceConfig;
-import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
+import com.android.odp.module.common.Clock;
+import com.android.odp.module.common.MonotonicClock;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.StableFlags;
 import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
 import com.android.ondevicepersonalization.services.data.events.EventState;
 import com.android.ondevicepersonalization.services.data.events.EventsDao;
@@ -62,34 +68,56 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.InjectMocks;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class OdpExampleStoreServiceTests {
     private static final String SERVICE_CLASS = "com.test.TestPersonalizationService";
-    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private static final Context APPLICATION_CONTEXT = ApplicationProvider.getApplicationContext();
+    private static final ComponentName ISOLATED_SERVICE_COMPONENT =
+            new ComponentName(APPLICATION_CONTEXT.getPackageName(), SERVICE_CLASS);
+    private static final ContextData TEST_CONTEXT_DATA =
+            new ContextData(
+                    ISOLATED_SERVICE_COMPONENT.getPackageName(),
+                    ISOLATED_SERVICE_COMPONENT.getClassName());
+    private static final String TEST_POPULATION_NAME = "PopulationName";
+    private static final String TEST_TASK_NAME = "TaskName";
+    private static final String TEST_COLLECTION_URI = "CollectionUri";
+    private static final int LATCH_LONG_TIMEOUT_MILLIS = 10000;
+    private static final int LATCH_SHORT_TIMEOUT_MILLIS = 1000;
+
     @Mock Context mMockContext;
     @InjectMocks OdpExampleStoreService mService;
 
-    @Mock
-    UserPrivacyStatus mUserPrivacyStatus;
+    @Mock UserPrivacyStatus mMockUserPrivacyStatus;
+
+    @Mock Clock mMockClock;
+
+    private Flags mStubFlags = new Flags() {
+        @Override public boolean getGlobalKillSwitch() {
+            return false;
+        }
+    };
 
     @Rule
-    public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
-            .addStaticMockFixtures(TestableDeviceConfig::new)
-            .spyStatic(UserPrivacyStatus.class)
-            .setStrictness(Strictness.LENIENT)
-            .build();
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this)
+                    .spyStatic(UserPrivacyStatus.class)
+                    .mockStatic(FlagsFactory.class)
+                    .spyStatic(StableFlags.class)
+                    .spyStatic(MonotonicClock.class)
+                    .setStrictness(Strictness.LENIENT)
+                    .build();
+
     private CountDownLatch mLatch;
-    private ComponentName mIsolatedService;
+
+
 
     private boolean mIteratorCallbackOnSuccessCalled = false;
     private boolean mIteratorCallbackOnFailureCalled = false;
@@ -97,30 +125,26 @@ public class OdpExampleStoreServiceTests {
     private boolean mQueryCallbackOnSuccessCalled = false;
     private boolean mQueryCallbackOnFailureCalled = false;
 
-    private final EventsDao mEventsDao = EventsDao.getInstanceForTest(mContext);
-
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(new Object[][] {{true}, {false}});
-    }
+    private final EventsDao mEventsDao = EventsDao.getInstanceForTest(APPLICATION_CONTEXT);
 
     @Before
     public void setUp() throws Exception {
         assumeTrue(DeviceSupportHelper.isDeviceSupported());
         initMocks(this);
-        when(mMockContext.getApplicationContext()).thenReturn(mContext);
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        doReturn(true).when(mUserPrivacyStatus).isMeasurementEnabled();
-        doReturn(true).when(mUserPrivacyStatus).isProtectedAudienceEnabled();
+        when(mMockContext.getApplicationContext()).thenReturn(APPLICATION_CONTEXT);
+        ExtendedMockito.doReturn(mMockUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        ExtendedMockito.doReturn(mMockClock).when(MonotonicClock::getInstance);
+        doReturn(true).when(mMockUserPrivacyStatus).isMeasurementEnabled();
+        doReturn(true).when(mMockUserPrivacyStatus).isProtectedAudienceEnabled();
+        doReturn(200L).when(mMockClock).currentTimeMillis();
+        doReturn(1000L).when(mMockClock).elapsedRealtime();
         mQueryCallbackOnSuccessCalled = false;
         mQueryCallbackOnFailureCalled = false;
         mLatch = new CountDownLatch(1);
-        mIsolatedService = new ComponentName(mContext.getPackageName(), SERVICE_CLASS);
-        PhFlagsTestUtil.setUpDeviceConfigPermissions();
-        PhFlagsTestUtil.setSharedIsolatedProcessFeatureEnabled(mIsSipFeatureEnabled);
+
+        ExtendedMockito.doReturn(mStubFlags).when(FlagsFactory::getFlags);
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
+                () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
     }
 
@@ -128,66 +152,50 @@ public class OdpExampleStoreServiceTests {
     public void testStartQuery_lessThanMinExample_failure() throws Exception {
         mEventsDao.updateOrInsertEventState(
                 new EventState.Builder()
-                        .setTaskIdentifier("PopulationName")
-                        .setService(mIsolatedService)
+                        .setTaskIdentifier(TEST_POPULATION_NAME)
+                        .setService(ISOLATED_SERVICE_COMPONENT)
                         .setToken()
                         .build());
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
-        Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
-        input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
-        input.putString(ClientConstants.EXTRA_POPULATION_NAME, "PopulationName");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
-        input.putString(ClientConstants.EXTRA_COLLECTION_URI, "CollectionUri");
-        input.putInt(ClientConstants.EXTRA_ELIGIBILITY_MIN_EXAMPLE, 4);
+        Bundle input = getTestInputBundle(/* eligibilityMinExample= */ 4);
 
         binder.startQuery(input, callback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(5000, TimeUnit.MILLISECONDS));
-
+                mLatch.await(LATCH_LONG_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertTrue(mQueryCallbackOnFailureCalled);
     }
 
     @Test
-    public void testStartQuery_moreThanMinExample_failure() throws Exception {
+    public void testStartQuery_moreThanMinExample_success() throws Exception {
         mEventsDao.updateOrInsertEventState(
                 new EventState.Builder()
-                        .setTaskIdentifier("PopulationName")
-                        .setService(mIsolatedService)
+                        .setTaskIdentifier(TEST_POPULATION_NAME)
+                        .setService(ISOLATED_SERVICE_COMPONENT)
                         .setToken()
                         .build());
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
-        Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
-        input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
-        input.putString(ClientConstants.EXTRA_POPULATION_NAME, "PopulationName");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
-        input.putString(ClientConstants.EXTRA_COLLECTION_URI, "CollectionUri");
-        input.putInt(ClientConstants.EXTRA_ELIGIBILITY_MIN_EXAMPLE, 2);
+        Bundle input = getTestInputBundle(/* eligibilityMinExample= */ 2);
 
         binder.startQuery(input, callback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(5000, TimeUnit.MILLISECONDS));
-
+                mLatch.await(LATCH_LONG_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertTrue(mQueryCallbackOnSuccessCalled);
         assertFalse(mQueryCallbackOnFailureCalled);
     }
@@ -196,31 +204,29 @@ public class OdpExampleStoreServiceTests {
     public void testWithStartQuery() throws Exception {
         mEventsDao.updateOrInsertEventState(
                 new EventState.Builder()
-                        .setTaskIdentifier("PopulationName")
-                        .setService(mIsolatedService)
+                        .setTaskIdentifier(TEST_POPULATION_NAME)
+                        .setService(ISOLATED_SERVICE_COMPONENT)
                         .setToken()
                         .build());
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
         Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
         input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
-        input.putString(ClientConstants.EXTRA_POPULATION_NAME, "PopulationName");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
-        input.putString(ClientConstants.EXTRA_COLLECTION_URI, "CollectionUri");
+                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(TEST_CONTEXT_DATA));
+        input.putString(ClientConstants.EXTRA_POPULATION_NAME, TEST_POPULATION_NAME);
+        input.putString(ClientConstants.EXTRA_TASK_ID, TEST_TASK_NAME);
+        input.putString(ClientConstants.EXTRA_COLLECTION_URI, TEST_COLLECTION_URI);
 
         binder.startQuery(input, callback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(5000, TimeUnit.MILLISECONDS));
-
+                mLatch.await(LATCH_LONG_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertTrue(mQueryCallbackOnSuccessCalled);
         assertFalse(mQueryCallbackOnFailureCalled);
 
@@ -229,50 +235,50 @@ public class OdpExampleStoreServiceTests {
         mLatch = new CountDownLatch(1);
         iteratorCallback.setExpected(new byte[] {10}, "token1".getBytes());
         iterator.next(iteratorCallback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(1000, TimeUnit.MILLISECONDS));
+                mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertTrue(mIteratorCallbackOnSuccessCalled);
         assertFalse(mIteratorCallbackOnFailureCalled);
-        mIteratorCallbackOnSuccessCalled = false;
 
+        mIteratorCallbackOnSuccessCalled = false;
         mLatch = new CountDownLatch(1);
         iteratorCallback.setExpected(new byte[] {20}, "token2".getBytes());
         iterator.next(iteratorCallback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(1000, TimeUnit.MILLISECONDS));
+                mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertTrue(mIteratorCallbackOnSuccessCalled);
         assertFalse(mIteratorCallbackOnFailureCalled);
     }
 
     @Test
     public void testWithStartQueryMeasurementControlRevoked() throws Exception {
-        doReturn(false).when(mUserPrivacyStatus).isMeasurementEnabled();
+        doReturn(false).when(mMockUserPrivacyStatus).isMeasurementEnabled();
         mEventsDao.updateOrInsertEventState(
                 new EventState.Builder()
-                        .setTaskIdentifier("PopulationName")
-                        .setService(mIsolatedService)
+                        .setTaskIdentifier(TEST_POPULATION_NAME)
+                        .setService(ISOLATED_SERVICE_COMPONENT)
                         .setToken()
                         .build());
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
         Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
         input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
-        input.putString(ClientConstants.EXTRA_POPULATION_NAME, "PopulationName");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
+                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(TEST_CONTEXT_DATA));
+        input.putString(ClientConstants.EXTRA_POPULATION_NAME, TEST_POPULATION_NAME);
+        input.putString(ClientConstants.EXTRA_TASK_ID, TEST_TASK_NAME);
 
         binder.startQuery(input, callback);
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
 
+        mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertTrue(mQueryCallbackOnFailureCalled);
     }
@@ -281,22 +287,20 @@ public class OdpExampleStoreServiceTests {
     public void testWithStartQueryNotValidJob() throws Exception {
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
         Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
         input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
-        input.putString(ClientConstants.EXTRA_POPULATION_NAME, "PopulationName");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
+                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(TEST_CONTEXT_DATA));
+        input.putString(ClientConstants.EXTRA_POPULATION_NAME, TEST_POPULATION_NAME);
+        input.putString(ClientConstants.EXTRA_TASK_ID, TEST_TASK_NAME);
 
         ((IExampleStoreService.Stub) binder).startQuery(input, callback);
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
 
+        mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertTrue(mQueryCallbackOnFailureCalled);
     }
@@ -305,13 +309,15 @@ public class OdpExampleStoreServiceTests {
     public void testWithStartQueryBadInput() throws Exception {
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
+
         binder.startQuery(Bundle.EMPTY, callback);
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+
+        mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertTrue(mQueryCallbackOnFailureCalled);
     }
@@ -323,7 +329,7 @@ public class OdpExampleStoreServiceTests {
                 .thenReturn(PackageManager.PERMISSION_DENIED);
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
 
@@ -331,7 +337,7 @@ public class OdpExampleStoreServiceTests {
                 SecurityException.class,
                 () -> binder.startQuery(Bundle.EMPTY, new TestQueryCallback()));
 
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(LATCH_SHORT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertFalse(mQueryCallbackOnFailureCalled);
     }
@@ -341,36 +347,45 @@ public class OdpExampleStoreServiceTests {
         mEventsDao.updateOrInsertEventState(
                 new EventState.Builder()
                         .setTaskIdentifier("throw_exception")
-                        .setService(mIsolatedService)
+                        .setService(ISOLATED_SERVICE_COMPONENT)
                         .setToken()
                         .build());
         mService.onCreate();
         Intent intent = new Intent();
-        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(mContext.getPackageName());
+        intent.setAction(EXAMPLE_STORE_ACTION).setPackage(APPLICATION_CONTEXT.getPackageName());
         IExampleStoreService binder =
                 IExampleStoreService.Stub.asInterface(mService.onBind(intent));
         assertNotNull(binder);
         TestQueryCallback callback = new TestQueryCallback();
         Bundle input = new Bundle();
-        ContextData contextData =
-                new ContextData(mIsolatedService.getPackageName(), mIsolatedService.getClassName());
         input.putByteArray(
-                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(contextData));
+                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(TEST_CONTEXT_DATA));
         input.putString(ClientConstants.EXTRA_POPULATION_NAME, "throw_exception");
-        input.putString(ClientConstants.EXTRA_TASK_ID, "TaskName");
-        input.putString(ClientConstants.EXTRA_COLLECTION_URI, "CollectionUri");
+        input.putString(ClientConstants.EXTRA_TASK_ID, TEST_TASK_NAME);
+        input.putString(ClientConstants.EXTRA_COLLECTION_URI, TEST_COLLECTION_URI);
         input.putInt(ClientConstants.EXTRA_ELIGIBILITY_MIN_EXAMPLE, 4);
 
         binder.startQuery(input, callback);
+
         assertTrue(
                 "timeout reached while waiting for countdownlatch!",
-                mLatch.await(5000, TimeUnit.MILLISECONDS));
-
+                mLatch.await(LATCH_LONG_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
         assertFalse(mQueryCallbackOnSuccessCalled);
         assertTrue(mQueryCallbackOnFailureCalled);
     }
 
-    public class TestIteratorCallback implements IExampleStoreIteratorCallback {
+    private static Bundle getTestInputBundle(int eligibilityMinExample) throws Exception {
+        Bundle input = new Bundle();
+        input.putByteArray(
+                ClientConstants.EXTRA_CONTEXT_DATA, ContextData.toByteArray(TEST_CONTEXT_DATA));
+        input.putString(ClientConstants.EXTRA_POPULATION_NAME, TEST_POPULATION_NAME);
+        input.putString(ClientConstants.EXTRA_TASK_ID, TEST_TASK_NAME);
+        input.putString(ClientConstants.EXTRA_COLLECTION_URI, TEST_COLLECTION_URI);
+        input.putInt(ClientConstants.EXTRA_ELIGIBILITY_MIN_EXAMPLE, eligibilityMinExample);
+        return input;
+    }
+
+    private class TestIteratorCallback implements IExampleStoreIteratorCallback {
         byte[] mExpectedExample;
         byte[] mExpectedResumptionToken;
 
@@ -401,7 +416,7 @@ public class OdpExampleStoreServiceTests {
         }
     }
 
-    public class TestQueryCallback implements IExampleStoreCallback {
+    private class TestQueryCallback implements IExampleStoreCallback {
         private IExampleStoreIterator mIterator;
 
         @Override
@@ -431,7 +446,7 @@ public class OdpExampleStoreServiceTests {
     @After
     public void cleanup() {
         OnDevicePersonalizationDbHelper dbHelper =
-                OnDevicePersonalizationDbHelper.getInstanceForTest(mContext);
+                OnDevicePersonalizationDbHelper.getInstanceForTest(APPLICATION_CONTEXT);
         dbHelper.getWritableDatabase().close();
         dbHelper.getReadableDatabase().close();
         dbHelper.close();
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
index 98683315..e62f7834 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
@@ -42,6 +42,7 @@ import android.os.ParcelFileDescriptor;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 
 import org.junit.Before;
@@ -93,7 +94,8 @@ public class IsolatedModelServiceImplTest {
         modelService.runInference(bundle, callback);
 
         InferenceOutputParcel result = verifyAndGetCallbackResult(callback);
-        Map<Integer, Object> outputs = result.getData();
+        Map<Integer, Object> outputs =
+                (Map<Integer, Object>) ByteArrayUtil.deserializeObject(result.getData());
         float[] output1 = (float[]) outputs.get(0);
         assertThat(output1.length).isEqualTo(1);
     }
@@ -120,7 +122,8 @@ public class IsolatedModelServiceImplTest {
         modelService.runInference(bundle, callback);
 
         InferenceOutputParcel result = verifyAndGetCallbackResult(callback);
-        Map<Integer, Object> outputs = result.getData();
+        Map<Integer, Object> outputs =
+                (Map<Integer, Object>) ByteArrayUtil.deserializeObject(result.getData());
         float[] output1 = (float[]) outputs.get(0);
         assertThat(output1.length).isEqualTo(numExample);
     }
@@ -146,7 +149,8 @@ public class IsolatedModelServiceImplTest {
         modelService.runInference(bundle, callback);
 
         InferenceOutputParcel result = verifyAndGetCallbackResult(callback);
-        Map<Integer, Object> outputs = result.getData();
+        Map<Integer, Object> outputs =
+                (Map<Integer, Object>) ByteArrayUtil.deserializeObject(result.getData());
         float[] output1 = (float[]) outputs.get(0);
         assertThat(output1.length).isEqualTo(numExample);
     }
@@ -171,7 +175,8 @@ public class IsolatedModelServiceImplTest {
         modelService.runInference(bundle, callback);
 
         InferenceOutputParcel result = verifyAndGetCallbackResult(callback);
-        Map<Integer, Object> outputs = result.getData();
+        Map<Integer, Object> outputs =
+                (Map<Integer, Object>) ByteArrayUtil.deserializeObject(result.getData());
         float[] output1 = (float[]) outputs.get(0);
         assertThat(output1.length).isEqualTo(numExample);
     }
@@ -231,28 +236,6 @@ public class IsolatedModelServiceImplTest {
                                 .build());
     }
 
-    @Test
-    public void runModelInference_missingModelOutput() throws Exception {
-        InferenceInput inferenceInput =
-                // Not set output structure in InferenceOutput.
-                new InferenceInput.Builder(
-                                mParams,
-                                generateInferenceInput(1),
-                                new InferenceOutput.Builder().build())
-                        .build();
-
-        Bundle bundle = new Bundle();
-        bundle.putBinder(Constants.EXTRA_DATA_ACCESS_SERVICE_BINDER, new TestDataAccessService());
-        bundle.putParcelable(
-                Constants.EXTRA_INFERENCE_INPUT, new InferenceInputParcel(inferenceInput));
-
-        IsolatedModelServiceImpl modelService = new IsolatedModelServiceImpl();
-        var callback = new TestServiceCallback();
-        modelService.runInference(bundle, callback);
-
-        verifyCallBackError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
-    }
-
     @Test
     public void runModelInference_modelNotExist() throws Exception {
         InferenceInput.Params params =
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunnerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
similarity index 81%
rename from tests/servicetests/src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunnerTest.java
rename to tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
index 0621f75e..064a0a58 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/SharedIsolatedProcessRunnerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
@@ -17,13 +17,17 @@
 package com.android.ondevicepersonalization.services.process;
 
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
-import static com.android.ondevicepersonalization.services.process.SharedIsolatedProcessRunner.TRUSTED_PARTNER_APPS_SIP;
-import static com.android.ondevicepersonalization.services.process.SharedIsolatedProcessRunner.UNKNOWN_APPS_SIP;
+import static com.android.ondevicepersonalization.services.process.IsolatedServiceBindingRunner.TRUSTED_PARTNER_APPS_SIP;
+import static com.android.ondevicepersonalization.services.process.IsolatedServiceBindingRunner.UNKNOWN_APPS_SIP;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
@@ -35,18 +39,21 @@ import android.adservices.ondevicepersonalization.aidl.IIsolatedServiceCallback;
 import android.annotation.NonNull;
 import android.content.ComponentName;
 import android.content.Context;
+import android.content.pm.ServiceInfo;
 import android.os.Bundle;
 
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.federatedcompute.internal.util.AbstractServiceBinder;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OdpServiceException;
 import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.StableFlags;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
@@ -67,10 +74,10 @@ import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
 
 @RunWith(JUnit4.class)
-public class SharedIsolatedProcessRunnerTest {
+public class IsolatedServiceBindingRunnerTest {
 
-    private static final SharedIsolatedProcessRunner sSipRunner =
-            SharedIsolatedProcessRunner.getInstance();
+    private final IsolatedServiceBindingRunner mRunner =
+            new IsolatedServiceBindingRunner();
 
     private static final String TRUSTED_APP_NAME = "trusted_app_name";
     private static final int CALLBACK_TIMEOUT_SECONDS = 60;
@@ -89,10 +96,10 @@ public class SharedIsolatedProcessRunnerTest {
             .setStrictness(Strictness.LENIENT)
             .build();
 
-    private final SharedIsolatedProcessRunner.Injector mTestInjector =
-            new SharedIsolatedProcessRunner.Injector();
+    private final IsolatedServiceBindingRunner.Injector mTestInjector =
+            new IsolatedServiceBindingRunner.Injector();
 
-    private SharedIsolatedProcessRunner mInstanceUnderTest;
+    private IsolatedServiceBindingRunner mInstanceUnderTest;
     private final CountDownLatch mCountDownLatch = new CountDownLatch(1);
     private final FutureCallback<Object> mTestCallback =
             new FutureCallback<Object>() {
@@ -109,14 +116,16 @@ public class SharedIsolatedProcessRunnerTest {
 
     @Before
     public void setup() throws Exception {
+        assumeTrue(DeviceSupportHelper.isDeviceSupported());
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
 
         ExtendedMockito.doReturn(mFlags).when(FlagsFactory::getFlags);
         ExtendedMockito.doReturn(TRUSTED_APP_NAME).when(
                 () -> StableFlags.get(KEY_TRUSTED_PARTNER_APPS_LIST));
-
+        ExtendedMockito.doReturn(true).when(
+                () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
         mInstanceUnderTest =
-                new SharedIsolatedProcessRunner(
+                new IsolatedServiceBindingRunner(
                         ApplicationProvider.getApplicationContext(), mTestInjector);
     }
 
@@ -124,7 +133,7 @@ public class SharedIsolatedProcessRunnerTest {
     public void testGetSipInstanceName_artImageLoadingOptimizationEnabled() {
         ExtendedMockito.doReturn(true).when(
                 () -> StableFlags.get(KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED));
-        assertThat(sSipRunner.getSipInstanceName(TRUSTED_APP_NAME))
+        assertThat(mRunner.getSipInstanceName(TRUSTED_APP_NAME))
                 .isEqualTo(TRUSTED_PARTNER_APPS_SIP + "_disable_art_image_");
     }
 
@@ -132,7 +141,7 @@ public class SharedIsolatedProcessRunnerTest {
     public void testGetSipInstanceName_trustedApp() {
         ExtendedMockito.doReturn(false).when(
                 () -> StableFlags.get(KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED));
-        assertThat(sSipRunner.getSipInstanceName(TRUSTED_APP_NAME))
+        assertThat(mRunner.getSipInstanceName(TRUSTED_APP_NAME))
                 .isEqualTo(TRUSTED_PARTNER_APPS_SIP);
     }
 
@@ -140,10 +149,47 @@ public class SharedIsolatedProcessRunnerTest {
     public void testGetSipInstanceName_unknownApp() {
         ExtendedMockito.doReturn(false).when(
                 () -> StableFlags.get(KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED));
-        assertThat(sSipRunner.getSipInstanceName("unknown_app_name"))
+        assertThat(mRunner.getSipInstanceName("unknown_app_name"))
                 .isEqualTo(UNKNOWN_APPS_SIP);
     }
 
+    @Test
+    public void testCheckIsolatedService() throws Exception {
+        ServiceInfo si = new ServiceInfo();
+        si.flags = si.FLAG_ISOLATED_PROCESS;
+        mRunner.checkIsolatedService(new ComponentName("a", "b"), si);  // does not throw
+    }
+
+    @Test
+    public void testCheckIsolatedServiceThrowsIfIsolatedProcessTagNotInManifest()
+            throws Exception {
+        ServiceInfo si = new ServiceInfo();
+        si.flags = 0;
+        assertThrows(
+                OdpServiceException.class,
+                () -> mRunner.checkIsolatedService(new ComponentName("a", "b"), si));
+    }
+
+    @Test
+    public void testIsSharedIsolatedProcessRequested() {
+        assumeTrue(SdkLevel.isAtLeastU());
+        ServiceInfo si = new ServiceInfo();
+        si.flags = si.FLAG_ISOLATED_PROCESS;
+        assertFalse(mRunner.isSharedIsolatedProcessRequested(si));
+        si.flags |= si.FLAG_ALLOW_SHARED_ISOLATED_PROCESS;
+        assertTrue(mRunner.isSharedIsolatedProcessRequested(si));
+    }
+
+    @Test
+    public void testIsSharedIsolatedProcessRequestedAlwaysFalseOnT() {
+        assumeTrue(SdkLevel.isAtLeastT() && !SdkLevel.isAtLeastU());
+        ServiceInfo si = new ServiceInfo();
+        si.flags = si.FLAG_ISOLATED_PROCESS;
+        assertFalse(mRunner.isSharedIsolatedProcessRequested(si));
+        si.flags |= si.FLAG_ALLOW_SHARED_ISOLATED_PROCESS;
+        assertFalse(mRunner.isSharedIsolatedProcessRequested(si));
+    }
+
     @Test
     @Ignore("TODO: b/342672147 - temporary disable failing tests.")
     public void testLoadIsolatedService_packageManagerNameNotFoundException_failedFuture()
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
index 20463f2f..875ed6a2 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
@@ -51,6 +51,7 @@ import com.android.ondevicepersonalization.internal.util.ByteArrayParceledSlice;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.internal.util.PersistableBundleUtils;
 import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.StableFlags;
 import com.android.ondevicepersonalization.services.data.DbUtils;
 import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
@@ -72,18 +73,16 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
 import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.List;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class AppRequestFlowTest {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = AppRequestFlowTest.class.getSimpleName();
@@ -108,22 +107,12 @@ public class AppRequestFlowTest {
     @Mock
     UserPrivacyStatus mUserPrivacyStatus;
     @Mock private NoiseUtil mMockNoiseUtil;
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
 
     class TestFlags implements Flags {
         int mIsolatedServiceDeadlineSeconds = 30;
         String mOutputDataAllowList = "*;*";
         String mPlatformDataAllowList = "";
+        boolean mIsIsolatedServiceDebuggingEnabled = true;
 
         @Override public boolean getGlobalKillSwitch() {
             return false;
@@ -139,6 +128,11 @@ public class AppRequestFlowTest {
         public String getDefaultPlatformDataForExecuteAllowlist() {
             return mPlatformDataAllowList;
         }
+
+        @Override
+        public boolean isIsolatedServiceDebuggingEnabled() {
+            return mIsIsolatedServiceDebuggingEnabled;
+        }
     }
 
     private TestFlags mSpyFlags = new TestFlags();
@@ -146,6 +140,7 @@ public class AppRequestFlowTest {
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule =
             new ExtendedMockitoRule.Builder(this)
+                    .mockStatic(FlagsFactory.class)
                     .spyStatic(StableFlags.class)
                     .spyStatic(UserPrivacyStatus.class)
                     .setStrictness(Strictness.LENIENT)
@@ -156,7 +151,8 @@ public class AppRequestFlowTest {
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
 
         ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
         doReturn(true).when(mUserPrivacyStatus).isMeasurementEnabled();
         doReturn(true).when(mUserPrivacyStatus).isProtectedAudienceEnabled();
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
index 69bb4086..49d5385f 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
@@ -58,16 +58,14 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
 import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.CountDownLatch;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class RenderFlowTest {
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
@@ -86,24 +84,17 @@ public class RenderFlowTest {
 
     @Mock UserPrivacyStatus mUserPrivacyStatus;
     @Mock CryptUtils mCryptUtils;
-
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
-
     private Flags mSpyFlags = new Flags() {
         int mIsolatedServiceDeadlineSeconds = 30;
+        boolean mIsIsolatedServiceDebuggingEnabled = true;
         @Override public int getIsolatedServiceDeadlineSeconds() {
             return mIsolatedServiceDeadlineSeconds;
         }
+
+        @Override
+        public boolean isIsolatedServiceDebuggingEnabled() {
+            return mIsIsolatedServiceDebuggingEnabled;
+        }
     };
 
     @Rule
@@ -120,7 +111,7 @@ public class RenderFlowTest {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
 
         setUpTestDate();
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
index 408ea6b5..d96011b7 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
@@ -54,16 +54,14 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
 import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.CountDownLatch;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class WebTriggerFlowTest {
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
@@ -78,18 +76,6 @@ public class WebTriggerFlowTest {
 
     @Mock UserPrivacyStatus mUserPrivacyStatus;
 
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
-
     static class TestFlags implements Flags {
         int mIsolatedServiceDeadlineSeconds = 30;
         boolean mGlobalKillSwitch = false;
@@ -117,7 +103,7 @@ public class WebTriggerFlowTest {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
 
         ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
index 7804bb2e..c708351d 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
@@ -56,15 +56,13 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
+import org.junit.runners.JUnit4;
 import org.mockito.quality.Strictness;
 
 import java.nio.charset.StandardCharsets;
-import java.util.Arrays;
-import java.util.Collection;
 import java.util.concurrent.CountDownLatch;
 
-@RunWith(Parameterized.class)
+@RunWith(JUnit4.class)
 public class WebViewFlowTest {
 
     private static final String SERVICE_CLASS = "com.test.TestPersonalizationService";
@@ -77,24 +75,13 @@ public class WebViewFlowTest {
     private FlowCallback mCallback;
     private static final ServiceFlowOrchestrator sSfo = ServiceFlowOrchestrator.getInstance();
 
-    @Parameterized.Parameter(0)
-    public boolean mIsSipFeatureEnabled;
-
-    @Parameterized.Parameters
-    public static Collection<Object[]> data() {
-        return Arrays.asList(
-                new Object[][] {
-                        {true}, {false}
-                }
-        );
-    }
-
     private Flags mSpyFlags = new Flags() {
         int mIsolatedServiceDeadlineSeconds = 30;
         @Override public int getIsolatedServiceDeadlineSeconds() {
             return mIsolatedServiceDeadlineSeconds;
         }
     };
+    private static final int DELAY_MILLIS = 2000;
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
@@ -107,7 +94,7 @@ public class WebViewFlowTest {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ShellUtils.runShellCommand("settings put global hidden_api_policy 1");
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doReturn(SdkLevel.isAtLeastU() && mIsSipFeatureEnabled).when(
+        ExtendedMockito.doReturn(SdkLevel.isAtLeastU()).when(
                 () -> StableFlags.get(KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED));
 
         mDao = EventsDao.getInstanceForTest(mContext);
@@ -173,6 +160,8 @@ public class WebViewFlowTest {
         assertThat(mCallback.mSuccess).isTrue();
         assertThat(mCallback.mFailure).isFalse();
 
+        Thread.sleep(DELAY_MILLIS);
+
         FlowCallback callback = new FlowCallback();
         sSfo.schedule(ServiceFlowType.WEB_VIEW_FLOW,
                 mContext, ComponentName.createRelative(mContext.getPackageName(), SERVICE_CLASS),
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/util/LogUtilsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/util/LogUtilsTest.java
index 04eb7897..2bc35b10 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/util/LogUtilsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/util/LogUtilsTest.java
@@ -17,7 +17,15 @@
 package com.android.ondevicepersonalization.services.util;
 
 import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
 
+import android.adservices.ondevicepersonalization.Constants;
 import android.adservices.ondevicepersonalization.EventLogRecord;
 import android.adservices.ondevicepersonalization.RequestLogRecord;
 import android.content.ComponentName;
@@ -25,18 +33,29 @@ import android.content.ContentValues;
 import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
 
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
 import com.android.ondevicepersonalization.services.data.events.EventsContract;
 import com.android.ondevicepersonalization.services.data.events.QueriesContract;
+import com.android.ondevicepersonalization.services.statsd.OdpStatsdLogger;
 
 import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
 
 import java.util.Collections;
 import java.util.List;
 
-public class LogUtilsTest {
+@RunWith(AndroidJUnit4.class)
+@MockStatic(OdpStatsdLogger.class)
+public final class LogUtilsTest {
     private static final String APP = "com.example.app";
     private final Context mContext = ApplicationProvider.getApplicationContext();
     private final ComponentName mService =
@@ -44,6 +63,16 @@ public class LogUtilsTest {
     private final OnDevicePersonalizationDbHelper mDbHelper =
             OnDevicePersonalizationDbHelper.getInstanceForTest(mContext);
 
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+    @Mock private OdpStatsdLogger mMockOdpStatsdLogger;
+
+    @Before
+    public void setup(){
+        when(OdpStatsdLogger.getInstance()).thenReturn(mMockOdpStatsdLogger);
+    }
+
     @After
     public void cleanup() {
         mDbHelper.getWritableDatabase().close();
@@ -56,11 +85,19 @@ public class LogUtilsTest {
         assertEquals(
                 -1L,
                 LogUtils.writeLogRecords(
+                        Constants.TASK_TYPE_EXECUTE,
                         mContext,
                         APP,
                         mService,
                         null,
                         Collections.emptyList()).get().longValue());
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_REQUEST_LOG),
+                        eq(Constants.STATUS_REQUEST_LOG_IS_NULL),
+                        anyLong(),
+                        anyString());
     }
 
     @Test
@@ -72,15 +109,23 @@ public class LogUtilsTest {
                         .addRow(new ContentValues())
                         .build();
         long queryId = LogUtils.writeLogRecords(
+                Constants.TASK_TYPE_EXECUTE,
                 mContext,
                 APP,
                 mService,
                 requestLogRecord,
-                Collections.emptyList()).get().longValue();
+                Collections.emptyList()).get();
         long queriesSizeAfter = getDbTableSize(QueriesContract.QueriesEntry.TABLE_NAME);
         long eventsSizeAfter = getDbTableSize(EventsContract.EventsEntry.TABLE_NAME);
         assertEquals(1, queriesSizeAfter - queriesSizeBefore);
         assertEquals(0, eventsSizeAfter - eventsSizeBefore);
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_REQUEST_LOG),
+                        eq(Constants.STATUS_REQUEST_LOG_DB_SUCCESS),
+                        anyLong(),
+                        anyString());
     }
 
     @Test
@@ -90,15 +135,23 @@ public class LogUtilsTest {
         RequestLogRecord requestLogRecord =
                 new RequestLogRecord.Builder().build();
         long queryId = LogUtils.writeLogRecords(
+                Constants.TASK_TYPE_EXECUTE,
                 mContext,
                 APP,
                 mService,
                 requestLogRecord,
-                Collections.emptyList()).get().longValue();
+                Collections.emptyList()).get();
         long queriesSizeAfter = getDbTableSize(QueriesContract.QueriesEntry.TABLE_NAME);
         long eventsSizeAfter = getDbTableSize(EventsContract.EventsEntry.TABLE_NAME);
         assertEquals(1, queriesSizeAfter - queriesSizeBefore);
         assertEquals(0, eventsSizeAfter - eventsSizeBefore);
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_REQUEST_LOG),
+                        eq(Constants.STATUS_REQUEST_LOG_IS_EMPTY),
+                        anyLong(),
+                        anyString());
     }
 
     @Test
@@ -111,11 +164,19 @@ public class LogUtilsTest {
                         .addRow(new ContentValues())
                         .build();
         long queryId = LogUtils.writeLogRecords(
+                Constants.TASK_TYPE_EXECUTE,
                 mContext,
                 APP,
                 mService,
                 requestLogRecord,
-                Collections.emptyList()).get().longValue();
+                Collections.emptyList()).get();
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_REQUEST_LOG),
+                        eq(Constants.STATUS_REQUEST_LOG_DB_SUCCESS),
+                        anyLong(),
+                        anyString());
         RequestLogRecord requestLogRecord2 =
                 new RequestLogRecord.Builder()
                         .setRequestId(queryId)
@@ -143,16 +204,24 @@ public class LogUtilsTest {
                         .setRequestLogRecord(requestLogRecord2)
                         .build();
         queryId = LogUtils.writeLogRecords(
-                mContext,
-                APP,
-                mService,
-                null,
-                List.of(eventLogRecord1, eventLogRecord2, eventLogRecord3))
-                .get().longValue();
+                        Constants.TASK_TYPE_EXECUTE,
+                        mContext,
+                        APP,
+                        mService,
+                        null,
+                        List.of(eventLogRecord1, eventLogRecord2, eventLogRecord3))
+                .get();
         long queriesSizeAfter = getDbTableSize(QueriesContract.QueriesEntry.TABLE_NAME);
         long eventsSizeAfter = getDbTableSize(EventsContract.EventsEntry.TABLE_NAME);
         assertEquals(1, queriesSizeAfter - queriesSizeBefore);
         assertEquals(3, eventsSizeAfter - eventsSizeBefore);
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_EVENT_LOG),
+                        eq(Constants.STATUS_EVENT_LOG_DB_SUCCESS),
+                        anyLong(),
+                        anyString());
     }
 
     @Test
@@ -170,15 +239,30 @@ public class LogUtilsTest {
                         .setData(new ContentValues())
                         .build();
         long queryId = LogUtils.writeLogRecords(
+                Constants.TASK_TYPE_EXECUTE,
                 mContext,
                 APP,
                 mService,
                 requestLogRecord,
-                List.of(eventLogRecord)).get().longValue();
+                List.of(eventLogRecord)).get();
         long queriesSizeAfter = getDbTableSize(QueriesContract.QueriesEntry.TABLE_NAME);
         long eventsSizeAfter = getDbTableSize(EventsContract.EventsEntry.TABLE_NAME);
         assertEquals(1, queriesSizeAfter - queriesSizeBefore);
         assertEquals(1, eventsSizeAfter - eventsSizeBefore);
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_REQUEST_LOG),
+                        eq(Constants.STATUS_REQUEST_LOG_DB_SUCCESS),
+                        anyLong(),
+                        anyString());
+        verify(mMockOdpStatsdLogger)
+                .logTraceEventStats(
+                        anyInt(),
+                        eq(Constants.EVENT_TYPE_WRITE_EVENT_LOG),
+                        eq(Constants.STATUS_EVENT_LOG_DB_SUCCESS),
+                        anyLong(),
+                        anyString());
     }
 
     private int getDbTableSize(String tableName) {
diff --git a/tests/systemserviceapitests/Android.bp b/tests/systemserviceapitests/Android.bp
index 966b6669..4c6ead58 100644
--- a/tests/systemserviceapitests/Android.bp
+++ b/tests/systemserviceapitests/Android.bp
@@ -33,6 +33,7 @@ android_test {
         "androidx.test.ext.truth",
         "androidx.test.rules",
         "modules-utils-build",
+        "ondevicepersonalization-testing-utils",
     ],
     sdk_version: "module_current",
     target_sdk_version: "current",
diff --git a/tests/systemserviceapitests/AndroidTest.xml b/tests/systemserviceapitests/AndroidTest.xml
index 5af5d42a..d030e35b 100644
--- a/tests/systemserviceapitests/AndroidTest.xml
+++ b/tests/systemserviceapitests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OnDevicePersonalizationSystemServiceApiTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false"/>
         <option name="package" value="com.android.ondevicepersonalization.systemserviceapitests"/>
diff --git a/tests/systemserviceapitests/src/com/android/ondevicepersonalization/systemserviceapitests/OdpSystemServiceApiTest.java b/tests/systemserviceapitests/src/com/android/ondevicepersonalization/systemserviceapitests/OdpSystemServiceApiTest.java
index 57f1cf02..08cee254 100644
--- a/tests/systemserviceapitests/src/com/android/ondevicepersonalization/systemserviceapitests/OdpSystemServiceApiTest.java
+++ b/tests/systemserviceapitests/src/com/android/ondevicepersonalization/systemserviceapitests/OdpSystemServiceApiTest.java
@@ -16,7 +16,6 @@
 
 package com.android.ondevicepersonalization.systemserviceapitests;
 
-import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertTrue;
 
@@ -29,7 +28,10 @@ import android.os.Bundle;
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.modules.utils.build.SdkLevel;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
+import org.junit.Assume;
+import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -40,16 +42,16 @@ import java.util.concurrent.CountDownLatch;
 public class OdpSystemServiceApiTest {
     private final Context mContext = ApplicationProvider.getApplicationContext();
     boolean mOnRequestCalled = false;
-    boolean mSetPersonalizationStatusCalled = false;
-    boolean mReadPersonalizationStatusCalled = false;
-    CountDownLatch mLatch = new CountDownLatch(3);
+    CountDownLatch mLatch = new CountDownLatch(1);
+
+    @Before
+    public void setUp() {
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(SdkLevel.isAtLeastU());
+    }
 
     @Test
     public void testInvokeSystemServerServiceSucceedsOnU() throws Exception {
-        if (!SdkLevel.isAtLeastU()) {
-            return;
-        }
-
         OnDevicePersonalizationSystemServiceManager manager =
                 mContext.getSystemService(OnDevicePersonalizationSystemServiceManager.class);
         assertNotEquals(null, manager);
@@ -70,43 +72,7 @@ public class OdpSystemServiceApiTest {
                     }
                 });
 
-        //TODO(b/302991761): delete the file in system server.
-        service.setPersonalizationStatus(false,
-                new IOnDevicePersonalizationSystemServiceCallback.Stub() {
-                    @Override public void onResult(Bundle result) {
-                        mSetPersonalizationStatusCalled = true;
-                        mLatch.countDown();
-                    }
-                    @Override public void onError(int errorCode) {
-                        mSetPersonalizationStatusCalled = true;
-                        mLatch.countDown();
-                    }
-                });
-
-        service.readPersonalizationStatus(
-                new IOnDevicePersonalizationSystemServiceCallback.Stub() {
-                    @Override public void onResult(Bundle result) {
-                        mReadPersonalizationStatusCalled = true;
-                        mLatch.countDown();
-                    }
-                    @Override public void onError(int errorCode) {
-                        mReadPersonalizationStatusCalled = true;
-                        mLatch.countDown();
-                    }
-                });
         mLatch.await();
         assertTrue(mOnRequestCalled);
-        assertTrue(mSetPersonalizationStatusCalled);
-        assertTrue(mReadPersonalizationStatusCalled);
-    }
-
-    @Test
-    public void testNullSystemServiceOnT() throws Exception {
-        if (SdkLevel.isAtLeastU()) {
-            return;
-        }
-        assertEquals(
-                null,
-                mContext.getSystemService(OnDevicePersonalizationSystemServiceManager.class));
     }
 }
diff --git a/tests/systemserviceimpltests/AndroidTest.xml b/tests/systemserviceimpltests/AndroidTest.xml
index feb73f65..db51a2ec 100644
--- a/tests/systemserviceimpltests/AndroidTest.xml
+++ b/tests/systemserviceimpltests/AndroidTest.xml
@@ -26,6 +26,19 @@
         <option name="test-file-name" value="OnDevicePersonalizationSystemServiceImplTests.apk"/>
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+    </target_preparer>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest">
         <option name="hidden-api-checks" value="false" />
         <option name="package" value="com.android.ondevicepersonalization.systemserviceimpltests"/>
diff --git a/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/BooleanFileDataStoreTest.java b/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/BooleanFileDataStoreTest.java
deleted file mode 100644
index 87394edc..00000000
--- a/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/BooleanFileDataStoreTest.java
+++ /dev/null
@@ -1,139 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.server.ondevicepersonalization;
-
-import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.assertTrue;
-
-import android.content.Context;
-
-import androidx.test.core.app.ApplicationProvider;
-
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Test;
-
-import java.io.IOException;
-import java.util.Set;
-
-public class BooleanFileDataStoreTest {
-    private static final Context APPLICATION_CONTEXT = ApplicationProvider.getApplicationContext();
-    private static final String FILENAME = "BooleanFileDatastoreTest";
-    private static final String TEST_KEY = "key";
-    private static final int TEST_KEY_COUNT = 10;
-
-    private BooleanFileDataStore mDataStore;
-
-    @Before
-    public void setup() throws IOException {
-        mDataStore = new BooleanFileDataStore(
-                        APPLICATION_CONTEXT.getFilesDir().getAbsolutePath(), FILENAME);
-        mDataStore.initialize();
-    }
-
-    @Test
-    public void testInitializeEmptyBooleanFileDatastore() {
-        assertTrue(mDataStore.keySet().isEmpty());
-    }
-
-    @Test
-    public void testNullOrEmptyKeyFails() {
-        assertThrows(
-                NullPointerException.class,
-                () -> {
-                    mDataStore.put(null, true);
-                });
-
-        assertThrows(
-                IllegalArgumentException.class,
-                () -> {
-                    mDataStore.put("", true);
-                });
-        assertThrows(
-                NullPointerException.class,
-                () -> {
-                    mDataStore.get(null);
-                });
-
-        assertThrows(
-                IllegalArgumentException.class,
-                () -> {
-                    mDataStore.get("");
-                });
-    }
-
-    @Test
-    public void testPutGetUpdate() throws IOException {
-        // Empty
-        assertNull(mDataStore.get(TEST_KEY));
-
-        // Put
-        mDataStore.put(TEST_KEY, false);
-
-        // Get
-        Boolean readValue = mDataStore.get(TEST_KEY);
-        assertEquals(false, readValue);
-
-        // Update
-        mDataStore.put(TEST_KEY, true);
-        readValue = mDataStore.get(TEST_KEY);
-        assertEquals(true, readValue);
-
-        // Test overwrite
-        Set<String> keys = mDataStore.keySet();
-        assertEquals(keys.size(), 1);
-        assertTrue(keys.contains(TEST_KEY));
-    }
-
-    @Test
-    public void testClearAll() throws IOException {
-        for (int i = 0; i < TEST_KEY_COUNT; ++i) {
-            mDataStore.put(TEST_KEY + i, true);
-        }
-        assertEquals(TEST_KEY_COUNT, mDataStore.keySet().size());
-        mDataStore.clear();
-        mDataStore.initialize();
-        assertTrue(mDataStore.keySet().isEmpty());
-    }
-
-    @Test
-    public void testReinitializeFromDisk() throws IOException {
-        for (int i = 0; i < TEST_KEY_COUNT; ++i) {
-            mDataStore.put(TEST_KEY + i, true);
-        }
-        assertEquals(TEST_KEY_COUNT, mDataStore.keySet().size());
-
-        // Mock memory crash
-        mDataStore.clearLocalMapForTesting();
-        assertTrue(mDataStore.keySet().isEmpty());
-
-        // Re-initialize from the file and still be able to recover
-        mDataStore.initialize();
-        assertEquals(TEST_KEY_COUNT, mDataStore.keySet().size());
-        for (int i = 0; i < TEST_KEY_COUNT; ++i) {
-            Boolean readValue = mDataStore.get(TEST_KEY + i);
-            assertEquals(true, readValue);
-        }
-    }
-
-    @After
-    public void tearDown() {
-        mDataStore.tearDownForTesting();
-    }
-}
diff --git a/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/OdpSystemServiceImplTest.java b/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/OdpSystemServiceImplTest.java
index 000d7571..36af06cd 100644
--- a/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/OdpSystemServiceImplTest.java
+++ b/tests/systemserviceimpltests/src/com/android/server/ondevicepersonalization/OdpSystemServiceImplTest.java
@@ -16,19 +16,8 @@
 
 package com.android.server.ondevicepersonalization;
 
-import static com.android.server.ondevicepersonalization.OnDevicePersonalizationSystemService.PERSONALIZATION_STATUS_KEY;
-
-import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doThrow;
-import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.verify;
-import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertNotNull;
-import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 
-import android.adservices.ondevicepersonalization.Constants;
 import android.content.Context;
 import android.ondevicepersonalization.IOnDevicePersonalizationSystemServiceCallback;
 import android.os.Bundle;
@@ -36,52 +25,32 @@ import android.os.Bundle;
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.modules.utils.build.SdkLevel;
-import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
-import org.junit.After;
 import org.junit.Assume;
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
-import org.mockito.quality.Strictness;
 
 import java.util.concurrent.CountDownLatch;
 
 @RunWith(JUnit4.class)
 public class OdpSystemServiceImplTest {
     private final Context mContext = ApplicationProvider.getApplicationContext();
-    private static final String TEST_CONFIG_FILE_IDENTIFIER = "TEST_CONFIG";
-    private static final String BAD_TEST_KEY = "non-exist-key";
-    private final BooleanFileDataStore mTestDataStore =
-                    new BooleanFileDataStore(mContext.getFilesDir().getAbsolutePath(),
-                                    TEST_CONFIG_FILE_IDENTIFIER);
-    private boolean mOnResultCalled;
-    private boolean mOnErrorCalled;
+    private boolean mOnResultCalled = false;
+    private boolean mOnErrorCalled = false;
     private Bundle mResult;
-    private int mErrorCode;
-    private CountDownLatch mLatch;
-    private OnDevicePersonalizationSystemService mService;
+    private int mErrorCode = 0;
+    private CountDownLatch mLatch = new CountDownLatch(1);
+    private OnDevicePersonalizationSystemService mService =
+            new OnDevicePersonalizationSystemService(mContext);
     private IOnDevicePersonalizationSystemServiceCallback mCallback;
 
-    @Rule
-    public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
-            .setStrictness(Strictness.LENIENT)
-            .build();
-
     @Before
     public void setUp() throws Exception {
         Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
         Assume.assumeTrue(SdkLevel.isAtLeastU());
-        mService = spy(new OnDevicePersonalizationSystemService(mContext, mTestDataStore));
-        doNothing().when(mService).enforceCallingPermission();
-        mOnResultCalled = false;
-        mOnErrorCalled = false;
-        mResult = null;
-        mErrorCode = 0;
-        mLatch = new CountDownLatch(1);
         mCallback = new IOnDevicePersonalizationSystemServiceCallback.Stub() {
             @Override
             public void onResult(Bundle bundle) {
@@ -97,7 +66,6 @@ public class OdpSystemServiceImplTest {
                 mLatch.countDown();
             }
         };
-        assertNotNull(mCallback);
     }
 
     @Test
@@ -105,53 +73,5 @@ public class OdpSystemServiceImplTest {
         mService.onRequest(new Bundle(), mCallback);
         mLatch.await();
         assertTrue(mOnResultCalled);
-        assertNull(mResult);
-        verify(mService).enforceCallingPermission();
-    }
-
-    @Test
-    public void testSystemServerServiceSetPersonalizationStatus() throws Exception {
-        mService.setPersonalizationStatus(true, mCallback);
-        mLatch.await();
-        assertTrue(mOnResultCalled);
-        assertNotNull(mResult);
-        boolean inputBool = mResult.getBoolean(PERSONALIZATION_STATUS_KEY);
-        assertTrue(inputBool);
-        verify(mService).enforceCallingPermission();
-    }
-
-    @Test
-    public void testSystemServerServiceReadPersonalizationStatusSuccess() throws Exception {
-        mTestDataStore.put(PERSONALIZATION_STATUS_KEY, true);
-        mService.readPersonalizationStatus(mCallback);
-        assertTrue(mOnResultCalled);
-        assertNotNull(mResult);
-        boolean inputBool = mResult.getBoolean(PERSONALIZATION_STATUS_KEY);
-        assertTrue(inputBool);
-        verify(mService).enforceCallingPermission();
-    }
-
-    @Test
-    public void testSystemServerServiceReadPersonalizationStatusNotFound() throws Exception {
-        mTestDataStore.put(BAD_TEST_KEY, true);
-        mService.readPersonalizationStatus(mCallback);
-        assertTrue(mOnErrorCalled);
-        assertNull(mResult);
-        assertEquals(mErrorCode, Constants.STATUS_KEY_NOT_FOUND);
-        verify(mService).enforceCallingPermission();
-    }
-
-    @Test
-    public void testSystemServerServiceSetPersonalizationStatusPermissionDenied()
-            throws Exception {
-        doThrow(SecurityException.class).when(mService).enforceCallingPermission();
-        assertThrows(
-                SecurityException.class,
-                () -> mService.setPersonalizationStatus(true, mCallback));
-    }
-
-    @After
-    public void cleanUp() {
-        mTestDataStore.tearDownForTesting();
     }
 }
diff --git a/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/DeviceSupportHelper.java b/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/DeviceSupportHelper.java
index 1e3c2a0b..e3212d56 100644
--- a/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/DeviceSupportHelper.java
+++ b/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/DeviceSupportHelper.java
@@ -17,11 +17,14 @@ package com.android.ondevicepersonalization.testing.utils;
 
 import android.app.Instrumentation;
 import android.content.pm.PackageManager;
+import android.os.Build;
+import android.os.ext.SdkExtensions;
 
 import androidx.test.platform.app.InstrumentationRegistry;
 
 /** Helper to check if device is enabled or supports OnDevicePersonalization module */
 public final class DeviceSupportHelper {
+    private static final int MIN_SDK_EXT = 13;  // M2024-08
 
     /**
      * Check whether the device is supported.
@@ -38,4 +41,13 @@ public final class DeviceSupportHelper {
                 // Android Go
                 && !pm.hasSystemFeature(PackageManager.FEATURE_RAM_LOW);
     }
+
+    /**
+     * Check whether the ODP module with public APIs is installed on the device.
+     * For CTS only.
+     */
+    public static boolean isOdpModuleAvailable() {
+        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM
+                || SdkExtensions.getExtensionVersion(SdkExtensions.AD_SERVICES) >= MIN_SDK_EXT;
+    }
 }
diff --git a/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/ResultReceiver.java b/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/ResultReceiver.java
index aa5dafea..9290c7c3 100644
--- a/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/ResultReceiver.java
+++ b/tests/testutils/src/com/android/ondevicepersonalization/testing/utils/ResultReceiver.java
@@ -37,7 +37,7 @@ public class ResultReceiver<T> implements OutcomeReceiver<T, Exception> {
 
     /** Creates a ResultReceiver. */
     public ResultReceiver() {
-        this(Duration.ofSeconds(30));
+        this(Duration.ofSeconds(60));
     }
 
     /** Creates a ResultReceiver with a deadline. */
@@ -99,7 +99,12 @@ public class ResultReceiver<T> implements OutcomeReceiver<T, Exception> {
 
     /** Returns the exception message. */
     public String getErrorMessage() throws InterruptedException {
-        await();
+        try {
+            await();
+        } catch (Exception e) {
+            return "ResultReceiver failed: " + e.getClass().getSimpleName()
+                    + ": " + e.getMessage();
+        }
         if (mException != null) {
             return mException.getClass().getSimpleName()
                     + ": " + mException.getMessage();
```

