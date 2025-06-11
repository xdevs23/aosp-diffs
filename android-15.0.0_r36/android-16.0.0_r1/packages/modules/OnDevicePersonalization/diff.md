```diff
diff --git a/Android.bp b/Android.bp
index 7e661a5c..5d9eaab8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,6 +55,17 @@ filegroup {
     path: "src",
 }
 
+filegroup {
+    name: "ondevicepersonalization-flags-constants-sources",
+    srcs: [
+        "src/com/android/ondevicepersonalization/services/FlagsConstants.java",
+    ],
+    path: "src",
+    visibility: [
+        "//packages/modules/OnDevicePersonalization/tests/testutils",
+    ],
+}
+
 filegroup {
     name: "chronicle-sources",
     srcs: [
@@ -115,16 +126,18 @@ android_app {
         "kotlin-stdlib",
         "kotlinx_coroutines",
         "kotlinx-coroutines-android",
-        "ondevicepersonalization-protos",
         "mobile_data_downloader_lib",
         "modules-utils-build",
         "ondevicepersonalization-plugin-lib",
+        "ondevicepersonalization-protos",
         "flatbuffers-java",
         "apache-velocity-engine-core",
         "owasp-java-encoder",
         "tensorflowlite_java",
         "tensorflow_core_proto_java_lite",
         "adservices-shared-spe",
+        "common-ondevicepersonalization-protos",
+        "adservices-shared-datastore", // For proto data store.
     ],
     sdk_version: "module_current",
     min_sdk_version: "33",
diff --git a/OWNERS b/OWNERS
index 1e6d84ae..1b3d000a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,16 +1,8 @@
 # Bug component: 1117807
 akvuong@google.com
-cazheng@google.com
-cuiq@google.com
 fumengyao@google.com
-karthik@google.com
 karthikmahesh@google.com
-leoni@google.com
-maco@google.com
 paragkulkarni@google.com
 qiaoli@google.com
-ryangu@google.com
 tarading@google.com
-xueyiwang@google.com
 yanning@google.com
-ymu@google.com
diff --git a/TEST_MAPPING b/TEST_MAPPING
index d91e2fc3..71bb9fcf 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -31,6 +31,10 @@
     {
       // Install com.google.android.ondevicepersonalization.apex and run CtsOnDevicePersonalizationConfigTests.
       "name": "CtsOnDevicePersonalizationConfigTests[com.google.android.ondevicepersonalization.apex]"
+    },
+    {
+      // Install com.google.android.ondevicepersonalization.apex and run CtsSandboxOnDevicePersonalizationManagerTests.
+      "name": "CtsSandboxOnDevicePersonalizationManagerTests[com.google.android.ondevicepersonalization.apex]"
     }
   ],
   "presubmit": [
@@ -57,6 +61,9 @@
     },
     {
       "name": "CtsOnDevicePersonalizationConfigTests"
+    },
+    {
+      "name": "CtsSandboxOnDevicePersonalizationManagerTests"
     }
   ],
   "ondevicepersonalization-mainline-presubmit": [
@@ -83,6 +90,9 @@
     },
     {
       "name": "CtsOnDevicePersonalizationConfigTests"
+    },
+    {
+      "name": "CtsSandboxOnDevicePersonalizationManagerTests"
     }
   ]
 }
diff --git a/common/Android.bp b/common/Android.bp
index d768fbfe..6018fb26 100644
--- a/common/Android.bp
+++ b/common/Android.bp
@@ -16,6 +16,29 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+java_library {
+    name: "common-ondevicepersonalization-protos",
+    proto: {
+        type: "lite",
+        canonical_path_from_root: false,
+        include_dirs: [
+            "external/protobuf/src",
+            "external/protobuf/java",
+        ],
+    },
+    sdk_version: "system_current",
+    min_sdk_version: "Tiramisu",
+    srcs: [
+        "proto/*.proto",
+        ":libprotobuf-internal-protos",
+    ],
+    visibility: ["//packages/modules/OnDevicePersonalization:__subpackages__"],
+    apex_available: [
+        "com.android.ondevicepersonalization",
+    ],
+    static_libs: ["libprotobuf-java-lite", "guava"]
+}
+
 filegroup {
     name: "common-ondevicepersonalization-sources",
     srcs: [
diff --git a/common/java/com/android/odp/module/common/FileUtils.java b/common/java/com/android/odp/module/common/FileUtils.java
index a280cd03..db9cb75f 100644
--- a/common/java/com/android/odp/module/common/FileUtils.java
+++ b/common/java/com/android/odp/module/common/FileUtils.java
@@ -74,6 +74,15 @@ public class FileUtils {
         }
     }
 
+    /** Delete the provided file if it exists. */
+    public static boolean deleteFileIfExist(String fileName) {
+        if (fileName == null || fileName.trim().isEmpty()) {
+            return true;
+        }
+        File fileToDelete = new File(fileName);
+        return fileToDelete.delete();
+    }
+
     /** Read the input file content to a byte array. */
     public static byte[] readFileAsByteArray(String filePath) throws IOException {
         File file = new File(filePath);
diff --git a/common/java/com/android/odp/module/common/ProcessWrapper.java b/common/java/com/android/odp/module/common/ProcessWrapper.java
new file mode 100644
index 00000000..bbbbaabd
--- /dev/null
+++ b/common/java/com/android/odp/module/common/ProcessWrapper.java
@@ -0,0 +1,39 @@
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
+package com.android.odp.module.common;
+
+import android.os.Process;
+
+/**
+ * A wrapper that provides access to android.os.Process class methods and details. This helps
+ * tests by providing a mockable object and not impacting other Process class level interactions.
+ */
+public class ProcessWrapper {
+    private ProcessWrapper() {}
+
+    /** Returns whether the provided UID belongs to an sdk sandbox process. */
+    public static boolean isSdkSandboxUid(int uid) {
+        return Process.isSdkSandboxUid(uid);
+    }
+
+    /** Returns the app uid corresponding to an sdk sandbox uid.
+     * @throws IllegalArgumentException if input is not an sdk sandbox uid
+     */
+    public static int getAppUidForSdkSandboxUid(int uid) {
+        return Process.getAppUidForSdkSandboxUid(uid);
+    }
+}
diff --git a/common/java/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStore.java b/common/java/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStore.java
new file mode 100644
index 00000000..e28aa337
--- /dev/null
+++ b/common/java/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStore.java
@@ -0,0 +1,108 @@
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
+import android.content.Context;
+
+import androidx.datastore.guava.GuavaDataStore;
+
+import com.android.adservices.shared.datastore.ProtoSerializer;
+import com.android.odp.module.common.proto.ErrorReportingMetadata;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.protobuf.ExtensionRegistryLite;
+import com.google.protobuf.Timestamp;
+
+import java.util.concurrent.Executor;
+
+public class ErrorReportingMetadataProtoDataStore implements ErrorReportingMetadataStore {
+
+    @VisibleForTesting static final String FILE_NAME = "error_reporting_metadata.binarypb";
+
+    private static volatile ErrorReportingMetadataStore sInstance = null;
+
+    private final GuavaDataStore<ErrorReportingMetadata> mErrorReportingMetadataStore;
+
+    @VisibleForTesting
+    ErrorReportingMetadataProtoDataStore(
+            Context context, Executor backgroundExecutor, String fileName) {
+        mErrorReportingMetadataStore =
+                new GuavaDataStore.Builder(
+                                context,
+                                fileName,
+                                new ProtoSerializer<ErrorReportingMetadata>(
+                                        ErrorReportingMetadata.getDefaultInstance(),
+                                        ExtensionRegistryLite.getEmptyRegistry()))
+                        .setExecutor(backgroundExecutor)
+                        .build();
+    }
+
+    /**
+     * @return The instance of {@link ErrorReportingMetadataStore}.
+     */
+    public static ErrorReportingMetadataStore getInstance(
+            Context context, Executor backgroundExecutor) {
+        if (sInstance == null) {
+            synchronized (ErrorReportingMetadataProtoDataStore.class) {
+                if (sInstance == null) {
+                    sInstance =
+                            new ErrorReportingMetadataProtoDataStore(
+                                    context, backgroundExecutor, FILE_NAME);
+                }
+            }
+        }
+        return sInstance;
+    }
+
+    /**
+     * Set the error reporting metadata.
+     *
+     * @param metadata The metadata to persist.
+     * @return A {@link ListenableFuture} that resolves when the set operation succeeds.
+     */
+    @Override
+    public ListenableFuture<ErrorReportingMetadata> set(ErrorReportingMetadata metadata) {
+        return mErrorReportingMetadataStore.updateDataAsync(currentDevSession -> metadata);
+    }
+
+    /**
+     * Get the dev session state.
+     *
+     * @return A future when the operation is complete, containing the current state.
+     */
+    @Override
+    public ListenableFuture<ErrorReportingMetadata> get() {
+        return mErrorReportingMetadataStore.getDataAsync();
+    }
+
+    /** Returns whether the provided {@link ErrorReportingMetadata} is unset/uninitialized. */
+    public static boolean isErrorReportingMetadataUninitialized(ErrorReportingMetadata metadata) {
+        return ErrorReportingMetadata.getDefaultInstance().equals(metadata);
+    }
+
+    /**
+     * Returns a {@link ErrorReportingMetadata} object created from the provided current time-stamp.
+     *
+     * @param currentEpochTime the seconds since epoch in UTC
+     * @return corresponding {@link ErrorReportingMetadata}.
+     */
+    public static ErrorReportingMetadata getMetadata(long currentEpochTime) {
+        Timestamp timestamp = Timestamp.newBuilder().setSeconds(currentEpochTime).build();
+        return ErrorReportingMetadata.newBuilder().setLastSuccessfulUpload(timestamp).build();
+    }
+}
diff --git a/common/java/com/android/odp/module/common/data/ErrorReportingMetadataStore.java b/common/java/com/android/odp/module/common/data/ErrorReportingMetadataStore.java
new file mode 100644
index 00000000..3472596b
--- /dev/null
+++ b/common/java/com/android/odp/module/common/data/ErrorReportingMetadataStore.java
@@ -0,0 +1,42 @@
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
+import com.android.odp.module.common.proto.ErrorReportingMetadata;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+/** Provides ability to get or set the {@link ErrorReportingMetadata} */
+public interface ErrorReportingMetadataStore {
+
+    /**
+     * Set the error reporting metadata.
+     *
+     * @param metadata The metadata to persist.
+     * @return A {@link ListenableFuture} that resolves when the set operation succeeds, the future
+     *     resolves with the persisted {@link ErrorReportingMetadata}
+     */
+    ListenableFuture<ErrorReportingMetadata> set(ErrorReportingMetadata metadata);
+
+    /**
+     * Get the error reporting metadata.
+     *
+     * @return A {@link ListenableFuture} that resolves with an instance of {@link
+     *     ErrorReportingMetadata} that has been persisted.
+     */
+    ListenableFuture<ErrorReportingMetadata> get();
+}
diff --git a/common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java b/common/java/com/android/odp/module/common/data/OdpAuthorizationToken.java
similarity index 95%
rename from common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java
rename to common/java/com/android/odp/module/common/data/OdpAuthorizationToken.java
index ec923b3e..72d9b860 100644
--- a/common/java/com/android/odp/module/common/data/ODPAuthorizationToken.java
+++ b/common/java/com/android/odp/module/common/data/OdpAuthorizationToken.java
@@ -22,7 +22,7 @@ import com.android.ondevicepersonalization.internal.util.AnnotationValidations;
 import com.android.ondevicepersonalization.internal.util.DataClass;
 
 @DataClass(genHiddenBuilder = true, genEqualsHashCode = true)
-public class ODPAuthorizationToken {
+public class OdpAuthorizationToken {
     @NonNull private final String mOwnerIdentifier;
 
     @NonNull private final String mAuthorizationToken;
@@ -45,7 +45,7 @@ public class ODPAuthorizationToken {
     // @formatter:off
 
     @DataClass.Generated.Member
-    /* package-private */ ODPAuthorizationToken(
+    /* package-private */ OdpAuthorizationToken(
             @NonNull String ownerIdentifier,
             @NonNull String authorizationToken,
             @NonNull long creationTime,
@@ -92,7 +92,7 @@ public class ODPAuthorizationToken {
         if (this == o) return true;
         if (o == null || getClass() != o.getClass()) return false;
         @SuppressWarnings("unchecked")
-        ODPAuthorizationToken that = (ODPAuthorizationToken) o;
+        OdpAuthorizationToken that = (OdpAuthorizationToken) o;
         //noinspection PointlessBooleanExpression
         return true
                 && java.util.Objects.equals(mOwnerIdentifier, that.mOwnerIdentifier)
@@ -116,7 +116,7 @@ public class ODPAuthorizationToken {
     }
 
     /**
-     * A builder for {@link ODPAuthorizationToken}
+     * A builder for {@link OdpAuthorizationToken}
      *
      * @hide
      */
@@ -181,12 +181,12 @@ public class ODPAuthorizationToken {
         }
 
         /** Builds the instance. This builder should not be touched after calling this! */
-        public @NonNull ODPAuthorizationToken build() {
+        public @NonNull OdpAuthorizationToken build() {
             checkNotUsed();
             mBuilderFieldsSet |= 0x10; // Mark builder used
 
-            ODPAuthorizationToken o =
-                    new ODPAuthorizationToken(
+            OdpAuthorizationToken o =
+                    new OdpAuthorizationToken(
                             mOwnerIdentifier, mAuthorizationToken, mCreationTime, mExpiryTime);
             return o;
         }
diff --git a/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java b/common/java/com/android/odp/module/common/data/OdpAuthorizationTokenContract.java
similarity index 95%
rename from common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java
rename to common/java/com/android/odp/module/common/data/OdpAuthorizationTokenContract.java
index bdb63a61..0fb0104e 100644
--- a/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenContract.java
+++ b/common/java/com/android/odp/module/common/data/OdpAuthorizationTokenContract.java
@@ -16,7 +16,7 @@
 
 package com.android.odp.module.common.data;
 
-public final class ODPAuthorizationTokenContract {
+public final class OdpAuthorizationTokenContract {
     public static final String ODP_AUTHORIZATION_TOKEN_TABLE = "odp_authorization_tokens";
     public static final String CREATE_ODP_AUTHORIZATION_TOKEN_TABLE =
             "CREATE TABLE "
@@ -31,7 +31,7 @@ public final class ODPAuthorizationTokenContract {
                     + ODPAuthorizationTokenColumns.EXPIRY_TIME
                     + " INTEGER NOT NULL)";
 
-    private ODPAuthorizationTokenContract() {}
+    private OdpAuthorizationTokenContract() {}
 
     public static final class ODPAuthorizationTokenColumns {
         private ODPAuthorizationTokenColumns() {}
diff --git a/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java b/common/java/com/android/odp/module/common/data/OdpAuthorizationTokenDao.java
similarity index 80%
rename from common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java
rename to common/java/com/android/odp/module/common/data/OdpAuthorizationTokenDao.java
index ad43ac2a..ace0cf3b 100644
--- a/common/java/com/android/odp/module/common/data/ODPAuthorizationTokenDao.java
+++ b/common/java/com/android/odp/module/common/data/OdpAuthorizationTokenDao.java
@@ -16,7 +16,7 @@
 
 package com.android.odp.module.common.data;
 
-import static com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
+import static com.android.odp.module.common.data.OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
 
 import android.annotation.NonNull;
 import android.content.ContentValues;
@@ -27,20 +27,20 @@ import android.database.sqlite.SQLiteException;
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODPAuthorizationTokenColumns;
+import com.android.odp.module.common.data.OdpAuthorizationTokenContract.ODPAuthorizationTokenColumns;
 
 import com.google.common.annotations.VisibleForTesting;
 
-public class ODPAuthorizationTokenDao {
-    private static final String TAG = ODPAuthorizationTokenDao.class.getSimpleName();
+public class OdpAuthorizationTokenDao {
+    private static final String TAG = OdpAuthorizationTokenDao.class.getSimpleName();
 
     private final OdpSQLiteOpenHelper mDbHelper;
 
     private final Clock mClock;
 
-    private static volatile ODPAuthorizationTokenDao sSingletonInstance;
+    private static volatile OdpAuthorizationTokenDao sSingletonInstance;
 
-    private ODPAuthorizationTokenDao(OdpSQLiteOpenHelper dbHelper, Clock clock) {
+    private OdpAuthorizationTokenDao(OdpSQLiteOpenHelper dbHelper, Clock clock) {
         mDbHelper = dbHelper;
         mClock = clock;
     }
@@ -49,34 +49,33 @@ public class ODPAuthorizationTokenDao {
      * @return an instance of ODPAuthorizationTokenDao given a context
      */
     @NonNull
-    public static ODPAuthorizationTokenDao getInstance(OdpSQLiteOpenHelper dbHelper) {
+    public static OdpAuthorizationTokenDao getInstance(OdpSQLiteOpenHelper dbHelper) {
         if (sSingletonInstance == null) {
-            synchronized (ODPAuthorizationTokenDao.class) {
+            synchronized (OdpAuthorizationTokenDao.class) {
                 if (sSingletonInstance == null) {
                     sSingletonInstance =
-                            new ODPAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
+                            new OdpAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
                 }
             }
         }
         return sSingletonInstance;
     }
 
-    /** Return a test instance with in-memory database. It is for test only. */
+    /**
+     * Return a test instance of the {@link OdpAuthorizationTokenDao} that uses the provided db
+     * helper instance. It is for use in tests only.
+     *
+     * <p>Returns a new instance everytime unlike the regular {@link #getInstance} method.
+     */
     @VisibleForTesting
-    public static ODPAuthorizationTokenDao getInstanceForTest(OdpSQLiteOpenHelper dbHelper) {
-        if (sSingletonInstance == null) {
-            synchronized (ODPAuthorizationTokenDao.class) {
-                if (sSingletonInstance == null) {
-                    sSingletonInstance =
-                            new ODPAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
-                }
-            }
-        }
+    public static synchronized OdpAuthorizationTokenDao getInstanceForTest(
+            OdpSQLiteOpenHelper dbHelper) {
+        sSingletonInstance = new OdpAuthorizationTokenDao(dbHelper, MonotonicClock.getInstance());
         return sSingletonInstance;
     }
 
     /** Insert a token to the odp authorization token table. */
-    public boolean insertAuthorizationToken(ODPAuthorizationToken authorizationToken) {
+    public boolean insertAuthorizationToken(OdpAuthorizationToken authorizationToken) {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
             throw new SQLiteException(TAG + ": Failed to open database.");
@@ -104,7 +103,7 @@ public class ODPAuthorizationTokenDao {
      *
      * @return an unexpired authorization token.
      */
-    public ODPAuthorizationToken getUnexpiredAuthorizationToken(String ownerIdentifier) {
+    public OdpAuthorizationToken getUnexpiredAuthorizationToken(String ownerIdentifier) {
         String selection =
                 ODPAuthorizationTokenColumns.EXPIRY_TIME
                         + " > ? "
@@ -117,7 +116,7 @@ public class ODPAuthorizationTokenDao {
     }
 
     /**
-     * Delete an ODP adopter's authorization token.
+     * Delete an ODP adopter's authorization token independent of whether it is expired or not.
      *
      * @return the number of rows deleted.
      */
@@ -129,11 +128,7 @@ public class ODPAuthorizationTokenDao {
         String whereClause = ODPAuthorizationTokenColumns.OWNER_IDENTIFIER + " = ?";
         String[] whereArgs = {ownerIdentifier};
         int deletedRows = db.delete(ODP_AUTHORIZATION_TOKEN_TABLE, whereClause, whereArgs);
-        LogUtil.d(
-                TAG,
-                "Deleted %d expired tokens for %s from database",
-                deletedRows,
-                ownerIdentifier);
+        LogUtil.d(TAG, "Deleted %d tokens for %s from database", deletedRows, ownerIdentifier);
         return deletedRows;
     }
 
@@ -154,7 +149,7 @@ public class ODPAuthorizationTokenDao {
         return deletedRows;
     }
 
-    private ODPAuthorizationToken readTokenFromDatabase(
+    private OdpAuthorizationToken readTokenFromDatabase(
             String selection, String[] selectionArgs, String orderBy) {
         SQLiteDatabase db = mDbHelper.safeGetReadableDatabase();
         if (db == null) {
@@ -169,7 +164,7 @@ public class ODPAuthorizationTokenDao {
         };
 
         Cursor cursor = null;
-        ODPAuthorizationToken authToken = null;
+        OdpAuthorizationToken authToken = null;
         try {
             cursor =
                     db.query(
@@ -182,8 +177,8 @@ public class ODPAuthorizationTokenDao {
                             /* orderBy= */ orderBy,
                             /* limit= */ String.valueOf(1));
             while (cursor.moveToNext()) {
-                ODPAuthorizationToken.Builder encryptionKeyBuilder =
-                        new ODPAuthorizationToken.Builder(
+                OdpAuthorizationToken.Builder encryptionKeyBuilder =
+                        new OdpAuthorizationToken.Builder(
                                 cursor.getString(
                                         cursor.getColumnIndexOrThrow(
                                                 ODPAuthorizationTokenColumns.OWNER_IDENTIFIER)),
diff --git a/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
index c488fc53..0912144a 100644
--- a/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
+++ b/common/java/com/android/odp/module/common/encryption/OdpEncryptionKeyManager.java
@@ -116,7 +116,7 @@ public class OdpEncryptionKeyManager {
     }
 
     @VisibleForTesting
-    static synchronized void resetForTesting() {
+    public static synchronized void resetForTesting() {
         sBackgroundKeyManager = null;
     }
 
diff --git a/common/proto/error_reporting_metadata.proto b/common/proto/error_reporting_metadata.proto
new file mode 100644
index 00000000..ea221b5f
--- /dev/null
+++ b/common/proto/error_reporting_metadata.proto
@@ -0,0 +1,21 @@
+syntax = "proto3";
+
+package com.android.odp.module.common.proto;
+
+import "google/protobuf/timestamp.proto";
+
+option java_multiple_files = true;
+option java_package = "com.android.odp.module.common.proto";
+
+
+
+/**
+ * Encompasses metadata associated with aggregated error data reporting.
+ */
+message ErrorReportingMetadata {
+  /**
+   * Timestamp corresponding to when the entity associated with this metadata
+   * was created.
+   */
+  google.protobuf.Timestamp last_successful_upload = 1;
+}
diff --git a/federatedcompute/OWNERS b/federatedcompute/OWNERS
index f3f8cf14..27ff0037 100644
--- a/federatedcompute/OWNERS
+++ b/federatedcompute/OWNERS
@@ -1,8 +1,7 @@
 alexbuy@google.com
-hansson@google.com
 karthikmahesh@google.com
 maco@google.com
 qiaoli@google.com
 tarading@google.com
 xueyiwang@google.com
-ymu@google.com
\ No newline at end of file
+ymu@google.com
diff --git a/federatedcompute/apk/Android.bp b/federatedcompute/apk/Android.bp
index 4e978121..e59661bd 100644
--- a/federatedcompute/apk/Android.bp
+++ b/federatedcompute/apk/Android.bp
@@ -65,6 +65,8 @@ android_app {
         "modules-utils-preconditions",
         // Used for client error logging and background job logging.
         "adservices-shared-spe",
+        "common-ondevicepersonalization-protos",
+        "adservices-shared-datastore", // For proto data store.
     ],
     sdk_version: "module_current",
     min_sdk_version: "Tiramisu",
diff --git a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeBroadcastReceiver.java b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeBroadcastReceiver.java
index 1cd3b1aa..94fb0c83 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeBroadcastReceiver.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeBroadcastReceiver.java
@@ -24,7 +24,7 @@ import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
-import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJobService;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJob;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob;
 import com.android.federatedcompute.services.scheduling.FederatedComputeLearningJobScheduleOrchestrator;
 import com.android.odp.module.common.DeviceUtils;
@@ -73,7 +73,7 @@ public class FederatedComputeBroadcastReceiver extends BroadcastReceiver {
             return;
         }
 
-        BackgroundKeyFetchJobService.scheduleJobIfNeeded(context, mFlags);
+        BackgroundKeyFetchJob.schedule(context);
         DeleteExpiredJob.schedule(context, mFlags);
 
         var unused = Futures.submit(() ->
diff --git a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
index d79e12c0..7de91f3c 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
@@ -46,7 +46,7 @@ import com.google.common.annotations.VisibleForTesting;
 import java.util.Objects;
 
 /** Implementation of {@link IFederatedComputeService}. */
-public class FederatedComputeManagingServiceDelegate extends IFederatedComputeService.Stub {
+class FederatedComputeManagingServiceDelegate extends IFederatedComputeService.Stub {
     private static final String TAG = "FcpServiceDelegate";
     @NonNull private final Context mContext;
     private final FederatedComputeStatsdLogger mFcStatsdLogger;
@@ -61,13 +61,13 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
 
     @NonNull private final Injector mInjector;
 
-    public FederatedComputeManagingServiceDelegate(
+    FederatedComputeManagingServiceDelegate(
             @NonNull Context context, FederatedComputeStatsdLogger federatedComputeStatsdLogger) {
         this(context, new Injector(), federatedComputeStatsdLogger, MonotonicClock.getInstance());
     }
 
     @VisibleForTesting
-    public FederatedComputeManagingServiceDelegate(
+    FederatedComputeManagingServiceDelegate(
             @NonNull Context context,
             @NonNull Injector injector,
             FederatedComputeStatsdLogger federatedComputeStatsdLogger,
@@ -75,7 +75,7 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
         mContext = Objects.requireNonNull(context);
         mInjector = Objects.requireNonNull(injector);
         mClock = clock;
-        this.mFcStatsdLogger = federatedComputeStatsdLogger;
+        mFcStatsdLogger = federatedComputeStatsdLogger;
     }
 
     @Override
@@ -83,29 +83,22 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
             String callingPackageName,
             TrainingOptions trainingOptions,
             IFederatedComputeCallback callback) {
-        // Use FederatedCompute instead of caller permission to read experiment flags. It requires
-        // READ_DEVICE_CONFIG permission.
         try {
-            long origId = Binder.clearCallingIdentity();
-            if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
-                ApiCallStats.Builder apiCallStatsBuilder = new ApiCallStats.Builder()
-                        .setApiName(FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE)
-                        .setResponseCode(STATUS_KILL_SWITCH_ENABLED);
-                if (trainingOptions.getOwnerComponentName() != null) {
-                    apiCallStatsBuilder.setSdkPackageName(
-                            trainingOptions.getOwnerComponentName().getPackageName());
-                } else {
-                    apiCallStatsBuilder.setSdkPackageName("");
-                }
-                mFcStatsdLogger.logApiCallStats(apiCallStatsBuilder.build());
-                sendResult(callback, STATUS_KILL_SWITCH_ENABLED);
-                return;
-            }
-            Binder.restoreCallingIdentity(origId);
-
             Objects.requireNonNull(callingPackageName);
             Objects.requireNonNull(callback);
 
+            String sdkPackageName =
+                    trainingOptions.getOwnerComponentName() == null
+                            ? ""
+                            : trainingOptions.getOwnerComponentName().getPackageName();
+            if (isKillSwitchEnabled(
+                    sdkPackageName,
+                    FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE,
+                    callback,
+                    mFcStatsdLogger)) {
+                return;
+            }
+
             final long startServiceTime = mClock.elapsedRealtime();
             FederatedComputeJobManager jobManager = mInjector.getJobManager(mContext);
             FederatedComputeExecutors.getBackgroundExecutor()
@@ -121,23 +114,13 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
                                     LogUtil.e(TAG, e, "Got exception for schedule()");
                                 } finally {
                                     sendResult(callback, resultCode);
-                                    int serviceLatency =
-                                            (int) (mClock.elapsedRealtime() - startServiceTime);
-                                    ApiCallStats.Builder apiCallStatsBuilder =
-                                            new ApiCallStats.Builder()
-                                                    .setApiName(
-                                                            FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE)
-                                                    .setLatencyMillis(serviceLatency)
-                                                    .setResponseCode(resultCode);
-                                    if (trainingOptions.getOwnerComponentName() != null) {
-                                        apiCallStatsBuilder.setSdkPackageName(
-                                                trainingOptions
-                                                        .getOwnerComponentName()
-                                                        .getPackageName());
-                                    } else {
-                                        apiCallStatsBuilder.setSdkPackageName("");
-                                    }
-                                    mFcStatsdLogger.logApiCallStats(apiCallStatsBuilder.build());
+                                    logServiceLatency(
+                                            startServiceTime,
+                                            FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE,
+                                            resultCode,
+                                            sdkPackageName,
+                                            mFcStatsdLogger,
+                                            mClock);
                                 }
                             });
         } catch (NullPointerException | IllegalArgumentException ex) {
@@ -154,27 +137,19 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
             ComponentName ownerComponent,
             String populationName,
             IFederatedComputeCallback callback) {
-        // Use FederatedCompute instead of caller permission to read experiment flags. It requires
-        // READ_DEVICE_CONFIG permission.
         try {
             Objects.requireNonNull(ownerComponent);
-            long origId = Binder.clearCallingIdentity();
-            if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
-                mFcStatsdLogger.logApiCallStats(
-                        new ApiCallStats.Builder()
-                                .setApiName(FEDERATED_COMPUTE_API_CALLED__API_NAME__CANCEL)
-                                .setResponseCode(STATUS_KILL_SWITCH_ENABLED)
-                                .setSdkPackageName(ownerComponent.getPackageName())
-                                .build());
-                sendResult(callback, STATUS_KILL_SWITCH_ENABLED);
-                return;
-            }
-            Binder.restoreCallingIdentity(origId);
-
-
             Objects.requireNonNull(callback);
             Objects.requireNonNull(populationName);
 
+            if (isKillSwitchEnabled(
+                    ownerComponent.getPackageName(),
+                    FEDERATED_COMPUTE_API_CALLED__API_NAME__CANCEL,
+                    callback,
+                    mFcStatsdLogger)) {
+                return;
+            }
+
             final long startServiceTime = mClock.elapsedRealtime();
             FederatedComputeJobManager jobManager = mInjector.getJobManager(mContext);
             FederatedComputeExecutors.getBackgroundExecutor()
@@ -190,23 +165,19 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
                                     LogUtil.e(
                                             TAG,
                                             e,
-                                            "Got exception when call Cancel population: %s, "
+                                            "Got exception when calling cancel for population: %s, "
                                                     + "owner: %s",
                                             populationName,
                                             ownerComponent.flattenToString());
                                 } finally {
                                     sendResult(callback, resultCode);
-                                    int serviceLatency =
-                                            (int) (mClock.elapsedRealtime() - startServiceTime);
-                                    mFcStatsdLogger.logApiCallStats(
-                                            new ApiCallStats.Builder()
-                                                    .setApiName(
-                                                            FEDERATED_COMPUTE_API_CALLED__API_NAME__CANCEL)
-                                                    .setLatencyMillis(serviceLatency)
-                                                    .setResponseCode(resultCode)
-                                                    .setSdkPackageName(
-                                                            ownerComponent.getPackageName())
-                                                    .build());
+                                    logServiceLatency(
+                                            startServiceTime,
+                                            FEDERATED_COMPUTE_API_CALLED__API_NAME__CANCEL,
+                                            resultCode,
+                                            ownerComponent.getPackageName(),
+                                            mFcStatsdLogger,
+                                            mClock);
                                 }
                             });
         } catch (NullPointerException | IllegalArgumentException ex) {
@@ -218,7 +189,54 @@ public class FederatedComputeManagingServiceDelegate extends IFederatedComputeSe
         }
     }
 
-    private void sendResult(@NonNull IFederatedComputeCallback callback, int resultCode) {
+    /** Helper method that logs service latency for the given api. */
+    private static void logServiceLatency(
+            long startServiceTime,
+            int apiName,
+            int resultCode,
+            String sdkPackageName,
+            FederatedComputeStatsdLogger fcStatsdLogger,
+            Clock clock) {
+        int serviceLatency = (int) (clock.elapsedRealtime() - startServiceTime);
+        fcStatsdLogger.logApiCallStats(
+                new ApiCallStats.Builder()
+                        .setApiName(apiName)
+                        .setLatencyMillis(serviceLatency)
+                        .setResponseCode(resultCode)
+                        .setSdkPackageName(sdkPackageName)
+                        .build());
+    }
+
+    /**
+     * Helper method that checks if the kill switch is enabled, returns true/false accordingly.
+     *
+     * <p>Should be called on the calling binder thread.
+     */
+    private static boolean isKillSwitchEnabled(
+            String sdkPackageName,
+            int apiName,
+            @NonNull IFederatedComputeCallback callback,
+            FederatedComputeStatsdLogger fcStatsdLogger) {
+        // Use FederatedCompute instead of caller permission to read experiment flags. It requires
+        // READ_DEVICE_CONFIG permission.
+        long origId = Binder.clearCallingIdentity();
+        boolean killSwitchEnabled = false;
+        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
+            ApiCallStats.Builder apiCallStatsBuilder =
+                    new ApiCallStats.Builder()
+                            .setApiName(apiName)
+                            .setResponseCode(STATUS_KILL_SWITCH_ENABLED)
+                            .setSdkPackageName(sdkPackageName);
+
+            fcStatsdLogger.logApiCallStats(apiCallStatsBuilder.build());
+            sendResult(callback, STATUS_KILL_SWITCH_ENABLED);
+            killSwitchEnabled = true;
+        }
+        Binder.restoreCallingIdentity(origId);
+        return killSwitchEnabled;
+    }
+
+    private static void sendResult(@NonNull IFederatedComputeCallback callback, int resultCode) {
         try {
             if (resultCode == STATUS_SUCCESS) {
                 callback.onSuccess();
diff --git a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImpl.java b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImpl.java
index e43990f6..e8cf1414 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImpl.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImpl.java
@@ -23,7 +23,7 @@ import android.os.IBinder;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
-import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJobService;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJob;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob;
 import com.android.federatedcompute.services.scheduling.FederatedComputeLearningJobScheduleOrchestrator;
 import com.android.federatedcompute.services.statsd.FederatedComputeStatsdLogger;
@@ -59,7 +59,7 @@ public class FederatedComputeManagingServiceImpl extends Service {
             mFcpServiceDelegate =
                     new FederatedComputeManagingServiceDelegate(
                             this, FederatedComputeStatsdLogger.getInstance());
-            BackgroundKeyFetchJobService.scheduleJobIfNeeded(this, mFlags);
+            BackgroundKeyFetchJob.schedule(this);
             DeleteExpiredJob.schedule(this, mFlags);
             var unused = Futures.submit(() ->
                     FederatedComputeLearningJobScheduleOrchestrator.getInstance(this)
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java b/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
index a12659da..cb9155eb 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
@@ -262,6 +262,34 @@ public interface Flags extends ModuleSharedFlags {
         return DEFAULT_SPE_PILOT_JOB_ENABLED;
     }
 
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to
+     * {@code BackgroundKeyFetchJobService}
+     */
+    @FeatureFlag boolean
+            DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB = false;
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to
+     * {@code BackgroundKeyFetchJobService}
+     */
+    default boolean getSpeOnBackgroundKeyFetchJobEnabled() {
+        return DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+    }
+
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code FederatedJobService}
+     */
+    @FeatureFlag boolean DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB = false;
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to
+     * {@code FederatedJobService}
+     */
+    default boolean getSpeOnFederatedJobEnabled() {
+        return DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
+    }
+
     @ConfigFlag int DEFAULT_FCP_TASK_LIMIT_PER_PACKAGE = 50;
 
     default int getFcpTaskLimitPerPackage() {
@@ -274,4 +302,17 @@ public interface Flags extends ModuleSharedFlags {
     default int getFcpCheckpointFileSizeLimit() {
         return FCP_DEFAULT_CHECKPOINT_FILE_SIZE_LIMIT;
     }
+
+    /** Default value for background job sampling logging rate. */
+    int FCP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE = 10;
+
+    /**
+     * Default value for temp file retention. Ideally temp file should be cleaned up after usage.
+     * It's a safe guard job to clean up orphan temp files.
+     */
+    long DEFAULT_TEMP_FILE_TTL_MILLIS = 2 * 60 * 60 * 1000; // 2 hours
+
+    default long getTempFileTtlMillis() {
+        return DEFAULT_TEMP_FILE_TTL_MILLIS;
+    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java b/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java
new file mode 100644
index 00000000..60bdb711
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java
@@ -0,0 +1,92 @@
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
+package com.android.federatedcompute.services.common;
+
+public final class FlagsConstants {
+
+    private FlagsConstants() {
+        throw new UnsupportedOperationException("Contains static constants only");
+    }
+
+    /*
+     * Keys for ALL the flags stored in DeviceConfig.
+     */
+    // Killswitch keys
+    static final String KEY_FEDERATED_COMPUTE_KILL_SWITCH = "federated_compute_kill_switch";
+
+    // OnDevicePersonalization Namespace String from DeviceConfig class
+    static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
+
+    static final String FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL =
+            "fcp_encryption_key_download_url";
+
+    static final String ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH =
+            "enable_background_encryption_key_fetch";
+
+    static final String HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME = "http_request_retry_limit";
+
+    static final String FCP_ENABLE_ENCRYPTION = "fcp_enable_encryption";
+
+    static final String MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME =
+            "min_scheduling_interval_secs_for_federated_computation";
+
+    static final String MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME =
+            "max_scheduling_interval_secs_for_federated_computation";
+
+    static final String DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME =
+            "default_scheduling_period_secs";
+
+    static final String MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME = "max_scheduling_period_secs";
+
+    static final String TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT_CONFIG_NAME =
+            "transient_error_retry_delay_jitter_percent";
+
+    static final String TRANSIENT_ERROR_RETRY_DELAY_SECS_CONFIG_NAME =
+            "transient_error_retry_delay_secs";
+    static final String TRAINING_MIN_BATTERY_LEVEL = "training_min_battery_level";
+    static final String TRAINING_THERMAL_STATUS_TO_THROTTLE = "training_thermal_to_throttle";
+    static final String ENABLE_ELIGIBILITY_TASK = "enable_eligibility_task";
+    static final String TRAINING_CONDITION_CHECK_THROTTLE_PERIOD_MILLIS =
+            "training_condition_check_period_throttle_period_mills";
+    static final String TASK_HISTORY_TTL_MILLIS = "task_history_ttl_millis";
+
+    static final String FCP_RESCHEDULE_LIMIT_CONFIG_NAME = "reschedule_limit";
+    static final String FCP_RECURRENT_RESCHEDULE_LIMIT_CONFIG_NAME = "recurrent_reschedule_limit";
+
+    static final String FCP_MEMORY_SIZE_LIMIT_CONFIG_NAME = "memory_size_limit";
+    static final String FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME = "task_limit_per_package";
+    static final String FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME = "checkpoint_file_size_limit";
+    static final String FCP_ENABLE_CLIENT_ERROR_LOGGING = "fcp_enable_client_error_logging";
+    static final String FCP_ENABLE_BACKGROUND_JOBS_LOGGING = "fcp_enable_background_jobs_logging";
+    static final String FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE =
+            "fcp_background_job_logging_sampling_rate";
+    static final String FCP_JOB_SCHEDULING_LOGGING_ENABLED = "fcp_job_scheduling_logging_enabled";
+
+    static final String FCP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE =
+            "fcp_job_scheduling_logging_sampling_rate";
+    static final String FCP_MODULE_JOB_POLICY = "fcp_module_job_policy";
+    static final String FCP_SPE_PILOT_JOB_ENABLED = "fcp_spe_pilot_job_enabled";
+    static final String FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB =
+            "FcpBackgroundJobs__enable_spe_on_background_key_fetch_job";
+    static final String FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB =
+            "FcpBackgroundJobs__enable_spe_on_federated_job";
+    static final String EXAMPLE_STORE_SERVICE_CALLBACK_TIMEOUT_SEC =
+            "example_store_service_timeout_sec";
+    static final String FCP_TF_ERROR_RESCHEDULE_SECONDS_CONFIG_NAME = "tf_error_reschedule_seconds";
+    static final String EXAMPLE_ITERATOR_NEXT_TIMEOUT_SEC = "example_iterator_next_timeout_sec";
+    static final String FCP_TEMP_FILE_TTL_IN_MILLIS_NAME = "FcpFeatures__temp_file_ttl_in_millis";
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java b/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
index 82df4413..401818d9 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
@@ -16,100 +16,57 @@
 
 package com.android.federatedcompute.services.common;
 
-import android.annotation.NonNull;
+import static com.android.federatedcompute.services.common.FlagsConstants.DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_ELIGIBILITY_TASK;
+import static com.android.federatedcompute.services.common.FlagsConstants.EXAMPLE_ITERATOR_NEXT_TIMEOUT_SEC;
+import static com.android.federatedcompute.services.common.FlagsConstants.EXAMPLE_STORE_SERVICE_CALLBACK_TIMEOUT_SEC;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_CLIENT_ERROR_LOGGING;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_ENCRYPTION;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_JOB_SCHEDULING_LOGGING_ENABLED;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_MEMORY_SIZE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_MODULE_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_RECURRENT_RESCHEDULE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_RESCHEDULE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_SPE_PILOT_JOB_ENABLED;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TEMP_FILE_TTL_IN_MILLIS_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TF_ERROR_RESCHEDULE_SECONDS_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL;
+import static com.android.federatedcompute.services.common.FlagsConstants.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.NAMESPACE_ON_DEVICE_PERSONALIZATION;
+import static com.android.federatedcompute.services.common.FlagsConstants.TASK_HISTORY_TTL_MILLIS;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_CONDITION_CHECK_THROTTLE_PERIOD_MILLIS;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_MIN_BATTERY_LEVEL;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_THERMAL_STATUS_TO_THROTTLE;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRANSIENT_ERROR_RETRY_DELAY_SECS_CONFIG_NAME;
+
 import android.os.SystemProperties;
 import android.provider.DeviceConfig;
 
 import com.android.internal.annotations.VisibleForTesting;
 
-import java.util.Map;
-import java.util.concurrent.ConcurrentHashMap;
-
 /** A placeholder class for PhFlag. */
 public final class PhFlags implements Flags {
-    /*
-     * Keys for ALL the flags stored in DeviceConfig.
-     */
-    // Killswitch keys
-    static final String KEY_FEDERATED_COMPUTE_KILL_SWITCH = "federated_compute_kill_switch";
-
+    private static final PhFlags sSingleton = new PhFlags();
     // SystemProperty prefix. SystemProperty is for overriding OnDevicePersonalization Configs.
     private static final String SYSTEM_PROPERTY_PREFIX = "debug.ondevicepersonalization.";
 
-    // OnDevicePersonalization Namespace String from DeviceConfig class
-    static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
-
-    static final String FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL =
-            "fcp_encryption_key_download_url";
-
-    static final String ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH =
-            "enable_background_encryption_key_fetch";
-
-    static final String HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME = "http_request_retry_limit";
-
-    static final String FCP_ENABLE_ENCRYPTION = "fcp_enable_encryption";
-
-    static final String MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME =
-            "min_scheduling_interval_secs_for_federated_computation";
-
-    static final String MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME =
-            "max_scheduling_interval_secs_for_federated_computation";
-
-    static final String DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME =
-            "default_scheduling_period_secs";
-
-    static final String MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME = "max_scheduling_period_secs";
-
-    static final String TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT_CONFIG_NAME =
-            "transient_error_retry_delay_jitter_percent";
-
-    static final String TRANSIENT_ERROR_RETRY_DELAY_SECS_CONFIG_NAME =
-            "transient_error_retry_delay_secs";
-    static final String TRAINING_MIN_BATTERY_LEVEL = "training_min_battery_level";
-    static final String TRAINING_THERMAL_STATUS_TO_THROTTLE = "training_thermal_to_throttle";
-    static final String ENABLE_ELIGIBILITY_TASK = "enable_eligibility_task";
-    static final String TRAINING_CONDITION_CHECK_THROTTLE_PERIOD_MILLIS =
-            "training_condition_check_period_throttle_period_mills";
-    static final String TASK_HISTORY_TTL_MILLIS = "task_history_ttl_millis";
-
-    static final String FCP_RESCHEDULE_LIMIT_CONFIG_NAME = "reschedule_limit";
-    static final String FCP_RECURRENT_RESCHEDULE_LIMIT_CONFIG_NAME = "recurrent_reschedule_limit";
-
-    static final String FCP_MEMORY_SIZE_LIMIT_CONFIG_NAME = "memory_size_limit";
-    static final String FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME = "task_limit_per_package";
-    static final String FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME = "checkpoint_file_size_limit";
-    static final String FCP_ENABLE_CLIENT_ERROR_LOGGING = "fcp_enable_client_error_logging";
-    static final String FCP_ENABLE_BACKGROUND_JOBS_LOGGING = "fcp_enable_background_jobs_logging";
-    static final String FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE =
-            "fcp_background_job_logging_sampling_rate";
-    static final String FCP_JOB_SCHEDULING_LOGGING_ENABLED = "fcp_job_scheduling_logging_enabled";
-
-    static final String FCP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE =
-            "fcp_job_scheduling_logging_sampling_rate";
-    static final String FCP_MODULE_JOB_POLICY = "fcp_module_job_policy";
-    static final String FCP_SPE_PILOT_JOB_ENABLED = "fcp_spe_pilot_job_enabled";
-    static final String EXAMPLE_STORE_SERVICE_CALLBACK_TIMEOUT_SEC =
-            "example_store_service_timeout_sec";
-    static final String FCP_TF_ERROR_RESCHEDULE_SECONDS_CONFIG_NAME = "tf_error_reschedule_seconds";
-    static final String EXAMPLE_ITERATOR_NEXT_TIMEOUT_SEC = "example_iterator_next_timeout_sec";
-    static final int FCP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE = 10;
-
-    private static final PhFlags sSingleton = new PhFlags();
-
-    // Flag values here remain stable within a process lifecycle, refresh upon process restart
-    private static final Map<String, Object> sStableFlags = new ConcurrentHashMap<>();
-
     private PhFlags() {
-        setStableFlags();
     }
 
-    // Set group of flags that needs to remain stable together at beginning of a workflow
-    // You can also set one stable flag value at the flag's read time if don't need this guarantee
-    private void setStableFlags() {}
-
     /** Returns the singleton instance of the PhFlags. */
-    @NonNull
-    public static PhFlags getInstance() {
+    static PhFlags getInstance() {
         return sSingleton;
     }
 
@@ -326,6 +283,23 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ DEFAULT_SPE_PILOT_JOB_ENABLED);
     }
 
+    @Override
+    public boolean getSpeOnBackgroundKeyFetchJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
+                /* defaultValue= */
+                DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB);
+    }
+
+    @Override
+    public boolean getSpeOnFederatedJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB,
+                /* defaultValue= */ DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB);
+    }
+
     @Override
     public int getExampleStoreServiceCallbackTimeoutSec() {
         return DeviceConfig.getInt(
@@ -373,4 +347,12 @@ public final class PhFlags implements Flags {
                 /* name= */ FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME,
                 /* defaultValue= */ FCP_DEFAULT_CHECKPOINT_FILE_SIZE_LIMIT);
     }
+
+    @Override
+    public long getTempFileTtlMillis() {
+        return DeviceConfig.getLong(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ FCP_TEMP_FILE_TTL_IN_MILLIS_NAME,
+                /* defaultValue= */ DEFAULT_TEMP_FILE_TTL_MILLIS);
+    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
index bf0d4e00..dfa93302 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeDbHelper.java
@@ -19,7 +19,7 @@ package com.android.federatedcompute.services.data;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_READ_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_WRITE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__FEDERATED_COMPUTE;
-import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
+import static com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
 import static com.android.federatedcompute.services.data.TaskHistoryContract.TaskHistoryEntry.CREATE_TASK_HISTORY_TABLE_STATEMENT;
 
 import android.annotation.Nullable;
@@ -30,10 +30,10 @@ import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
+import com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FederatedTrainingTaskColumns;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.odp.module.common.data.ODPAuthorizationTokenContract;
+import com.android.odp.module.common.data.OdpAuthorizationTokenContract;
 import com.android.odp.module.common.data.OdpSQLiteOpenHelper;
 import com.android.odp.module.common.encryption.OdpEncryptionKeyContract;
 
@@ -127,9 +127,23 @@ public class FederatedComputeDbHelper extends OdpSQLiteOpenHelper {
         return sInstance;
     }
 
+    /**
+     * Returns an instance of the FederatedComputeDbHelper given a context. The db is created in
+     * memory and this method is for use in tests only.
+     *
+     * <p>Returns a new object on every call.
+     */
+    @VisibleForTesting
+    public static FederatedComputeDbHelper getNonSingletonInstanceForTest(Context context) {
+        // Use null database name to make it in-memory
+        return getNonSingletonInstanceForTest(context, /* dbName= */ null);
+    }
+
     /**
      * Returns an instance of the FederatedComputeDbHelper given a context and database name. This
      * is used for testing only.
+     *
+     * <p>Returns a new object on every call.
      */
     @VisibleForTesting
     public static FederatedComputeDbHelper getNonSingletonInstanceForTest(
@@ -142,7 +156,7 @@ public class FederatedComputeDbHelper extends OdpSQLiteOpenHelper {
         db.execSQL(CREATE_TRAINING_TASK_TABLE);
         db.execSQL(CREATE_TRAINING_TASK_OWNER_PACKAGE_INDEX);
         db.execSQL(OdpEncryptionKeyContract.CREATE_ENCRYPTION_KEY_TABLE);
-        db.execSQL(ODPAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
+        db.execSQL(OdpAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
         db.execSQL(CREATE_TASK_HISTORY_TABLE_STATEMENT);
     }
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java
index 0664f9a3..e2cbeeaa 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtils.java
@@ -47,8 +47,8 @@ public class FederatedComputeEncryptionKeyDaoUtils {
      * <p>Public for use in unit tests.
      */
     @VisibleForTesting
-    public static OdpEncryptionKeyDao getInstanceForTest(Context context) {
-        return OdpEncryptionKeyDao.getInstance(
-                context, FederatedComputeDbHelper.getInstanceForTest(context));
+    public static OdpEncryptionKeyDao getInstanceForTest(
+            Context context, FederatedComputeDbHelper federatedComputeDbHelper) {
+        return OdpEncryptionKeyDao.getInstance(context, federatedComputeDbHelper);
     }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTask.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTask.java
index 18555d8a..3aa5b9d1 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTask.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTask.java
@@ -16,7 +16,7 @@
 
 package com.android.federatedcompute.services.data;
 
-import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
+import static com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -24,7 +24,7 @@ import android.content.ContentValues;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 
-import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
+import com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FederatedTrainingTaskColumns;
 import com.android.federatedcompute.services.data.fbs.TrainingConstraints;
 import com.android.federatedcompute.services.data.fbs.TrainingIntervalOptions;
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTraningTaskContract.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskContract.java
similarity index 97%
rename from federatedcompute/src/com/android/federatedcompute/services/data/FederatedTraningTaskContract.java
rename to federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskContract.java
index aa5e2211..98eeffd6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTraningTaskContract.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskContract.java
@@ -19,10 +19,10 @@ package com.android.federatedcompute.services.data;
 import android.provider.BaseColumns;
 
 /** The contract class for training tasks. */
-public final class FederatedTraningTaskContract {
+final class FederatedTrainingTaskContract {
     public static final String FEDERATED_TRAINING_TASKS_TABLE = "federated_training_tasks";
 
-    private FederatedTraningTaskContract() {}
+    private FederatedTrainingTaskContract() {}
 
     /** Column name for the federated training task table. */
     public static final class FederatedTrainingTaskColumns implements BaseColumns {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDao.java b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDao.java
index 60424336..ff7f0b11 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDao.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDao.java
@@ -18,7 +18,7 @@ package com.android.federatedcompute.services.data;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DELETE_TASK_FAILURE;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__FEDERATED_COMPUTE;
-import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
+import static com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -30,7 +30,7 @@ import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
 
 import com.android.federatedcompute.internal.util.LogUtil;
-import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
+import com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FederatedTrainingTaskColumns;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
 
 import com.google.common.annotations.VisibleForTesting;
@@ -39,7 +39,9 @@ import com.google.common.collect.Iterables;
 import java.util.ArrayList;
 import java.util.List;
 
-/** DAO for accessing training task table. */
+/**
+ * DAO for accessing table for {@link FederatedTrainingTask} and the table for {@link TaskHistory}.
+ */
 public class FederatedTrainingTaskDao {
 
     private static final String TAG = FederatedTrainingTaskDao.class.getSimpleName();
@@ -66,17 +68,31 @@ public class FederatedTrainingTaskDao {
         return sSingletonInstance;
     }
 
-    /** It's only public to unit test. */
+    /**
+     * Get instance of the {@link FederatedTrainingTaskDao} for use in tests.
+     *
+     * <p>Uses the testing only version of the {@link FederatedComputeDbHelper}.
+     */
     @VisibleForTesting
-    public static FederatedTrainingTaskDao getInstanceForTest(Context context) {
-        synchronized (FederatedTrainingTaskDao.class) {
-            if (sSingletonInstance == null) {
-                FederatedComputeDbHelper dbHelper =
-                        FederatedComputeDbHelper.getInstanceForTest(context);
-                sSingletonInstance = new FederatedTrainingTaskDao(dbHelper);
-            }
-            return sSingletonInstance;
+    public static synchronized FederatedTrainingTaskDao getInstanceForTest(Context context) {
+        if (sSingletonInstance == null) {
+            FederatedComputeDbHelper dbHelper =
+                    FederatedComputeDbHelper.getNonSingletonInstanceForTest(context);
+            sSingletonInstance = new FederatedTrainingTaskDao(dbHelper);
         }
+        return sSingletonInstance;
+    }
+
+    /**
+     * Get instance of the {@link FederatedTrainingTaskDao} for use in tests.
+     *
+     * <p>Allows injection of the provided {@link FederatedComputeDbHelper} into the Dao.
+     */
+    @VisibleForTesting
+    public static synchronized FederatedTrainingTaskDao getInstanceForTest(
+            FederatedComputeDbHelper dbHelper) {
+        sSingletonInstance = new FederatedTrainingTaskDao(dbHelper);
+        return sSingletonInstance;
     }
 
     /** Deletes a training task in FederatedTrainingTask table. */
@@ -401,7 +417,10 @@ public class FederatedTrainingTaskDao {
         return null;
     }
 
-    /** Batch delete expired task history records. */
+    /**
+     * Batch delete expired task history records whose {@code CONTRIBUTION_TIME} is less than the
+     * specified deletion time.
+     */
     public int deleteExpiredTaskHistory(long deleteTime) {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
@@ -415,7 +434,7 @@ public class FederatedTrainingTaskDao {
         return deletedRows;
     }
 
-    private String[] selectionArgs(Number... args) {
+    private static String[] selectionArgs(Number... args) {
         String[] values = new String[args.length];
         for (int i = 0; i < args.length; i++) {
             values[i] = String.valueOf(args[i]);
diff --git a/federatedcompute/src/com/android/federatedcompute/services/data/TaskHistoryContract.java b/federatedcompute/src/com/android/federatedcompute/services/data/TaskHistoryContract.java
index 328c00f3..309d0006 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/data/TaskHistoryContract.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/data/TaskHistoryContract.java
@@ -18,7 +18,10 @@ package com.android.federatedcompute.services.data;
 
 import android.provider.BaseColumns;
 
+import com.google.common.annotations.VisibleForTesting;
+
 /** Contract for the task history table. Defines the table. */
+@VisibleForTesting
 public class TaskHistoryContract {
     private TaskHistoryContract() {}
 
@@ -36,7 +39,7 @@ public class TaskHistoryContract {
         // The round number that device contribute training result successfully. The round number is
         // returned by federated compute server when assigning task to device.
         public static final String CONTRIBUTION_ROUND = "contribution_round";
-        // The total number that device has participate in the training per task per population.
+        // The total number that device has participated in the training per task per population.
         public static final String TOTAL_PARTICIPATION = "total_participation";
         public static final String CREATE_TASK_HISTORY_TABLE_STATEMENT =
                 "CREATE TABLE IF NOT EXISTS "
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java
new file mode 100644
index 00000000..5a643dea
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java
@@ -0,0 +1,169 @@
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
+package com.android.federatedcompute.services.encryption;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+
+import android.content.Context;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.federatedcompute.internal.util.LogUtil;
+import com.android.federatedcompute.services.common.FederatedComputeExecutors;
+import com.android.federatedcompute.services.common.FederatedComputeJobInfo;
+import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
+import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobServiceFactory;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.EventLogger;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+import java.util.Optional;
+
+/** Job to fetch and persist active keys from a server and deletes expired keys */
+public final class BackgroundKeyFetchJob implements JobWorker {
+    private static final String TAG = BackgroundKeyFetchJob.class.getSimpleName();
+    private static final int ENCRYPTION_KEY_FETCH_JOB_ID =
+            FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
+
+    @VisibleForTesting
+    static class Injector {
+        ListeningExecutorService getExecutor() {
+            return FederatedComputeExecutors.getBackgroundExecutor();
+        }
+
+        ListeningExecutorService getLightWeightExecutor() {
+            return FederatedComputeExecutors.getLightweightExecutor();
+        }
+
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return FederatedComputeEncryptionKeyManagerUtils.getInstance(context);
+        }
+
+        EventLogger getEventLogger() {
+            return new BackgroundKeyFetchJobEventLogger();
+        }
+    }
+
+    private final Injector mInjector;
+
+    public BackgroundKeyFetchJob() {
+        this(new Injector());
+    }
+
+    @VisibleForTesting
+    BackgroundKeyFetchJob(Injector injector) {
+        mInjector = injector;
+    }
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(Context context,
+            ExecutionRuntimeParameters executionRuntimeParameters) {
+        return
+                FluentFuture.from(Futures.submitAsync(
+                        () -> {
+                            mInjector.getEventLogger().logEncryptionKeyFetchStartEventKind();
+                            return mInjector
+                                    .getEncryptionKeyManager(context)
+                                    .fetchAndPersistActiveKeys(
+                                            OdpEncryptionKey.KEY_TYPE_ENCRYPTION,
+                                            /* isScheduledJob= */ true,
+                                            Optional.of(mInjector.getEventLogger()));
+                        },
+                        mInjector.getLightWeightExecutor())
+                ).transform(odpEncryptionKeys -> {
+                    LogUtil.d(TAG, "BackgroundKeyFetchJob %d is done, fetched %d keys",
+                            ENCRYPTION_KEY_FETCH_JOB_ID, odpEncryptionKeys.size());
+                    return ExecutionResult.SUCCESS;
+                }, mInjector.getExecutor());
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
+            LogUtil.d(TAG, "GlobalKillSwitch enabled, skip execution of BackgroundKeyFetchJob.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!FlagsFactory.getFlags().getEnableBackgroundEncryptionKeyFetch()) {
+            LogUtil.d(TAG, "Background key fetch is disabled; skipping execution.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled()) {
+            LogUtil.d(TAG, "SPE background key fetch job is disabled; skipping execution.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
+    /** Schedules a unique instance of {@link BackgroundKeyFetchJobService}. */
+    public static void schedule(Context context) {
+        // If SPE is not enabled, force to schedule the job with the old JobService.
+        if (!FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled()) {
+            LogUtil.d(TAG, "SPE is not enabled. Schedule the job with "
+                    + "BackgroundKeyFetchJobService.");
+
+            int resultCode = BackgroundKeyFetchJobService.scheduleJobIfNeeded(
+                    context, FlagsFactory.getFlags(), /* forceSchedule */ false);
+            FederatedComputeJobServiceFactory.getInstance(context)
+                    .getJobSchedulingLogger()
+                    .recordOnSchedulingLegacy(ENCRYPTION_KEY_FETCH_JOB_ID, resultCode);
+
+            return;
+        }
+
+        FederatedComputeJobScheduler.getInstance(context).schedule(context, createDefaultJobSpec());
+    }
+
+    @VisibleForTesting
+    static JobSpec createDefaultJobSpec() {
+        Flags flags = FlagsFactory.getFlags();
+
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(ENCRYPTION_KEY_FETCH_JOB_ID)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(
+                                                flags.getEncryptionKeyFetchPeriodSeconds() * 1000))
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireDeviceIdle(true)
+                        .setNetworkType(NETWORK_TYPE_UNMETERED)
+                        .setIsPersisted(true)
+                        .build();
+
+        return new JobSpec.Builder(jobPolicy).build();
+    }
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
index 5a1e5076..5935df29 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobService.java
@@ -16,7 +16,12 @@
 
 package com.android.federatedcompute.services.encryption;
 
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
+
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 
 import android.app.job.JobInfo;
 import android.app.job.JobParameters;
@@ -25,6 +30,7 @@ import android.app.job.JobService;
 import android.content.ComponentName;
 import android.content.Context;
 
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.FederatedComputeJobInfo;
@@ -99,6 +105,15 @@ public class BackgroundKeyFetchJobService extends JobService {
                     ENCRYPTION_KEY_FETCH_JOB_ID,
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON);
         }
+        // Reschedule jobs with SPE if it's enabled. Note scheduled jobs by this
+        // BackgroundKeyFetchJobService will be cancelled for the same job ID
+        if (FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled()) {
+            LogUtil.d(TAG,
+                    "SPE is enabled. Reschedule BackgroundKeyFetchJobService with "
+                            + "BackgroundKeyFetchJob.");
+            BackgroundKeyFetchJob.schedule(/* context */ this);
+            return false;
+        }
         EventLogger eventLogger = mInjector.getEventLogger();
         eventLogger.logEncryptionKeyFetchStartEventKind();
         mInjector
@@ -181,17 +196,18 @@ public class BackgroundKeyFetchJobService extends JobService {
     }
 
     /** Schedule the periodic background key fetch and delete job if it is not scheduled. */
-    public static boolean scheduleJobIfNeeded(Context context, Flags flags) {
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int scheduleJobIfNeeded(Context context, Flags flags, boolean forceSchedule) {
         if (!flags.getEnableBackgroundEncryptionKeyFetch()) {
             LogUtil.d(
                     TAG,
                     "Schedule encryption key job fetch is not enable in flags.");
-            return false;
+            return SCHEDULING_RESULT_CODE_FAILED;
         }
         final JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
         if (jobScheduler == null) {
             LogUtil.e(TAG, "Failed to get job scheduler from system service.");
-            return false;
+            return SCHEDULING_RESULT_CODE_FAILED;
         }
 
         final JobInfo scheduledJob = jobScheduler.getPendingJob(ENCRYPTION_KEY_FETCH_JOB_ID);
@@ -208,19 +224,20 @@ public class BackgroundKeyFetchJobService extends JobService {
                         .setPersisted(true)
                         .build();
 
-        if (!jobInfo.equals(scheduledJob)) {
-            jobScheduler.schedule(jobInfo);
+        if (forceSchedule || !jobInfo.equals(scheduledJob)) {
+            int schedulingResult = jobScheduler.schedule(jobInfo);
             LogUtil.d(
                     TAG,
                     "Scheduled job BackgroundKeyFetchJobService id %d",
                     ENCRYPTION_KEY_FETCH_JOB_ID);
-            return true;
+            return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                    : SCHEDULING_RESULT_CODE_FAILED;
         } else {
             LogUtil.d(
                     TAG,
                     "Already scheduled job BackgroundKeyFetchJobService id %d",
                     ENCRYPTION_KEY_FETCH_JOB_ID);
-            return false;
+            return SCHEDULING_RESULT_CODE_SKIPPED;
         }
     }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java
index c657d826..df8420ac 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtils.java
@@ -97,12 +97,11 @@ public class FederatedComputeEncryptionKeyManagerUtils {
             Flags flags,
             HttpClient client,
             ListeningExecutorService executor,
-            Context context) {
+            FederatedComputeDbHelper dbHelper) {
         return OdpEncryptionKeyManager.getInstanceForTesting(
                 clock,
                 encryptionKeyDao,
-                new FlagKeyManagerConfig(
-                        flags, FederatedComputeDbHelper.getInstanceForTest(context)),
+                new FlagKeyManagerConfig(flags, dbHelper),
                 client,
                 executor);
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/examplestore/FederatedExampleIterator.java b/federatedcompute/src/com/android/federatedcompute/services/examplestore/FederatedExampleIterator.java
index 68212ca6..9f35f975 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/examplestore/FederatedExampleIterator.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/examplestore/FederatedExampleIterator.java
@@ -87,7 +87,6 @@ public final class FederatedExampleIterator implements ExampleIterator {
 
     private NextResultState mNextResultState;
     private final long mTaskId;
-    private final Context mContext;
 
     private final long mApexVersion;
 
@@ -103,9 +102,8 @@ public final class FederatedExampleIterator implements ExampleIterator {
         this.mClosed = false;
         this.mRecorder = recorder;
         this.mTaskId = taskId;
-        this.mContext = context;
         this.mIteratorWrapper = new ProxyIteratorWrapper(exampleStoreIterator);
-        this.mApexVersion = PackageUtils.getApexVersion(this.mContext);
+        this.mApexVersion = PackageUtils.getApexVersion(context);
     }
 
     @Override
@@ -180,7 +178,7 @@ public final class FederatedExampleIterator implements ExampleIterator {
         }
     }
 
-    private final class ProxyIteratorWrapper implements Closeable {
+    private static final class ProxyIteratorWrapper implements Closeable {
         private final IExampleStoreIterator mExampleStoreIterator;
         private boolean mIteratorClosed = false;
         private final FederatedExampleStoreIteratorCallback mIteratorCallback =
@@ -283,18 +281,15 @@ public final class FederatedExampleIterator implements ExampleIterator {
 
         @Override
         public void onIteratorNextSuccess(Bundle result) {
-            if (result == null) {
-                // Reach the end of data collection.
-                mResultOrErrorCodeFuture.set(Pair.create(null, null));
-                return;
-            }
-            byte[] example = result.getByteArray(EXTRA_EXAMPLE_ITERATOR_RESULT);
-            if (example == null) {
-                // Reaches the end of data collection.
+            byte[] example =
+                    result == null ? null : result.getByteArray(EXTRA_EXAMPLE_ITERATOR_RESULT);
+            if (result == null || example == null) {
+                // Reached the end of data collection.
                 mResultOrErrorCodeFuture.set(Pair.create(null, null));
                 return;
             }
 
+
             byte[] resumptionToken = result.getByteArray(EXTRA_EXAMPLE_ITERATOR_RESUMPTION_TOKEN);
             if (resumptionToken == null) {
                 resumptionToken = new byte[] {};
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
index 7d436f3c..cba9a2db 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
@@ -29,6 +29,7 @@ import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_OK_
 import static com.android.federatedcompute.services.http.HttpClientUtil.HTTP_UNAUTHORIZED_STATUS;
 import static com.android.federatedcompute.services.http.HttpClientUtil.ODP_IDEMPOTENCY_KEY;
 import static com.android.odp.module.common.FileUtils.createTempFile;
+import static com.android.odp.module.common.FileUtils.deleteFileIfExist;
 import static com.android.odp.module.common.FileUtils.readFileAsByteArray;
 import static com.android.odp.module.common.FileUtils.writeToFile;
 import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_HDR;
@@ -129,7 +130,7 @@ public final class HttpFederatedProtocol {
                 trainingEventLogger);
     }
 
-    /** Checks in with remote server to participant in federated computation. */
+    /** Checks in with remote server to participate in federated computation. */
     public FluentFuture<CreateTaskAssignmentResponse> createTaskAssignment(
             AuthorizationContext authContext) {
         Trace.beginAsyncSection(TRACE_HTTP_ISSUE_CHECKIN, 0);
@@ -375,16 +376,17 @@ public final class HttpFederatedProtocol {
 
         // Process downloaded checkpoint resource.
         String payloadFileName = checkpointDataResponse.getPayloadFileName();
+        String checkpointFile = payloadFileName;
         long checkpointFileSize = checkpointDataResponse.getDownloadedPayloadSize();
         if (checkpointDataResponse.isResponseCompressed()) {
-            String checkpointFile = createTempFile("input", ".ckp");
+            checkpointFile = createTempFile("input", ".ckp");
             checkpointFileSize =
                     writeToFile(
                             checkpointFile,
                             new GZIPInputStream(
                                     new BufferedInputStream(new FileInputStream(payloadFileName))));
+            deleteFileIfExist(payloadFileName);
             LogUtil.d(TAG, "Uncompressed checkpoint data file size: %d", checkpointFileSize);
-            payloadFileName = checkpointFile;
         }
         if (checkpointFileSize > FlagsFactory.getFlags().getFcpCheckpointFileSizeLimit()) {
             LogUtil.e(
@@ -399,7 +401,7 @@ public final class HttpFederatedProtocol {
 
         mTrainingEventLogger.logCheckinFinished(networkStats);
         Trace.endAsyncSection(TRACE_HTTP_ISSUE_CHECKIN, 0);
-        return new CheckinResult(payloadFileName, clientOnlyPlan, taskAssignment);
+        return new CheckinResult(checkpointFile, clientOnlyPlan, taskAssignment);
     }
 
     private ListenableFuture<OdpHttpResponse> performReportResult(
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
index ec5609e0..c8696adc 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
@@ -40,7 +40,7 @@ import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJ
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
@@ -69,8 +69,8 @@ public final class DeleteExpiredJob implements JobWorker {
             return FederatedComputeExecutors.getBackgroundExecutor();
         }
 
-        ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
-            return ODPAuthorizationTokenDao.getInstance(
+        OdpAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
+            return OdpAuthorizationTokenDao.getInstance(
                     FederatedComputeDbHelper.getInstance(context));
         }
 
@@ -97,7 +97,7 @@ public final class DeleteExpiredJob implements JobWorker {
                                         .getODPAuthorizationTokenDao(context)
                                         .deleteExpiredAuthorizationTokens(),
                         mInjector.getExecutor());
-
+        // TODO (b/392643302): add cleanup cache job.
         return FluentFuture.from(deleteExpiredAuthTokenFuture)
                 .transform(
                         numberOfDeletedTokens -> {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
index a5aff02a..c62f4075 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobService.java
@@ -41,20 +41,32 @@ import com.android.federatedcompute.services.statsd.joblogging.FederatedComputeJ
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
 
+import java.io.File;
 import java.util.List;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 public class DeleteExpiredJobService extends JobService {
 
     private static final String TAG = DeleteExpiredJobService.class.getSimpleName();
 
     private static final int DELETE_EXPIRED_JOB_ID = FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID;
+    // Regex for "federated_client_only_plan" files
+    private static final Pattern FEDERATED_PLAN_PATTERN =
+            Pattern.compile("federated_client_only_plan\\d+\\.pb");
+
+    // Regex for input checkpoint files
+    private static final Pattern INPUT_MODEL_PATTERN = Pattern.compile("input\\d+\\.(ckp|tmp)");
+
+    // Regex for output checkpoint files
+    private static final Pattern OUTPUT_MODEL_PATTERN = Pattern.compile("output\\d+\\.ckp");
 
     private final Injector mInjector;
 
@@ -63,17 +75,20 @@ public class DeleteExpiredJobService extends JobService {
     }
 
     @VisibleForTesting
-    public DeleteExpiredJobService(Injector injector) {
+    DeleteExpiredJobService(Injector injector) {
         mInjector = injector;
     }
 
+    @VisibleForTesting
     static class Injector {
+        private static final long MIN_TTL_MILLIS = 1000 * 60 * 10; // 10 mins
+
         ListeningExecutorService getExecutor() {
             return FederatedComputeExecutors.getBackgroundExecutor();
         }
 
-        ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
-            return ODPAuthorizationTokenDao.getInstance(
+        OdpAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
+            return OdpAuthorizationTokenDao.getInstance(
                     FederatedComputeDbHelper.getInstance(context));
         }
 
@@ -81,6 +96,10 @@ public class DeleteExpiredJobService extends JobService {
             return FederatedTrainingTaskDao.getInstance(context);
         }
 
+        File getCacheDir(Context context) {
+            return context.getCacheDir();
+        }
+
         Clock getClock() {
             return MonotonicClock.getInstance();
         }
@@ -88,6 +107,10 @@ public class DeleteExpiredJobService extends JobService {
         Flags getFlags() {
             return FlagsFactory.getFlags();
         }
+
+        long getMinimumTempFileTtlMillis() {
+            return MIN_TTL_MILLIS;
+        }
     }
 
     @Override
@@ -137,8 +160,13 @@ public class DeleteExpiredJobService extends JobService {
                                     .deleteExpiredTaskHistory(deleteTime);
                         },
                         mInjector.getExecutor());
+        ListenableFuture<Integer> deleteCacheDirFuture =
+                Futures.submit(() -> deleteCacheEntries(this), mInjector.getExecutor());
         ListenableFuture<List<Integer>> futuresList =
-                Futures.allAsList(deleteExpiredAuthTokenFuture, deleteExpiredTaskHistoryFuture);
+                Futures.allAsList(
+                        deleteExpiredAuthTokenFuture,
+                        deleteExpiredTaskHistoryFuture,
+                        deleteCacheDirFuture);
         Futures.addCallback(
                 futuresList,
                 new FutureCallback<List<Integer>>() {
@@ -170,6 +198,44 @@ public class DeleteExpiredJobService extends JobService {
         return true;
     }
 
+    private int deleteCacheEntries(Context context) {
+        File[] cacheFiles = mInjector.getCacheDir(context).listFiles();
+        int deleteCount = 0;
+        for (File file : cacheFiles) {
+            // Only clean up model related files.
+            if (!isFileMatched(file.getName())) {
+                continue;
+            }
+
+            long age = System.currentTimeMillis() - file.lastModified();
+            if (age
+                    > Math.max(
+                            mInjector.getFlags().getTempFileTtlMillis(),
+                            mInjector.getMinimumTempFileTtlMillis())) {
+                deleteCount++;
+                file.delete();
+            }
+        }
+        return deleteCount;
+    }
+
+    @VisibleForTesting
+    boolean isFileMatched(String fileName) {
+        Matcher planMatcher = FEDERATED_PLAN_PATTERN.matcher(fileName);
+        if (planMatcher.matches()) {
+            return true;
+        }
+        Matcher inputMatcher = INPUT_MODEL_PATTERN.matcher(fileName);
+        if (inputMatcher.matches()) {
+            return true;
+        }
+        Matcher outputMatcher = OUTPUT_MODEL_PATTERN.matcher(fileName);
+        if (outputMatcher.matches()) {
+            return true;
+        }
+        return false;
+    }
+
     @Override
     public boolean onStopJob(JobParameters params) {
         LogUtil.d(TAG, "DeleteExpiredJobService.onStopJob %d", params.getJobId());
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
index 55865a5b..9b805c1b 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
@@ -33,7 +33,7 @@ import android.federatedcompute.common.TrainingOptions;
 
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.Flags;
-import com.android.federatedcompute.services.common.PhFlags;
+import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.data.FederatedTrainingTask;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
 import com.android.federatedcompute.services.data.TaskHistory;
@@ -98,7 +98,7 @@ public class FederatedComputeJobManager {
                                     FederatedJobIdGenerator.getInstance(),
                                     new JobSchedulerHelper(clock),
                                     clock,
-                                    PhFlags.getInstance());
+                                    FlagsFactory.getFlags());
                 }
             }
         }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
index a49966d9..a45c0720 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
@@ -97,6 +97,7 @@ public class JobSchedulerHelper {
                         (task.earliestNextRunTime() - nowMillis) > 0
                                 ? (task.earliestNextRunTime() - nowMillis)
                                 : 0)
+                .setRequiresStorageNotLow(true)
                 .setPersisted(true);
 
         jobInfo.setRequiredNetworkType(
diff --git a/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java b/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
index cb61e1d6..19e7e354 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/security/AuthorizationContext.java
@@ -28,11 +28,12 @@ import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
+import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationToken;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationToken;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
@@ -48,7 +49,6 @@ import java.util.UUID;
 import java.util.concurrent.ArrayBlockingQueue;
 import java.util.concurrent.BlockingQueue;
 import java.util.concurrent.TimeUnit;
-import java.util.concurrent.atomic.AtomicInteger;
 
 /** Manages the details of authenticating with remote server. */
 public class AuthorizationContext {
@@ -58,12 +58,17 @@ public class AuthorizationContext {
     @NonNull private final String mOwnerId;
     @NonNull private final String mOwnerCert;
 
-    @Nullable private List<String> mAttestationRecord = null;
+    @GuardedBy("this")
+    @Nullable
+    private List<String> mAttestationRecord = null;
+
+    @GuardedBy("this")
+    private int mTryCount = 1;
 
-    private final AtomicInteger mTryCount = new AtomicInteger(1);
     private final KeyAttestation mKeyAttestation;
-    private final ODPAuthorizationTokenDao mAuthorizationTokenDao;
+    private final OdpAuthorizationTokenDao mAuthorizationTokenDao;
     private final Clock mClock;
+    private final TrainingEventLogger mTrainingEventLogger;
 
     private static final int BLOCKING_QUEUE_TIMEOUT_IN_SECONDS = 2;
 
@@ -71,29 +76,35 @@ public class AuthorizationContext {
     public AuthorizationContext(
             @NonNull String ownerId,
             @NonNull String ownerCert,
-            ODPAuthorizationTokenDao authorizationTokenDao,
+            OdpAuthorizationTokenDao authorizationTokenDao,
             KeyAttestation keyAttestation,
-            Clock clock) {
+            Clock clock,
+            TrainingEventLogger trainingEventLogger) {
         mOwnerId = ownerId;
         mOwnerCert = ownerCert;
         mAuthorizationTokenDao = authorizationTokenDao;
         mKeyAttestation = keyAttestation;
         mClock = clock;
+        mTrainingEventLogger = trainingEventLogger;
     }
 
     /** Creates a new {@link AuthorizationContext} used for authentication with remote server. */
     public static AuthorizationContext create(
-            Context context, @NonNull String ownerId, @NonNull String ownerCert) {
+            Context context,
+            @NonNull String ownerId,
+            @NonNull String ownerCert,
+            TrainingEventLogger trainingEventLogger) {
         return new AuthorizationContext(
                 ownerId,
                 ownerCert,
-                ODPAuthorizationTokenDao.getInstance(FederatedComputeDbHelper.getInstance(context)),
+                OdpAuthorizationTokenDao.getInstance(FederatedComputeDbHelper.getInstance(context)),
                 KeyAttestation.getInstance(context),
-                MonotonicClock.getInstance());
+                MonotonicClock.getInstance(),
+                trainingEventLogger);
     }
 
-    public boolean isFirstAuthTry() {
-        return mTryCount.get() == 1;
+    public synchronized boolean isFirstAuthTry() {
+        return mTryCount == 1;
     }
 
     @NonNull
@@ -107,60 +118,63 @@ public class AuthorizationContext {
     }
 
     @Nullable
-    public List<String> getAttestationRecord() {
+    public synchronized List<String> getAttestationRecord() {
         return mAttestationRecord;
     }
 
     /**
      * Updates authentication state e.g. update retry count, generate attestation record if needed.
      */
-    public void updateAuthState(
+    public synchronized List<String> updateAuthState(
             AuthenticationMetadata authMetadata, TrainingEventLogger trainingEventLogger) {
         // TODO: introduce auth state if we plan to auth more than twice.
         // After first authentication failed, we will clean up expired token and generate
         // key attestation records using server provided challenge for second try.
-        if (mTryCount.get() == 1) {
-            mTryCount.incrementAndGet();
+        if (mTryCount == 1) {
+            mTryCount++;
             mAuthorizationTokenDao.deleteAuthorizationToken(mOwnerId);
-            long kaStartTime = mClock.currentTimeMillis();
             mAttestationRecord =
                     mKeyAttestation.generateAttestationRecord(
                             authMetadata.getKeyAttestationMetadata().getChallenge().toByteArray(),
-                            mOwnerId);
-            trainingEventLogger.logKeyAttestationLatencyEvent(
-                    mClock.currentTimeMillis() - kaStartTime);
+                            mOwnerId,
+                            mTrainingEventLogger);
+            return mAttestationRecord;
         }
+        return null;
     }
 
     /**
      * Generates authentication headers used for http request.
      *
-     * <p>Returns empty headers if the call to get {@link ODPAuthorizationToken} from the {@link
-     * ODPAuthorizationTokenDao} fails or times out.
+     * <p>Returns empty headers if the call to get {@link OdpAuthorizationToken} from the {@link
+     * OdpAuthorizationTokenDao} fails or times out.
      */
     public Map<String, String> generateAuthHeaders() {
         Map<String, String> headers = new HashMap<>();
-        if (mAttestationRecord != null) {
-            // Only when the device is solving challenge, the attestation record is not null.
-            JSONArray attestationArr = new JSONArray(mAttestationRecord);
-            headers.put(ODP_AUTHENTICATION_KEY, attestationArr.toString());
-            // Generate a UUID that will serve as the authorization token.
-            String authTokenUUID = UUID.randomUUID().toString();
-            headers.put(ODP_AUTHORIZATION_KEY, authTokenUUID);
-            ODPAuthorizationToken authToken =
-                    new ODPAuthorizationToken.Builder()
-                            .setAuthorizationToken(authTokenUUID)
-                            .setOwnerIdentifier(mOwnerId)
-                            .setCreationTime(mClock.currentTimeMillis())
-                            .setExpiryTime(
-                                    mClock.currentTimeMillis()
-                                            + FlagsFactory.getFlags().getOdpAuthorizationTokenTtl())
-                            .build();
-            var unused =
-                    Futures.submit(
-                            () -> mAuthorizationTokenDao.insertAuthorizationToken(authToken),
-                            FederatedComputeExecutors.getBackgroundExecutor());
-            return headers;
+        synchronized (this) {
+            if (mAttestationRecord != null && !mAttestationRecord.isEmpty()) {
+                // Only when the device is solving challenge, the attestation record is not null.
+                JSONArray attestationArr = new JSONArray(mAttestationRecord);
+                headers.put(ODP_AUTHENTICATION_KEY, attestationArr.toString());
+                // Generate a UUID that will serve as the authorization token.
+                String authTokenUUID = UUID.randomUUID().toString();
+                headers.put(ODP_AUTHORIZATION_KEY, authTokenUUID);
+                OdpAuthorizationToken authToken =
+                        new OdpAuthorizationToken.Builder()
+                                .setAuthorizationToken(authTokenUUID)
+                                .setOwnerIdentifier(mOwnerId)
+                                .setCreationTime(mClock.currentTimeMillis())
+                                .setExpiryTime(
+                                        mClock.currentTimeMillis()
+                                                + FlagsFactory.getFlags()
+                                                        .getOdpAuthorizationTokenTtl())
+                                .build();
+                var unused =
+                        Futures.submit(
+                                () -> mAuthorizationTokenDao.insertAuthorizationToken(authToken),
+                                FederatedComputeExecutors.getBackgroundExecutor());
+                return headers;
+            }
         }
 
         // Get existing OdpAuthorizationToken from the Dao.
@@ -212,25 +226,25 @@ public class AuthorizationContext {
         };
     }
 
-    private static AuthTokenCallbackResult convertODPAuthToken(ODPAuthorizationToken authToken) {
+    private static AuthTokenCallbackResult convertODPAuthToken(OdpAuthorizationToken authToken) {
         return new AuthTokenCallbackResult(authToken, authToken == null);
     }
 
     private static class AuthTokenCallbackResult {
-        final ODPAuthorizationToken mAuthToken;
+        final OdpAuthorizationToken mAuthToken;
 
         final boolean mIsEmpty;
 
-        AuthTokenCallbackResult(ODPAuthorizationToken authToken, boolean isEmpty) {
+        AuthTokenCallbackResult(OdpAuthorizationToken authToken, boolean isEmpty) {
             mAuthToken = authToken;
             mIsEmpty = isEmpty;
         }
 
-        ODPAuthorizationToken getAuthToken() {
+        OdpAuthorizationToken getAuthToken() {
             return mAuthToken;
         }
 
-        Boolean isEmpty() {
+        boolean isEmpty() {
             return mIsEmpty;
         }
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java b/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
index 59072bae..d4b36392 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/security/KeyAttestation.java
@@ -16,6 +16,13 @@
 
 package com.android.federatedcompute.services.security;
 
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_CERTIFICATE_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_IO_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_KEYSTORE_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_ALGORITHM_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_PROVIDER_EXCEPTION;
+
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.security.keystore.KeyGenParameterSpec;
@@ -23,8 +30,13 @@ import android.security.keystore.KeyProperties;
 import android.util.Base64;
 
 import com.android.federatedcompute.internal.util.LogUtil;
+import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.Clock;
+import com.android.odp.module.common.MonotonicClock;
 
+import java.io.IOException;
+import java.security.InvalidAlgorithmParameterException;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.KeyStore;
@@ -32,6 +44,7 @@ import java.security.KeyStoreException;
 import java.security.NoSuchAlgorithmException;
 import java.security.NoSuchProviderException;
 import java.security.cert.Certificate;
+import java.security.cert.CertificateException;
 import java.security.spec.ECGenParameterSpec;
 import java.util.ArrayList;
 import java.util.List;
@@ -56,6 +69,10 @@ public class KeyAttestation {
                 throws NoSuchAlgorithmException, NoSuchProviderException {
             return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
         }
+
+        Clock getClock() {
+            return MonotonicClock.getInstance();
+        }
     }
 
     private final Injector mInjector;
@@ -110,58 +127,97 @@ public class KeyAttestation {
      * <p>Returned list is empty in case of failure.
      */
     public List<String> generateAttestationRecord(
-            final byte[] challenge, final String callingPackage) {
-        final String keyAlias = getKeyAlias(callingPackage);
-        // Generate the key pair and attestation certificate using the provided challenge.
-        // The key-pair is unused, but the attestation certs will be used (via certificate chain)
-        // by subsequent getAttestationRecordFromKeyAlias call to generate the attestation record.
-        KeyPair kp = generateHybridKey(challenge, keyAlias);
-        if (kp == null) {
+            final byte[] challenge,
+            final String callingPackage,
+            TrainingEventLogger trainingEventLogger) {
+        try {
+            long startTime = mInjector.getClock().currentTimeMillis();
+            final String keyAlias = getKeyAlias(callingPackage);
+            // Generate the key pair and attestation certificate using the provided challenge.
+            // The key-pair is unused, but the attestation certs will be used (via certificate
+            // chain) by subsequent getAttestationRecordFromKeyAlias call to generate the
+            // attestation record.
+            KeyPair kp = generateHybridKey(challenge, keyAlias);
+            if (kp == null) {
+                LogUtil.e(TAG, "Key pair is empty.");
+                trainingEventLogger.logEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR);
+                return new ArrayList<>();
+            }
+            List<String> records = getAttestationRecordFromKeyAlias(keyAlias);
+            if (records.isEmpty()) {
+                LogUtil.e(TAG, "Key attestation record is empty.");
+                trainingEventLogger.logEventKind(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR);
+                return records;
+            }
+            trainingEventLogger.logKeyAttestationLatencyEvent(
+                    mInjector.getClock().currentTimeMillis() - startTime);
+            return records;
+        } catch (Exception e) {
+            LogUtil.e(TAG, e, "Failed to generate hybrid key attestation.");
+            switch (e) {
+                case NoSuchAlgorithmException ex:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_ALGORITHM_EXCEPTION);
+                    break;
+                case NoSuchProviderException ex:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_PROVIDER_EXCEPTION);
+                    break;
+                case IOException ex:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_IO_EXCEPTION);
+                    break;
+                case KeyStoreException ex:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_KEYSTORE_EXCEPTION);
+                    break;
+                case CertificateException ex:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_CERTIFICATE_EXCEPTION);
+                    break;
+                default:
+                        trainingEventLogger.logEventKind(
+                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR);
+            }
             return new ArrayList<>();
         }
-        return getAttestationRecordFromKeyAlias(keyAlias);
     }
 
     @VisibleForTesting
-    KeyPair generateHybridKey(final byte[] challenge, final String keyAlias) {
-        try {
-            KeyPairGenerator keyPairGenerator = mInjector.getKeyPairGenerator();
-            keyPairGenerator.initialize(
-                    new KeyGenParameterSpec.Builder(
-                                    /* keystoreAlias= */ keyAlias,
-                                    /* purposes= */ KeyProperties.PURPOSE_SIGN)
-                            .setDigests(KeyProperties.DIGEST_SHA256)
-                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
-                            .setAttestationChallenge(challenge)
-                            // device properties are not specified when acquiring the challenge
-                            .setDevicePropertiesAttestationIncluded(false)
-                            .setIsStrongBoxBacked(mUseStrongBox)
-                            .build());
-            return keyPairGenerator.generateKeyPair();
-        } catch (Exception e) {
-            LogUtil.e(TAG, e, "Failed to generate hybrid key attestation.");
-        }
-        return null;
+    KeyPair generateHybridKey(final byte[] challenge, final String keyAlias)
+            throws InvalidAlgorithmParameterException,
+                    NoSuchAlgorithmException,
+                    NoSuchProviderException {
+        KeyPairGenerator keyPairGenerator = mInjector.getKeyPairGenerator();
+        keyPairGenerator.initialize(
+                new KeyGenParameterSpec.Builder(
+                                /* keystoreAlias= */ keyAlias,
+                                /* purposes= */ KeyProperties.PURPOSE_SIGN)
+                        .setDigests(KeyProperties.DIGEST_SHA256)
+                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
+                        .setAttestationChallenge(challenge)
+                        // device properties are not specified when acquiring the challenge
+                        .setDevicePropertiesAttestationIncluded(false)
+                        .setIsStrongBoxBacked(mUseStrongBox)
+                        .build());
+        return keyPairGenerator.generateKeyPair();
     }
 
     @VisibleForTesting
-    List<String> getAttestationRecordFromKeyAlias(String keyAlias) {
+    List<String> getAttestationRecordFromKeyAlias(String keyAlias)
+            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
         ArrayList<String> attestationRecord = new ArrayList<>();
-        try {
-            KeyStore keyStore = mInjector.getKeyStore();
-            keyStore.load(null);
-            Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
-            if (certificateChain == null) {
-                return attestationRecord;
-            }
-
-            for (Certificate certificate : certificateChain) {
-                attestationRecord.add(
-                        Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP));
-            }
+        KeyStore keyStore = mInjector.getKeyStore();
+        keyStore.load(null);
+        Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
+        if (certificateChain == null) {
             return attestationRecord;
-        } catch (Exception e) {
-            LogUtil.e(TAG, e, "Got exception when generating attestation record.");
+        }
+
+        for (Certificate certificate : certificateChain) {
+            attestationRecord.add(Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP));
         }
         return attestationRecord;
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobService.java b/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobService.java
index 65774540..7b9d4b16 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobService.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobService.java
@@ -17,6 +17,7 @@
 package com.android.federatedcompute.services.sharedlibrary.spe;
 
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID;
+import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
 
 import android.app.job.JobParameters;
 
@@ -71,10 +72,13 @@ public final class FederatedComputeJobService extends AbstractJobService {
     boolean shouldRescheduleWithLegacyMethod(int jobId) {
         Flags flags = FlagsFactory.getFlags();
 
-        if (jobId == DELETE_EXPIRED_JOB_ID && !flags.getSpePilotJobEnabled()) {
-            return true;
+        switch (jobId) {
+            case DELETE_EXPIRED_JOB_ID:
+                return !flags.getSpePilotJobEnabled();
+            case ENCRYPTION_KEY_FETCH_JOB_ID:
+                return !flags.getSpeOnBackgroundKeyFetchJobEnabled();
+            default:
+                return false;
         }
-
-        return false;
     }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactory.java b/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactory.java
index 29d0ef11..5e857721 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactory.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactory.java
@@ -17,6 +17,7 @@
 package com.android.federatedcompute.services.sharedlibrary.spe;
 
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID;
+import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.JOB_ID_TO_NAME_MAP;
 
 import android.content.Context;
@@ -31,6 +32,8 @@ import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJob;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJobService;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJobService;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
@@ -134,6 +137,8 @@ public class FederatedComputeJobServiceFactory implements JobServiceFactory {
             switch (jobId) {
                 case DELETE_EXPIRED_JOB_ID:
                     return new DeleteExpiredJob();
+                case ENCRYPTION_KEY_FETCH_JOB_ID:
+                    return new BackgroundKeyFetchJob();
                 default:
                     throw new RuntimeException(
                             "The job is not configured for the instance creation.");
@@ -182,6 +187,10 @@ public class FederatedComputeJobServiceFactory implements JobServiceFactory {
                 case DELETE_EXPIRED_JOB_ID:
                     DeleteExpiredJobService.scheduleJobIfNeeded(context, mFlags, forceSchedule);
                     return;
+                case ENCRYPTION_KEY_FETCH_JOB_ID:
+                    BackgroundKeyFetchJobService
+                            .scheduleJobIfNeeded(context, mFlags, forceSchedule);
+                    return;
                 default:
                     throw new RuntimeException(
                             "The job isn't configured for jobWorker creation. Requested Job ID: "
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java b/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
index 3c2ba0e5..e7aa76e2 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/EligibilityDecider.java
@@ -19,6 +19,8 @@ package com.android.federatedcompute.services.training;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_COMPLETED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ELIGIBLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ERROR_EXAMPLE_ITERATOR;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_ERROR;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START;
@@ -76,6 +78,8 @@ public class EligibilityDecider {
             ExampleSelector exampleSelector) {
         boolean eligible = true;
         ExampleStats exampleStats = new ExampleStats();
+        EligibilityPolicyEvalSpec.PolicyTypeCase policyTypeCase =
+                EligibilityPolicyEvalSpec.PolicyTypeCase.MIN_SEP_POLICY;
         trainingEventLogger.logEventKind(
                 FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED);
         EligibilityResult.Builder result = new EligibilityResult.Builder();
@@ -111,6 +115,7 @@ public class EligibilityDecider {
             // Device has to meet all eligibility policies in order to execute task.
             if (!eligible) {
                 result.setEligible(false);
+                policyTypeCase = policyEvalSpec.getPolicyTypeCase();
                 break;
             }
         }
@@ -131,6 +136,15 @@ public class EligibilityDecider {
         if (eligibilityResult.getExampleStoreIterator() != null) {
             mExampleStoreServiceProvider.unbindFromExampleStoreService();
         }
+
+        if (policyTypeCase == EligibilityPolicyEvalSpec.PolicyTypeCase.MIN_SEP_POLICY) {
+            trainingEventLogger.logEventKind(
+                    FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION);
+        } else if (policyTypeCase
+                == EligibilityPolicyEvalSpec.PolicyTypeCase.DATA_AVAILABILITY_POLICY) {
+            trainingEventLogger.logEventKind(
+                    FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE);
+        }
         return new EligibilityResult.Builder().setEligible(false).build();
     }
 
@@ -149,9 +163,17 @@ public class EligibilityDecider {
         }
         boolean result = minSepPolicy.getMinimumSeparation()
                 <= minSepPolicy.getCurrentIndex() - taskHistory.getContributionRound();
-        LogUtil.d(TAG, "min sep policy eligible: %s, minSepPolicy.getMinimumSeparation(): %d, "
-                + "minSepPolicy.getCurrentIndex(): %d, taskHistory.getContributionRound(): %d",
-                result, minSepPolicy.getMinimumSeparation(), minSepPolicy.getCurrentIndex(),
+        LogUtil.d(
+                TAG,
+                "population name %s task id %s job id %d min sep policy eligible: %s, "
+                        + "MinimumSeparation: %d, CurrentIndex: %d "
+                        + "taskHistory.getContributionRound(): %d",
+                populationName,
+                taskId,
+                jobId,
+                result,
+                minSepPolicy.getMinimumSeparation(),
+                minSepPolicy.getCurrentIndex(),
                 taskHistory.getContributionRound());
         return result;
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java b/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
index 0bd13aad..9119462d 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/FederatedComputeWorker.java
@@ -43,6 +43,7 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_STARTED;
 import static com.android.odp.module.common.FileUtils.createTempFile;
 import static com.android.odp.module.common.FileUtils.createTempFileDescriptor;
+import static com.android.odp.module.common.FileUtils.deleteFileIfExist;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -122,8 +123,12 @@ import java.util.Optional;
 import java.util.Set;
 import java.util.concurrent.atomic.AtomicBoolean;
 
-/** The worker to execute federated computation jobs. */
-public class FederatedComputeWorker {
+/**
+ * The worker to execute federated computation jobs.
+ *
+ * <p>Used by the {@link FederatedJobService} to start/cancel training runs.
+ */
+class FederatedComputeWorker {
     private static final String TAG = FederatedComputeWorker.class.getSimpleName();
     private static final int NUM_ACTIVE_KEYS_TO_CHOOSE_FROM = 5;
     private static volatile FederatedComputeWorker sWorker;
@@ -137,15 +142,17 @@ public class FederatedComputeWorker {
     private final ComputationRunner mComputationRunner;
     private final ResultCallbackHelper mResultCallbackHelper;
     @NonNull private final Injector mInjector;
+    private final ExampleStoreServiceProvider mExampleStoreServiceProvider;
+
+    private final OdpEncryptionKeyManager mEncryptionKeyManager;
 
     @GuardedBy("mLock")
     @Nullable
     private TrainingRun mActiveRun = null;
 
     private HttpFederatedProtocol mHttpFederatedProtocol;
-    private final ExampleStoreServiceProvider mExampleStoreServiceProvider;
+
     private AbstractServiceBinder<IIsolatedTrainingService> mIsolatedTrainingServiceBinder;
-    private final OdpEncryptionKeyManager mEncryptionKeyManager;
 
     @VisibleForTesting
     FederatedComputeWorker(
@@ -169,7 +176,7 @@ public class FederatedComputeWorker {
 
     /** Gets an instance of {@link FederatedComputeWorker}. */
     @NonNull
-    public static FederatedComputeWorker getInstance(Context context) {
+    static FederatedComputeWorker getInstance(Context context) {
         if (sWorker == null) {
             synchronized (FederatedComputeWorker.class) {
                 if (sWorker == null) {
@@ -189,8 +196,9 @@ public class FederatedComputeWorker {
         return sWorker;
     }
 
-    /** Starts a training run with the given job Id. */
-    public ListenableFuture<FLRunnerResult> startTrainingRun(
+    /** Starts a training run with the given job-Id. */
+    @VisibleForTesting
+    ListenableFuture<FLRunnerResult> startTrainingRun(
             int jobId, FederatedJobService.OnJobFinishedCallback callback) {
         LogUtil.d(TAG, "startTrainingRun() %d", jobId);
         TrainingEventLogger trainingEventLogger = mInjector.getTrainingEventLogger();
@@ -312,12 +320,11 @@ public class FederatedComputeWorker {
             AuthorizationContext authContext =
                     mInjector.createAuthContext(
                             mContext,
-                            ComponentName.createRelative(
-                                            run.mTask.ownerPackageName(),
-                                            run.mTask.ownerClassName())
-                                    .flattenToString(),
-                            run.mTask.ownerIdCertDigest());
-            return FluentFuture.from(mHttpFederatedProtocol.createTaskAssignment(authContext))
+                            getOwnerPackageName(run),
+                            run.mTask.ownerIdCertDigest(),
+                            run.mTrainingEventLogger);
+            return mHttpFederatedProtocol
+                    .createTaskAssignment(authContext)
                     .transformAsync(
                             taskAssignmentResponse -> {
                                 if (taskAssignmentResponse.hasRejectionInfo()) {
@@ -357,19 +364,33 @@ public class FederatedComputeWorker {
             CreateTaskAssignmentResponse createTaskAssignmentResponse,
             AuthorizationContext authContext) {
         // Generate attestation record and make 2nd try.
-        authContext.updateAuthState(
-                createTaskAssignmentResponse.getRejectionInfo().getAuthMetadata(),
-                run.mTrainingEventLogger);
-        return FluentFuture.from(mHttpFederatedProtocol.createTaskAssignment(authContext))
+        List<String> attestationRecord =
+                authContext.updateAuthState(
+                        createTaskAssignmentResponse.getRejectionInfo().getAuthMetadata(),
+                        run.mTrainingEventLogger);
+        if (attestationRecord == null || attestationRecord.isEmpty()) {
+            String errorMsg =
+                    String.format(
+                            "Failed to generate attestation record for population name %s "
+                                    + "when task assignment",
+                            run.mTask.populationName());
+            LogUtil.e(TAG, errorMsg);
+            return Futures.immediateFailedFuture(new IllegalStateException(errorMsg));
+        }
+        return mHttpFederatedProtocol
+                .createTaskAssignment(authContext)
                 .transformAsync(
                         taskAssignmentOnUnauthenticated -> {
                             if (taskAssignmentOnUnauthenticated.hasRejectionInfo()) {
                                 // This function is called only when the device received
                                 // 401 (unauthenticated). Only retry rejection is allowed.
                                 LogUtil.d(
-                                        TAG, "job %d was rejected during check in, reason %s",
-                                        run.mTask.jobId(), taskAssignmentOnUnauthenticated
-                                            .getRejectionInfo().getReason());
+                                        TAG,
+                                        "job %d was rejected during check in, reason %s",
+                                        run.mTask.jobId(),
+                                        taskAssignmentOnUnauthenticated
+                                                .getRejectionInfo()
+                                                .getReason());
                                 if (taskAssignmentOnUnauthenticated
                                         .getRejectionInfo()
                                         .hasRetryWindow()) {
@@ -429,19 +450,17 @@ public class FederatedComputeWorker {
             if (!eligibleResult.isEligible()) {
                 reportFailureResultToServer(
                         new ComputationResult(
-                                null,
+                                /* outputCheckpointFile= */ null,
                                 FLRunnerResult.newBuilder()
                                         .setContributionResult(ContributionResult.FAIL)
                                         .setErrorStatus(FLRunnerResult.ErrorStatus.NOT_ELIGIBLE)
                                         .build(),
-                                null),
-                        AuthorizationContext.create(
+                                /* exampleConsumptionList= */ null),
+                        mInjector.createAuthContext(
                                 mContext,
-                                ComponentName.createRelative(
-                                                run.mTask.ownerPackageName(),
-                                                run.mTask.ownerClassName())
-                                        .flattenToString(),
-                                run.mTask.ownerIdCertDigest()),
+                                getOwnerPackageName(run),
+                                run.mTask.ownerIdCertDigest(),
+                                run.mTrainingEventLogger),
                         run.mTrainingEventLogger);
                 run.mTrainingEventLogger.logEventKind(
                         FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_NOT_ELIGIBLE);
@@ -513,6 +532,7 @@ public class FederatedComputeWorker {
     @NonNull
     private ListenableFuture<FLRunnerResult> doFederatedComputation(
             TrainingRun run, CheckinResult checkinResult, EligibilityResult eligibilityResult) {
+        run.mInputModelFile = checkinResult.getInputCheckpointFile();
         // 3. Fetch Active keys to encrypt the computation result.
         List<OdpEncryptionKey> activeKeys =
                 mEncryptionKeyManager.getOrFetchActiveKeys(
@@ -561,20 +581,16 @@ public class FederatedComputeWorker {
         ListenableFuture<ComputationResult> computationResultAndCallbackFuture =
                 CallbackToFutureAdapter.getFuture(
                         completer -> {
-                            String ownerId =
-                                    ComponentName.createRelative(
-                                                    run.mTask.ownerPackageName(),
-                                                    run.mTask.ownerClassName())
-                                            .flattenToString();
                             Futures.addCallback(
                                     computationResultFuture,
                                     new ReportFailureToServerCallback(run.mTrainingEventLogger)
                                             .getServerFailureReportCallback(
                                                     completer,
-                                                    AuthorizationContext.create(
+                                                    mInjector.createAuthContext(
                                                             mContext,
-                                                            ownerId,
-                                                            run.mTask.ownerIdCertDigest())),
+                                                            getOwnerPackageName(run),
+                                                            run.mTask.ownerIdCertDigest(),
+                                                            run.mTrainingEventLogger)),
                                     getLightweightExecutor());
                             return "Report computation result failure to the server.";
                         });
@@ -584,16 +600,14 @@ public class FederatedComputeWorker {
                 Futures.transformAsync(
                         computationResultAndCallbackFuture,
                         result -> {
-                            String ownerId =
-                                    ComponentName.createRelative(
-                                                    run.mTask.ownerPackageName(),
-                                                    run.mTask.ownerClassName())
-                                            .flattenToString();
                             return reportResultWithAuthentication(
                                     result,
                                     encryptionKey,
                                     mInjector.createAuthContext(
-                                            mContext, ownerId, run.mTask.ownerIdCertDigest()),
+                                            mContext,
+                                            getOwnerPackageName(run),
+                                            run.mTask.ownerIdCertDigest(),
+                                            run.mTrainingEventLogger),
                                     run.mTrainingEventLogger);
                         },
                         getLightweightExecutor());
@@ -675,17 +689,18 @@ public class FederatedComputeWorker {
             runnerResultBuilder.setErrorStatus(failureStatus);
         }
         ComputationResult failedComputationResult =
-                new ComputationResult(null, runnerResultBuilder.build(), null);
+                new ComputationResult(
+                        /* outputCheckpointFile= */ null,
+                        runnerResultBuilder.build(),
+                        /* exampleConsumptionList= */ null);
         try {
             reportFailureResultToServer(
                     failedComputationResult,
-                    AuthorizationContext.create(
+                    mInjector.createAuthContext(
                             mContext,
-                            ComponentName.createRelative(
-                                            run.mTask.ownerPackageName(),
-                                            run.mTask.ownerClassName())
-                                    .flattenToString(),
-                            run.mTask.ownerIdCertDigest()),
+                            getOwnerPackageName(run),
+                            run.mTask.ownerIdCertDigest(),
+                            run.mTrainingEventLogger),
                     run.mTrainingEventLogger);
         } catch (Exception e) {
             LogUtil.e(TAG, e, "Failed to report failure result to server.");
@@ -752,7 +767,7 @@ public class FederatedComputeWorker {
      * Completes the running job , schedule recurrent job, and unbind from ExampleStoreService and
      * ResultHandlingService etc.
      */
-    public void finish(FLRunnerResult flRunnerResult) {
+    void finish(FLRunnerResult flRunnerResult) {
         TaskRetry taskRetry = null;
         ContributionResult contributionResult = ContributionResult.UNSPECIFIED;
         if (flRunnerResult != null) {
@@ -773,14 +788,12 @@ public class FederatedComputeWorker {
     }
 
     /** Log that training run failed with exception. */
-    public void logTrainEventFinishedWithException() {
+    void logTrainEventFinishedWithException() {
         synchronized (mLock) {
-            if (mActiveRun == null) {
-                return;
-            }
-            if (mActiveRun.mTrainingEventLogger == null) {
+            if (mActiveRun == null || mActiveRun.mTrainingEventLogger == null) {
                 return;
             }
+
             mActiveRun.mTrainingEventLogger.logEventKind(
                     FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_WITH_EXCEPTION);
         }
@@ -790,8 +803,7 @@ public class FederatedComputeWorker {
      * Cancel the current running job, schedule recurrent job, unbind from ExampleStoreService and
      * ResultHandlingService etc.
      */
-    public void finish(
-            TaskRetry taskRetry, ContributionResult contributionResult, boolean cancelFuture) {
+    void finish(TaskRetry taskRetry, ContributionResult contributionResult, boolean cancelFuture) {
         TrainingRun runToFinish;
         synchronized (mLock) {
             if (mActiveRun == null) {
@@ -804,6 +816,7 @@ public class FederatedComputeWorker {
                 runToFinish.mFuture.cancel(true);
             }
         }
+        cleanUpTempFiles(runToFinish);
 
         performFinishRoutines(
                 runToFinish.mCallback,
@@ -815,14 +828,16 @@ public class FederatedComputeWorker {
     }
 
     /** To clean up active run for subsequent executions. */
-    public void cleanUpActiveRun() {
+    void cleanUpActiveRun() {
+        TrainingRun runToFinish;
         synchronized (mLock) {
             if (mActiveRun == null) {
                 return;
             }
-
+            runToFinish = mActiveRun;
             mActiveRun = null;
         }
+        cleanUpTempFiles(runToFinish);
     }
 
     private void performFinishRoutines(
@@ -860,6 +875,18 @@ public class FederatedComputeWorker {
                 enableFailuresTracking);
     }
 
+    private void cleanUpTempFiles(TrainingRun run) {
+        var unused =
+                mInjector
+                        .getBgExecutor()
+                        .submit(
+                                () -> {
+                                    deleteFileIfExist(run.mInputModelFile);
+                                    deleteFileIfExist(run.mPlanFile);
+                                    deleteFileIfExist(run.mOutputModelFile);
+                                });
+    }
+
     private void unBindServicesIfNecessary(TrainingRun runToFinish) {
         if (runToFinish.mIsolatedTrainingService != null) {
             LogUtil.i(TAG, "Unbinding from IsolatedTrainingService");
@@ -930,6 +957,7 @@ public class FederatedComputeWorker {
             // Write ClientOnlyPlan to file and pass ParcelFileDescriptor to isolated process to
             // avoid TransactionTooLargeException through IPC.
             String clientOnlyPlanFile = createTempFile(CLIENT_ONLY_PLAN_FILE_NAME, ".pb");
+            run.mPlanFile = clientOnlyPlanFile;
             FileUtils.writeToFile(clientOnlyPlanFile, clientPlan.toByteArray());
             ParcelFileDescriptor clientPlanFd =
                     createTempFileDescriptor(
@@ -1100,6 +1128,8 @@ public class FederatedComputeWorker {
             CheckinResult checkinResult, TrainingRun run, IExampleStoreIterator iterator) {
         ClientOnlyPlan clientPlan = checkinResult.getPlanData();
         String outputCheckpointFile = createTempFile("output", ".ckp");
+        run.mOutputModelFile = outputCheckpointFile;
+
         run.mTrainingEventLogger.logEventKind(
                 FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_COMPUTATION_STARTED);
 
@@ -1176,8 +1206,15 @@ public class FederatedComputeWorker {
                                 return Futures.immediateFuture(null);
                             }
                             if (authContext.isFirstAuthTry() && resp.hasAuthMetadata()) {
-                                authContext.updateAuthState(
-                                        resp.getAuthMetadata(), trainingEventLogger);
+                                List<String> attestationRecord =
+                                        authContext.updateAuthState(
+                                                resp.getAuthMetadata(), trainingEventLogger);
+                                if (attestationRecord == null || attestationRecord.isEmpty()) {
+                                    return Futures.immediateFailedFuture(
+                                            new IllegalStateException(
+                                                    "Failed to generate attestation record when"
+                                                            + " report result"));
+                                }
                                 return reportResultWithAuthentication(
                                         computationResult,
                                         encryptionKey,
@@ -1240,8 +1277,12 @@ public class FederatedComputeWorker {
                     trainingEventLogger);
         }
 
-        AuthorizationContext createAuthContext(Context context, String ownerId, String ownerCert) {
-            return AuthorizationContext.create(context, ownerId, ownerCert);
+        AuthorizationContext createAuthContext(
+                Context context,
+                String ownerId,
+                String ownerCert,
+                TrainingEventLogger trainingEventLogger) {
+            return AuthorizationContext.create(context, ownerId, ownerCert, trainingEventLogger);
         }
 
         EligibilityDecider getEligibilityDecider(Context context) {
@@ -1271,6 +1312,23 @@ public class FederatedComputeWorker {
 
         private FederatedJobService.OnJobFinishedCallback mCallback;
 
+        /**
+         * The file path of download initial checkpoint file. It's a temp file created under cache
+         * directory.
+         */
+        private String mInputModelFile = null;
+
+        /**
+         * The file path of downloaded plan file. It's a temp file created under cache directory.
+         */
+        private String mPlanFile = null;
+
+        /**
+         * The file path of new model checkpoint file. It's a temp file created under cache
+         * directory.
+         */
+        private String mOutputModelFile = null;
+
         private TrainingRun(
                 int jobId,
                 FederatedTrainingTask task,
@@ -1336,6 +1394,14 @@ public class FederatedComputeWorker {
             ComputationResult result,
             AuthorizationContext authContext,
             TrainingEventLogger trainingEventLogger) {
-        var unused = reportResultWithAuthentication(result, null, authContext, trainingEventLogger);
+        var unused =
+                reportResultWithAuthentication(
+                        result, /* encryptionKey= */ null, authContext, trainingEventLogger);
+    }
+
+    private static String getOwnerPackageName(TrainingRun run) {
+        return ComponentName.createRelative(
+                        run.mTask.ownerPackageName(), run.mTask.ownerClassName())
+                .flattenToString();
     }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/util/TrainingConditionsChecker.java b/federatedcompute/src/com/android/federatedcompute/services/training/util/TrainingConditionsChecker.java
index 27512577..c5fb0fcf 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/util/TrainingConditionsChecker.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/util/TrainingConditionsChecker.java
@@ -25,7 +25,7 @@ import android.os.StatFs;
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.common.BatteryInfo;
 import com.android.federatedcompute.services.common.Flags;
-import com.android.federatedcompute.services.common.PhFlags;
+import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.data.fbs.TrainingConstraints;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
@@ -78,7 +78,7 @@ public class TrainingConditionsChecker {
         if (sSingletonInstance == null) {
             synchronized (TrainingConditionsChecker.class) {
                 if (sSingletonInstance == null) {
-                    Flags flags = PhFlags.getInstance();
+                    Flags flags = FlagsFactory.getFlags();
                     sSingletonInstance =
                             new TrainingConditionsChecker(
                                     new BatteryInfo(context.getApplicationContext(), flags),
diff --git a/flags/Android.bp b/flags/Android.bp
index 4d4b9fdd..df2650dc 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -28,6 +28,6 @@ java_aconfig_library {
     ],
     min_sdk_version: "33",
     apex_available: [
-        "com.android.adservices.ondevicepersonalization",
+        "com.android.ondevicepersonalization",
     ],
 }
diff --git a/flags/ondevicepersonalization_flags.aconfig b/flags/ondevicepersonalization_flags.aconfig
index f3215b44..2eea5fd4 100644
--- a/flags/ondevicepersonalization_flags.aconfig
+++ b/flags/ondevicepersonalization_flags.aconfig
@@ -64,3 +64,12 @@ flag {
     is_fixed_read_only: true
     is_exported: true
 }
+
+flag {
+    name: "unhidden_on_device_personalization_exception_enabled"
+    namespace: "ondevicepersonalization_aconfig"
+    bug: "379743390"
+    description: "Enable unhidden of OnDevicePersonalizationException."
+    is_fixed_read_only: true
+    is_exported: true
+}
\ No newline at end of file
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 7a4ce655..2e626092 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -144,7 +144,7 @@ package android.adservices.ondevicepersonalization {
   public class FederatedComputeScheduler {
     method @WorkerThread public void cancel(@NonNull android.adservices.ondevicepersonalization.FederatedComputeInput);
     method @WorkerThread public void schedule(@NonNull android.adservices.ondevicepersonalization.FederatedComputeScheduler.Params, @NonNull android.adservices.ondevicepersonalization.FederatedComputeInput);
-    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.fcp_schedule_with_outcome_receiver_enabled") @WorkerThread public void schedule(@NonNull android.adservices.ondevicepersonalization.FederatedComputeScheduleRequest, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.FederatedComputeScheduleResponse,java.lang.Exception>);
+    method @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.fcp_schedule_with_outcome_receiver_enabled") @WorkerThread public void schedule(@NonNull android.adservices.ondevicepersonalization.FederatedComputeScheduleRequest, @NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.adservices.ondevicepersonalization.FederatedComputeScheduleResponse,java.lang.Exception>);
   }
 
   public static class FederatedComputeScheduler.Params {
@@ -254,6 +254,10 @@ package android.adservices.ondevicepersonalization {
   }
 
   public class OnDevicePersonalizationException extends java.lang.Exception {
+    ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.unhidden_on_device_personalization_exception_enabled") public OnDevicePersonalizationException(int);
+    ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.unhidden_on_device_personalization_exception_enabled") public OnDevicePersonalizationException(int, @Nullable String);
+    ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.unhidden_on_device_personalization_exception_enabled") public OnDevicePersonalizationException(int, @Nullable Throwable);
+    ctor @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.unhidden_on_device_personalization_exception_enabled") public OnDevicePersonalizationException(int, @Nullable String, @Nullable Throwable);
     method public int getErrorCode();
     field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public static final int ERROR_INFERENCE_FAILED = 9; // 0x9
     field @FlaggedApi("com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled") public static final int ERROR_INFERENCE_MODEL_NOT_FOUND = 8; // 0x8
diff --git a/framework/java/android/adservices/ondevicepersonalization/Constants.java b/framework/java/android/adservices/ondevicepersonalization/Constants.java
index c5d5a806..c4fb23d4 100644
--- a/framework/java/android/adservices/ondevicepersonalization/Constants.java
+++ b/framework/java/android/adservices/ondevicepersonalization/Constants.java
@@ -188,6 +188,7 @@ public class Constants {
 
     // Task type for trace event logging. Must match the values in
     // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+    public static final int TASK_TYPE_UNKNOWN = 0;
     public static final int TASK_TYPE_EXECUTE = 1;
     public static final int TASK_TYPE_RENDER = 2;
     public static final int TASK_TYPE_DOWNLOAD = 3;
@@ -198,9 +199,9 @@ public class Constants {
 
     // Event type for trace event logging. Must match the values in
     // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
-    public static final int EVENT_TYPE_UNKNOWN = 1;
-    public static final int EVENT_TYPE_WRITE_REQUEST_LOG = 2;
-    public static final int EVENT_TYPE_WRITE_EVENT_LOG = 3;
+    public static final int EVENT_TYPE_UNKNOWN = 0;
+    public static final int EVENT_TYPE_WRITE_REQUEST_LOG = 1;
+    public static final int EVENT_TYPE_WRITE_EVENT_LOG = 2;
 
     // Status for trace event logging. Must match the values in
     // frameworks/proto_logging/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
diff --git a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleRequest.java b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleRequest.java
index f8282e80..caff4968 100644
--- a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleRequest.java
+++ b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleRequest.java
@@ -26,7 +26,7 @@ import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /**
  * The input for {@link FederatedComputeScheduler#schedule(FederatedComputeScheduleRequest,
- * android.os.OutcomeReceiver)}.
+ * java.util.concurrent.Executor, android.os.OutcomeReceiver)}.
  */
 @DataClass(genEqualsHashCode = true)
 @FlaggedApi(Flags.FLAG_FCP_SCHEDULE_WITH_OUTCOME_RECEIVER_ENABLED)
diff --git a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleResponse.java b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleResponse.java
index ae905cec..9d894fab 100644
--- a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleResponse.java
+++ b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduleResponse.java
@@ -25,7 +25,7 @@ import com.android.ondevicepersonalization.internal.util.DataClass;
 
 /**
  * The result returned by {@link FederatedComputeScheduler#schedule(FederatedComputeScheduleRequest,
- * android.os.OutcomeReceiver)} when successful.
+ * java.util.concurrent.Executor, android.os.OutcomeReceiver)} when successful.
  */
 @DataClass(genEqualsHashCode = true)
 @FlaggedApi(Flags.FLAG_FCP_SCHEDULE_WITH_OUTCOME_RECEIVER_ENABLED)
diff --git a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
index a338494e..62cc2724 100644
--- a/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
+++ b/framework/java/android/adservices/ondevicepersonalization/FederatedComputeScheduler.java
@@ -19,6 +19,7 @@ package android.adservices.ondevicepersonalization;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IFederatedComputeCallback;
 import android.adservices.ondevicepersonalization.aidl.IFederatedComputeService;
+import android.annotation.CallbackExecutor;
 import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.WorkerThread;
@@ -30,6 +31,7 @@ import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 
 import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
 
 /**
@@ -52,8 +54,6 @@ public class FederatedComputeScheduler {
         mDataAccessService = dataService;
     }
 
-    // TODO(b/300461799): add federated compute server document.
-    // TODO(b/269665435): add sample code snippet.
     /**
      * Schedules a federated compute job. In {@link IsolatedService#onRequest}, the app can call
      * {@link IsolatedService#getFederatedComputeScheduler} to pass the scheduler when constructing
@@ -61,7 +61,9 @@ public class FederatedComputeScheduler {
      *
      * @param params parameters related to job scheduling.
      * @param input the configuration of the federated computation. It should be consistent with the
-     *     federated compute server setup.
+     *     federated compute server setup as described in <a
+     *     href="https://developers.google.com/privacy-sandbox/protections/on-device-personalization/federated-compute-server">
+     *     Federated Compute Server documentation. </a>.
      */
     @WorkerThread
     public void schedule(@NonNull Params params, @NonNull FederatedComputeInput input) {
@@ -132,6 +134,7 @@ public class FederatedComputeScheduler {
      * the {@link IsolatedWorker}.
      *
      * @param federatedComputeScheduleRequest input parameters related to job scheduling.
+     * @param executor the {@link Executor} on which to invoke the callback.
      * @param outcomeReceiver This either returns a {@link FederatedComputeScheduleResponse} on
      *     success, or {@link Exception} on failure. The exception type is {@link
      *     OnDevicePersonalizationException} with error code {@link
@@ -144,15 +147,18 @@ public class FederatedComputeScheduler {
     @FlaggedApi(Flags.FLAG_FCP_SCHEDULE_WITH_OUTCOME_RECEIVER_ENABLED)
     public void schedule(
             @NonNull FederatedComputeScheduleRequest federatedComputeScheduleRequest,
+            @NonNull @CallbackExecutor Executor executor,
             @NonNull OutcomeReceiver<FederatedComputeScheduleResponse, Exception> outcomeReceiver) {
         if (mFcService == null) {
             logApiCallStats(
                     Constants.API_NAME_FEDERATED_COMPUTE_SCHEDULE,
                     0,
                     Constants.STATUS_INTERNAL_ERROR);
-            outcomeReceiver.onError(
-                    new IllegalStateException(
-                            "FederatedComputeScheduler not available for this instance."));
+            executor.execute(
+                    () -> {
+                        outcomeReceiver.onError(new IllegalStateException(
+                                "FederatedComputeScheduler not available for this instance."));
+                    });
         }
 
         final long startTimeMillis = System.currentTimeMillis();
@@ -175,9 +181,12 @@ public class FederatedComputeScheduler {
                                     Constants.API_NAME_FEDERATED_COMPUTE_SCHEDULE,
                                     System.currentTimeMillis() - startTimeMillis,
                                     Constants.STATUS_SUCCESS);
-                            outcomeReceiver.onResult(
-                                    new FederatedComputeScheduleResponse(
-                                            federatedComputeScheduleRequest));
+                            executor.execute(
+                                    () -> {
+                                        outcomeReceiver.onResult(
+                                                new FederatedComputeScheduleResponse(
+                                                        federatedComputeScheduleRequest));
+                                    });
                         }
 
                         @Override
@@ -186,9 +195,12 @@ public class FederatedComputeScheduler {
                                     Constants.API_NAME_FEDERATED_COMPUTE_SCHEDULE,
                                     System.currentTimeMillis() - startTimeMillis,
                                     errorCode);
-                            outcomeReceiver.onError(
-                                    new OnDevicePersonalizationException(
-                                            translateErrorCode(errorCode)));
+                            executor.execute(
+                                    () -> {
+                                        outcomeReceiver.onError(
+                                                new OnDevicePersonalizationException(
+                                                        translateErrorCode(errorCode)));
+                                    });
                         }
                     });
         } catch (RemoteException e) {
@@ -197,7 +209,10 @@ public class FederatedComputeScheduler {
                     Constants.API_NAME_FEDERATED_COMPUTE_SCHEDULE,
                     System.currentTimeMillis() - startTimeMillis,
                     Constants.STATUS_REMOTE_EXCEPTION);
-            outcomeReceiver.onError(e);
+            executor.execute(
+                    () -> {
+                        outcomeReceiver.onError(e);
+                    });
         }
     }
 
diff --git a/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java b/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
index 649e4190..b161a79a 100644
--- a/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
+++ b/framework/java/android/adservices/ondevicepersonalization/IsolatedService.java
@@ -178,8 +178,8 @@ public abstract class IsolatedService extends Service {
 
     /**
      * Returns an {@link FederatedComputeScheduler} for the current request. The {@link
-     * FederatedComputeScheduler} can be used to schedule and cancel federated computation jobs.
-     * The federated computation includes federated learning and federated analytic jobs.
+     * FederatedComputeScheduler} can be used to schedule and cancel federated computation jobs. The
+     * federated computation includes federated learning and federated analytics jobs.
      *
      * @param requestToken an opaque token that identifies the current request to the service.
      * @return An {@link FederatedComputeScheduler} that returns a federated computation job
diff --git a/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java b/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
index 250d785a..c4fe3ec1 100644
--- a/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
+++ b/framework/java/android/adservices/ondevicepersonalization/LocalDataImpl.java
@@ -37,8 +37,7 @@ import java.util.concurrent.BlockingQueue;
 public class LocalDataImpl implements MutableKeyValueStore {
     private static final String TAG = "LocalDataImpl";
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
-    @NonNull
-    IDataAccessService mDataAccessService;
+    @NonNull private final IDataAccessService mDataAccessService;
 
     /** @hide */
     public LocalDataImpl(@NonNull IDataAccessService binder) {
@@ -152,6 +151,7 @@ public class LocalDataImpl implements MutableKeyValueStore {
     }
 
     private CallbackResult handleAsyncRequest(int op, Bundle params) {
+        // Blocks on the calling thread and waits for the response from the data access service.
         try {
             BlockingQueue<CallbackResult> asyncResult = new ArrayBlockingQueue<>(1);
             mDataAccessService.onRequest(
@@ -160,12 +160,12 @@ public class LocalDataImpl implements MutableKeyValueStore {
                     new IDataAccessServiceCallback.Stub() {
                         @Override
                         public void onSuccess(@NonNull Bundle result) {
-                            asyncResult.add(new CallbackResult(result, 0));
+                            asyncResult.add(new CallbackResult(result, /* errorCode= */ 0));
                         }
 
                         @Override
                         public void onError(int errorCode) {
-                            asyncResult.add(new CallbackResult(null, errorCode));
+                            asyncResult.add(new CallbackResult(/* result= */ null, errorCode));
                         }
                     });
             return asyncResult.take();
@@ -176,10 +176,10 @@ public class LocalDataImpl implements MutableKeyValueStore {
     }
 
     private static class CallbackResult {
-        final Bundle mResult;
-        final int mErrorCode;
+        private final Bundle mResult;
+        private final int mErrorCode;
 
-        CallbackResult(Bundle result, int errorCode) {
+        private CallbackResult(Bundle result, int errorCode) {
             mResult = result;
             mErrorCode = errorCode;
         }
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
index 84a30083..b6018c82 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationException.java
@@ -17,6 +17,7 @@
 package android.adservices.ondevicepersonalization;
 import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
+import android.annotation.Nullable;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
 
@@ -119,28 +120,28 @@ public class OnDevicePersonalizationException extends Exception {
 
     private final @ErrorCode int mErrorCode;
 
-    /** @hide */
+    @FlaggedApi(Flags.FLAG_UNHIDDEN_ON_DEVICE_PERSONALIZATION_EXCEPTION_ENABLED)
     public OnDevicePersonalizationException(@ErrorCode int errorCode) {
         mErrorCode = errorCode;
     }
 
-    /** @hide */
+    @FlaggedApi(Flags.FLAG_UNHIDDEN_ON_DEVICE_PERSONALIZATION_EXCEPTION_ENABLED)
     public OnDevicePersonalizationException(
-            @ErrorCode int errorCode, String message) {
+            @ErrorCode int errorCode, @Nullable String message) {
         super(message);
         mErrorCode = errorCode;
     }
 
-    /** @hide */
+    @FlaggedApi(Flags.FLAG_UNHIDDEN_ON_DEVICE_PERSONALIZATION_EXCEPTION_ENABLED)
     public OnDevicePersonalizationException(
-            @ErrorCode int errorCode, Throwable cause) {
+            @ErrorCode int errorCode, @Nullable Throwable cause) {
         super(cause);
         mErrorCode = errorCode;
     }
 
-    /** @hide */
+    @FlaggedApi(Flags.FLAG_UNHIDDEN_ON_DEVICE_PERSONALIZATION_EXCEPTION_ENABLED)
     public OnDevicePersonalizationException(
-            @ErrorCode int errorCode, String message, Throwable cause) {
+            @ErrorCode int errorCode, @Nullable String message, @Nullable Throwable cause) {
         super(message, cause);
         mErrorCode = errorCode;
     }
diff --git a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
index 452a51d2..89bc7809 100644
--- a/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
+++ b/framework/java/android/adservices/ondevicepersonalization/OnDevicePersonalizationManager.java
@@ -311,8 +311,10 @@ public class OnDevicePersonalizationManager {
                 wrappedParams.putParcelable(
                         Constants.EXTRA_APP_PARAMS_SERIALIZED,
                         new ByteArrayParceledSlice(PersistableBundleUtils.toByteArray(params)));
+                String appPackageName =
+                        mContext.getPackageManager().getNameForUid(Binder.getCallingUid());
                 odpService.execute(
-                        mContext.getPackageName(),
+                        appPackageName,
                         service,
                         wrappedParams,
                         new CallerMetadata.Builder().setStartTimeMillis(startTimeMillis).build(),
@@ -462,8 +464,10 @@ public class OnDevicePersonalizationManager {
                         Constants.EXTRA_APP_PARAMS_SERIALIZED,
                         new ByteArrayParceledSlice(
                                 PersistableBundleUtils.toByteArray(request.getAppParams())));
+                String appPackageName =
+                        mContext.getPackageManager().getNameForUid(Binder.getCallingUid());
                 odpService.execute(
-                        mContext.getPackageName(),
+                        appPackageName,
                         request.getService(),
                         wrappedParams,
                         new CallerMetadata.Builder().setStartTimeMillis(startTimeMillis).build(),
diff --git a/framework/java/android/federatedcompute/ExampleStoreIterator.java b/framework/java/android/federatedcompute/ExampleStoreIterator.java
index 3e154c58..cec1f539 100644
--- a/framework/java/android/federatedcompute/ExampleStoreIterator.java
+++ b/framework/java/android/federatedcompute/ExampleStoreIterator.java
@@ -23,7 +23,7 @@ import java.io.Closeable;
 
 /**
  * Iterator interface that client apps implement to return training examples. When FederatedCompute
- * runs a computation, it will call into this interface to fetech training examples to feed to the
+ * runs a computation, it will call into this interface to fetch training examples to feed to the
  * computation.
  *
  * @hide
@@ -31,16 +31,19 @@ import java.io.Closeable;
 public interface ExampleStoreIterator extends Closeable {
     /** Called when FederatedCompute needs another example. */
     void next(@NonNull IteratorCallback callback);
+
     /** Called by FederatedCompute when it is done using this iterator instance. */
     @Override
     void close();
+
     /** The client app must implement this callback return training examples. */
     public interface IteratorCallback {
         /**
-         * Called when the result for {@link ExampleStoreIterator#next} is available, or when the
-         * end of the collection has been reached.
+         * Called when the result for {@link ExampleStoreIterator#next} is available, or {@code
+         * null} when the end of the collection has been reached.
          */
         boolean onIteratorNextSuccess(Bundle result);
+
         /** Called when an error occurred and the result cannot be returned. */
         void onIteratorNextFailure(int errorCode);
     }
diff --git a/framework/java/android/federatedcompute/ExampleStoreQueryCallbackImpl.java b/framework/java/android/federatedcompute/ExampleStoreQueryCallbackImpl.java
index 7b491885..e9937853 100644
--- a/framework/java/android/federatedcompute/ExampleStoreQueryCallbackImpl.java
+++ b/framework/java/android/federatedcompute/ExampleStoreQueryCallbackImpl.java
@@ -25,6 +25,8 @@ import android.os.Bundle;
 import android.os.RemoteException;
 
 import com.android.federatedcompute.internal.util.LogUtil;
+import com.android.internal.annotations.GuardedBy;
+import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.Preconditions;
 
 /**
@@ -36,6 +38,7 @@ public class ExampleStoreQueryCallbackImpl implements QueryCallback {
     private static final String TAG = "ExampleStoreQueryCallbackImpl";
     private final IExampleStoreCallback mExampleStoreQueryCallback;
 
+    @VisibleForTesting
     public ExampleStoreQueryCallbackImpl(IExampleStoreCallback exampleStoreQueryCallback) {
         this.mExampleStoreQueryCallback = exampleStoreQueryCallback;
     }
@@ -60,6 +63,7 @@ public class ExampleStoreQueryCallbackImpl implements QueryCallback {
             LogUtil.w(TAG, e, "onIteratorNextFailure AIDL call failed, closing iterator");
         }
     }
+
     /**
      * The implementation of {@link IExampleStoreIterator}.
      *
@@ -68,6 +72,8 @@ public class ExampleStoreQueryCallbackImpl implements QueryCallback {
     public static class IteratorAdapter extends IExampleStoreIterator.Stub {
         private final ExampleStoreIterator mIterator;
         private final Object mLock = new Object();
+
+        @GuardedBy("mLock")
         private boolean mClosed = false;
 
         public IteratorAdapter(ExampleStoreIterator iterator) {
@@ -100,6 +106,7 @@ public class ExampleStoreQueryCallbackImpl implements QueryCallback {
             mIterator.close();
         }
     }
+
     /**
      * The implementation of {@link ExampleStoreIterator.IteratorCallback} that FederatedCompute
      * pass to the apps.
diff --git a/framework/java/android/federatedcompute/ExampleStoreService.java b/framework/java/android/federatedcompute/ExampleStoreService.java
index 7daadd3c..2ca64599 100644
--- a/framework/java/android/federatedcompute/ExampleStoreService.java
+++ b/framework/java/android/federatedcompute/ExampleStoreService.java
@@ -29,7 +29,7 @@ import android.os.IBinder;
  * The abstract base class that client apps hosting their own Example Stores must implement.
  *
  * <p>The FederatedCompute will call into client apps' implementations to fetch data to use during
- * the training of new models or get the aggregation analytic result. Apps must add a {@code
+ * the training of new models or get the federated analytics result. Apps must add a {@code
  * <service>} entry to their manifest so that the FederatedCompute can bind to their implementation,
  * like so:
  *
diff --git a/framework/java/android/federatedcompute/FederatedComputeManager.java b/framework/java/android/federatedcompute/FederatedComputeManager.java
index a1cbd11d..d28cea46 100644
--- a/framework/java/android/federatedcompute/FederatedComputeManager.java
+++ b/framework/java/android/federatedcompute/FederatedComputeManager.java
@@ -23,6 +23,7 @@ import android.content.Context;
 import android.federatedcompute.aidl.IFederatedComputeCallback;
 import android.federatedcompute.aidl.IFederatedComputeService;
 import android.federatedcompute.common.ScheduleFederatedComputeRequest;
+import android.os.Binder;
 import android.os.OutcomeReceiver;
 
 import com.android.federatedcompute.internal.util.AbstractServiceBinder;
@@ -81,8 +82,8 @@ public final class FederatedComputeManager {
             @NonNull @CallbackExecutor Executor executor,
             @NonNull OutcomeReceiver<Object, Exception> callback) {
         Objects.requireNonNull(request);
-        final IFederatedComputeService service = mServiceBinder.getService(executor);
         try {
+            final IFederatedComputeService service = mServiceBinder.getService(executor);
             IFederatedComputeCallback federatedComputeCallback =
                     new IFederatedComputeCallback.Stub() {
                         @Override
@@ -105,8 +106,10 @@ public final class FederatedComputeManager {
                             unbindFromService();
                         }
                     };
+            String appPackageName =
+                    mContext.getPackageManager().getNameForUid(Binder.getCallingUid());
             service.schedule(
-                    mContext.getPackageName(),
+                    appPackageName,
                     request.getTrainingOptions(),
                     federatedComputeCallback);
         } catch (Exception e) {
@@ -127,8 +130,8 @@ public final class FederatedComputeManager {
             @NonNull @CallbackExecutor Executor executor,
             @NonNull OutcomeReceiver<Object, Exception> callback) {
         Objects.requireNonNull(populationName);
-        final IFederatedComputeService service = mServiceBinder.getService(executor);
         try {
+            final IFederatedComputeService service = mServiceBinder.getService(executor);
             IFederatedComputeCallback federatedComputeCallback =
                     new IFederatedComputeCallback.Stub() {
                         @Override
diff --git a/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java b/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
index 2dedcdb9..5ee62d37 100644
--- a/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
+++ b/samples/odpsamplenetwork/src/main/java/com/example/odpsamplenetwork/SampleHandler.java
@@ -362,6 +362,23 @@ public class SampleHandler implements IsolatedWorker {
                 .build();
     }
 
+    private static Feature convertFloatListToFeature(String value) {
+        String[] splitPixels = value.split(",", -1);
+        FloatList.Builder floatListBuilder = FloatList.newBuilder();
+        for (int count = 0; count < 784; count++) {
+            floatListBuilder.addValue(Float.parseFloat(splitPixels[count]));
+        }
+        return Feature.newBuilder().setFloatList(floatListBuilder.build()).build();
+    }
+
+    private static Example convertToMnistExample(String strExample) {
+        String[] splitExample = strExample.split(":", -1);
+        Features.Builder featuresBuilder = Features.newBuilder();
+        featuresBuilder.putFeature("x", convertFloatListToFeature(splitExample[0]));
+        featuresBuilder.putFeature("y", convertLongToFeature(splitExample[1]));
+        return Example.newBuilder().setFeatures(featuresBuilder.build()).build();
+    }
+
     private static Example convertToExample(String serializedExample) {
         String[] splitExample = serializedExample.split(",", -1);
         Features.Builder featuresBuilder = Features.newBuilder();
@@ -417,7 +434,6 @@ public class SampleHandler implements IsolatedWorker {
                 resultBuilder.addTrainingExampleRecord(record);
             }
         } else if (input.getPopulationName().contains("keras")) {
-            Boolean isBuiltByTaskBuilder = input.getPopulationName().contains("task_builder");
             Random rand = new Random();
             int numExample = rand.nextInt(400);
             for (int exampleCount = 0; exampleCount < numExample; exampleCount++) {
@@ -435,8 +451,8 @@ public class SampleHandler implements IsolatedWorker {
                             .build();
                 Example example = Example.newBuilder().setFeatures(
                         Features.newBuilder()
-                            .putFeature(isBuiltByTaskBuilder ? "x" : "inputs", inputsFeature)
-                            .putFeature(isBuiltByTaskBuilder ? "y" : "outputs", outputsFeature)
+                            .putFeature("x" , inputsFeature)
+                            .putFeature("y" , outputsFeature)
                             .build())
                         .build();
                 TrainingExampleRecord record =
@@ -447,6 +463,24 @@ public class SampleHandler implements IsolatedWorker {
                                 .build();
                 resultBuilder.addTrainingExampleRecord(record);
             }
+        } else if (input.getPopulationName().contains("mnist")) {
+            for (int count = 1; count < 300; count++) {
+                try {
+                    Example example =
+                            convertToMnistExample(
+                                    new String(
+                                            mRemoteData.get(String.format("example%d", count)),
+                                            StandardCharsets.UTF_8));
+                    TrainingExampleRecord record =
+                            new TrainingExampleRecord.Builder()
+                                    .setTrainingExample(example.toByteArray())
+                                    .setResumptionToken(String.format("token%d", count).getBytes())
+                                    .build();
+                    resultBuilder.addTrainingExampleRecord(record);
+                } catch (Exception e) {
+                    break;
+                }
+            }
         }
 
         receiver.onResult(resultBuilder.build());
diff --git a/src/com/android/ondevicepersonalization/services/Flags.java b/src/com/android/ondevicepersonalization/services/Flags.java
index 98f48d0d..17cee0d1 100644
--- a/src/com/android/ondevicepersonalization/services/Flags.java
+++ b/src/com/android/ondevicepersonalization/services/Flags.java
@@ -92,6 +92,39 @@ public interface Flags extends ModuleSharedFlags {
     /** Default value for SPE to be enabled for the pilot background jobs. */
     @FeatureFlag boolean DEFAULT_SPE_PILOT_JOB_ENABLED = false;
 
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * AggregateErrorDataReportingService}
+     */
+    @FeatureFlag boolean
+            DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB = false;
+
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * MddJobService}
+     */
+    @FeatureFlag boolean DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB = false;
+
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * OnDevicePersonalizationDownloadProcessingJobService}.
+     */
+    @FeatureFlag boolean DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB =
+            false;
+
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * ResetDataJobService}.
+     */
+    @FeatureFlag boolean DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB = false;
+
+    /**
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * UserDataCollectionJobService}.
+     */
+    @FeatureFlag boolean DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB =
+            false;
+
     /** Default value for isolated service debugging flag. */
     boolean DEFAULT_ISOLATED_SERVICE_DEBUGGING_ENABLED = false;
 
@@ -244,6 +277,46 @@ public interface Flags extends ModuleSharedFlags {
         return DEFAULT_SPE_PILOT_JOB_ENABLED;
     }
 
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * AggregateErrorDataReportingService}
+     */
+    default boolean getSpeOnAggregateErrorDataReportingJobEnabled() {
+        return DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
+    }
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * MddJobService}
+     */
+    default boolean getSpeOnMddJobEnabled() {
+        return DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+    }
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * OnDevicePersonalizationDownloadProcessingJobService}.
+     */
+    default boolean getSpeOnOdpDownloadProcessingJobEnabled() {
+        return DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+    }
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * ResetDataJobService}.
+     */
+    default boolean getSpeOnResetDataJobEnabled() {
+        return DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+    }
+
+    /**
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * UserDataCollectionJobService}.
+     */
+    default boolean getSpeOnUserDataCollectionJobEnabled() {
+        return DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+    }
+
     default boolean getEnableClientErrorLogging() {
         return DEFAULT_CLIENT_ERROR_LOGGING_ENABLED;
     }
diff --git a/src/com/android/ondevicepersonalization/services/FlagsConstants.java b/src/com/android/ondevicepersonalization/services/FlagsConstants.java
new file mode 100644
index 00000000..fc014332
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/FlagsConstants.java
@@ -0,0 +1,155 @@
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
+public final class FlagsConstants {
+    /*
+     * Keys for ALL the flags stored in DeviceConfig.
+     */
+    // Killswitch keys
+    public static final String KEY_GLOBAL_KILL_SWITCH = "global_kill_switch";
+
+    public static final String KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE =
+            "enable_personalization_status_override";
+
+    public static final String KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE =
+            "personalization_status_override_value";
+
+    public static final String KEY_ISOLATED_SERVICE_DEADLINE_SECONDS =
+            "isolated_service_deadline_seconds";
+
+    public static final String KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS =
+            "app_request_flow_deadline_seconds";
+
+    public static final String KEY_RENDER_FLOW_DEADLINE_SECONDS = "render_flow_deadline_seconds";
+
+    public static final String KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS =
+            "web_view_flow_deadline_seconds";
+
+    public static final String KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS =
+            "web_trigger_flow_deadline_seconds";
+
+    public static final String KEY_TRUSTED_PARTNER_APPS_LIST = "trusted_partner_apps_list";
+
+    public static final String KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED =
+            "shared_isolated_process_feature_enabled";
+
+    public static final String KEY_CALLER_APP_ALLOW_LIST = "caller_app_allow_list";
+
+    public static final String KEY_ISOLATED_SERVICE_ALLOW_LIST = "isolated_service_allow_list";
+
+    public static final String KEY_OUTPUT_DATA_ALLOW_LIST = "output_data_allow_list";
+
+    public static final String KEY_USER_CONTROL_CACHE_IN_MILLIS =
+            "user_control_cache_duration_millis";
+
+    public static final String KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING =
+            "odp_enable_client_error_logging";
+
+    public static final String KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE =
+            "odp_background_job_sampling_logging_rate";
+
+    public static final String KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED =
+            "odp_job_scheduling_logging_enabled";
+
+    public static final String KEY_ODP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE =
+            "odp_job_scheduling_logging_sampling_rate";
+
+    public static final String KEY_ODP_MODULE_JOB_POLICY = "odp_module_job_policy";
+
+    public static final String KEY_ODP_SPE_PILOT_JOB_ENABLED = "odp_spe_pilot_job_enabled";
+
+    public static final String
+            KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB =
+            "OdpBackgroundJobs__enable_spe_on_aggregate_error_data_reporting_job";
+
+    public static final String KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB =
+            "OdpBackgroundJobs__enable_spe_on_mdd_job";
+
+    public static final String KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB =
+            "OdpBackgroundJobs__enable_spe_on_odp_download_processing_job";
+
+    public static final String KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB =
+            "OdpBackgroundJobs__enable_spe_on_reset_data_job";
+
+    public static final String KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB =
+            "OdpBackgroundJobs__enable_spe_on_user_data_collection_job";
+
+    public static final String KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED =
+            "is_art_image_loading_optimization_enabled";
+
+    public static final String KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED =
+            "isolated_service_debugging_enabled";
+
+    public static final String KEY_RESET_DATA_DELAY_SECONDS = "reset_data_delay_seconds";
+
+    public static final String KEY_RESET_DATA_DEADLINE_SECONDS = "reset_data_deadline_seconds";
+
+    public static final String APP_INSTALL_HISTORY_TTL = "app_install_history_ttl";
+    public static final String EXECUTE_BEST_VALUE_NOISE = "noise_for_execute_best_value";
+
+    public static final String KEY_ENABLE_AGGREGATED_ERROR_REPORTING =
+            "Odp__enable_aggregated_error_reporting";
+
+    public static final String KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS =
+            "Odp__aggregated_error_report_ttl_days";
+
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_PATH =
+            "Odp__aggregated_error_reporting_path";
+
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD =
+            "Odp__aggregated_error_reporting_threshold";
+
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS =
+            "Odp__aggregated_error_reporting_interval_hours";
+    public static final String KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING =
+            "Odp__aggregated_error_allow_unencrypted_aggregated_error_reporting";
+
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
+    public static final String MAX_INT_VALUES_LIMIT = "max_int_values_limit";
+
+    public static final String KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS =
+            "adservices_ipc_call_timeout_in_millis";
+    public static final String KEY_PLATFORM_DATA_FOR_TRAINING_ALLOWLIST =
+            "platform_data_for_training_allowlist";
+    public static final String KEY_PLATFORM_DATA_FOR_EXECUTE_ALLOWLIST =
+            "platform_data_for_execute_allowlist";
+
+    public static final String KEY_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST =
+            "log_isolated_service_error_code_non_aggregated_allowlist";
+
+    public static final String KEY_PLUGIN_PROCESS_RUNNER_ENABLED =
+            "Odp__enable_plugin_process_runner";
+
+    public static final String KEY_IS_FEATURE_ENABLED_API_ENABLED =
+            "Odp__enable_is_feature_enabled";
+
+    public static final String KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS =
+            "download_flow_deadline_seconds";
+
+    public static final String KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS =
+            "example_store_flow_deadline_seconds";
+}
diff --git a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
index c17586c3..f965cb3f 100644
--- a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
+++ b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiver.java
@@ -28,8 +28,8 @@ import android.content.pm.PackageManager;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.DeviceUtils;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
-import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingService;
-import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJobService;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingJob;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJob;
 import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
 
@@ -126,10 +126,10 @@ public class OnDevicePersonalizationBroadcastReceiver extends BroadcastReceiver
                             // Schedule maintenance task
                             OnDevicePersonalizationMaintenanceJob.schedule(context);
                             // Schedule user data collection task
-                            UserDataCollectionJobService.schedule(context);
+                            UserDataCollectionJob.schedule(context);
                             // Schedule regular ODP aggregated error reporting task if the flag
                             // is enabled etc.
-                            AggregateErrorDataReportingService.scheduleIfNeeded(context);
+                            AggregateErrorDataReportingJob.schedule(context);
                         },
                         executor);
 
diff --git a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
index d6f51e26..ebd48bdf 100644
--- a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
+++ b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceDelegate.java
@@ -39,6 +39,7 @@ import android.os.Trace;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.DeviceUtils;
+import com.android.odp.module.common.ProcessWrapper;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.enrollment.PartnerEnrollmentChecker;
 import com.android.ondevicepersonalization.services.serviceflow.ServiceFlowOrchestrator;
@@ -284,7 +285,8 @@ public class OnDevicePersonalizationManagingServiceDelegate
         return flagEnabled;
     }
 
-    private void enforceCallingPackageBelongsToUid(@NonNull String packageName, int uid) {
+    @VisibleForTesting
+    void enforceCallingPackageBelongsToUid(@NonNull String packageName, int uid) {
         int packageUid;
         PackageManager pm = mContext.getPackageManager();
         try {
@@ -292,10 +294,12 @@ public class OnDevicePersonalizationManagingServiceDelegate
         } catch (PackageManager.NameNotFoundException e) {
             throw new SecurityException(packageName + " not found");
         }
-        if (packageUid != uid) {
+
+        int appUid = ProcessWrapper.isSdkSandboxUid(uid)
+                ? ProcessWrapper.getAppUidForSdkSandboxUid(uid) : uid;
+        if (packageUid != appUid) {
             throw new SecurityException(packageName + " does not belong to uid " + uid);
         }
-        //TODO(b/242792629): Handle requests from the SDK sandbox.
     }
 
     private void enforceEnrollment(@NonNull String callingPackageName,
diff --git a/src/com/android/ondevicepersonalization/services/PhFlags.java b/src/com/android/ondevicepersonalization/services/PhFlags.java
index ab963829..68211f3b 100644
--- a/src/com/android/ondevicepersonalization/services/PhFlags.java
+++ b/src/com/android/ondevicepersonalization/services/PhFlags.java
@@ -16,6 +16,57 @@
 
 package com.android.ondevicepersonalization.services;
 
+import static com.android.ondevicepersonalization.services.FlagsConstants.APP_INSTALL_HISTORY_TTL;
+import static com.android.ondevicepersonalization.services.FlagsConstants.EXECUTE_BEST_VALUE_NOISE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_PATH;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_CALLER_APP_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_URL;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_GLOBAL_KILL_SWITCH;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_MODULE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_SPE_PILOT_JOB_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_OUTPUT_DATA_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PLATFORM_DATA_FOR_EXECUTE_ALLOWLIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PLATFORM_DATA_FOR_TRAINING_ALLOWLIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PLUGIN_PROCESS_RUNNER_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RENDER_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_DELAY_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_CONTROL_CACHE_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.MAX_INT_VALUES_LIMIT;
+
 import android.annotation.NonNull;
 import android.provider.DeviceConfig;
 
@@ -26,120 +77,6 @@ import java.util.Map;
 
 /** Flags Implementation that delegates to DeviceConfig. */
 public final class PhFlags implements Flags {
-    /*
-     * Keys for ALL the flags stored in DeviceConfig.
-     */
-    // Killswitch keys
-    public static final String KEY_GLOBAL_KILL_SWITCH = "global_kill_switch";
-
-    public static final String KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE =
-            "enable_personalization_status_override";
-
-    public static final String KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE =
-            "personalization_status_override_value";
-
-    public static final String KEY_ISOLATED_SERVICE_DEADLINE_SECONDS =
-            "isolated_service_deadline_seconds";
-
-    public static final String KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS =
-            "app_request_flow_deadline_seconds";
-
-    public static final String KEY_RENDER_FLOW_DEADLINE_SECONDS =
-            "render_flow_deadline_seconds";
-
-    public static final String KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS =
-            "web_view_flow_deadline_seconds";
-
-    public static final String KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS =
-            "web_trigger_flow_deadline_seconds";
-
-    public static final String KEY_TRUSTED_PARTNER_APPS_LIST = "trusted_partner_apps_list";
-
-    public static final String KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED =
-            "shared_isolated_process_feature_enabled";
-
-    public static final String KEY_CALLER_APP_ALLOW_LIST = "caller_app_allow_list";
-
-    public static final String KEY_ISOLATED_SERVICE_ALLOW_LIST = "isolated_service_allow_list";
-
-    public static final String KEY_OUTPUT_DATA_ALLOW_LIST = "output_data_allow_list";
-
-    public static final String KEY_USER_CONTROL_CACHE_IN_MILLIS =
-            "user_control_cache_duration_millis";
-
-    public static final String KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING =
-            "odp_enable_client_error_logging";
-
-    public static final String KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE =
-            "odp_background_job_sampling_logging_rate";
-
-    public static final String KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED =
-            "odp_job_scheduling_logging_enabled";
-
-    public static final String KEY_ODP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE =
-            "odp_job_scheduling_logging_sampling_rate";
-
-    public static final String KEY_ODP_MODULE_JOB_POLICY = "odp_module_job_policy";
-
-    public static final String KEY_ODP_SPE_PILOT_JOB_ENABLED = "odp_spe_pilot_job_enabled";
-
-    public static final String KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED =
-            "is_art_image_loading_optimization_enabled";
-
-    public static final String KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED =
-            "isolated_service_debugging_enabled";
-
-    public static final String KEY_RESET_DATA_DELAY_SECONDS = "reset_data_delay_seconds";
-
-    public static final String KEY_RESET_DATA_DEADLINE_SECONDS = "reset_data_deadline_seconds";
-
-    public static final String APP_INSTALL_HISTORY_TTL = "app_install_history_ttl";
-    public static final String EXECUTE_BEST_VALUE_NOISE = "noise_for_execute_best_value";
-
-    public static final String KEY_ENABLE_AGGREGATED_ERROR_REPORTING =
-            "Odp__enable_aggregated_error_reporting";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS =
-            "Odp__aggregated_error_report_ttl_days";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORTING_PATH =
-            "Odp__aggregated_error_reporting_path";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD =
-            "Odp__aggregated_error_reporting_threshold";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS =
-            "Odp__aggregated_error_reporting_interval_hours";
-    public static final String KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING =
-            "Odp__aggregated_error_allow_unencrypted_aggregated_error_reporting";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS =
-            "Odp__aggregated_error_reporting_http_timeout_seconds";
-
-    public static final String KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT =
-            "Odp__aggregated_error_reporting_http_retry_limit";
-
-    public static final String KEY_ENCRYPTION_KEY_URL = "Odp__encryption_key_download_url";
-
-    public static final String KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS =
-            "Odp__encryption_key_max_age_seconds";
-    public static final String MAX_INT_VALUES_LIMIT = "max_int_values_limit";
-
-    public static final String KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS =
-            "adservices_ipc_call_timeout_in_millis";
-    public static final String KEY_PLATFORM_DATA_FOR_TRAINING_ALLOWLIST =
-            "platform_data_for_training_allowlist";
-    public static final String KEY_PLATFORM_DATA_FOR_EXECUTE_ALLOWLIST =
-            "platform_data_for_execute_allowlist";
-
-    public static final String KEY_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST =
-            "log_isolated_service_error_code_non_aggregated_allowlist";
-
-    public static final String KEY_PLUGIN_PROCESS_RUNNER_ENABLED =
-            "Odp__enable_plugin_process_runner";
-
-    public static final String KEY_IS_FEATURE_ENABLED_API_ENABLED =
-            "Odp__enable_is_feature_enabled";
 
     // OnDevicePersonalization Namespace String from DeviceConfig class
     public static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
@@ -231,9 +168,6 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ WEB_TRIGGER_FLOW_DEADLINE_SECONDS);
     }
 
-    public static final String KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS =
-            "example_store_flow_deadline_seconds";
-
     @Override
     public int getExampleStoreFlowDeadlineSeconds() {
         return DeviceConfig.getInt(
@@ -242,9 +176,6 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ EXAMPLE_STORE_FLOW_DEADLINE_SECONDS);
     }
 
-    public static final String KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS =
-            "download_flow_deadline_seconds";
-
     @Override
     public int getDownloadFlowDeadlineSeconds() {
         return DeviceConfig.getInt(
@@ -372,6 +303,50 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ DEFAULT_SPE_PILOT_JOB_ENABLED);
     }
 
+    @Override
+    public boolean getSpeOnAggregateErrorDataReportingJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB,
+                /* defaultValue= */
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB);
+    }
+
+    @Override
+    public boolean getSpeOnMddJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB,
+                /* defaultValue= */ DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB);
+    }
+
+    @Override
+    public boolean getSpeOnOdpDownloadProcessingJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB,
+                /* defaultValue= */
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB);
+    }
+
+    @Override
+    public boolean getSpeOnResetDataJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB,
+                /* defaultValue= */ DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB);
+    }
+
+    @Override
+    public boolean getSpeOnUserDataCollectionJobEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB,
+                /* defaultValue= */
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB);
+    }
+
     @Override
     public boolean isArtImageLoadingOptimizationEnabled() {
         return DeviceConfig.getBoolean(
diff --git a/src/com/android/ondevicepersonalization/services/StableFlags.java b/src/com/android/ondevicepersonalization/services/StableFlags.java
index 22cb30c5..2fa4da25 100644
--- a/src/com/android/ondevicepersonalization/services/StableFlags.java
+++ b/src/com/android/ondevicepersonalization/services/StableFlags.java
@@ -55,31 +55,43 @@ public class StableFlags {
 
     @VisibleForTesting
     StableFlags(Flags flags) {
-        mStableFlagsMap.put(PhFlags.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS,
                 flags.getAppRequestFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_RENDER_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_RENDER_FLOW_DEADLINE_SECONDS,
                 flags.getRenderFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS,
                 flags.getWebTriggerFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS,
                 flags.getWebViewFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS,
                 flags.getExampleStoreFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS,
                 flags.getDownloadFlowDeadlineSeconds());
-        mStableFlagsMap.put(PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED,
                 flags.isSharedIsolatedProcessFeatureEnabled());
-        mStableFlagsMap.put(PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST,
-                flags.getTrustedPartnerAppsList());
-        mStableFlagsMap.put(PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST, flags.getTrustedPartnerAppsList());
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED,
                 flags.isArtImageLoadingOptimizationEnabled());
-        mStableFlagsMap.put(PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE,
                 flags.isPersonalizationStatusOverrideEnabled());
-        mStableFlagsMap.put(PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE,
                 flags.getPersonalizationStatusOverrideValue());
-        mStableFlagsMap.put(PhFlags.KEY_USER_CONTROL_CACHE_IN_MILLIS,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_USER_CONTROL_CACHE_IN_MILLIS,
                 flags.getUserControlCacheInMillis());
-        mStableFlagsMap.put(PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED,
+        mStableFlagsMap.put(
+                FlagsConstants.KEY_PLUGIN_PROCESS_RUNNER_ENABLED,
                 flags.isPluginProcessRunnerEnabled());
     }
 
diff --git a/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java b/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
index 281aeea1..57fb8317 100644
--- a/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/data/DataAccessServiceImpl.java
@@ -68,6 +68,7 @@ import java.util.Objects;
 public class DataAccessServiceImpl extends IDataAccessService.Stub {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = "DataAccessServiceImpl";
+
     @NonNull
     private final Context mApplicationContext;
     @NonNull
@@ -104,7 +105,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
     }
 
     @VisibleForTesting
-    public DataAccessServiceImpl(
+    DataAccessServiceImpl(
             @NonNull ComponentName service,
             @NonNull Context applicationContext,
             Map<String, byte[]> remoteData,
@@ -149,10 +150,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
     /** Handle a request from the isolated process. */
     @Override
     public void onRequest(
-            int operation,
-            @NonNull Bundle params,
-            @NonNull IDataAccessServiceCallback callback
-    ) {
+            int operation, @NonNull Bundle params, @NonNull IDataAccessServiceCallback callback) {
         sLogger.d(TAG + ": onRequest: op=" + operation + " params: " + params.toString());
         switch (operation) {
             case Constants.DATA_ACCESS_OP_REMOTE_DATA_LOOKUP:
@@ -482,16 +480,15 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
         try {
             byte[] modelData = null;
             switch (modelId.getTableId()) {
-                case ModelId.TABLE_ID_REMOTE_DATA:
-                    modelData = mVendorDataDao.readSingleVendorDataRow(modelId.getKey());
-                    break;
-                case ModelId.TABLE_ID_LOCAL_DATA:
-                    modelData = mLocalDataDao.readSingleLocalDataRow(modelId.getKey());
-                    break;
-                default:
+                case ModelId.TABLE_ID_REMOTE_DATA ->
+                        modelData = mVendorDataDao.readSingleVendorDataRow(modelId.getKey());
+                case ModelId.TABLE_ID_LOCAL_DATA ->
+                        modelData = mLocalDataDao.readSingleLocalDataRow(modelId.getKey());
+                default -> {
                     sLogger.e(TAG + "Unsupported model table Id %d", modelId.getTableId());
                     sendError(callback, Constants.STATUS_MODEL_TABLE_ID_INVALID);
                     return;
+                }
             }
 
             if (modelData == null) {
@@ -514,9 +511,8 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
         }
     }
 
-    private void sendResult(
-            @NonNull Bundle result,
-            @NonNull IDataAccessServiceCallback callback) {
+    private static void sendResult(
+            @NonNull Bundle result, @NonNull IDataAccessServiceCallback callback) {
         try {
             callback.onSuccess(result);
         } catch (RemoteException e) {
@@ -524,7 +520,7 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
         }
     }
 
-    private void sendError(@NonNull IDataAccessServiceCallback callback, int errorCode) {
+    private static void sendError(@NonNull IDataAccessServiceCallback callback, int errorCode) {
         try {
             callback.onError(errorCode);
         } catch (RemoteException e) {
@@ -543,22 +539,18 @@ public class DataAccessServiceImpl extends IDataAccessService.Stub {
         }
 
         OnDevicePersonalizationVendorDataDao getVendorDataDao(
-                Context context, ComponentName service, String certDigest
-        ) {
+                Context context, ComponentName service, String certDigest) {
             return OnDevicePersonalizationVendorDataDao.getInstance(context,
                     service, certDigest);
         }
 
         OnDevicePersonalizationLocalDataDao getLocalDataDao(
-                Context context, ComponentName service, String certDigest
-        ) {
+                Context context, ComponentName service, String certDigest) {
             return OnDevicePersonalizationLocalDataDao.getInstance(context,
                     service, certDigest);
         }
 
-        EventsDao getEventsDao(
-                Context context
-        ) {
+        EventsDao getEventsDao(Context context) {
             return EventsDao.getInstance(context);
         }
 
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java
new file mode 100644
index 00000000..847075a3
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java
@@ -0,0 +1,173 @@
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+
+import android.content.Context;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.data.EncryptionUtils;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+import java.util.List;
+import java.util.Optional;
+
+/**
+ * The {@link JobWorker} to perform daily reporting of aggregated error codes.
+ *
+ * <p>The actual reporting task is offloaded to {@link AggregatedErrorReportingWorker}.
+ */
+public final class AggregateErrorDataReportingJob implements JobWorker {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = AggregateErrorDataReportingJob.class.getSimpleName();
+
+    private final Injector mInjector;
+
+    public AggregateErrorDataReportingJob() {
+        this(new Injector());
+    }
+
+    @VisibleForTesting
+    AggregateErrorDataReportingJob(Injector injector) {
+        mInjector = injector;
+    }
+
+    @VisibleForTesting
+    static class Injector {
+        ListeningExecutorService getExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        Flags getFlags() {
+            return FlagsFactory.getFlags();
+        }
+
+        AggregatedErrorReportingWorker getErrorReportingWorker() {
+            return AggregatedErrorReportingWorker.createWorker();
+        }
+
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return EncryptionUtils.getEncryptionKeyManager(context);
+        }
+    }
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(
+            Context context, ExecutionRuntimeParameters executionRuntimeParameters) {
+        // By default, the aggregated error data payload is encrypted.
+        FluentFuture<List<OdpEncryptionKey>> encryptionKeyFuture =
+                mInjector.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload()
+                        ? FluentFuture.from(Futures.immediateFuture(List.of()))
+                        : mInjector.getEncryptionKeyManager(context)
+                                .fetchAndPersistActiveKeys(
+                                        OdpEncryptionKey.KEY_TYPE_ENCRYPTION,
+                                        /* isScheduledJob */ true,
+                                        /* loggerOptional*/ Optional.empty());
+        return
+                encryptionKeyFuture.transformAsync(
+                        encryptionKeys ->
+                                FluentFuture.from(
+                                        mInjector.getErrorReportingWorker().reportAggregateErrors(
+                                                context,
+                                                OdpEncryptionKeyManager
+                                                        .getRandomKey(encryptionKeys))),
+                        mInjector.getExecutor())
+                        .transform(voidResult -> ExecutionResult.SUCCESS, mInjector.getExecutor());
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (mInjector.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG
+                    + ": GlobalKillSwitch enabled, skip execution of"
+                    + " AggregateErrorDataReportingJob.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!mInjector.getFlags().getAggregatedErrorReportingEnabled()) {
+            sLogger.d(TAG + ": aggregate error reporting disabled, finishing job.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
+    /** Schedules a unique instance of {@link AggregateErrorDataReportingJob}. */
+    public static void schedule(Context context) {
+        // If SPE is not enabled, force to schedule the job with the old JobService.
+        if (!FlagsFactory.getFlags().getSpeOnAggregateErrorDataReportingJobEnabled()) {
+            sLogger.d("SPE is not enabled. Schedule the job with"
+                    + " AggregateErrorDataReportingService.");
+
+            int resultCode = AggregateErrorDataReportingService
+                    .scheduleIfNeeded(context, /* forceSchedule */ false);
+            OdpJobServiceFactory.getInstance(context)
+                    .getJobSchedulingLogger()
+                    .recordOnSchedulingLegacy(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID, resultCode);
+
+            return;
+        }
+
+        OdpJobScheduler.getInstance(context).schedule(context, createDefaultJobSpec());
+    }
+
+    @VisibleForTesting
+    static JobSpec createDefaultJobSpec() {
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_UNMETERED)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder().setPeriodicIntervalMs(
+                                        FlagsFactory.getFlags()
+                                                .getAggregatedErrorReportingIntervalInHours()
+                                        * 3600L * 1000L
+                                ))
+                        .setIsPersisted(true)
+                        .build();
+        return new JobSpec.Builder(jobPolicy).build();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
index 4e3eb451..d8b5b935 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingService.java
@@ -16,10 +16,13 @@
 
 package com.android.ondevicepersonalization.services.data.errors;
 
-import static android.app.job.JobScheduler.RESULT_FAILURE;
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_JOB_NOT_CONFIGURED;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
 
 import android.app.job.JobInfo;
@@ -29,6 +32,7 @@ import android.app.job.JobService;
 import android.content.ComponentName;
 import android.content.Context;
 
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
 import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
@@ -89,21 +93,29 @@ public class AggregateErrorDataReportingService extends JobService {
     }
 
     /** Schedules a unique instance of the {@link AggregateErrorDataReportingService} to be run. */
-    public static int scheduleIfNeeded(Context context) {
-        return scheduleIfNeeded(context, FlagsFactory.getFlags());
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int scheduleIfNeeded(Context context, boolean forceSchedule) {
+        return scheduleIfNeeded(context, FlagsFactory.getFlags(), forceSchedule);
     }
 
     @VisibleForTesting
-    static int scheduleIfNeeded(Context context, Flags flags) {
+    @JobServiceConstants.JobSchedulingResultCode
+    static int scheduleIfNeeded(Context context, Flags flags, boolean forceSchedule) {
         if (!flags.getAggregatedErrorReportingEnabled()) {
             sLogger.d(TAG + ": Aggregate error reporting is disabled.");
-            return RESULT_FAILURE;
+            return SCHEDULING_RESULT_CODE_FAILED;
         }
 
         JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
-        if (jobScheduler.getPendingJob(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID) != null) {
+        if (jobScheduler == null) {
+            sLogger.e(TAG, "Failed to get job scheduler from system service.");
+            return SCHEDULING_RESULT_CODE_FAILED;
+        }
+
+        if (!forceSchedule
+                && jobScheduler.getPendingJob(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID) != null) {
             sLogger.d(TAG + ": Job is already scheduled. Doing nothing.");
-            return RESULT_FAILURE;
+            return SCHEDULING_RESULT_CODE_SKIPPED;
         }
 
         ComponentName serviceComponent =
@@ -123,7 +135,9 @@ public class AggregateErrorDataReportingService extends JobService {
         // persist this job across boots
         builder.setPersisted(true);
 
-        return jobScheduler.schedule(builder.build());
+        int schedulingResult = jobScheduler.schedule(builder.build());
+        return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                : SCHEDULING_RESULT_CODE_FAILED;
     }
 
     @Override
@@ -145,6 +159,16 @@ public class AggregateErrorDataReportingService extends JobService {
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_JOB_NOT_CONFIGURED);
         }
 
+        // Reschedule jobs with SPE if it's enabled. Note scheduled jobs by this
+        // AggregateErrorDataReportingService will be cancelled for the same job ID.
+        if (FlagsFactory.getFlags().getSpeOnAggregateErrorDataReportingJobEnabled()) {
+            sLogger.i(
+                    "SPE is enabled. Reschedule AggregateErrorDataReportingService with"
+                            + " AggregateErrorDataReportingJob.");
+            AggregateErrorDataReportingJob.schedule(/* context */ this);
+            return false;
+        }
+
         OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(/* context= */ this);
         // By default, the aggregated error data payload is encrypted.
         FluentFuture<List<OdpEncryptionKey>> encryptionKeyFuture =
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java
index 2bfb217e..71641c0f 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocol.java
@@ -200,8 +200,7 @@ class AggregatedErrorReportingProtocol implements ReportingProtocol {
         }
     }
 
-    @VisibleForTesting
-    ListenableFuture<OdpHttpResponse> uploadExceptionData(
+    private ListenableFuture<OdpHttpResponse> uploadExceptionData(
             OdpHttpResponse response, @Nullable OdpEncryptionKey encryptionKey) {
         try {
             validateHttpResponseStatus(/* stage= */ "reportRequest", response);
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
index 73ac8149..a0d2a5a6 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
@@ -39,9 +39,11 @@ import android.content.pm.PackageManager;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.data.ErrorReportingMetadataProtoDataStore;
+import com.android.odp.module.common.data.ErrorReportingMetadataStore;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
+import com.android.odp.module.common.proto.ErrorReportingMetadata;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
-import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
@@ -52,6 +54,8 @@ import com.google.common.util.concurrent.FutureCallback;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+import com.google.protobuf.Timestamp;
 
 import java.util.ArrayList;
 import java.util.List;
@@ -73,6 +77,7 @@ class AggregatedErrorReportingWorker {
     private final Injector mInjector;
 
     /** Helper class to allow injection of mocks/test-objects in test. */
+    @VisibleForTesting
     static class Injector {
         ListeningExecutorService getLightweightExecutor() {
             return OnDevicePersonalizationExecutors.getLightweightExecutor();
@@ -82,10 +87,6 @@ class AggregatedErrorReportingWorker {
             return OnDevicePersonalizationExecutors.getBackgroundExecutor();
         }
 
-        Flags getFlags() {
-            return FlagsFactory.getFlags();
-        }
-
         ReportingProtocol getAggregatedErrorReportingProtocol(
                 ImmutableList<ErrorData> errorData, String requestBaseUri, Context context) {
             return AggregatedErrorReportingProtocol.createAggregatedErrorReportingProtocol(
@@ -95,6 +96,15 @@ class AggregatedErrorReportingWorker {
         String getServerUrl(Context context, String packageName) {
             return AggregatedErrorReportingWorker.getFcRemoteServerUrl(context, packageName);
         }
+
+        long getErrorReportingIntervalHours() {
+            return FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours();
+        }
+
+        ErrorReportingMetadataStore getMetadataStore(Context context) {
+            return ErrorReportingMetadataProtoDataStore.getInstance(
+                    context, getBackgroundExecutor());
+        }
     }
 
     private AggregatedErrorReportingWorker(Injector injector) {
@@ -113,7 +123,7 @@ class AggregatedErrorReportingWorker {
 
     @VisibleForTesting
     static void resetForTesting() {
-        sOnGoingReporting.set(false);
+        cleanup();
     }
 
     /**
@@ -132,15 +142,74 @@ class AggregatedErrorReportingWorker {
                     new IllegalStateException("Duplicate report request"));
         }
 
-        sLogger.d(TAG + ": beginning aggregate error reporting.");
-        return Futures.submitAsync(
-                () -> reportAggregateErrorsHelper(context, encryptionKey),
+        ListenableFuture<Boolean> checkIntervalFuture = isReportingIntervalSatisfied(context);
+
+        return Futures.transformAsync(
+                checkIntervalFuture,
+                intervalSatisfied -> {
+                    if (intervalSatisfied) {
+                        return reportAggregateErrorsHelper(context, encryptionKey);
+                    } else {
+                        sLogger.d(
+                                TAG
+                                        + ": skipping aggregate error reporting due to reporting"
+                                        + " interval.");
+                        return Futures.immediateVoidFuture();
+                    }
+                },
                 mInjector.getBackgroundExecutor());
     }
 
+    @VisibleForTesting
+    ListenableFuture<Boolean> isReportingIntervalSatisfied(Context context) {
+        ErrorReportingMetadataStore store = mInjector.getMetadataStore(context);
+        ListenableFuture<ErrorReportingMetadata> existingMetadataFuture = store.get();
+
+        return Futures.transform(
+                existingMetadataFuture,
+                existingData ->
+                        isReportingIntervalSatisfied(
+                                existingData, mInjector.getErrorReportingIntervalHours()),
+                mInjector.getLightweightExecutor());
+    }
+
+    private static boolean isReportingIntervalSatisfied(
+            ErrorReportingMetadata existingData, long reportingIntervalHours) {
+        if (ErrorReportingMetadataProtoDataStore.isErrorReportingMetadataUninitialized(
+                existingData)) {
+            sLogger.d(TAG, "No existing error reporting metadata found");
+            return true;
+        }
+
+        long lastUpload = existingData.getLastSuccessfulUpload().getSeconds();
+        long currentTimeSeconds = DateTimeUtils.epochSecondsUtc();
+        if (currentTimeSeconds >= lastUpload + reportingIntervalHours * 3600) {
+            return true;
+        } else {
+            sLogger.d(TAG, "Reporting interval not satisfied, skipping reporting");
+            return false;
+        }
+    }
+
+    @VisibleForTesting
+    ListenableFuture<Boolean> updateLastReportedTime(Context context) {
+        ErrorReportingMetadataStore store = mInjector.getMetadataStore(context);
+        Timestamp currentTime =
+                Timestamp.newBuilder().setSeconds(DateTimeUtils.epochSecondsUtc()).build();
+        sLogger.d(TAG + ": updating the error reporting metadata with current time " + currentTime);
+        ErrorReportingMetadata newMetadata =
+                ErrorReportingMetadata.newBuilder().setLastSuccessfulUpload(currentTime).build();
+
+        // Use the direct executor since simple transform
+        return Futures.transform(
+                store.set(newMetadata), result -> true, MoreExecutors.directExecutor());
+    }
+
     @VisibleForTesting
     ListenableFuture<Void> reportAggregateErrorsHelper(
             Context context, @Nullable OdpEncryptionKey encryptionKey) {
+        sLogger.d(TAG + ": beginning aggregate error reporting.");
+
         try {
             List<ComponentName> odpServices =
                     AppManifestConfigHelper.getOdpServices(context, /* enrolledOnly= */ true);
@@ -151,6 +220,7 @@ class AggregatedErrorReportingWorker {
             }
 
             List<ListenableFuture<Boolean>> futureList = new ArrayList<>();
+            futureList.add(updateLastReportedTime(context));
             for (ComponentName componentName : odpServices) {
                 String certDigest = getCertDigest(context, componentName.getPackageName());
                 if (certDigest.isEmpty()) {
@@ -244,8 +314,7 @@ class AggregatedErrorReportingWorker {
         }
     }
 
-    @VisibleForTesting
-    static void cleanup() {
+    private static void cleanup() {
         // Helper method to clean-up at the end of reporting.
         sOnGoingReporting.set(false);
     }
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java b/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
index 139ca733..836b5834 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/OnDevicePersonalizationAggregatedErrorDataDao.java
@@ -186,7 +186,12 @@ class OnDevicePersonalizationAggregatedErrorDataDao {
         return packageVersion;
     }
 
-    /** Delete the existing aggregate exception data for this package. */
+    /**
+     * Delete the existing aggregate exception data for this package.
+     *
+     * <p>For use in tests only.
+     */
+    @VisibleForTesting
     public boolean deleteExceptionData() {
         SQLiteDatabase db = mDbHelper.safeGetWritableDatabase();
         if (db == null) {
diff --git a/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java
new file mode 100644
index 00000000..3d7a6b20
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java
@@ -0,0 +1,157 @@
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
+package com.android.ondevicepersonalization.services.data.user;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
+
+import android.content.Context;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationApplication;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+/** JobService to collect user data in the background thread. */
+public final class UserDataCollectionJob implements JobWorker {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = UserDataCollectionJob.class.getSimpleName();
+    // 4-hour interval.
+    private static final long PERIOD_SECONDS = 14400;
+    private UserDataCollector mUserDataCollector;
+    private RawUserData mUserData;
+
+    private final Injector mInjector;
+
+    public UserDataCollectionJob() {
+        mInjector = new Injector();
+    }
+
+    @VisibleForTesting
+    public UserDataCollectionJob(Injector injector) {
+        mInjector = injector;
+    }
+
+    static class Injector {
+        ListeningExecutorService getExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        Flags getFlags() {
+            return FlagsFactory.getFlags();
+        }
+    }
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(
+            Context context, ExecutionRuntimeParameters executionRuntimeParameters) {
+        return Futures.submit(() -> {
+            startUserDataCollectionJob(context);
+            return ExecutionResult.SUCCESS;
+        }, mInjector.getExecutor());
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (mInjector.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG + ": GlobalKillSwitch enabled, skip execution of UserDataCollectionJob.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!mInjector.getFlags().getSpeOnUserDataCollectionJobEnabled()) {
+            sLogger.d(TAG + ": user data collection is disabled; skipping and cancelling job");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (UserPrivacyStatus.getInstance().isProtectedAudienceAndMeasurementBothDisabled()) {
+            sLogger.d(TAG + ": consent revoked; "
+                    + "skipping, cancelling job, and deleting existing user data");
+            handlePrivacyControlsRevoked(OnDevicePersonalizationApplication.getAppContext());
+            return JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
+    /** Schedules a unique instance of {@link UserDataCollectionJob}. */
+    public static void schedule(Context context) {
+        // If SPE is not enabled, force to schedule the job with the old JobService.
+        if (!FlagsFactory.getFlags().getSpeOnUserDataCollectionJobEnabled()) {
+            sLogger.d("SPE is not enabled. Schedule the job with UserDataCollectionJobService.");
+
+            int resultCode =
+                    UserDataCollectionJobService.schedule(context, /* forceSchedule */ false);
+            OdpJobServiceFactory.getInstance(context)
+                    .getJobSchedulingLogger()
+                    .recordOnSchedulingLegacy(USER_DATA_COLLECTION_ID, resultCode);
+
+            return;
+        }
+
+        OdpJobScheduler.getInstance(context).schedule(context, createDefaultJobSpec());
+    }
+
+    @VisibleForTesting
+    static JobSpec createDefaultJobSpec() {
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(USER_DATA_COLLECTION_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_NONE)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(1000 * PERIOD_SECONDS))
+                        .setIsPersisted(true)
+                        .build();
+        return new JobSpec.Builder(jobPolicy).build();
+    }
+
+    private void startUserDataCollectionJob(Context context) {
+        mUserDataCollector = UserDataCollector.getInstance(context);
+        mUserData = RawUserData.getInstance();
+        mUserDataCollector.updateUserData(mUserData);
+    }
+
+    private void handlePrivacyControlsRevoked(Context context) {
+        mUserDataCollector = UserDataCollector.getInstance(context);
+        mUserData = RawUserData.getInstance();
+        mUserDataCollector.clearUserData(mUserData);
+        mUserDataCollector.clearMetadata();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobService.java b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobService.java
index 46356d72..42945d2c 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobService.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobService.java
@@ -16,10 +16,13 @@
 
 package com.android.ondevicepersonalization.services.data.user;
 
-import static android.app.job.JobScheduler.RESULT_FAILURE;
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_PERSONALIZATION_NOT_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
 import android.app.job.JobInfo;
@@ -29,6 +32,7 @@ import android.app.job.JobService;
 import android.content.ComponentName;
 import android.content.Context;
 
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.Flags;
@@ -73,11 +77,16 @@ public class UserDataCollectionJobService extends JobService {
     }
 
     /** Schedules a unique instance of UserDataCollectionJobService to be run. */
-    public static int schedule(Context context) {
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int schedule(Context context, boolean forceSchedule) {
         JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
-        if (jobScheduler.getPendingJob(USER_DATA_COLLECTION_ID) != null) {
+        if (jobScheduler == null) {
+            sLogger.e(TAG, "Failed to get job scheduler from system service.");
+            return SCHEDULING_RESULT_CODE_FAILED;
+        }
+        if (!forceSchedule && jobScheduler.getPendingJob(USER_DATA_COLLECTION_ID) != null) {
             sLogger.d(TAG + ": Job is already scheduled. Doing nothing,");
-            return RESULT_FAILURE;
+            return SCHEDULING_RESULT_CODE_SKIPPED;
         }
         ComponentName serviceComponent =
                 new ComponentName(context, UserDataCollectionJobService.class);
@@ -92,7 +101,9 @@ public class UserDataCollectionJobService extends JobService {
         // persist this job across boots
         builder.setPersisted(true);
 
-        return jobScheduler.schedule(builder.build());
+        int schedulingResult = jobScheduler.schedule(builder.build());
+        return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                : SCHEDULING_RESULT_CODE_FAILED;
     }
 
     @Override
@@ -105,6 +116,15 @@ public class UserDataCollectionJobService extends JobService {
                     params,
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON);
         }
+        // Reschedule jobs with SPE if it's enabled. Note scheduled jobs by this
+        // UserDataCollectionJobService will be cancelled for the same job ID.
+        if (mInjector.getFlags().getSpeOnUserDataCollectionJobEnabled()) {
+            sLogger.i(
+                    "SPE is enabled. Reschedule UserDataCollectionJobService with"
+                            + " UserDataCollectionJob.");
+            UserDataCollectionJob.schedule(/* context */ this);
+            return false;
+        }
         runPrivacyStatusChecksInBackground(params);
         return true;
     }
diff --git a/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java b/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
index 7b0a2266..47ed50d4 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatus.java
@@ -29,9 +29,9 @@ import static android.adservices.ondevicepersonalization.Constants.STATUS_TIMEOU
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_USER_CONTROL_CACHE_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_CONTROL_CACHE_IN_MILLIS;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.odp.module.common.Clock;
@@ -39,7 +39,7 @@ import com.android.odp.module.common.MonotonicClock;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationApplication;
 import com.android.ondevicepersonalization.services.StableFlags;
-import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
+import com.android.ondevicepersonalization.services.reset.ResetDataJob;
 import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 import com.android.ondevicepersonalization.services.util.DebugUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
@@ -251,7 +251,7 @@ public final class UserPrivacyStatus {
 
     private void handleResetIfNeeded() {
         if (isMeasurementReset() || isProtectedAudienceReset()) {
-            ResetDataJobService.schedule();
+            ResetDataJob.schedule(OnDevicePersonalizationApplication.getAppContext());
         }
     }
 
diff --git a/src/com/android/ondevicepersonalization/services/data/vendor/FileUtils.java b/src/com/android/ondevicepersonalization/services/data/vendor/FileUtils.java
index f341260c..451268c8 100644
--- a/src/com/android/ondevicepersonalization/services/data/vendor/FileUtils.java
+++ b/src/com/android/ondevicepersonalization/services/data/vendor/FileUtils.java
@@ -30,6 +30,41 @@ public class FileUtils {
     private static final String TAG = "FileUtils";
     private FileUtils() {}
 
+    /**
+     * Delete all files from the directory that match the provided {@code key}, except the version
+     * corresponding to the provided timestamp.
+     *
+     * <p>If you want to delete all files including the latest version, provide a negative value for
+     * the timestamp.
+     *
+     * @param key the key for which we want to delete corresponding files
+     * @param dir the directory in which to look for the files to delete
+     * @param latestTimeStamp the timestamp corresponding to the latest version, this will be
+     *     skipped for deletion.
+     */
+    public static void cleanUpFilesDir(String key, File dir, long latestTimeStamp) {
+        if (!dir.isDirectory()) {
+            sLogger.w(TAG + " :File is not a directory: " + dir.getName());
+            return;
+        }
+
+        for (File f : dir.listFiles()) {
+            try {
+                long timestamp = getTimeStamp(f);
+                String fKey = getKeyName(f);
+
+                boolean isLatest = latestTimeStamp > 0 && latestTimeStamp == timestamp;
+                if (fKey.equals(key) && !isLatest) {
+                    f.delete();
+                }
+            } catch (Exception e) {
+                // Delete any files that do not match expected format.
+                sLogger.w(TAG + " :Failed to parse file: " + f.getName(), e);
+                f.delete();
+            }
+        }
+    }
+
     /**
      * Deletes all files from the directory that no longer
      * exist in the given keySet or are not the most recent version.
@@ -41,21 +76,22 @@ public class FileUtils {
         if (dir.isDirectory()) {
             for (File f : dir.listFiles()) {
                 try {
-                    String[] fileNameList = f.getName().split("_");
-                    long timestamp = Long.parseLong(fileNameList[1]);
-                    String fKey = fileNameList[0];
+                    long timestamp = getTimeStamp(f);
+                    String fKey = getKeyName(f);
 
                     // Key no longer exists in DB. Mark for deletion
                     if (!keySet.contains(fKey)) {
                         filesToDelete.add(f);
                     }
 
-                    // If duplicate key, mark oldest key for deletion
+                    // If duplicate key, mark the oldest key for deletion
                     if (filesSeen.containsKey(fKey)) {
                         File existingFile = filesSeen.get(fKey);
-                        if (timestamp < Long.parseLong(existingFile.getName().split("_")[1])) {
+                        if (timestamp < getTimeStamp(existingFile)) {
+                            // This file is the other older one, mark for deletion.
                             filesToDelete.add(f);
                         } else {
+                            // The previously seen file is the older one so mark for deletion.
                             filesToDelete.add(existingFile);
                             filesSeen.put(fKey, f);
                         }
@@ -74,6 +110,16 @@ public class FileUtils {
         }
     }
 
+    private static String getKeyName(File file) {
+        String[] fileNameList = file.getName().split("_");
+        return fileNameList[0];
+    }
+
+    private static long getTimeStamp(File file) {
+        String[] fileNameList = file.getName().split("_");
+        return Long.parseLong(fileNameList[1]);
+    }
+
     /**
      * Deletes a directory and all files recursively
      */
diff --git a/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDao.java b/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDao.java
index 6ff20619..04e3d87e 100644
--- a/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDao.java
+++ b/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDao.java
@@ -243,9 +243,13 @@ public class OnDevicePersonalizationLocalDataDao {
             } else {
                 values.put(LocalDataContract.LocalDataEntry.DATA, localData.getData());
             }
-            // TODO: Cleanup file on replace instead of waiting for maintenance job.
-            return db.insertWithOnConflict(mTableName, null,
-                    values, SQLiteDatabase.CONFLICT_REPLACE) != -1;
+            if (db.insertWithOnConflict(mTableName, null, values, SQLiteDatabase.CONFLICT_REPLACE)
+                    != -1) {
+                // Insertion successful, delete any potential older versions of the file that may
+                // have been created.
+                FileUtils.cleanUpFilesDir(localData.getKey(), new File(mFileDir), timeMillis);
+                return true;
+            }
         } catch (SQLiteException | IOException e) {
             sLogger.e(TAG + ": Failed to update or insert local data", e);
             // Attempt to delete file if something failed
@@ -267,7 +271,11 @@ public class OnDevicePersonalizationLocalDataDao {
             SQLiteDatabase db = mDbHelper.getWritableDatabase();
             String whereClause = LocalDataContract.LocalDataEntry.KEY + " = ?";
             String[] selectionArgs = {key};
-            return db.delete(mTableName, whereClause, selectionArgs) == 1;
+            if (db.delete(mTableName, whereClause, selectionArgs) == 1) {
+                // Deletion was successful, delete any files associated with this key
+                FileUtils.cleanUpFilesDir(key, new File(mFileDir), /* latestTimeStamp= */ -1);
+                return true;
+            }
         } catch (SQLiteException e) {
             sLogger.e(TAG + ": Failed to delete row from local data", e);
         }
diff --git a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
index a92b5fee..d46e9ab7 100644
--- a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
+++ b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
@@ -25,7 +25,6 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.net.Uri;
 import android.os.Bundle;
-import android.util.JsonReader;
 
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
@@ -59,10 +58,7 @@ import com.google.mobiledatadownload.ClientConfigProto;
 
 import java.io.IOException;
 import java.io.InputStream;
-import java.io.InputStreamReader;
-import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
-import java.util.Base64;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
@@ -79,13 +75,12 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
     private IsolatedModelServiceProvider mModelServiceProvider;
     private long mStartServiceTimeMillis;
     private ComponentName mService;
-    private Map<String, VendorData> mProcessedVendorDataMap;
-    private long mProcessedSyncToken;
+    private ParsedFileContents mParsedFileContents;
 
     private final Injector mInjector;
     private final FutureCallback<DownloadCompletedOutputParcel> mCallback;
 
-    static class Injector {
+    private static class Injector {
         Clock getClock() {
             return MonotonicClock.getInstance();
         }
@@ -110,31 +105,18 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
 
             Uri uri = Objects.requireNonNull(getClientFileUri());
 
-            long syncToken = -1;
-            Map<String, VendorData> vendorDataMap = null;
+            ParsedFileContents fileContents;
 
             SynchronousFileStorage fileStorage = MobileDataDownloadFactory.getFileStorage(mContext);
             try (InputStream in = fileStorage.open(uri, ReadStreamOpener.create())) {
-                try (JsonReader reader = new JsonReader(new InputStreamReader(in))) {
-                    reader.beginObject();
-                    while (reader.hasNext()) {
-                        String name = reader.nextName();
-                        if (name.equals("syncToken")) {
-                            syncToken = reader.nextLong();
-                        } else if (name.equals("contents")) {
-                            vendorDataMap = readContentsArray(reader);
-                        } else {
-                            reader.skipValue();
-                        }
-                    }
-                    reader.endObject();
-                }
+                fileContents = DownloadedFileParser.parseJson(in);
             } catch (IOException ie) {
                 sLogger.e(ie, TAG + mPackageName + " Failed to process downloaded JSON file");
                 onSuccess(null);
                 return false;
             }
 
+            long syncToken = fileContents.getSyncToken();
             if (syncToken == -1 || !validateSyncToken(syncToken)) {
                 sLogger.d(TAG + mPackageName
                         + " downloaded JSON file has invalid syncToken provided");
@@ -142,6 +124,7 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
                 return false;
             }
 
+            var vendorDataMap = fileContents.getVendorDataMap();
             if (vendorDataMap == null || vendorDataMap.isEmpty()) {
                 sLogger.d(TAG + mPackageName + " downloaded JSON file has no content provided");
                 onSuccess(null);
@@ -155,13 +138,17 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
             // If existingToken is greaterThan or equal to the new token, skip as there is
             // no new data. Mark success to upstream caller for reporting purpose
             if (existingSyncToken >= syncToken) {
-                sLogger.d(TAG + ": syncToken is not newer than existing token.");
+                sLogger.d(
+                        TAG
+                                + ": new syncToken value "
+                                + syncToken
+                                + " is not newer than existing token value "
+                                + existingSyncToken);
                 onSuccess(null);
                 return false;
             }
 
-            mProcessedVendorDataMap = vendorDataMap;
-            mProcessedSyncToken = syncToken;
+            mParsedFileContents = fileContents;
 
             return true;
         } catch (Exception e) {
@@ -192,8 +179,8 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
                 new FederatedComputeServiceImpl(getService(), mContext));
 
         Map<String, byte[]> downloadedContent = new HashMap<>();
-        for (String key : mProcessedVendorDataMap.keySet()) {
-            downloadedContent.put(key, mProcessedVendorDataMap.get(key).getData());
+        for (String key : mParsedFileContents.getVendorDataMap().keySet()) {
+            downloadedContent.put(key, mParsedFileContents.getVendorDataMap().get(key).getData());
         }
 
         DataAccessServiceImpl downloadedContentBinder = new DataAccessServiceImpl(
@@ -266,14 +253,15 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
 
                             List<VendorData> filteredList = new ArrayList<>();
                             for (String key : retainedKeys) {
-                                if (mProcessedVendorDataMap.containsKey(key)) {
-                                    filteredList.add(mProcessedVendorDataMap.get(key));
+                                if (mParsedFileContents.getVendorDataMap().containsKey(key)) {
+                                    filteredList.add(
+                                            mParsedFileContents.getVendorDataMap().get(key));
                                 }
                             }
 
                             boolean transactionResult =
                                     mDao.batchUpdateOrInsertVendorDataTransaction(filteredList,
-                                            retainedKeys, mProcessedSyncToken);
+                                            retainedKeys, mParsedFileContents.getSyncToken());
 
                             sLogger.d(TAG + ": filter and store data completed, transaction"
                                     + " successful: "
@@ -316,51 +304,6 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
         mModelServiceProvider.unBindFromModelService();
     }
 
-    private Map<String, VendorData> readContentsArray(JsonReader reader) throws IOException {
-        Map<String, VendorData> vendorDataMap = new HashMap<>();
-        reader.beginArray();
-        while (reader.hasNext()) {
-            VendorData data = readContent(reader);
-            if (data != null) {
-                vendorDataMap.put(data.getKey(), data);
-            }
-        }
-        reader.endArray();
-
-        return vendorDataMap;
-    }
-
-    private VendorData readContent(JsonReader reader) throws IOException {
-        String key = null;
-        byte[] data = null;
-        String encoding = null;
-        reader.beginObject();
-        while (reader.hasNext()) {
-            String name = reader.nextName();
-            if (name.equals("key")) {
-                key = reader.nextString();
-            } else if (name.equals("data")) {
-                data = reader.nextString().getBytes(StandardCharsets.UTF_8);
-            } else if (name.equals("encoding")) {
-                encoding = reader.nextString();
-            } else {
-                reader.skipValue();
-            }
-        }
-        reader.endObject();
-        if (key == null || data == null) {
-            return null;
-        }
-        if (encoding != null && !encoding.isBlank()) {
-            if (encoding.strip().equalsIgnoreCase("base64")) {
-                data = Base64.getDecoder().decode(data);
-            } else if (!encoding.strip().equalsIgnoreCase("utf8")) {
-                return null;
-            }
-        }
-        return new VendorData.Builder().setKey(key).setData(data).build();
-    }
-
     private Uri getClientFileUri() throws Exception {
         MobileDataDownload mdd = MobileDataDownloadFactory.getMdd(mContext);
 
diff --git a/src/com/android/ondevicepersonalization/services/download/DownloadedFileParser.java b/src/com/android/ondevicepersonalization/services/download/DownloadedFileParser.java
new file mode 100644
index 00000000..712b78dd
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/download/DownloadedFileParser.java
@@ -0,0 +1,103 @@
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
+package com.android.ondevicepersonalization.services.download;
+
+import android.util.JsonReader;
+
+import com.android.ondevicepersonalization.services.data.vendor.VendorData;
+
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.InputStreamReader;
+import java.nio.charset.StandardCharsets;
+import java.util.Base64;
+import java.util.HashMap;
+import java.util.Map;
+
+/**
+ * Parses the downloaded file.
+ */
+class DownloadedFileParser {
+    public static ParsedFileContents parseJson(InputStream in) throws IOException {
+        long syncToken = -1;
+        Map<String, VendorData> vendorDataMap = null;
+
+        try (JsonReader reader = new JsonReader(new InputStreamReader(in))) {
+            reader.beginObject();
+            while (reader.hasNext()) {
+                String name = reader.nextName();
+                if (name.equals("syncToken")) {
+                    syncToken = reader.nextLong();
+                } else if (name.equals("contents")) {
+                    vendorDataMap = readContentsArray(reader);
+                } else {
+                    reader.skipValue();
+                }
+            }
+            reader.endObject();
+        }
+        return new ParsedFileContents(syncToken, vendorDataMap);
+    }
+
+    private static Map<String, VendorData> readContentsArray(JsonReader reader)
+            throws IOException {
+        Map<String, VendorData> vendorDataMap = new HashMap<>();
+        reader.beginArray();
+        while (reader.hasNext()) {
+            VendorData data = readContent(reader);
+            if (data != null) {
+                vendorDataMap.put(data.getKey(), data);
+            }
+        }
+        reader.endArray();
+
+        return vendorDataMap;
+    }
+
+    private static VendorData readContent(JsonReader reader) throws IOException {
+        String key = null;
+        byte[] data = null;
+        String encoding = null;
+        reader.beginObject();
+        while (reader.hasNext()) {
+            String name = reader.nextName();
+            if (name.equals("key")) {
+                key = reader.nextString();
+            } else if (name.equals("data")) {
+                data = reader.nextString().getBytes(StandardCharsets.UTF_8);
+            } else if (name.equals("encoding")) {
+                encoding = reader.nextString();
+            } else {
+                reader.skipValue();
+            }
+        }
+        reader.endObject();
+        if (key == null || data == null) {
+            return null;
+        }
+        if (encoding != null && !encoding.isBlank()) {
+            if (encoding.strip().equalsIgnoreCase("base64")) {
+                data = Base64.getDecoder().decode(data);
+            } else if (!encoding.strip().equalsIgnoreCase("utf8")) {
+                return null;
+            }
+        }
+        return new VendorData.Builder().setKey(key).setData(data).build();
+    }
+
+    private DownloadedFileParser() {}
+}
diff --git a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java
new file mode 100644
index 00000000..d07e8aec
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java
@@ -0,0 +1,158 @@
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
+package com.android.ondevicepersonalization.services.download;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
+
+import android.content.Context;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
+import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.android.libraries.mobiledatadownload.MobileDataDownload;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/**
+ * JobService to handle the processing of the downloaded vendor data
+ */
+public final class OnDevicePersonalizationDownloadProcessingJob implements JobWorker {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = "OnDevicePersonalizationDownloadProcessingJob";
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(Context context,
+            ExecutionRuntimeParameters executionRuntimeParameters) {
+        ListenableFuture<List<ListenableFuture<Void>>> outerFeature =
+                Futures.submit(
+                        () -> {
+                            List<ListenableFuture<Void>> innerFeatures = new ArrayList<>();
+                            // Processing installed packages
+                            for (String packageName : AppManifestConfigHelper.getOdpPackages(
+                                    context, /* enrolledOnly= */ true)) {
+                                innerFeatures.add(Futures.submitAsync(
+                                        new OnDevicePersonalizationDataProcessingAsyncCallable(
+                                                packageName, context),
+                                        OnDevicePersonalizationExecutors.getBackgroundExecutor()));
+                            }
+                            return innerFeatures;
+                        },
+                        OnDevicePersonalizationExecutors.getBackgroundExecutor());
+
+        // Handling task completion asynchronously
+        return Futures.transformAsync(
+                outerFeature,
+                innerFutures -> Futures.whenAllComplete(innerFutures).call(() -> {
+                    boolean allSuccess = true;
+                    int successTaskCount = 0;
+                    int failureTaskCount = 0;
+                    for (ListenableFuture<Void> future : innerFutures) {
+                        try {
+                            future.get();
+                            successTaskCount++;
+                        } catch (Exception e) {
+                            sLogger.e(e, TAG + ": Error processing future");
+                            failureTaskCount++;
+                            allSuccess = false;
+                        }
+                    }
+                    sLogger.d(TAG + ": all download processing tasks finished, %d succeeded,"
+                            + " %d failed", successTaskCount, failureTaskCount);
+                    // Manually trigger MDD garbage collection after finishing processing all
+                    // downloads.
+                    MobileDataDownload mdd = MobileDataDownloadFactory.getMdd(context);
+                    var unused = mdd.collectGarbage();
+
+                    return allSuccess ? ExecutionResult.SUCCESS
+                            : ExecutionResult.FAILURE_WITHOUT_RETRY;
+                }, OnDevicePersonalizationExecutors.getLightweightExecutor()),
+                OnDevicePersonalizationExecutors.getLightweightExecutor()
+        );
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG + ": GlobalKillSwitch enabled, skip execution of "
+                    + "OnDevicePersonalizationDownloadProcessingJob.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled()) {
+            sLogger.d(TAG + ": download processing is disabled; skipping and cancelling job");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
+    /** Schedules a unique instance of {@link OnDevicePersonalizationDownloadProcessingJob}. */
+    public static void schedule(Context context) {
+        // If SPE is not enabled, force to schedule the job with the old JobService.
+        if (!FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled()) {
+            sLogger.d("SPE is not enabled. Schedule the job with "
+                    + "OnDevicePersonalizationDownloadProcessingJobService.");
+
+            int resultCode = OnDevicePersonalizationDownloadProcessingJobService.schedule(
+                    context, /* forceSchedule */ false);
+            OdpJobServiceFactory.getInstance(context)
+                    .getJobSchedulingLogger()
+                    .recordOnSchedulingLegacy(DOWNLOAD_PROCESSING_TASK_JOB_ID, resultCode);
+
+            return;
+        }
+
+        OdpJobScheduler.getInstance(context).schedule(context, createDefaultJobSpec());
+    }
+
+    @VisibleForTesting
+    static JobSpec createDefaultJobSpec() {
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(DOWNLOAD_PROCESSING_TASK_JOB_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_NONE)
+                        .setIsPersisted(true)
+                        .build();
+
+        return new JobSpec.Builder(jobPolicy).build();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
index 5829083f..5c2f1fc8 100644
--- a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
+++ b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobService.java
@@ -16,9 +16,12 @@
 
 package com.android.ondevicepersonalization.services.download;
 
-import static android.app.job.JobScheduler.RESULT_FAILURE;
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 
 import android.app.job.JobInfo;
@@ -28,6 +31,7 @@ import android.app.job.JobService;
 import android.content.ComponentName;
 import android.content.Context;
 
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
@@ -54,12 +58,17 @@ public class OnDevicePersonalizationDownloadProcessingJobService extends JobServ
     /**
      * Schedules a unique instance of OnDevicePersonalizationDownloadProcessingJobService to be run.
      */
-    public static int schedule(Context context) {
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int schedule(Context context, boolean forceSchedule) {
         JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
-        if (jobScheduler.getPendingJob(
-                DOWNLOAD_PROCESSING_TASK_JOB_ID) != null) {
+        if (jobScheduler == null) {
+            sLogger.e(TAG, "Failed to get job scheduler from system service.");
+            return SCHEDULING_RESULT_CODE_FAILED;
+        }
+
+        if (!forceSchedule && jobScheduler.getPendingJob(DOWNLOAD_PROCESSING_TASK_JOB_ID) != null) {
             sLogger.d(TAG + ": Job is already scheduled. Doing nothing,");
-            return RESULT_FAILURE;
+            return SCHEDULING_RESULT_CODE_SKIPPED;
         }
         ComponentName serviceComponent = new ComponentName(context,
                 OnDevicePersonalizationDownloadProcessingJobService.class);
@@ -73,7 +82,9 @@ public class OnDevicePersonalizationDownloadProcessingJobService extends JobServ
         builder.setRequiredNetworkType(JobInfo.NETWORK_TYPE_NONE);
         builder.setPersisted(true);
 
-        return jobScheduler.schedule(builder.build());
+        int schedulingResult = jobScheduler.schedule(builder.build());
+        return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                : SCHEDULING_RESULT_CODE_FAILED;
     }
 
     @Override
@@ -89,6 +100,16 @@ public class OnDevicePersonalizationDownloadProcessingJobService extends JobServ
             return true;
         }
 
+        // Reschedule jobs with SPE if it's enabled. Note scheduled jobs by this
+        // OnDevicePersonalizationDownloadProcessingJobService will be cancelled for the same job ID
+        if (FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled()) {
+            sLogger.d(
+                    "SPE is enabled. Reschedule OnDevicePersonalizationDownloadProcessingJobService"
+                            + " with OnDevicePersonalizationDownloadProcessingJob.");
+            OnDevicePersonalizationDownloadProcessingJob.schedule(/* context */ this);
+            return false;
+        }
+
         OnDevicePersonalizationExecutors.getHighPriorityBackgroundExecutor().execute(() -> {
             mFutures = new ArrayList<>();
             // Processing installed packages
diff --git a/src/com/android/ondevicepersonalization/services/download/ParsedFileContents.java b/src/com/android/ondevicepersonalization/services/download/ParsedFileContents.java
new file mode 100644
index 00000000..43b67f77
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/download/ParsedFileContents.java
@@ -0,0 +1,44 @@
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
+package com.android.ondevicepersonalization.services.download;
+
+import com.android.ondevicepersonalization.services.data.vendor.VendorData;
+
+import java.util.Collections;
+import java.util.Map;
+
+/**
+ * Contents of the download file.
+ */
+class ParsedFileContents {
+    private long mSyncToken;
+
+    private Map<String, VendorData> mVendorDataMap;
+
+    ParsedFileContents(long syncToken, Map<String, VendorData> vendorDataMap) {
+        mSyncToken = syncToken;
+        mVendorDataMap = (vendorDataMap == null) ? Collections.emptyMap() : vendorDataMap;
+    }
+
+    public long getSyncToken() {
+        return mSyncToken;
+    }
+
+    public Map<String, VendorData> getVendorDataMap() {
+        return mVendorDataMap;
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java b/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java
new file mode 100644
index 00000000..62d12dc7
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java
@@ -0,0 +1,124 @@
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
+package com.android.ondevicepersonalization.services.download.mdd;
+
+
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
+
+import android.content.Context;
+
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
+
+import com.google.android.libraries.mobiledatadownload.tracing.PropagatedFutures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+/**
+ * MDD JobService. This will download MDD files in background tasks.
+ */
+public final class MddJob implements JobWorker {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = "MddJob";
+
+    private final String mMddTaskTag;
+    private final Injector mInjector;
+
+    public MddJob(String mddTaskTag) {
+        mInjector = new Injector();
+        mMddTaskTag = mddTaskTag;
+    }
+
+    @VisibleForTesting
+    public MddJob(String mddTaskTag, Injector injector) {
+        mInjector = injector;
+        mMddTaskTag = mddTaskTag;
+    }
+
+    static class Injector {
+        ListeningExecutorService getBackgroundExecutor() {
+            return OnDevicePersonalizationExecutors.getBackgroundExecutor();
+        }
+
+        Flags getFlags() {
+            return FlagsFactory.getFlags();
+        }
+    }
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(
+            Context context, ExecutionRuntimeParameters executionRuntimeParameters) {
+        ListenableFuture<Void> handleTaskFuture =
+                PropagatedFutures.submitAsync(
+                        () -> MobileDataDownloadFactory.getMdd(context).handleTask(mMddTaskTag),
+                        mInjector.getBackgroundExecutor());
+
+        return PropagatedFutures.transform(handleTaskFuture, unused -> {
+            if (WIFI_CHARGING_PERIODIC_TASK.equals(mMddTaskTag)) {
+                OnDevicePersonalizationDownloadProcessingJob.schedule(context);
+            }
+            return ExecutionResult.SUCCESS;
+        }, mInjector.getBackgroundExecutor());
+    }
+
+    @Override
+    public ListenableFuture<Void> getExecutionStopFuture(
+            Context context, ExecutionRuntimeParameters executionRuntimeParameters) {
+        // Attempt to process any data downloaded before the worker was stopped.
+        return PropagatedFutures.submit(() -> {
+            if (WIFI_CHARGING_PERIODIC_TASK.equals(mMddTaskTag)) {
+                OnDevicePersonalizationDownloadProcessingJob.schedule(context);
+            }
+        },
+        mInjector.getBackgroundExecutor());
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (mInjector.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG + ": GlobalKillSwitch enabled, skip execution of MddJob.");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (!mInjector.getFlags().getSpeOnMddJobEnabled()) {
+            sLogger.d(TAG + ": mdd is disabled; skipping and cancelling job");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        if (UserPrivacyStatus.getInstance().isProtectedAudienceAndMeasurementBothDisabled()) {
+            sLogger.d(TAG + ": consent revoked; skipping, cancelling job");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MddJobService.java b/src/com/android/ondevicepersonalization/services/download/mdd/MddJobService.java
index fd169188..b300a69e 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/MddJobService.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MddJobService.java
@@ -18,14 +18,13 @@ package com.android.ondevicepersonalization.services.download.mdd;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_PERSONALIZATION_NOT_ENABLED;
-import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.MDD_TASK_TAG_KEY;
+import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.getMddTaskTag;
 
 import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
 
 import android.app.job.JobParameters;
 import android.app.job.JobScheduler;
 import android.app.job.JobService;
-import android.os.PersistableBundle;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
@@ -33,7 +32,7 @@ import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
-import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJobService;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
 import com.android.ondevicepersonalization.services.statsd.joblogging.OdpJobServiceLogger;
 
 import com.google.android.libraries.mobiledatadownload.tracing.PropagatedFutures;
@@ -49,8 +48,6 @@ public class MddJobService extends JobService {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = "MddJobService";
 
-    private String mMddTaskTag;
-
     private final Injector mInjector;
 
     public MddJobService() {
@@ -75,7 +72,7 @@ public class MddJobService extends JobService {
     @Override
     public boolean onStartJob(JobParameters params) {
         sLogger.d(TAG + ": onStartJob()");
-        OdpJobServiceLogger.getInstance(this).recordOnStartJob(getMddTaskJobId(params));
+        OdpJobServiceLogger.getInstance(this).recordOnStartJob(params.getJobId());
 
         if (mInjector.getFlags().getGlobalKillSwitch()) {
             sLogger.d(TAG + ": GlobalKillSwitch enabled, finishing job.");
@@ -83,29 +80,34 @@ public class MddJobService extends JobService {
                     AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_KILL_SWITCH_ON);
         }
 
+        // Reschedule jobs with SPE if it's enabled.
+        // Note: scheduled jobs by this MddJobService will be cancelled for the same job ID
+        if (mInjector.getFlags().getSpeOnMddJobEnabled()) {
+            sLogger.d("SPE is enabled. Reschedule MddJobService with MddJob.");
+            MddTaskScheduler.schedule(/* context */ this, params.getExtras());
+            return false;
+        }
+
         // Run privacy status checks in the background
         runPrivacyStatusChecksInBackgroundAndExecute(params);
         return true;
     }
 
     private void runPrivacyStatusChecksInBackgroundAndExecute(final JobParameters params) {
-        int jobId = getMddTaskJobId(params);
         OnDevicePersonalizationExecutors.getHighPriorityBackgroundExecutor().execute(() -> {
             if (UserPrivacyStatus.getInstance().isProtectedAudienceAndMeasurementBothDisabled()) {
                 // User control is revoked; handle this case
                 sLogger.d(TAG + ": User control is not given for all ODP services.");
                 OdpJobServiceLogger.getInstance(MddJobService.this)
-                        .recordJobSkipped(jobId,
+                        .recordJobSkipped(params.getJobId(),
                                 AD_SERVICES_BACKGROUND_JOBS_EXECUTION_REPORTED__EXECUTION_RESULT_CODE__SKIP_FOR_PERSONALIZATION_NOT_ENABLED);
                 jobFinished(params, false);
             } else {
                 // User control is given; handle the MDD task
-                mMddTaskTag = getMddTaskTag(params);
-
                 ListenableFuture<Void> handleTaskFuture =
                         PropagatedFutures.submitAsync(
                                 () -> MobileDataDownloadFactory.getMdd(this)
-                                        .handleTask(mMddTaskTag),
+                                        .handleTask(getMddTaskTag(params.getExtras())),
                                 mInjector.getBackgroundExecutor());
 
                 Futures.addCallback(
@@ -113,12 +115,12 @@ public class MddJobService extends JobService {
                         new FutureCallback<Void>() {
                             @Override
                             public void onSuccess(Void result) {
-                                handleSuccess(jobId, params);
+                                handleSuccess(params);
                             }
 
                             @Override
                             public void onFailure(Throwable t) {
-                                handleFailure(jobId, params, t);
+                                handleFailure(params, t);
                             }
                         },
                         mInjector.getBackgroundExecutor());
@@ -126,18 +128,18 @@ public class MddJobService extends JobService {
         });
     }
 
-    private void handleSuccess(int jobId, JobParameters params) {
+    private void handleSuccess(JobParameters params) {
         sLogger.d(TAG + ": MddJobService.MddHandleTask succeeded!");
-        if (WIFI_CHARGING_PERIODIC_TASK.equals(mMddTaskTag)) {
-            OnDevicePersonalizationDownloadProcessingJobService.schedule(this);
+        if (WIFI_CHARGING_PERIODIC_TASK.equals(getMddTaskTag(params.getExtras()))) {
+            OnDevicePersonalizationDownloadProcessingJob.schedule(/* context */ this);
         }
-        recordJobFinished(jobId, true);
+        recordJobFinished(params.getJobId(), true);
         jobFinished(params, false);
     }
 
-    private void handleFailure(int jobId, JobParameters params, Throwable throwable) {
-        sLogger.e(TAG + ": Failed to handle JobService: " + jobId, throwable);
-        recordJobFinished(jobId, false);
+    private void handleFailure(JobParameters params, Throwable throwable) {
+        sLogger.e(TAG + ": Failed to handle JobService: " + params.getJobId(), throwable);
+        recordJobFinished(params.getJobId(), false);
         jobFinished(params, false);
     }
 
@@ -150,19 +152,19 @@ public class MddJobService extends JobService {
     @Override
     public boolean onStopJob(JobParameters params) {
         // Attempt to process any data downloaded before the worker was stopped.
-        if (WIFI_CHARGING_PERIODIC_TASK.equals(mMddTaskTag)) {
-            OnDevicePersonalizationDownloadProcessingJobService.schedule(this);
+        if (WIFI_CHARGING_PERIODIC_TASK.equals(getMddTaskTag(params.getExtras()))) {
+            OnDevicePersonalizationDownloadProcessingJob.schedule(/* context */ this);
         }
         // Reschedule the job since it ended before finishing
         boolean wantsReschedule = true;
         OdpJobServiceLogger.getInstance(this)
-                .recordOnStopJob(params, getMddTaskJobId(params), wantsReschedule);
+                .recordOnStopJob(params, params.getJobId(), wantsReschedule);
         return wantsReschedule;
     }
 
     private boolean cancelAndFinishJob(final JobParameters params, int skipReason) {
         JobScheduler jobScheduler = this.getSystemService(JobScheduler.class);
-        int jobId = getMddTaskJobId(params);
+        int jobId = params.getJobId();
         if (jobScheduler != null) {
             jobScheduler.cancel(jobId);
         }
@@ -170,19 +172,4 @@ public class MddJobService extends JobService {
         jobFinished(params, /* wantsReschedule = */ false);
         return true;
     }
-
-    private int getMddTaskJobId(final JobParameters params) {
-        mMddTaskTag = getMddTaskTag(params);
-        return MddTaskScheduler.getMddTaskJobId(mMddTaskTag);
-    }
-
-    private String getMddTaskTag(final JobParameters params) {
-        // Get the MddTaskTag from input.
-        PersistableBundle extras = params.getExtras();
-        if (null == extras) {
-            sLogger.e(TAG + ": can't find MDD task tag");
-            throw new IllegalArgumentException("Can't find MDD Tasks Tag!");
-        }
-        return extras.getString(MDD_TASK_TAG_KEY);
-    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskScheduler.java b/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskScheduler.java
index a3b8cd3b..e658815c 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskScheduler.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskScheduler.java
@@ -16,6 +16,15 @@
 
 package com.android.ondevicepersonalization.services.download.mdd;
 
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_ANY;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
@@ -28,7 +37,15 @@ import android.content.Context;
 import android.content.SharedPreferences;
 import android.os.PersistableBundle;
 
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.proto.JobPolicy.NetworkType;
+import com.android.adservices.shared.spe.JobServiceConstants;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.internal.annotations.VisibleForTesting;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
 
 import com.google.android.libraries.mobiledatadownload.TaskScheduler;
 
@@ -38,15 +55,17 @@ import com.google.android.libraries.mobiledatadownload.TaskScheduler;
 public class MddTaskScheduler implements TaskScheduler {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private static final String TAG = MddTaskScheduler.class.getSimpleName();
-    static final String MDD_TASK_TAG_KEY = "MDD_TASK_TAG_KEY";
     private static final String MDD_TASK_SHARED_PREFS = "mdd_worker_task_periods";
     private final Context mContext;
+    static final String MDD_NETWORK_STATE_KEY = "MDD_NETWORK_STATE_KEY";
+    static final String MDD_PERIOD_SECONDS_KEY = "MDD_PERIOD_SECONDS_KEY";
+    static final String MDD_TASK_TAG_KEY = "MDD_TASK_TAG_KEY";
 
     public MddTaskScheduler(Context context) {
         this.mContext = context;
     }
 
-    static int getMddTaskJobId(String mddTag) {
+    private static int getMddTaskJobId(String mddTag) {
         switch (mddTag) {
             case MAINTENANCE_PERIODIC_TASK:
                 return MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
@@ -75,10 +94,55 @@ public class MddTaskScheduler implements TaskScheduler {
     }
 
     @Override
-    public void schedulePeriodicTask(String mddTaskTag, long periodSeconds,
+    public void schedulePeriodicTask(
+            String mddTaskTag, long periodSeconds, NetworkState networkState) {
+        schedule(mContext, mddTaskTag, periodSeconds, networkState);
+    }
+
+    /** Schedules a unique instance of {@link MddJob}. */
+    public static void schedule(Context context, PersistableBundle extras) {
+        schedule(context,
+                getMddTaskTag(extras),
+                getMddPeriodSeconds(extras),
+                getMddNetworkState(extras));
+    }
+
+    /** Schedules a unique instance of {@link MddJobService}. */
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int scheduleWithLegacy(
+            Context context, PersistableBundle extras, boolean forceSchedule) {
+        return scheduleWithLegacy(context,
+                getMddTaskTag(extras),
+                getMddPeriodSeconds(extras),
+                getMddNetworkState(extras),
+                forceSchedule);
+    }
+
+    private static void schedule(Context context, String mddTaskTag, long periodSeconds,
             NetworkState networkState) {
+        if (FlagsFactory.getFlags().getSpeOnMddJobEnabled()) {
+            OdpJobScheduler.getInstance(context).schedule(
+                    context,
+                    createJobSpec(mddTaskTag, periodSeconds, networkState));
+            return;
+        }
+
+        sLogger.d("SPE is not enabled. Schedule the job with MddJobService.");
+        int resultCode = scheduleWithLegacy(
+                context, mddTaskTag, periodSeconds, networkState, /* forceSchedule */ false);
+
+        OdpJobServiceFactory.getInstance(context)
+                .getJobSchedulingLogger()
+                .recordOnSchedulingLegacy(getMddTaskJobId(mddTaskTag), resultCode);
+    }
+
+    /** Schedules a unique instance of {@link MddJobService}. */
+    @VisibleForTesting
+    @JobServiceConstants.JobSchedulingResultCode
+    static int scheduleWithLegacy(Context context, String mddTaskTag, long periodSeconds,
+            NetworkState networkState, boolean forceSchedule) {
         SharedPreferences prefs =
-                mContext.getSharedPreferences(MDD_TASK_SHARED_PREFS, Context.MODE_PRIVATE);
+                context.getSharedPreferences(MDD_TASK_SHARED_PREFS, Context.MODE_PRIVATE);
 
         // When the period change, we will need to update the existing works.
         boolean updateCurrent = false;
@@ -89,43 +153,123 @@ public class MddTaskScheduler implements TaskScheduler {
             updateCurrent = true;
         }
 
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
+        JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
         if (jobScheduler.getPendingJob(getMddTaskJobId(mddTaskTag)) == null) {
             sLogger.d(TAG + ": MddJob %s is not scheduled, scheduling now", mddTaskTag);
-            schedulePeriodicTaskWithUpdate(jobScheduler, mddTaskTag, periodSeconds, networkState);
+            return schedulePeriodicTaskWithUpdate(
+                    context , jobScheduler, mddTaskTag, periodSeconds, networkState);
         } else if (updateCurrent) {
             sLogger.d(TAG + ": scheduling MddJob %s with frequency update", mddTaskTag);
-            schedulePeriodicTaskWithUpdate(jobScheduler, mddTaskTag, periodSeconds, networkState);
-        } else {
-            sLogger.d(TAG + ": MddJob %s already scheduled and frequency unchanged,"
-                    + " not scheduling", mddTaskTag);
+            return schedulePeriodicTaskWithUpdate(
+                    context, jobScheduler, mddTaskTag, periodSeconds, networkState);
+        } else if (forceSchedule) {
+            sLogger.d(TAG + ": force scheduling MddJob %s", mddTaskTag);
+            return schedulePeriodicTaskWithUpdate(
+                    context, jobScheduler, mddTaskTag, periodSeconds, networkState);
         }
+        sLogger.d(TAG + ": MddJob %s already scheduled and frequency unchanged,"
+                + " not scheduling", mddTaskTag);
+        return SCHEDULING_RESULT_CODE_SKIPPED;
     }
 
-    private void schedulePeriodicTaskWithUpdate(JobScheduler jobScheduler, String mddTaskTag,
-            long periodSeconds, NetworkState networkState) {
-
-        // We use Extra to pass the MDD Task Tag. This will be used in the MddJobService.
+    @JobServiceConstants.JobSchedulingResultCode
+    private static int schedulePeriodicTaskWithUpdate(Context context, JobScheduler jobScheduler,
+            String mddTaskTag, long periodSeconds, NetworkState networkState) {
+        // We use extras to pass MDD config values. They will be used in the mdd jobs.
         PersistableBundle extras = new PersistableBundle();
         extras.putString(MDD_TASK_TAG_KEY, mddTaskTag);
+        extras.putLong(MDD_PERIOD_SECONDS_KEY, periodSeconds);
+        extras.putString(MDD_NETWORK_STATE_KEY, networkState.name());
 
         final JobInfo job =
                 new JobInfo.Builder(
                         getMddTaskJobId(mddTaskTag),
-                        new ComponentName(mContext, MddJobService.class))
+                        new ComponentName(context, MddJobService.class))
                         .setRequiresDeviceIdle(true)
                         .setRequiresCharging(false)
                         .setRequiresBatteryNotLow(true)
                         .setPeriodic(1000 * periodSeconds) // JobScheduler uses Milliseconds.
+                        .setRequiresStorageNotLow(requireStorageNotLow(mddTaskTag))
                         // persist this job across boots
                         .setPersisted(true)
                         .setRequiredNetworkType(getNetworkConstraints(networkState))
                         .setExtras(extras)
                         .build();
-        jobScheduler.schedule(job);
+        int schedulingResult = jobScheduler.schedule(job);
+        return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                : SCHEDULING_RESULT_CODE_FAILED;
     }
 
-    private long getCurrentPeriodValue(SharedPreferences prefs, String mddTaskTag) {
+    @VisibleForTesting
+    static JobSpec createJobSpec(String mddTaskTag, long periodSeconds, NetworkState networkState) {
+        // We use extras to pass MDD config values. They will be used in the mdd jobs.
+        PersistableBundle extras = new PersistableBundle();
+        extras.putString(MDD_TASK_TAG_KEY, mddTaskTag);
+        extras.putLong(MDD_PERIOD_SECONDS_KEY, periodSeconds);
+        extras.putString(MDD_NETWORK_STATE_KEY, networkState.name());
+
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(getMddTaskJobId(mddTaskTag))
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(1000 * periodSeconds)
+                                        .build())
+                        .setNetworkType(getNetworkType(networkState))
+                        .setRequireStorageNotLow(requireStorageNotLow(mddTaskTag))
+                        .setIsPersisted(true)
+                        .build();
+
+        return new JobSpec.Builder(jobPolicy)
+                .setExtras(extras).build();
+    }
+
+    private static NetworkType getNetworkType(NetworkState networkState) {
+        switch (networkState) {
+            case NETWORK_STATE_ANY:
+                // Network not required.
+                return NETWORK_TYPE_NONE;
+            case NETWORK_STATE_CONNECTED:
+                // Metered or unmetered network available.
+                return NETWORK_TYPE_ANY;
+            case NETWORK_STATE_UNMETERED:
+            default:
+                return NETWORK_TYPE_UNMETERED;
+        }
+    }
+
+    static String getMddTaskTag(final PersistableBundle extras) {
+        requireNonNullExtras(extras);
+        String mddTaskTag = extras.getString(MDD_TASK_TAG_KEY);
+        if (null == mddTaskTag) {
+            throw new IllegalArgumentException("Mdd task tag not found");
+        }
+        return mddTaskTag;
+    }
+
+    private static long getMddPeriodSeconds(final PersistableBundle extras) {
+        requireNonNullExtras(extras);
+        return extras.getLong(MDD_PERIOD_SECONDS_KEY);
+    }
+
+    private static NetworkState getMddNetworkState(final PersistableBundle extras) {
+        requireNonNullExtras(extras);
+        String networkState = extras.getString(MDD_NETWORK_STATE_KEY);
+        if (networkState == null) {
+            throw new IllegalArgumentException("MDD extra network state not found");
+        }
+        return NetworkState.valueOf(networkState);
+    }
+
+    private static void requireNonNullExtras(PersistableBundle extras) {
+        if (null == extras) {
+            throw new IllegalArgumentException("MDD extras not found");
+        }
+    }
+
+    private static long getCurrentPeriodValue(SharedPreferences prefs, String mddTaskTag) {
         try {
             return prefs.getLong(mddTaskTag, 0);
         } catch (ClassCastException e) {
@@ -134,4 +278,9 @@ public class MddTaskScheduler implements TaskScheduler {
             return 0;
         }
     }
+
+    private static boolean requireStorageNotLow(String mddTaskTag) {
+        return WIFI_CHARGING_PERIODIC_TASK.equals(mddTaskTag)
+                || CELLULAR_CHARGING_PERIODIC_TASK.equals(mddTaskTag);
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileDownloader.java b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileDownloader.java
index 4328e789..f2a5a570 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileDownloader.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileDownloader.java
@@ -22,7 +22,6 @@ import android.content.Context;
 import android.content.SharedPreferences;
 import android.net.Uri;
 
-
 import androidx.annotation.NonNull;
 
 import com.android.internal.annotations.VisibleForTesting;
@@ -65,26 +64,17 @@ public class OnDevicePersonalizationFileDownloader implements FileDownloader {
 
     private static final String MDD_METADATA_SHARED_PREFERENCES = "mdd_metadata_store";
 
-    private final SynchronousFileStorage mFileStorage;
-    private final Context mContext;
-
-    private final Executor mDownloadExecutor;
-
     private final FileDownloader mOffroad2FileDownloader;
     private final FileDownloader mLocalFileDownloader;
 
     public OnDevicePersonalizationFileDownloader(
             SynchronousFileStorage fileStorage, Executor downloadExecutor,
             Context context) {
-        this.mFileStorage = fileStorage;
-        this.mDownloadExecutor = downloadExecutor;
-        this.mContext = context;
-
-        this.mOffroad2FileDownloader = getOffroad2FileDownloader(mContext, mFileStorage,
-                mDownloadExecutor);
-        this.mLocalFileDownloader = new OnDevicePersonalizationLocalFileDownloader(mFileStorage,
-                mDownloadExecutor, mContext);
-
+        this.mOffroad2FileDownloader =
+                getOffroad2FileDownloader(context, fileStorage, downloadExecutor);
+        this.mLocalFileDownloader =
+                new OnDevicePersonalizationLocalFileDownloader(
+                        fileStorage, downloadExecutor, context);
     }
 
     @NonNull
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
index 04cbf78b..44d30c82 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
@@ -126,7 +126,7 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
      */
     public static String createPackageFileGroupName(String packageName, Context context) throws
             PackageManager.NameNotFoundException {
-        return packageName + "_" + PackageUtils.getCertDigest(context, packageName);
+        return "odp" + "_" + packageName + "_" + PackageUtils.getCertDigest(context, packageName);
     }
 
     /**
diff --git a/src/com/android/ondevicepersonalization/services/federatedcompute/ContextData.java b/src/com/android/ondevicepersonalization/services/federatedcompute/ContextData.java
index 7b971283..0541c54a 100644
--- a/src/com/android/ondevicepersonalization/services/federatedcompute/ContextData.java
+++ b/src/com/android/ondevicepersonalization/services/federatedcompute/ContextData.java
@@ -25,26 +25,19 @@ import java.io.ObjectInputStream;
 import java.io.ObjectOutputStream;
 import java.io.Serializable;
 
-/**
- * ContextData object to pass to federatedcompute
- * TODO(278106108): Move this class depending on scheduling impl.
- */
-public class ContextData implements Serializable {
-    @NonNull
-    String mPackageName;
+/** ContextData object to pass to federatedcompute. */
+class ContextData implements Serializable {
+    @NonNull private final String mPackageName;
 
-    @NonNull
-    String mClassName;
+    @NonNull private final String mClassName;
 
-    public ContextData(@NonNull String packageName, @NonNull String className) {
+    ContextData(@NonNull String packageName, @NonNull String className) {
         this.mPackageName = packageName;
         this.mClassName = className;
     }
 
-    /**
-     * Converts the given ContextData into a serialized byte[]
-     */
-    public static byte[] toByteArray(ContextData contextData) throws IOException {
+    /** Converts the given ContextData into a serialized byte[] */
+    static byte[] toByteArray(ContextData contextData) throws IOException {
         try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
              ObjectOutputStream objectOutputStream = new ObjectOutputStream(
                      byteArrayOutputStream)) {
@@ -53,10 +46,8 @@ public class ContextData implements Serializable {
         }
     }
 
-    /**
-     * Converts the given serialized byte[] into a ContextData object
-     */
-    public static ContextData fromByteArray(byte[] arr) throws IOException, ClassNotFoundException {
+    /** Converts the given serialized byte[] into a ContextData object */
+    static ContextData fromByteArray(byte[] arr) throws IOException, ClassNotFoundException {
         try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(arr);
              ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
             return (ContextData) objectInputStream.readObject();
@@ -64,12 +55,12 @@ public class ContextData implements Serializable {
     }
 
     @NonNull
-    public String getPackageName() {
+    String getPackageName() {
         return mPackageName;
     }
 
     @NonNull
-    public String getClassName() {
+    String getClassName() {
         return mClassName;
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImpl.java b/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImpl.java
index 5a395baa..7ac4c0c5 100644
--- a/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImpl.java
@@ -44,12 +44,14 @@ import java.io.IOException;
 import java.util.Objects;
 
 /**
- * A class that exports methods that plugin code in the isolated process can use to schedule
+ * A class that exports methods that adopter code in the isolated process can use to schedule/cancel
  * federatedCompute jobs.
+ *
+ * <p>See {@link android.adservices.ondevicepersonalization.FederatedComputeScheduler#schedule}
  */
 public class FederatedComputeServiceImpl extends IFederatedComputeService.Stub {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
-    private static final String TAG = "FederatedComputeServiceImpl";
+    private static final String TAG = FederatedComputeServiceImpl.class.getSimpleName();
 
     @NonNull private final Context mApplicationContext;
     @NonNull private final ComponentName mCallingService;
@@ -57,8 +59,13 @@ public class FederatedComputeServiceImpl extends IFederatedComputeService.Stub {
 
     @NonNull private final FederatedComputeManager mFederatedComputeManager;
 
-    @VisibleForTesting
     public FederatedComputeServiceImpl(
+            @NonNull ComponentName service, @NonNull Context applicationContext) {
+        this(service, applicationContext, new Injector());
+    }
+
+    @VisibleForTesting
+    FederatedComputeServiceImpl(
             @NonNull ComponentName service,
             @NonNull Context applicationContext,
             @NonNull Injector injector) {
@@ -69,11 +76,6 @@ public class FederatedComputeServiceImpl extends IFederatedComputeService.Stub {
                 Objects.requireNonNull(injector.getFederatedComputeManager(mApplicationContext));
     }
 
-    public FederatedComputeServiceImpl(
-            @NonNull ComponentName service, @NonNull Context applicationContext) {
-        this(service, applicationContext, new Injector());
-    }
-
     @Override
     public void schedule(TrainingOptions trainingOptions, IFederatedComputeCallback callback) {
         mInjector.getExecutor().execute(() -> handleSchedule(trainingOptions, callback));
diff --git a/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreIterator.java b/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreIterator.java
index 62aa2eeb..d3a16a85 100644
--- a/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreIterator.java
+++ b/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreIterator.java
@@ -29,9 +29,9 @@ import java.util.List;
 import java.util.ListIterator;
 
 /** Implementation of ExampleStoreIterator for OnDevicePersonalization */
-public class OdpExampleStoreIterator implements ExampleStoreIterator {
+class OdpExampleStoreIterator implements ExampleStoreIterator {
 
-    ListIterator<TrainingExampleRecord> mExampleIterator;
+    private final ListIterator<TrainingExampleRecord> mExampleIterator;
 
     OdpExampleStoreIterator(List<TrainingExampleRecord> exampleRecordList) {
         mExampleIterator = exampleRecordList.listIterator();
@@ -49,7 +49,7 @@ public class OdpExampleStoreIterator implements ExampleStoreIterator {
             callback.onIteratorNextSuccess(result);
             return;
         }
-        callback.onIteratorNextSuccess(null);
+        callback.onIteratorNextSuccess(/* result= */ null);
     }
 
     @Override
diff --git a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
index 5202cb22..e83315c1 100644
--- a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
+++ b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
@@ -83,6 +83,11 @@ public final class OnDevicePersonalizationMaintenanceJob implements JobWorker {
         return JOB_ENABLED_STATUS_ENABLED;
     }
 
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
     /** Schedules a unique instance of {@link OnDevicePersonalizationMaintenanceJob}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
@@ -110,7 +115,6 @@ public final class OnDevicePersonalizationMaintenanceJob implements JobWorker {
                 JobPolicy.newBuilder()
                         .setJobId(MAINTENANCE_TASK_JOB_ID)
                         .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
-                        .setRequireStorageNotLow(true)
                         .setPeriodicJobParams(
                                 JobPolicy.PeriodicJobParams.newBuilder()
                                         .setPeriodicIntervalMs(PERIOD_MILLIS)
@@ -118,10 +122,7 @@ public final class OnDevicePersonalizationMaintenanceJob implements JobWorker {
                         .setIsPersisted(true)
                         .build();
 
-        BackoffPolicy backoffPolicy =
-                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
-
-        return new JobSpec.Builder(jobPolicy).setBackoffPolicy(backoffPolicy).build();
+        return new JobSpec.Builder(jobPolicy).build();
     }
 
     @VisibleForTesting
diff --git a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobService.java b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobService.java
index fa32e290..ee0080ac 100644
--- a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobService.java
+++ b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobService.java
@@ -76,7 +76,6 @@ public class OnDevicePersonalizationMaintenanceJobService extends JobService {
         // Constraints.
         builder.setRequiresDeviceIdle(true);
         builder.setRequiresBatteryNotLow(true);
-        builder.setRequiresStorageNotLow(true);
         builder.setRequiredNetworkType(JobInfo.NETWORK_TYPE_NONE);
         builder.setPeriodic(1000 * PERIOD_SECONDS); // JobScheduler uses Milliseconds.
         // persist this job across boots
@@ -94,9 +93,7 @@ public class OnDevicePersonalizationMaintenanceJobService extends JobService {
         return schedulingResult;
     }
 
-    @VisibleForTesting
-    static void deleteEventsAndQueries(
-            Context context) throws Exception {
+    private static void deleteEventsAndQueries(Context context) throws Exception {
         EventsDao eventsDao = EventsDao.getInstance(context);
         // Cleanup event and queries table.
         eventsDao.deleteEventsAndQueries(
diff --git a/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java b/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
index 57850f60..becf3dbc 100644
--- a/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
+++ b/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunner.java
@@ -16,9 +16,9 @@
 
 package com.android.ondevicepersonalization.services.process;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
 
 import android.adservices.ondevicepersonalization.Constants;
 import android.adservices.ondevicepersonalization.IsolatedServiceException;
diff --git a/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java b/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java
index 9ce154ac..d8db93bb 100644
--- a/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java
+++ b/src/com/android/ondevicepersonalization/services/process/ProcessRunnerFactory.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.process;
 
-import com.android.ondevicepersonalization.services.PhFlags;
+import com.android.ondevicepersonalization.services.FlagsConstants;
 import com.android.ondevicepersonalization.services.StableFlags;
 
 /** Creates a ProcessRunner */
@@ -26,7 +26,7 @@ public class ProcessRunnerFactory {
         static final ProcessRunner LAZY_INSTANCE = createProcessRunner();
 
         private static ProcessRunner createProcessRunner() {
-            return (boolean) StableFlags.get(PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED)
+            return (boolean) StableFlags.get(FlagsConstants.KEY_PLUGIN_PROCESS_RUNNER_ENABLED)
                     ? new PluginProcessRunner()
                     : new IsolatedServiceBindingRunner();
         }
diff --git a/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java b/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java
new file mode 100644
index 00000000..02452cf8
--- /dev/null
+++ b/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java
@@ -0,0 +1,117 @@
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
+package com.android.ondevicepersonalization.services.reset;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+
+import android.content.Context;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.framework.JobWorker;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+
+/**
+ * JobService to handle the OnDevicePersonalization maintenance
+ */
+public final class ResetDataJob implements JobWorker {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final long MILLIS = 1000;
+
+    @Override
+    public ListenableFuture<ExecutionResult> getExecutionFuture(Context context,
+            ExecutionRuntimeParameters executionRuntimeParameters) {
+        return Futures.submit(
+                () -> {
+                    deleteMeasurementData();
+                    return ExecutionResult.SUCCESS;
+                },
+                OnDevicePersonalizationExecutors.getBackgroundExecutor());
+    }
+
+    @Override
+    public int getJobEnablementStatus() {
+        if (!FlagsFactory.getFlags().getSpeOnResetDataJobEnabled()) {
+            sLogger.d("ResetDataJob is disabled; skipping and cancelling job");
+            return JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+        }
+        return JOB_ENABLED_STATUS_ENABLED;
+    }
+
+    /** Schedules a unique instance of {@link ResetDataJob}. */
+    public static void schedule(Context context) {
+        // If SPE is not enabled, force to schedule the job with the old JobService.
+        if (!FlagsFactory.getFlags().getSpeOnResetDataJobEnabled()) {
+            sLogger.d("SPE is not enabled. Schedule the job with ResetDataJobService.");
+
+            int resultCode = ResetDataJobService.schedule(/* forceSchedule */ false);
+            OdpJobServiceFactory.getInstance(context)
+                    .getJobSchedulingLogger()
+                    .recordOnSchedulingLegacy(RESET_DATA_JOB_ID, resultCode);
+
+            return;
+        }
+
+        OdpJobScheduler.getInstance(context).schedule(context, createDefaultJobSpec());
+    }
+
+    @VisibleForTesting
+    static JobSpec createDefaultJobSpec() {
+        Flags flags = FlagsFactory.getFlags();
+
+        JobPolicy jobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(RESET_DATA_JOB_ID)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setOneOffJobParams(
+                                JobPolicy.OneOffJobParams.newBuilder()
+                                        .setMinimumLatencyMs(
+                                                flags.getResetDataDelaySeconds() * MILLIS)
+                                        .setOverrideDeadlineMs(
+                                                flags.getResetDataDeadlineSeconds() * MILLIS)
+                                        .build())
+                        .setIsPersisted(true)
+                        .build();
+
+        return new JobSpec.Builder(jobPolicy).build();
+    }
+
+    @Override
+    public BackoffPolicy getBackoffPolicy() {
+        return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+    }
+
+    @VisibleForTesting
+    void deleteMeasurementData() {
+        ResetDataTask.deleteMeasurementData();
+    }
+}
diff --git a/src/com/android/ondevicepersonalization/services/reset/ResetDataJobService.java b/src/com/android/ondevicepersonalization/services/reset/ResetDataJobService.java
index b54cdc7c..da5ffdfb 100644
--- a/src/com/android/ondevicepersonalization/services/reset/ResetDataJobService.java
+++ b/src/com/android/ondevicepersonalization/services/reset/ResetDataJobService.java
@@ -16,8 +16,11 @@
 
 package com.android.ondevicepersonalization.services.reset;
 
-import static android.app.job.JobScheduler.RESULT_FAILURE;
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
 
 import android.app.job.JobInfo;
@@ -27,6 +30,7 @@ import android.app.job.JobService;
 import android.content.ComponentName;
 import android.content.Context;
 
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
@@ -48,13 +52,19 @@ public class ResetDataJobService extends JobService {
     private ListenableFuture<Void> mFuture;
 
     /** Schedule the Reset job. */
-    public static int schedule() {
+    @JobServiceConstants.JobSchedulingResultCode
+    public static int schedule(boolean forceSchedule) {
         Flags flags = FlagsFactory.getFlags();
         Context context = OnDevicePersonalizationApplication.getAppContext();
         JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
-        if (jobScheduler.getPendingJob(RESET_DATA_JOB_ID) != null) {
+        if (jobScheduler == null) {
+            sLogger.e(TAG, "Failed to get job scheduler from system service.");
+            return SCHEDULING_RESULT_CODE_FAILED;
+        }
+
+        if (!forceSchedule && jobScheduler.getPendingJob(RESET_DATA_JOB_ID) != null) {
             sLogger.d(TAG + ": Job is already scheduled. Doing nothing,");
-            return RESULT_FAILURE;
+            return SCHEDULING_RESULT_CODE_SKIPPED;
         }
 
         ComponentName service = new ComponentName(context, ResetDataJobService.class);
@@ -65,7 +75,9 @@ public class ResetDataJobService extends JobService {
                 .setPersisted(true)
                 .build();
 
-        return jobScheduler.schedule(jobInfo);
+        int schedulingResult = jobScheduler.schedule(jobInfo);
+        return RESULT_SUCCESS == schedulingResult ? SCHEDULING_RESULT_CODE_SUCCESSFUL
+                : SCHEDULING_RESULT_CODE_FAILED;
     }
 
     @Override
@@ -74,6 +86,15 @@ public class ResetDataJobService extends JobService {
         OdpJobServiceLogger.getInstance(this).recordOnStartJob(
                 RESET_DATA_JOB_ID);
 
+        // Reschedule jobs with SPE if it's enabled. Note scheduled jobs by this
+        // ResetDataJobService will be cancelled for the same job ID.
+        if (FlagsFactory.getFlags().getSpeOnResetDataJobEnabled()) {
+            sLogger.d(
+                    "SPE is enabled. Reschedule ResetDataJobService with ResetDataJob.");
+            ResetDataJob.schedule(/* context */ this);
+            return false;
+        }
+
         mFuture = Futures.submit(new Runnable() {
             @Override
             public void run() {
diff --git a/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobService.java b/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobService.java
index e6ac3a06..967bf511 100644
--- a/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobService.java
+++ b/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobService.java
@@ -16,7 +16,15 @@
 
 package com.android.ondevicepersonalization.services.sharedlibrary.spe;
 
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
 import android.app.job.JobParameters;
 
@@ -52,7 +60,7 @@ public final class OdpJobService extends AbstractJobService {
                     jobId);
 
             OdpJobServiceFactory factory = (OdpJobServiceFactory) getJobServiceFactory();
-            factory.rescheduleJobWithLegacyMethod(this, jobId);
+            factory.rescheduleJobWithLegacyMethod(this, jobId, params.getExtras());
 
             return false;
         }
@@ -69,10 +77,24 @@ public final class OdpJobService extends AbstractJobService {
     boolean shouldRescheduleWithLegacyMethod(int jobId) {
         Flags flags = FlagsFactory.getFlags();
 
-        if (jobId == MAINTENANCE_TASK_JOB_ID && !flags.getSpePilotJobEnabled()) {
-            return true;
+        switch (jobId) {
+            case AGGREGATE_ERROR_DATA_REPORTING_JOB_ID:
+                return !flags.getSpeOnAggregateErrorDataReportingJobEnabled();
+            case DOWNLOAD_PROCESSING_TASK_JOB_ID:
+                return !flags.getSpeOnOdpDownloadProcessingJobEnabled();
+            case MAINTENANCE_TASK_JOB_ID:
+                return !flags.getSpePilotJobEnabled();
+            case MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID:
+            case MDD_CHARGING_PERIODIC_TASK_JOB_ID:
+            case MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID:
+            case MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID:
+                return !flags.getSpeOnMddJobEnabled();
+            case RESET_DATA_JOB_ID:
+                return !flags.getSpeOnResetDataJobEnabled();
+            case USER_DATA_COLLECTION_ID:
+                return !flags.getSpeOnUserDataCollectionJobEnabled();
+            default:
+                return false;
         }
-
-        return false;
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactory.java b/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactory.java
index 7540877d..adea5838 100644
--- a/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactory.java
+++ b/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactory.java
@@ -16,10 +16,24 @@
 
 package com.android.ondevicepersonalization.services.sharedlibrary.spe;
 
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.JOB_ID_TO_NAME_MAP;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
+
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CELLULAR_CHARGING_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CHARGING_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.MAINTENANCE_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
 
 import android.content.Context;
+import android.os.PersistableBundle;
 
 import com.android.adservices.shared.proto.ModuleJobPolicy;
 import com.android.adservices.shared.spe.framework.JobServiceFactory;
@@ -33,8 +47,18 @@ import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingJob;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingService;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJob;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJobService;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJobService;
+import com.android.ondevicepersonalization.services.download.mdd.MddJob;
+import com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJobService;
+import com.android.ondevicepersonalization.services.reset.ResetDataJob;
+import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
 import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 import com.android.ondevicepersonalization.services.statsd.joblogging.OdpJobServiceLogger;
 import com.android.ondevicepersonalization.services.statsd.joblogging.OdpStatsdJobServiceLogger;
@@ -131,8 +155,24 @@ public final class OdpJobServiceFactory implements JobServiceFactory {
     public JobWorker getJobWorkerInstance(int jobId) {
         try {
             switch (jobId) {
+                case AGGREGATE_ERROR_DATA_REPORTING_JOB_ID:
+                    return new AggregateErrorDataReportingJob();
+                case DOWNLOAD_PROCESSING_TASK_JOB_ID:
+                    return new OnDevicePersonalizationDownloadProcessingJob();
                 case MAINTENANCE_TASK_JOB_ID:
                     return new OnDevicePersonalizationMaintenanceJob();
+                case MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID:
+                    return new MddJob(CELLULAR_CHARGING_PERIODIC_TASK);
+                case MDD_CHARGING_PERIODIC_TASK_JOB_ID:
+                    return new MddJob(CHARGING_PERIODIC_TASK);
+                case MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID:
+                    return new MddJob(MAINTENANCE_PERIODIC_TASK);
+                case MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID:
+                    return new MddJob(WIFI_CHARGING_PERIODIC_TASK);
+                case RESET_DATA_JOB_ID:
+                    return new ResetDataJob();
+                case USER_DATA_COLLECTION_ID:
+                    return new UserDataCollectionJob();
                 default:
                     throw new RuntimeException(
                             "The job is not configured for the instance creation.");
@@ -166,8 +206,11 @@ public final class OdpJobServiceFactory implements JobServiceFactory {
      * SPE framework).
      *
      * @param jobId the unique job ID for the background job to reschedule.
+     * @param extras holds the extras which were passed when constructing the job in case of any,
+     *               this is optional for most jobs.
      */
-    public void rescheduleJobWithLegacyMethod(Context context, int jobId) {
+    public void rescheduleJobWithLegacyMethod(
+            Context context, int jobId, PersistableBundle extras) {
         // The legacy job generally only checks some constraints of the job, instead of the entire
         // JobInfo including service name as SPE. Therefore, it needs to force-schedule the job
         // because the constraint should remain the same for legacy job and SPE.
@@ -175,9 +218,28 @@ public final class OdpJobServiceFactory implements JobServiceFactory {
 
         try {
             switch (jobId) {
+                case AGGREGATE_ERROR_DATA_REPORTING_JOB_ID:
+                    AggregateErrorDataReportingService.scheduleIfNeeded(context, forceSchedule);
+                    return;
+                case DOWNLOAD_PROCESSING_TASK_JOB_ID:
+                    OnDevicePersonalizationDownloadProcessingJobService
+                            .schedule(context, forceSchedule);
+                    return;
                 case MAINTENANCE_TASK_JOB_ID:
                     OnDevicePersonalizationMaintenanceJobService.schedule(context, forceSchedule);
                     return;
+                case MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID:
+                case MDD_CHARGING_PERIODIC_TASK_JOB_ID:
+                case MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID:
+                case MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID:
+                    MddTaskScheduler.scheduleWithLegacy(context, extras, forceSchedule);
+                    return;
+                case RESET_DATA_JOB_ID:
+                    ResetDataJobService.schedule(forceSchedule);
+                    return;
+                case USER_DATA_COLLECTION_ID:
+                    UserDataCollectionJobService.schedule(context, forceSchedule);
+                    return;
                 default:
                     throw new RuntimeException(
                             "The job isn't configured for jobWorker creation. Requested Job ID: "
diff --git a/src/proguard.flags b/src/proguard.flags
index 1744366d..9f21a444 100644
--- a/src/proguard.flags
+++ b/src/proguard.flags
@@ -1,4 +1,7 @@
--keep class com.android.ondevicepersonalization.services.process.OnDevicePersonalizationPlugin
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.ondevicepersonalization.services.process.OnDevicePersonalizationPlugin {
+    void <init>();
+}
 
 -keep class org.apache.velocity.runtime.** {
     <init>(...);
@@ -7,14 +10,3 @@
 -keep class org.apache.velocity.util.introspection.** {
     <init>(...);
 }
-
-# Stop proguard from stripping away code used by tensorflow JNI library.
--keepclassmembers class org.tensorflow.lite.NativeInterpreterWrapper {
-    private long inferenceDurationNanoseconds;
-}
-
--keep class org.tensorflow.lite.annotations.UsedByReflection
--keep @org.tensorflow.lite.annotations.UsedByReflection class *
--keepclassmembers class * {
-    @org.tensorflow.lite.annotations.UsedByReflection *;
-}
diff --git a/tests/commontests/Android.bp b/tests/commontests/Android.bp
index ab9ff95c..1109dc35 100644
--- a/tests/commontests/Android.bp
+++ b/tests/commontests/Android.bp
@@ -45,6 +45,8 @@ android_test {
         "modules-utils-build",
         "modules-utils-preconditions",
         "libprotobuf-java-lite",
+        "common-ondevicepersonalization-protos",
+        "adservices-shared-datastore", // For proto data store.
     ],
     manifest: "AndroidManifest.xml",
     plugins: ["auto_value_plugin"],
diff --git a/tests/commontests/src/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStoreTest.java b/tests/commontests/src/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStoreTest.java
new file mode 100644
index 00000000..abe9dceb
--- /dev/null
+++ b/tests/commontests/src/com/android/odp/module/common/data/ErrorReportingMetadataProtoDataStoreTest.java
@@ -0,0 +1,95 @@
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
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertTrue;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.odp.module.common.proto.ErrorReportingMetadata;
+
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+import com.google.protobuf.Timestamp;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.concurrent.TimeUnit;
+
+@RunWith(AndroidJUnit4.class)
+public class ErrorReportingMetadataProtoDataStoreTest {
+
+    private static final Context sTestContext = ApplicationProvider.getApplicationContext();
+    private static final ListeningExecutorService sTestExecutor =
+            MoreExecutors.newDirectExecutorService();
+
+    private static final long TEST_EPOCH_SECONDS = 1733795133L;
+
+    private static final int TIMEOUT_SEC = 5;
+    private static final Timestamp TEST_TIMESTAMP =
+            Timestamp.newBuilder().setSeconds(TEST_EPOCH_SECONDS).build();
+
+    private ErrorReportingMetadataStore mInstanceUnderTest = null;
+
+    @Test
+    public void getInstance_returnsSingletonInstance() {
+        mInstanceUnderTest =
+                ErrorReportingMetadataProtoDataStore.getInstance(sTestContext, sTestExecutor);
+
+        assertThat(mInstanceUnderTest)
+                .isSameInstanceAs(
+                        ErrorReportingMetadataProtoDataStore.getInstance(
+                                sTestContext, sTestExecutor));
+    }
+
+    @Test
+    public void setAndGet_successful() throws Exception {
+        mInstanceUnderTest =
+                ErrorReportingMetadataProtoDataStore.getInstance(sTestContext, sTestExecutor);
+        ErrorReportingMetadata testMetadata =
+                ErrorReportingMetadataProtoDataStore.getMetadata(TEST_EPOCH_SECONDS);
+
+        ErrorReportingMetadata returnedSetData = wait(mInstanceUnderTest.set(testMetadata));
+        ErrorReportingMetadata returnedGetData = wait(mInstanceUnderTest.get());
+
+        assertThat(returnedSetData.getLastSuccessfulUpload()).isEqualTo(TEST_TIMESTAMP);
+        assertThat(returnedGetData.getLastSuccessfulUpload()).isEqualTo(TEST_TIMESTAMP);
+    }
+
+    @Test
+    public void getWithoutSet_returnsDefaultInstance() throws Exception {
+        mInstanceUnderTest =
+                ErrorReportingMetadataProtoDataStore.getInstance(sTestContext, sTestExecutor);
+
+        ErrorReportingMetadata returnedData = wait(mInstanceUnderTest.get());
+
+        assertTrue(
+                ErrorReportingMetadataProtoDataStore.isErrorReportingMetadataUninitialized(
+                        returnedData));
+    }
+
+    private static <T> T wait(ListenableFuture<T> future) throws Exception {
+        return future.get(TIMEOUT_SEC, TimeUnit.SECONDS);
+    }
+}
diff --git a/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java b/tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenDaoTest.java
similarity index 82%
rename from tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java
rename to tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenDaoTest.java
index e14102fb..cd3b79f1 100644
--- a/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenDaoTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenDaoTest.java
@@ -38,7 +38,7 @@ import org.junit.runner.RunWith;
 import java.util.UUID;
 
 @RunWith(AndroidJUnit4.class)
-public class ODPAuthorizationTokenDaoTest {
+public class OdpAuthorizationTokenDaoTest {
 
     private static final Context sTestContext = ApplicationProvider.getApplicationContext();
     private static final OdpEncryptionKeyDaoTest.TestDbHelper sTestDbHelper =
@@ -56,11 +56,11 @@ public class ODPAuthorizationTokenDaoTest {
 
     private static final long ONE_HOUR = 60 * 60 * 60 * 1000L;
 
-    private ODPAuthorizationTokenDao mDaoUnderTest;
+    private OdpAuthorizationTokenDao mDaoUnderTest;
 
     @Before
     public void setUp() {
-        mDaoUnderTest = ODPAuthorizationTokenDao.getInstanceForTest(sTestDbHelper);
+        mDaoUnderTest = OdpAuthorizationTokenDao.getInstanceForTest(sTestDbHelper);
     }
 
     @After
@@ -75,33 +75,33 @@ public class ODPAuthorizationTokenDaoTest {
         SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                db, OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(0);
-        ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
-        ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
+        OdpAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
+        OdpAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
 
         mDaoUnderTest.insertAuthorizationToken(authToken1);
         mDaoUnderTest.insertAuthorizationToken(authToken2);
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                db, OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(2);
     }
 
     @Test
     public void testInsertAuthToken_preExist_success() {
         SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
-        ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
-        ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER1, TOKEN2, ONE_HOUR);
+        OdpAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
+        OdpAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER1, TOKEN2, ONE_HOUR);
 
         mDaoUnderTest.insertAuthorizationToken(authToken1);
         mDaoUnderTest.insertAuthorizationToken(authToken2);
-        ODPAuthorizationToken storedToken =
+        OdpAuthorizationToken storedToken =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
 
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                db, OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(1);
         assertThat(storedToken).isEqualTo(authToken2);
     }
@@ -112,8 +112,8 @@ public class ODPAuthorizationTokenDaoTest {
     }
 
     private void insertNullAuthToken() {
-        ODPAuthorizationToken authToken =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken authToken =
+                new OdpAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER1)
                         .setCreationTime(mClock.currentTimeMillis())
                         .setExpiryTime(mClock.currentTimeMillis() + ONE_HOUR)
@@ -123,21 +123,21 @@ public class ODPAuthorizationTokenDaoTest {
 
     @Test
     public void testGetAuthToken_notExist_returnsNullToken() {
-        ODPAuthorizationToken authToken =
+        OdpAuthorizationToken authToken =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
         assertThat(authToken).isEqualTo(null);
     }
 
     @Test
     public void testGetAuthToken_exist_success() {
-        ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
-        ODPAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
+        OdpAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
+        OdpAuthorizationToken authToken2 = createAuthToken(OWNER_IDENTIFIER2, TOKEN2, ONE_HOUR);
         mDaoUnderTest.insertAuthorizationToken(authToken1);
         mDaoUnderTest.insertAuthorizationToken(authToken2);
 
-        ODPAuthorizationToken storedToken1 =
+        OdpAuthorizationToken storedToken1 =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
-        ODPAuthorizationToken storedToken2 =
+        OdpAuthorizationToken storedToken2 =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
 
         assertThat(storedToken1).isEqualTo(authToken1);
@@ -146,16 +146,16 @@ public class ODPAuthorizationTokenDaoTest {
 
     @Test
     public void testGetAuthToken_expired_returnsNullToken() {
-        ODPAuthorizationToken authToken1 =
+        OdpAuthorizationToken authToken1 =
                 createAuthToken(OWNER_IDENTIFIER1, TOKEN1, /* ttl= */ 0L);
-        ODPAuthorizationToken authToken2 =
+        OdpAuthorizationToken authToken2 =
                 createAuthToken(OWNER_IDENTIFIER2, TOKEN2, /* ttl= */ 0L);
         mDaoUnderTest.insertAuthorizationToken(authToken1);
         mDaoUnderTest.insertAuthorizationToken(authToken2);
 
-        ODPAuthorizationToken storedToken1 =
+        OdpAuthorizationToken storedToken1 =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER1);
-        ODPAuthorizationToken storedToken2 =
+        OdpAuthorizationToken storedToken2 =
                 mDaoUnderTest.getUnexpiredAuthorizationToken(OWNER_IDENTIFIER2);
 
         assertThat(storedToken1).isEqualTo(null);
@@ -165,14 +165,14 @@ public class ODPAuthorizationTokenDaoTest {
     @Test
     public void testDeleteAuthToken_exist_success() {
         SQLiteDatabase db = sTestDbHelper.getReadableDatabase();
-        ODPAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
+        OdpAuthorizationToken authToken1 = createAuthToken(OWNER_IDENTIFIER1, TOKEN1, ONE_HOUR);
         mDaoUnderTest.insertAuthorizationToken(authToken1);
 
         int deletedRows = mDaoUnderTest.deleteAuthorizationToken(OWNER_IDENTIFIER1);
 
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                db, OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(0);
         assertThat(deletedRows).isEqualTo(1);
     }
@@ -204,8 +204,8 @@ public class ODPAuthorizationTokenDaoTest {
         assertThat(rowsDeleted).isEqualTo(2);
     }
 
-    private ODPAuthorizationToken createAuthToken(String owner, String token, Long ttl) {
+    private OdpAuthorizationToken createAuthToken(String owner, String token, Long ttl) {
         long now = mClock.currentTimeMillis();
-        return new ODPAuthorizationToken.Builder(owner, token, now, now + ttl).build();
+        return new OdpAuthorizationToken.Builder(owner, token, now, now + ttl).build();
     }
 }
diff --git a/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java b/tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenTest.java
similarity index 86%
rename from tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java
rename to tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenTest.java
index 60a1c6b7..97c61c45 100644
--- a/tests/commontests/src/com/android/odp/module/common/data/ODPAuthorizationTokenTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/OdpAuthorizationTokenTest.java
@@ -26,7 +26,7 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 @RunWith(AndroidJUnit4.class)
-public class ODPAuthorizationTokenTest {
+public class OdpAuthorizationTokenTest {
     private static final String TOKEN = "b3c4dc4a-768b-415d-8adb-d3aa2206b7bb";
 
     private static final String OWNER_IDENTIFIER = "atp1";
@@ -39,15 +39,15 @@ public class ODPAuthorizationTokenTest {
 
     @Test
     public void testBuilderAndEquals() {
-        ODPAuthorizationToken token1 =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken token1 =
+                new OdpAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER)
                         .setAuthorizationToken(TOKEN)
                         .setCreationTime(NOW)
                         .setExpiryTime(NOW + ONE_HOUR)
                         .build();
-        ODPAuthorizationToken token2 =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken token2 =
+                new OdpAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER)
                         .setAuthorizationToken(TOKEN)
                         .setCreationTime(NOW)
@@ -56,8 +56,8 @@ public class ODPAuthorizationTokenTest {
 
         assertEquals(token1, token2);
 
-        ODPAuthorizationToken token3 =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken token3 =
+                new OdpAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER2)
                         .setAuthorizationToken(TOKEN)
                         .setCreationTime(NOW)
@@ -70,8 +70,8 @@ public class ODPAuthorizationTokenTest {
 
     @Test
     public void testBuildTwiceThrows() {
-        ODPAuthorizationToken.Builder builder =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken.Builder builder =
+                new OdpAuthorizationToken.Builder()
                         .setOwnerIdentifier(OWNER_IDENTIFIER)
                         .setAuthorizationToken(TOKEN)
                         .setCreationTime(NOW)
diff --git a/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java b/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
index 36d94723..29350b51 100644
--- a/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/data/OdpEncryptionKeyDaoTest.java
@@ -276,7 +276,7 @@ public class OdpEncryptionKeyDaoTest {
         @Override
         public void onCreate(SQLiteDatabase db) {
             db.execSQL(OdpEncryptionKeyContract.CREATE_ENCRYPTION_KEY_TABLE);
-            db.execSQL(ODPAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
+            db.execSQL(OdpAuthorizationTokenContract.CREATE_ODP_AUTHORIZATION_TOKEN_TABLE);
         }
 
         @Override
diff --git a/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
index 2bc071e3..1020f0fe 100644
--- a/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/encryption/OdpEncryptionKeyManagerTest.java
@@ -26,7 +26,7 @@ import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 
 import android.content.Context;
 
@@ -194,7 +194,7 @@ public class OdpEncryptionKeyManagerTest {
                 KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
                 Optional.of(mMockTrainingEventLogger)).get();
 
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
         assertThat(keys.size()).isGreaterThan(0);
     }
 
@@ -214,7 +214,7 @@ public class OdpEncryptionKeyManagerTest {
                 KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
                 Optional.of(mMockTrainingEventLogger)).get();
 
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
         assertThat(keys.size()).isGreaterThan(0);
     }
 
@@ -282,7 +282,7 @@ public class OdpEncryptionKeyManagerTest {
                                         /* isScheduledJob= */ true,
                                         Optional.of(mMockTrainingEventLogger))
                                 .get());
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
     }
 
     @Test
@@ -304,7 +304,7 @@ public class OdpEncryptionKeyManagerTest {
                                         /* isScheduledJob= */ false,
                                         Optional.of(mMockTrainingEventLogger))
                                 .get());
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
     }
 
     @Test
@@ -322,7 +322,7 @@ public class OdpEncryptionKeyManagerTest {
         mOdpEncryptionKeyManager
                 .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
                         Optional.of(mMockTrainingEventLogger)).get();
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
         List<OdpEncryptionKey> keys =
                 sEncryptionKeyDao.readEncryptionKeysFromDatabase(
                         ""
@@ -357,7 +357,7 @@ public class OdpEncryptionKeyManagerTest {
         mOdpEncryptionKeyManager
                 .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
                         Optional.of(mMockTrainingEventLogger)).get();
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
 
         List<OdpEncryptionKey> keys =
                 sEncryptionKeyDao.readEncryptionKeysFromDatabase(
@@ -402,7 +402,7 @@ public class OdpEncryptionKeyManagerTest {
         mOdpEncryptionKeyManager
                 .fetchAndPersistActiveKeys(KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true,
                         Optional.of(mMockTrainingEventLogger)).get();
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
 
         List<OdpEncryptionKey> keys =
                 sEncryptionKeyDao.readEncryptionKeysFromDatabase(
@@ -442,7 +442,7 @@ public class OdpEncryptionKeyManagerTest {
         mOdpEncryptionKeyManager.fetchAndPersistActiveKeys(
                 KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ false,
                 Optional.of(mMockTrainingEventLogger)).get();
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
 
         List<OdpEncryptionKey> keys =
                 sEncryptionKeyDao.readEncryptionKeysFromDatabase(
@@ -509,7 +509,7 @@ public class OdpEncryptionKeyManagerTest {
                         KEY_TYPE_ENCRYPTION, /* keyCount= */ 2,
                         Optional.of(mMockTrainingEventLogger));
 
-        verifyZeroInteractions(mMockTrainingEventLogger);
+        verifyNoMoreInteractions(mMockTrainingEventLogger);
         verify(mMockHttpClient, never()).performRequestAsyncWithRetry(any());
         assertThat(keys.size()).isEqualTo(1);
     }
diff --git a/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java b/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
index b923c0a7..a2c88d1d 100644
--- a/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/HttpClientTest.java
@@ -19,7 +19,6 @@ package com.android.odp.module.common.http;
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertTrue;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
@@ -70,7 +69,7 @@ public final class HttpClientTest {
 
         assertEquals(DEFAULT_RETRY_LIMIT, testSupplier.mCallCount.get());
         assertThat(returnedResponse.getStatusCode()).isEqualTo(HTTP_UNAVAILABLE);
-        assertTrue(returnedResponse.getHeaders().isEmpty());
+        assertThat(returnedResponse.getHeaders()).isEmpty();
         assertThat(returnedResponse.getPayload()).isEqualTo(failureMessage.getBytes(UTF_8));
     }
 
diff --git a/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java b/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
index af0c6986..b90f1456 100644
--- a/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/HttpClientUtilsTest.java
@@ -20,7 +20,6 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.when;
@@ -170,7 +169,7 @@ public class HttpClientUtilsTest {
                         DEFAULT_GET_REQUEST, mHttpURLConnectionSupplier, false);
 
         assertThat(response.getStatusCode()).isEqualTo(503);
-        assertTrue(response.getHeaders().isEmpty());
+        assertThat(response.getHeaders()).isEmpty();
         assertThat(response.getPayload()).isEqualTo(TEST_FAILURE_MESSAGE.getBytes(UTF_8));
     }
 
diff --git a/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
index efd20278..8cd631b1 100644
--- a/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
+++ b/tests/commontests/src/com/android/odp/module/common/http/OdpHttpRequestTest.java
@@ -22,7 +22,6 @@ import static com.android.odp.module.common.http.HttpClientUtils.GZIP_ENCODING_H
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.assertTrue;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -85,7 +84,7 @@ public final class OdpHttpRequestTest {
         assertThat(request.getUri()).isEqualTo(expectedUri);
         assertThat(request.getHttpMethod()).isEqualTo(HttpClientUtils.HttpMethod.GET);
         assertThat(request.getBody()).isEqualTo(HttpClientUtils.EMPTY_BODY);
-        assertTrue(request.getExtraHeaders().isEmpty());
+        assertThat(request.getExtraHeaders()).isEmpty();
     }
 
     @Test
@@ -117,7 +116,7 @@ public final class OdpHttpRequestTest {
                         HttpClientUtils.EMPTY_BODY);
 
         assertThat(request.getUri()).isEqualTo(expectedUri);
-        assertTrue(request.getExtraHeaders().isEmpty());
+        assertThat(request.getExtraHeaders()).isEmpty();
         assertThat(request.getHttpMethod()).isEqualTo(HttpClientUtils.HttpMethod.POST);
         assertThat(request.getBody()).isEqualTo(HttpClientUtils.EMPTY_BODY);
     }
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
index 2e0ccd62..ca97f215 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
@@ -69,10 +69,11 @@ public class CtsOdpManagerTests {
             "com.android.ondevicepersonalization.testing.sampleservice";
     private static final String SERVICE_CLASS =
             "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
-    private static final int LARGE_BLOB_SIZE = 10485760;
+    private static final int LARGE_BLOB_SIZE = 30000000;
     private static final int DELAY_MILLIS = 2000;
 
     private static final String TEST_POPULATION_NAME = "criteo_app_test_task";
+    private static final String TEST_WRITE_DATA = Base64.encodeToString(new byte[] {'A'}, 0);
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
@@ -107,6 +108,10 @@ public class CtsOdpManagerTests {
                         + "output_data_allow_list "
                         + mContext.getPackageName()
                         + ";com.android.ondevicepersonalization.testing.sampleservice");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "Odp__enable_is_feature_enabled "
+                        + true);
     }
 
     @After
@@ -120,6 +125,10 @@ public class CtsOdpManagerTests {
         ShellUtils.runShellCommand(
                 "am force-stop com.google.android.ondevicepersonalization.services");
         ShellUtils.runShellCommand("am force-stop com.android.ondevicepersonalization.services");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "Odp__enable_is_feature_enabled "
+                        + "null");
     }
 
     @Test
@@ -336,8 +345,7 @@ public class CtsOdpManagerTests {
         PersistableBundle appParams = new PersistableBundle();
         appParams.putString(
                 SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RETURN_OUTPUT_DATA);
-        appParams.putString(
-                SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
         manager.execute(
                 new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
                 appParams,
@@ -493,74 +501,19 @@ public class CtsOdpManagerTests {
         assertNotNull(manager);
 
         // Write 1 byte.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        writeLocalData(manager, tableKey, /* writeLargeData= */ false);
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value matches written value.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        readExpectedLocalData(manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ false);
         Thread.sleep(DELAY_MILLIS);
 
         // Remove.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        removeLocalData(manager, tableKey);
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value was removed.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
+        checkExpectedMissingLocalData(manager, tableKey);
     }
 
     @Test
@@ -570,77 +523,20 @@ public class CtsOdpManagerTests {
                 mContext.getSystemService(OnDevicePersonalizationManager.class);
         assertNotNull(manager);
 
-        // Write 10MB.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        // Write 30MB.
+        writeLocalData(manager, tableKey, /* writeLargeData= */ true);
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value matches written value.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        readExpectedLocalData(manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ true);
         Thread.sleep(DELAY_MILLIS);
 
         // Remove.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        removeLocalData(manager, tableKey);
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value was removed.
-        {
-            var receiver = new ResultReceiver<ExecuteResult>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            manager.execute(
-                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                    appParams,
-                    Executors.newSingleThreadExecutor(),
-                    receiver);
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
+        checkExpectedMissingLocalData(manager, tableKey);
     }
 
     @Test
@@ -768,7 +664,7 @@ public class CtsOdpManagerTests {
         PersistableBundle appParams = new PersistableBundle();
         appParams.putString(
                 SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CANCEL_FEDERATED_JOB);
-        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, "criteo_app_test_task");
+        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
         manager.execute(
                 new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
                 appParams,
@@ -1168,93 +1064,23 @@ public class CtsOdpManagerTests {
         assertNotNull(manager);
 
         // Write 1 byte.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        writeLocalDataNewExecuteApi(manager, tableKey, /* writeLargeData= */ false);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value matches written value.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ false);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
         // Remove.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        removeLocalDataNewExecuteApi(manager, tableKey);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value was removed.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
+        checkExpectedMissingLocalDataNewExecuteApi(manager, tableKey);
     }
 
     @Test
@@ -1266,96 +1092,23 @@ public class CtsOdpManagerTests {
                 mContext.getSystemService(OnDevicePersonalizationManager.class);
         assertNotNull(manager);
 
-        // Write 10MB.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        // Write 30MB.
+        writeLocalDataNewExecuteApi(manager, tableKey, /* writeLargeData= */ true);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
         // Read and check whether value matches written value.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            appParams.putString(
-                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(new byte[] {'A'}, 0));
-            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ true);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
         // Remove.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
-
+        removeLocalDataNewExecuteApi(manager, tableKey);
         // Add delay between writing and read from db to reduce flakiness.
         Thread.sleep(DELAY_MILLIS);
 
-        // Read and check whether value was removed.
-        {
-            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-            PersistableBundle appParams = new PersistableBundle();
-            appParams.putString(
-                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
-            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
-            ExecuteInIsolatedServiceRequest request =
-                    new ExecuteInIsolatedServiceRequest.Builder(
-                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                            .setAppParams(appParams)
-                            .build();
-
-            manager.executeInIsolatedService(
-                    request, Executors.newSingleThreadExecutor(), receiver);
-
-            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-        }
+        checkExpectedMissingLocalDataNewExecuteApi(manager, tableKey);
     }
 
     @Test
@@ -1478,7 +1231,7 @@ public class CtsOdpManagerTests {
         PersistableBundle appParams = new PersistableBundle();
         appParams.putString(
                 SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CANCEL_FEDERATED_JOB);
-        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, "criteo_app_test_task");
+        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
         ExecuteInIsolatedServiceRequest request =
                 new ExecuteInIsolatedServiceRequest.Builder(
                                 new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
@@ -1489,6 +1242,91 @@ public class CtsOdpManagerTests {
         assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public void testQueryFeatureAvailableApi() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        manager.queryFeatureAvailability("featureName",
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public void testQueryFeatureAvailableApiThrowsIfFeatureNameMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability(null,
+                                Executors.newSingleThreadExecutor(),
+                                receiver));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public void testQueryFeatureAvailableApiThrowsIfExecutorMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability("featureName",
+                                null,
+                                receiver));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_EXECUTE_IN_ISOLATED_SERVICE_API_ENABLED)
+    public void testExecuteNoOutputData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RETURN_OUTPUT_DATA);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        assertThat(receiver.getResult().getOutputData()).isNull();
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_IS_FEATURE_ENABLED_API_ENABLED)
+    public void testQueryFeatureAvailableApiThrowsIfReceiverMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability("featureName",
+                                Executors.newSingleThreadExecutor(),
+                                null));
+    }
+
     private static PersistableBundle getScheduleFCJobParams(boolean useLegacyApi) {
         PersistableBundle appParams = new PersistableBundle();
         appParams.putString(
@@ -1499,4 +1337,200 @@ public class CtsOdpManagerTests {
         appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
         return appParams;
     }
+
+    /**
+     * Sends a request to the sample service to write to local data using {@code TEST_WRITE_DATA}. *
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void writeLocalData(
+            OnDevicePersonalizationManager manager, String tableKey, boolean writeLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        if (writeLargeData) {
+            // Set repeat count to inform sample service to write a large blob of data.
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to write to local data using {@code TEST_WRITE_DATA}
+     *
+     * <p>Uses the new {@code executeInIsolatedService} API.
+     */
+    private static void writeLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey, boolean writeLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        if (writeLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key does not exist in local
+     * data.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void checkExpectedMissingLocalData(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        // Check to ensure that the given key is missing in the local data
+        readExpectedLocalData(
+                manager, tableKey, /* expectedDataValue= */ "", /* expectLargeData= */ false);
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key does not exist in local
+     * data.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void checkExpectedMissingLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, /* expectedDataValue= */ "", /* expectLargeData= */ false);
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key has a matching value in
+     * the local data table.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void readExpectedLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager,
+            String tableKey,
+            String expectedDataValue,
+            boolean expectLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        if (!expectedDataValue.isEmpty()) {
+            // If expected data value is empty, and we do not include it in the bundle to the
+            // SampleService, it will check to ensure that the key does not exist in local data.
+            appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, expectedDataValue);
+        }
+
+        if (expectLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key has a matching value in
+     * the local data table.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void readExpectedLocalData(
+            OnDevicePersonalizationManager manager,
+            String tableKey,
+            String expectedDataValue,
+            boolean expectLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        if (!expectedDataValue.isEmpty()) {
+            appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, expectedDataValue);
+        }
+
+        if (expectLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to remove the given key from the local data table.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void removeLocalData(OnDevicePersonalizationManager manager, String tableKey)
+            throws InterruptedException {
+        // Remove local data associated with the given tableKey and assert that the execute
+        // call is successful. Uses the legacy execute API.
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to remove the given key from the local data table.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void removeLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        // Remove local data associated with the given tableKey and assert that the execute
+        // call is successful. Uses the new execute API.
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
 }
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
index 93ab78af..b79adf87 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/DataClassesTest.java
@@ -35,6 +35,7 @@ import android.adservices.ondevicepersonalization.FederatedComputeScheduleRespon
 import android.adservices.ondevicepersonalization.FederatedComputeScheduler;
 import android.adservices.ondevicepersonalization.IsolatedServiceException;
 import android.adservices.ondevicepersonalization.MeasurementWebTriggerEventParams;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationException;
 import android.adservices.ondevicepersonalization.RenderOutput;
 import android.adservices.ondevicepersonalization.RenderingConfig;
 import android.adservices.ondevicepersonalization.RequestLogRecord;
@@ -476,4 +477,27 @@ public class DataClassesTest {
         assertThat(data.getOutputData()).isNull();
         assertThat(data.getBestValue()).isEqualTo(100);
     }
-}
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_UNHIDDEN_ON_DEVICE_PERSONALIZATION_EXCEPTION_ENABLED)
+    public void testOnDevicePersonalizationException() {
+        OnDevicePersonalizationException odpException1 = new OnDevicePersonalizationException(1);
+        assertEquals(1, odpException1.getErrorCode());
+
+        OnDevicePersonalizationException odpException2 =
+                new OnDevicePersonalizationException(2, "odpException");
+        assertEquals(2, odpException2.getErrorCode());
+        assertEquals("odpException", odpException2.getMessage());
+
+        OnDevicePersonalizationException odpException3 =
+                new OnDevicePersonalizationException(3, new Throwable("exception"));
+        assertEquals(3, odpException3.getErrorCode());
+        assertEquals("exception", odpException3.getCause().getMessage());
+
+        OnDevicePersonalizationException odpException4 =
+                new OnDevicePersonalizationException(4, "odpException", new Throwable("exception"));
+        assertEquals(4, odpException4.getErrorCode());
+        assertEquals("odpException", odpException4.getMessage());
+        assertEquals("exception", odpException4.getCause().getMessage());
+    }
+}
\ No newline at end of file
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
index a8c846f6..4f877dc2 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceInputTest.java
@@ -16,6 +16,8 @@
 
 package com.android.ondevicepersonalization.cts.e2e;
 
+import static com.android.ondevicepersonalization.cts.e2e.TestUtils.serializeFloatArray;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static junit.framework.Assert.assertEquals;
@@ -28,7 +30,9 @@ import android.adservices.ondevicepersonalization.RemoteDataImpl;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessService;
 import android.adservices.ondevicepersonalization.aidl.IDataAccessServiceCallback;
 import android.os.Bundle;
+import android.platform.test.annotations.RequiresFlagsEnabled;
 
+import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
 import org.junit.Assume;
@@ -169,6 +173,41 @@ public class InferenceInputTest {
                 () -> new InferenceInput.Params.Builder(mRemoteData, null).build());
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+    public void buildInferenceInput_ctorInputBytes_success() {
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY)
+                        .setKeyValueStore(mRemoteData)
+                        .setModelKey(MODEL_KEY)
+                        .setModelType(InferenceInput.Params.MODEL_TYPE_EXECUTORCH)
+                        .build();
+        byte[] inputData = serializeFloatArray(new float[] {1.2f, 2.3f});
+        InferenceInput inferenceInput = new InferenceInput.Builder(params, inputData).build();
+
+        assertThat(inferenceInput.getData()).isEqualTo(inputData);
+        assertThat(inferenceInput.getParams().getModelType())
+                .isEqualTo(InferenceInput.Params.MODEL_TYPE_EXECUTORCH);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+    public void buildInferenceInput_setInputDataBytes_success() {
+        InferenceInput.Params params =
+                new InferenceInput.Params.Builder(mRemoteData, MODEL_KEY)
+                        .setKeyValueStore(mRemoteData)
+                        .setModelKey(MODEL_KEY)
+                        .setModelType(InferenceInput.Params.MODEL_TYPE_EXECUTORCH)
+                        .build();
+        byte[] inputData = serializeFloatArray(new float[] {1.2f, 2.3f});
+        InferenceInput inferenceInput =
+                new InferenceInput.Builder(params, inputData).setInputData(inputData).build();
+
+        assertThat(inferenceInput.getData()).isEqualTo(inputData);
+        assertThat(inferenceInput.getParams().getModelType())
+                .isEqualTo(InferenceInput.Params.MODEL_TYPE_EXECUTORCH);
+    }
+
     static class TestDataAccessService extends IDataAccessService.Stub {
         @Override
         public void onRequest(int operation, Bundle params, IDataAccessServiceCallback callback) {}
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
index 0e8388cb..480bd814 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/InferenceOutputTest.java
@@ -16,12 +16,16 @@
 
 package com.android.ondevicepersonalization.cts.e2e;
 
+import static com.android.ondevicepersonalization.cts.e2e.TestUtils.serializeFloatArray;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static junit.framework.Assert.assertEquals;
 
 import android.adservices.ondevicepersonalization.InferenceOutput;
+import android.platform.test.annotations.RequiresFlagsEnabled;
 
+import com.android.adservices.ondevicepersonalization.flags.Flags;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
 import org.junit.Assume;
@@ -59,4 +63,13 @@ public class InferenceOutputTest {
 
         assertThat(value).isEqualTo(expected);
     }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_EXECUTORCH_INFERENCE_API_ENABLED)
+    public void build_dataBytes_success() {
+        byte[] data = serializeFloatArray(new float[] {1.2f, 2.3f});
+        InferenceOutput output = new InferenceOutput.Builder().setData(data).build();
+
+        assertThat(output.getData()).isEqualTo(data);
+    }
 }
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
index 7ca41202..dda37b2f 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/IsolatedWorkerTest.java
@@ -29,6 +29,7 @@ import android.adservices.ondevicepersonalization.EventInput;
 import android.adservices.ondevicepersonalization.EventLogRecord;
 import android.adservices.ondevicepersonalization.EventOutput;
 import android.adservices.ondevicepersonalization.ExecuteInput;
+import android.adservices.ondevicepersonalization.ExecuteInputParcel;
 import android.adservices.ondevicepersonalization.ExecuteOutput;
 import android.adservices.ondevicepersonalization.IsolatedServiceException;
 import android.adservices.ondevicepersonalization.IsolatedWorker;
@@ -53,6 +54,8 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.adservices.ondevicepersonalization.flags.Flags;
+import com.android.ondevicepersonalization.internal.util.ByteArrayParceledSlice;
+import com.android.ondevicepersonalization.internal.util.PersistableBundleUtils;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
 import org.junit.Assume;
@@ -70,7 +73,6 @@ import java.util.Set;
  */
 @SmallTest
 @RunWith(AndroidJUnit4.class)
-@RequiresFlagsEnabled(Flags.FLAG_DATA_CLASS_MISSING_CTORS_AND_GETTERS_ENABLED)
 public class IsolatedWorkerTest {
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
@@ -87,7 +89,14 @@ public class IsolatedWorkerTest {
         WorkerResultReceiver<ExecuteOutput> receiver = new WorkerResultReceiver<>();
         PersistableBundle bundle = new PersistableBundle();
         bundle.putString("x", "y");
-        worker.onExecute(new ExecuteInput("com.example.app", bundle), receiver);
+        ByteArrayParceledSlice slice =
+                new ByteArrayParceledSlice(PersistableBundleUtils.toByteArray(bundle));
+        ExecuteInputParcel inputParcel =
+                new ExecuteInputParcel.Builder()
+                        .setAppPackageName("com.example.app")
+                        .setSerializedAppParams(slice)
+                        .build();
+        worker.onExecute(new ExecuteInput(inputParcel), receiver);
     }
 
     @Test
@@ -106,7 +115,7 @@ public class IsolatedWorkerTest {
         WorkerResultReceiver<DownloadCompletedOutput> receiver = new WorkerResultReceiver<>();
         TestKeyValueStore store = new TestKeyValueStore(
                 Map.of("a", new byte[]{'A'}, "b", new byte[]{'B'}));
-        worker.onDownloadCompleted(new DownloadCompletedInput(store), receiver);
+        worker.onDownloadCompleted(new DownloadCompletedInput.Builder(store).build(), receiver);
         assertThat(receiver.mResult.getRetainedKeys(), containsInAnyOrder("a", "b"));
     }
 
@@ -148,6 +157,27 @@ public class IsolatedWorkerTest {
         assertEquals(1, receiver.mResult.getEventLogRecords().size());
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_DATA_CLASS_MISSING_CTORS_AND_GETTERS_ENABLED)
+    public void testOnExecuteWithCtor() throws Exception {
+        IsolatedWorker worker = new TestWorker();
+        WorkerResultReceiver<ExecuteOutput> receiver = new WorkerResultReceiver<>();
+        PersistableBundle bundle = new PersistableBundle();
+        bundle.putString("x", "y");
+        worker.onExecute(new ExecuteInput("com.example.app", bundle), receiver);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_DATA_CLASS_MISSING_CTORS_AND_GETTERS_ENABLED)
+    public void testOnDownloadCompletedWithCtors() throws Exception {
+        IsolatedWorker worker = new TestWorker();
+        WorkerResultReceiver<DownloadCompletedOutput> receiver = new WorkerResultReceiver<>();
+        TestKeyValueStore store =
+                new TestKeyValueStore(Map.of("a", new byte[] {'A'}, "b", new byte[] {'B'}));
+        worker.onDownloadCompleted(new DownloadCompletedInput(store), receiver);
+        assertThat(receiver.mResult.getRetainedKeys(), containsInAnyOrder("a", "b"));
+    }
+
     class TestWorker implements IsolatedWorker {
         @Override public void onExecute(
                 ExecuteInput input,
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/TestUtils.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/TestUtils.java
new file mode 100644
index 00000000..14df0f0b
--- /dev/null
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/TestUtils.java
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.ondevicepersonalization.cts.e2e;
+
+import java.io.ByteArrayOutputStream;
+import java.io.DataOutputStream;
+import java.io.IOException;
+
+/** Util class for cts tests. */
+public class TestUtils {
+
+    /** Serialize an float array to a byte array. */
+    public static byte[] serializeFloatArray(float[] floatArray) {
+        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
+                DataOutputStream dos = new DataOutputStream(bos)) {
+            for (float f : floatArray) {
+                dos.writeFloat(f);
+            }
+
+            return bos.toByteArray();
+        } catch (IOException e) {
+            throw new IllegalArgumentException("Failed to serialize float array", e);
+        }
+    }
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/Android.bp b/tests/cts/sandbox/ondevicepersonalization/Android.bp
new file mode 100644
index 00000000..939ab5b0
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/Android.bp
@@ -0,0 +1,55 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "CtsSandboxOnDevicePersonalizationManagerTests",
+    certificate: ":sdksandbox-test",
+    data: [
+        ":SdkOnDevicePersonalization",
+        ":OdpTestingSampleService",
+    ],
+    srcs: [
+        "src/**/*.java",
+    ],
+    static_libs: [
+        "SdkOnDevicePersonalizationInterfaces",
+        "ondevicepersonalization-testing-utils",
+        "ondevicepersonalization-testing-sample-service-api",
+        "compatibility-device-util-axt",
+        "androidx.test.runner",
+        "truth",
+    ],
+    libs: [
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
+        "framework-sdksandbox.stubs.module_lib",
+        "framework-ondevicepersonalization.stubs.module_lib",
+    ],
+    min_sdk_version: "Tiramisu",
+    target_sdk_version: "Tiramisu",
+    sdk_version: "module_current",
+    test_mainline_modules: ["com.google.android.ondevicepersonalization.apex"],
+    test_suites: [
+        "cts",
+        "general-tests",
+        "mts-ondevicepersonalization",
+        "mcts-ondevicepersonalization",
+    ],
+    test_config: "AndroidTest.xml",
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/AndroidManifest.xml b/tests/cts/sandbox/ondevicepersonalization/AndroidManifest.xml
new file mode 100644
index 00000000..3c09e3e4
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/AndroidManifest.xml
@@ -0,0 +1,46 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.tests.sandbox.ondevicepersonalization" >
+
+    <uses-permission android:name="android.permission.INTERNET" />
+    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
+
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner" />
+        <uses-sdk-library android:name="com.android.tests.providers.sdkondevicepersonalization"
+                          android:versionMajor="1"
+                          android:certDigest="0B:44:2D:88:FA:A7:B3:AD:23:8D:DE:29:8A:A1:9B:D5:62:03:92:0B:BF:D8:D3:EB:C8:99:33:2C:8E:E1:15:99"/>
+
+        <activity android:name=".SimpleActivity"
+                  android:excludeFromRecents="true"
+                  android:exported="false"
+                  android:turnScreenOn="true"
+                  android:keepScreenOn="true"
+                  android:showWhenLocked="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN" />
+                <category android:name="android.intent.category.LAUNCHER" />
+            </intent-filter>
+        </activity>
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="com.android.tests.sandbox.ondevicepersonalization"
+                     android:label="OnDevicePersonalization API end to end tests"/>
+</manifest>
diff --git a/tests/cts/sandbox/ondevicepersonalization/AndroidTest.xml b/tests/cts/sandbox/ondevicepersonalization/AndroidTest.xml
new file mode 100644
index 00000000..7faec503
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/AndroidTest.xml
@@ -0,0 +1,61 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<configuration description="Config for CtsSandboxOnDevicePersonalizationManagerTests end to end tests">
+    <option name="test-suite-tag" value="cts" />
+    <option name="config-descriptor:metadata" key="component" value="framework"/>
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app"/>
+    <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi"/>
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true"/>
+        <option name="test-file-name" value="OdpTestingSampleService.apk"/>
+        <option name="test-file-name" value="SdkOnDevicePersonalization.apk"/>
+        <option name="test-file-name" value="CtsSandboxOnDevicePersonalizationManagerTests.apk"/>
+    </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="device_config set_sync_disabled_for_tests persistent" />
+        <option name="run-command" value="device_config put adservices disable_sdk_sandbox false" />
+        <option name="run-command" value="device_config put adservices sdksandbox_enforce_restrictions false" />
+        <option name="run-command" value="device_config put on_device_personalization global_kill_switch false" />
+        <option name="run-command" value="device_config put on_device_personalization federated_compute_kill_switch false" />
+        <option name="run-command" value="device_config put on_device_personalization enable_personalization_status_override true"/>
+        <option name="run-command" value="device_config put on_device_personalization personalization_status_override_value true"/>
+        <option name="run-command" value="device_config put on_device_personalization isolated_service_debugging_enabled true"/>
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="teardown-command" value="device_config delete adservices disable_sdk_sandbox" />
+        <option name="teardown-command" value="device_config delete adservices sdksandbox_enforce_restrictions" />
+        <option name="teardown-command" value="device_config delete on_device_personalization global_kill_switch" />
+        <option name="teardown-command" value="device_config delete on_device_personalization federated_compute_kill_switch" />
+        <option name="teardown-command" value="device_config delete on_device_personalization enable_personalization_status_override" />
+        <option name="teardown-command" value="device_config delete on_device_personalization personalization_status_override_value" />
+        <option name="teardown-command" value="device_config delete on_device_personalization isolated_service_debugging_enabled" />
+        <option name="teardown-command" value="device_config set_sync_disabled_for_tests none" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest">
+        <option name="hidden-api-checks" value="false"/>
+        <option name="package" value="com.android.tests.sandbox.ondevicepersonalization"/>
+    </test>
+
+    <object type="module_controller"
+            class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController" >
+        <option name="mainline-module-package-name" value="com.google.android.ondevicepersonalization" />
+    </object>
+    <option name="config-descriptor:metadata" key="mainline-param"
+            value="com.google.android.ondevicepersonalization.apex" />
+</configuration>
\ No newline at end of file
diff --git a/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/Android.bp b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/Android.bp
new file mode 100644
index 00000000..5bd05bfe
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/Android.bp
@@ -0,0 +1,39 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test_helper_app {
+    name: "SdkOnDevicePersonalization",
+    certificate: ":sdksandbox-test",
+    defaults: ["platform_app_defaults"],
+    srcs: [
+        "src/**/*.java",
+    ],
+    static_libs: [
+        "SdkOnDevicePersonalizationInterfaces",
+        "ondevicepersonalization-testing-utils",
+        "ondevicepersonalization-testing-sample-service-api",
+        "androidx.concurrent_concurrent-futures",
+        "compatibility-device-util-axt",
+        "truth",
+    ],
+    libs: [
+        "android.test.base.stubs.system",
+    ],
+    min_sdk_version: "33",
+    target_sdk_version: "33",
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/AndroidManifest.xml b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/AndroidManifest.xml
new file mode 100644
index 00000000..00e7b6ed
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/AndroidManifest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.tests.providers.sdkondevicepersonalization">
+
+    <application>
+        <sdk-library android:name="com.android.tests.providers.sdkondevicepersonalization"
+                     android:versionMajor="1" />
+        <property android:name="android.sdksandbox.PROPERTY_SDK_PROVIDER_CLASS_NAME"
+                  android:value="com.android.tests.providers.sdkondevicepersonalization.SdkOnDevicePersonalizationProvider" />
+    </application>
+</manifest>
diff --git a/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationApi.java b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationApi.java
new file mode 100644
index 00000000..5dd44b9b
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationApi.java
@@ -0,0 +1,66 @@
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
+package com.android.tests.providers.sdkondevicepersonalization;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.app.sdksandbox.interfaces.ISdkOnDevicePersonalizationApi;
+import android.content.ComponentName;
+import android.content.Context;
+import android.os.PersistableBundle;
+import android.util.Log;
+
+import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import java.util.concurrent.Executors;
+
+public class SdkOnDevicePersonalizationApi extends ISdkOnDevicePersonalizationApi.Stub {
+    public static final String TAG = "SdkOnDevicePersonalizationApi";
+    private static final String SERVICE_PACKAGE =
+            "com.android.ondevicepersonalization.testing.sampleservice";
+    private static final String SERVICE_CLASS =
+            "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
+
+    private final OnDevicePersonalizationManager mOdpManager;
+
+    public SdkOnDevicePersonalizationApi(Context context) {
+        mOdpManager = context.getSystemService(OnDevicePersonalizationManager.class);
+    }
+
+    @Override
+    public boolean matchPackageName(String packageName) {
+        var receiver = new ResultReceiver<OnDevicePersonalizationManager.ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE,
+                SampleServiceApi.OPCODE_CHECK_PACKAGE_NAME);
+        appParams.putString(
+                SampleServiceApi.KEY_EXPECTED_PACKAGE_NAME,
+                packageName);
+        mOdpManager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        try {
+            return receiver.isSuccess();
+        } catch (InterruptedException e) {
+            Log.e(TAG, "Error while calling ResultReceiver#isSuccess", e);
+            return false;
+        }
+    }
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationProvider.java b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationProvider.java
new file mode 100644
index 00000000..84410846
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/providers/sdkondevicepersonalization/src/com/android/tests/providers/sdkondevicepersonalization/SdkOnDevicePersonalizationProvider.java
@@ -0,0 +1,44 @@
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
+package com.android.tests.providers.sdkondevicepersonalization;
+
+import android.app.sdksandbox.LoadSdkException;
+import android.app.sdksandbox.SandboxedSdk;
+import android.app.sdksandbox.SandboxedSdkProvider;
+import android.content.Context;
+import android.os.Bundle;
+import android.view.View;
+
+import androidx.annotation.NonNull;
+
+public class SdkOnDevicePersonalizationProvider extends SandboxedSdkProvider {
+
+    @Override
+    public SandboxedSdk onLoadSdk(Bundle params) throws LoadSdkException {
+        try {
+            return new SandboxedSdk(new SdkOnDevicePersonalizationApi(getContext()));
+        } catch (Exception e) {
+            throw new LoadSdkException(e, new Bundle());
+        }
+    }
+
+    @Override
+    public View getView(
+            @NonNull Context windowContext, @NonNull Bundle params, int width, int height) {
+        throw new UnsupportedOperationException("View not defined");
+    }
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/Android.bp b/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/Android.bp
new file mode 100644
index 00000000..ed1d08b3
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/Android.bp
@@ -0,0 +1,24 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "SdkOnDevicePersonalizationInterfaces",
+    srcs: [
+        "src/**/*.aidl",
+    ],
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/src/android/app/sdksandbox/interfaces/ISdkOnDevicePersonalizationApi.aidl b/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/src/android/app/sdksandbox/interfaces/ISdkOnDevicePersonalizationApi.aidl
new file mode 100644
index 00000000..cce3ace6
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/sdkinterfaces/src/android/app/sdksandbox/interfaces/ISdkOnDevicePersonalizationApi.aidl
@@ -0,0 +1,21 @@
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
+package android.app.sdksandbox.interfaces;
+
+interface ISdkOnDevicePersonalizationApi {
+    boolean matchPackageName(in String packageName);
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SandboxOnDevicePersonalizationManagerTest.java b/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SandboxOnDevicePersonalizationManagerTest.java
new file mode 100644
index 00000000..00b149c9
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SandboxOnDevicePersonalizationManagerTest.java
@@ -0,0 +1,221 @@
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
+package com.android.tests.sandbox.ondevicepersonalization;
+
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.app.sdksandbox.LoadSdkException;
+import android.app.sdksandbox.SandboxedSdk;
+import android.app.sdksandbox.SdkSandboxManager;
+import android.app.sdksandbox.interfaces.ISdkOnDevicePersonalizationApi;
+import android.content.ComponentName;
+import android.content.Context;
+import android.os.Bundle;
+import android.os.IBinder;
+import android.os.OutcomeReceiver;
+import android.os.PersistableBundle;
+import android.os.RemoteException;
+import android.util.Log;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.compatibility.common.util.ShellUtils;
+import com.android.modules.utils.build.SdkLevel;
+import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.After;
+import org.junit.Assume;
+import org.junit.Before;
+import org.junit.Test;
+
+import java.time.Duration;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.Executors;
+import java.util.concurrent.TimeUnit;
+
+/*
+ * Test OnDevicePersonalization APIs running within the Sandbox.
+ */
+public final class SandboxOnDevicePersonalizationManagerTest {
+    private static final String TAG = "SandboxOnDevicePersonalizationManagerTest";
+    private static final String SDK_NAME = "com.android.tests.providers.sdkondevicepersonalization";
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+    private static final String SERVICE_PACKAGE =
+            "com.android.ondevicepersonalization.testing.sampleservice";
+    private static final String SERVICE_CLASS =
+            "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
+
+    private SandboxedSdk mSandboxedSdk;
+
+    @Before
+    public void setUp() throws Exception {
+        // Skip the test if it runs on unsupported platforms.
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+
+        SimpleActivity.startAndWaitForSimpleActivity(sContext, Duration.ofSeconds(10));
+
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "caller_app_allow_list "
+                        + sContext.getPackageName());
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "shared_isolated_process_feature_enabled "
+                        + SdkLevel.isAtLeastU());
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "debug.validate_rendering_config_keys "
+                        + false);
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_allow_list "
+                        + "com.android.ondevicepersonalization.testing.sampleservice,"
+                        + "com.example.odptargetingapp2,"
+                        + "com.android.tests.sandbox.ondevicepersonalization");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "output_data_allow_list "
+                        + sContext.getPackageName()
+                        + ";com.android.ondevicepersonalization.testing.sampleservice");
+    }
+
+    @After
+    public void reset() {
+        SimpleActivity.stopSimpleActivity(sContext);
+        ShellUtils.runShellCommand(
+                "device_config delete on_device_personalization "
+                        + "caller_app_allow_list");
+        ShellUtils.runShellCommand(
+                "device_config delete on_device_personalization "
+                        + "shared_isolated_process_feature_enabled");
+        ShellUtils.runShellCommand(
+                "device_config delete on_device_personalization "
+                        + "debug.validate_rendering_config_keys");
+        ShellUtils.runShellCommand(
+                "device_config delete on_device_personalization "
+                        + "isolated_service_allow_list");
+        ShellUtils.runShellCommand(
+                "device_config delete on_device_personalization "
+                        + "output_data_allow_list");
+
+        ShellUtils.runShellCommand(
+                "am force-stop com.google.android.ondevicepersonalization.services");
+        ShellUtils.runShellCommand(
+                "am force-stop com.android.ondevicepersonalization.services");
+        mSandboxedSdk = null;
+    }
+
+    @Test
+    public void matchPackageNameWithoutSandbox() {
+        boolean result = matchPackageNameWithoutSandbox(sContext.getPackageName());
+
+        assertTrue("Package name did not match without sandbox", result);
+    }
+
+    @Test
+    public void matchPackageNameWithinSandbox() {
+        Assume.assumeTrue(SdkLevel.isAtLeastU());
+        assertTrue("Unable to load SDK", loadSdk(SDK_NAME));
+
+        boolean result = matchPackageNameWithinSandbox(sContext.getPackageName());
+
+        assertTrue("Package name did not match within sandbox", result);
+    }
+
+    private boolean matchPackageNameWithoutSandbox(String packageName) {
+        var receiver = new ResultReceiver<OnDevicePersonalizationManager.ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE,
+                SampleServiceApi.OPCODE_CHECK_PACKAGE_NAME);
+        appParams.putString(
+                SampleServiceApi.KEY_EXPECTED_PACKAGE_NAME,
+                packageName);
+        sContext.getSystemService(OnDevicePersonalizationManager.class).execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        try {
+            return receiver.isSuccess();
+        } catch (InterruptedException e) {
+            Log.e(TAG, "Error while calling ResultReceiver#isSuccess", e);
+            return false;
+        }
+    }
+
+    private boolean matchPackageNameWithinSandbox(String packageName) {
+        try {
+            ISdkOnDevicePersonalizationApi sdkApi = getInterface(mSandboxedSdk);
+            return sdkApi.matchPackageName(packageName);
+        } catch (RemoteException e) {
+            Log.e(TAG, "Error while calling sdk API", e);
+            return false;
+        }
+    }
+
+    private ISdkOnDevicePersonalizationApi getInterface(SandboxedSdk sandboxedSdk) {
+        IBinder binder = sandboxedSdk.getInterface();
+        return ISdkOnDevicePersonalizationApi.Stub.asInterface(binder);
+    }
+
+    private boolean loadSdk(String sdkName) {
+        SdkSandboxManager sdkSandboxManager =
+                sContext.getSystemService(SdkSandboxManager.class);
+        CountDownLatch latch = new CountDownLatch(1);
+        final LoadSdkCallbackImpl callback = new LoadSdkCallbackImpl(latch);
+        sdkSandboxManager.loadSdk(
+                sdkName, new Bundle(), Runnable::run, callback);
+        try {
+            latch.await(/* timeout */ 30, TimeUnit.SECONDS);
+            return mSandboxedSdk != null;
+        } catch (InterruptedException e) {
+            return false;
+        }
+    }
+
+    private class LoadSdkCallbackImpl implements OutcomeReceiver<SandboxedSdk, LoadSdkException> {
+        private CountDownLatch mLatch;
+
+        private LoadSdkCallbackImpl(CountDownLatch latch) {
+            mLatch = latch;
+        }
+
+        /**
+         * Notifies client the requested SDK is successfully loaded.
+         */
+        @Override
+        public void onResult(SandboxedSdk sandboxedSdk) {
+            Log.i(TAG, "SDK has been loaded successfully");
+            mSandboxedSdk = sandboxedSdk;
+            mLatch.countDown();
+        }
+
+        /**
+         * Notifies client the requested Sdk failed to be loaded.
+         */
+        @Override
+        public void onError(LoadSdkException error) {
+            Log.e(TAG, "Error while loading SDK", error);
+            mLatch.countDown();
+        }
+    }
+}
diff --git a/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SimpleActivity.java b/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SimpleActivity.java
new file mode 100644
index 00000000..83655eb3
--- /dev/null
+++ b/tests/cts/sandbox/ondevicepersonalization/src/com/android/tests/sandbox/ondevicepersonalization/SimpleActivity.java
@@ -0,0 +1,170 @@
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
+package com.android.tests.sandbox.ondevicepersonalization;
+
+import android.app.Activity;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.os.Bundle;
+import android.os.SystemClock;
+
+import java.time.Duration;
+import java.util.concurrent.TimeoutException;
+
+/**
+ * Simple activity so test can run in the foreground and services could bind with high priority.
+ */
+public class SimpleActivity extends Activity {
+    private static final String EXTRA_FINISH_FLAG = "finish";
+    private static final String ACTION_SIMPLE_ACTIVITY_START_RESULT =
+            "com.android.tests.sandbox.ondevicepersonalization.SimpleActivity.RESULT";
+
+    @Override
+    public void onCreate(Bundle icicle) {
+        super.onCreate(icicle);
+    }
+
+    @Override
+    public void onStart() {
+        super.onStart();
+    }
+
+    @Override
+    public void onResume() {
+        super.onResume();
+        Intent reply = new Intent(ACTION_SIMPLE_ACTIVITY_START_RESULT);
+        reply.setFlags(Intent.FLAG_RECEIVER_FOREGROUND);
+        sendBroadcast(reply);
+    }
+
+    @Override
+    protected void onNewIntent(Intent intent) {
+        super.onNewIntent(intent);
+        if (intent.getExtras().getBoolean(EXTRA_FINISH_FLAG)) {
+            finish();
+        }
+    }
+
+    /** @return an intent targeting {@link SimpleActivity} */
+    public static Intent getSimpleActivityIntent() {
+        return new Intent(Intent.ACTION_MAIN)
+                .setClassName(
+                        SimpleActivity.class.getPackageName(),
+                        SimpleActivity.class.getName())
+                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+    }
+
+    /** Starts a {@link SimpleActivity}. Doesn't wait for activity to be started */
+    public static void startSimpleActivity(Context targetContext) {
+        targetContext.startActivity(getSimpleActivityIntent());
+    }
+
+    /**
+     * Stops a single activity, doesn't wait for the activity to stop or check if the activity was
+     * actually running.
+     */
+    public static void stopSimpleActivity(Context targetContext) {
+        targetContext.startActivity(
+                getSimpleActivityIntent()
+                        .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
+                        .putExtra(EXTRA_FINISH_FLAG, true));
+    }
+
+    /**
+     * Starts a {@link SimpleActivity} and wait for the activity to be started the specified max
+     * waiting time.
+     *
+     * @param targetContext the context to start the activity in
+     * @param maxWaitTime the max waiting time
+     * @throws TimeoutException if the activity didn't start within timeout
+     */
+    public static void startAndWaitForSimpleActivity(Context targetContext, Duration maxWaitTime)
+            throws TimeoutException {
+        try (SimpleActivity.WaitForBroadcast waiter =
+                new SimpleActivity.WaitForBroadcast(targetContext)) {
+            waiter.prepare(ACTION_SIMPLE_ACTIVITY_START_RESULT);
+            startSimpleActivity(targetContext);
+            waiter.doWait(maxWaitTime.toMillis());
+        }
+    }
+
+    /** See {@code android.app.cts.android.app.cts.tools.WaitForBroadcast} */
+    private static class WaitForBroadcast implements AutoCloseable {
+        private final Context mContext;
+
+        String mWaitingAction;
+        boolean mHasResult;
+        Intent mReceivedIntent;
+        private final Object mWaitMonitor = new Object();
+
+        final BroadcastReceiver mReceiver =
+                new BroadcastReceiver() {
+                    @Override
+                    public void onReceive(Context context, Intent intent) {
+                        synchronized (mWaitMonitor) {
+                            mReceivedIntent = intent;
+                            mHasResult = true;
+                            mWaitMonitor.notifyAll();
+                        }
+                    }
+                };
+
+        WaitForBroadcast(Context context) {
+            mContext = context;
+        }
+
+        public void prepare(String action) {
+            if (mWaitingAction != null) {
+                throw new IllegalStateException("Already prepared");
+            }
+            mWaitingAction = action;
+            IntentFilter filter = new IntentFilter();
+            filter.addAction(action);
+            mContext.registerReceiver(mReceiver, filter, Context.RECEIVER_EXPORTED);
+        }
+
+        public Intent doWait(long timeoutMillis) throws TimeoutException {
+            final long endTime = SystemClock.uptimeMillis() + timeoutMillis;
+
+            synchronized (mWaitMonitor) {
+                while (!mHasResult) {
+                    final long now = SystemClock.uptimeMillis();
+                    if (now >= endTime) {
+                        String action = mWaitingAction;
+                        throw new TimeoutException("Timed out waiting for broadcast " + action);
+                    }
+                    try {
+                        mWaitMonitor.wait(endTime - now);
+                    } catch (InterruptedException e) {
+                        Thread.currentThread().interrupt();
+                    }
+                }
+                return mReceivedIntent;
+            }
+        }
+
+        @Override
+        public void close() {
+            if (mWaitingAction != null) {
+                mContext.unregisterReceiver(mReceiver);
+                mWaitingAction = null;
+            }
+        }
+    }
+}
diff --git a/tests/cts/service/src/com/android/ondevicepersonalization/testing/sampleservice/SampleWorker.java b/tests/cts/service/src/com/android/ondevicepersonalization/testing/sampleservice/SampleWorker.java
index 69716616..7067f85f 100644
--- a/tests/cts/service/src/com/android/ondevicepersonalization/testing/sampleservice/SampleWorker.java
+++ b/tests/cts/service/src/com/android/ondevicepersonalization/testing/sampleservice/SampleWorker.java
@@ -48,6 +48,8 @@ import android.util.Log;
 
 import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
 
+import com.google.common.util.concurrent.MoreExecutors;
+
 import java.time.Duration;
 import java.time.Instant;
 import java.util.Arrays;
@@ -116,10 +118,11 @@ class SampleWorker implements IsolatedWorker {
             throw createException(appParams);
         }
 
-        mExecutor.submit(() -> handleOnExecute(appParams, receiver));
+        var unused = mExecutor.submit(() -> handleOnExecute(input, appParams, receiver));
     }
 
     private void handleOnExecute(
+            ExecuteInput input,
             PersistableBundle appParams,
             OutcomeReceiver<ExecuteOutput, IsolatedServiceException> receiver) {
         Log.i(TAG, "handleOnExecute()");
@@ -156,6 +159,8 @@ class SampleWorker implements IsolatedWorker {
                 result = handleScheduleFederatedJob(appParams, /* useLegacyScheduleApi= */ false);
             } else if (op.equals(SampleServiceApi.OPCODE_CANCEL_FEDERATED_JOB)) {
                 result = handleCancelFederatedJob(appParams);
+            } else if (op.equals(SampleServiceApi.OPCODE_CHECK_PACKAGE_NAME)) {
+                result = handleMatchPackageName(input, appParams);
             }
 
         } catch (Exception e) {
@@ -368,6 +373,7 @@ class SampleWorker implements IsolatedWorker {
             byte[] actualValue = mLocalData.get(key);
             success = Arrays.equals(expectedValue, actualValue);
         } else {
+            // No value in the app params indicates that the key should not exist in local data.
             success = mLocalData.get(key) == null;
         }
 
@@ -378,7 +384,7 @@ class SampleWorker implements IsolatedWorker {
         }
     }
 
-    private ExecuteOutput handleCheckValueLength(PersistableBundle appParams) {
+    private static ExecuteOutput handleCheckValueLength(PersistableBundle appParams) {
         Log.i(TAG, "handleCheckValueLength()");
         String encodedValue = appParams.getString(SampleServiceApi.KEY_BASE64_VALUE);
         byte[] value = (encodedValue != null) ? Base64.decode(encodedValue, 0) : null;
@@ -391,7 +397,7 @@ class SampleWorker implements IsolatedWorker {
         }
     }
 
-    private byte[] expandByteArray(byte[] input, int count) {
+    private static byte[] expandByteArray(byte[] input, int count) {
         byte[] output = new byte[input.length * count];
         for (int i = 0; i < count; ++i) {
             System.arraycopy(input, 0, output, i * input.length, input.length);
@@ -399,7 +405,7 @@ class SampleWorker implements IsolatedWorker {
         return output;
     }
 
-    private RuntimeException createException(PersistableBundle appParams) {
+    private static RuntimeException createException(PersistableBundle appParams) {
         try {
             String exceptionClass =
                     appParams.getString(
@@ -412,7 +418,7 @@ class SampleWorker implements IsolatedWorker {
         }
     }
 
-    private void putObject(ContentValues cv, String key, Object value) {
+    private static void putObject(ContentValues cv, String key, Object value) {
         if (value instanceof String) {
             cv.put(key, (String) value);
         } else if (value instanceof Double) {
@@ -494,6 +500,7 @@ class SampleWorker implements IsolatedWorker {
                 new FederatedComputeScheduleRequest(params, populationName);
         mFcpScheduler.schedule(
                 request,
+                MoreExecutors.directExecutor(),
                 new OutcomeReceiver<FederatedComputeScheduleResponse, Exception>() {
                     @Override
                     public void onResult(FederatedComputeScheduleResponse result) {
@@ -529,4 +536,16 @@ class SampleWorker implements IsolatedWorker {
         mFcpScheduler.cancel(input);
         return new ExecuteOutput.Builder().build();
     }
+
+    private static ExecuteOutput handleMatchPackageName(
+            ExecuteInput input, PersistableBundle appParams) {
+        Log.i(TAG, "handleMatchPackageName()");
+        String expectedPackageName = Objects.requireNonNull(
+                appParams.getString(SampleServiceApi.KEY_EXPECTED_PACKAGE_NAME));
+        if (input.getAppPackageName().equals(expectedPackageName)) {
+            return new ExecuteOutput.Builder().build();
+        } else {
+            return null;
+        }
+    }
 }
diff --git a/tests/cts/serviceapi/src/com/android/ondevicepersonalization/testing/sampleserviceapi/SampleServiceApi.java b/tests/cts/serviceapi/src/com/android/ondevicepersonalization/testing/sampleserviceapi/SampleServiceApi.java
index 4f5d83a3..0975cf0e 100644
--- a/tests/cts/serviceapi/src/com/android/ondevicepersonalization/testing/sampleserviceapi/SampleServiceApi.java
+++ b/tests/cts/serviceapi/src/com/android/ondevicepersonalization/testing/sampleserviceapi/SampleServiceApi.java
@@ -32,6 +32,7 @@ public class SampleServiceApi {
     public static final String KEY_EXPECTED_LOG_DATA_KEY = "expected_log_key";
     public static final String KEY_EXPECTED_LOG_DATA_VALUE = "expected_log_value";
     public static final String KEY_POPULATION_NAME = "value_population_name";
+    public static final String KEY_EXPECTED_PACKAGE_NAME = "expected_package_name";
 
     // Values of opcodes.
     public static final String OPCODE_RENDER_AND_LOG = "render_and_log";
@@ -45,6 +46,7 @@ public class SampleServiceApi {
     public static final String OPCODE_READ_REMOTE_DATA = "read_remote_data";
     public static final String OPCODE_READ_USER_DATA = "read_user_data";
     public static final String OPCODE_READ_LOG = "read_log";
+    public static final String OPCODE_CHECK_PACKAGE_NAME = "check_package_name";
 
     // Code for the legacy FCP schedule API.
     public static final String OPCODE_SCHEDULE_FEDERATED_JOB = "schedule_federated_job";
diff --git a/tests/federatedcomputetests/Android.bp b/tests/federatedcomputetests/Android.bp
index 6d451ee4..605143e7 100644
--- a/tests/federatedcomputetests/Android.bp
+++ b/tests/federatedcomputetests/Android.bp
@@ -53,6 +53,8 @@ android_test {
         "tensorflow_core_proto_java_lite",
         // Used for client error logging and background job logging.
         "adservices-shared-spe",
+        "common-ondevicepersonalization-protos",
+        "adservices-shared-datastore", // For proto data store.
     ],
     manifest: "AndroidManifest.xml",
     plugins: ["auto_value_plugin"],
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImplTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImplTest.java
index 971f9cba..f7a0d696 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImplTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceImplTest.java
@@ -16,12 +16,13 @@
 
 package com.android.federatedcompute.services;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+
 import static org.junit.Assert.assertNotNull;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
 
 import android.content.Intent;
 import android.os.IBinder;
@@ -29,7 +30,7 @@ import android.os.IBinder;
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
-import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJobService;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJob;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob;
 import com.android.federatedcompute.services.scheduling.FederatedComputeLearningJobScheduleOrchestrator;
 
@@ -52,14 +53,13 @@ public final class FederatedComputeManagingServiceImplTest {
     public void testBindableFederatedComputeService() {
         MockitoSession session =
                 ExtendedMockito.mockitoSession()
-                        .spyStatic(BackgroundKeyFetchJobService.class)
+                        .spyStatic(BackgroundKeyFetchJob.class)
                         .spyStatic(DeleteExpiredJob.class)
                         .spyStatic(FederatedComputeLearningJobScheduleOrchestrator.class)
                         .startMocking();
-        ExtendedMockito.doReturn(true)
-                .when(() -> BackgroundKeyFetchJobService.scheduleJobIfNeeded(any(), any()));
-        ExtendedMockito.doNothing().when(() -> DeleteExpiredJob.schedule(any(), any()));
-        ExtendedMockito.doReturn(mMockOrchestrator)
+        doNothing().when(() -> BackgroundKeyFetchJob.schedule(any()));
+        doNothing().when(() -> DeleteExpiredJob.schedule(any(), any()));
+        doReturn(mMockOrchestrator)
                 .when(() -> FederatedComputeLearningJobScheduleOrchestrator.getInstance(any()));
         doNothing().when(mMockOrchestrator).checkAndSchedule();
         try {
@@ -71,9 +71,8 @@ public final class FederatedComputeManagingServiceImplTest {
                             ApplicationProvider.getApplicationContext(),
                             FederatedComputeManagingServiceImpl.class);
             IBinder binder = spyFcpService.onBind(intent);
-            ExtendedMockito.verify(
-                    () -> BackgroundKeyFetchJobService.scheduleJobIfNeeded(any(), any()), times(1));
-            ExtendedMockito.verify(() -> DeleteExpiredJob.schedule(any(), any()));
+            verify(() -> BackgroundKeyFetchJob.schedule(any()));
+            verify(() -> DeleteExpiredJob.schedule(any(), any()));
             verify(mMockOrchestrator).checkAndSchedule();
             assertNotNull(binder);
         } finally {
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
index 58665b08..7c9bbf47 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
@@ -20,6 +20,8 @@ import static com.android.adservices.shared.common.flags.ModuleSharedFlags.BACKG
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_JOB_SCHEDULING_LOGGING_ENABLED;
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_ENABLE_ELIGIBILITY_TASK;
+import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_MODULE_JOB_POLICY;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_TASK_LIMIT_PER_PACKAGE;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_SCHEDULING_PERIOD_SECS;
@@ -41,34 +43,36 @@ import static com.android.federatedcompute.services.common.Flags.MIN_SCHEDULING_
 import static com.android.federatedcompute.services.common.Flags.TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT;
 import static com.android.federatedcompute.services.common.Flags.TRANSIENT_ERROR_RETRY_DELAY_SECS;
 import static com.android.federatedcompute.services.common.Flags.USE_BACKGROUND_ENCRYPTION_KEY_FETCH;
-import static com.android.federatedcompute.services.common.PhFlags.DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
-import static com.android.federatedcompute.services.common.PhFlags.ENABLE_ELIGIBILITY_TASK;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_ELIGIBILITY_TASK;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_BACKGROUND_JOBS_LOGGING;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_CLIENT_ERROR_LOGGING;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_ENCRYPTION;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_JOB_SCHEDULING_LOGGING_ENABLED;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_MEMORY_SIZE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_MODULE_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_RECURRENT_RESCHEDULE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_RESCHEDULE_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_SPE_PILOT_JOB_ENABLED;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_CONDITION_CHECK_THROTTLE_PERIOD_MILLIS;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_MIN_BATTERY_LEVEL;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRAINING_THERMAL_STATUS_TO_THROTTLE;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.TRANSIENT_ERROR_RETRY_DELAY_SECS_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.PhFlags.FCP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_ENABLE_BACKGROUND_JOBS_LOGGING;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_ENABLE_CLIENT_ERROR_LOGGING;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_ENABLE_ENCRYPTION;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_JOB_SCHEDULING_LOGGING_ENABLED;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_MEMORY_SIZE_LIMIT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_MODULE_JOB_POLICY;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_RECURRENT_RESCHEDULE_LIMIT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_RESCHEDULE_LIMIT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_SPE_PILOT_JOB_ENABLED;
-import static com.android.federatedcompute.services.common.PhFlags.FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL;
-import static com.android.federatedcompute.services.common.PhFlags.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
-import static com.android.federatedcompute.services.common.PhFlags.MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.TRAINING_CONDITION_CHECK_THROTTLE_PERIOD_MILLIS;
-import static com.android.federatedcompute.services.common.PhFlags.TRAINING_MIN_BATTERY_LEVEL;
-import static com.android.federatedcompute.services.common.PhFlags.TRAINING_THERMAL_STATUS_TO_THROTTLE;
-import static com.android.federatedcompute.services.common.PhFlags.TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT_CONFIG_NAME;
-import static com.android.federatedcompute.services.common.PhFlags.TRANSIENT_ERROR_RETRY_DELAY_SECS_CONFIG_NAME;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -80,6 +84,8 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.util.function.Supplier;
+
 /** Unit tests for {@link PhFlags} */
 @RunWith(JUnit4.class)
 public class PhFlagsTest {
@@ -765,19 +771,46 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpePilotJobEnabled() {
-        // read a stable flag value and verify it's equal to the default value.
-        boolean stableValue = FlagsFactory.getFlags().getSpePilotJobEnabled();
-        assertThat(stableValue).isEqualTo(DEFAULT_SPE_PILOT_JOB_ENABLED);
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpePilotJobEnabled(),
+                /* flagName */ FCP_SPE_PILOT_JOB_ENABLED,
+                /* defaultValue */ DEFAULT_SPE_PILOT_JOB_ENABLED);
+    }
 
-        // override the value in device config.
-        boolean overrideEnabled = !stableValue;
+    @Test
+    public void testGetSpeOnBackgroundKeyFetchJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled(),
+                /* flagName */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
+                /* defaultValue */
+                DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB);
+    }
+
+    @Test
+    public void testGetSpeOnFederatedJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnFederatedJobEnabled(),
+                /* flagName */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB,
+                /* defaultValue */ DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB);
+    }
+
+    private void assertSpeFeatureFlags(
+            Supplier<Boolean> flagSupplier, String flagName, boolean defaultValue) {
+        // Test override value
+        boolean overrideValue = !defaultValue;
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                FCP_SPE_PILOT_JOB_ENABLED,
-                Boolean.toString(overrideEnabled),
-                /* makeDefault= */ false);
+                flagName,
+                Boolean.toString(overrideValue),
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(overrideValue);
 
-        // the flag value remains stable
-        assertThat(FlagsFactory.getFlags().getSpePilotJobEnabled()).isEqualTo(overrideEnabled);
+        // Test default value
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                Boolean.toString(defaultValue),
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(defaultValue);
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
index ee8a990d..3213a747 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
@@ -17,8 +17,9 @@
 package com.android.federatedcompute.services.common;
 
 import static com.android.federatedcompute.services.common.Flags.USE_BACKGROUND_ENCRYPTION_KEY_FETCH;
-import static com.android.federatedcompute.services.common.PhFlags.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
-import static com.android.federatedcompute.services.common.PhFlags.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
 
 import android.provider.DeviceConfig;
 
@@ -83,4 +84,22 @@ public class PhFlagsTestUtil {
                 Boolean.toString(false),
                 /* makeDefault= */ false);
     }
+
+    /** Enable SPE scheduling for the background key fetch job. */
+    public static void enableSpeBackgroundKeyFetchJob() {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
+                Boolean.toString(true),
+                /* makeDefault= */ false);
+    }
+
+    /** Disable SPE scheduling for the background key fetch job. */
+    public static void disableSpeBackgroundKeyFetchJob() {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
+                Boolean.toString(false),
+                /* makeDefault= */ false);
+    }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
index bbe9a517..5b1975b4 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeDbHelperTest.java
@@ -20,8 +20,8 @@ import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICE
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__DATABASE_WRITE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__FEDERATED_COMPUTE;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doThrow;
-import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
-import static com.android.odp.module.common.data.ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
+import static com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
+import static com.android.odp.module.common.data.OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE;
 import static com.android.odp.module.common.encryption.OdpEncryptionKeyContract.ENCRYPTION_KEY_TABLE;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -44,7 +44,7 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.federatedcompute.services.common.Flags;
 import com.android.federatedcompute.services.common.FlagsFactory;
-import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
+import com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FederatedTrainingTaskColumns;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java
index 207e531e..616e4661 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedComputeEncryptionKeyDaoUtilsTest.java
@@ -36,6 +36,9 @@ public class FederatedComputeEncryptionKeyDaoUtilsTest {
 
     private static final Context sContext = ApplicationProvider.getApplicationContext();
 
+    private final FederatedComputeDbHelper mTestDbHelper =
+            FederatedComputeDbHelper.getNonSingletonInstanceForTest(sContext);
+
     @Test
     public void testGetInstance() {
         OdpEncryptionKeyDao instanceUnderTest =
@@ -51,9 +54,9 @@ public class FederatedComputeEncryptionKeyDaoUtilsTest {
     @Test
     public void testGetInstanceForTest() {
         OdpEncryptionKeyDao instanceUnderTest =
-                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext);
+                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext, mTestDbHelper);
         OdpEncryptionKeyDao secondInstance =
-                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext);
+                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(sContext, mTestDbHelper);
 
         assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
         assertNotNull(instanceUnderTest);
@@ -62,9 +65,8 @@ public class FederatedComputeEncryptionKeyDaoUtilsTest {
 
     @After
     public void cleanUp() throws Exception {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(sContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDaoTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDaoTest.java
index 7ac468c9..0af1f1d7 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDaoTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskDaoTest.java
@@ -43,6 +43,8 @@ import org.junit.Test;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
+import java.util.List;
+
 @MockStatic(ClientErrorLogger.class)
 public final class FederatedTrainingTaskDaoTest {
 
@@ -76,24 +78,27 @@ public final class FederatedTrainingTaskDaoTest {
                     .setTotalParticipation(2)
                     .build();
 
+    private static final Context sTestContext = ApplicationProvider.getApplicationContext();
+
+    private FederatedComputeDbHelper mTestDbHelper;
     private FederatedTrainingTaskDao mTrainingTaskDao;
-    private Context mContext;
 
     @Mock private ClientErrorLogger mMockClientErrorLogger;
 
     @Before
     public void setUp() {
-        mContext = ApplicationProvider.getApplicationContext();
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(sTestContext);
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mTestDbHelper);
+        mTrainingTaskDao.deleteExpiredTaskHistory(/* deleteTime= */ Long.MAX_VALUE);
+
         when(ClientErrorLogger.getInstance()).thenReturn(mMockClientErrorLogger);
     }
 
     @After
     public void cleanUp() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -104,16 +109,16 @@ public final class FederatedTrainingTaskDaoTest {
         FederatedTrainingTask task2 =
                 createDefaultFederatedTrainingTask().toBuilder().jobId(jobId2).build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task2);
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(2);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(2);
 
         FederatedTrainingTask removedTask = mTrainingTaskDao.findAndRemoveTaskByJobId(JOB_ID);
 
         assertThat(DataTestUtil.isEqualTask(removedTask, task)).isTrue();
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(1);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(1);
     }
 
     @Test
-    public void findAndRemoveTaskByJobId_nonExist() {
+    public void findAndRemoveTaskByJobId_nonExist_returnsNull() {
         FederatedTrainingTask removedTask = mTrainingTaskDao.findAndRemoveTaskByJobId(JOB_ID);
 
         assertThat(removedTask).isNull();
@@ -129,13 +134,13 @@ public final class FederatedTrainingTaskDaoTest {
                         .populationName(POPULATION_NAME + "_2")
                         .build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task2);
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(2);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(2);
 
         FederatedTrainingTask removedTask =
                 mTrainingTaskDao.findAndRemoveTaskByPopulationAndJobId(POPULATION_NAME, JOB_ID);
 
         assertThat(DataTestUtil.isEqualTask(removedTask, task)).isTrue();
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(1);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(1);
     }
 
     @Test
@@ -173,13 +178,13 @@ public final class FederatedTrainingTaskDaoTest {
                         .populationName(POPULATION_NAME + "_2")
                         .build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task2);
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(2);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(2);
 
         FederatedTrainingTask removedTask =
                 mTrainingTaskDao.findAndRemoveTaskByPopulationName(POPULATION_NAME);
 
         assertThat(DataTestUtil.isEqualTask(removedTask, task)).isTrue();
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(1);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(1);
     }
 
     @Test
@@ -193,14 +198,14 @@ public final class FederatedTrainingTaskDaoTest {
                         .populationName(POPULATION_NAME + "_2")
                         .build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task2);
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(2);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(2);
 
         FederatedTrainingTask removedTask =
                 mTrainingTaskDao.findAndRemoveTaskByPopulationNameAndCallingPackage(
                         POPULATION_NAME, PACKAGE_NAME);
 
         assertThat(DataTestUtil.isEqualTask(removedTask, task)).isTrue();
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(1);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(1);
     }
 
     @Test
@@ -242,14 +247,14 @@ public final class FederatedTrainingTaskDaoTest {
                         .ownerIdCertDigest(OWNER_ID_CERT_DIGEST + "_2")
                         .build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task4);
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(4);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(4);
 
         FederatedTrainingTask removedTask =
                 mTrainingTaskDao.findAndRemoveTaskByPopulationNameAndOwnerId(
                         POPULATION_NAME, OWNER_PACKAGE, OWNER_CLASS, OWNER_ID_CERT_DIGEST);
 
         assertThat(DataTestUtil.isEqualTask(removedTask, task)).isTrue();
-        assertThat(mTrainingTaskDao.getFederatedTrainingTask(null, null)).hasSize(3);
+        assertThat(getAllTrainingTasks(mTrainingTaskDao)).hasSize(3);
     }
 
     @Test
@@ -349,7 +354,13 @@ public final class FederatedTrainingTaskDaoTest {
         return builder.sizedByteArray();
     }
 
-    private FederatedTrainingTask createDefaultFederatedTrainingTask() {
+    private static List<FederatedTrainingTask> getAllTrainingTasks(
+            FederatedTrainingTaskDao trainingTaskDao) {
+        return trainingTaskDao.getFederatedTrainingTask(
+                /* selection= */ null, /* selectionArgs= */ null);
+    }
+
+    private static FederatedTrainingTask createDefaultFederatedTrainingTask() {
         return FederatedTrainingTask.builder()
                 .appPackageName(PACKAGE_NAME)
                 .jobId(JOB_ID)
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskTest.java
index 81447c21..d9d2e83c 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/data/FederatedTrainingTaskTest.java
@@ -16,7 +16,7 @@
 
 package com.android.federatedcompute.services.data;
 
-import static com.android.federatedcompute.services.data.FederatedTraningTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
+import static com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FEDERATED_TRAINING_TASKS_TABLE;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -27,7 +27,7 @@ import android.database.sqlite.SQLiteDatabase;
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.federatedcompute.services.data.FederatedTraningTaskContract.FederatedTrainingTaskColumns;
+import com.android.federatedcompute.services.data.FederatedTrainingTaskContract.FederatedTrainingTaskColumns;
 import com.android.federatedcompute.services.data.fbs.SchedulingMode;
 import com.android.federatedcompute.services.data.fbs.SchedulingReason;
 import com.android.federatedcompute.services.data.fbs.TrainingConstraints;
@@ -60,7 +60,7 @@ public final class FederatedTrainingTaskTest {
     private static final int SCHEDULING_REASON = SchedulingReason.SCHEDULING_REASON_NEW_TASK;
     private static final byte[] INTERVAL_OPTIONS = createDefaultTrainingIntervalOptions();
     private static final byte[] TRAINING_CONSTRAINTS = createDefaultTrainingConstraints();
-    public static final int RESCHEDULE_COUNT = 2;
+    private static final int RESCHEDULE_COUNT = 2;
 
     private SQLiteDatabase mDatabase;
     private FederatedComputeDbHelper mDbHelper;
@@ -70,6 +70,9 @@ public final class FederatedTrainingTaskTest {
         Context context = ApplicationProvider.getApplicationContext();
         mDbHelper = FederatedComputeDbHelper.getInstanceForTest(context);
         mDatabase = mDbHelper.getWritableDatabase();
+        // Force delete any rows in the database
+        mDatabase.delete(
+                FEDERATED_TRAINING_TASKS_TABLE, /* whereClause= */ null, /* whereArgs= */ null);
     }
 
     @After
@@ -171,7 +174,7 @@ public final class FederatedTrainingTaskTest {
         return builder.sizedByteArray();
     }
 
-    private FederatedTrainingTask createFederatedTrainingTaskWithAllFields() {
+    private static FederatedTrainingTask createFederatedTrainingTaskWithAllFields() {
         return FederatedTrainingTask.builder()
                 .appPackageName(PACKAGE_NAME)
                 .jobId(JOB_ID)
@@ -192,7 +195,7 @@ public final class FederatedTrainingTaskTest {
                 .build();
     }
 
-    private FederatedTrainingTask createFederatedTrainingTaskWithRequiredFields() {
+    private static FederatedTrainingTask createFederatedTrainingTaskWithRequiredFields() {
         return FederatedTrainingTask.builder()
                 .appPackageName(PACKAGE_NAME)
                 .jobId(JOB_ID)
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
index bc417e80..5e1a2ddb 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobServiceTest.java
@@ -16,6 +16,10 @@
 
 package com.android.federatedcompute.services.encryption;
 
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.odp.module.common.encryption.OdpEncryptionKey.KEY_TYPE_ENCRYPTION;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -27,7 +31,6 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
@@ -48,6 +51,7 @@ import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.PhFlagsTestUtil;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.federatedcompute.services.data.FederatedComputeEncryptionKeyDaoUtils;
+import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
 import com.android.odp.module.common.EventLogger;
 import com.android.odp.module.common.MonotonicClock;
 import com.android.odp.module.common.data.OdpEncryptionKeyDao;
@@ -94,6 +98,8 @@ public class BackgroundKeyFetchJobServiceTest {
 
     private TestInjector mInjector;
 
+    private FederatedComputeDbHelper mTestDbHelper;
+
     @Mock
     private EventLogger mMockEventLogger;
 
@@ -102,10 +108,14 @@ public class BackgroundKeyFetchJobServiceTest {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         PhFlagsTestUtil.disableGlobalKillSwitch();
         PhFlagsTestUtil.enableScheduleBackgroundKeyFetchJob();
+        PhFlagsTestUtil.disableSpeBackgroundKeyFetchJob();
         MockitoAnnotations.initMocks(this);
+
         mContext = ApplicationProvider.getApplicationContext();
         mInjector = new TestInjector();
-        mEncryptionDao = FederatedComputeEncryptionKeyDaoUtils.getInstance(mContext);
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(mContext);
+        mEncryptionDao =
+                FederatedComputeEncryptionKeyDaoUtils.getInstanceForTest(mContext, mTestDbHelper);
         mHttpClient = new HttpClient(/* retryLimit= */ 3, MoreExecutors.newDirectExecutorService());
         mSpyService = spy(new BackgroundKeyFetchJobService(new TestInjector()));
         doReturn(mSpyService).when(mSpyService).getApplicationContext();
@@ -120,9 +130,10 @@ public class BackgroundKeyFetchJobServiceTest {
                                 FlagsFactory.getFlags(),
                                 mHttpClient,
                                 MoreExecutors.newDirectExecutorService(),
-                                mContext));
+                                mTestDbHelper));
         mStaticMockSession =
                 ExtendedMockito.mockitoSession()
+                        .mockStatic(FederatedComputeJobScheduler.class)
                         .initMocks(this)
                         .strictness(Strictness.LENIENT)
                         .startMocking();
@@ -134,10 +145,9 @@ public class BackgroundKeyFetchJobServiceTest {
             mStaticMockSession.finishMocking();
         }
 
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -162,6 +172,20 @@ public class BackgroundKeyFetchJobServiceTest {
         verify(mMockEventLogger, times(1)).logEncryptionKeyFetchStartEventKind();
     }
 
+    @Test
+    public void onStartJobTestSpeEnabled() {
+        PhFlagsTestUtil.enableSpeBackgroundKeyFetchJob();
+
+        // Mock OdpJobScheduler to not actually schedule the job.
+        FederatedComputeJobScheduler mockedScheduler = mock(FederatedComputeJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> FederatedComputeJobScheduler.getInstance(any()));
+
+        assertThat(mSpyService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify SPE scheduler has rescheduled the job.
+        verify(mockedScheduler).schedule(any(), any());
+    }
+
     @Test
     public void testOnStartJob_onFailure() {
         OdpEncryptionKeyManager keyManager = mInjector.getEncryptionKeyManager(mContext);
@@ -188,8 +212,8 @@ public class BackgroundKeyFetchJobServiceTest {
 
         assertThat(
                         BackgroundKeyFetchJobService.scheduleJobIfNeeded(
-                                mContext, FlagsFactory.getFlags()))
-                .isEqualTo(true);
+                                mContext, FlagsFactory.getFlags(), /* forceSchedule */ false))
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
 
         final JobInfo scheduledJob =
                 jobScheduler.getPendingJob(
@@ -203,13 +227,26 @@ public class BackgroundKeyFetchJobServiceTest {
     public void testScheduleJob_notNeeded() {
         assertThat(
                         BackgroundKeyFetchJobService.scheduleJobIfNeeded(
-                                mContext, FlagsFactory.getFlags()))
-                .isEqualTo(true);
+                                mContext, FlagsFactory.getFlags(), /* forceSchedule */ false))
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
 
         assertThat(
                         BackgroundKeyFetchJobService.scheduleJobIfNeeded(
-                                mContext, FlagsFactory.getFlags()))
-                .isEqualTo(false);
+                                mContext, FlagsFactory.getFlags(), /* forceSchedule */ false))
+                .isEqualTo(SCHEDULING_RESULT_CODE_SKIPPED);
+    }
+
+    @Test
+    public void testScheduleJob_forceScheduleSuccessful() {
+        assertThat(
+                BackgroundKeyFetchJobService.scheduleJobIfNeeded(
+                        mContext, FlagsFactory.getFlags(), /* forceSchedule */ false))
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+
+        assertThat(
+                BackgroundKeyFetchJobService.scheduleJobIfNeeded(
+                        mContext, FlagsFactory.getFlags(), /* forceSchedule */ true))
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
     }
 
     @Test
@@ -217,8 +254,8 @@ public class BackgroundKeyFetchJobServiceTest {
         PhFlagsTestUtil.disableScheduleBackgroundKeyFetchJob();
 
         assertThat(BackgroundKeyFetchJobService.scheduleJobIfNeeded(
-                mContext, FlagsFactory.getFlags()
-        )).isEqualTo(false);
+                mContext, FlagsFactory.getFlags(), /* forceSchedule */ false
+        )).isEqualTo(SCHEDULING_RESULT_CODE_FAILED);
     }
 
     @Test
@@ -236,7 +273,8 @@ public class BackgroundKeyFetchJobServiceTest {
                 .fetchAndPersistActiveKeys(
                         KEY_TYPE_ENCRYPTION, /* isScheduledJob= */ true, Optional.empty());
         doReturn(mJobScheduler).when(mSpyService).getSystemService(JobScheduler.class);
-        mSpyService.scheduleJobIfNeeded(mContext, FlagsFactory.getFlags());
+        mSpyService
+                .scheduleJobIfNeeded(mContext, FlagsFactory.getFlags(), /* forceSchedule */ false);
         assertTrue(mJobScheduler.getPendingJob(
                 FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID)
                 != null);
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java
new file mode 100644
index 00000000..03ac6b3a
--- /dev/null
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java
@@ -0,0 +1,262 @@
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
+package com.android.federatedcompute.services.encryption;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
+
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.junit.Assert.assertThrows;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.common.FlagsFactory;
+import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
+import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobServiceFactory;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.odp.module.common.EventLogger;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+import java.util.List;
+import java.util.concurrent.ExecutionException;
+
+@MockStatic(FederatedComputeJobScheduler.class)
+@MockStatic(FederatedComputeJobServiceFactory.class)
+@MockStatic(BackgroundKeyFetchJobService.class)
+@MockStatic(FlagsFactory.class)
+@MockStatic(OdpEncryptionKeyManager.class)
+@MockStatic(BackgroundKeyFetchJobEventLogger.class)
+public final class BackgroundKeyFetchJobTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private BackgroundKeyFetchJob mBackgroundKeyFetchJob;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private ExecutionRuntimeParameters mMockParams;
+    @Mock
+    private FederatedComputeJobScheduler mMockFederatedComputeJobScheduler;
+    @Mock
+    private FederatedComputeJobServiceFactory mMockFederatedComputeJobServiceFactory;
+    @Mock
+    private EventLogger mMockBackgroundKeyFetchJobEventLogger;
+    @Mock
+    private OdpEncryptionKeyManager mMockOdpEncryptionKeyManager;
+
+    @Before
+    public void setup() throws Exception {
+        mBackgroundKeyFetchJob = new BackgroundKeyFetchJob(new TestInjector());
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockFederatedComputeJobScheduler)
+                .when(() -> FederatedComputeJobScheduler.getInstance(any()));
+        doReturn(mMockFederatedComputeJobServiceFactory)
+                .when(() -> FederatedComputeJobServiceFactory.getInstance(any()));
+        doReturn(FluentFuture.from(Futures.immediateFuture(List.of())))
+                .when(mMockOdpEncryptionKeyManager)
+                .fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any());
+    }
+
+    @Test
+    public void testGetExecutionFuture_executionSuccess() throws Exception {
+        ListenableFuture<ExecutionResult> executionFuture =
+                mBackgroundKeyFetchJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_executionSuccess()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.SUCCESS);
+    }
+
+    @Test
+    public void testGetExecutionFuture_executionFailure() {
+        doReturn(FluentFuture.from(Futures.immediateFailedFuture(new IllegalStateException())))
+                .when(mMockOdpEncryptionKeyManager)
+                .fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any());
+
+        ListenableFuture<ExecutionResult> executionFuture =
+                mBackgroundKeyFetchJob.getExecutionFuture(sContext, mMockParams);
+
+        assertThrows(ExecutionException.class, () -> executionFuture.get());
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(true);
+        when(mMockFlags.getEnableBackgroundEncryptionKeyFetch()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_enabled()")
+                .that(mBackgroundKeyFetchJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabledByGlobalKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(true);
+        when(mMockFlags.getEnableBackgroundEncryptionKeyFetch()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_disabledByGlobalKillSwitch()")
+                .that(mBackgroundKeyFetchJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabledBySpeOff() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(false);
+        when(mMockFlags.getEnableBackgroundEncryptionKeyFetch()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_disabledBySpeOff()")
+                .that(mBackgroundKeyFetchJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabledByBackgroundEncryptionFetchFlag() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(true);
+        when(mMockFlags.getEnableBackgroundEncryptionKeyFetch()).thenReturn(false);
+
+
+        assertWithMessage(
+                "testGetJobEnablementStatus_disabledByBackgroundEncryptionFetchFlag()")
+                .that(mBackgroundKeyFetchJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testSchedule_spe() {
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(true);
+
+        BackgroundKeyFetchJob.schedule(sContext);
+
+        verify(mMockFederatedComputeJobScheduler).schedule(eq(sContext), any());
+    }
+
+    @Test
+    public void testSchedule_legacy() {
+        int resultCode = SCHEDULING_RESULT_CODE_SUCCESSFUL;
+        when(mMockFlags.getSpeOnBackgroundKeyFetchJobEnabled()).thenReturn(false);
+
+        JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
+        when(mMockFederatedComputeJobServiceFactory
+                .getJobSchedulingLogger()).thenReturn(loggerMock);
+        doReturn(resultCode).when(() -> BackgroundKeyFetchJobService
+                .scheduleJobIfNeeded(any(), any(), /* forceSchedule */ eq(false)));
+
+        BackgroundKeyFetchJob.schedule(sContext);
+
+        verify(mMockFederatedComputeJobScheduler, never()).schedule(eq(sContext), any());
+        verify(() -> BackgroundKeyFetchJobService
+                .scheduleJobIfNeeded(any(), any(), /* forceSchedule */ eq(false)));
+        verify(loggerMock).recordOnSchedulingLegacy(ENCRYPTION_KEY_FETCH_JOB_ID, resultCode);
+    }
+
+    @Test
+    public void testCreateDefaultJobSpec() {
+        long expectedIntervalSeconds = 60L;
+        doReturn(expectedIntervalSeconds).when(mMockFlags).getEncryptionKeyFetchPeriodSeconds();
+        JobPolicy expectedJobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(ENCRYPTION_KEY_FETCH_JOB_ID)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(expectedIntervalSeconds * 1000)
+                                        .build())
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireDeviceIdle(true)
+                        .setNetworkType(NETWORK_TYPE_UNMETERED)
+                        .setIsPersisted(true)
+                        .build();
+
+        assertWithMessage("createDefaultJobSpec() for BackgroundKeyFetchJob")
+                .that(BackgroundKeyFetchJob.createDefaultJobSpec())
+                .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for BackgroundKeyFetchJob")
+                .that(new BackgroundKeyFetchJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+
+    public class TestInjector extends BackgroundKeyFetchJob.Injector {
+        @Override
+        ListeningExecutorService getLightWeightExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        OdpEncryptionKeyManager getEncryptionKeyManager(Context context) {
+            return mMockOdpEncryptionKeyManager;
+        }
+
+        @Override
+        EventLogger getEventLogger() {
+            return mMockBackgroundKeyFetchJobEventLogger;
+        }
+
+        @Override
+        ListeningExecutorService getExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+    }
+}
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java
index 9421e3a4..91e8c112 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/FederatedComputeEncryptionKeyManagerUtilsTest.java
@@ -61,16 +61,19 @@ public class FederatedComputeEncryptionKeyManagerUtilsTest {
 { "keys": [{ "id": "0cc9b4c9-08bd", "key": "BQo+c1Tw6TaQ+VH/b+9PegZOjHuKAFkl8QdmS0IjRj8" """
                     + "} ] }";
 
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
     @Mock private HttpClient mMockHttpClient;
 
     @Mock private OdpEncryptionKeyDao mMockEncryptionKeyDao;
 
-    private static final Context sContext = ApplicationProvider.getApplicationContext();
 
     private Clock mClock;
 
     private Flags mMockFlags;
 
+    private FederatedComputeDbHelper mTestDbHelper;
+
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
@@ -78,14 +81,16 @@ public class FederatedComputeEncryptionKeyManagerUtilsTest {
         mMockFlags = Mockito.mock(Flags.class);
         String overrideUrl = "https://real-coordinator/v1alpha/publicKeys";
         doReturn(overrideUrl).when(mMockFlags).getEncryptionKeyFetchUrl();
+
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(sContext);
+        OdpEncryptionKeyManager.resetForTesting();
     }
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(sContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -111,7 +116,7 @@ public class FederatedComputeEncryptionKeyManagerUtilsTest {
                         mMockFlags,
                         mMockHttpClient,
                         MoreExecutors.newDirectExecutorService(),
-                        sContext);
+                        mTestDbHelper);
         OdpEncryptionKeyManager secondInstance =
                 FederatedComputeEncryptionKeyManagerUtils.getInstanceForTest(
                         mClock,
@@ -119,12 +124,12 @@ public class FederatedComputeEncryptionKeyManagerUtilsTest {
                         mMockFlags,
                         mMockHttpClient,
                         MoreExecutors.newDirectExecutorService(),
-                        sContext);
+                        mTestDbHelper);
 
         assertThat(instanceUnderTest).isSameInstanceAs(secondInstance);
         assertNotNull(instanceUnderTest);
         assertThat(instanceUnderTest).isInstanceOf(OdpEncryptionKeyManager.class);
         assertThat(instanceUnderTest.getKeyManagerConfigForTesting().getSQLiteOpenHelper())
-                .isSameInstanceAs(FederatedComputeDbHelper.getInstanceForTest(sContext));
+                .isSameInstanceAs(mTestDbHelper);
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
index c693084e..4f11d4f1 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/http/HttpFederatedProtocolTest.java
@@ -53,6 +53,7 @@ import android.net.Uri;
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.common.NetworkStats;
 import com.android.federatedcompute.services.common.PhFlags;
 import com.android.federatedcompute.services.common.TrainingEventLogger;
@@ -64,8 +65,8 @@ import com.android.federatedcompute.services.training.util.ComputationResult;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationToken;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationToken;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 import com.android.odp.module.common.encryption.HpkeJniEncrypter;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
 import com.android.odp.module.common.http.HttpClient;
@@ -233,7 +234,8 @@ public final class HttpFederatedProtocolTest {
     private ArgumentCaptor<NetworkStats> mNetworkStatsArgumentCaptor =
             ArgumentCaptor.forClass(NetworkStats.class);
 
-    private ODPAuthorizationTokenDao mODPAuthorizationTokenDao;
+    private FederatedComputeDbHelper mTestDbHelper;
+    private OdpAuthorizationTokenDao mOdpAuthorizationTokenDao;
 
     private final Clock mClock = MonotonicClock.getInstance();
 
@@ -243,9 +245,11 @@ public final class HttpFederatedProtocolTest {
 
     @Before
     public void setUp() throws Exception {
-        mODPAuthorizationTokenDao =
-                ODPAuthorizationTokenDao.getInstanceForTest(
-                        FederatedComputeDbHelper.getInstanceForTest(sTestContent));
+        // Clear any existing data in the token dao.
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(sTestContent);
+        mOdpAuthorizationTokenDao = OdpAuthorizationTokenDao.getInstanceForTest(mTestDbHelper);
+        mOdpAuthorizationTokenDao.deleteAuthorizationToken(OWNER_ID);
+
         mHttpFederatedProtocol =
                 new HttpFederatedProtocol(
                         TASK_ASSIGNMENT_TARGET_URI,
@@ -254,24 +258,25 @@ public final class HttpFederatedProtocolTest {
                         mMockHttpClient,
                         new HpkeJniEncrypter(),
                         mTrainingEventLogger);
-        doReturn(KA_RECORD).when(mMockKeyAttestation).generateAttestationRecord(any(), any());
+        doReturn(KA_RECORD)
+                .when(mMockKeyAttestation)
+                .generateAttestationRecord(any(), any(), any());
         doNothing().when(mTrainingEventLogger).logReportResultUnauthorized();
         doNothing().when(mTrainingEventLogger).logReportResultAuthSucceeded();
         doNothing().when(mTrainingEventLogger).logTaskAssignmentUnauthorized();
         doNothing().when(mTrainingEventLogger).logTaskAssignmentAuthSucceeded();
         doReturn(true).when(mMocKFlags).isEncryptionEnabled();
-        when(PhFlags.getInstance()).thenReturn(mMocKFlags);
+        when(FlagsFactory.getFlags()).thenReturn(mMocKFlags);
         when(mMocKFlags.getFcpCheckpointFileSizeLimit())
                 .thenReturn(Flags.FCP_DEFAULT_CHECKPOINT_FILE_SIZE_LIMIT);
     }
 
     @After
     public void cleanUp() {
-        FederatedComputeDbHelper dbHelper =
-                FederatedComputeDbHelper.getInstanceForTest(sTestContent);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -401,9 +406,9 @@ public final class HttpFederatedProtocolTest {
     public void testIssueCheckin_withAuthToken_success() throws Exception {
 
         // insert authorization token
-        ODPAuthorizationToken authToken = createAuthToken();
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken);
-        assertThat(mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
+        OdpAuthorizationToken authToken = createAuthToken();
+        mOdpAuthorizationTokenDao.insertAuthorizationToken(authToken);
+        assertThat(mOdpAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
                 .isEqualTo(authToken);
         setUpHttpFederatedProtocol();
 
@@ -428,7 +433,7 @@ public final class HttpFederatedProtocolTest {
                 .isEqualTo(false);
 
         // the old authorization token is not deleted
-        assertThat(mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
+        assertThat(mOdpAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
                 .isEqualTo(authToken);
     }
 
@@ -506,12 +511,12 @@ public final class HttpFederatedProtocolTest {
         verify(mTrainingEventLogger, times(1)).logTaskAssignmentAuthSucceeded();
         // A new authorization token is stored in DB
         assertThat(
-                        mODPAuthorizationTokenDao
+                        mOdpAuthorizationTokenDao
                                 .getUnexpiredAuthorizationToken(OWNER_ID)
                                 .getAuthorizationToken())
                 .isNotNull();
         assertThat(
-                        mODPAuthorizationTokenDao
+                        mOdpAuthorizationTokenDao
                                 .getUnexpiredAuthorizationToken(OWNER_ID)
                                 .getOwnerIdentifier())
                 .isEqualTo(OWNER_ID);
@@ -1133,9 +1138,9 @@ public final class HttpFederatedProtocolTest {
 
     private void insertAuthToken() {
         // insert authorization token
-        ODPAuthorizationToken authToken = createAuthToken();
-        mODPAuthorizationTokenDao.insertAuthorizationToken(authToken);
-        assertThat(mODPAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
+        OdpAuthorizationToken authToken = createAuthToken();
+        mOdpAuthorizationTokenDao.insertAuthorizationToken(authToken);
+        assertThat(mOdpAuthorizationTokenDao.getUnexpiredAuthorizationToken(OWNER_ID))
                 .isEqualTo(authToken);
     }
 
@@ -1143,9 +1148,10 @@ public final class HttpFederatedProtocolTest {
         return new AuthorizationContext(
                 OWNER_ID,
                 OWNER_ID_CERT_DIGEST,
-                mODPAuthorizationTokenDao,
+                mOdpAuthorizationTokenDao,
                 mMockKeyAttestation,
-                mClock);
+                mClock,
+                mTrainingEventLogger);
     }
 
     private AuthorizationContext createAuthContextWithAttestationRecord() {
@@ -1153,9 +1159,10 @@ public final class HttpFederatedProtocolTest {
                 new AuthorizationContext(
                         OWNER_ID,
                         OWNER_ID_CERT_DIGEST,
-                        mODPAuthorizationTokenDao,
+                        mOdpAuthorizationTokenDao,
                         mMockKeyAttestation,
-                        mClock);
+                        mClock,
+                        mTrainingEventLogger);
         // Pretend 1st try failed.
         authContext.updateAuthState(AUTH_METADATA, mTrainingEventLogger);
         return authContext;
@@ -1328,8 +1335,8 @@ public final class HttpFederatedProtocolTest {
         return CreateTaskAssignmentResponse.newBuilder().setTaskAssignment(taskAssignment).build();
     }
 
-    private ODPAuthorizationToken createAuthToken() {
-        return new ODPAuthorizationToken.Builder(
+    private OdpAuthorizationToken createAuthToken() {
+        return new OdpAuthorizationToken.Builder(
                         OWNER_ID,
                         TOKEN,
                         mClock.currentTimeMillis(),
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
index d40ee5b1..80c369ba 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobServiceTest.java
@@ -18,6 +18,7 @@ package com.android.federatedcompute.services.scheduling;
 
 import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.odp.module.common.FileUtils.createTempFile;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -40,7 +41,6 @@ import android.app.job.JobParameters;
 import android.app.job.JobScheduler;
 import android.content.Context;
 import android.database.DatabaseUtils;
-import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
 
 import androidx.test.core.app.ApplicationProvider;
@@ -53,15 +53,17 @@ import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
 import com.android.federatedcompute.services.data.TaskHistory;
+import com.android.federatedcompute.services.data.TaskHistoryContract;
 import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJobScheduler;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationToken;
-import com.android.odp.module.common.data.ODPAuthorizationTokenContract;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationToken;
+import com.android.odp.module.common.data.OdpAuthorizationTokenContract;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
+import com.google.common.collect.ImmutableList;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
 
@@ -72,10 +74,14 @@ import org.junit.Test;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
+import java.io.File;
+import java.time.Duration;
+import java.util.Arrays;
 import java.util.UUID;
 
 @MockStatic(FlagsFactory.class)
 public class DeleteExpiredJobServiceTest {
+
     @Rule(order = 0)
     public final ExtendedMockitoRule extendedMockitoRule =
             new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
@@ -83,47 +89,65 @@ public class DeleteExpiredJobServiceTest {
     private static final String TAG = DeleteExpiredJobServiceTest.class.getSimpleName();
     private static final String POPULATION_NAME = "population_name";
     private static final int JOB_ID = 123;
+
+    private static final long TEST_CURRENT_TIME = 400L;
+    public static final long TEST_TTL = 200L;
+
     private static final String TASK_ID = "task_id";
+    private static final Duration THREAD_SLEEP = Duration.ofSeconds(5);
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private static final String TEST_EXPIRED_TOKEN1 = "expired1";
+    private static final String TEST_EXPIRED_TOKEN2 = "expired3";
+    private static final String TEST_UNEXPIRED_TOKEN = "unexpired";
+
+    private static final ImmutableList<String> TEST_OWNER_IDS =
+            ImmutableList.of(TEST_EXPIRED_TOKEN1, TEST_EXPIRED_TOKEN2, TEST_UNEXPIRED_TOKEN);
     private DeleteExpiredJobService mSpyService;
 
-    private ODPAuthorizationTokenDao mSpyAuthTokenDao;
+    private OdpAuthorizationTokenDao mSpyAuthTokenDao;
+
+    private FederatedComputeDbHelper mTestDbHelper;
     private FederatedTrainingTaskDao mTrainingTaskDao;
 
-    private Context mContext;
     private JobScheduler mJobScheduler;
     @Mock private Clock mClock;
     @Mock private Flags mMockFlag;
+    private Context mContext;
 
     @Before
     public void setUp() throws Exception {
+        mContext = ApplicationProvider.getApplicationContext();
         doReturn(mMockFlag).when(FlagsFactory::getFlags);
         when(mMockFlag.getGlobalKillSwitch()).thenReturn(false);
 
         // By default, disable SPE.
         when(mMockFlag.getSpePilotJobEnabled()).thenReturn(false);
 
-        mContext = ApplicationProvider.getApplicationContext();
-        when(mClock.currentTimeMillis()).thenReturn(400L);
-        when(mMockFlag.getTaskHistoryTtl()).thenReturn(200L);
+        when(mClock.currentTimeMillis()).thenReturn(TEST_CURRENT_TIME);
+        when(mMockFlag.getTaskHistoryTtl()).thenReturn(TEST_TTL);
+
         LogUtil.i(TAG, "mSpyAuthTokenDao " + mSpyAuthTokenDao);
-        mSpyAuthTokenDao =
-                spy(
-                        ODPAuthorizationTokenDao.getInstanceForTest(
-                                FederatedComputeDbHelper.getInstanceForTest(mContext)));
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(sContext);
+        mSpyAuthTokenDao = spy(OdpAuthorizationTokenDao.getInstanceForTest(mTestDbHelper));
+        clearTokenDao(mSpyAuthTokenDao);
+
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mTestDbHelper);
+        // Force delete any existing data in the dao
+        mTrainingTaskDao.deleteExpiredTaskHistory(/* deleteTime= */ Long.MAX_VALUE);
         mSpyService = spy(new DeleteExpiredJobService(new TestInjector()));
 
-        mJobScheduler = mContext.getSystemService(JobScheduler.class);
+        mJobScheduler = sContext.getSystemService(JobScheduler.class);
         mJobScheduler.cancel(FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID);
         doNothing().when(mSpyService).jobFinished(any(), anyBoolean());
     }
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -134,28 +158,27 @@ public class DeleteExpiredJobServiceTest {
 
     @Test
     public void deleteExpiredAuthToken_success() throws Exception {
-        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken("expired1"));
-        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken("expired2"));
-        mSpyAuthTokenDao.insertAuthorizationToken(createUnexpiredAuthToken("unexpired"));
+        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken(TEST_EXPIRED_TOKEN1));
+        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken(TEST_EXPIRED_TOKEN2));
+        mSpyAuthTokenDao.insertAuthorizationToken(createUnexpiredAuthToken(TEST_UNEXPIRED_TOKEN));
 
         mSpyService.onStartJob(mock(JobParameters.class));
 
         // TODO(b/326444021): remove thread sleep after use JobServiceCallback.
-        Thread.sleep(5000);
+        Thread.sleep(THREAD_SLEEP.toMillis());
         verify(mSpyService).jobFinished(any(), eq(false));
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                mTestDbHelper.getReadableDatabase(),
+                                OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(1);
     }
 
     @Test
     public void deleteExpiredAuthToken_failure() throws Exception {
-        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken("expired1"));
-        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken("expired2"));
-        mSpyAuthTokenDao.insertAuthorizationToken(createUnexpiredAuthToken("unexpired"));
+        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken(TEST_EXPIRED_TOKEN1));
+        mSpyAuthTokenDao.insertAuthorizationToken(createExpiredAuthToken(TEST_EXPIRED_TOKEN2));
+        mSpyAuthTokenDao.insertAuthorizationToken(createUnexpiredAuthToken(TEST_UNEXPIRED_TOKEN));
         doThrow(new SQLiteException("exception"))
                 .when(mSpyAuthTokenDao)
                 .deleteExpiredAuthorizationTokens();
@@ -163,20 +186,27 @@ public class DeleteExpiredJobServiceTest {
         mSpyService.onStartJob(mock(JobParameters.class));
 
         // TODO(b/326444021): remove thread sleep after use JobServiceCallback.
-        Thread.sleep(2000);
+        Thread.sleep(THREAD_SLEEP.toMillis());
         verify(mSpyService).jobFinished(any(), eq(false));
         verify(mSpyAuthTokenDao).deleteExpiredAuthorizationTokens();
-        SQLiteDatabase db =
-                FederatedComputeDbHelper.getInstanceForTest(mContext).getReadableDatabase();
         assertThat(
                         DatabaseUtils.queryNumEntries(
-                                db, ODPAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
+                                mTestDbHelper.getReadableDatabase(),
+                                OdpAuthorizationTokenContract.ODP_AUTHORIZATION_TOKEN_TABLE))
                 .isEqualTo(3);
     }
 
     @Test
     public void deletedExpiredTaskHistory_success() throws Exception {
-        // record1 is expired because contribution time (100) < current time (400) - ttl (200).
+        // Ensure the task history table is empty prior to the test.
+        assertThat(
+                        DatabaseUtils.queryNumEntries(
+                                mTestDbHelper.getReadableDatabase(),
+                                TaskHistoryContract.TaskHistoryEntry.TABLE_NAME))
+                .isEqualTo(0);
+        // record1 is expired because its contribution time (100) < TEST_CURRENT_TIME (400) -
+        // TEST_TTL (200). The DeleteExpiredJobService should delete it and remove it from the
+        // TrainingTaskDao.
         TaskHistory record1 =
                 new TaskHistory.Builder()
                         .setJobId(JOB_ID)
@@ -195,15 +225,16 @@ public class DeleteExpiredJobServiceTest {
                         .setTotalParticipation(3)
                         .setContributionTime(300)
                         .build();
-        mTrainingTaskDao.updateOrInsertTaskHistory(record1);
-        mTrainingTaskDao.updateOrInsertTaskHistory(record2);
+
+        assertTrue(mTrainingTaskDao.updateOrInsertTaskHistory(record1));
+        assertTrue(mTrainingTaskDao.updateOrInsertTaskHistory(record2));
         assertThat(mTrainingTaskDao.getTaskHistoryList(JOB_ID, POPULATION_NAME, TASK_ID))
                 .containsExactly(record1, record2);
 
         mSpyService.onStartJob(mock(JobParameters.class));
 
         // TODO(b/326444021): remove thread sleep after use JobServiceCallback.
-        Thread.sleep(2000);
+        Thread.sleep(THREAD_SLEEP.toMillis());
         verify(mSpyService).jobFinished(any(), eq(false));
         assertThat(mTrainingTaskDao.getTaskHistoryList(JOB_ID, POPULATION_NAME, TASK_ID))
                 .containsExactly(record2);
@@ -216,7 +247,7 @@ public class DeleteExpiredJobServiceTest {
 
         assertThat(
                         DeleteExpiredJobService.scheduleJobIfNeeded(
-                                mContext, FlagsFactory.getFlags(), /* forceSchedule= */ false))
+                                sContext, FlagsFactory.getFlags(), /* forceSchedule= */ false))
                 .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
 
         assertNotNull(mJobScheduler.getPendingJob(FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID));
@@ -252,16 +283,72 @@ public class DeleteExpiredJobServiceTest {
 
         assertThat(injector.getExecutor())
                 .isEqualTo(FederatedComputeExecutors.getBackgroundExecutor());
-        assertThat(injector.getODPAuthorizationTokenDao(mContext))
+        assertThat(injector.getODPAuthorizationTokenDao(sContext))
                 .isEqualTo(
-                        ODPAuthorizationTokenDao.getInstance(
-                                FederatedComputeDbHelper.getInstance(mContext)));
+                        OdpAuthorizationTokenDao.getInstance(
+                                FederatedComputeDbHelper.getInstance(sContext)));
+    }
+
+    @Test
+    public void deleteCacheDirectory_success() throws Exception {
+        when(mMockFlag.getTempFileTtlMillis()).thenReturn(0L);
+        createTempFile("input", ".ckp");
+        createTempFile("output", ".ckp");
+        // Verify cache directory has created files.
+        long matchFileCount =
+                Arrays.stream(mContext.getCacheDir().listFiles())
+                        .filter(f -> mSpyService.isFileMatched(f.getName()))
+                        .count();
+        assertThat(matchFileCount).isEqualTo(2);
+
+        mSpyService.onStartJob(mock(JobParameters.class));
+
+        Thread.sleep(THREAD_SLEEP.toMillis());
+        verify(mSpyService).jobFinished(any(), eq(false));
+
+        // Verify cache directory is empty after deletion job.
+        File[] files = mContext.getCacheDir().listFiles();
+        matchFileCount =
+                Arrays.stream(mContext.getCacheDir().listFiles())
+                        .filter(f -> mSpyService.isFileMatched(f.getName()))
+                        .count();
+        assertThat(matchFileCount).isEqualTo(0);
+    }
+
+    @Test
+    public void deleteCacheDirectory_fileNotMatch() throws Exception {
+        when(mMockFlag.getTempFileTtlMillis()).thenReturn(0L);
+        createTempFile("metadata", ".ckp");
+        assertThat(mContext.getCacheDir().listFiles()).isNotEmpty();
+
+        mSpyService.onStartJob(mock(JobParameters.class));
+
+        Thread.sleep(THREAD_SLEEP.toMillis());
+        verify(mSpyService).jobFinished(any(), eq(false));
+
+        // Verify cache directory is empty after deletion job.
+        File[] files = mContext.getCacheDir().listFiles();
+        long matchFileCount =
+                Arrays.stream(mContext.getCacheDir().listFiles())
+                        .filter(f -> mSpyService.isFileMatched(f.getName()))
+                        .count();
+        assertThat(files.length).isAtLeast(1);
+        assertThat(matchFileCount).isEqualTo(0);
     }
 
-    private ODPAuthorizationToken createExpiredAuthToken(String ownerId) {
+    private static void clearTokenDao(OdpAuthorizationTokenDao tokenDao) {
+        // Force clear any existing auth tokens before tests
+
+        for (String ownerIdentifier : TEST_OWNER_IDS) {
+            tokenDao.deleteAuthorizationToken(ownerIdentifier);
+        }
+    }
+
+    private static OdpAuthorizationToken createExpiredAuthToken(String ownerId) {
+        // Create an already expired token with expiry time in the past.
         long now = MonotonicClock.getInstance().currentTimeMillis();
-        ODPAuthorizationToken token =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken token =
+                new OdpAuthorizationToken.Builder()
                         .setAuthorizationToken(UUID.randomUUID().toString())
                         .setOwnerIdentifier(ownerId)
                         .setCreationTime(now)
@@ -270,11 +357,12 @@ public class DeleteExpiredJobServiceTest {
         return token;
     }
 
-    private ODPAuthorizationToken createUnexpiredAuthToken(String ownerId) {
+    private static OdpAuthorizationToken createUnexpiredAuthToken(String ownerId) {
+        // Create an unexpired token with a TTL of 24 hours.
         long now = MonotonicClock.getInstance().currentTimeMillis();
         long ttl = 24 * 60 * 60 * 1000L;
-        ODPAuthorizationToken token =
-                new ODPAuthorizationToken.Builder()
+        OdpAuthorizationToken token =
+                new OdpAuthorizationToken.Builder()
                         .setAuthorizationToken(UUID.randomUUID().toString())
                         .setOwnerIdentifier(ownerId)
                         .setCreationTime(now)
@@ -283,14 +371,14 @@ public class DeleteExpiredJobServiceTest {
         return token;
     }
 
-    class TestInjector extends DeleteExpiredJobService.Injector {
+    private class TestInjector extends DeleteExpiredJobService.Injector {
         @Override
         ListeningExecutorService getExecutor() {
             return MoreExecutors.newDirectExecutorService();
         }
 
         @Override
-        ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
+        OdpAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
             return mSpyAuthTokenDao;
         }
 
@@ -299,6 +387,11 @@ public class DeleteExpiredJobServiceTest {
             return mTrainingTaskDao;
         }
 
+        @Override
+        File getCacheDir(Context context) {
+            return mContext.getCacheDir();
+        }
+
         @Override
         Clock getClock() {
             return mClock;
@@ -308,5 +401,10 @@ public class DeleteExpiredJobServiceTest {
         Flags getFlags() {
             return mMockFlag;
         }
+
+        @Override
+        long getMinimumTempFileTtlMillis() {
+            return 0;
+        }
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
index c1eadfe4..4067e76c 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
@@ -54,7 +54,7 @@ import com.android.federatedcompute.services.sharedlibrary.spe.FederatedComputeJ
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.Clock;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
@@ -87,7 +87,7 @@ public class DeleteExpiredJobTest {
     @Mock private FederatedComputeJobScheduler mMockFederatedComputeJobScheduler;
     @Mock private FederatedComputeJobServiceFactory mMockFederatedComputeJobServiceFactory;
 
-    @Mock private ODPAuthorizationTokenDao mMockOdpAuthorizationTokenDao;
+    @Mock private OdpAuthorizationTokenDao mMockOdpAuthorizationTokenDao;
     @Mock private FederatedTrainingTaskDao mMockFederatedTrainingTaskDao;
     @Mock private Clock mMockClock;
 
@@ -202,7 +202,7 @@ public class DeleteExpiredJobTest {
         }
 
         @Override
-        ODPAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
+        OdpAuthorizationTokenDao getODPAuthorizationTokenDao(Context context) {
             return mMockOdpAuthorizationTokenDao;
         }
 
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManagerTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManagerTest.java
index 3850e65f..2740b31d 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManagerTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManagerTest.java
@@ -119,6 +119,9 @@ public final class FederatedComputeJobManagerTest {
             TaskRetry.newBuilder().setDelayMin(5000000).setDelayMax(6000000).build();
     private FederatedComputeJobManager mJobManager;
     private Context mContext;
+
+    private FederatedComputeDbHelper mTestDbHelper;
+
     private FederatedTrainingTaskDao mTrainingTaskDao;
     @Mock private Clock mClock;
     @Mock private Flags mMockFlags;
@@ -146,7 +149,8 @@ public final class FederatedComputeJobManagerTest {
                         .build();
         mJobScheduler = mContext.getSystemService(JobScheduler.class);
         mJobScheduler.cancelAll();
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(mContext);
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mTestDbHelper);
         mJobManager =
                 new FederatedComputeJobManager(
                         mContext,
@@ -173,10 +177,9 @@ public final class FederatedComputeJobManagerTest {
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelperTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelperTest.java
index 0b38ec7a..9005c744 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelperTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelperTest.java
@@ -158,6 +158,7 @@ public class JobSchedulerHelperTest {
         assertThat(jobInfo.isRequireDeviceIdle()).isFalse();
         assertThat(jobInfo.isRequireBatteryNotLow()).isTrue();
         assertThat(jobInfo.getNetworkType()).isEqualTo(NETWORK_TYPE_UNMETERED);
+        assertDefaultJobRequirements(jobInfo);
     }
 
     @Test
@@ -178,6 +179,7 @@ public class JobSchedulerHelperTest {
         assertThat(jobInfo.isRequireDeviceIdle()).isTrue();
         assertThat(jobInfo.isRequireBatteryNotLow()).isTrue();
         assertThat(jobInfo.getNetworkType()).isEqualTo(NETWORK_TYPE_ANY);
+        assertDefaultJobRequirements(jobInfo);
     }
 
     @Test
@@ -198,6 +200,7 @@ public class JobSchedulerHelperTest {
         assertThat(jobInfo.isRequireDeviceIdle()).isTrue();
         assertThat(jobInfo.isRequireBatteryNotLow()).isFalse();
         assertThat(jobInfo.getNetworkType()).isEqualTo(NETWORK_TYPE_UNMETERED);
+        assertDefaultJobRequirements(jobInfo);
     }
 
     @Test
@@ -243,4 +246,9 @@ public class JobSchedulerHelperTest {
                         builder, SchedulingMode.ONE_TIME, 0));
         return builder.sizedByteArray();
     }
+
+    private void assertDefaultJobRequirements(JobInfo jobInfo) {
+        assertThat(jobInfo.isRequireStorageNotLow()).isTrue();
+        assertThat(jobInfo.isPersisted()).isTrue();
+    }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
index 429d6d96..509811ed 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/AuthorizationContextTest.java
@@ -25,17 +25,15 @@ import static com.google.common.truth.Truth.assertThat;
 import static junit.framework.Assert.assertFalse;
 import static junit.framework.Assert.assertNotNull;
 import static junit.framework.Assert.assertNull;
-import static junit.framework.Assert.assertTrue;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.timeout;
-import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
 import android.content.Context;
@@ -46,8 +44,8 @@ import com.android.federatedcompute.services.common.TrainingEventLogger;
 import com.android.federatedcompute.services.data.FederatedComputeDbHelper;
 import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationToken;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationToken;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 
 import com.google.internal.federatedcompute.v1.AuthenticationMetadata;
 import com.google.internal.federatedcompute.v1.KeyAttestationAuthMetadata;
@@ -81,28 +79,30 @@ public class AuthorizationContextTest {
     @Mock private KeyAttestation mMocKeyAttestation;
 
     @Mock private TrainingEventLogger mMockTrainingEventLogger;
-    private ODPAuthorizationTokenDao mAuthTokenDao;
+    private FederatedComputeDbHelper mTestDbHelper;
+    private OdpAuthorizationTokenDao mAuthTokenDao;
     private Clock mClock;
 
     @Before
     public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
         mContext = ApplicationProvider.getApplicationContext();
-        doReturn(KA_RECORD).when(mMocKeyAttestation).generateAttestationRecord(any(), anyString());
-        mAuthTokenDao =
-                spy(
-                        ODPAuthorizationTokenDao.getInstanceForTest(
-                                FederatedComputeDbHelper.getInstanceForTest(mContext)));
+        doReturn(KA_RECORD)
+                .when(mMocKeyAttestation)
+                .generateAttestationRecord(any(), anyString(), any());
         mClock = MonotonicClock.getInstance();
+        doNothing().when(mMockTrainingEventLogger).logEventKind(anyInt());
         doNothing().when(mMockTrainingEventLogger).logKeyAttestationLatencyEvent(anyLong());
+
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(mContext);
+        mAuthTokenDao = spy(OdpAuthorizationTokenDao.getInstanceForTest(mTestDbHelper));
     }
 
     @After
     public void tearDown() throws Exception {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -113,13 +113,13 @@ public class AuthorizationContextTest {
                         OWNER_ID_CERT_DIGEST,
                         mAuthTokenDao,
                         mMocKeyAttestation,
-                        MonotonicClock.getInstance());
+                        MonotonicClock.getInstance(),
+                        mMockTrainingEventLogger);
 
         authContext.updateAuthState(AUTH_METADATA, mMockTrainingEventLogger);
 
         assertFalse(authContext.isFirstAuthTry());
         assertNotNull(authContext.getAttestationRecord());
-        verify(mMockTrainingEventLogger, timeout(1)).logKeyAttestationLatencyEvent(anyLong());
     }
 
     @Test
@@ -130,10 +130,11 @@ public class AuthorizationContextTest {
                         OWNER_ID_CERT_DIGEST,
                         mAuthTokenDao,
                         mMocKeyAttestation,
-                        MonotonicClock.getInstance());
+                        MonotonicClock.getInstance(),
+                        mMockTrainingEventLogger);
 
         Map<String, String> headers = authContext.generateAuthHeaders();
-        assertTrue(headers.isEmpty());
+        assertThat(headers).isEmpty();
         assertNull(mAuthTokenDao.getUnexpiredAuthorizationToken(OWNER_ID));
     }
 
@@ -146,7 +147,8 @@ public class AuthorizationContextTest {
                         OWNER_ID_CERT_DIGEST,
                         mAuthTokenDao,
                         mMocKeyAttestation,
-                        MonotonicClock.getInstance());
+                        MonotonicClock.getInstance(),
+                        mMockTrainingEventLogger);
 
         Map<String, String> headers = authContext.generateAuthHeaders();
         assertThat(headers.get(ODP_AUTHORIZATION_KEY)).isEqualTo(TOKEN);
@@ -160,7 +162,8 @@ public class AuthorizationContextTest {
                         OWNER_ID_CERT_DIGEST,
                         mAuthTokenDao,
                         mMocKeyAttestation,
-                        MonotonicClock.getInstance());
+                        MonotonicClock.getInstance(),
+                        mMockTrainingEventLogger);
 
         CountDownLatch latch = new CountDownLatch(1);
         doAnswer(
@@ -170,23 +173,22 @@ public class AuthorizationContextTest {
                             return true;
                         })
                 .when(mAuthTokenDao)
-                .insertAuthorizationToken(any(ODPAuthorizationToken.class));
+                .insertAuthorizationToken(any(OdpAuthorizationToken.class));
         authContext.updateAuthState(AUTH_METADATA, mMockTrainingEventLogger);
         assertNull(mAuthTokenDao.getUnexpiredAuthorizationToken(OWNER_ID));
-        verify(mMockTrainingEventLogger, times(1)).logKeyAttestationLatencyEvent(anyLong());
 
         Map<String, String> headerMap = authContext.generateAuthHeaders();
         latch.await();
 
         assertNotNull(headerMap.get(ODP_AUTHORIZATION_KEY));
         assertNotNull(mAuthTokenDao.getUnexpiredAuthorizationToken(OWNER_ID));
-        verify(mMocKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString());
+        verify(mMocKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString(), any());
     }
 
     private void insertAuthToken() {
         // insert authorization token
-        ODPAuthorizationToken authToken =
-                new ODPAuthorizationToken.Builder(
+        OdpAuthorizationToken authToken =
+                new OdpAuthorizationToken.Builder(
                                 OWNER_ID,
                                 TOKEN,
                                 mClock.currentTimeMillis(),
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
index cb80e4b8..84c8b5dc 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/security/KeyAttestationTest.java
@@ -16,28 +16,43 @@
 
 package com.android.federatedcompute.services.security;
 
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_CERTIFICATE_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_KEYSTORE_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_ALGORITHM_EXCEPTION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_PROVIDER_EXCEPTION;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
+import com.android.federatedcompute.services.common.TrainingEventLogger;
+import com.android.odp.module.common.Clock;
+
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-import java.security.InvalidAlgorithmParameterException;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.KeyStore;
 import java.security.KeyStoreException;
-import java.security.ProviderException;
+import java.security.NoSuchAlgorithmException;
+import java.security.NoSuchProviderException;
 import java.security.cert.Certificate;
 import java.security.cert.CertificateException;
 import java.util.List;
@@ -58,8 +73,11 @@ public final class KeyAttestationTest {
     @Mock private KeyStore mMockKeyStore;
 
     @Mock private KeyPairGenerator mMockKeyPairGenerator;
+    @Mock private TrainingEventLogger mTrainingEventLogger;
 
     @Mock private Certificate mMockCert;
+    @Captor private ArgumentCaptor<Integer> mEventKindCaptor;
+    @Mock private Clock mMockClock;
 
     @Before
     public void setUp() throws Exception {
@@ -67,30 +85,41 @@ public final class KeyAttestationTest {
         mKeyAttestation =
                 KeyAttestation.getInstanceForTest(
                         ApplicationProvider.getApplicationContext(), new TestInjector());
+        doNothing().when(mTrainingEventLogger).logEventKind(mEventKindCaptor.capture());
+        doNothing().when(mTrainingEventLogger).logKeyAttestationLatencyEvent(anyLong());
+        when(mMockClock.currentTimeMillis()).thenReturn(10L, 20L, 30L);
     }
 
     @Test
     public void testGenerateAttestationRecord_nullKey() {
         doReturn(null).when(mMockKeyPairGenerator).generateKeyPair();
 
-        List<String> record = mKeyAttestation.generateAttestationRecord(CHALLENGE, CALLING_APP);
+        List<String> record =
+                mKeyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
 
         assertThat(record).isEmpty();
     }
 
     @Test
-    public void testGenerateHybridKey_initFailure() throws Exception {
-        doThrow(new InvalidAlgorithmParameterException("Invalid Parameters"))
-                .when(mMockKeyPairGenerator)
-                .initialize(any());
+    public void testGenerateHybridKey_noSuchAlgoFailure() {
+        KeyAttestation keyAttestation =
+                KeyAttestation.getInstanceForTest(
+                        ApplicationProvider.getApplicationContext(),
+                        new TestInjectorWithNoSuchAlgoException());
 
-        KeyPair keyPair = mKeyAttestation.generateHybridKey(CHALLENGE, KEY_ALIAS);
+        List<String> record =
+                keyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
 
-        assertThat(keyPair).isNull();
+        assertThat(mEventKindCaptor.getValue())
+                .isEqualTo(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_ALGORITHM_EXCEPTION);
+        assertThat(record).isEmpty();
     }
 
     @Test
-    public void testGetAttestationRecordFromKeyAlias_noKey() {
+    public void testGetAttestationRecordFromKeyAlias_noKey() throws Exception {
         String keyAlias2 = CALLING_APP + "-ODPKeyAttestation2";
 
         KeyPair unused = mKeyAttestation.generateHybridKey(CHALLENGE, KEY_ALIAS);
@@ -101,30 +130,49 @@ public final class KeyAttestationTest {
 
     @Test
     public void testGetAttestationRecordFromKeyAlias_certFailure() throws Exception {
+        doReturn(new KeyPair(null, null)).when(mMockKeyPairGenerator).generateKeyPair();
         doThrow(new CertificateException("Cert Exception")).when(mMockKeyStore).load(any());
 
-        List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
+        List<String> record =
+                mKeyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
 
+        assertThat(mEventKindCaptor.getValue())
+                .isEqualTo(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_CERTIFICATE_EXCEPTION);
         assertThat(record).isEmpty();
     }
 
     @Test
-    public void testGetAttestationRecordFromKeyAlias_keyStoreFailure() throws Exception {
-        doThrow(new KeyStoreException("Key Store Exception"))
-                .when(mMockKeyStore)
-                .getCertificateChain(any());
+    public void testGetAttestationRecordFromKeyAlias_keyStoreFailure() {
+        doReturn(new KeyPair(null, null)).when(mMockKeyPairGenerator).generateKeyPair();
+        KeyAttestation keyAttestation =
+                KeyAttestation.getInstanceForTest(
+                        ApplicationProvider.getApplicationContext(),
+                        new TestInjectorWithKeyStoreException());
 
-        List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
+        List<String> record =
+                keyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
 
+        assertThat(mEventKindCaptor.getValue())
+                .isEqualTo(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_KEYSTORE_EXCEPTION);
         assertThat(record).isEmpty();
     }
 
     @Test
     public void testGetAttestationRecordFromKeyAlias_nullCertificate() throws Exception {
+        doReturn(new KeyPair(null, null)).when(mMockKeyPairGenerator).generateKeyPair();
         when(mMockKeyStore.getCertificateChain(any())).thenReturn(null);
 
-        List<String> record = mKeyAttestation.getAttestationRecordFromKeyAlias(KEY_ALIAS);
+        List<String> record =
+                mKeyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
 
+        assertThat(mEventKindCaptor.getValue())
+                .isEqualTo(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_ERROR);
         assertThat(record).isEmpty();
     }
 
@@ -139,14 +187,70 @@ public final class KeyAttestationTest {
     }
 
     @Test
-    public void testGetAttestationRecord_securityProviderException() throws Exception {
-        doThrow(new ProviderException("Failed to generate key pair."))
-                .when(mMockKeyPairGenerator)
-                .generateKeyPair();
+    public void testGetAttestationRecord_noSuchProviderException() {
+        KeyAttestation keyAttestation =
+                KeyAttestation.getInstanceForTest(
+                        ApplicationProvider.getApplicationContext(),
+                        new TestInjectorWithNoSuchProviderException());
+
+        List<String> record =
+                keyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
+
+        assertThat(mEventKindCaptor.getValue())
+                .isEqualTo(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_KEY_ATTESTATION_NO_SUCH_PROVIDER_EXCEPTION);
+        assertThat(record).isEmpty();
+    }
+
+    @Test
+    public void testGenerateAttestationRecord_success() throws Exception {
+        doReturn(new KeyPair(null, null)).when(mMockKeyPairGenerator).generateKeyPair();
+        when(mMockKeyStore.getCertificateChain(any())).thenReturn(new Certificate[] {mMockCert});
+        when(mMockCert.getEncoded()).thenReturn(new byte[] {20});
+
+        List<String> record =
+                mKeyAttestation.generateAttestationRecord(
+                        CHALLENGE, CALLING_APP, mTrainingEventLogger);
+
+        verify(mTrainingEventLogger, times(1)).logKeyAttestationLatencyEvent(anyLong());
+        assertThat(record).hasSize(1);
+    }
+
+    private class TestInjectorWithNoSuchProviderException extends KeyAttestation.Injector {
+        @Override
+        KeyPairGenerator getKeyPairGenerator() throws NoSuchProviderException {
+            throw new NoSuchProviderException("no such provider exception");
+        }
 
-        KeyPair keyPair = mKeyAttestation.generateHybridKey(CHALLENGE, KEY_ALIAS);
+        @Override
+        KeyStore getKeyStore() {
+            return mMockKeyStore;
+        }
+    }
+
+    private class TestInjectorWithKeyStoreException extends KeyAttestation.Injector {
+        @Override
+        KeyPairGenerator getKeyPairGenerator() {
+            return mMockKeyPairGenerator;
+        }
+
+        @Override
+        KeyStore getKeyStore() throws KeyStoreException {
+            throw new KeyStoreException("key store exception");
+        }
+    }
+
+    private class TestInjectorWithNoSuchAlgoException extends KeyAttestation.Injector {
+        @Override
+        KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException {
+            throw new NoSuchAlgorithmException("no such algo exception");
+        }
 
-        assertThat(keyPair).isNull();
+        @Override
+        KeyStore getKeyStore() {
+            return mMockKeyStore;
+        }
     }
 
     private class TestInjector extends KeyAttestation.Injector {
@@ -159,5 +263,10 @@ public final class KeyAttestationTest {
         KeyPairGenerator getKeyPairGenerator() {
             return mMockKeyPairGenerator;
         }
+
+        @Override
+        Clock getClock() {
+            return mMockClock;
+        }
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactoryTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactoryTest.java
index 2403521d..bd7ecf7c 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactoryTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceFactoryTest.java
@@ -18,6 +18,7 @@ package com.android.federatedcompute.services.sharedlibrary.spe;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID;
+import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -29,6 +30,8 @@ import com.android.adservices.shared.proto.ModuleJobPolicy;
 import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
 import com.android.adservices.shared.spe.logging.JobServiceLogger;
 import com.android.federatedcompute.services.common.Flags;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJob;
+import com.android.federatedcompute.services.encryption.BackgroundKeyFetchJobService;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJob;
 import com.android.federatedcompute.services.scheduling.DeleteExpiredJobService;
 import com.android.federatedcompute.services.statsd.ClientErrorLogger;
@@ -49,6 +52,7 @@ import java.util.concurrent.Executor;
 import java.util.concurrent.Executors;
 
 /** Unit tests for {@link FederatedComputeJobServiceFactory}. */
+@MockStatic(BackgroundKeyFetchJobService.class)
 @MockStatic(DeleteExpiredJobService.class)
 public final class FederatedComputeJobServiceFactoryTest {
     @Rule(order = 0)
@@ -97,12 +101,19 @@ public final class FederatedComputeJobServiceFactoryTest {
     }
 
     @Test
-    public void testGetJobInstance() {
+    public void testGetJobInstance_deleteExpiredJob() {
         expect.withMessage("getJobWorkerInstance() for DeleteExpiredJob")
                 .that(mFactory.getJobWorkerInstance(DELETE_EXPIRED_JOB_ID))
                 .isInstanceOf(DeleteExpiredJob.class);
     }
 
+    @Test
+    public void testGetJobInstance_backgroundKeyFetchJob() {
+        expect.withMessage("getJobWorkerInstance() for BackgroundKeyFetchJob")
+                .that(mFactory.getJobWorkerInstance(ENCRYPTION_KEY_FETCH_JOB_ID))
+                .isInstanceOf(BackgroundKeyFetchJob.class);
+    }
+
     @Test
     public void testRescheduleJobWithLegacyMethod_notConfiguredJob() {
         int notConfiguredJobId = -1;
@@ -111,7 +122,7 @@ public final class FederatedComputeJobServiceFactoryTest {
     }
 
     @Test
-    public void testRescheduleJobWithLegacyMethod() {
+    public void testRescheduleJobWithLegacyMethod_deleteExpiredJob() {
         boolean forceSchedule = true;
 
         mFactory.rescheduleJobWithLegacyMethod(sContext, DELETE_EXPIRED_JOB_ID);
@@ -121,6 +132,17 @@ public final class FederatedComputeJobServiceFactoryTest {
                                 sContext, mMockFlags, forceSchedule));
     }
 
+    @Test
+    public void testRescheduleJobWithLegacyMethod_backgroundKeyFetchJob() {
+        boolean forceSchedule = true;
+
+        mFactory.rescheduleJobWithLegacyMethod(sContext, ENCRYPTION_KEY_FETCH_JOB_ID);
+        verify(
+                () ->
+                        BackgroundKeyFetchJobService.scheduleJobIfNeeded(
+                                sContext, mMockFlags, forceSchedule));
+    }
+
     @Test
     public void testGetJobIdToNameMap() {
         assertThat(mFactory.getJobIdToNameMap()).isSameInstanceAs(sJobIdToNameMap);
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceTest.java
index cebe6cf9..8f37af33 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/sharedlibrary/spe/FederatedComputeJobServiceTest.java
@@ -21,6 +21,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doAnswer;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.DELETE_EXPIRED_JOB_ID;
+import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
@@ -53,6 +54,8 @@ import org.mockito.Mock;
 import org.mockito.Spy;
 import org.mockito.quality.Strictness;
 
+import java.util.function.Supplier;
+
 /** Unit tests for {@link FederatedComputeJobService}. */
 @SpyStatic(FlagsFactory.class)
 public final class FederatedComputeJobServiceTest {
@@ -162,34 +165,88 @@ public final class FederatedComputeJobServiceTest {
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speDisabled() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+    public void testShouldRescheduleWithLegacyMethod_deleteExpiredJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                DELETE_EXPIRED_JOB_ID,
+                /* jobName */ "DeleteExpiredJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_backgroundKeyFetchJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                ENCRYPTION_KEY_FETCH_JOB_ID,
+                /* jobName */ "BackgroundKeyFetchJob",
+                mMockFlags::getSpeOnBackgroundKeyFetchJobEnabled);
+    }
+
+    private void assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(false);
 
-        assertWithMessage("shouldRescheduleWithLegacyMethod() for" + " DeleteExpiredJob")
-                .that(
-                        mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(
-                                DELETE_EXPIRED_JOB_ID))
+        assertWithMessage(
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " did not reschedule with legacy even though the spe job is disabled")
+                .that(mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isTrue();
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speDisabled_notConfiguredJobId() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(true);
+    public void testShouldRescheduleWithLegacyMethod_deleteExpiredJobEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "DeleteExpiredJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_backgroundKeyJobEnabled_notConfiguredJobId() {
         int invalidJobId = -1;
 
-        assertWithMessage("shouldRescheduleWithLegacyMethod() for" + " not configured job ID")
-                .that(mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(invalidJobId))
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "BackgroundKeyFetchJob",
+                mMockFlags::getSpeOnBackgroundKeyFetchJobEnabled);
+    }
+
+
+    private void assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(true);
+
+        assertWithMessage(
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " rescheduled even though job ID was misconfigured")
+                .that(mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isFalse();
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speEnabled() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(true);
+    public void testShouldRescheduleWithLegacyMethod_deleteExpiredJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                DELETE_EXPIRED_JOB_ID,
+                /* jobName */ "DeleteExpiredJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_backgroundKeyFetchJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                ENCRYPTION_KEY_FETCH_JOB_ID,
+                /* jobName */ "BackgroundKeyFetchJob",
+                mMockFlags::getSpeOnBackgroundKeyFetchJobEnabled);
+    }
+
+    private void assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(true);
 
-        assertWithMessage("shouldRescheduleWithLegacyMethod() for" + " DeleteExpiredJob")
-                .that(
-                        mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(
-                                DELETE_EXPIRED_JOB_ID))
+        assertWithMessage(
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " rescheduled with legacy method even though the spe job is enabled")
+                .that(mSpyFederatedComputeJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isFalse();
     }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/EligibilityDeciderTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/EligibilityDeciderTest.java
index eb44bf86..3edce535 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/EligibilityDeciderTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/EligibilityDeciderTest.java
@@ -18,9 +18,13 @@ package com.android.federatedcompute.services.training;
 
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_COMPLETED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ELIGIBLE;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ERROR_EXAMPLE_ITERATOR;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_ERROR;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_SUCCESS;
 
@@ -108,7 +112,8 @@ public class EligibilityDeciderTest {
                                     .build())
                     .build();
 
-    private Context mContext;
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private FederatedComputeDbHelper mTestDbHelper;
     private FederatedTrainingTaskDao mTrainingTaskDao;
     private EligibilityDecider mEligibilityDecider;
 
@@ -121,17 +126,16 @@ public class EligibilityDeciderTest {
 
     @Before
     public void setUp() {
-        mContext = ApplicationProvider.getApplicationContext();
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(mContext);
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mTestDbHelper);
         mEligibilityDecider = new EligibilityDecider(mTrainingTaskDao, mSpyExampleStoreProvider);
     }
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -217,10 +221,12 @@ public class EligibilityDeciderTest {
                         EXAMPLE_SELECTOR);
 
         assertFalse(result.isEligible());
-        verify(mMockTrainingEventLogger)
-                .logEventKind(
-                        eq(
-                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED));
+        ArgumentCaptor<Integer> eventKindCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockTrainingEventLogger, times(2)).logEventKind(eventKindCaptor.capture());
+        assertThat(eventKindCaptor.getAllValues())
+                .containsAtLeast(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION);
     }
 
     @Test
@@ -289,10 +295,12 @@ public class EligibilityDeciderTest {
                         EXAMPLE_SELECTOR);
 
         assertFalse(result.isEligible());
-        verify(mMockTrainingEventLogger)
-                .logEventKind(
-                        eq(
-                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED));
+        ArgumentCaptor<Integer> eventKindCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockTrainingEventLogger, times(2)).logEventKind(eventKindCaptor.capture());
+        assertThat(eventKindCaptor.getAllValues())
+                .containsAtLeast(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION);
     }
 
     @Test
@@ -311,10 +319,17 @@ public class EligibilityDeciderTest {
                         EXAMPLE_SELECTOR);
 
         assertFalse(result.isEligible());
-        verify(mMockTrainingEventLogger)
-                .logEventKind(
-                        eq(
-                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED));
+        ArgumentCaptor<Integer> eventKindCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockTrainingEventLogger, times(7)).logEventKind(eventKindCaptor.capture());
+        assertThat(eventKindCaptor.getAllValues())
+                .containsExactly(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_ERROR,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ERROR_EXAMPLE_ITERATOR,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE);
         verify(mSpyExampleStoreProvider).unbindFromExampleStoreService();
     }
 
@@ -335,10 +350,17 @@ public class EligibilityDeciderTest {
 
         assertFalse(result.isEligible());
         verify(mSpyExampleStoreProvider).unbindFromExampleStoreService();
-        verify(mMockTrainingEventLogger)
-                .logEventKind(
-                        eq(
-                                FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED));
+        ArgumentCaptor<Integer> eventKindCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockTrainingEventLogger, times(7)).logEventKind(eventKindCaptor.capture());
+        assertThat(eventKindCaptor.getAllValues())
+                .containsExactly(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_ERROR,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ERROR_EXAMPLE_ITERATOR,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE);
     }
 
     @Test
@@ -417,6 +439,16 @@ public class EligibilityDeciderTest {
         assertFalse(result.isEligible());
         assertThat(result.getExampleStoreIterator()).isNull();
         verify(mSpyExampleStoreProvider).unbindFromExampleStoreService();
+        ArgumentCaptor<Integer> eventKindCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockTrainingEventLogger, times(6)).logEventKind(eventKindCaptor.capture());
+        assertThat(eventKindCaptor.getAllValues())
+                .containsExactly(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_BIND_SUCCESS,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_START,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_EXAMPLE_STORE_START_QUERY_SUCCESS,
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION);
     }
 
     private void setUpExampleStoreService(TestExampleStoreService exampleStoreService) {
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
index 2f00547c..97ef3088 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/training/FederatedComputeWorkerTest.java
@@ -98,7 +98,7 @@ import com.android.federatedcompute.services.training.util.TrainingConditionsChe
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.odp.module.common.MonotonicClock;
-import com.android.odp.module.common.data.ODPAuthorizationTokenDao;
+import com.android.odp.module.common.data.OdpAuthorizationTokenDao;
 import com.android.odp.module.common.encryption.HpkeJniEncrypter;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
 import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
@@ -209,17 +209,6 @@ public final class FederatedComputeWorkerTest {
                     .setExampleSelector(
                             ExampleSelector.newBuilder().setCollectionUri(COLLECTION_URI).build())
                     .build();
-    private static final CheckinResult FL_CHECKIN_RESULT =
-            new CheckinResult(
-                    createTempFile("input", ".ckp"),
-                    TrainingTestUtil.createFakeFederatedLearningClientPlan(),
-                    TASK_ASSIGNMENT);
-
-    private static final CheckinResult FA_CHECKIN_RESULT =
-            new CheckinResult(
-                    createTempFile("input", ".ckp"),
-                    TrainingTestUtil.createFederatedAnalyticClientPlan(),
-                    TASK_ASSIGNMENT);
     public static final RejectionInfo RETRY_REJECTION_INFO =
             RejectionInfo.newBuilder()
                     .setRetryWindow(
@@ -316,7 +305,7 @@ public final class FederatedComputeWorkerTest {
                     .build();
     @Mock TrainingConditionsChecker mTrainingConditionsChecker;
     @Mock FederatedComputeJobManager mMockJobManager;
-    private Context mContext;
+    private final Context mContext = ApplicationProvider.getApplicationContext();
     private FederatedComputeWorker mSpyWorker;
     private HttpFederatedProtocol mSpyHttpFederatedProtocol;
     @Mock private ComputationRunner mMockComputationRunner;
@@ -324,6 +313,8 @@ public final class FederatedComputeWorkerTest {
     @Mock private TrainingEventLogger mMockTrainingEventLogger;
     private ResultCallbackHelper mSpyResultCallbackHelper;
     private ExampleStoreServiceProvider mSpyExampleStoreProvider;
+
+    private FederatedComputeDbHelper mTestDbHelper;
     private FederatedTrainingTaskDao mTrainingTaskDao;
 
     @Mock private OdpEncryptionKeyManager mMockKeyManager;
@@ -367,7 +358,6 @@ public final class FederatedComputeWorkerTest {
 
     @Before
     public void setUp() {
-        mContext = ApplicationProvider.getApplicationContext();
         when(ClientErrorLogger.getInstance()).thenReturn(mMockClientErrorLogger);
         mSpyHttpFederatedProtocol =
                 spy(
@@ -379,7 +369,9 @@ public final class FederatedComputeWorkerTest {
                                 mMockTrainingEventLogger));
         mSpyResultCallbackHelper = spy(new ResultCallbackHelper(mContext));
         mSpyExampleStoreProvider = spy(new ExampleStoreServiceProvider());
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+
+        mTestDbHelper = FederatedComputeDbHelper.getNonSingletonInstanceForTest(mContext);
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mTestDbHelper);
         mSpyWorker =
                 spy(
                         new FederatedComputeWorker(
@@ -411,15 +403,16 @@ public final class FederatedComputeWorkerTest {
         doReturn(List.of(ENCRYPTION_KEY))
                 .when(mMockKeyManager)
                 .getOrFetchActiveKeys(anyInt(), anyInt(), any());
-        doReturn(KA_RECORD).when(mMockKeyAttestation).generateAttestationRecord(any(), anyString());
+        doReturn(KA_RECORD)
+                .when(mMockKeyAttestation)
+                .generateAttestationRecord(any(), anyString(), any());
     }
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
-        dbHelper.getWritableDatabase().close();
-        dbHelper.getReadableDatabase().close();
-        dbHelper.close();
+        mTestDbHelper.getWritableDatabase().close();
+        mTestDbHelper.getReadableDatabase().close();
+        mTestDbHelper.close();
     }
 
     @Test
@@ -525,13 +518,45 @@ public final class FederatedComputeWorkerTest {
         verify(mMockJobServiceOnFinishCallback).callJobFinished(eq(false));
     }
 
+    @Test
+    public void testCheckinWithKeyAttestationFails_fails() {
+        setUpExampleStoreService();
+        doReturn(new ArrayList<>())
+                .when(mMockKeyAttestation)
+                .generateAttestationRecord(any(), anyString(), any());
+        // Always return Unauthenticated during checkin. The second request with auth will fail.
+        doReturn(
+                        FluentFuture.from(
+                                immediateFuture(
+                                        CREATE_TASK_ASSIGNMENT_RESPONSE_UNAUTHENTICATED_REJECTION)))
+                .when(mSpyHttpFederatedProtocol)
+                .createTaskAssignment(any());
+
+        // The second auth request will throw exception as http status 401 is not allowed.
+        ExecutionException exp =
+                assertThrows(
+                        ExecutionException.class,
+                        () ->
+                                mSpyWorker
+                                        .startTrainingRun(JOB_ID, mMockJobServiceOnFinishCallback)
+                                        .get());
+
+        assertThat(exp.getCause()).isInstanceOf(IllegalStateException.class);
+        assertThat(exp.getCause().getMessage()).contains("Failed to generate attestation record");
+        // verify one issueCheckin call and skip second call because failed to generate key
+        // attestation record.
+        verify(mSpyHttpFederatedProtocol, times(1)).createTaskAssignment(any());
+        mSpyWorker.finish(null, ContributionResult.FAIL, false);
+        verify(mMockJobServiceOnFinishCallback).callJobFinished(eq(false));
+    }
+
     @Test
     public void testCheckinWithUnAuthRejection_success() throws Exception {
         setUpExampleStoreService();
         doReturn(FluentFuture.from(immediateFuture(null)))
                 .when(mSpyHttpFederatedProtocol)
                 .reportResult(any(), any(), any());
-        doReturn(immediateFuture(FL_CHECKIN_RESULT))
+        doReturn(immediateFuture(createFLCheckinResult()))
                 .when(mSpyHttpFederatedProtocol)
                 .downloadTaskAssignment(any());
         // When allowing unauthenticated, return 401 UNAUTHENTICATED rejection info and return
@@ -557,7 +582,7 @@ public final class FederatedComputeWorkerTest {
         // Verify first issueCheckin call.
         verify(mSpyHttpFederatedProtocol, times(2)).createTaskAssignment(any());
         // After the first issueCheckin, the FederatedComputeWorker would do the key attestation.
-        verify(mMockKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString());
+        verify(mMockKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString(), any());
         assertThat(result.getContributionResult()).isEqualTo(ContributionResult.SUCCESS);
         verify(mMockJobManager)
                 .onTrainingCompleted(
@@ -573,7 +598,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testReportResultWithRejection() throws Exception {
         setUpExampleStoreService();
-        setUpIssueCheckin(FA_CHECKIN_RESULT);
+        setUpIssueCheckin(createFACheckinResult());
         doReturn(FluentFuture.from(immediateFuture(RETRY_REJECTION_INFO)))
                 .when(mSpyHttpFederatedProtocol)
                 .reportResult(any(), any(), any());
@@ -607,7 +632,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testReportResultFails_throwsException() throws Exception {
         setUpExampleStoreService();
-        setUpIssueCheckin(FA_CHECKIN_RESULT);
+        setUpIssueCheckin(createFACheckinResult());
         doReturn(
                         FluentFuture.from(
                                 immediateFailedFuture(
@@ -631,7 +656,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testReportResultUnauthenticated_throws() throws Exception {
         setUpExampleStoreService();
-        setUpIssueCheckin(FA_CHECKIN_RESULT);
+        setUpIssueCheckin(createFACheckinResult());
         doReturn(FluentFuture.from(immediateFuture(UNAUTHENTICATED_REJECTION_INFO)))
                 .when(mSpyHttpFederatedProtocol)
                 .reportResult(any(), any(), any());
@@ -655,7 +680,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testReportResultWithUnAuthRejection_success() throws Exception {
         setUpExampleStoreService();
-        setUpIssueCheckin(FL_CHECKIN_RESULT);
+        setUpIssueCheckin(createFLCheckinResult());
         // Return 401 UNAUTHENTICATED rejection info and then return successful checkin result.
         doReturn(FluentFuture.from(immediateFuture(UNAUTHENTICATED_REJECTION_INFO)))
                 .doReturn(FluentFuture.from(immediateFuture(null)))
@@ -673,7 +698,7 @@ public final class FederatedComputeWorkerTest {
         // Verify two reportResult calls.
         verify(mSpyHttpFederatedProtocol, times(2)).reportResult(any(), any(), any());
         // After the first reportResult, the FederatedComputeWorker would do the key attestation.
-        verify(mMockKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString());
+        verify(mMockKeyAttestation).generateAttestationRecord(eq(CHALLENGE), anyString(), any());
         assertThat(result.getContributionResult()).isEqualTo(ContributionResult.SUCCESS);
         verify(mMockJobManager)
                 .onTrainingCompleted(
@@ -690,7 +715,7 @@ public final class FederatedComputeWorkerTest {
     public void testBindToExampleStoreFails_throwsException() throws Exception {
         ArgumentCaptor<ComputationResult> computationResultCaptor =
                 ArgumentCaptor.forClass(ComputationResult.class);
-        setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFLCheckinResult());
         // Mock failure bind to ExampleStoreService.
         doReturn(null).when(mSpyExampleStoreProvider).getExampleStoreService(anyString(), any());
 
@@ -715,7 +740,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testRunFAComputationReturnsFailResult() throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FA_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFACheckinResult());
 
         // Mock return failed runner result from native fcp client.
         when(mMockComputationRunner.runTaskWithNativeRunner(
@@ -760,7 +785,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testRunFAComputationThrows() throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FA_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFACheckinResult());
         //        setUpReportFailureToServerCallback();
         doReturn(FluentFuture.from(immediateFuture(null)))
                 .when(mSpyHttpFederatedProtocol)
@@ -800,7 +825,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testPublishToResultHandlingServiceFails_returnsSuccess() throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FA_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFACheckinResult());
 
         // Mock publish to ResultHandlingService fails which is best effort and should not affect
         // final result.
@@ -827,7 +852,7 @@ public final class FederatedComputeWorkerTest {
     public void testPublishToResultHandlingServiceThrowsException_returnsSuccess()
             throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FA_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFACheckinResult());
 
         // Mock publish to ResultHandlingService throws exception which is best effort and should
         // not affect final result.
@@ -865,7 +890,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testRunFAComputation_returnsSuccess() throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FA_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFACheckinResult());
 
         FLRunnerResult result =
                 mSpyWorker.startTrainingRun(JOB_ID, mMockJobServiceOnFinishCallback).get();
@@ -879,7 +904,7 @@ public final class FederatedComputeWorkerTest {
 
     @Test
     public void testBindToIsolatedTrainingServiceFail_returnsFail() throws Exception {
-        setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFLCheckinResult());
         setUpExampleStoreService();
 
         // Mock failure bind to IsolatedTrainingService.
@@ -957,7 +982,7 @@ public final class FederatedComputeWorkerTest {
     @Test
     public void testRunFLComputation_returnsSuccess() throws Exception {
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFLCheckinResult());
 
         // Mock bind to IsolatedTrainingService.
         doReturn(new FakeIsolatedTrainingService()).when(mSpyWorker).getIsolatedTrainingService();
@@ -1043,8 +1068,12 @@ public final class FederatedComputeWorkerTest {
                         .setContributionRound(9)
                         .setContributionTime(120L)
                         .build());
+        TaskHistory storedHistory =
+                mTrainingTaskDao.getLatestTaskHistory(JOB_ID, POPULATION_NAME, TASK_ID);
+        // verify insert task history success.
+        assertThat(storedHistory.getContributionRound()).isEqualTo(9);
         setUpExampleStoreService();
-        setUpIssueCheckin(FL_CHECKIN_RESULT);
+        setUpIssueCheckin(createFLCheckinResult());
         ArgumentCaptor<ComputationResult> captor = ArgumentCaptor.forClass(ComputationResult.class);
         doReturn(FluentFuture.from(immediateFuture(null)))
                 .when(mSpyHttpFederatedProtocol)
@@ -1068,10 +1097,10 @@ public final class FederatedComputeWorkerTest {
                         .setTaskId(TASK_ID)
                         .setPopulationName(POPULATION_NAME)
                         .setContributionRound(1)
-                        .setContributionTime(120L)
+                        .setContributionTime(20L)
                         .build());
         setUpExampleStoreService();
-        setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFLCheckinResult());
 
         // Mock bind to IsolatedTrainingService.
         doReturn(new FakeIsolatedTrainingService()).when(mSpyWorker).getIsolatedTrainingService();
@@ -1085,7 +1114,7 @@ public final class FederatedComputeWorkerTest {
 
     @Test
     public void testRunFLComputation_noKey_throws() throws Exception {
-        setUpHttpFederatedProtocol(FL_CHECKIN_RESULT);
+        setUpHttpFederatedProtocol(createFLCheckinResult());
         doReturn(new ArrayList<OdpEncryptionKey>() {})
                 .when(mMockKeyManager)
                 .getOrFetchActiveKeys(anyInt(), anyInt(), any());
@@ -1126,6 +1155,20 @@ public final class FederatedComputeWorkerTest {
         doNothing().when(mSpyWorker).reportFailureResultToServer(any(), any(), any());
     }
 
+    private CheckinResult createFLCheckinResult() {
+        return new CheckinResult(
+                createTempFile("input", ".ckp"),
+                TrainingTestUtil.createFakeFederatedLearningClientPlan(),
+                TASK_ASSIGNMENT);
+    }
+
+    private CheckinResult createFACheckinResult() {
+        return new CheckinResult(
+                createTempFile("input", ".ckp"),
+                TrainingTestUtil.createFederatedAnalyticClientPlan(),
+                TASK_ASSIGNMENT);
+    }
+
     private static class TestExampleStoreService extends IExampleStoreService.Stub {
         @Override
         public void startQuery(Bundle params, IExampleStoreCallback callback)
@@ -1140,7 +1183,7 @@ public final class FederatedComputeWorkerTest {
         }
     }
 
-    class TestInjector extends FederatedComputeWorker.Injector {
+    private class TestInjector extends FederatedComputeWorker.Injector {
         @Override
         ExampleConsumptionRecorder getExampleConsumptionRecorder() {
             return new ExampleConsumptionRecorder() {
@@ -1164,14 +1207,18 @@ public final class FederatedComputeWorkerTest {
         }
 
         @Override
-        AuthorizationContext createAuthContext(Context context, String ownerId, String owerCert) {
+        AuthorizationContext createAuthContext(
+                Context context,
+                String ownerId,
+                String ownerCert,
+                TrainingEventLogger trainingEventLogger) {
             return new AuthorizationContext(
                     ownerId,
-                    owerCert,
-                    ODPAuthorizationTokenDao.getInstanceForTest(
-                            FederatedComputeDbHelper.getInstanceForTest(context)),
+                    ownerCert,
+                    OdpAuthorizationTokenDao.getInstanceForTest(mTestDbHelper),
                     mMockKeyAttestation,
-                    MonotonicClock.getInstance());
+                    MonotonicClock.getInstance(),
+                    mMockTrainingEventLogger);
         }
 
         @Override
diff --git a/tests/frameworktests/src/android/adservices/ondevicepersonalization/FederatedComputeSchedulerTest.java b/tests/frameworktests/src/android/adservices/ondevicepersonalization/FederatedComputeSchedulerTest.java
index 45d45cc7..59e3fd85 100644
--- a/tests/frameworktests/src/android/adservices/ondevicepersonalization/FederatedComputeSchedulerTest.java
+++ b/tests/frameworktests/src/android/adservices/ondevicepersonalization/FederatedComputeSchedulerTest.java
@@ -37,6 +37,8 @@ import androidx.test.filters.SmallTest;
 
 import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
 
+import com.google.common.util.concurrent.MoreExecutors;
+
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
@@ -90,7 +92,8 @@ public class FederatedComputeSchedulerTest {
     public void testSchedule_withOutcomeReceiver_success() throws Exception {
         var receiver = new ResultReceiver();
 
-        mFederatedComputeScheduler.schedule(TEST_SCHEDULE_INPUT, receiver);
+        mFederatedComputeScheduler.schedule(
+                TEST_SCHEDULE_INPUT, MoreExecutors.directExecutor(), receiver);
 
         assertNotNull(receiver.getResult());
         assertTrue(receiver.isSuccess());
@@ -105,7 +108,8 @@ public class FederatedComputeSchedulerTest {
                 new FederatedComputeScheduleRequest(TEST_SCHEDULER_PARAMS, ERROR_POPULATION_NAME);
         var receiver = new ResultReceiver();
 
-        mFederatedComputeScheduler.schedule(scheduleInput, receiver);
+        mFederatedComputeScheduler.schedule(
+                scheduleInput, MoreExecutors.directExecutor(), receiver);
 
         assertNull(receiver.getResult());
         assertTrue(receiver.isError());
@@ -125,7 +129,8 @@ public class FederatedComputeSchedulerTest {
                         TEST_SCHEDULER_PARAMS, INVALID_MANIFEST_ERROR_POPULATION_NAME);
         var receiver = new ResultReceiver();
 
-        mFederatedComputeScheduler.schedule(scheduleInput, receiver);
+        mFederatedComputeScheduler.schedule(
+                scheduleInput, MoreExecutors.directExecutor(), receiver);
 
         assertNull(receiver.getResult());
         assertTrue(receiver.isError());
diff --git a/tests/frameworktests/src/android/federatedcompute/FederatedComputeManagerTest.java b/tests/frameworktests/src/android/federatedcompute/FederatedComputeManagerTest.java
index eac7b7bd..13dfcb81 100644
--- a/tests/frameworktests/src/android/federatedcompute/FederatedComputeManagerTest.java
+++ b/tests/frameworktests/src/android/federatedcompute/FederatedComputeManagerTest.java
@@ -119,6 +119,14 @@ public class FederatedComputeManagerTest {
                                 null,
                                 null /* mock will be returned */
                         },
+                        {
+                                "schedule-unavailable-iService",
+                                new ScheduleFederatedComputeRequest.Builder()
+                                        .setTrainingOptions(new TrainingOptions.Builder().build())
+                                        .build(),
+                                null,
+                                null /* throw exception when getting instance */
+                        },
                         {"cancel-allNull", null, null, null},
                         {
                                 "cancel-default-iService",
@@ -144,6 +152,12 @@ public class FederatedComputeManagerTest {
                                 "testPopulation",
                                 null /* mock will be returned */
                         },
+                        {
+                                "cancel-unavailable-iService",
+                                null,
+                                "testPopulation",
+                                null /* throw exception when getting instance */
+                        },
                 });
     }
 
@@ -222,6 +236,16 @@ public class FederatedComputeManagerTest {
                 verify(spyCallback, times(1)).onError(any(FederatedComputeException.class));
                 verify(mContext, times(1)).unbindService(any());
                 break;
+            case "schedule-unavailable-iService":
+                when(mMockIBinder.queryLocalInterface(any())).thenThrow(RuntimeException.class);
+                spyCallback = spy(new MyTestCallback());
+
+                manager.schedule(request, Runnable::run, spyCallback);
+
+                verify(mContext, times(1)).bindService(any(), anyInt(), any(), any());
+                verify(spyCallback, times(1)).onError(any(RuntimeException.class));
+                verify(mContext, times(1)).unbindService(any());
+                break;
             case "cancel-allNull":
                 assertThrows(
                         NullPointerException.class,
@@ -302,6 +326,20 @@ public class FederatedComputeManagerTest {
                 verify(spyCallback, times(1)).onError(any(FederatedComputeException.class));
                 verify(mContext, times(1)).unbindService(any());
                 break;
+            case "cancel-unavailable-iService":
+                when(mMockIBinder.queryLocalInterface(any())).thenThrow(RuntimeException.class);
+                spyCallback = spy(new MyTestCallback());
+
+                manager.cancel(
+                        OWNER_COMPONENT,
+                        populationName,
+                        Runnable::run,
+                        spyCallback);
+
+                verify(mContext, times(1)).bindService(any(), anyInt(), any(), any());
+                verify(spyCallback, times(1)).onError(any(RuntimeException.class));
+                verify(mContext, times(1)).unbindService(any());
+                break;
             default:
                 break;
         }
diff --git a/tests/manualtests/Android.bp b/tests/manualtests/Android.bp
index 0cea2009..8613e487 100644
--- a/tests/manualtests/Android.bp
+++ b/tests/manualtests/Android.bp
@@ -57,6 +57,8 @@ android_test {
         "owasp-java-encoder",
         "tensorflowlite_java",
         "adservices-shared-spe",
+         "common-ondevicepersonalization-protos",
+         "adservices-shared-datastore", // For proto data store.
     ],
     sdk_version: "module_current",
     target_sdk_version: "current",
diff --git a/tests/servicetests/Android.bp b/tests/servicetests/Android.bp
index b3e8efff..0d5069ae 100644
--- a/tests/servicetests/Android.bp
+++ b/tests/servicetests/Android.bp
@@ -64,6 +64,8 @@ android_test {
         "tensorflowlite_java",
         "adservices-shared-spe",
         "ondevicepersonalization-testing-utils",
+        "common-ondevicepersonalization-protos",
+        "adservices-shared-datastore", // For proto data store.
     ],
     sdk_version: "module_current",
     target_sdk_version: "current",
diff --git a/tests/servicetests/res/raw/test_data1.json b/tests/servicetests/res/raw/test_data1.json
index 0bc7094d..913ac022 100644
--- a/tests/servicetests/res/raw/test_data1.json
+++ b/tests/servicetests/res/raw/test_data1.json
@@ -1,4 +1,10 @@
 {
+  "unknownKey": "unknownValue",
+  "unknownArrayKey" : [1, 2, 3],
+  "unknownObjectKey": {
+    "a": "aa",
+    "b": "bb"
+  },
   "syncToken": 1662134400,
   "contents": [
     { "key": "key1",
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
index ba4e36ae..e5d61b8c 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationBroadcastReceiverTests.java
@@ -45,6 +45,8 @@ import androidx.test.core.app.ApplicationProvider;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.DeviceUtils;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingJob;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJob;
 import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
 
@@ -95,7 +97,9 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
             new ExtendedMockitoRule.Builder(this)
                     .spyStatic(FlagsFactory.class)
                     .spyStatic(DeviceUtils.class)
+                    .spyStatic(AggregateErrorDataReportingJob.class)
                     .spyStatic(OnDevicePersonalizationMaintenanceJob.class)
+                    .spyStatic(UserDataCollectionJob.class)
                     .setStrictness(Strictness.LENIENT)
                     .build();
 
@@ -106,6 +110,7 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
 
         // By default, disable SPE and aggregate error reporting.
         when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+        when(mMockFlags.getSpeOnAggregateErrorDataReportingJobEnabled()).thenReturn(false);
         when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
 
         ExtendedMockito.doReturn(true).when(() -> DeviceUtils.isOdpSupported(any()));
@@ -124,6 +129,8 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
         mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext));
+        verify(() -> UserDataCollectionJob.schedule(mContext));
+        verify(() -> AggregateErrorDataReportingJob.schedule(mContext));
         assertAllJobsScheduled();
     }
 
@@ -134,6 +141,8 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
         mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
+        verify(() -> UserDataCollectionJob.schedule(mContext), never());
+        verify(() -> AggregateErrorDataReportingJob.schedule(mContext), never());
         assertNoJobsScheduled();
     }
 
@@ -144,6 +153,8 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
         mReceiverUnderTest.onReceive(mContext, BOOT_COMPLETED_INTENT);
 
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
+        verify(() -> UserDataCollectionJob.schedule(mContext), never());
+        verify(() -> AggregateErrorDataReportingJob.schedule(mContext), never());
         assertNoJobsScheduled();
     }
 
@@ -152,6 +163,8 @@ public class OnDevicePersonalizationBroadcastReceiverTests {
         mReceiverUnderTest.onReceive(mContext, new Intent(Intent.ACTION_DIAL_EMERGENCY));
 
         verify(() -> OnDevicePersonalizationMaintenanceJob.schedule(mContext), never());
+        verify(() -> UserDataCollectionJob.schedule(mContext), never());
+        verify(() -> AggregateErrorDataReportingJob.schedule(mContext), never());
         assertNoJobsScheduled();
     }
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
index f3fdbcb2..e79b0e53 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
@@ -26,6 +26,9 @@ import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -58,6 +61,7 @@ import androidx.test.rule.ServiceTestRule;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.DeviceUtils;
+import com.android.odp.module.common.ProcessWrapper;
 import com.android.ondevicepersonalization.internal.util.ByteArrayParceledSlice;
 import com.android.ondevicepersonalization.internal.util.PersistableBundleUtils;
 import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJobService;
@@ -67,6 +71,7 @@ import com.android.ondevicepersonalization.services.enrollment.PartnerEnrollment
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJobService;
 
 import com.google.android.libraries.mobiledatadownload.MobileDataDownload;
+import com.google.common.util.concurrent.Futures;
 
 import org.junit.Before;
 import org.junit.Rule;
@@ -76,6 +81,7 @@ import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.quality.Strictness;
 
+import java.util.List;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeoutException;
 
@@ -85,6 +91,10 @@ public class OnDevicePersonalizationManagingServiceTest {
             new ComponentName(
                     ApplicationProvider.getApplicationContext(),
                     "com.test.TestPersonalizationHandler");
+    private static final int UID_CALLER_APP_1 = 1000;
+    private static final int UID_CALLER_APP_2 = 1001;
+    private static final int UID_CALLER_SDK_1 = 2000;
+    private static final int UID_CALLER_SDK_2 = 2001;
 
     @Rule public final ServiceTestRule serviceRule = new ServiceTestRule();
     private final Context mContext = spy(ApplicationProvider.getApplicationContext());
@@ -92,6 +102,7 @@ public class OnDevicePersonalizationManagingServiceTest {
     @Mock private UserPrivacyStatus mUserPrivacyStatus;
     @Mock private MobileDataDownload mMockMdd;
     @Mock private Flags mMockFlags;
+    @Mock private PackageManager mMockPackageManager;
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule =
@@ -100,9 +111,11 @@ public class OnDevicePersonalizationManagingServiceTest {
                     .spyStatic(UserPrivacyStatus.class)
                     .spyStatic(DeviceUtils.class)
                     .spyStatic(OnDevicePersonalizationMaintenanceJobService.class)
+                    .spyStatic(OnDevicePersonalizationBroadcastReceiver.class)
                     .spyStatic(UserDataCollectionJobService.class)
                     .spyStatic(MobileDataDownloadFactory.class)
                     .spyStatic(PartnerEnrollmentChecker.class)
+                    .spyStatic(ProcessWrapper.class)
                     .setStrictness(Strictness.LENIENT)
                     .build();
 
@@ -119,14 +132,15 @@ public class OnDevicePersonalizationManagingServiceTest {
         ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
         doReturn(true).when(mUserPrivacyStatus).isMeasurementEnabled();
         doReturn(true).when(mUserPrivacyStatus).isProtectedAudienceEnabled();
-        when(mContext.checkCallingPermission(NOTIFY_MEASUREMENT_EVENT))
-                .thenReturn(PackageManager.PERMISSION_GRANTED);
+        doReturn(PackageManager.PERMISSION_GRANTED)
+                .when(mContext).checkCallingPermission(NOTIFY_MEASUREMENT_EVENT);
         ExtendedMockito.doReturn(SCHEDULING_RESULT_CODE_SUCCESSFUL)
                 .when(
                         () ->
                                 OnDevicePersonalizationMaintenanceJobService.schedule(
                                         any(), anyBoolean()));
-        ExtendedMockito.doReturn(1).when(() -> UserDataCollectionJobService.schedule(any()));
+        ExtendedMockito.doReturn(1)
+                .when(() -> UserDataCollectionJobService.schedule(any(), eq(false)));
         ExtendedMockito.doReturn(mMockMdd).when(() -> MobileDataDownloadFactory.getMdd(any()));
         doReturn(immediateVoidFuture()).when(mMockMdd).schedulePeriodicBackgroundTasks();
         ExtendedMockito.doReturn(true)
@@ -588,10 +602,16 @@ public class OnDevicePersonalizationManagingServiceTest {
 
     @Test
     public void testWithBoundService() throws TimeoutException {
+        ExtendedMockito.doReturn(Futures.immediateFuture(List.of())).when(
+                () -> OnDevicePersonalizationBroadcastReceiver.restoreOdpJobs(any(), any()));
         Intent serviceIntent =
                 new Intent(mContext, OnDevicePersonalizationManagingServiceImpl.class);
+
         IBinder binder = serviceRule.bindService(serviceIntent);
+
         assertTrue(binder instanceof OnDevicePersonalizationManagingServiceDelegate);
+        ExtendedMockito.verify(() ->
+                OnDevicePersonalizationBroadcastReceiver.restoreOdpJobs(any(), any()));
     }
 
     @Test
@@ -605,7 +625,8 @@ public class OnDevicePersonalizationManagingServiceTest {
         assertTrue(binder instanceof OnDevicePersonalizationManagingServiceDelegate);
         ExtendedMockito.verify(
                 () -> OnDevicePersonalizationMaintenanceJobService.schedule(any(), anyBoolean()));
-        ExtendedMockito.verify(() -> UserDataCollectionJobService.schedule(any()), times(1));
+        ExtendedMockito.verify(() ->
+                UserDataCollectionJobService.schedule(any(), eq(false)), times(1));
         verify(mMockMdd).schedulePeriodicBackgroundTasks();
     }
 
@@ -657,6 +678,77 @@ public class OnDevicePersonalizationManagingServiceTest {
         assertTrue(callback.mWasInvoked);
     }
 
+    @Test
+    public void testEnforceCallingPackageBelongsToUid_AppUidCallWithSameAppPackageUid()
+            throws Exception {
+        setupEnforceCallingPackageBelongsToUid(/* isSdkSandboxUid */ false);
+
+        // test that no exceptions are thrown
+        mService.enforceCallingPackageBelongsToUid(mContext.getPackageName(), UID_CALLER_APP_1);
+    }
+
+    @Test
+    public void testEnforceCallingPackageBelongsToUid_AppUidCallWithDifferentAppPackageUid()
+            throws Exception {
+        setupEnforceCallingPackageBelongsToUid(/* isSdkSandboxUid */ false);
+        int invalidAppCallerUid = UID_CALLER_APP_2;
+
+        SecurityException e = assertThrows(
+                SecurityException.class,
+                () ->
+                        mService.enforceCallingPackageBelongsToUid(
+                                mContext.getPackageName(),
+                                invalidAppCallerUid));
+
+        assertEquals(
+                /* expected */ mContext.getPackageName() + " does not belong to uid "
+                        + invalidAppCallerUid,
+                e.getMessage());
+    }
+
+    @Test
+    public void testEnforceCallingPackageBelongsToUid_SdkUidCallWithSameAppPackageUid()
+            throws Exception {
+        setupEnforceCallingPackageBelongsToUid(/* isSdkSandboxUid */ true);
+
+        // test that no exceptions are thrown
+        mService.enforceCallingPackageBelongsToUid(mContext.getPackageName(), UID_CALLER_SDK_1);
+    }
+
+    @Test
+    public void testEnforceCallingPackageBelongsToUid_SdkUidCallWithDifferentAppPackageUid()
+            throws Exception {
+        setupEnforceCallingPackageBelongsToUid(/* isSdkSandboxUid */ true);
+        int invalidSdkCallerUid = UID_CALLER_SDK_2;
+
+        SecurityException e = assertThrows(
+                SecurityException.class,
+                () ->
+                        mService.enforceCallingPackageBelongsToUid(
+                                mContext.getPackageName(),
+                                invalidSdkCallerUid));
+        assertEquals(
+                /* expected */ mContext.getPackageName() + " does not belong to uid "
+                        + invalidSdkCallerUid,
+                e.getMessage());
+    }
+
+    private void setupEnforceCallingPackageBelongsToUid(boolean isSdkSandboxUid)
+            throws PackageManager.NameNotFoundException {
+        doReturn(mMockPackageManager).when(mContext).getPackageManager();
+        doReturn(UID_CALLER_APP_1)
+                .when(mMockPackageManager).getPackageUid(anyString(), anyInt());
+        ExtendedMockito.doReturn(isSdkSandboxUid)
+                .when(() -> ProcessWrapper.isSdkSandboxUid(UID_CALLER_SDK_1));
+        ExtendedMockito.doReturn(UID_CALLER_APP_1)
+                .when(() -> ProcessWrapper.getAppUidForSdkSandboxUid(UID_CALLER_SDK_1));
+
+        ExtendedMockito.doReturn(isSdkSandboxUid)
+                .when(() -> ProcessWrapper.isSdkSandboxUid(UID_CALLER_SDK_2));
+        ExtendedMockito.doReturn(UID_CALLER_APP_2)
+                .when(() -> ProcessWrapper.getAppUidForSdkSandboxUid(UID_CALLER_SDK_2));
+    }
+
     private static Bundle createWrappedAppParams() throws Exception {
         Bundle wrappedParams = new Bundle();
         ByteArrayParceledSlice buffer =
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
index dfe30d2b..8809e4d7 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
@@ -35,10 +35,15 @@ import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPT
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ISOLATED_SERVICE_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_MODULE_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_OUTPUT_DATA_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SPE_PILOT_JOB_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_TRUSTED_PARTNER_APPS_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DOWNLOAD_FLOW_DEADLINE_SECONDS;
@@ -50,42 +55,47 @@ import static com.android.ondevicepersonalization.services.Flags.PERSONALIZATION
 import static com.android.ondevicepersonalization.services.Flags.RENDER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.WEB_VIEW_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.APP_INSTALL_HISTORY_TTL;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_PATH;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_CALLER_APP_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENCRYPTION_KEY_URL;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_GLOBAL_KILL_SWITCH;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_FEATURE_ENABLED_API_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_MODULE_JOB_POLICY;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_SPE_PILOT_JOB_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_OUTPUT_DATA_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_PLUGIN_PROCESS_RUNNER_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_RENDER_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.APP_INSTALL_HISTORY_TTL;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_PATH;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_CALLER_APP_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_URL;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_GLOBAL_KILL_SWITCH;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_MODULE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_SPE_PILOT_JOB_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_OUTPUT_DATA_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PLUGIN_PROCESS_RUNNER_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RENDER_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -102,6 +112,8 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
+import java.util.function.Supplier;
+
 /** Unit tests for {@link com.android.ondevicepersonalization.services.PhFlags} */
 @RunWith(AndroidJUnit4.class)
 @Ignore("b/375661140")
@@ -597,20 +609,56 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpePilotJobEnabled() {
-        // read a stable flag value and verify it's equal to the default value.
-        boolean stableValue = FlagsFactory.getFlags().getSpePilotJobEnabled();
-        assertThat(stableValue).isEqualTo(DEFAULT_SPE_PILOT_JOB_ENABLED);
-
-        // override the value in device config.
-        boolean overrideEnabled = !stableValue;
-        DeviceConfig.setProperty(
-                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpePilotJobEnabled(),
                 KEY_ODP_SPE_PILOT_JOB_ENABLED,
-                Boolean.toString(overrideEnabled),
-                /* makeDefault= */ false);
+                DEFAULT_SPE_PILOT_JOB_ENABLED
+        );
+    }
 
-        // the flag value remains stable
-        assertThat(FlagsFactory.getFlags().getSpePilotJobEnabled()).isEqualTo(overrideEnabled);
+    @Test
+    public void testGetSpeOnAggregateErrorDataReportingJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnAggregateErrorDataReportingJobEnabled(),
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB,
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB
+        );
+    }
+
+    @Test
+    public void testGetSpeOnMddJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnMddJobEnabled(),
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB,
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB
+        );
+    }
+
+    @Test
+    public void testGetSpeOnOdpDownloadProcessingJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled(),
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB,
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB
+        );
+    }
+
+    @Test
+    public void testGetSpeOnResetDataJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnResetDataJobEnabled(),
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB,
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB
+        );
+    }
+
+    @Test
+    public void testGetSpeOnUserDataCollectionJobEnabled() {
+        assertSpeFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeOnUserDataCollectionJobEnabled(),
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB,
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB
+        );
     }
 
     @Test
@@ -904,4 +952,24 @@ public class PhFlagsTest {
 
         assertThat(FlagsFactory.getFlags().isFeatureEnabledApiEnabled()).isEqualTo(overrideEnabled);
     }
+
+    private void assertSpeFeatureFlags(
+            Supplier<Boolean> flagSupplier, String flagName, boolean defaultValue) {
+        // Test override value
+        boolean overrideValue = !defaultValue;
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                Boolean.toString(overrideValue),
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(overrideValue);
+
+        // Test default value
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                Boolean.toString(defaultValue),
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(defaultValue);
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
index 49c0d291..0ae02c7c 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTestUtil.java
@@ -16,14 +16,15 @@
 
 package com.android.ondevicepersonalization.services;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_CALLER_APP_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_GLOBAL_KILL_SWITCH;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ISOLATED_SERVICE_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ODP_SPE_PILOT_JOB_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_OUTPUT_DATA_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_CALLER_APP_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_GLOBAL_KILL_SWITCH;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_SPE_PILOT_JOB_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_OUTPUT_DATA_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import android.provider.DeviceConfig;
 
@@ -131,6 +132,15 @@ public class PhFlagsTestUtil {
                 /* makeDefault */ false);
     }
 
+    /** Sets if SPE is enabled for {@code ResetDataJob}. */
+    public static void setSpeOnResetDataJobEnabled(boolean enabled) {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB,
+                Boolean.toString(enabled),
+                /* makeDefault */ false);
+    }
+
     /** Sets if aggregate error reporting is enabled or not. */
     public static void setAggregatedErrorReportingEnabled(boolean enabled) {
         DeviceConfig.setProperty(
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/StableFlagsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/StableFlagsTest.java
index 56caab07..199e1d6c 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/StableFlagsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/StableFlagsTest.java
@@ -28,7 +28,6 @@ import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 import org.mockito.quality.Strictness;
 
-
 @RunWith(JUnit4.class)
 public final class StableFlagsTest {
     @Rule
@@ -46,7 +45,7 @@ public final class StableFlagsTest {
     @Test
     public void testValidStableFlags() {
         Object isSipFeatureEnabled =
-                StableFlags.get(PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED);
+                StableFlags.get(FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED);
 
         assertThat(isSipFeatureEnabled).isNotNull();
     }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java
new file mode 100644
index 00000000..40eb693c
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java
@@ -0,0 +1,252 @@
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
+package com.android.ondevicepersonalization.services.data.errors;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.adservices.shared.spe.framework.ExecutionResult.SUCCESS;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.FluentFuture;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+import java.util.List;
+
+/** Unit tests for {@link AggregateErrorDataReportingJob}. */
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@MockStatic(AggregateErrorDataReportingService.class)
+@MockStatic(FlagsFactory.class)
+public class AggregateErrorDataReportingJobTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private AggregateErrorDataReportingJob mSpyAggregateErrorDataReportingJob;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private ExecutionRuntimeParameters mMockParams;
+    @Mock
+    private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock
+    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+    @Mock
+    private AggregatedErrorReportingWorker mMockReportingWorker;
+    @Mock
+    private OdpEncryptionKeyManager mMockEncryptionKeyManager;
+
+    @Before
+    public void setup() throws Exception {
+        mSpyAggregateErrorDataReportingJob = new AggregateErrorDataReportingJob(new TestInjector());
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+    }
+
+    @Test
+    public void testGetExecutionFuture_unencryptedFlow() throws Exception {
+        when(mMockFlags.getAllowUnencryptedAggregatedErrorReportingPayload()).thenReturn(true);
+        when(mMockReportingWorker.reportAggregateErrors(any(), any()))
+                .thenReturn(Futures.immediateVoidFuture());
+
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyAggregateErrorDataReportingJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_unencryptedFlow().get()")
+                .that(executionFuture.get())
+                .isEqualTo(SUCCESS);
+        verify(mMockEncryptionKeyManager, never())
+                .fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any());
+        verify(mMockReportingWorker).reportAggregateErrors(any(), any());
+    }
+
+    @Test
+    public void testGetExecutionFuture_encryptedFlow() throws Exception {
+        when(mMockFlags.getAllowUnencryptedAggregatedErrorReportingPayload())
+                .thenReturn(false);
+        when(mMockReportingWorker.reportAggregateErrors(any(), any()))
+                .thenReturn(Futures.immediateVoidFuture());
+        when(mMockEncryptionKeyManager.fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any()))
+                .thenReturn(FluentFuture.from(Futures.immediateFuture(List.of())));
+
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyAggregateErrorDataReportingJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_encryptedFlow().get()")
+                .that(executionFuture.get())
+                .isEqualTo(SUCCESS);
+        verify(mMockEncryptionKeyManager).fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any());
+        verify(mMockReportingWorker).reportAggregateErrors(any(), any());
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_enabled()")
+                .that(mSpyAggregateErrorDataReportingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_globalKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_globalKillSwitch()")
+                .that(mSpyAggregateErrorDataReportingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_featureOff() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getAggregatedErrorReportingEnabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_featureOff()")
+                .that(mSpyAggregateErrorDataReportingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testSchedule_spe() {
+        when(mMockFlags.getSpeOnAggregateErrorDataReportingJobEnabled()).thenReturn(true);
+
+        AggregateErrorDataReportingJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler).schedule(eq(sContext), any());
+    }
+
+    @Test
+    public void testSchedule_legacy() {
+        int resultCode = SCHEDULING_RESULT_CODE_SUCCESSFUL;
+        when(mMockFlags.getSpeOnAggregateErrorDataReportingJobEnabled()).thenReturn(false);
+
+        JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
+        when(mMockOdpJobServiceFactory.getJobSchedulingLogger()).thenReturn(loggerMock);
+        doReturn(resultCode).when(() -> AggregateErrorDataReportingService
+                .scheduleIfNeeded(any(), /* forceSchedule */ eq(false)));
+
+        AggregateErrorDataReportingJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(sContext), any());
+        verify(() -> AggregateErrorDataReportingService
+                .scheduleIfNeeded(any(), /* forceSchedule */ eq(false)));
+        verify(loggerMock).recordOnSchedulingLegacy(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID,
+                resultCode);
+    }
+
+    @Test
+    public void testCreateDefaultJobSpec() {
+        JobPolicy expectedJobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_UNMETERED)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder().setPeriodicIntervalMs(
+                                        mMockFlags.getAggregatedErrorReportingIntervalInHours()
+                                                * 1000L * 3600L
+                                        ).build())
+                        .setIsPersisted(true)
+                        .build();
+
+        assertWithMessage("createDefaultJobSpec() for AggregateErrorDataReportingJob")
+                .that(AggregateErrorDataReportingJob.createDefaultJobSpec())
+                .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for ResetDataJob")
+                .that(new AggregateErrorDataReportingJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+
+    public class TestInjector extends AggregateErrorDataReportingJob.Injector {
+        @Override
+        ListeningExecutorService getExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        Flags getFlags() {
+            return mMockFlags;
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
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
index ce11a8a3..9cc7e378 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingServiceTest.java
@@ -16,8 +16,12 @@
 
 package com.android.ondevicepersonalization.services.data.errors;
 
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
@@ -26,7 +30,6 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -39,13 +42,14 @@ import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.adservices.shared.spe.JobServiceConstants;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
 import com.android.odp.module.common.encryption.OdpEncryptionKeyManager;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
 
 import com.google.common.util.concurrent.FluentFuture;
 import com.google.common.util.concurrent.Futures;
@@ -73,6 +77,7 @@ public class AggregateErrorDataReportingServiceTest {
     private final JobScheduler mJobScheduler = mContext.getSystemService(JobScheduler.class);
     private boolean mGetGlobalKillSwitch = false;
     private boolean mAggregateErrorReportingEnabled = true;
+    private boolean mSpeOnAggregateErrorDataReportingJobEnabled = false;
 
     @Parameterized.Parameter(0)
     public boolean mAllowUnEncryptedPayload = true;
@@ -100,7 +105,7 @@ public class AggregateErrorDataReportingServiceTest {
 
     @Before
     public void setup() throws Exception {
-        ExtendedMockito.doReturn(mTestFlags).when(FlagsFactory::getFlags);
+        doReturn(mTestFlags).when(FlagsFactory::getFlags);
         MockitoAnnotations.initMocks(this);
 
         mService = spy(new AggregateErrorDataReportingService(new TestInjector()));
@@ -127,8 +132,9 @@ public class AggregateErrorDataReportingServiceTest {
         when(mMockReportingWorker.reportAggregateErrors(any(), any()))
                 .thenReturn(Futures.immediateVoidFuture());
         assertEquals(
-                JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
@@ -155,8 +161,9 @@ public class AggregateErrorDataReportingServiceTest {
         mAggregateErrorReportingEnabled = true;
         when(mMockReportingWorker.reportAggregateErrors(any(), any())).thenReturn(returnedFuture);
         assertEquals(
-                JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
@@ -184,8 +191,9 @@ public class AggregateErrorDataReportingServiceTest {
         mGetGlobalKillSwitch = true;
         doReturn(mJobScheduler).when(mService).getSystemService(JobScheduler.class);
         assertEquals(
-                JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
@@ -207,8 +215,9 @@ public class AggregateErrorDataReportingServiceTest {
         // reporting flag has been disabled.
         doReturn(mJobScheduler).when(mService).getSystemService(JobScheduler.class);
         assertEquals(
-                JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
         assertNotNull(
                 mJobScheduler.getPendingJob(
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
@@ -225,6 +234,25 @@ public class AggregateErrorDataReportingServiceTest {
                         OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID));
     }
 
+    @Test
+    @ExtendedMockitoRule.MockStatic(OdpJobScheduler.class)
+    public void onStartJobTestSpeEnabled() {
+        // Enable SPE.
+        mSpeOnAggregateErrorDataReportingJobEnabled = true;
+
+        // Mock OdpJobScheduler to not actually schedule the job.
+        OdpJobScheduler mockedScheduler = mock(OdpJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+
+        assertThat(mService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify SPE scheduler has rescheduled the job.
+        verify(mockedScheduler).schedule(any(), any());
+
+        // Revert SPE flag.
+        mSpeOnAggregateErrorDataReportingJobEnabled = false;
+    }
+
     @Test
     public void onStopJobTest() {
         assertTrue(mService.onStopJob(mock(JobParameters.class)));
@@ -235,8 +263,9 @@ public class AggregateErrorDataReportingServiceTest {
         mAggregateErrorReportingEnabled = false;
 
         assertEquals(
-                JobScheduler.RESULT_FAILURE,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
     }
 
     @Test
@@ -244,8 +273,9 @@ public class AggregateErrorDataReportingServiceTest {
         mAggregateErrorReportingEnabled = true;
 
         assertEquals(
-                JobScheduler.RESULT_SUCCESS,
-                AggregateErrorDataReportingService.scheduleIfNeeded(mContext, mTestFlags));
+                SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                AggregateErrorDataReportingService
+                        .scheduleIfNeeded(mContext, mTestFlags, /* forceSchedule */ false));
     }
 
     private class TestInjector extends AggregateErrorDataReportingService.Injector {
@@ -285,5 +315,10 @@ public class AggregateErrorDataReportingServiceTest {
         public boolean getAllowUnencryptedAggregatedErrorReportingPayload() {
             return mAllowUnEncryptedPayload;
         }
+
+        @Override
+        public boolean getSpeOnAggregateErrorDataReportingJobEnabled() {
+            return mSpeOnAggregateErrorDataReportingJobEnabled;
+        }
     }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
index 7650abfd..68392c6b 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorCodesLoggerTest.java
@@ -18,6 +18,8 @@ package com.android.ondevicepersonalization.services.data.errors;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
@@ -92,7 +94,7 @@ public class AggregatedErrorCodesLoggerTest {
                         TEST_ISOLATED_SERVICE_ERROR_CODE, TEST_COMPONENT_NAME, mContext);
 
         assertTrue(loggingFuture.isDone());
-        assertTrue(mErrorDataDao.getExceptionData().isEmpty());
+        assertThat(mErrorDataDao.getExceptionData()).isEmpty();
     }
 
     @Test
@@ -132,10 +134,9 @@ public class AggregatedErrorCodesLoggerTest {
                 AggregatedErrorCodesLogger.cleanupAggregatedErrorData(mContext);
 
         assertTrue(cleanupFuture.isDone());
-        assertTrue(mErrorDataDao.getExceptionData().isEmpty());
-        assertTrue(
-                OnDevicePersonalizationAggregatedErrorDataDao.getErrorDataTableNames(mContext)
-                        .isEmpty());
+        assertThat(mErrorDataDao.getExceptionData()).isEmpty();
+        assertThat(OnDevicePersonalizationAggregatedErrorDataDao.getErrorDataTableNames(mContext))
+                .isEmpty();
     }
 
     @After
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java
index e0d40678..5e7615cc 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingProtocolTest.java
@@ -33,7 +33,7 @@ import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
 import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
@@ -241,7 +241,7 @@ public class AggregatedErrorReportingProtocolTest {
                 Arrays.equals(
                         expectedClientUploadRequest.getBody(), clientRequests.get(1).getBody()));
         // No interactions with encrypter since the key was null
-        verifyZeroInteractions(mMockEncrypter);
+        verifyNoMoreInteractions(mMockEncrypter);
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
index 3367c3ad..7f132a79 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
@@ -26,7 +26,10 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
 
 import android.content.ComponentName;
 import android.content.Context;
@@ -35,8 +38,9 @@ import androidx.test.core.app.ApplicationProvider;
 
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.odp.module.common.PackageUtils;
+import com.android.odp.module.common.data.ErrorReportingMetadataStore;
 import com.android.odp.module.common.encryption.OdpEncryptionKey;
-import com.android.ondevicepersonalization.services.Flags;
+import com.android.odp.module.common.proto.ErrorReportingMetadata;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
 
 import com.google.common.collect.ImmutableList;
@@ -45,6 +49,7 @@ import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
 import com.google.common.util.concurrent.SettableFuture;
+import com.google.protobuf.Timestamp;
 
 import org.junit.After;
 import org.junit.Before;
@@ -52,6 +57,8 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.quality.Strictness;
@@ -78,11 +85,18 @@ public class AggregatedErrorReportingWorkerTest {
     private static final ListenableFuture<Boolean> SUCCESSFUL_FUTURE =
             Futures.immediateFuture(true);
 
+    private static final long DEFAULT_REPORTING_INTERVAL_HOURS = 24;
+    private static final ErrorReportingMetadata DEFAULT_UNINITIALIZED_METADATA =
+            ErrorReportingMetadata.getDefaultInstance();
 
     private static final ImmutableList<ComponentName> EMPTY_ODP_SERVICE_LIST = ImmutableList.of();
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
+    private final OnDevicePersonalizationAggregatedErrorDataDao mErrorDataDao =
+            OnDevicePersonalizationAggregatedErrorDataDao.getInstance(
+                    mContext, TEST_COMPONENT_NAME, TEST_CERT_DIGEST);
+
     private TestInjector mTestInjector;
 
     private int mDayIndexUtc;
@@ -90,13 +104,10 @@ public class AggregatedErrorReportingWorkerTest {
     private TestReportingProtocol mTestReportingProtocol;
     private AggregatedErrorReportingWorker mInstanceUnderTest;
 
-    @Mock private Flags mMockFlags;
-
     @Mock private OdpEncryptionKey mMockEncryptionKey;
+    @Mock private ErrorReportingMetadataStore mMockMetadataStore;
 
-    private final OnDevicePersonalizationAggregatedErrorDataDao mErrorDataDao =
-            OnDevicePersonalizationAggregatedErrorDataDao.getInstance(
-                    mContext, TEST_COMPONENT_NAME, TEST_CERT_DIGEST);
+    @Captor ArgumentCaptor<ErrorReportingMetadata> mMetadataArgumentCaptor;
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule =
@@ -108,10 +119,24 @@ public class AggregatedErrorReportingWorkerTest {
 
         // Setup package utils to return the test cert digest
         doReturn(TEST_CERT_DIGEST).when(() -> PackageUtils.getCertDigest(mContext, TEST_PACKAGE));
+        // By default, there is no metadata from previous run
+        doReturn(Futures.immediateFuture(DEFAULT_UNINITIALIZED_METADATA))
+                .when(mMockMetadataStore)
+                .get();
+        doReturn(
+                        Futures.immediateFuture(
+                                DEFAULT_UNINITIALIZED_METADATA.toBuilder()
+                                        .setLastSuccessfulUpload(
+                                                Timestamp.newBuilder()
+                                                        .setSeconds(DateTimeUtils.epochSecondsUtc())
+                                                        .build())))
+                .when(mMockMetadataStore)
+                .set(mMetadataArgumentCaptor.capture());
         mDayIndexUtc = DateTimeUtils.dayIndexUtc();
-        // Inject mock flags and a test ReportingProtocol object
+
+        // Inject a test ReportingProtocol object and a mock metadata store.
         mTestReportingProtocol = new TestReportingProtocol();
-        mTestInjector = new TestInjector(mTestReportingProtocol, mMockFlags);
+        mTestInjector = new TestInjector(mTestReportingProtocol, mMockMetadataStore);
         mInstanceUnderTest = AggregatedErrorReportingWorker.createWorker(mTestInjector);
     }
 
@@ -155,6 +180,7 @@ public class AggregatedErrorReportingWorkerTest {
         doReturn(TEST_ODP_SERVICE_LIST)
                 .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
         mErrorDataDao.addExceptionCount(TEST_ISOLATED_SERVICE_ERROR_CODE, 1);
+        long startSecondsUtc = DateTimeUtils.epochSecondsUtc();
 
         ListenableFuture<Void> returnedFuture =
                 mInstanceUnderTest.reportAggregateErrorsHelper(mContext, mMockEncryptionKey);
@@ -165,6 +191,50 @@ public class AggregatedErrorReportingWorkerTest {
         assertEquals(getExpectedErrorData(mDayIndexUtc), mTestInjector.mErrorData.get(0));
         assertEquals(1, mTestReportingProtocol.mCallCount.get());
         assertThat(mTestReportingProtocol.mOdpEncryptionKey).isSameInstanceAs(mMockEncryptionKey);
+        // Assert that the metadata store has been updated with a recent timestamp.
+        assertThat(mMetadataArgumentCaptor.getAllValues()).hasSize(1);
+        assertThat(mMetadataArgumentCaptor.getValue().getLastSuccessfulUpload().getSeconds())
+                .isAtLeast(startSecondsUtc);
+    }
+
+    @Test
+    public void reportAggregateErrors_withErrorData_beforeIntervalRequirement_noOp() {
+        // When odp services are installed and there is error data present in the tables,
+        // but the interval requirements are not met, expect there to be no interaction with the
+        // test reporting object and a single interaction with the metadata store to get the
+        // current last reported time stamp.
+        doReturn(TEST_ODP_SERVICE_LIST)
+                .when(() -> AppManifestConfigHelper.getOdpServices(mContext, true));
+        mErrorDataDao.addExceptionCount(TEST_ISOLATED_SERVICE_ERROR_CODE, 1);
+        Timestamp currentTimeStamp =
+                Timestamp.newBuilder().setSeconds(DateTimeUtils.epochSecondsUtc()).build();
+        ErrorReportingMetadata newMetadata =
+                DEFAULT_UNINITIALIZED_METADATA.toBuilder()
+                        .setLastSuccessfulUpload(currentTimeStamp)
+                        .build();
+        doReturn(Futures.immediateFuture(newMetadata)).when(mMockMetadataStore).get();
+
+        ListenableFuture<Void> returnedFuture =
+                mInstanceUnderTest.reportAggregateErrors(mContext, mMockEncryptionKey);
+
+        assertTrue(returnedFuture.isDone());
+        assertEquals(0, mTestInjector.mCallCount.get());
+        assertEquals(0, mTestReportingProtocol.mCallCount.get());
+        verify(mMockMetadataStore, times(0)).set(any());
+        verify(mMockMetadataStore, times(1)).get();
+    }
+
+    @Test
+    public void isReportingIntervalSatisfied_uninitialized_returnsTrue() throws Exception {
+        doReturn(Futures.immediateFuture(DEFAULT_UNINITIALIZED_METADATA))
+                .when(mMockMetadataStore)
+                .get();
+
+        ListenableFuture<Boolean> returnedFuture =
+                mInstanceUnderTest.isReportingIntervalSatisfied(mContext);
+
+        assertTrue(returnedFuture.isDone());
+        assertThat(returnedFuture.get()).isTrue();
     }
 
     @Test
@@ -227,15 +297,18 @@ public class AggregatedErrorReportingWorkerTest {
 
     private static final class TestInjector extends AggregatedErrorReportingWorker.Injector {
         private final ReportingProtocol mTestProtocol;
-        private final Flags mFlags;
+
+        private final ErrorReportingMetadataStore mStore;
 
         private String mRequestUri;
         private ImmutableList<ErrorData> mErrorData;
         private final AtomicInteger mCallCount = new AtomicInteger(0);
 
-        TestInjector(ReportingProtocol testProtocol, Flags flags) {
+        TestInjector(
+                ReportingProtocol testProtocol,
+                ErrorReportingMetadataStore errorReportingMetadataStore) {
             this.mTestProtocol = testProtocol;
-            this.mFlags = flags;
+            this.mStore = errorReportingMetadataStore;
         }
 
         @Override
@@ -250,11 +323,6 @@ public class AggregatedErrorReportingWorkerTest {
             return MoreExecutors.newDirectExecutorService();
         }
 
-        @Override
-        Flags getFlags() {
-            return mFlags;
-        }
-
         @Override
         ReportingProtocol getAggregatedErrorReportingProtocol(
                 ImmutableList<ErrorData> errorData, String requestBaseUri, Context context) {
@@ -268,5 +336,15 @@ public class AggregatedErrorReportingWorkerTest {
         String getServerUrl(Context context, String packageName) {
             return TEST_SERVER_URL;
         }
+
+        @Override
+        long getErrorReportingIntervalHours() {
+            return DEFAULT_REPORTING_INTERVAL_HOURS;
+        }
+
+        @Override
+        ErrorReportingMetadataStore getMetadataStore(Context context) {
+            return mStore;
+        }
     }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/events/EventsDaoTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/events/EventsDaoTest.java
index 2849cd9a..25a50388 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/events/EventsDaoTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/events/EventsDaoTest.java
@@ -16,6 +16,8 @@
 
 package com.android.ondevicepersonalization.services.data.events;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -46,39 +48,48 @@ public class EventsDaoTest {
     private static final String APP_NAME = "com.app";
     private static final String TASK_IDENTIFIER = "taskIdentifier";
     private static final String SERVICE_CLASS = "TestClass";
-    private final Context mContext = ApplicationProvider.getApplicationContext();
-    private final ComponentName mService =
-            new ComponentName(mContext.getPackageName(), SERVICE_CLASS);
-    private final String mServiceCert = "AABBCCDD";
-    private final byte[] mQueryData = "query".getBytes(StandardCharsets.UTF_8);
-
-    private final Event mTestEvent = new Event.Builder()
-            .setType(EVENT_TYPE_B2D)
-            .setEventData("event".getBytes(StandardCharsets.UTF_8))
-            .setService(mService)
-            .setQueryId(1L)
-            .setTimeMillis(1L)
-            .setRowIndex(0)
-            .build();
-    private final Query mTestQuery = new Query.Builder(
-            1L, APP_NAME, mService, mServiceCert, mQueryData)
-            .build();
-    private final EventState mEventState = new EventState.Builder()
-            .setTaskIdentifier(TASK_IDENTIFIER)
-            .setService(mService)
-            .setToken(new byte[]{1})
-            .build();
+    private static final Context sTestContext = ApplicationProvider.getApplicationContext();
+    private static final ComponentName TEST_SERVICE_COMPONENT_NAME =
+            new ComponentName(sTestContext.getPackageName(), SERVICE_CLASS);
+    private static final String TEST_SERVICE_CERT = "AABBCCDD";
+    private static final byte[] TEST_QUERY_DATA = "query".getBytes(StandardCharsets.UTF_8);
+
+    private static final byte[] TEST_EVENT_DATA = "event".getBytes(StandardCharsets.UTF_8);
+
+    private static final Event TEST_EVENT =
+            new Event.Builder()
+                    .setType(EVENT_TYPE_B2D)
+                    .setEventData(TEST_EVENT_DATA)
+                    .setService(TEST_SERVICE_COMPONENT_NAME)
+                    .setQueryId(1L)
+                    .setTimeMillis(1L)
+                    .setRowIndex(0)
+                    .build();
+    private static final Query TEST_QUERY =
+            new Query.Builder(
+                            1L,
+                            APP_NAME,
+                            TEST_SERVICE_COMPONENT_NAME,
+                            TEST_SERVICE_CERT,
+                            TEST_QUERY_DATA)
+                    .build();
+    private static final EventState TEST_EVENT_STATE =
+            new EventState.Builder()
+                    .setTaskIdentifier(TASK_IDENTIFIER)
+                    .setService(TEST_SERVICE_COMPONENT_NAME)
+                    .setToken(new byte[] {1})
+                    .build();
     private EventsDao mDao;
 
     @Before
     public void setup() {
-        mDao = EventsDao.getInstanceForTest(mContext);
+        mDao = EventsDao.getInstanceForTest(sTestContext);
     }
 
     @After
     public void cleanup() {
         OnDevicePersonalizationDbHelper dbHelper =
-                OnDevicePersonalizationDbHelper.getInstanceForTest(mContext);
+                OnDevicePersonalizationDbHelper.getInstanceForTest(sTestContext);
         dbHelper.getWritableDatabase().close();
         dbHelper.getReadableDatabase().close();
         dbHelper.close();
@@ -86,32 +97,34 @@ public class EventsDaoTest {
 
     @Test
     public void testInsertQueryAndEvent() {
-        assertEquals(1, mDao.insertQuery(mTestQuery));
-        assertEquals(1, mDao.insertEvent(mTestEvent));
-        Event testEvent = new Event.Builder()
-                .setType(EVENT_TYPE_CLICK)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(1L)
-                .setTimeMillis(1L)
-                .setRowIndex(0)
-                .build();
+        assertEquals(1, mDao.insertQuery(TEST_QUERY));
+        assertEquals(1, mDao.insertEvent(TEST_EVENT));
+        Event testEvent =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_CLICK)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(1L)
+                        .setTimeMillis(1L)
+                        .setRowIndex(0)
+                        .build();
         assertEquals(2, mDao.insertEvent(testEvent));
     }
 
     @Test
     public void testInsertEvents() {
-        mDao.insertQuery(mTestQuery);
-        Event testEvent = new Event.Builder()
-                .setType(EVENT_TYPE_CLICK)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(1L)
-                .setTimeMillis(1L)
-                .setRowIndex(0)
-                .build();
+        mDao.insertQuery(TEST_QUERY);
+        Event testEvent =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_CLICK)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(1L)
+                        .setTimeMillis(1L)
+                        .setRowIndex(0)
+                        .build();
         List<Event> events = new ArrayList<>();
-        events.add(mTestEvent);
+        events.add(TEST_EVENT);
         events.add(testEvent);
         assertTrue(mDao.insertEvents(events));
     }
@@ -119,53 +132,56 @@ public class EventsDaoTest {
     @Test
     public void testInsertEventsFalse() {
         List<Event> events = new ArrayList<>();
-        events.add(mTestEvent);
+        events.add(TEST_EVENT);
         assertFalse(mDao.insertEvents(events));
     }
 
     @Test
     public void testInsertAndReadEventState() {
-        assertTrue(mDao.updateOrInsertEventState(mEventState));
-        assertEquals(mEventState, mDao.getEventState(TASK_IDENTIFIER, mService));
-        EventState testEventState = new EventState.Builder()
-                .setTaskIdentifier(TASK_IDENTIFIER)
-                .setService(mService)
-                .setToken(new byte[]{100})
-                .build();
+        assertTrue(mDao.updateOrInsertEventState(TEST_EVENT_STATE));
+        assertEquals(
+                TEST_EVENT_STATE, mDao.getEventState(TASK_IDENTIFIER, TEST_SERVICE_COMPONENT_NAME));
+        EventState testEventState =
+                new EventState.Builder()
+                        .setTaskIdentifier(TASK_IDENTIFIER)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setToken(new byte[] {100})
+                        .build();
         assertTrue(mDao.updateOrInsertEventState(testEventState));
-        assertEquals(testEventState,
-                mDao.getEventState(TASK_IDENTIFIER, mService));
+        assertEquals(
+                testEventState, mDao.getEventState(TASK_IDENTIFIER, TEST_SERVICE_COMPONENT_NAME));
     }
 
 
     @Test
     public void testInsertAndReadEventStatesTransaction() {
-        EventState testEventState = new EventState.Builder()
-                .setTaskIdentifier(TASK_IDENTIFIER)
-                .setService(mService)
-                .setToken(new byte[]{100})
-                .build();
+        EventState testEventState =
+                new EventState.Builder()
+                        .setTaskIdentifier(TASK_IDENTIFIER)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setToken(new byte[] {100})
+                        .build();
         List<EventState> eventStates = new ArrayList<>();
-        eventStates.add(mEventState);
+        eventStates.add(TEST_EVENT_STATE);
         eventStates.add(testEventState);
         assertTrue(mDao.updateOrInsertEventStatesTransaction(eventStates));
-        assertEquals(testEventState,
-                mDao.getEventState(TASK_IDENTIFIER, mService));
+        assertEquals(
+                testEventState, mDao.getEventState(TASK_IDENTIFIER, TEST_SERVICE_COMPONENT_NAME));
     }
     @Test
     public void testDeleteEventState() {
         ComponentName serviceA = new ComponentName("packageA", "clsA");
-        mDao.updateOrInsertEventState(mEventState);
+        mDao.updateOrInsertEventState(TEST_EVENT_STATE);
         EventState testEventState = new EventState.Builder()
                 .setTaskIdentifier(TASK_IDENTIFIER)
                 .setService(serviceA)
                 .setToken(new byte[]{100})
                 .build();
         mDao.updateOrInsertEventState(testEventState);
-        mDao.deleteEventState(mService);
+        mDao.deleteEventState(TEST_SERVICE_COMPONENT_NAME);
         assertEquals(testEventState,
                 mDao.getEventState(TASK_IDENTIFIER, serviceA));
-        assertNull(mDao.getEventState(TASK_IDENTIFIER, mService));
+        assertNull(mDao.getEventState(TASK_IDENTIFIER, TEST_SERVICE_COMPONENT_NAME));
 
         mDao.deleteEventState(serviceA);
         assertNull(mDao.getEventState(TASK_IDENTIFIER, serviceA));
@@ -173,38 +189,46 @@ public class EventsDaoTest {
 
     @Test
     public void testDeleteEventsAndQueries() {
-        mDao.insertQuery(mTestQuery);
-        mDao.insertEvent(mTestEvent);
-        long queryId2 = mDao.insertQuery(mTestQuery);
-        Event testEvent = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId2)
-                .setTimeMillis(3L)
-                .setRowIndex(0)
-                .build();
+        mDao.insertQuery(TEST_QUERY);
+        mDao.insertEvent(TEST_EVENT);
+        long queryId2 = mDao.insertQuery(TEST_QUERY);
+        Event testEvent =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId2)
+                        .setTimeMillis(3L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(testEvent);
 
-        Query testQuery = new Query.Builder(5L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query testQuery =
+                new Query.Builder(
+                                5L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(testQuery);
 
         // Delete query1 event1. Assert query2 and event2 still exist.
         mDao.deleteEventsAndQueries(2);
         List<JoinedEvent> joinedEventList = mDao.readAllNewRows(0, 0);
-        assertEquals(3, joinedEventList.size());
-        assertEquals(createExpectedJoinedEvent(testEvent, mTestQuery, eventId2, queryId2),
+        assertThat(joinedEventList).hasSize(3);
+        assertEquals(
+                createExpectedJoinedEvent(testEvent, TEST_QUERY, eventId2, queryId2),
                 joinedEventList.get(0));
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId2),
-                joinedEventList.get(1));
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId2), joinedEventList.get(1));
         assertEquals(createExpectedJoinedEvent(null, testQuery, 0, queryId3),
                 joinedEventList.get(2));
 
         // Delete query2 event2. Assert query3 still exist.
         mDao.deleteEventsAndQueries(4);
         joinedEventList = mDao.readAllNewRows(0, 0);
-        assertEquals(1, joinedEventList.size());
+        assertThat(joinedEventList).hasSize(1);
         assertEquals(createExpectedJoinedEvent(null, testQuery, 0, queryId3),
                 joinedEventList.get(0));
     }
@@ -213,97 +237,103 @@ public class EventsDaoTest {
     @Test
     public void testReadAllNewRowsEmptyTable() {
         List<JoinedEvent> joinedEventList = mDao.readAllNewRows(0, 0);
-        assertTrue(joinedEventList.isEmpty());
+        assertThat(joinedEventList).isEmpty();
     }
 
     @Test
     public void testReadAllNewRowsForPackageEmptyTable() {
-        List<JoinedEvent> joinedEventList = mDao.readAllNewRowsForPackage(mService,
-                0, 0);
-        assertTrue(joinedEventList.isEmpty());
+        List<JoinedEvent> joinedEventList =
+                mDao.readAllNewRowsForPackage(TEST_SERVICE_COMPONENT_NAME, 0, 0);
+        assertThat(joinedEventList).isEmpty();
     }
 
     @Test
     public void testReadAllNewRowsForPackage() {
-        long queryId1 = mDao.insertQuery(mTestQuery);
-        long eventId1 = mDao.insertEvent(mTestEvent);
-        long queryId2 = mDao.insertQuery(mTestQuery);
+        long queryId1 = mDao.insertQuery(TEST_QUERY);
+        long eventId1 = mDao.insertEvent(TEST_EVENT);
+        long queryId2 = mDao.insertQuery(TEST_QUERY);
         ComponentName serviceA = new ComponentName("packageA", "clsA");
 
-        Query packageAQuery = new Query.Builder(1L, APP_NAME, serviceA, mServiceCert, mQueryData)
-                .build();
+        Query packageAQuery =
+                new Query.Builder(1L, APP_NAME, serviceA, TEST_SERVICE_CERT, TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(packageAQuery);
 
-        Event packageAEvent = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(serviceA)
-                .setQueryId(queryId3)
-                .setTimeMillis(1L)
-                .setRowIndex(0)
-                .build();
+        Event packageAEvent =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(serviceA)
+                        .setQueryId(queryId3)
+                        .setTimeMillis(1L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(packageAEvent);
 
-        List<JoinedEvent> joinedEventList = mDao.readAllNewRowsForPackage(mService,
-                0, 0);
-        assertEquals(3, joinedEventList.size());
-        assertEquals(createExpectedJoinedEvent(mTestEvent, mTestQuery, eventId1, queryId1),
-                joinedEventList.get(0));
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId1),
-                joinedEventList.get(1));
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId2),
-                joinedEventList.get(2));
-
-        joinedEventList = mDao.readAllNewRowsForPackage(mService, eventId1,
-                queryId2);
-        assertTrue(joinedEventList.isEmpty());
-
-        joinedEventList = mDao.readAllNewRowsForPackage(mService, eventId1,
-                queryId1);
-        assertEquals(1, joinedEventList.size());
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId2),
+        List<JoinedEvent> joinedEventList =
+                mDao.readAllNewRowsForPackage(TEST_SERVICE_COMPONENT_NAME, 0, 0);
+        assertThat(joinedEventList).hasSize(3);
+        assertEquals(
+                createExpectedJoinedEvent(TEST_EVENT, TEST_QUERY, eventId1, queryId1),
                 joinedEventList.get(0));
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId1), joinedEventList.get(1));
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId2), joinedEventList.get(2));
+
+        joinedEventList =
+                mDao.readAllNewRowsForPackage(TEST_SERVICE_COMPONENT_NAME, eventId1, queryId2);
+        assertThat(joinedEventList).isEmpty();
+
+        joinedEventList =
+                mDao.readAllNewRowsForPackage(TEST_SERVICE_COMPONENT_NAME, eventId1, queryId1);
+        assertThat(joinedEventList).hasSize(1);
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId2), joinedEventList.get(0));
     }
 
     @Test
     public void testReadAllNewRows() {
-        long queryId1 = mDao.insertQuery(mTestQuery);
-        long eventId1 = mDao.insertEvent(mTestEvent);
-        long queryId2 = mDao.insertQuery(mTestQuery);
+        long queryId1 = mDao.insertQuery(TEST_QUERY);
+        long eventId1 = mDao.insertEvent(TEST_EVENT);
+        long queryId2 = mDao.insertQuery(TEST_QUERY);
         ComponentName serviceA = new ComponentName("packageA", "clsA");
 
-        Query packageAQuery = new Query.Builder(1L, APP_NAME, serviceA, mServiceCert, mQueryData)
-                .build();
+        Query packageAQuery =
+                new Query.Builder(1L, APP_NAME, serviceA, TEST_SERVICE_CERT, TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(packageAQuery);
 
-        Event packageAEvent = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(serviceA)
-                .setQueryId(queryId3)
-                .setTimeMillis(1L)
-                .setRowIndex(0)
-                .build();
+        Event packageAEvent =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(serviceA)
+                        .setQueryId(queryId3)
+                        .setTimeMillis(1L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(packageAEvent);
 
         List<JoinedEvent> joinedEventList = mDao.readAllNewRows(0, 0);
-        assertEquals(5, joinedEventList.size());
-        assertEquals(createExpectedJoinedEvent(mTestEvent, mTestQuery, eventId1, queryId1),
+        assertThat(joinedEventList).hasSize(5);
+        assertEquals(
+                createExpectedJoinedEvent(TEST_EVENT, TEST_QUERY, eventId1, queryId1),
                 joinedEventList.get(0));
         assertEquals(createExpectedJoinedEvent(packageAEvent, packageAQuery, eventId2, queryId3),
                 joinedEventList.get(1));
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId1),
-                joinedEventList.get(2));
-        assertEquals(createExpectedJoinedEvent(null, mTestQuery, 0, queryId2),
-                joinedEventList.get(3));
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId1), joinedEventList.get(2));
+        assertEquals(
+                createExpectedJoinedEvent(null, TEST_QUERY, 0, queryId2), joinedEventList.get(3));
         assertEquals(createExpectedJoinedEvent(null, packageAQuery, 0, queryId3),
                 joinedEventList.get(4));
 
         joinedEventList = mDao.readAllNewRows(eventId2, queryId3);
-        assertTrue(joinedEventList.isEmpty());
+        assertThat(joinedEventList).isEmpty();
 
         joinedEventList = mDao.readAllNewRows(eventId2, queryId2);
-        assertEquals(1, joinedEventList.size());
+        assertThat(joinedEventList).hasSize(1);
         assertEquals(createExpectedJoinedEvent(null, packageAQuery, 0, queryId3),
                 joinedEventList.get(0));
     }
@@ -312,276 +342,351 @@ public class EventsDaoTest {
     public void testReadAllQueries() {
         ComponentName otherService = new ComponentName("package", "cls");
         String otherCert = "11223344";
-        Query query1 = new Query.Builder(1L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query1 =
+                new Query.Builder(
+                                1L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId1 = mDao.insertQuery(query1);
-        Query query2 = new Query.Builder(10L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query2 =
+                new Query.Builder(
+                                10L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId2 = mDao.insertQuery(query2);
-        Query query3 = new Query.Builder(100L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query3 =
+                new Query.Builder(
+                                100L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(query3);
-        Query query4 = new Query.Builder(100L, APP_NAME, otherService, otherCert, mQueryData)
-                .build();
+        Query query4 =
+                new Query.Builder(100L, APP_NAME, otherService, otherCert, TEST_QUERY_DATA).build();
         long queryId4 = mDao.insertQuery(query4);
 
-        List<Query> result = mDao.readAllQueries(0, 1000, mService);
-        assertEquals(3, result.size());
+        List<Query> result = mDao.readAllQueries(0, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(3);
         assertEquals(queryId1, (long) result.get(0).getQueryId());
         assertEquals(queryId2, (long) result.get(1).getQueryId());
         assertEquals(queryId3, (long) result.get(2).getQueryId());
 
         result = mDao.readAllQueries(0, 1000, otherService);
-        assertEquals(1, result.size());
+        assertThat(result).hasSize(1);
         assertEquals(queryId4, (long) result.get(0).getQueryId());
 
-        result = mDao.readAllQueries(500, 1000, mService);
-        assertEquals(0, result.size());
+        result = mDao.readAllQueries(500, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).isEmpty();
 
-        result = mDao.readAllQueries(5, 1000, mService);
-        assertEquals(2, result.size());
+        result = mDao.readAllQueries(5, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(2);
         assertEquals(queryId2, (long) result.get(0).getQueryId());
         assertEquals(queryId3, (long) result.get(1).getQueryId());
     }
 
     @Test
     public void testReadAllEventIds() {
-        Query query1 = new Query.Builder(
-                1L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query1 =
+                new Query.Builder(
+                                1L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId1 = mDao.insertQuery(query1);
-        Query query2 = new Query.Builder(
-                10L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query2 =
+                new Query.Builder(
+                                10L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId2 = mDao.insertQuery(query2);
-        Query query3 = new Query.Builder(
-                100L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query3 =
+                new Query.Builder(
+                                100L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(query3);
 
-        Event event1 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId1)
-                .setTimeMillis(2L)
-                .setRowIndex(0)
-                .build();
+        Event event1 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId1)
+                        .setTimeMillis(2L)
+                        .setRowIndex(0)
+                        .build();
         long eventId1 = mDao.insertEvent(event1);
-        Event event2 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId2)
-                .setTimeMillis(11L)
-                .setRowIndex(0)
-                .build();
+        Event event2 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId2)
+                        .setTimeMillis(11L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(event2);
-        Event event3 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId3)
-                .setTimeMillis(101L)
-                .setRowIndex(0)
-                .build();
+        Event event3 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId3)
+                        .setTimeMillis(101L)
+                        .setRowIndex(0)
+                        .build();
         long eventId3 = mDao.insertEvent(event3);
 
-        List<Long> result = mDao.readAllEventIds(0, 1000, mService);
-        assertEquals(3, result.size());
+        List<Long> result = mDao.readAllEventIds(0, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(3);
         assertEquals(eventId1, (long) result.get(0));
         assertEquals(eventId2, (long) result.get(1));
         assertEquals(eventId3, (long) result.get(2));
 
         result = mDao.readAllEventIds(0, 1000, new ComponentName("pkg", "cls"));
-        assertEquals(0, result.size());
+        assertThat(result).isEmpty();
 
-        result = mDao.readAllEventIds(500, 1000, mService);
-        assertEquals(0, result.size());
+        result = mDao.readAllEventIds(500, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).isEmpty();
 
-        result = mDao.readAllEventIds(5, 1000, mService);
-        assertEquals(2, result.size());
+        result = mDao.readAllEventIds(5, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(2);
         assertEquals(eventId2, (long) result.get(0));
         assertEquals(eventId3, (long) result.get(1));
     }
 
     @Test
     public void testReadEventIdsForRequest() {
-        Query query1 = new Query.Builder(
-                1L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query1 =
+                new Query.Builder(
+                                1L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId1 = mDao.insertQuery(query1);
-        Query query2 = new Query.Builder(
-                10L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query2 =
+                new Query.Builder(
+                                10L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId2 = mDao.insertQuery(query2);
 
-        Event event1 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId1)
-                .setTimeMillis(2L)
-                .setRowIndex(0)
-                .build();
+        Event event1 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId1)
+                        .setTimeMillis(2L)
+                        .setRowIndex(0)
+                        .build();
         long eventId1 = mDao.insertEvent(event1);
-        Event event2 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId2)
-                .setTimeMillis(11L)
-                .setRowIndex(0)
-                .build();
+        Event event2 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId2)
+                        .setTimeMillis(11L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(event2);
-        Event event3 = new Event.Builder()
-                .setType(EVENT_TYPE_CLICK)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId2)
-                .setTimeMillis(101L)
-                .setRowIndex(0)
-                .build();
+        Event event3 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_CLICK)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId2)
+                        .setTimeMillis(101L)
+                        .setRowIndex(0)
+                        .build();
         long eventId3 = mDao.insertEvent(event3);
 
-        List<Long> result = mDao.readAllEventIdsForQuery(queryId1, mService);
-        assertEquals(1, result.size());
+        List<Long> result = mDao.readAllEventIdsForQuery(queryId1, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(1);
         assertEquals(eventId1, (long) result.get(0));
 
-        result = mDao.readAllEventIdsForQuery(queryId2, mService);
-        assertEquals(2, result.size());
+        result = mDao.readAllEventIdsForQuery(queryId2, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(2);
         assertEquals(eventId2, (long) result.get(0));
         assertEquals(eventId3, (long) result.get(1));
 
-        result = mDao.readAllEventIdsForQuery(1000, mService);
-        assertEquals(0, result.size());
+        result = mDao.readAllEventIdsForQuery(1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).isEmpty();
 
         result = mDao.readAllEventIdsForQuery(queryId1, new ComponentName("pkg", "cls"));
-        assertEquals(0, result.size());
+        assertThat(result).isEmpty();
     }
 
     @Test
     public void testReadJoinedEvents() {
-        Query query1 = new Query.Builder(
-                1L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query1 =
+                new Query.Builder(
+                                1L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId1 = mDao.insertQuery(query1);
-        Query query2 = new Query.Builder(
-                10L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query2 =
+                new Query.Builder(
+                                10L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId2 = mDao.insertQuery(query2);
-        Query query3 = new Query.Builder(
-                100L, APP_NAME, mService, mServiceCert, mQueryData)
-                .build();
+        Query query3 =
+                new Query.Builder(
+                                100L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .build();
         long queryId3 = mDao.insertQuery(query3);
 
-        Event event1 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId1)
-                .setTimeMillis(2L)
-                .setRowIndex(0)
-                .build();
+        Event event1 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId1)
+                        .setTimeMillis(2L)
+                        .setRowIndex(0)
+                        .build();
         long eventId1 = mDao.insertEvent(event1);
-        Event event2 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId2)
-                .setTimeMillis(11L)
-                .setRowIndex(0)
-                .build();
+        Event event2 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId2)
+                        .setTimeMillis(11L)
+                        .setRowIndex(0)
+                        .build();
         long eventId2 = mDao.insertEvent(event2);
-        Event event3 = new Event.Builder()
-                .setType(EVENT_TYPE_B2D)
-                .setEventData("event".getBytes(StandardCharsets.UTF_8))
-                .setService(mService)
-                .setQueryId(queryId3)
-                .setTimeMillis(101L)
-                .setRowIndex(0)
-                .build();
+        Event event3 =
+                new Event.Builder()
+                        .setType(EVENT_TYPE_B2D)
+                        .setEventData(TEST_EVENT_DATA)
+                        .setService(TEST_SERVICE_COMPONENT_NAME)
+                        .setQueryId(queryId3)
+                        .setTimeMillis(101L)
+                        .setRowIndex(0)
+                        .build();
         long eventId3 = mDao.insertEvent(event3);
 
-        List<JoinedEvent> result = mDao.readJoinedTableRows(0, 1000, mService);
-        assertEquals(3, result.size());
+        List<JoinedEvent> result = mDao.readJoinedTableRows(0, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(3);
         assertEquals(createExpectedJoinedEvent(event1, query1, eventId1, queryId1), result.get(0));
         assertEquals(createExpectedJoinedEvent(event2, query2, eventId2, queryId2), result.get(1));
         assertEquals(createExpectedJoinedEvent(event3, query3, eventId3, queryId3), result.get(2));
 
         result = mDao.readJoinedTableRows(0, 1000, new ComponentName("pkg", "cls"));
-        assertEquals(0, result.size());
+        assertThat(result).isEmpty();
+
+        result = mDao.readJoinedTableRows(500, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).isEmpty();
 
-        result = mDao.readJoinedTableRows(500, 1000, mService);
-        assertEquals(0, result.size());
+        result = mDao.readJoinedTableRows(5, 1000, TEST_SERVICE_COMPONENT_NAME);
+        assertThat(result).hasSize(2);
 
-        result = mDao.readJoinedTableRows(5, 1000, mService);
-        assertEquals(2, result.size());
         assertEquals(createExpectedJoinedEvent(event2, query2, eventId2, queryId2), result.get(0));
         assertEquals(createExpectedJoinedEvent(event3, query3, eventId3, queryId3), result.get(1));
     }
 
     @Test
     public void testReadSingleQuery() {
-        Query query1 = new Query.Builder(
-                1L, APP_NAME, mService, mServiceCert, mQueryData)
-                .setQueryId(1)
-                .build();
+        Query query1 =
+                new Query.Builder(
+                                1L,
+                                APP_NAME,
+                                TEST_SERVICE_COMPONENT_NAME,
+                                TEST_SERVICE_CERT,
+                                TEST_QUERY_DATA)
+                        .setQueryId(1)
+                        .build();
         mDao.insertQuery(query1);
-        Query query2 = mDao.readSingleQueryRow(1, mService);
+        Query query2 = mDao.readSingleQueryRow(1, TEST_SERVICE_COMPONENT_NAME);
         assertEquals(query1.getQueryId(), query2.getQueryId());
         assertEquals(query1.getTimeMillis(), query2.getTimeMillis());
         assertEquals(query1.getAppPackageName(), query2.getAppPackageName());
         assertEquals(query1.getService(), query2.getService());
         assertEquals(query1.getServiceCertDigest(), query2.getServiceCertDigest());
         assertArrayEquals(query1.getQueryData(), query2.getQueryData());
-        assertNull(mDao.readSingleQueryRow(100, mService));
+        assertNull(mDao.readSingleQueryRow(100, TEST_SERVICE_COMPONENT_NAME));
         assertNull(mDao.readSingleQueryRow(1, new ComponentName("pkg", "cls")));
     }
 
     @Test
     public void testReadSingleJoinedTableRow() {
-        mDao.insertQuery(mTestQuery);
-        mDao.insertEvent(mTestEvent);
-        assertEquals(createExpectedJoinedEvent(mTestEvent, mTestQuery, 1, 1),
-                mDao.readSingleJoinedTableRow(1, mService));
-        assertNull(mDao.readSingleJoinedTableRow(100, mService));
+        mDao.insertQuery(TEST_QUERY);
+        mDao.insertEvent(TEST_EVENT);
+        assertEquals(
+                createExpectedJoinedEvent(TEST_EVENT, TEST_QUERY, 1, 1),
+                mDao.readSingleJoinedTableRow(1, TEST_SERVICE_COMPONENT_NAME));
+        assertNull(mDao.readSingleJoinedTableRow(100, TEST_SERVICE_COMPONENT_NAME));
         assertNull(mDao.readSingleJoinedTableRow(1, new ComponentName("pkg", "cls")));
     }
 
     @Test
     public void testReadEventStateNoEventState() {
-        assertNull(mDao.getEventState(TASK_IDENTIFIER, mService));
+        assertNull(mDao.getEventState(TASK_IDENTIFIER, TEST_SERVICE_COMPONENT_NAME));
     }
 
 
     @Test
     public void testInsertEventFKError() {
-        assertEquals(-1, mDao.insertEvent(mTestEvent));
+        assertEquals(-1, mDao.insertEvent(TEST_EVENT));
     }
 
     @Test
     public void testInsertQueryId() {
-        assertEquals(1, mDao.insertQuery(mTestQuery));
-        assertEquals(2, mDao.insertQuery(mTestQuery));
+        assertEquals(1, mDao.insertQuery(TEST_QUERY));
+        assertEquals(2, mDao.insertQuery(TEST_QUERY));
     }
 
     @Test
     public void testInsertEventExistingKey() {
-        assertEquals(1, mDao.insertQuery(mTestQuery));
-        assertEquals(1, mDao.insertEvent(mTestEvent));
-        assertEquals(2, mDao.insertEvent(mTestEvent));
+        assertEquals(1, mDao.insertQuery(TEST_QUERY));
+        assertEquals(1, mDao.insertEvent(TEST_EVENT));
+        assertEquals(2, mDao.insertEvent(TEST_EVENT));
     }
 
     @Test
     public void testHasExistingEvent() {
-        assertEquals(1, mDao.insertQuery(mTestQuery));
-        assertEquals(1, mDao.insertEvent(mTestEvent));
-        assertTrue(mDao.hasEvent(
-                mTestEvent.getQueryId(),
-                mTestEvent.getType(),
-                mTestEvent.getRowIndex(),
-                mTestEvent.getService()));
+        assertEquals(1, mDao.insertQuery(TEST_QUERY));
+        assertEquals(1, mDao.insertEvent(TEST_EVENT));
+        assertTrue(
+                mDao.hasEvent(
+                        TEST_EVENT.getQueryId(),
+                        TEST_EVENT.getType(),
+                        TEST_EVENT.getRowIndex(),
+                        TEST_EVENT.getService()));
     }
 
     private JoinedEvent createExpectedJoinedEvent(Event event, Query query, long eventId,
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobServiceTest.java
index 7eac2c5d..d7565044 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobServiceTest.java
@@ -16,6 +16,18 @@
 
 package com.android.ondevicepersonalization.services.data.user;
 
+import static android.app.job.JobScheduler.RESULT_FAILURE;
+import static android.app.job.JobScheduler.RESULT_SUCCESS;
+
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_FAILED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
+
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
@@ -24,23 +36,24 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.app.job.JobInfo;
 import android.app.job.JobParameters;
 import android.app.job.JobScheduler;
 import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
 
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
@@ -77,6 +90,7 @@ public class UserDataCollectionJobServiceTest {
         mService = spy(new UserDataCollectionJobService(new TestInjector()));
         doNothing().when(mService).jobFinished(any(), anyBoolean());
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(false);
     }
 
     @After
@@ -95,8 +109,8 @@ public class UserDataCollectionJobServiceTest {
     @Test
     public void onStartJobTest() throws Exception {
         doReturn(mContext.getPackageManager()).when(mService).getPackageManager();
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(false).when(mUserPrivacyStatus)
+        doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        doReturn(false).when(mUserPrivacyStatus)
                 .isProtectedAudienceAndMeasurementBothDisabled();
 
         boolean result = mService.onStartJob(mock(JobParameters.class));
@@ -109,7 +123,7 @@ public class UserDataCollectionJobServiceTest {
     public void onStartJobTestKillSwitchEnabled() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
         doReturn(mJobScheduler).when(mService).getSystemService(JobScheduler.class);
-        mService.schedule(mContext);
+        mService.schedule(mContext, /* forceSchedule */ false);
         assertNotNull(
                 mJobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID));
 
@@ -121,12 +135,103 @@ public class UserDataCollectionJobServiceTest {
                 mJobScheduler.getPendingJob(OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID));
     }
 
+    @Test
+    @MockStatic(OdpJobScheduler.class)
+    @MockStatic(FlagsFactory.class)
+    public void onStartJobTestSpeEnabled() {
+        // Enable SPE on UserDataCollectionJob & UserDataCollectionJobService
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(true);
+
+        // Mock OdpJobScheduler to not actually schedule the job.
+        OdpJobScheduler mockedScheduler = mock(OdpJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+
+        assertThat(mService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify SPE scheduler has rescheduled the job.
+        verify(mockedScheduler).schedule(any(), any());
+    }
+
+    @Test
+    public void testSchedule_scheduleSuccessful_resultCodeSuccess() {
+        Context spyContext = getSpyContext();
+        JobScheduler mockJobScheduler = mock(JobScheduler.class);
+        doReturn(mockJobScheduler).when(spyContext).getSystemService(JobScheduler.class);
+        doReturn(/* jobInfo */ null).when(mockJobScheduler).getPendingJob(USER_DATA_COLLECTION_ID);
+
+        // Schedule successful
+        doReturn(RESULT_SUCCESS).when(mockJobScheduler).schedule(any());
+
+        int resultCode = mService.schedule(spyContext, /* forceSchedule */ false);
+
+        assertThat(resultCode).isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+    }
+
+    @Test
+    public void testSchedule_scheduleFailure_resultCodeFailed() {
+        Context spyContext = getSpyContext();
+        JobScheduler mockJobScheduler = mock(JobScheduler.class);
+        doReturn(mockJobScheduler).when(spyContext).getSystemService(JobScheduler.class);
+        doReturn(/* jobInfo */ null).when(mockJobScheduler).getPendingJob(USER_DATA_COLLECTION_ID);
+
+        // Schedule failure
+        doReturn(RESULT_FAILURE).when(mockJobScheduler).schedule(any());
+
+        int resultCode = mService.schedule(spyContext, /* forceSchedule */ false);
+
+        assertThat(resultCode).isEqualTo(SCHEDULING_RESULT_CODE_FAILED);
+    }
+
+    @Test
+    public void testSchedule_pendingJobForceSchedule_resultCodeSuccess() {
+        Context spyContext = getSpyContext();
+        JobScheduler mockJobScheduler = mock(JobScheduler.class);
+        doReturn(mockJobScheduler).when(spyContext).getSystemService(JobScheduler.class);
+
+        // Pending job
+        doReturn(mock(JobInfo.class)).when(mockJobScheduler)
+                .getPendingJob(USER_DATA_COLLECTION_ID);
+        doReturn(RESULT_SUCCESS).when(mockJobScheduler).schedule(any());
+
+        int resultCode = mService.schedule(spyContext, /* forceSchedule */ true);
+
+        assertThat(resultCode).isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+    }
+
+    @Test
+    public void testSchedule_nullJobScheduler_resultCodeFailed() {
+        Context spyContext = getSpyContext();
+
+        // Null scheduler
+        doReturn(/* jobScheduler */ null).when(spyContext).getSystemService(JobScheduler.class);
+
+        int resultCode = mService.schedule(spyContext, /* forceSchedule */ false);
+
+        assertThat(resultCode).isEqualTo(SCHEDULING_RESULT_CODE_FAILED);
+    }
+
+    @Test
+    public void testSchedule_pendingJob_resultCodeSkipped() {
+        Context spyContext = getSpyContext();
+        JobScheduler mockJobScheduler = mock(JobScheduler.class);
+        doReturn(mockJobScheduler).when(spyContext).getSystemService(JobScheduler.class);
+
+        // Pending job
+        doReturn(/* jobInfo */ mock(JobInfo.class)).when(mockJobScheduler)
+                .getPendingJob(USER_DATA_COLLECTION_ID);
+
+        int resultCode = mService.schedule(spyContext, /* forceSchedule */ false);
+
+        assertThat(resultCode).isEqualTo(SCHEDULING_RESULT_CODE_SKIPPED);
+    }
+
     @Test
     public void onStartJobTestUserControlRevoked() throws Exception {
         mUserDataCollector.updateUserData(RawUserData.getInstance());
         assertTrue(mUserDataCollector.isInitialized());
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(true).when(mUserPrivacyStatus)
+        doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        doReturn(true).when(mUserPrivacyStatus)
                 .isProtectedAudienceAndMeasurementBothDisabled();
 
         boolean result = mService.onStartJob(mock(JobParameters.class));
@@ -142,6 +247,10 @@ public class UserDataCollectionJobServiceTest {
         assertTrue(mService.onStopJob(mock(JobParameters.class)));
     }
 
+    private Context getSpyContext() {
+        return spy(ApplicationProvider.getApplicationContext());
+    }
+
     private class TestInjector extends UserDataCollectionJobService.Injector {
         @Override
         ListeningExecutorService getExecutor() {
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java
new file mode 100644
index 00000000..e1145d27
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java
@@ -0,0 +1,230 @@
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
+package com.android.ondevicepersonalization.services.data.user;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
+
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@MockStatic(UserDataCollectionJobService.class)
+@MockStatic(FlagsFactory.class)
+@MockStatic(UserPrivacyStatus.class)
+@MockStatic(UserDataCollector.class)
+public final class UserDataCollectionJobTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private UserDataCollectionJob mSpyUserDataCollectionJob;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private UserPrivacyStatus mMockUserPrivacyStatus;
+    @Mock
+    private UserDataCollector mMockUserDataCollector;
+    @Mock
+    private ExecutionRuntimeParameters mMockParams;
+    @Mock
+    private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock
+    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+
+    @Before
+    public void setup() throws Exception {
+        mSpyUserDataCollectionJob = new UserDataCollectionJob(new TestInjector());
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        doReturn(mMockUserDataCollector).when(() -> UserDataCollector.getInstance(any()));
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+    }
+
+    @Test
+    public void testGetExecutionFuture_executionSuccess() throws Exception {
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyUserDataCollectionJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_executionSuccess()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.SUCCESS);
+        verify(mMockUserDataCollector).updateUserData(any());
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_enabled()")
+                .that(mSpyUserDataCollectionJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_globalKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_globalKillSwitch()")
+                .that(mSpyUserDataCollectionJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_speOff() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(false);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_speOff()")
+                .that(mSpyUserDataCollectionJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(true);
+
+        assertWithMessage(
+                "testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent()")
+                .that(mSpyUserDataCollectionJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED);
+    }
+
+    @Test
+    public void testSchedule_spe() {
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(true);
+
+        UserDataCollectionJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler).schedule(eq(sContext), any());
+    }
+
+    @Test
+    public void testSchedule_legacy() {
+        int resultCode = SCHEDULING_RESULT_CODE_SUCCESSFUL;
+        when(mMockFlags.getSpeOnUserDataCollectionJobEnabled()).thenReturn(false);
+
+        JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
+        when(mMockOdpJobServiceFactory.getJobSchedulingLogger()).thenReturn(loggerMock);
+        doReturn(resultCode).when(() -> UserDataCollectionJobService
+                .schedule(any(), /* forceSchedule */ eq(false)));
+
+        UserDataCollectionJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(sContext), any());
+        verify(() -> UserDataCollectionJobService
+                .schedule(any(), /* forceSchedule */ eq(false)));
+        verify(loggerMock).recordOnSchedulingLegacy(USER_DATA_COLLECTION_ID,
+                resultCode);
+    }
+
+    @Test
+    public void testCreateDefaultJobSpec() {
+        long expectedMillis = 1000L * 60L * 60L * 4L; // 4 hours
+        JobPolicy expectedJobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(USER_DATA_COLLECTION_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_NONE)
+                        .setPeriodicJobParams(
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(expectedMillis).build())
+                        .setIsPersisted(true)
+                        .build();
+
+        assertWithMessage("createDefaultJobSpec() for UserDataCollectionJob")
+                .that(UserDataCollectionJob.createDefaultJobSpec())
+                .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for UserDataCollectionJob")
+                .that(new UserDataCollectionJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+
+    public class TestInjector extends UserDataCollectionJob.Injector {
+        @Override
+        ListeningExecutorService getExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+        @Override
+        Flags getFlags() {
+            return mMockFlags;
+        }
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
index 6c167ca4..1de17484 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserPrivacyStatusTest.java
@@ -24,27 +24,26 @@ import static android.adservices.ondevicepersonalization.Constants.STATUS_METHOD
 import static android.adservices.ondevicepersonalization.Constants.STATUS_NULL_ADSERVICES_COMMON_MANAGER;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_REMOTE_EXCEPTION;
 import static android.adservices.ondevicepersonalization.Constants.STATUS_TIMEOUT;
-import static android.app.job.JobScheduler.RESULT_SUCCESS;
 
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__ERROR_CODE__API_REMOTE_EXCEPTION;
 import static com.android.adservices.service.stats.AdServicesStatsLog.AD_SERVICES_ERROR_REPORTED__PPAPI_NAME__ODP;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_USER_CONTROL_CACHE_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_CONTROL_CACHE_IN_MILLIS;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
@@ -55,7 +54,7 @@ import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.StableFlags;
-import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
+import com.android.ondevicepersonalization.services.reset.ResetDataJob;
 import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 import com.android.ondevicepersonalization.services.util.DebugUtils;
 import com.android.ondevicepersonalization.services.util.StatsUtils;
@@ -117,7 +116,7 @@ public final class UserPrivacyStatusTest {
             .mockStatic(DebugUtils.class)
             .mockStatic(FlagsFactory.class)
             .mockStatic(StatsUtils.class)
-            .spyStatic(ResetDataJobService.class)
+            .spyStatic(ResetDataJob.class)
             .spyStatic(StableFlags.class)
             .setStrictness(Strictness.LENIENT)
             .build();
@@ -126,7 +125,7 @@ public final class UserPrivacyStatusTest {
     public void setup() throws Exception {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
         ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
-        ExtendedMockito.doNothing().when(() -> StatsUtils.writeServiceRequestMetrics(
+        doNothing().when(() -> StatsUtils.writeServiceRequestMetrics(
                 anyInt(), anyString(), any(), any(), anyInt(), anyLong()));
         ExtendedMockito.doReturn(false).when(
                 () -> StableFlags.get(KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE));
@@ -135,7 +134,7 @@ public final class UserPrivacyStatusTest {
         ExtendedMockito.doReturn(CACHE_TIMEOUT_MILLIS).when(
                 () -> StableFlags.get(KEY_USER_CONTROL_CACHE_IN_MILLIS));
         mUserPrivacyStatus = new UserPrivacyStatus(mCommonStatesWrapper, mTestClock);
-        doReturn(RESULT_SUCCESS).when(ResetDataJobService::schedule);
+        doNothing().when(() -> ResetDataJob.schedule(any()));
         when(ClientErrorLogger.getInstance()).thenReturn(mMockClientErrorLogger);
     }
 
@@ -152,7 +151,7 @@ public final class UserPrivacyStatusTest {
         assertTrue(mUserPrivacyStatus.isUserControlCacheValid());
         assertTrue(mUserPrivacyStatus.isProtectedAudienceEnabled());
         assertTrue(mUserPrivacyStatus.isMeasurementEnabled());
-        verify(ResetDataJobService::schedule, times(0));
+        ExtendedMockito.verify(() -> ResetDataJob.schedule(any()), times(0));
     }
 
     @Test
@@ -163,7 +162,7 @@ public final class UserPrivacyStatusTest {
         assertTrue(mUserPrivacyStatus.isUserControlCacheValid());
         assertFalse(mUserPrivacyStatus.isProtectedAudienceEnabled());
         assertFalse(mUserPrivacyStatus.isMeasurementEnabled());
-        verify(ResetDataJobService::schedule);
+        ExtendedMockito.verify(() -> ResetDataJob.schedule(any()));
     }
 
     @Test
@@ -173,7 +172,7 @@ public final class UserPrivacyStatusTest {
         assertTrue(mUserPrivacyStatus.isUserControlCacheValid());
         assertTrue(mUserPrivacyStatus.isProtectedAudienceEnabled());
         assertTrue(mUserPrivacyStatus.isMeasurementEnabled());
-        verify(ResetDataJobService::schedule);
+        ExtendedMockito.verify(() -> ResetDataJob.schedule(any()));
     }
 
     @Test
@@ -234,6 +233,7 @@ public final class UserPrivacyStatusTest {
         assertFalse(mUserPrivacyStatus.isProtectedAudienceAndMeasurementBothDisabled());
         assertTrue(mUserPrivacyStatus.isMeasurementEnabled());
         assertTrue(mUserPrivacyStatus.isProtectedAudienceEnabled());
+        ExtendedMockito.verify(() -> ResetDataJob.schedule(any()));
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDaoTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDaoTest.java
index ab5f5d1e..beec7a75 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDaoTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/vendor/OnDevicePersonalizationLocalDataDaoTest.java
@@ -20,6 +20,7 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 
 import android.content.ComponentName;
@@ -37,13 +38,16 @@ import org.junit.runners.JUnit4;
 
 import java.io.File;
 import java.util.ArrayList;
-import java.util.HashSet;
 import java.util.Set;
 
 @RunWith(JUnit4.class)
 public class OnDevicePersonalizationLocalDataDaoTest {
     private static final ComponentName TEST_OWNER = new ComponentName("ownerPkg", "ownerCls");
     private static final String TEST_CERT_DIGEST = "certDigest";
+    private static final byte[] LARGE_TEST_DATA = new byte[111111];
+    private static final byte[] SMALL_TEST_DATA = new byte[10];
+    private static final int TEST_DELAY_MILLIS = 2000;
+
     private final Context mContext = ApplicationProvider.getApplicationContext();
     private OnDevicePersonalizationLocalDataDao mLocalDao;
 
@@ -73,58 +77,114 @@ public class OnDevicePersonalizationLocalDataDaoTest {
         assertEquals(0, mVendorDao.getSyncToken());
     }
 
+    @Test
+    public void testDeleteLocalDataRow_largeData_fileDeleted() {
+        mLocalDao.createTable();
+        File dir =
+                new File(
+                        OnDevicePersonalizationLocalDataDao.getFileDir(
+                                OnDevicePersonalizationLocalDataDao.getTableName(
+                                        TEST_OWNER, TEST_CERT_DIGEST),
+                                mContext.getFilesDir()));
+        assertTrue(dir.isDirectory());
+        String testKey = "largeKey";
+        LocalData largeLocalData =
+                new LocalData.Builder().setKey(testKey).setData(LARGE_TEST_DATA).build();
+        boolean insertResult = mLocalDao.updateOrInsertLocalData(largeLocalData);
+        assertEquals(1, dir.listFiles().length);
+        assertTrue(insertResult);
+        assertArrayEquals(LARGE_TEST_DATA, mLocalDao.readSingleLocalDataRow(testKey));
+
+        boolean deleteResult = mLocalDao.deleteLocalDataRow(testKey);
+
+        assertNull(mLocalDao.readSingleLocalDataRow(testKey));
+        assertTrue(deleteResult);
+        assertEquals(0, dir.listFiles().length);
+    }
+
+    @Test
+    public void testUpdateOrInsertLocalData_largeData_fileDeleted() throws Exception {
+        mLocalDao.createTable();
+        File dir =
+                new File(
+                        OnDevicePersonalizationLocalDataDao.getFileDir(
+                                OnDevicePersonalizationLocalDataDao.getTableName(
+                                        TEST_OWNER, TEST_CERT_DIGEST),
+                                mContext.getFilesDir()));
+        assertTrue(dir.isDirectory());
+        String testKey = "largeKey";
+        LocalData largeLocalData =
+                new LocalData.Builder().setKey(testKey).setData(LARGE_TEST_DATA).build();
+        boolean insertResult = mLocalDao.updateOrInsertLocalData(largeLocalData);
+        assertEquals(1, dir.listFiles().length);
+        assertTrue(insertResult);
+        assertArrayEquals(LARGE_TEST_DATA, mLocalDao.readSingleLocalDataRow(testKey));
+        // Add a sleep to ensure the subsequent updateOrInsert call generates a new timestamp.
+        Thread.sleep(TEST_DELAY_MILLIS);
+
+        // Updating the key with a new value, should lead to the old value and associated file
+        // being deleted.
+        LocalData newLocalData =
+                new LocalData.Builder().setKey(testKey).setData(SMALL_TEST_DATA).build();
+        boolean updateResult = mLocalDao.updateOrInsertLocalData(newLocalData);
+
+        // Add a sleep before update/delete to allow any pending file system operations.
+        Thread.sleep(TEST_DELAY_MILLIS);
+        assertArrayEquals(SMALL_TEST_DATA, mLocalDao.readSingleLocalDataRow(testKey));
+        assertTrue(updateResult);
+        assertEquals(0, dir.listFiles().length);
+    }
+
     private void basicDaoOperations() {
         File dir = new File(OnDevicePersonalizationLocalDataDao.getFileDir(
                 OnDevicePersonalizationLocalDataDao.getTableName(TEST_OWNER, TEST_CERT_DIGEST),
                 mContext.getFilesDir()));
         assertTrue(dir.isDirectory());
 
-        byte[] data = new byte[10];
-        LocalData localData = new LocalData.Builder().setKey("key").setData(data).build();
+        LocalData localData =
+                new LocalData.Builder().setKey("key").setData(SMALL_TEST_DATA).build();
         boolean insertResult = mLocalDao.updateOrInsertLocalData(localData);
         assertTrue(insertResult);
-        LocalData localData2 = new LocalData.Builder().setKey("large").setData(
-                new byte[111111]).build();
+        LocalData localData2 =
+                new LocalData.Builder().setKey("large").setData(LARGE_TEST_DATA).build();
         boolean insertResult2 = mLocalDao.updateOrInsertLocalData(localData2);
         assertTrue(insertResult2);
-        assertArrayEquals(data, mLocalDao.readSingleLocalDataRow("key"));
-        assertArrayEquals(new byte[111111], mLocalDao.readSingleLocalDataRow("large"));
+        assertArrayEquals(SMALL_TEST_DATA, mLocalDao.readSingleLocalDataRow("key"));
+        assertArrayEquals(LARGE_TEST_DATA, mLocalDao.readSingleLocalDataRow("large"));
         assertEquals(1, dir.listFiles().length);
 
-        assertEquals(null, mLocalDao.readSingleLocalDataRow("nonExistentKey"));
+        assertNull(mLocalDao.readSingleLocalDataRow("nonExistentKey"));
         assertFalse(mLocalDao.deleteLocalDataRow("nonExistentKey"));
         assertTrue(mLocalDao.deleteLocalDataRow("key"));
-        assertEquals(null, mLocalDao.readSingleLocalDataRow("key"));
+        assertNull(mLocalDao.readSingleLocalDataRow("key"));
     }
 
     @Test
     public void testReadAllLocalDataKeys() {
         mVendorDao.batchUpdateOrInsertVendorDataTransaction(new ArrayList<>(), new ArrayList<>(),
                 System.currentTimeMillis());
-
-        byte[] data = new byte[10];
-        LocalData localData = new LocalData.Builder().setKey("key").setData(data).build();
+        LocalData localData =
+                new LocalData.Builder().setKey("key").setData(SMALL_TEST_DATA).build();
         mLocalDao.updateOrInsertLocalData(localData);
-        localData = new LocalData.Builder().setKey("key2").setData(data).build();
+        localData = new LocalData.Builder().setKey("key2").setData(SMALL_TEST_DATA).build();
         mLocalDao.updateOrInsertLocalData(localData);
+
         Set<String> keys = mLocalDao.readAllLocalDataKeys();
-        Set<String> expectedKeys = new HashSet<>();
-        expectedKeys.add("key");
-        expectedKeys.add("key2");
-        assertEquals(expectedKeys, keys);
+
+        assertEquals(Set.of("key", "key2"), keys);
     }
 
     @Test
     public void testInsertUncreatedTable() {
-        byte[] data = new byte[10];
-        LocalData localData = new LocalData.Builder().setKey("key").setData(data).build();
+        LocalData localData =
+                new LocalData.Builder().setKey("key").setData(SMALL_TEST_DATA).build();
         boolean insertResult = mLocalDao.updateOrInsertLocalData(localData);
         assertFalse(insertResult);
     }
 
     @Test
     public void testReadUncreatedTable() {
-        assertEquals(null, mLocalDao.readSingleLocalDataRow("key"));
+        assertNull(mLocalDao.readSingleLocalDataRow("key"));
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
index 6893bc5b..ffbe7582 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/display/OdpWebViewClientTests.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.display;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/DownloadedFileParserTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/DownloadedFileParserTest.java
new file mode 100644
index 00000000..1ecdd921
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/DownloadedFileParserTest.java
@@ -0,0 +1,58 @@
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
+package com.android.ondevicepersonalization.services.download;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.ByteArrayInputStream;
+import java.nio.charset.StandardCharsets;
+
+@RunWith(JUnit4.class)
+public final class DownloadedFileParserTest {
+    private String mTestInput = "{"
+            + "\"unknownString\": \"ignored\", "
+            + "\"unknownArray\": [\"ignored1\", \"ignored2\"], "
+            + "\"unknownObject\": {\"key\": \"val\"}, "
+            + "\"syncToken\": 1010, "
+            + "\"contents\": ["
+            + "{\"key\": \"key1\", \"data\": \"val1\"}, "
+            + "{\"key\": \"key2\", \"data\": \"val2\", \"encoding\": \"utf8\"}, "
+            + "{\"key\": \"key3\", \"data\": \"dmFsMw==\", \"encoding\": \"base64\"} "
+            + "]}";
+
+    @Test
+    public void testParseJson() throws Exception {
+        ParsedFileContents result = DownloadedFileParser.parseJson(
+                new ByteArrayInputStream(mTestInput.getBytes(StandardCharsets.UTF_8)));
+
+        assertEquals(1010, result.getSyncToken());
+        var vendorDataMap = result.getVendorDataMap();
+        assertNotNull(vendorDataMap);
+        assertEquals("key1", vendorDataMap.get("key1").getKey());
+        assertArrayEquals("val1".getBytes(), vendorDataMap.get("key1").getData());
+        assertEquals("key2", vendorDataMap.get("key2").getKey());
+        assertArrayEquals("val2".getBytes(), vendorDataMap.get("key2").getData());
+        assertEquals("key3", vendorDataMap.get("key3").getKey());
+        assertArrayEquals("val3".getBytes(), vendorDataMap.get("key3").getData());
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
index 00da3711..14918cbd 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDataProcessingAsyncCallableTests.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.download;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobServiceTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobServiceTests.java
index 47edfcbc..3d507f02 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobServiceTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobServiceTests.java
@@ -16,8 +16,11 @@
 
 package com.android.ondevicepersonalization.services.download;
 
-import static android.app.job.JobScheduler.RESULT_FAILURE;
-import static android.app.job.JobScheduler.RESULT_SUCCESS;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+
+import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
@@ -27,7 +30,6 @@ import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -39,14 +41,15 @@ import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.download.mdd.MobileDataDownloadFactory;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
 
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
@@ -66,9 +69,14 @@ public class OnDevicePersonalizationDownloadProcessingJobServiceTests {
 
     static class TestFlags implements Flags {
         boolean mGlobalKillSwitch = false;
+        boolean mSpeOnOdpDownloadProcessingJobEnabled = false;
         @Override public boolean getGlobalKillSwitch() {
             return mGlobalKillSwitch;
         }
+
+        @Override public boolean getSpeOnOdpDownloadProcessingJobEnabled() {
+            return mSpeOnOdpDownloadProcessingJobEnabled;
+        }
     }
 
     private TestFlags mSpyFlags = new TestFlags();
@@ -85,7 +93,9 @@ public class OnDevicePersonalizationDownloadProcessingJobServiceTests {
     @Before
     public void setup() throws Exception {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
-        ExtendedMockito.doReturn(mSpyFlags).when(FlagsFactory::getFlags);
+        doReturn(mSpyFlags).when(FlagsFactory::getFlags);
+        mSpyFlags.mGlobalKillSwitch = false;
+        mSpyFlags.mSpeOnOdpDownloadProcessingJobEnabled = false;
         // Use direct executor to keep all work sequential for the tests
         ListeningExecutorService executorService = MoreExecutors.newDirectExecutorService();
         MobileDataDownloadFactory.getMdd(mContext, executorService, executorService);
@@ -113,9 +123,9 @@ public class OnDevicePersonalizationDownloadProcessingJobServiceTests {
                 })
                 .when(mSpyService).jobFinished(any(), anyBoolean());
         doReturn(mContext.getPackageManager()).when(mSpyService).getPackageManager();
-        ExtendedMockito.doReturn(MoreExecutors.newDirectExecutorService()).when(
+        doReturn(MoreExecutors.newDirectExecutorService()).when(
                 OnDevicePersonalizationExecutors::getBackgroundExecutor);
-        ExtendedMockito.doReturn(MoreExecutors.newDirectExecutorService()).when(
+        doReturn(MoreExecutors.newDirectExecutorService()).when(
                 OnDevicePersonalizationExecutors::getLightweightExecutor);
 
         boolean result = mSpyService.onStartJob(mock(JobParameters.class));
@@ -135,20 +145,37 @@ public class OnDevicePersonalizationDownloadProcessingJobServiceTests {
         verify(mSpyService, times(1)).jobFinished(any(), eq(false));
     }
 
+    @Test
+    @MockStatic(OdpJobScheduler.class)
+    @MockStatic(FlagsFactory.class)
+    public void onStartJobTestSpeEnabled() {
+        mSpyFlags.mSpeOnOdpDownloadProcessingJobEnabled = true;
+
+        // Mock OdpJobScheduler to not actually schedule the job.
+        OdpJobScheduler mockedScheduler = mock(OdpJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+
+        assertThat(mSpyService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify SPE scheduler has rescheduled the job.
+        verify(mockedScheduler).schedule(any(), any());
+    }
+
     @Test
     public void onStopJobTest() {
         assertTrue(mSpyService.onStopJob(mock(JobParameters.class)));
     }
 
-
     @Test
     public void testSuccessfulScheduling() {
         JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
-        assertEquals(RESULT_SUCCESS,
-                OnDevicePersonalizationDownloadProcessingJobService.schedule(mContext));
+        assertEquals(SCHEDULING_RESULT_CODE_SUCCESSFUL,
+                OnDevicePersonalizationDownloadProcessingJobService
+                        .schedule(mContext, /* forceSchedule */ false));
         assertTrue(jobScheduler.getPendingJob(
                 OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID) != null);
-        assertEquals(RESULT_FAILURE,
-                OnDevicePersonalizationDownloadProcessingJobService.schedule(mContext));
+        assertEquals(SCHEDULING_RESULT_CODE_SKIPPED,
+                OnDevicePersonalizationDownloadProcessingJobService
+                        .schedule(mContext, /* forceSchedule */ false));
     }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java
new file mode 100644
index 00000000..779c548e
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java
@@ -0,0 +1,205 @@
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
+package com.android.ondevicepersonalization.services.download;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
+
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.modules.utils.testing.ExtendedMockitoRule.SpyStatic;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.util.concurrent.ListenableFuture;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+/** Unit tests for {@link OnDevicePersonalizationDownloadProcessingJob}. */
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@MockStatic(OnDevicePersonalizationDownloadProcessingJobService.class)
+@MockStatic(FlagsFactory.class)
+@SpyStatic(AppManifestConfigHelper.class)
+public final class OnDevicePersonalizationDownloadProcessingJobTests {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private OnDevicePersonalizationDownloadProcessingJob mSpyOdpDownloadProcessingJob;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private ExecutionRuntimeParameters mMockParams;
+    @Mock
+    private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock
+    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+
+    @Before
+    public void setup() throws Exception {
+        mSpyOdpDownloadProcessingJob = new OnDevicePersonalizationDownloadProcessingJob();
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+    }
+
+    @Test
+    public void testGetExecutionFuture_success() throws Exception {
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyOdpDownloadProcessingJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_success().get()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.SUCCESS);
+    }
+
+    @Test
+    public void testGetExecutionFuture_invalidPackageName_returnFailure() throws Exception {
+        doReturn(ImmutableList.of("invalidPackageName_thisWillThrowPackageNameNotFoundException"))
+                .when(() ->AppManifestConfigHelper.getOdpPackages(any(), anyBoolean()));
+
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyOdpDownloadProcessingJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture_invalidPackageName_returnFailure().get()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.FAILURE_WITHOUT_RETRY);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnOdpDownloadProcessingJobEnabled()).thenReturn(true);
+
+        assertWithMessage("testGetJobEnablementStatus_enabled()")
+                .that(mSpyOdpDownloadProcessingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_globalKillSwitchOff_disabledByKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        when(mMockFlags.getSpeOnOdpDownloadProcessingJobEnabled()).thenReturn(true);
+
+        assertWithMessage(
+                "testGetJobEnablementStatus_globalKillSwitchOff_disabledByKillSwitch()")
+                .that(mSpyOdpDownloadProcessingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_speOff_disabledByKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnOdpDownloadProcessingJobEnabled()).thenReturn(false);
+
+        assertWithMessage(
+                "testGetJobEnablementStatus_speOff_disabledByKillSwitch()")
+                .that(mSpyOdpDownloadProcessingJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testSchedule_spe() {
+        when(mMockFlags.getSpeOnOdpDownloadProcessingJobEnabled()).thenReturn(true);
+
+        OnDevicePersonalizationDownloadProcessingJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler).schedule(eq(sContext), any());
+    }
+
+    @Test
+    public void testSchedule_legacy() {
+        int resultCode = SCHEDULING_RESULT_CODE_SUCCESSFUL;
+        when(mMockFlags.getSpeOnOdpDownloadProcessingJobEnabled()).thenReturn(false);
+
+        JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
+        when(mMockOdpJobServiceFactory.getJobSchedulingLogger()).thenReturn(loggerMock);
+        doReturn(resultCode).when(() -> OnDevicePersonalizationDownloadProcessingJobService
+                .schedule(any(), /* forceSchedule */ eq(false)));
+
+        OnDevicePersonalizationDownloadProcessingJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(sContext), any());
+        verify(() -> OnDevicePersonalizationDownloadProcessingJobService
+                .schedule(any(), /* forceSchedule */ eq(false)));
+        verify(loggerMock).recordOnSchedulingLegacy(DOWNLOAD_PROCESSING_TASK_JOB_ID, resultCode);
+    }
+
+    @Test
+    public void testCreateDefaultJobSpec() {
+        JobPolicy expectedJobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(DOWNLOAD_PROCESSING_TASK_JOB_ID)
+                        .setRequireDeviceIdle(true)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setRequireStorageNotLow(true)
+                        .setNetworkType(NETWORK_TYPE_NONE)
+                        .setIsPersisted(true)
+                        .build();
+
+        assertWithMessage("createDefaultJobSpec() for "
+                + "OnDevicePersonalizationDownloadProcessingJob")
+                .that(OnDevicePersonalizationDownloadProcessingJob.createDefaultJobSpec())
+                .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for OnDevicePersonalizationDownloadProcessingJob")
+                .that(new OnDevicePersonalizationDownloadProcessingJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobServiceTest.java
index fcd22015..c07f100e 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobServiceTest.java
@@ -16,24 +16,27 @@
 
 package com.android.ondevicepersonalization.services.download.mdd;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.MDD_TASK_TAG_KEY;
 
 import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
+import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertNotNull;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.app.job.JobInfo;
@@ -45,11 +48,14 @@ import android.os.PersistableBundle;
 
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.ondevicepersonalization.services.Flags;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.statsd.joblogging.OdpJobServiceLogger;
 
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
@@ -64,6 +70,7 @@ import org.mockito.quality.Strictness;
 
 @RunWith(JUnit4.class)
 public class MddJobServiceTest {
+    private static final int TIMEOUT_MILLIS = 5000;
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
     private JobScheduler mMockJobScheduler;
@@ -72,9 +79,13 @@ public class MddJobServiceTest {
 
     @Mock
     private Flags mMockFlags;
+    @Mock
+    private OdpJobServiceLogger mMockOdpJobServiceLogger;
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder(this)
+            .mockStatic(OnDevicePersonalizationDownloadProcessingJob.class)
+            .mockStatic(OdpJobServiceLogger.class)
             .spyStatic(UserPrivacyStatus.class)
             .spyStatic(OnDevicePersonalizationExecutors.class)
             .setStrictness(Strictness.LENIENT)
@@ -95,6 +106,8 @@ public class MddJobServiceTest {
     @Before
     public void setup() throws Exception {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(false);
+
         mUserPrivacyStatus = spy(UserPrivacyStatus.getInstance());
         ListeningExecutorService executorService = MoreExecutors.newDirectExecutorService();
         MobileDataDownloadFactory.getMdd(mContext, executorService, executorService);
@@ -106,6 +119,8 @@ public class MddJobServiceTest {
         doReturn(null).when(mMockJobScheduler).getPendingJob(DOWNLOAD_PROCESSING_TASK_JOB_ID);
         doReturn(0).when(mMockJobScheduler).schedule(any());
         doReturn(mContext.getPackageName()).when(mSpyService).getPackageName();
+        doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        doReturn(mMockOdpJobServiceLogger).when(() -> OdpJobServiceLogger.getInstance(any()));
     }
 
     @Test
@@ -116,22 +131,20 @@ public class MddJobServiceTest {
 
     @Test
     public void onStartJobTest() throws Exception {
-        ExtendedMockito.doReturn(MoreExecutors.newDirectExecutorService()).when(
+        doReturn(MoreExecutors.newDirectExecutorService()).when(
                 OnDevicePersonalizationExecutors::getBackgroundExecutor);
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(false).when(mUserPrivacyStatus)
+        doReturn(false).when(mUserPrivacyStatus)
                 .isProtectedAudienceAndMeasurementBothDisabled();
 
-        JobParameters jobParameters = mock(JobParameters.class);
+        JobParameters jobParameters = createDefaultMockJobParameters();
         PersistableBundle extras = new PersistableBundle();
         extras.putString(MDD_TASK_TAG_KEY, WIFI_CHARGING_PERIODIC_TASK);
         doReturn(extras).when(jobParameters).getExtras();
 
         boolean result = mSpyService.onStartJob(jobParameters);
         assertTrue(result);
-        Thread.sleep(5000);
-        verify(mSpyService, times(1)).jobFinished(any(), eq(false));
-        verify(mMockJobScheduler, times(1)).schedule(any());
+        verify(mSpyService, timeout(TIMEOUT_MILLIS)).jobFinished(any(), eq(false));
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()));
     }
 
     @Test
@@ -147,6 +160,7 @@ public class MddJobServiceTest {
                 .setRequiresCharging(false)
                 .setRequiresBatteryNotLow(true)
                 .setPeriodic(21_600_000L)
+                .setRequiresStorageNotLow(true)
                 .setPersisted(true)
                 .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                 .setExtras(extras)
@@ -155,19 +169,19 @@ public class MddJobServiceTest {
         assertTrue(mJobScheduler.getPendingJob(MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID) != null);
         doReturn(mJobScheduler).when(mSpyService).getSystemService(JobScheduler.class);
         doNothing().when(mSpyService).jobFinished(any(), anyBoolean());
-        JobParameters jobParameters = mock(JobParameters.class);
+        JobParameters jobParameters = createDefaultMockJobParameters();
         doReturn(extras).when(jobParameters).getExtras();
         boolean result = mSpyService.onStartJob(jobParameters);
         assertTrue(result);
         verify(mSpyService, times(1)).jobFinished(any(), eq(false));
         verify(mMockJobScheduler, times(0)).schedule(any());
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
         assertTrue(mJobScheduler.getPendingJob(MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID) == null);
     }
 
     @Test
     public void onStartJobTestUserControlRevoked() throws Exception {
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(true).when(mUserPrivacyStatus)
+        doReturn(true).when(mUserPrivacyStatus)
                 .isProtectedAudienceAndMeasurementBothDisabled();
         JobScheduler mJobScheduler = mContext.getSystemService(JobScheduler.class);
         PersistableBundle extras = new PersistableBundle();
@@ -179,6 +193,7 @@ public class MddJobServiceTest {
                 .setRequiresCharging(false)
                 .setRequiresBatteryNotLow(true)
                 .setPeriodic(21_600_000L)
+                .setRequiresStorageNotLow(true)
                 .setPersisted(true)
                 .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                 .setExtras(extras)
@@ -187,45 +202,66 @@ public class MddJobServiceTest {
         assertTrue(mJobScheduler.getPendingJob(MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID) != null);
         doReturn(mJobScheduler).when(mSpyService).getSystemService(JobScheduler.class);
         doNothing().when(mSpyService).jobFinished(any(), anyBoolean());
-        JobParameters jobParameters = mock(JobParameters.class);
+        JobParameters jobParameters = createDefaultMockJobParameters();
         doReturn(extras).when(jobParameters).getExtras();
         boolean result = mSpyService.onStartJob(jobParameters);
         assertTrue(result);
-        Thread.sleep(2000);
-        verify(mSpyService, times(1)).jobFinished(any(), eq(false));
-        verify(mMockJobScheduler, times(0)).schedule(any());
+        verify(mSpyService, timeout(TIMEOUT_MILLIS)).jobFinished(any(), eq(false));
+        verify(mMockJobScheduler, never()).schedule(any());
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
     }
 
     @Test
-    public void onStartJobNoTaskTagTest() {
+    public void onStartJob_withNoTaskTagTest_logJobFailure() {
+        doReturn(false).when(mUserPrivacyStatus).isProtectedAudienceAndMeasurementBothDisabled();
 
-        assertThrows(IllegalArgumentException.class,
-                () -> mSpyService.onStartJob(mock(JobParameters.class)));
-        verify(mSpyService, times(0)).jobFinished(any(), eq(false));
+        mSpyService.onStartJob(createDefaultMockJobParameters());
+
+        verify(mSpyService, timeout(TIMEOUT_MILLIS)).jobFinished(any(), eq(false));
         verify(mMockJobScheduler, times(0)).schedule(any());
+        verify(mMockOdpJobServiceLogger).recordJobFinished(
+                anyInt(),
+                /* isSuccessful */ eq(false),
+                anyBoolean());
     }
 
     @Test
     public void onStartJobFailHandleTaskTest() throws Exception {
-        ExtendedMockito.doReturn(mUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
-        ExtendedMockito.doReturn(false).when(mUserPrivacyStatus)
+        doReturn(false).when(mUserPrivacyStatus)
                 .isProtectedAudienceAndMeasurementBothDisabled();
 
-        JobParameters jobParameters = mock(JobParameters.class);
+        JobParameters jobParameters = createDefaultMockJobParameters();
         PersistableBundle extras = new PersistableBundle();
         extras.putString(MDD_TASK_TAG_KEY, "INVALID_TASK_TAG_KEY");
         doReturn(extras).when(jobParameters).getExtras();
 
         boolean result = mSpyService.onStartJob(jobParameters);
         assertTrue(result);
-        Thread.sleep(2000);
-        verify(mSpyService, times(1)).jobFinished(any(), eq(false));
+        verify(mSpyService, timeout(TIMEOUT_MILLIS)).jobFinished(any(), eq(false));
         verify(mMockJobScheduler, times(0)).schedule(any());
     }
 
+    @Test
+    @MockStatic(OdpJobScheduler.class)
+    @MockStatic(MddTaskScheduler.class)
+    public void onStartJobTestSpeEnabled() {
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+
+        // Mock OdpJobScheduler to not actually schedule the job.
+        OdpJobScheduler mockedScheduler = mock(OdpJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+
+        assertThat(mSpyService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify mdd task scheduler has been called.
+        verify(() -> MddTaskScheduler.schedule(any(), any()));
+        verify(mMockJobScheduler, never()).schedule(any());
+    }
+
+
     @Test
     public void onStopJobTest() {
-        JobParameters jobParameters = mock(JobParameters.class);
+        JobParameters jobParameters = createDefaultMockJobParameters();
         PersistableBundle extras = new PersistableBundle();
         extras.putString(MDD_TASK_TAG_KEY, WIFI_CHARGING_PERIODIC_TASK);
         doReturn(extras).when(jobParameters).getExtras();
@@ -233,4 +269,14 @@ public class MddJobServiceTest {
         assertTrue(mSpyService.onStopJob(jobParameters));
         verify(mMockJobScheduler, times(0)).schedule(any());
     }
+
+    private JobParameters createDefaultMockJobParameters() {
+        return createMockJobParameters(MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID);
+    }
+
+    private JobParameters createMockJobParameters(int jobId) {
+        JobParameters mockJobParameters = mock(JobParameters.class);
+        when(mockJobParameters.getJobId()).thenReturn(jobId);
+        return mockJobParameters;
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java
new file mode 100644
index 00000000..ac7736f1
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java
@@ -0,0 +1,226 @@
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
+package com.android.ondevicepersonalization.services.download.mdd;
+
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CHARGING_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
+import static com.google.common.truth.Truth.assertWithMessage;
+import static com.google.common.util.concurrent.Futures.immediateVoidFuture;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.android.libraries.mobiledatadownload.MobileDataDownload;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+@MockStatic(FlagsFactory.class)
+@MockStatic(MddTaskScheduler.class)
+@MockStatic(MobileDataDownloadFactory.class)
+@MockStatic(OnDevicePersonalizationDownloadProcessingJob.class)
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@MockStatic(UserPrivacyStatus.class)
+public final class MddJobTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+
+    private MddJob mMddJobChargingPeriodic;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private UserPrivacyStatus mMockUserPrivacyStatus;
+    @Mock
+    private MobileDataDownload mMockMobileDataDownload;
+    @Mock
+    private ExecutionRuntimeParameters mMockParams;
+    @Mock
+    private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock
+    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+
+    @Before
+    public void setup() throws Exception {
+        mMddJobChargingPeriodic = new MddJob(CHARGING_PERIODIC_TASK, new TestInjector());
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+        doReturn(mMockMobileDataDownload).when(() -> MobileDataDownloadFactory.getMdd(any()));
+        doReturn(immediateVoidFuture()).when(mMockMobileDataDownload).handleTask(any());
+    }
+
+    @Test
+    public void testGetExecutionFuture_executionSuccess() throws Exception {
+        ListenableFuture<ExecutionResult> executionFuture =
+                mMddJobChargingPeriodic.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage(
+                "testGetExecutionFuture_executionSuccess()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.SUCCESS);
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
+    }
+
+    @Test
+    public void testGetExecutionFuture_wifiChargingPeriodic_scheduleDownloadJob() throws Exception {
+        MddJob mddWifiChargingPeriodicJob = createWifiChargingPeriodicMddJob();
+        ListenableFuture<ExecutionResult> executionFuture =
+                mddWifiChargingPeriodicJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage(
+                "testGetExecutionFuture_wifiChargingPeriodic_scheduleDownloadJob()")
+                .that(executionFuture.get())
+                .isEqualTo(ExecutionResult.SUCCESS);
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()));
+    }
+
+    @Test
+    public void testGetExecutionStopFuture_notWifiChargingPeriodic_dontScheduleDownloadJob()
+            throws Exception {
+        ListenableFuture<Void> executionFuture =
+                mMddJobChargingPeriodic.getExecutionStopFuture(sContext, mMockParams);
+
+        assertWithMessage(
+                "testGetExecutionStopFuture_notWifiChargingPeriodic_dontScheduleDownloadJob()")
+                .that(executionFuture.get())
+                .isNull();
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
+    }
+
+    @Test
+    public void testGetExecutionStopFuture_wifiChargingPeriodic_scheduleDownloadJob()
+            throws Exception {
+        MddJob mddWifiChargingPeriodicJob = createWifiChargingPeriodicMddJob();
+        ListenableFuture<Void> executionFuture =
+                mddWifiChargingPeriodicJob.getExecutionStopFuture(sContext, mMockParams);
+
+        assertWithMessage(
+                "testGetExecutionStopFuture_wifiChargingPeriodic_scheduleDownloadJob()")
+                .that(executionFuture.get())
+                .isNull();
+        verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()));
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_enabled()")
+                .that(mMddJobChargingPeriodic.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_globalKillSwitch() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_globalKillSwitch()")
+                .that(mMddJobChargingPeriodic.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_speOff() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(false);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+
+        assertWithMessage("testGetJobEnablementStatus_disabled_speOff()")
+                .that(mMddJobChargingPeriodic.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent() {
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus
+                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(true);
+
+        assertWithMessage(
+                "testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent()")
+                .that(mMddJobChargingPeriodic.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED);
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for MddJob")
+                .that(mMddJobChargingPeriodic.getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+
+    private MddJob createWifiChargingPeriodicMddJob() {
+        return new MddJob(WIFI_CHARGING_PERIODIC_TASK);
+    }
+
+    public class TestInjector extends MddJob.Injector {
+        @Override
+        ListeningExecutorService getBackgroundExecutor() {
+            return MoreExecutors.newDirectExecutorService();
+        }
+
+        @Override
+        Flags getFlags() {
+            return mMockFlags;
+        }
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java
index e00d1415..a49c3c96 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddLoggerTest.java
@@ -79,7 +79,7 @@ public final class MddLoggerTest {
     public void mddLoggerTest_unspecified() {
         mMddLogger.log(mMockLog, EVENT_CODE_UNSPECIFIED);
         // Unspecified event does not trigger MDD logging.
-        ExtendedMockito.verifyZeroInteractions(staticMockMarker(AdServicesStatsLog.class));
+        ExtendedMockito.verifyNoMoreInteractions(staticMockMarker(AdServicesStatsLog.class));
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskSchedulerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskSchedulerTest.java
new file mode 100644
index 00000000..89d3eb0d
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddTaskSchedulerTest.java
@@ -0,0 +1,348 @@
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
+package com.android.ondevicepersonalization.services.download.mdd;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_ANY;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_NONE;
+import static com.android.adservices.shared.proto.JobPolicy.NetworkType.NETWORK_TYPE_UNMETERED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SKIPPED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.MDD_NETWORK_STATE_KEY;
+import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.MDD_PERIOD_SECONDS_KEY;
+import static com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler.MDD_TASK_TAG_KEY;
+
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CELLULAR_CHARGING_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CHARGING_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.MAINTENANCE_PERIODIC_TASK;
+import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.app.job.JobScheduler;
+import android.content.Context;
+import android.os.PersistableBundle;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.proto.JobPolicy.NetworkType;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.modules.utils.testing.ExtendedMockitoRule.SpyStatic;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.android.libraries.mobiledatadownload.TaskScheduler.NetworkState;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.quality.Strictness;
+
+@MockStatic(FlagsFactory.class)
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@SpyStatic(MddTaskScheduler.class)
+public final class MddTaskSchedulerTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final long DEFAULT_PERIOD_SECONDS = 5;
+    private static final String DEFAULT_MDD_TASK_TAG = MAINTENANCE_PERIODIC_TASK;
+    private static final NetworkState DEFAULT_NETWORK_STATE = NetworkState.NETWORK_STATE_ANY;
+
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private final JobScheduler mJobScheduler = mContext.getSystemService(JobScheduler.class);
+
+    private MddTaskScheduler mMddTaskScheduler;
+    @Mock
+    private Flags mMockFlags;
+    @Mock
+    private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock
+    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+    @Mock
+    private JobSchedulingLogger mMockJobSchedulingLogger;
+
+    @Before
+    public void setup() throws Exception {
+        mMddTaskScheduler = new MddTaskScheduler(mContext);
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+        when(mMockOdpJobServiceFactory.getJobSchedulingLogger())
+                .thenReturn(mMockJobSchedulingLogger);
+    }
+
+    @After
+    public void teardown() {
+        mJobScheduler.cancelAll();
+        assertWithMessage("Any pending job in JobScheduler")
+                .that(mJobScheduler.getAllPendingJobs())
+                .isEmpty();
+    }
+
+    @Test
+    public void testSchedulePeriodicTask_withSpeSchedulingEnabled() {
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+
+        mMddTaskScheduler.schedulePeriodicTask(
+                DEFAULT_MDD_TASK_TAG, DEFAULT_PERIOD_SECONDS, DEFAULT_NETWORK_STATE);
+
+        verify(mMockOdpJobScheduler).schedule(eq(mContext), any());
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(any(), any(), anyLong(), any(), anyBoolean()), never());
+    }
+
+    @Test
+    public void testSchedulePeriodicTask_withLegacySchedulingEnabled() {
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(false);
+
+        mMddTaskScheduler.schedulePeriodicTask(
+                DEFAULT_MDD_TASK_TAG,
+                DEFAULT_PERIOD_SECONDS,
+                DEFAULT_NETWORK_STATE);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(mContext), any());
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(any(), any(), anyLong(), any(), anyBoolean()));
+    }
+
+    @Test
+    public void testSchedule_withSpeSchedulingEnabled() {
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
+
+        MddTaskScheduler.schedule(
+                mContext,
+                createMddExtras(
+                        DEFAULT_MDD_TASK_TAG,
+                        DEFAULT_PERIOD_SECONDS,
+                        DEFAULT_NETWORK_STATE));
+
+        verify(mMockOdpJobScheduler).schedule(eq(mContext), any());
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(any(), any(), anyLong(), any(), anyBoolean()), never());
+    }
+
+    @Test
+    public void testSchedule_withLegacySchedulingEnabled() {
+        when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(false);
+
+        MddTaskScheduler.schedule(
+                mContext,
+                createMddExtras(
+                        DEFAULT_MDD_TASK_TAG,
+                        DEFAULT_PERIOD_SECONDS,
+                        DEFAULT_NETWORK_STATE));
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(mContext), any());
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(any(), any(), anyLong(), any(), anyBoolean()));
+    }
+
+    @Test
+    public void testScheduleWithLegacy_scheduledSuccessful() {
+        int actualResultCode = MddTaskScheduler
+                .scheduleWithLegacy(mContext, createDefaultMddExtras(), /* forceSchedule */ false);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(mContext), any());
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(any(), any(), anyLong(), any(), anyBoolean()));
+        assertWithMessage("Scheduling failed")
+                .that(actualResultCode)
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+    }
+
+    @Test
+    public void testScheduleWithLegacy_alreadyScheduled_skippedScheduling() {
+        PersistableBundle extras = createDefaultMddExtras();
+
+        MddTaskScheduler.scheduleWithLegacy(mContext, extras, /* forceSchedule */ false);
+        int actualResultCode = MddTaskScheduler
+                .scheduleWithLegacy(mContext, extras, /* forceSchedule */ false);
+
+        assertWithMessage(
+                "Scheduling not skipped")
+                .that(actualResultCode)
+                .isEqualTo(SCHEDULING_RESULT_CODE_SKIPPED);
+    }
+
+    @Test
+    public void testScheduleWithLegacy_alreadyScheduled_forcedScheduledSuccessful() {
+        PersistableBundle extras = createDefaultMddExtras();
+
+        MddTaskScheduler.scheduleWithLegacy(mContext, extras, /* forceSchedule */ false);
+        int actualResultCode = MddTaskScheduler
+                .scheduleWithLegacy(mContext, extras, /* forceSchedule */ true);
+
+        assertWithMessage(
+                "Scheduling failed")
+                .that(actualResultCode)
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+    }
+
+    @Test
+    public void testScheduleWithLegacy_alreadyScheduled_changedPeriodSchedulingSuccessful() {
+        PersistableBundle extras = createMddExtras(
+                DEFAULT_MDD_TASK_TAG, DEFAULT_PERIOD_SECONDS, DEFAULT_NETWORK_STATE);
+        MddTaskScheduler.scheduleWithLegacy(mContext, extras, /* forceSchedule */ false);
+
+        PersistableBundle extrasPeriodUpdated = createMddExtras(
+                DEFAULT_MDD_TASK_TAG, DEFAULT_PERIOD_SECONDS + 1, DEFAULT_NETWORK_STATE);
+        int actualResultCode = MddTaskScheduler
+                .scheduleWithLegacy(mContext, extrasPeriodUpdated, /* forceSchedule */ false);
+
+        assertWithMessage(
+                "Scheduling failed")
+                .that(actualResultCode)
+                .isEqualTo(SCHEDULING_RESULT_CODE_SUCCESSFUL);
+    }
+
+    @Test
+    public void testCreateJobSpec_maintenancePeriodicJob() {
+        JobPolicy jobPolicy =
+                createJobPolicy(
+                        MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID,
+                        NETWORK_TYPE_NONE,
+                        /* requireStorageNotLow= */ false);
+        JobSpec expectedJobSpec = new JobSpec.Builder(jobPolicy).setExtras(createMddExtras(
+                MAINTENANCE_PERIODIC_TASK,
+                DEFAULT_PERIOD_SECONDS,
+                NetworkState.NETWORK_STATE_ANY))
+                .build();
+
+        assertWithMessage("testCreateJobSpec() for MddJob#maintenancePeriodic")
+                .that(MddTaskScheduler.createJobSpec(
+                        MAINTENANCE_PERIODIC_TASK,
+                        DEFAULT_PERIOD_SECONDS,
+                        NetworkState.NETWORK_STATE_ANY))
+                .isEqualTo(expectedJobSpec);
+    }
+
+    @Test
+    public void testCreateJobSpec_chargingPeriodicJob() {
+        JobPolicy jobPolicy =
+                createJobPolicy(
+                        MDD_CHARGING_PERIODIC_TASK_JOB_ID,
+                        NETWORK_TYPE_NONE,
+                        /* requireStorageNotLow= */ false);
+        JobSpec expectedJobSpec = new JobSpec.Builder(jobPolicy).setExtras(createMddExtras(
+                CHARGING_PERIODIC_TASK,
+                DEFAULT_PERIOD_SECONDS,
+                NetworkState.NETWORK_STATE_ANY))
+                .build();
+
+        assertWithMessage("testCreateJobSpec() for MddJob#charging")
+                .that(MddTaskScheduler.createJobSpec(
+                        CHARGING_PERIODIC_TASK,
+                        DEFAULT_PERIOD_SECONDS,
+                        NetworkState.NETWORK_STATE_ANY))
+                .isEqualTo(expectedJobSpec);
+    }
+
+    @Test
+    public void testCreateJobSpec_cellularChargingPeriodicJob() {
+        JobPolicy jobPolicy =
+                createJobPolicy(
+                        MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID,
+                        NETWORK_TYPE_ANY,
+                        /* requireStorageNotLow= */ true);
+        JobSpec expectedJobSpec = new JobSpec.Builder(jobPolicy).setExtras(createMddExtras(
+                CELLULAR_CHARGING_PERIODIC_TASK,
+                DEFAULT_PERIOD_SECONDS,
+                NetworkState.NETWORK_STATE_CONNECTED))
+                .build();
+
+        assertWithMessage("testCreateJobSpec() for MddJob#cellularChargingPeriodic")
+                .that(MddTaskScheduler.createJobSpec(
+                        CELLULAR_CHARGING_PERIODIC_TASK,
+                        DEFAULT_PERIOD_SECONDS,
+                        NetworkState.NETWORK_STATE_CONNECTED))
+                .isEqualTo(expectedJobSpec);
+    }
+
+    @Test
+    public void testCreateJobSpec_wifiPeriodicJob() {
+        JobPolicy jobPolicy =
+                createJobPolicy(
+                        MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID,
+                        NETWORK_TYPE_UNMETERED,
+                        /* requireStorageNotLow= */ true);
+        JobSpec expectedJobSpec = new JobSpec.Builder(jobPolicy).setExtras(createMddExtras(
+                WIFI_CHARGING_PERIODIC_TASK,
+                DEFAULT_PERIOD_SECONDS,
+                NetworkState.NETWORK_STATE_UNMETERED))
+                .build();
+
+        assertWithMessage("testCreateJobSpec() for MddJob#wifiPeriodic")
+                .that(MddTaskScheduler.createJobSpec(
+                        WIFI_CHARGING_PERIODIC_TASK,
+                        DEFAULT_PERIOD_SECONDS,
+                        NetworkState.NETWORK_STATE_UNMETERED))
+                .isEqualTo(expectedJobSpec);
+    }
+
+    private JobPolicy createJobPolicy(int jobId, NetworkType networkType,
+                                      boolean requireStorageNotLow) {
+        return JobPolicy.newBuilder()
+                .setJobId(jobId)
+                .setRequireDeviceIdle(true)
+                .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                .setPeriodicJobParams(
+                        JobPolicy.PeriodicJobParams.newBuilder()
+                                .setPeriodicIntervalMs(DEFAULT_PERIOD_SECONDS * 1000)
+                                .build())
+                .setNetworkType(networkType)
+                .setRequireStorageNotLow(requireStorageNotLow)
+                .setIsPersisted(true)
+                .build();
+    }
+
+    private PersistableBundle createMddExtras(
+            String mddTaskTag, long periodSeconds, NetworkState networkState) {
+        PersistableBundle extras = new PersistableBundle();
+        extras.putString(MDD_TASK_TAG_KEY, mddTaskTag);
+        extras.putLong(MDD_PERIOD_SECONDS_KEY, periodSeconds);
+        extras.putString(MDD_NETWORK_STATE_KEY, networkState.name());
+        return extras;
+    }
+
+    private PersistableBundle createDefaultMddExtras() {
+        return createMddExtras(
+                DEFAULT_MDD_TASK_TAG, DEFAULT_PERIOD_SECONDS, DEFAULT_NETWORK_STATE);
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
index 15bda2ea..275fe9b6 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
@@ -80,6 +80,7 @@ public class FederatedComputeServiceImplTest {
                     .build();
 
     private static final String SERVICE_CLASS = "com.test.TestPersonalizationService";
+    public static final int TEST_TIMEOUT_MILLIS = 1000;
     private final Context mApplicationContext = ApplicationProvider.getApplicationContext();
     ArgumentCaptor<OutcomeReceiver<Object, Exception>> mCallbackCapture;
     ArgumentCaptor<ScheduleFederatedComputeRequest> mRequestCapture;
@@ -133,7 +134,7 @@ public class FederatedComputeServiceImplTest {
         mServiceProxy.schedule(TEST_OPTIONS, new TestCallback());
         mCallbackCapture.getValue().onResult(null);
         var request = mRequestCapture.getValue();
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertEquals(FC_SERVER_URL, request.getTrainingOptions().getServerAddress());
         assertEquals(TEST_POPULATION_NAME, request.getTrainingOptions().getPopulationName());
@@ -147,7 +148,7 @@ public class FederatedComputeServiceImplTest {
                 .when(mUserPrivacyStatus).isMeasurementEnabled();
 
         mServiceProxy.schedule(TEST_OPTIONS, new TestCallback());
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertFalse(mOnSuccessCalled);
     }
@@ -164,7 +165,7 @@ public class FederatedComputeServiceImplTest {
         mServiceProxy.schedule(TEST_OPTIONS, new TestCallback());
         mCallbackCapture.getValue().onResult(null);
         var request = mRequestCapture.getValue();
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertEquals(overrideUrl, request.getTrainingOptions().getServerAddress());
         assertEquals(TEST_POPULATION_NAME, request.getTrainingOptions().getPopulationName());
@@ -175,7 +176,7 @@ public class FederatedComputeServiceImplTest {
     public void testScheduleErr() throws Exception {
         mServiceProxy.schedule(TEST_OPTIONS, new TestCallback());
         mCallbackCapture.getValue().onError(new Exception());
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertTrue(mOnErrorCalled);
         assertEquals(ClientConstants.STATUS_INTERNAL_ERROR, mErrorCode);
@@ -193,7 +194,7 @@ public class FederatedComputeServiceImplTest {
 
         mServiceProxy.cancel(TEST_POPULATION_NAME, new TestCallback());
         mCallbackCapture.getValue().onResult(null);
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertTrue(mOnSuccessCalled);
     }
@@ -201,7 +202,7 @@ public class FederatedComputeServiceImplTest {
     @Test
     public void testCancelNoPopulation() throws Exception {
         mServiceProxy.cancel(TEST_POPULATION_NAME, new TestCallback());
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         verify(mMockManager, times(0)).cancel(any(), any(), any(), any());
         assertTrue(mOnSuccessCalled);
@@ -219,7 +220,7 @@ public class FederatedComputeServiceImplTest {
 
         mServiceProxy.cancel(TEST_POPULATION_NAME, new TestCallback());
         mCallbackCapture.getValue().onError(new Exception());
-        mLatch.await(1000, TimeUnit.MILLISECONDS);
+        mLatch.await(TEST_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         assertTrue(mOnErrorCalled);
         assertEquals(ClientConstants.STATUS_INTERNAL_ERROR, mErrorCode);
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
index 40245087..5f2c80e5 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/OdpExampleStoreServiceTests.java
@@ -20,7 +20,8 @@ import static android.federatedcompute.common.ClientConstants.EXAMPLE_STORE_ACTI
 import static android.federatedcompute.common.ClientConstants.EXTRA_EXAMPLE_ITERATOR_RESULT;
 import static android.federatedcompute.common.ClientConstants.EXTRA_EXAMPLE_ITERATOR_RESUMPTION_TOKEN;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertFalse;
@@ -28,6 +29,10 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assume.assumeTrue;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.when;
@@ -61,6 +66,7 @@ import com.android.ondevicepersonalization.services.data.OnDevicePersonalization
 import com.android.ondevicepersonalization.services.data.events.EventState;
 import com.android.ondevicepersonalization.services.data.events.EventsDao;
 import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
+import com.android.ondevicepersonalization.services.util.StatsUtils;
 import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
 
 import org.junit.After;
@@ -91,6 +97,7 @@ public class OdpExampleStoreServiceTests {
     private static final String TEST_COLLECTION_URI = "CollectionUri";
     private static final int LATCH_LONG_TIMEOUT_MILLIS = 10000;
     private static final int LATCH_SHORT_TIMEOUT_MILLIS = 1000;
+    private static final int CONCURRENT_MOCK_WAIT_TIMEOUT_MILLIS = 200;
 
     @Mock Context mMockContext;
     @InjectMocks OdpExampleStoreService mService;
@@ -110,6 +117,7 @@ public class OdpExampleStoreServiceTests {
             new ExtendedMockitoRule.Builder(this)
                     .spyStatic(UserPrivacyStatus.class)
                     .mockStatic(FlagsFactory.class)
+                    .mockStatic(StatsUtils.class)
                     .spyStatic(StableFlags.class)
                     .spyStatic(MonotonicClock.class)
                     .setStrictness(Strictness.LENIENT)
@@ -130,6 +138,10 @@ public class OdpExampleStoreServiceTests {
     @Before
     public void setUp() throws Exception {
         assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        doNothing().when(() -> StatsUtils.writeServiceRequestMetrics(
+                anyInt(), anyString(), any(), any(), anyInt(), anyLong()));
+        doNothing().when(() -> StatsUtils.writeServiceRequestMetrics(
+                anyInt(), anyInt()));
         initMocks(this);
         when(mMockContext.getApplicationContext()).thenReturn(APPLICATION_CONTEXT);
         ExtendedMockito.doReturn(mMockUserPrivacyStatus).when(UserPrivacyStatus::getInstance);
@@ -444,11 +456,12 @@ public class OdpExampleStoreServiceTests {
     }
 
     @After
-    public void cleanup() {
+    public void cleanup() throws Exception {
         OnDevicePersonalizationDbHelper dbHelper =
                 OnDevicePersonalizationDbHelper.getInstanceForTest(APPLICATION_CONTEXT);
         dbHelper.getWritableDatabase().close();
         dbHelper.getReadableDatabase().close();
         dbHelper.close();
+        Thread.sleep(CONCURRENT_MOCK_WAIT_TIMEOUT_MILLIS);
     }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
index 2f67eb86..d0019a3d 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
@@ -219,7 +219,6 @@ public final class OnDevicePersonalizationMaintenanceJobTest {
                 JobPolicy.newBuilder()
                         .setJobId(MAINTENANCE_TASK_JOB_ID)
                         .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
-                        .setRequireStorageNotLow(true)
                         .setPeriodicJobParams(
                                 JobPolicy.PeriodicJobParams.newBuilder()
                                         .setPeriodicIntervalMs(PERIOD_MILLIS)
@@ -227,17 +226,23 @@ public final class OnDevicePersonalizationMaintenanceJobTest {
                         .setIsPersisted(true)
                         .build();
 
-        BackoffPolicy backoffPolicy =
-                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
-
         assertWithMessage("createDefaultJobSpec() for OnDevicePersonalizationMaintenanceJob")
                 .that(OnDevicePersonalizationMaintenanceJob.createDefaultJobSpec())
                 .isEqualTo(
                         new JobSpec.Builder(expectedJobPolicy)
-                                .setBackoffPolicy(backoffPolicy)
                                 .build());
     }
 
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for OnDevicePersonalizationMaintenanceJob")
+                .that(new OnDevicePersonalizationMaintenanceJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+
     @Test
     public void testVendorDataCleanup() throws Exception {
         // Restore cleanupVendorData() from doNothing().
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
index 064a0a58..0c69da8d 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/IsolatedServiceBindingRunnerTest.java
@@ -16,9 +16,9 @@
 
 package com.android.ondevicepersonalization.services.process;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
 import static com.android.ondevicepersonalization.services.process.IsolatedServiceBindingRunner.TRUSTED_PARTNER_APPS_SIP;
 import static com.android.ondevicepersonalization.services.process.IsolatedServiceBindingRunner.UNKNOWN_APPS_SIP;
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/PluginProcessRunnerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/PluginProcessRunnerTest.java
index 80966ede..de71a629 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/process/PluginProcessRunnerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/process/PluginProcessRunnerTest.java
@@ -16,8 +16,9 @@
 
 package com.android.ondevicepersonalization.services.process;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertTrue;
 
 import androidx.test.core.app.ApplicationProvider;
 
@@ -34,9 +35,10 @@ public class PluginProcessRunnerTest {
     ProcessRunner mProcessRunner = new PluginProcessRunner(
             ApplicationProvider.getApplicationContext(),
             new PluginProcessRunner.Injector());
+
     @Test
-    public void testGetArchiveList_NullApkList() throws Exception {
-        assertTrue(PluginProcessRunner.getArchiveList(null).isEmpty());
+    public void testGetArchiveList_NullApkList() {
+        assertThat(PluginProcessRunner.getArchiveList(null)).isEmpty();
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobServiceTest.java
index b76198a7..4178ccd2 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobServiceTest.java
@@ -20,6 +20,8 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
@@ -32,6 +34,8 @@ import android.app.job.JobParameters;
 
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
+import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
 
 import com.google.common.util.concurrent.MoreExecutors;
 
@@ -56,6 +60,10 @@ public class ResetDataJobServiceTest {
     @Before
     public void setup() throws Exception {
         mSpyService = spy(new ResetDataJobService());
+        PhFlagsTestUtil.setUpDeviceConfigPermissions();
+
+        // By default, disable ResetDataJob SPE.
+        PhFlagsTestUtil.setSpeOnResetDataJobEnabled(false);
     }
 
     @Test
@@ -68,7 +76,25 @@ public class ResetDataJobServiceTest {
         boolean result = mSpyService.onStartJob(mock(JobParameters.class));
         assertTrue(result);
         verify(mSpyService, times(1)).jobFinished(any(), eq(false));
-        verify(() -> ResetDataTask.deleteMeasurementData());
+        verify(ResetDataTask::deleteMeasurementData);
+    }
+
+    @Test
+    @ExtendedMockitoRule.MockStatic(OdpJobScheduler.class)
+    public void onStartJobTestSpeEnabled() {
+        // Enable SPE.
+        PhFlagsTestUtil.setSpeOnResetDataJobEnabled(true);
+        // Mock OdpJobScheduler to not actually schedule the job.
+        OdpJobScheduler mockedScheduler = mock(OdpJobScheduler.class);
+        doReturn(mockedScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+
+        assertThat(mSpyService.onStartJob(mock(JobParameters.class))).isFalse();
+
+        // Verify SPE scheduler has rescheduled the job.
+        verify(mockedScheduler).schedule(any(), any());
+
+        // Revert SPE flag.
+        PhFlagsTestUtil.setSpePilotJobEnabled(false);
     }
 
     @Test
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java
new file mode 100644
index 00000000..3adbe5c3
--- /dev/null
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java
@@ -0,0 +1,188 @@
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
+package com.android.ondevicepersonalization.services.reset;
+
+import static com.android.adservices.shared.proto.JobPolicy.BatteryType.BATTERY_TYPE_REQUIRE_NOT_LOW;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
+import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_RESULT_CODE_SUCCESSFUL;
+import static com.android.adservices.shared.spe.framework.ExecutionResult.SUCCESS;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+
+import static com.google.common.truth.Truth.assertWithMessage;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.adservices.shared.proto.JobPolicy;
+import com.android.adservices.shared.spe.framework.ExecutionResult;
+import com.android.adservices.shared.spe.framework.ExecutionRuntimeParameters;
+import com.android.adservices.shared.spe.logging.JobSchedulingLogger;
+import com.android.adservices.shared.spe.scheduling.BackoffPolicy;
+import com.android.adservices.shared.spe.scheduling.JobSpec;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
+import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.FlagsFactory;
+import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobScheduler;
+import com.android.ondevicepersonalization.services.sharedlibrary.spe.OdpJobServiceFactory;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.Spy;
+import org.mockito.quality.Strictness;
+
+/** Unit tests for {@link ResetDataJob}. */
+@MockStatic(OdpJobScheduler.class)
+@MockStatic(OdpJobServiceFactory.class)
+@MockStatic(ResetDataJobService.class)
+@MockStatic(FlagsFactory.class)
+public final class ResetDataJobTest {
+    @Rule(order = 0)
+    public final ExtendedMockitoRule extendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this).setStrictness(Strictness.LENIENT).build();
+
+    private static final Context sContext = ApplicationProvider.getApplicationContext();
+    private static final long MILLIS = 1000;
+
+    @Spy private ResetDataJob mSpyResetDataJob;
+    @Mock private Flags mMockFlags;
+    @Mock private ExecutionRuntimeParameters mMockParams;
+    @Mock private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock private OdpJobServiceFactory mMockOdpJobServiceFactory;
+
+    @Before
+    public void setup() throws Exception {
+        doReturn(mMockFlags).when(FlagsFactory::getFlags);
+        doReturn(mMockOdpJobScheduler).when(() -> OdpJobScheduler.getInstance(any()));
+        doReturn(mMockOdpJobServiceFactory).when(() -> OdpJobServiceFactory.getInstance(any()));
+
+        // Mock execution main function to do nothing unless asked.
+        doNothing().when(mSpyResetDataJob).deleteMeasurementData();
+    }
+
+    @After
+    public void teardown() {
+        OnDevicePersonalizationDbHelper dbHelper =
+                OnDevicePersonalizationDbHelper.getInstanceForTest(sContext);
+        dbHelper.getWritableDatabase().close();
+        dbHelper.getReadableDatabase().close();
+        dbHelper.close();
+    }
+
+    @Test
+    public void testGetExecutionFuture() throws Exception {
+        ListenableFuture<ExecutionResult> executionFuture =
+                mSpyResetDataJob.getExecutionFuture(sContext, mMockParams);
+
+        assertWithMessage("testGetExecutionFuture().get()")
+                .that(executionFuture.get())
+                .isEqualTo(SUCCESS);
+        verify(mSpyResetDataJob).deleteMeasurementData();
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_enabled() {
+        when(mMockFlags.getSpeOnResetDataJobEnabled()).thenReturn(true);
+
+        assertWithMessage("getJobEnablementStatus()")
+                .that(mSpyResetDataJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_ENABLED);
+    }
+
+    @Test
+    public void testGetJobEnablementStatus_disabled() {
+        when(mMockFlags.getSpeOnResetDataJobEnabled()).thenReturn(false);
+
+        assertWithMessage("getJobEnablementStatus()")
+                .that(mSpyResetDataJob.getJobEnablementStatus())
+                .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON);
+    }
+
+    @Test
+    public void testSchedule_spe() {
+        when(mMockFlags.getSpeOnResetDataJobEnabled()).thenReturn(true);
+
+        ResetDataJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler).schedule(eq(sContext), any());
+    }
+
+    @Test
+    public void testSchedule_legacy() {
+        int resultCode = SCHEDULING_RESULT_CODE_SUCCESSFUL;
+        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+
+        JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
+        when(mMockOdpJobServiceFactory.getJobSchedulingLogger()).thenReturn(loggerMock);
+        doReturn(resultCode).when(() ->
+                ResetDataJobService.schedule(/* forceSchedule */ eq(false)));
+
+        ResetDataJob.schedule(sContext);
+
+        verify(mMockOdpJobScheduler, never()).schedule(eq(sContext), any());
+        verify(() -> ResetDataJobService.schedule(/* forceSchedule */ eq(false)));
+        verify(loggerMock).recordOnSchedulingLegacy(RESET_DATA_JOB_ID, resultCode);
+    }
+
+    @Test
+    public void testCreateDefaultJobSpec() {
+        JobPolicy expectedJobPolicy =
+                JobPolicy.newBuilder()
+                        .setJobId(RESET_DATA_JOB_ID)
+                        .setBatteryType(BATTERY_TYPE_REQUIRE_NOT_LOW)
+                        .setOneOffJobParams(
+                                JobPolicy.OneOffJobParams.newBuilder()
+                                        .setMinimumLatencyMs(
+                                                mMockFlags.getResetDataDelaySeconds() * MILLIS)
+                                        .setOverrideDeadlineMs(
+                                                mMockFlags.getResetDataDeadlineSeconds() * MILLIS)
+                                        .build())
+                        .setIsPersisted(true)
+                        .build();
+
+        assertWithMessage("createDefaultJobSpec() for ResetDataJob")
+                .that(ResetDataJob.createDefaultJobSpec())
+                .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
+    }
+
+    @Test
+    public void testGetBackoffPolicy() {
+        BackoffPolicy expectedBackoffPolicy =
+                new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
+
+        assertWithMessage("getBackoffPolicy() for ResetDataJob")
+                .that(new ResetDataJob().getBackoffPolicy())
+                .isEqualTo(expectedBackoffPolicy);
+    }
+}
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
index 875ed6a2..e2e6fad7 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/AppRequestFlowTest.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.serviceflow;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
index 49d5385f..893aceae 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/RenderFlowTest.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.serviceflow;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
index d96011b7..8bf57036 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebTriggerFlowTest.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.serviceflow;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
index c708351d..9f9bb4c0 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/serviceflow/WebViewFlowTest.java
@@ -16,7 +16,7 @@
 
 package com.android.ondevicepersonalization.services.serviceflow;
 
-import static com.android.ondevicepersonalization.services.PhFlags.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactoryTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactoryTest.java
index 964ce4a0..268ecace 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactoryTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceFactoryTest.java
@@ -17,11 +17,20 @@
 package com.android.ondevicepersonalization.services.sharedlibrary.spe;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import android.content.Context;
+import android.os.PersistableBundle;
 
 import androidx.test.core.app.ApplicationProvider;
 
@@ -31,8 +40,18 @@ import com.android.adservices.shared.spe.logging.JobServiceLogger;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 import com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import com.android.ondevicepersonalization.services.Flags;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingJob;
+import com.android.ondevicepersonalization.services.data.errors.AggregateErrorDataReportingService;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJob;
+import com.android.ondevicepersonalization.services.data.user.UserDataCollectionJobService;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJob;
+import com.android.ondevicepersonalization.services.download.OnDevicePersonalizationDownloadProcessingJobService;
+import com.android.ondevicepersonalization.services.download.mdd.MddJob;
+import com.android.ondevicepersonalization.services.download.mdd.MddTaskScheduler;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJob;
 import com.android.ondevicepersonalization.services.maintenance.OnDevicePersonalizationMaintenanceJobService;
+import com.android.ondevicepersonalization.services.reset.ResetDataJob;
+import com.android.ondevicepersonalization.services.reset.ResetDataJobService;
 import com.android.ondevicepersonalization.services.statsd.errorlogging.ClientErrorLogger;
 
 import com.google.common.truth.Expect;
@@ -49,7 +68,12 @@ import java.util.concurrent.Executor;
 import java.util.concurrent.Executors;
 
 /** Unit tests for {@link OdpJobServiceFactory}. */
+@MockStatic(OnDevicePersonalizationDownloadProcessingJobService.class)
 @MockStatic(OnDevicePersonalizationMaintenanceJobService.class)
+@MockStatic(AggregateErrorDataReportingService.class)
+@MockStatic(ResetDataJobService.class)
+@MockStatic(UserDataCollectionJobService.class)
+@MockStatic(MddTaskScheduler.class)
 public final class OdpJobServiceFactoryTest {
     @Rule(order = 0)
     public final ExtendedMockitoRule extendedMockitoRule =
@@ -91,36 +115,165 @@ public final class OdpJobServiceFactoryTest {
 
     @Test
     public void testGetJobInstance_notConfiguredJob() {
-        int notConfiguredJobId = 1000;
+        int notConfiguredJobId = -1;
 
         assertThat(mFactory.getJobWorkerInstance(notConfiguredJobId)).isNull();
     }
 
     @Test
-    public void testGetJobInstance() {
+    public void testGetJobInstance_onDevicePersonalizationMaintenanceJob() {
         expect.withMessage("getJobWorkerInstance() for OnDevicePersonalizationMaintenanceJob")
                 .that(mFactory.getJobWorkerInstance(MAINTENANCE_TASK_JOB_ID))
                 .isInstanceOf(OnDevicePersonalizationMaintenanceJob.class);
     }
 
+    @Test
+    public void testGetJobInstance_aggregateErrorDataReportingJob() {
+        expect.withMessage("getJobWorkerInstance() for AggregateErrorDataReportingJob")
+                .that(mFactory.getJobWorkerInstance(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID))
+                .isInstanceOf(AggregateErrorDataReportingJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_resetDataJob() {
+        expect.withMessage("getJobWorkerInstance() for ResetDataJob")
+                .that(mFactory.getJobWorkerInstance(RESET_DATA_JOB_ID))
+                .isInstanceOf(ResetDataJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_userDataCollectionJob() {
+        expect.withMessage("getJobWorkerInstance() for UserDataCollectionJob")
+                .that(mFactory.getJobWorkerInstance(USER_DATA_COLLECTION_ID))
+                .isInstanceOf(UserDataCollectionJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_odpDownloadProcessingJob() {
+        expect.withMessage(
+                "getJobWorkerInstance() for OnDevicePersonalizationDownloadProcessingJob")
+                .that(mFactory.getJobWorkerInstance(DOWNLOAD_PROCESSING_TASK_JOB_ID))
+                .isInstanceOf(OnDevicePersonalizationDownloadProcessingJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_mddJob_cellularChargingPeriodicJobId() {
+        expect.withMessage(
+                "getJobWorkerInstance() for MddJob cellular charging periodic")
+                .that(mFactory.getJobWorkerInstance(MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isInstanceOf(MddJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_mddJob_chargingPeriodicJobId() {
+        expect.withMessage(
+                "getJobWorkerInstance() for MddJob charging periodic")
+                .that(mFactory.getJobWorkerInstance(MDD_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isInstanceOf(MddJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_mddJob_maintenancePeriodicJobId() {
+        expect.withMessage(
+                "getJobWorkerInstance() for MddJob maintenance periodic")
+                .that(mFactory.getJobWorkerInstance(MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID))
+                .isInstanceOf(MddJob.class);
+    }
+
+    @Test
+    public void testGetJobInstance_mddJob_wifiChargingPeriodicJobId() {
+        expect.withMessage(
+                "getJobWorkerInstance() for MddJob wifi charging periodic")
+                .that(mFactory.getJobWorkerInstance(MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isInstanceOf(MddJob.class);
+    }
+
     @Test
     public void testRescheduleJobWithLegacyMethod_notConfiguredJob() {
         int notConfiguredJobId = -1;
 
-        mFactory.rescheduleJobWithLegacyMethod(sContext, notConfiguredJobId);
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, notConfiguredJobId, /* extras */ null);
     }
 
     @Test
-    public void testRescheduleJobWithLegacyMethod() {
+    public void testRescheduleJobWithLegacyMethod_onDevicePersonalizationMaintenanceJobService() {
         boolean forceSchedule = true;
 
-        mFactory.rescheduleJobWithLegacyMethod(sContext, MAINTENANCE_TASK_JOB_ID);
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, MAINTENANCE_TASK_JOB_ID, /* extras */ null);
         verify(
                 () ->
                         OnDevicePersonalizationMaintenanceJobService.schedule(
                                 sContext, forceSchedule));
     }
 
+    @Test
+    public void testRescheduleJobWithLegacyMethod_aggregateErrorDataReportingService() {
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, AGGREGATE_ERROR_DATA_REPORTING_JOB_ID, /* extras */ null);
+        verify(() -> AggregateErrorDataReportingService
+                .scheduleIfNeeded(sContext, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_resetDataJobService() {
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, RESET_DATA_JOB_ID, /* extras */ null);
+        verify(() -> ResetDataJobService.schedule(/* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_userDataCollectionJobService() {
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, USER_DATA_COLLECTION_ID, /* extras */ null);
+        verify(() -> UserDataCollectionJobService.schedule(sContext, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_odpDownloadProcessingJobService() {
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, DOWNLOAD_PROCESSING_TASK_JOB_ID, /* extras */ null);
+        verify(() -> OnDevicePersonalizationDownloadProcessingJobService
+                .schedule(sContext, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_mddJobService_cellularChargingPeriodicJobId() {
+        PersistableBundle extras = createExtras();
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID, extras);
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(sContext, extras, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_mddJobService_chargingPeriodicJobId() {
+        PersistableBundle extras = createExtras();
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, MDD_CHARGING_PERIODIC_TASK_JOB_ID, extras);
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(sContext, extras, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_mddJobService_maintenancePeriodicJobId() {
+        PersistableBundle extras = createExtras();
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID, extras);
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(sContext, extras, /* forceSchedule */ true));
+    }
+
+    @Test
+    public void testRescheduleJobWithLegacyMethod_mddJobService_wifiChargingPeriodicJobId() {
+        PersistableBundle extras = createExtras();
+        mFactory.rescheduleJobWithLegacyMethod(
+                sContext, MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID, extras);
+        verify(() -> MddTaskScheduler
+                .scheduleWithLegacy(sContext, extras, /* forceSchedule */ true));
+    }
+
     @Test
     public void testGetJobIdToNameMap() {
         assertThat(mFactory.getJobIdToNameMap()).isSameInstanceAs(sJobIdToNameMap);
@@ -155,4 +308,8 @@ public final class OdpJobServiceFactoryTest {
     public void testGetFlags() {
         assertThat(mFactory.getFlags()).isSameInstanceAs(mMockFlags);
     }
+
+    private PersistableBundle createExtras() {
+        return new PersistableBundle();
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceTest.java
index ee6c229a..6d4cb891 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/sharedlibrary/spe/OdpJobServiceTest.java
@@ -20,7 +20,15 @@ import static com.android.adservices.shared.spe.JobServiceConstants.SKIP_REASON_
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doAnswer;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doNothing;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MAINTENANCE_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
@@ -53,6 +61,8 @@ import org.mockito.Mock;
 import org.mockito.Spy;
 import org.mockito.quality.Strictness;
 
+import java.util.function.Supplier;
+
 /** Unit tests for {@link OdpJobService}. */
 @SpyStatic(FlagsFactory.class)
 public final class OdpJobServiceTest {
@@ -137,7 +147,8 @@ public final class OdpJobServiceTest {
                             return null;
                         })
                 .when(mMockJobServiceFactory)
-                .rescheduleJobWithLegacyMethod(mSpyOdpJobService, jobId);
+                .rescheduleJobWithLegacyMethod(
+                        mSpyOdpJobService, jobId, /* extras */ null);
 
         // Disable SPE and the job should be rescheduled by the legacy scheduling method.
         doReturn(true).when(mSpyOdpJobService).shouldRescheduleWithLegacyMethod(jobId);
@@ -155,34 +166,239 @@ public final class OdpJobServiceTest {
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speDisabled() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(false);
+    public void testShouldRescheduleWithLegacyMethod_spePilotJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                MAINTENANCE_TASK_JOB_ID,
+                /* jobName */ "OnDevicePersonalizationMaintenanceJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_resetDataJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                RESET_DATA_JOB_ID,
+                /* jobName */ "ResetDataJob",
+                mMockFlags::getSpeOnResetDataJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_aggregateErrorDataReportingJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                AGGREGATE_ERROR_DATA_REPORTING_JOB_ID,
+                /* jobName */ "AggregateErrorDataReportingJob",
+                mMockFlags::getSpeOnAggregateErrorDataReportingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_userDataCollectionJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                USER_DATA_COLLECTION_ID,
+                /* jobName */ "UserDataCollectionJob",
+                mMockFlags::getSpeOnUserDataCollectionJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_odpDownloadProcessingJobDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                DOWNLOAD_PROCESSING_TASK_JOB_ID,
+                /* jobName */ "OnDevicePersonalizationDownloadProcessingJob",
+                mMockFlags::getSpeOnOdpDownloadProcessingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobCellularChargingPeriodicDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#cellularChargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobChargingPeriodicDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                MDD_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#chargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobMaintenancePeriodicDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#maintenancePeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobWifiChargingPeriodicDisabled() {
+        assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+                MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#wifiChargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    private void assertRescheduledWithLegacyMethodWhenSpeJobDisabled(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(false);
 
         assertWithMessage(
-                        "shouldRescheduleWithLegacyMethod() for"
-                                + " OnDevicePersonalizationMaintenanceJob")
-                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(MAINTENANCE_TASK_JOB_ID))
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " did not reschedule with legacy even though the spe job is disabled")
+                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isTrue();
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speDisabled_notConfiguredJobId() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(true);
+    public void testShouldRescheduleWithLegacyMethod_spePilotJobEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "OnDevicePersonalizationMaintenanceJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_resetDataJobEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "ResetDataJob",
+                mMockFlags::getSpeOnResetDataJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_aggregateErrorJobEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "AggregateErrorDataReportingJob",
+                mMockFlags::getSpeOnAggregateErrorDataReportingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_dataCollectionJobEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "UserDataCollectionJob",
+                mMockFlags::getSpeOnUserDataCollectionJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_downloadProcessEnabled_notConfiguredJobId() {
+        int invalidJobId = -1;
+
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "OnDevicePersonalizationDownloadProcessingJob",
+                mMockFlags::getSpeOnOdpDownloadProcessingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobEnabled_notConfiguredJobId() {
         int invalidJobId = -1;
 
-        assertWithMessage("shouldRescheduleWithLegacyMethod() for" + " not configured job ID")
-                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(invalidJobId))
+        assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+                invalidJobId,
+                /* jobName */ "MddJob",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    private void assertNotRescheduledWithLegacyMethodWhenJobMisconfigured(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(true);
+
+        assertWithMessage(
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " rescheduled even though job ID was misconfigured")
+                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isFalse();
     }
 
     @Test
-    public void testShouldRescheduleWithLegacyMethod_speEnabled() {
-        when(mMockFlags.getSpePilotJobEnabled()).thenReturn(true);
+    public void testShouldRescheduleWithLegacyMethod_spePilotJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                MAINTENANCE_TASK_JOB_ID,
+                /* jobName */ "OnDevicePersonalizationMaintenanceJob",
+                mMockFlags::getSpePilotJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_resetDataJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                RESET_DATA_JOB_ID,
+                /* jobName */ "ResetDataJob",
+                mMockFlags::getSpeOnResetDataJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_aggregateErrorDataReportingJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                AGGREGATE_ERROR_DATA_REPORTING_JOB_ID,
+                /* jobName */ "AggregateErrorDataReportingJob",
+                mMockFlags::getSpeOnAggregateErrorDataReportingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_userDataCollectionJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                USER_DATA_COLLECTION_ID,
+                /* jobName */ "UserDataCollectionJob",
+                mMockFlags::getSpeOnUserDataCollectionJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_odpDownloadProcessingJobEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                DOWNLOAD_PROCESSING_TASK_JOB_ID,
+                /* jobName */ "OnDevicePersonalizationDownloadProcessingJob",
+                mMockFlags::getSpeOnOdpDownloadProcessingJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobCellularChargingPeriodicEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#cellularChargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobChargingPeriodicEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                MDD_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#chargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobMaintenancePeriodicEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#maintenancePeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    @Test
+    public void testShouldRescheduleWithLegacyMethod_mddJobWifiChargingPeriodicEnabled() {
+        assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+                MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID,
+                /* jobName */ "MddJob#wifiChargingPeriodic",
+                mMockFlags::getSpeOnMddJobEnabled);
+    }
+
+    private void assertNotRescheduledWithLegacyMethodWhenSpeJobEnabled(
+            int jobId, String jobName, Supplier<Boolean> speJobEnabledFlagSupplier) {
+        when(speJobEnabledFlagSupplier.get()).thenReturn(true);
 
         assertWithMessage(
-                        "shouldRescheduleWithLegacyMethod() for"
-                                + " OnDevicePersonalizationMaintenanceJob")
-                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(MAINTENANCE_TASK_JOB_ID))
+                /* messageToPrepend */ "shouldRescheduleWithLegacyMethod() for " + jobName
+                        + " rescheduled with legacy method even though the spe job is enabled")
+                .that(mSpyOdpJobService.shouldRescheduleWithLegacyMethod(jobId))
                 .isFalse();
     }
 }
```

