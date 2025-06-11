```diff
diff --git a/aconfig/systemui.aconfig b/aconfig/systemui.aconfig
index 9a9259c..7fdc509 100644
--- a/aconfig/systemui.aconfig
+++ b/aconfig/systemui.aconfig
@@ -78,17 +78,99 @@ flag {
 }
 
 flag {
-    name: "enable_launcher_icon_shapes"
+    name: "smartspace_sports_card_background"
     namespace: "systemui"
-    description: "Enables launcher icon shapes customization"
-    bug: "348708061"
+    description: "Enables Smartspace sports card background protection and related ui updates"
+    bug: "380285747"
+    metadata {
+         purpose: PURPOSE_BUGFIX
+    }
 }
 
 flag {
-    name: "smartspace_sports_card_background"
+    name: "screenshot_context_url"
     namespace: "systemui"
-    description: "Enables Smartspace sports card background protection and related ui updates"
-    bug: "380285747"
+    description: "Include optional app-provided context URL when sharing a screenshot."
+    bug: "242791070"
+}
+
+flag {
+  name: "status_bar_connected_displays"
+  namespace: "lse_desktop_experience"
+  description: "Shows the status bar on connected displays"
+  bug: "379264862"
+}
+
+flag {
+   name: "lockscreen_custom_clocks"
+   namespace: "systemui"
+   description: "Enable lockscreen custom clocks"
+   bug: "378486437"
+}
+
+flag {
+   name: "clock_reactive_variants"
+   namespace: "systemui"
+   description: "Add reactive variant fonts to some clocks"
+   bug: "343495953"
+}
+
+flag {
+   name: "clock_reactive_smartspace_layout"
+   namespace: "systemui"
+   description: "Smartspace layout logic change for reactive clocks"
+   bug: "343495953"
+}
+
+flag {
+    name: "extended_wallpaper_effects"
+    namespace: "systemui"
+    description: "Enables extended wallpaper effects"
+    bug: "334125919"
+}
+
+
+flag {
+    name: "use_preferred_image_editor"
+    namespace: "systemui"
+    description: "Prefer the editor in config_preferredScreenshotEditor if component is present/enabled on the system"
+    bug: "391401141"
+}
+
+flag {
+    name: "enable_lpp_squeeze_effect"
+    namespace: "systemui"
+    description: "Enables squeeze effect on power button long press launching Gemini"
+    bug: "396099245"
+}
+
+flag {
+  name: "cursor_hot_corner"
+  namespace: "systemui"
+  description: "Enables hot corner navigation by cursor"
+  bug: "397182595"
+}
+
+flag {
+    name: "smartspace_ui_update"
+    namespace: "systemui"
+    description: "Update Smartspace UI"
+    bug: "389741821"
+}
+
+flag {
+    name: "smartspace_ui_update_resources"
+    namespace: "systemui"
+    description: "Read-only flag for updating resources for Smartspace UI"
+    bug: "389741821"
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "smartspace_remoteviews_intent_handler"
+    namespace: "systemui"
+    description: "Enables Smartspace RemoteViews intent handling on lockscreen"
+    bug: "399416038"
     metadata {
          purpose: PURPOSE_BUGFIX
     }
diff --git a/ambientlib/Android.bp b/ambientlib/Android.bp
new file mode 100644
index 0000000..2b20c91
--- /dev/null
+++ b/ambientlib/Android.bp
@@ -0,0 +1,43 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+android_library {
+    name: "ambientlib",
+    manifest: "AndroidManifest.xml",
+    sdk_version: "current",
+    // TODO(b/391934208): Update min_sdk_version to 35
+    min_sdk_version: "31",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    static_libs: [
+        "androidx.core_core-ktx",
+        "androidx.annotation_annotation",
+        "androidx.appsearch_appsearch",
+        "androidx.appsearch_appsearch-builtin-types",
+        "androidx.appsearch_appsearch-platform-storage",
+        "androidx.concurrent_concurrent-futures-ktx",
+        "guava",
+        "kotlin-stdlib",
+        "kotlinx_coroutines",
+        "kotlinx-coroutines-android",
+        "kotlinx-coroutines-core",
+        "kotlinx_coroutines_guava",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/ambientlib/AndroidManifest.xml b/ambientlib/AndroidManifest.xml
new file mode 100644
index 0000000..119dc1c
--- /dev/null
+++ b/ambientlib/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.google.android.ambient.app">
+</manifest>
\ No newline at end of file
diff --git a/ambientlib/build.gradle.kts b/ambientlib/build.gradle.kts
new file mode 100644
index 0000000..7b754d2
--- /dev/null
+++ b/ambientlib/build.gradle.kts
@@ -0,0 +1,26 @@
+plugins {
+    id(libs.plugins.android.library.get().pluginId)
+    id(libs.plugins.kotlin.android.get().pluginId)
+    id(libs.plugins.kotlin.kapt.get().pluginId)
+}
+
+android {
+    namespace = "com.google.android.ambient.app"
+    sourceSets {
+        named("main") {
+            java.setSrcDirs(listOf("src"))
+            manifest.srcFile("AndroidManifest.xml")
+        }
+    }
+}
+
+dependencies {
+    implementation("androidx.core:core")
+    implementation("androidx.core:core-ktx:1.12.0")
+    implementation("com.google.guava:guava:30.1.1-jre")
+    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-guava:1.7.3")
+    implementation(libs.androidx.appsearch)
+    implementation(libs.androidx.appsearch.platform.storage)
+    implementation(libs.androidx.appsearch.builtin.types)
+    kapt("androidx.appsearch:appsearch-compiler:1.1.0-beta01")
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/AmbientData.kt b/ambientlib/src/com/google/android/ambient/app/AmbientData.kt
new file mode 100644
index 0000000..50aea25
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/AmbientData.kt
@@ -0,0 +1,127 @@
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
+package com.google.android.ambient.app
+
+import android.content.Intent
+import java.time.Instant
+
+/**
+ * A high level, abstracted definition of an [AmbientData] which always contains [MetaData] included
+ * for ranking.
+ */
+sealed interface AmbientData {
+
+    /** Ranking [MetaData] associated with this [AmbientData]. */
+    val metaData: MetaData
+
+    /** A notification id value that can be utilized to dedupe against. */
+    val notificationDedupeId: String
+
+    /** An intrinsic weight definition derived from the type of content, see [Ranker]. */
+    val intrinsicWeight: Int
+
+    /**
+     * Tap action.
+     *
+     * <p>{@link Intent#parseUri()} intent.
+     *
+     * @see <a href="//reference/android/content/Intent#intent-structure">Intent Structure</a>
+     */
+    val tapAction: Intent?
+
+    /**
+     * Dismiss action.
+     *
+     * <p>{@link Intent#parseUri()} intent.
+     *
+     * @see <a href="//reference/android/content/Intent#intent-structure">Intent Structure</a>
+     */
+    val dismissAction: Intent?
+}
+
+/**
+ * Ranking metadata with some basic defaults, reference the ambient ranking meta data document for
+ * more insight.
+ */
+data class MetaData(
+    /**
+     * An unique identifier for the [AmbientData], keep this stable if you want to update an
+     * existing record rather than creating a new one.
+     */
+    val id: String,
+
+    /**
+     * Field to uniquely identify the message corresponding to an instance of [AmbientData]
+     * document.
+     *
+     * [instanceId] identify a message used to update the [AmbientDataDocument] document. The
+     * [instanceId] is different from the [id] of the [AmbientDataDocument]. The [id] is a unique
+     * identifier for the event it represents. and it remains stable when the document is
+     * overwritten everytime new data is published. But the [instanceId] uniquely identifies a
+     * message and changes when the document is overwritten with the data in the new message.
+     *
+     * When logging interactions, consumers of this data document must make sure to read the value
+     * of this field and set it to the [mQuery] field of [TakenAction] documents.
+     */
+    val instanceId: String? = null,
+
+    /**
+     * The source package that published the [AmbientData].
+     *
+     * Will only be populated when read from the read session.
+     */
+    val attribution: String? = null,
+
+    /**
+     * The created time of the [AmbientData], which if it hasn't been set, defaults to
+     * [Instant.MAX].
+     */
+    val createAtInstant: Instant = Instant.MAX,
+
+    /**
+     * The ttl time of the [AmbientData], which if it hasn't been set, defaults to [Long.MAX_VALUE].
+     */
+    val ttlMillis: Long = Long.MAX_VALUE,
+
+    /**
+     * The start time of the [AmbientData], which if it hasn't been set, defaults to [Instant.MAX].
+     */
+    val startTime: Instant = Instant.MAX,
+
+    /**
+     * The end time of the [AmbientData], which if it hasn't been set, defaults to [Instant.MAX].
+     */
+    val endTime: Instant = Instant.MAX,
+
+    /**
+     * The confidence score of the [AmbientData], which is utilized to break ties in ranking or sort
+     * results. Defaults to 1.0 (max confidence).
+     */
+    val confidence: Double = 1.0,
+
+    /**
+     * A list of [ImportantTimeDuration]'s, that must fall between the [startTime] and the [endTime]
+     * that provide extra signals to create a curve for the ranking methodology.
+     */
+    val importantTimes: List<ImportantTimeDuration> = listOf(),
+) {
+
+    /**
+     * An [ImportantTimeDuration] is a range of time within the [MetaData.startTime] and
+     * [MetaData.endTime] that signals the highest priority points across the generated curve.
+     */
+    data class ImportantTimeDuration(val startTime: Instant, val endTime: Instant)
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/AmbientDataPublishingManager.kt b/ambientlib/src/com/google/android/ambient/app/AmbientDataPublishingManager.kt
new file mode 100644
index 0000000..ca3b3a9
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/AmbientDataPublishingManager.kt
@@ -0,0 +1,24 @@
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
+package com.google.android.ambient.app
+
+import android.content.Context
+import java.util.concurrent.Executor
+
+/** Generic high level interface for a [AmbientDataPublishingManager]. */
+interface AmbientDataPublishingManager {
+    suspend fun createWriteSession(executor: Executor, context: Context): AmbientDataWriteSession?
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/AmbientDataWriteSession.kt b/ambientlib/src/com/google/android/ambient/app/AmbientDataWriteSession.kt
new file mode 100644
index 0000000..13c46d6
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/AmbientDataWriteSession.kt
@@ -0,0 +1,26 @@
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
+package com.google.android.ambient.app
+
+/**
+ * Generic high level interface for write sessions created from [AmbientDataPublishingManager]'s.
+ */
+// TODO(b/391934208): This file is partially migrated. Lack reportUsage, delete.
+interface AmbientDataWriteSession {
+    fun publish(ambientData: AmbientData)
+
+    fun close()
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/ThingAmbientData.kt b/ambientlib/src/com/google/android/ambient/app/ThingAmbientData.kt
new file mode 100644
index 0000000..7292657
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/ThingAmbientData.kt
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
+package com.google.android.ambient.app
+
+import android.app.blob.BlobHandle
+import android.content.Intent
+
+/** Ambient data describing a generic thing. */
+data class ThingAmbientData(
+    val thing: Thing,
+    override val metaData: MetaData,
+    override val notificationDedupeId: String = "",
+    override val tapAction: Intent? = null,
+    override val dismissAction: Intent? = null,
+) : AmbientData {
+    override val intrinsicWeight: Int
+        get() = Integer.MAX_VALUE
+}
+
+data class Thing(
+    val name: String,
+    val shortName: String,
+    val description: String,
+    val image: BlobHandle?,
+    val url: String,
+)
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingManagerImpl.kt b/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingManagerImpl.kt
new file mode 100644
index 0000000..7821bce
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingManagerImpl.kt
@@ -0,0 +1,64 @@
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
+package com.google.android.ambient.app.backend
+
+import android.content.Context
+import android.util.Log
+import androidx.appsearch.app.AppSearchSession
+import androidx.appsearch.platformstorage.PlatformStorage
+import com.google.android.ambient.app.AmbientDataPublishingManager
+import com.google.android.ambient.app.AmbientDataWriteSession
+import com.google.common.util.concurrent.Futures
+import java.util.concurrent.Executor
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.guava.await
+
+/** An implementation of [AmbientDataPublishingManager] that is backed by AppSearch. */
+class AmbientDataAppSearchPublishingManagerImpl : AmbientDataPublishingManager {
+
+    override suspend fun createWriteSession(
+        executor: Executor,
+        context: Context,
+    ): AmbientDataWriteSession? {
+        try {
+            Log.d("AmbientDataAppSearchPublishingManagerImpl", "createWriteSession")
+            val platformSession = createPlatformSession(context, executor)
+            return AmbientDataAppSearchPublishingWriteSessionImpl(platformSession, executor)
+        } catch (e: Exception) {
+            return null
+        }
+    }
+
+    private suspend fun createPlatformSession(
+        context: Context,
+        executor: Executor,
+    ): AppSearchSession {
+        val deferred = CompletableDeferred<AppSearchSession>()
+        val platformStorageFuture =
+            PlatformStorage.createSearchSessionAsync(
+                PlatformStorage.SearchContext.Builder(context, DATABASE_NAME)
+                    .setWorkerExecutor(executor)
+                    .build()
+            )
+        Futures.transform(platformStorageFuture, { result -> deferred.complete(result) }, executor)
+            .await()
+        return deferred.await()
+    }
+
+    companion object {
+        private const val DATABASE_NAME: String = "AMBIENT_DATA_DB"
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingWriteSessionImpl.kt b/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingWriteSessionImpl.kt
new file mode 100644
index 0000000..0f5dfce
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/AmbientDataAppSearchPublishingWriteSessionImpl.kt
@@ -0,0 +1,91 @@
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
+package com.google.android.ambient.app.backend
+
+import android.util.Log
+import androidx.appsearch.app.AppSearchBatchResult
+import androidx.appsearch.app.AppSearchSession
+import androidx.appsearch.app.PutDocumentsRequest
+import androidx.appsearch.app.SetSchemaRequest
+import androidx.appsearch.app.SetSchemaResponse
+import com.google.android.ambient.app.AmbientData
+import com.google.android.ambient.app.AmbientDataWriteSession
+import com.google.android.ambient.app.backend.documents.AppSearchAmbientDataConverter
+import com.google.android.ambient.app.backend.documents.ThingAmbientDataDocument
+import com.google.common.util.concurrent.FutureCallback
+import com.google.common.util.concurrent.Futures
+import com.google.common.util.concurrent.ListenableFuture
+import java.util.concurrent.Executor
+
+/** An implementation of [AmbientDataWriteSession] that is backed by AppSearch. */
+// TODO(b/391934208): This file is only partially migrated.
+class AmbientDataAppSearchPublishingWriteSessionImpl(
+    private val appSearchSession: AppSearchSession,
+    private val executor: Executor,
+) : AmbientDataWriteSession {
+
+    override fun publish(ambientData: AmbientData) {
+        val document = AppSearchAmbientDataConverter.serialize(ambientData)
+        Log.d("Ambient", "Writing $document")
+        val putDocumentRequest = PutDocumentsRequest.Builder().addDocuments(document).build()
+        val schemaFuture = setSchema()
+
+        val publishFuture =
+            Futures.transformAsync(
+                schemaFuture,
+                { appSearchSession.putAsync(putDocumentRequest) },
+                executor,
+            )
+
+        Futures.addCallback(
+            publishFuture,
+            object : FutureCallback<AppSearchBatchResult<String, Void>?> {
+                override fun onSuccess(result: AppSearchBatchResult<String, Void>?) {
+                    val successfulResults = result?.successes
+                    val failedResults = result?.failures
+                    Log.d(
+                        "Ambient",
+                        "${failedResults?.size} failed, ${successfulResults?.size} succeeded",
+                    )
+                    if (!failedResults.isNullOrEmpty()) {
+                        Log.e("Ambient", "$failedResults")
+                    }
+                }
+
+                override fun onFailure(t: Throwable) {
+                    Log.e("Ambient", "Failed to put documents.", t)
+                }
+            },
+            executor,
+        )
+    }
+
+    private fun setSchema(): ListenableFuture<SetSchemaResponse> {
+        Log.d("Ambient", "Setting schema for ambient data and usage reports")
+        val schemaRequestBuilder =
+            SetSchemaRequest.Builder()
+                .addDocumentClasses(ThingAmbientDataDocument::class.java)
+                .setSchemaTypeDisplayedBySystem(ThingAmbientDataDocument.SCHEMA_NAME, true)
+                .setForceOverride(true)
+
+        return appSearchSession.setSchemaAsync(schemaRequestBuilder.build())
+    }
+
+    override fun close() {
+        // appSearchSession.requestFlushAsync()
+        appSearchSession.close()
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientDataDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientDataDocument.kt
new file mode 100644
index 0000000..c642a77
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientDataDocument.kt
@@ -0,0 +1,115 @@
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
+package com.google.android.ambient.app.backend.documents
+
+import androidx.appsearch.annotation.Document
+import androidx.appsearch.builtintypes.PotentialAction
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ThingDocument
+
+/**
+ * High level [Document] definition describing Ambient Data as it is to be persisted within
+ * AppSearch.
+ */
+// TODO(b/391934208): This file is partially migrated. Sports is not migrated.
+@Document
+interface AmbientDataDocument {
+    /** Required field for an AppSearch document class. */
+    @get:Document.Id val id: String
+
+    /**
+     * Required field for a document class. All AppSearch documents MUST have a namespace. Value
+     * should be set to "Ambient" so that it can be discovered by consuming surfaces.
+     */
+    @get:Document.Namespace val namespace: String
+
+    /**
+     * Required field for a document class. All AppSearch documents MUST have a creation timestamp.
+     */
+    @get:Document.CreationTimestampMillis val creationTimestamp: Long
+
+    /**
+     * Required field so that documents are auto-cleaned up by AppSearch. See [Document.TtlMillis]
+     */
+    @get:Document.TtlMillis val documentTtlMillis: Long
+
+    /**
+     * RANKING REQUIRED FIELDS, see go/android-ambient-data-platform-ranking From the following
+     * fields, Ranking implementations can derive an importance curve and apply any of their own
+     * weights to it.
+     */
+    @get:Document.DocumentProperty(indexNestedProperties = true)
+    val ambientRankingMetaData: AmbientRankingMetaDataDocument
+
+    /** Optional notification id field that that this Ambient Data should be deduped against. */
+    @get:Document.StringProperty val notificationDedupeId: String
+
+    /**
+     * Tap action, for when the ambient data is clicked on.
+     *
+     * @see [PotentialAction]
+     */
+    @get:Document.DocumentProperty(indexNestedProperties = false) val tapAction: PotentialAction
+
+    /**
+     * Dismiss action, for when the ambient data is dismissed.
+     *
+     * @see [PotentialAction]
+     */
+    @get:Document.DocumentProperty(indexNestedProperties = false) val dismissAction: PotentialAction
+
+    /**
+     * The underlying built in derived type of the ambient data.
+     *
+     * By default the properties of the built in type are indexed so that they can be queried
+     * independently of the ambient data definition.
+     *
+     * @see [ThingDocument]
+     */
+    @get:Document.DocumentProperty(indexNestedProperties = true) val builtInType: ThingDocument
+
+    companion object {
+        const val NAMESPACE = "AmbientData"
+
+        // Required static creator
+        @JvmStatic
+        fun create(
+            id: String,
+            namespace: String,
+            creationTimestamp: Long,
+            documentTtlMillis: Long,
+            ambientRankingMetaData: AmbientRankingMetaDataDocument,
+            notificationDedupeId: String,
+            tapAction: PotentialAction,
+            dismissAction: PotentialAction,
+            builtInType: ThingDocument,
+        ): AmbientDataDocument {
+            return when (builtInType) {
+                else ->
+                    ThingAmbientDataDocument.ThingAmbientDataDocumentImpl(
+                        id,
+                        namespace,
+                        creationTimestamp,
+                        documentTtlMillis,
+                        ambientRankingMetaData,
+                        notificationDedupeId,
+                        tapAction,
+                        dismissAction,
+                        builtInType,
+                    )
+            }
+        }
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientRankingMetaDataDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientRankingMetaDataDocument.kt
new file mode 100644
index 0000000..db0a7ed
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/AmbientRankingMetaDataDocument.kt
@@ -0,0 +1,69 @@
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
+package com.google.android.ambient.app.backend.documents
+
+import androidx.appsearch.annotation.Document
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ImportantDurationDocument
+
+/**
+ * The ranking metadata document with sufficient signals from the publisher to understand when an
+ * Ambient event is happening, ending, and the important timeframes within that range.
+ *
+ * Also contains a confidence score to allow sorting during tie breaker events.
+ */
+@Document
+data class AmbientRankingMetaDataDocument(
+    /** Required field for an AppSearch document class. */
+    @Document.Id val id: String,
+
+    /** Required field for an AppSearch document class. */
+    @Document.Namespace val namespace: String = NAMESPACE,
+
+    /**
+     * Field to uniquely identify the message corresponding to an instance of [AmbientData]
+     * document.
+     *
+     * [instanceId] identify a message used to update the [AmbientDataDocument] document. The
+     * [instanceId] is different from the [id] of the [AmbientDataDocument]. The [id] is a unique
+     * identifier for the event it represents. and it remains stable when the document is
+     * overwritten everytime new data is published. But the [instanceId] uniquely identifies a
+     * message and changes when the document is overwritten with the data in the new message.
+     *
+     * When logging interactions, consumers of this data document must make sure to read the value
+     * of this field and set it to the [mQuery] field of [TakenAction] documents.
+     */
+    @Document.StringProperty val instanceId: String?,
+
+    /** Required field for Ambient document ranking. Describes when the content becomes relevant. */
+    @Document.LongProperty val startTimeMillis: Long,
+
+    // Required field for Ambient document ranking. Describes when the content
+    // is no longer relevant.
+    @Document.LongProperty val endTimeMillis: Long,
+
+    // Required field for Ambient document ranking. A value between 0 and 1 detailing
+    // the confidence of the published ambient data.
+    @Document.DoubleProperty val confidence: Double,
+
+    // Required field for Ambient document ranking. Describes the points
+    // in time where the content is most relevant.
+    @get:Document.DocumentProperty(indexNestedProperties = true)
+    val importantTimeFrames: List<ImportantDurationDocument>,
+) {
+    companion object {
+        const val NAMESPACE = "AmbientRankingMetaData"
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/AppSearchAmbientDataConverter.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/AppSearchAmbientDataConverter.kt
new file mode 100644
index 0000000..918d2a8
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/AppSearchAmbientDataConverter.kt
@@ -0,0 +1,161 @@
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
+package com.google.android.ambient.app.backend.documents
+
+import android.content.Intent
+import android.util.Log
+import androidx.appsearch.app.GenericDocument
+import androidx.appsearch.builtintypes.PotentialAction
+import com.google.android.ambient.app.AmbientData
+import com.google.android.ambient.app.MetaData
+import com.google.android.ambient.app.Thing
+import com.google.android.ambient.app.ThingAmbientData
+import com.google.android.ambient.app.backend.documents.BlobStoreHandleDocument.Companion.toBlobHandle
+import com.google.android.ambient.app.backend.documents.BlobStoreHandleDocument.Companion.toBlobStoreHandleDocument
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ImportantDurationDocument
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ThingDocument
+import java.time.Instant
+
+/**
+ * Conversion library for translating between AppSearch definitions of [AmbientDataDocument]'s to
+ * [AmbientData] and vice versa.
+ */
+// TODO(b/391934208): This file is only partially migrated.
+object AppSearchAmbientDataConverter {
+
+    private fun serializeMetaData(ambientData: AmbientData): AmbientRankingMetaDataDocument {
+        val rankingMetadataId = ambientData.metaData.id + ":RankingMetaData"
+        return AmbientRankingMetaDataDocument(
+            id = rankingMetadataId,
+            startTimeMillis = ambientData.metaData.startTime.toEpochMilli(),
+            endTimeMillis = ambientData.metaData.endTime.toEpochMilli(),
+            confidence = ambientData.metaData.confidence,
+            importantTimeFrames =
+                ambientData.metaData.importantTimes.map {
+                    ImportantDurationDocument.fromImportantDuration(
+                        parentId = rankingMetadataId,
+                        duration = it,
+                    )
+                },
+            instanceId = ambientData.metaData.instanceId ?: "",
+        )
+    }
+
+    private fun serializeIntent(intent: Intent?): PotentialAction {
+        return PotentialAction.Builder().setUri(intent?.toUri(Intent.URI_INTENT_SCHEME)).build()
+    }
+
+    /**
+     * Convenience function to serialize an [AmbientData] definition to an [AmbientDataDocument].
+     */
+    fun serialize(ambientData: AmbientData): AmbientDataDocument {
+        when (ambientData) {
+            is ThingAmbientData -> {
+                return ThingAmbientDataDocument(
+                    builtInType =
+                        ThingDocument.create(
+                            id = "builtInType:${ambientData.metaData.id}",
+                            name = ambientData.thing.name,
+                            alternateNames = listOf(ambientData.thing.shortName),
+                            description = ambientData.thing.description,
+                            image = ambientData.thing.image?.tag ?: "",
+                            blobStoreImage = ambientData.thing.image?.toBlobStoreHandleDocument(),
+                            url = ambientData.thing.url,
+                        ),
+                    // General AmbientDataDocument fields
+                    id = ambientData.metaData.id,
+                    documentTtlMillis = ambientData.metaData.ttlMillis,
+                    creationTimestamp = Instant.now().toEpochMilli(),
+                    ambientRankingMetaData = serializeMetaData(ambientData),
+                    notificationDedupeId = ambientData.notificationDedupeId,
+                    tapAction = serializeIntent(ambientData.tapAction),
+                    dismissAction = serializeIntent(ambientData.dismissAction),
+                )
+            }
+            else -> throw IllegalArgumentException("No document type found")
+        }
+    }
+
+    /**
+     * Convenience function to retrieve an [AmbientData] representation from a [GenericDocument].
+     */
+    fun from(genericDocument: GenericDocument, packageName: String): AmbientData? {
+        val feature = toFeature(genericDocument, packageName) ?: return null
+        return feature
+    }
+
+    private fun toMetaData(
+        ambientDataDocument: AmbientDataDocument,
+        packageName: String,
+    ): MetaData {
+        return MetaData(
+            id = ambientDataDocument.id,
+            attribution = packageName,
+            createAtInstant = Instant.ofEpochMilli(ambientDataDocument.creationTimestamp),
+            ttlMillis = ambientDataDocument.documentTtlMillis,
+            confidence = ambientDataDocument.ambientRankingMetaData.confidence,
+            startTime =
+                Instant.ofEpochMilli(ambientDataDocument.ambientRankingMetaData.startTimeMillis),
+            endTime =
+                Instant.ofEpochMilli(ambientDataDocument.ambientRankingMetaData.endTimeMillis),
+            importantTimes =
+                ambientDataDocument.ambientRankingMetaData.importantTimeFrames.map {
+                    it.toDuration()
+                },
+            instanceId = ambientDataDocument.ambientRankingMetaData.instanceId,
+        )
+    }
+
+    private fun toIntent(potentialAction: PotentialAction): Intent? {
+        return if (potentialAction.uri != null) {
+            Intent.parseUri(potentialAction.uri, Intent.URI_INTENT_SCHEME)
+        } else {
+            null
+        }
+    }
+
+    private fun toFeature(genericDocument: GenericDocument, packageName: String): AmbientData? {
+        val parentTypes: List<String>? = genericDocument.parentTypes
+
+        if (parentTypes.isNullOrEmpty()) {
+            Log.w("Ambient", "Parent types is null")
+        }
+
+        when (genericDocument.schemaType) {
+            ThingAmbientDataDocument.SCHEMA_NAME -> {
+                val thingAmbientDocument =
+                    genericDocument.toDocumentClass(ThingAmbientDataDocument::class.java)
+                val thingDocument = thingAmbientDocument.builtInType
+                return ThingAmbientData(
+                    thing =
+                        Thing(
+                            name = thingDocument.name,
+                            shortName = thingDocument.alternateNames.firstOrNull() ?: "",
+                            description = thingDocument.description,
+                            image = thingDocument.blobStoreImage?.toBlobHandle(),
+                            url = thingDocument.url,
+                        ),
+                    // General AmbientData fields
+                    metaData = toMetaData(thingAmbientDocument, packageName),
+                    notificationDedupeId = thingAmbientDocument.notificationDedupeId,
+                    tapAction = toIntent(thingAmbientDocument.tapAction),
+                    dismissAction = toIntent(thingAmbientDocument.dismissAction),
+                )
+            }
+            else -> return null
+        }
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/BlobStoreHandleDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/BlobStoreHandleDocument.kt
new file mode 100644
index 0000000..04a0113
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/BlobStoreHandleDocument.kt
@@ -0,0 +1,68 @@
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
+package com.google.android.ambient.app.backend.documents
+
+import android.app.blob.BlobHandle
+import androidx.appsearch.annotation.Document
+import com.google.android.ambient.app.backend.documents.BlobStoreHandleDocument.Companion.SCHEMA_NAME
+import com.google.common.io.BaseEncoding
+import java.time.Duration
+
+/**
+ * A document describing information to access some blobstore data. This document does not contain
+ * the data itself and the consumer needs to assemble info to fetch the image use BlobHandle APIs
+ */
+@Document(name = SCHEMA_NAME)
+data class BlobStoreHandleDocument(
+    // Required field for an AppSearch document class.
+    @Document.Id val id: String,
+    // Required field for an AppSearch document class.
+    @Document.Namespace val namespace: String = NAMESPACE,
+    // SHA 256 digest supplied to BlobStore.
+    @Document.StringProperty val resourceDigest: String,
+    // Publisher package name of the data blob, will be used as the label for this blob.
+    @Document.StringProperty val publisherLabel: String,
+    @Document.CreationTimestampMillis val creationTimestamp: Long = System.currentTimeMillis(),
+    @Document.LongProperty val expiryTimeMillis: Long = TTL.toMillis(),
+    @Document.StringProperty val tag: String,
+) {
+
+    companion object {
+        const val NAMESPACE = "BlobStoreHandle"
+        const val SCHEMA_NAME = "AmbientDataSchema:BlobStoreHandle"
+        val TTL: Duration = Duration.ZERO
+
+        fun BlobHandle.toBlobStoreHandleDocument(): BlobStoreHandleDocument {
+            val hash = BaseEncoding.base64().encode(sha256Digest)
+            return BlobStoreHandleDocument(
+                id = hash,
+                resourceDigest = hash,
+                publisherLabel = label.toString(),
+                expiryTimeMillis = expiryTimeMillis,
+                tag = tag,
+            )
+        }
+
+        fun BlobStoreHandleDocument.toBlobHandle(): BlobHandle {
+            return BlobHandle.createWithSha256(
+                BaseEncoding.base64().decode(resourceDigest),
+                publisherLabel,
+                expiryTimeMillis,
+                tag,
+            )
+        }
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/ThingAmbientDataDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/ThingAmbientDataDocument.kt
new file mode 100644
index 0000000..6b000d2
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/ThingAmbientDataDocument.kt
@@ -0,0 +1,54 @@
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
+package com.google.android.ambient.app.backend.documents
+
+import androidx.appsearch.annotation.Document
+import androidx.appsearch.builtintypes.PotentialAction
+import com.google.android.ambient.app.backend.documents.ThingAmbientDataDocument.Companion.SCHEMA_NAME
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ThingDocument
+
+/** A high level AmbientDataDocument describing a thing ambient data. */
+@Document(name = SCHEMA_NAME, parent = [AmbientDataDocument::class])
+data class ThingAmbientDataDocument(
+    @get:Document.DocumentProperty(indexNestedProperties = true)
+    override val builtInType: ThingDocument,
+    // Inherited from AmbientDataDocument
+    override val namespace: String = AmbientDataDocument.NAMESPACE,
+    override val id: String,
+    override val creationTimestamp: Long,
+    override val documentTtlMillis: Long,
+    override val ambientRankingMetaData: AmbientRankingMetaDataDocument,
+    override val notificationDedupeId: String,
+    override val tapAction: PotentialAction,
+    override val dismissAction: PotentialAction,
+) : AmbientDataDocument {
+    companion object {
+        const val SCHEMA_NAME = "AmbientDataSchema:Thing"
+    }
+
+    // Required root implementation definition
+    data class ThingAmbientDataDocumentImpl(
+        override val id: String,
+        override val namespace: String,
+        override val creationTimestamp: Long,
+        override val documentTtlMillis: Long,
+        override val ambientRankingMetaData: AmbientRankingMetaDataDocument,
+        override val notificationDedupeId: String,
+        override val tapAction: PotentialAction,
+        override val dismissAction: PotentialAction,
+        override val builtInType: ThingDocument,
+    ) : AmbientDataDocument
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ImportantDurationDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ImportantDurationDocument.kt
new file mode 100644
index 0000000..17ab485
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ImportantDurationDocument.kt
@@ -0,0 +1,54 @@
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
+package com.google.android.ambient.app.backend.documents.builtintypecandidates
+
+import androidx.appsearch.annotation.Document
+import com.google.android.ambient.app.MetaData
+import java.time.Instant
+
+/** A document describing an important duration in an [AmbientRankingMetaDataDocument]. */
+@Document
+data class ImportantDurationDocument(
+    // Required field for an AppSearch document class.
+    @Document.Id val id: String,
+    // Required field for an AppSearch document class.
+    @Document.Namespace val namespace: String = NAMESPACE,
+    @Document.LongProperty val startTimeMillis: Long,
+    @Document.LongProperty val endTimMillis: Long,
+) {
+
+    fun toDuration(): MetaData.ImportantTimeDuration {
+        return MetaData.ImportantTimeDuration(
+            startTime = Instant.ofEpochMilli(startTimeMillis),
+            endTime = Instant.ofEpochMilli(endTimMillis),
+        )
+    }
+
+    companion object {
+        const val NAMESPACE = "ImportantDuration"
+
+        fun fromImportantDuration(
+            parentId: String,
+            duration: MetaData.ImportantTimeDuration,
+        ): ImportantDurationDocument {
+            return ImportantDurationDocument(
+                startTimeMillis = duration.startTime.toEpochMilli(),
+                endTimMillis = duration.endTime.toEpochMilli(),
+                id = "$parentId:ImportantDuration:${duration.startTime.toEpochMilli()}}",
+            )
+        }
+    }
+}
diff --git a/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ThingDocument.kt b/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ThingDocument.kt
new file mode 100644
index 0000000..1c83cbf
--- /dev/null
+++ b/ambientlib/src/com/google/android/ambient/app/backend/documents/buildintypecandidates/ThingDocument.kt
@@ -0,0 +1,80 @@
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
+package com.google.android.ambient.app.backend.documents.builtintypecandidates
+
+import androidx.appsearch.annotation.Document
+import com.google.android.ambient.app.backend.documents.BlobStoreHandleDocument
+import com.google.android.ambient.app.backend.documents.builtintypecandidates.ThingDocument.Companion.SCHEMA_NAME
+
+/**
+ * A placeholder [Document] that represents a [Thing] in AppSearch, until we upstream the other
+ * definitions.
+ */
+@Document(name = SCHEMA_NAME)
+interface ThingDocument {
+    // Required field for an AppSearch document class.
+    @get:Document.Id val id: String
+    // Required field for an AppSearch document class.
+    @get:Document.Namespace val namespace: String
+
+    @get:Document.StringProperty val name: String
+    @get:Document.StringProperty val description: String
+    @get:Document.StringProperty val image: String
+    @get:Document.DocumentProperty val blobStoreImage: BlobStoreHandleDocument?
+    @get:Document.StringProperty val url: String
+    @get:Document.StringProperty val alternateNames: List<String>
+
+    companion object {
+        const val NAMESPACE = "Thing"
+        const val SCHEMA_NAME = "builtIn:Thing"
+
+        // Required static creator
+        @JvmStatic
+        fun create(
+            id: String,
+            namespace: String = NAMESPACE,
+            name: String,
+            description: String,
+            image: String,
+            blobStoreImage: BlobStoreHandleDocument?,
+            url: String,
+            alternateNames: List<String>,
+        ): ThingDocument {
+            return ThingDocumentImpl(
+                id,
+                namespace,
+                name,
+                description,
+                image,
+                blobStoreImage,
+                url,
+                alternateNames,
+            )
+        }
+
+        // Required root implementation definition
+        private data class ThingDocumentImpl(
+            override val id: String,
+            override val namespace: String,
+            override val name: String,
+            override val description: String,
+            override val image: String,
+            override val blobStoreImage: BlobStoreHandleDocument?,
+            override val url: String,
+            override val alternateNames: List<String>,
+        ) : ThingDocument
+    }
+}
diff --git a/animationlib/Android.bp b/animationlib/Android.bp
index 06a7034..9f496a9 100644
--- a/animationlib/Android.bp
+++ b/animationlib/Android.bp
@@ -68,7 +68,6 @@ android_robolectric_test {
     ],
     java_resource_dirs: ["tests/robolectric/config"],
     instrumentation_for: "TestAnimationLibApp",
-    upstream: true,
     strict_mode: false,
 }
 
diff --git a/displaylib/Android.bp b/displaylib/Android.bp
new file mode 100644
index 0000000..85eefb8
--- /dev/null
+++ b/displaylib/Android.bp
@@ -0,0 +1,30 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+    name: "displaylib",
+    manifest: "AndroidManifest.xml",
+    static_libs: [
+        "kotlinx_coroutines_android",
+        "dagger2",
+        "jsr330",
+        "//frameworks/libs/systemui:tracinglib-platform",
+    ],
+    plugins: ["dagger2-compiler"],
+    srcs: ["src/**/*.kt"],
+}
diff --git a/displaylib/AndroidManifest.xml b/displaylib/AndroidManifest.xml
new file mode 100644
index 0000000..4f3234b
--- /dev/null
+++ b/displaylib/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.app.displaylib">
+</manifest>
diff --git a/displaylib/README.MD b/displaylib/README.MD
new file mode 100644
index 0000000..2739a46
--- /dev/null
+++ b/displaylib/README.MD
@@ -0,0 +1,4 @@
+# displaylib
+
+This library contains utilities that make the management of multiple displays easier, more
+performant and elegant.
\ No newline at end of file
diff --git a/displaylib/TEST_MAPPING b/displaylib/TEST_MAPPING
new file mode 100644
index 0000000..31260e9
--- /dev/null
+++ b/displaylib/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "presubmit": [
+    {
+      "name": "displaylib_tests"
+    }
+  ]
+}
diff --git a/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt b/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt
new file mode 100644
index 0000000..1ae3483
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/DisplayLibComponent.kt
@@ -0,0 +1,72 @@
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
+package com.android.app.displaylib
+
+import android.hardware.display.DisplayManager
+import android.os.Handler
+import dagger.Binds
+import dagger.BindsInstance
+import dagger.Component
+import dagger.Module
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+
+/**
+ * Component that creates all classes in displaylib.
+ *
+ * Each user of this library will bind the required element in the factory constructor. It's advised
+ * to use this component through [createDisplayLibComponent], which wraps the dagger generated
+ * method.
+ */
+@Component(modules = [DisplayLibModule::class])
+@Singleton
+interface DisplayLibComponent {
+
+    @Component.Factory
+    interface Factory {
+        fun create(
+            @BindsInstance displayManager: DisplayManager,
+            @BindsInstance bgHandler: Handler,
+            @BindsInstance bgApplicationScope: CoroutineScope,
+            @BindsInstance backgroundCoroutineDispatcher: CoroutineDispatcher,
+        ): DisplayLibComponent
+    }
+
+    val displayRepository: DisplayRepository
+}
+
+@Module
+interface DisplayLibModule {
+    @Binds fun bindDisplayManagerImpl(impl: DisplayRepositoryImpl): DisplayRepository
+}
+
+/**
+ * Just a wrapper to make the generated code to create the component more explicit.
+ *
+ * This should be called only once per process. Note that [bgHandler], [bgApplicationScope] and
+ * [backgroundCoroutineDispatcher] are expected to be backed by background threads. In the future
+ * this might throw an exception if they are tied to the main thread!
+ */
+fun createDisplayLibComponent(
+    displayManager: DisplayManager,
+    bgHandler: Handler,
+    bgApplicationScope: CoroutineScope,
+    backgroundCoroutineDispatcher: CoroutineDispatcher,
+): DisplayLibComponent {
+    return DaggerDisplayLibComponent.factory()
+        .create(displayManager, bgHandler, bgApplicationScope, backgroundCoroutineDispatcher)
+}
diff --git a/displaylib/src/com/android/app/displaylib/DisplayRepository.kt b/displaylib/src/com/android/app/displaylib/DisplayRepository.kt
new file mode 100644
index 0000000..820c518
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/DisplayRepository.kt
@@ -0,0 +1,468 @@
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
+package com.android.app.displaylib
+
+import android.hardware.display.DisplayManager
+import android.hardware.display.DisplayManager.DISPLAY_CATEGORY_ALL_INCLUDING_DISABLED
+import android.hardware.display.DisplayManager.DisplayListener
+import android.hardware.display.DisplayManager.EVENT_TYPE_DISPLAY_ADDED
+import android.hardware.display.DisplayManager.EVENT_TYPE_DISPLAY_CHANGED
+import android.hardware.display.DisplayManager.EVENT_TYPE_DISPLAY_REMOVED
+import android.os.Handler
+import android.util.Log
+import android.view.Display
+import com.android.app.tracing.FlowTracing.traceEach
+import com.android.app.tracing.traceSection
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asFlow
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.conflate
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.filterIsInstance
+import kotlinx.coroutines.flow.flatMapLatest
+import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.onStart
+import kotlinx.coroutines.flow.scan
+import kotlinx.coroutines.flow.stateIn
+
+/** Repository for providing access to display related information and events. */
+interface DisplayRepository {
+    /** Provides the current set of displays. */
+    val displays: StateFlow<Set<Display>>
+
+    /** Display change event indicating a change to the given displayId has occurred. */
+    val displayChangeEvent: Flow<Int>
+
+    /** Display addition event indicating a new display has been added. */
+    val displayAdditionEvent: Flow<Display?>
+
+    /** Display removal event indicating a display has been removed. */
+    val displayRemovalEvent: Flow<Int>
+
+    /**
+     * Provides the current set of display ids.
+     *
+     * Note that it is preferred to use this instead of [displays] if only the
+     * [Display.getDisplayId] is needed.
+     */
+    val displayIds: StateFlow<Set<Int>>
+
+    /**
+     * Pending display id that can be enabled/disabled.
+     *
+     * When `null`, it means there is no pending display waiting to be enabled.
+     */
+    val pendingDisplay: Flow<PendingDisplay?>
+
+    /** Whether the default display is currently off. */
+    val defaultDisplayOff: Flow<Boolean>
+
+    /**
+     * Given a display ID int, return the corresponding Display object, or null if none exist.
+     *
+     * This method is guaranteed to not result in any binder call.
+     */
+    fun getDisplay(displayId: Int): Display? =
+        displays.value.firstOrNull { it.displayId == displayId }
+
+    /** Represents a connected display that has not been enabled yet. */
+    interface PendingDisplay {
+        /** Id of the pending display. */
+        val id: Int
+
+        /** Enables the display, making it available to the system. */
+        suspend fun enable()
+
+        /**
+         * Ignores the pending display. When called, this specific display id doesn't appear as
+         * pending anymore until the display is disconnected and reconnected again.
+         */
+        suspend fun ignore()
+
+        /** Disables the display, making it unavailable to the system. */
+        suspend fun disable()
+    }
+}
+
+@Singleton
+class DisplayRepositoryImpl
+@Inject
+constructor(
+    private val displayManager: DisplayManager,
+    backgroundHandler: Handler,
+    bgApplicationScope: CoroutineScope,
+    backgroundCoroutineDispatcher: CoroutineDispatcher,
+) : DisplayRepository {
+    private val allDisplayEvents: Flow<DisplayEvent> =
+        callbackFlow {
+                val callback =
+                    object : DisplayListener {
+                        override fun onDisplayAdded(displayId: Int) {
+                            trySend(DisplayEvent.Added(displayId))
+                        }
+
+                        override fun onDisplayRemoved(displayId: Int) {
+                            trySend(DisplayEvent.Removed(displayId))
+                        }
+
+                        override fun onDisplayChanged(displayId: Int) {
+                            trySend(DisplayEvent.Changed(displayId))
+                        }
+                    }
+                displayManager.registerDisplayListener(
+                    callback,
+                    backgroundHandler,
+                    EVENT_TYPE_DISPLAY_ADDED or
+                        EVENT_TYPE_DISPLAY_CHANGED or
+                        EVENT_TYPE_DISPLAY_REMOVED,
+                )
+                awaitClose { displayManager.unregisterDisplayListener(callback) }
+            }
+            .conflate()
+            .onStart { emit(DisplayEvent.Changed(Display.DEFAULT_DISPLAY)) }
+            .debugLog("allDisplayEvents")
+            .flowOn(backgroundCoroutineDispatcher)
+
+    override val displayChangeEvent: Flow<Int> =
+        allDisplayEvents.filterIsInstance<DisplayEvent.Changed>().map { event -> event.displayId }
+
+    override val displayRemovalEvent: Flow<Int> =
+        allDisplayEvents.filterIsInstance<DisplayEvent.Removed>().map { it.displayId }
+
+    // This is necessary because there might be multiple displays, and we could
+    // have missed events for those added before this process or flow started.
+    // Note it causes a binder call from the main thread (it's traced).
+    private val initialDisplays: Set<Display> =
+        traceSection("$TAG#initialDisplays") { displayManager.displays?.toSet() ?: emptySet() }
+    private val initialDisplayIds = initialDisplays.map { display -> display.displayId }.toSet()
+
+    /** Propagate to the listeners only enabled displays */
+    private val enabledDisplayIds: StateFlow<Set<Int>> =
+        allDisplayEvents
+            .scan(initial = initialDisplayIds) { previousIds: Set<Int>, event: DisplayEvent ->
+                val id = event.displayId
+                when (event) {
+                    is DisplayEvent.Removed -> previousIds - id
+                    is DisplayEvent.Added,
+                    is DisplayEvent.Changed -> previousIds + id
+                }
+            }
+            .distinctUntilChanged()
+            .debugLog("enabledDisplayIds")
+            .stateIn(bgApplicationScope, SharingStarted.WhileSubscribed(), initialDisplayIds)
+
+    private val defaultDisplay by lazy {
+        getDisplayFromDisplayManager(Display.DEFAULT_DISPLAY)
+            ?: error("Unable to get default display.")
+    }
+    /**
+     * Represents displays that went though the [DisplayListener.onDisplayAdded] callback.
+     *
+     * Those are commonly the ones provided by [DisplayManager.getDisplays] by default.
+     */
+    private val enabledDisplays: StateFlow<Set<Display>> =
+        enabledDisplayIds
+            .mapElementsLazily { displayId -> getDisplayFromDisplayManager(displayId) }
+            .onEach {
+                if (it.isEmpty()) Log.wtf(TAG, "No enabled displays. This should never happen.")
+            }
+            .flowOn(backgroundCoroutineDispatcher)
+            .debugLog("enabledDisplays")
+            .stateIn(
+                bgApplicationScope,
+                started = SharingStarted.WhileSubscribed(),
+                // This triggers a single binder call on the UI thread per process. The
+                // alternative would be to use sharedFlows, but they are prohibited due to
+                // performance concerns.
+                // Ultimately, this is a trade-off between a one-time UI thread binder call and
+                // the constant overhead of sharedFlows.
+                initialValue = initialDisplays,
+            )
+
+    /**
+     * Represents displays that went though the [DisplayListener.onDisplayAdded] callback.
+     *
+     * Those are commonly the ones provided by [DisplayManager.getDisplays] by default.
+     */
+    override val displays: StateFlow<Set<Display>> = enabledDisplays
+
+    override val displayIds: StateFlow<Set<Int>> = enabledDisplayIds
+
+    /**
+     * Implementation that maps from [displays], instead of [allDisplayEvents] for 2 reasons:
+     * 1. Guarantee that it emits __after__ [displays] emitted. This way it is guaranteed that
+     *    calling [getDisplay] for the newly added display will be non-null.
+     * 2. Reuse the existing instance of [Display] without a new call to [DisplayManager].
+     */
+    override val displayAdditionEvent: Flow<Display?> =
+        displays
+            .pairwiseBy { previousDisplays, currentDisplays -> currentDisplays - previousDisplays }
+            .flatMapLatest { it.asFlow() }
+
+    val _ignoredDisplayIds = MutableStateFlow<Set<Int>>(emptySet())
+    private val ignoredDisplayIds: Flow<Set<Int>> = _ignoredDisplayIds.debugLog("ignoredDisplayIds")
+
+    private fun getInitialConnectedDisplays(): Set<Int> =
+        traceSection("$TAG#getInitialConnectedDisplays") {
+            displayManager
+                .getDisplays(DISPLAY_CATEGORY_ALL_INCLUDING_DISABLED)
+                .map { it.displayId }
+                .toSet()
+                .also {
+                    if (DEBUG) {
+                        Log.d(TAG, "getInitialConnectedDisplays: $it")
+                    }
+                }
+        }
+
+    /* keeps connected displays until they are disconnected. */
+    private val connectedDisplayIds: StateFlow<Set<Int>> =
+        callbackFlow {
+                val connectedIds = getInitialConnectedDisplays().toMutableSet()
+                val callback =
+                    object : DisplayConnectionListener {
+                        override fun onDisplayConnected(id: Int) {
+                            if (DEBUG) {
+                                Log.d(TAG, "display with id=$id connected.")
+                            }
+                            connectedIds += id
+                            _ignoredDisplayIds.value -= id
+                            trySend(connectedIds.toSet())
+                        }
+
+                        override fun onDisplayDisconnected(id: Int) {
+                            connectedIds -= id
+                            if (DEBUG) {
+                                Log.d(TAG, "display with id=$id disconnected.")
+                            }
+                            _ignoredDisplayIds.value -= id
+                            trySend(connectedIds.toSet())
+                        }
+                    }
+                trySend(connectedIds.toSet())
+                displayManager.registerDisplayListener(
+                    callback,
+                    backgroundHandler,
+                    /* eventFlags */ 0,
+                    DisplayManager.PRIVATE_EVENT_TYPE_DISPLAY_CONNECTION_CHANGED,
+                )
+                awaitClose { displayManager.unregisterDisplayListener(callback) }
+            }
+            .conflate()
+            .distinctUntilChanged()
+            .debugLog("connectedDisplayIds")
+            .stateIn(
+                bgApplicationScope,
+                started = SharingStarted.WhileSubscribed(),
+                // The initial value is set to empty, but connected displays are gathered as soon as
+                // the flow starts being collected. This is to ensure the call to get displays (an
+                // IPC) happens in the background instead of when this object
+                // is instantiated.
+                initialValue = emptySet(),
+            )
+
+    private val connectedExternalDisplayIds: Flow<Set<Int>> =
+        connectedDisplayIds
+            .map { connectedDisplayIds ->
+                traceSection("$TAG#filteringExternalDisplays") {
+                    connectedDisplayIds
+                        .filter { id -> getDisplayType(id) == Display.TYPE_EXTERNAL }
+                        .toSet()
+                }
+            }
+            .flowOn(backgroundCoroutineDispatcher)
+            .debugLog("connectedExternalDisplayIds")
+
+    private fun getDisplayType(displayId: Int): Int? =
+        traceSection("$TAG#getDisplayType") { displayManager.getDisplay(displayId)?.type }
+
+    private fun getDisplayFromDisplayManager(displayId: Int): Display? =
+        traceSection("$TAG#getDisplay") { displayManager.getDisplay(displayId) }
+
+    /**
+     * Pending displays are the ones connected, but not enabled and not ignored.
+     *
+     * A connected display is ignored after the user makes the decision to use it or not. For now,
+     * the initial decision from the user is final and not reversible.
+     */
+    private val pendingDisplayIds: Flow<Set<Int>> =
+        combine(enabledDisplayIds, connectedExternalDisplayIds, ignoredDisplayIds) {
+                enabledDisplaysIds,
+                connectedExternalDisplayIds,
+                ignoredDisplayIds ->
+                if (DEBUG) {
+                    Log.d(
+                        TAG,
+                        "combining enabled=$enabledDisplaysIds, " +
+                            "connectedExternalDisplayIds=$connectedExternalDisplayIds, " +
+                            "ignored=$ignoredDisplayIds",
+                    )
+                }
+                connectedExternalDisplayIds - enabledDisplaysIds - ignoredDisplayIds
+            }
+            .debugLog("allPendingDisplayIds")
+
+    /** Which display id should be enabled among the pending ones. */
+    private val pendingDisplayId: Flow<Int?> =
+        pendingDisplayIds.map { it.maxOrNull() }.distinctUntilChanged().debugLog("pendingDisplayId")
+
+    override val pendingDisplay: Flow<DisplayRepository.PendingDisplay?> =
+        pendingDisplayId
+            .map { displayId ->
+                val id = displayId ?: return@map null
+                object : DisplayRepository.PendingDisplay {
+                    override val id = id
+
+                    override suspend fun enable() {
+                        traceSection("DisplayRepository#enable($id)") {
+                            if (DEBUG) {
+                                Log.d(TAG, "Enabling display with id=$id")
+                            }
+                            displayManager.enableConnectedDisplay(id)
+                        }
+                        // After the display has been enabled, it is automatically ignored.
+                        ignore()
+                    }
+
+                    override suspend fun ignore() {
+                        traceSection("DisplayRepository#ignore($id)") {
+                            _ignoredDisplayIds.value += id
+                        }
+                    }
+
+                    override suspend fun disable() {
+                        ignore()
+                        traceSection("DisplayRepository#disable($id)") {
+                            if (DEBUG) {
+                                Log.d(TAG, "Disabling display with id=$id")
+                            }
+                            displayManager.disableConnectedDisplay(id)
+                        }
+                    }
+                }
+            }
+            .debugLog("pendingDisplay")
+
+    override val defaultDisplayOff: Flow<Boolean> =
+        displayChangeEvent
+            .filter { it == Display.DEFAULT_DISPLAY }
+            .map { defaultDisplay.state == Display.STATE_OFF }
+            .distinctUntilChanged()
+
+    private fun <T> Flow<T>.debugLog(flowName: String): Flow<T> {
+        return if (DEBUG) {
+            traceEach(flowName, logcat = true, traceEmissionCount = true)
+        } else {
+            this
+        }
+    }
+
+    /**
+     * Maps a set of T to a set of V, minimizing the number of `createValue` calls taking into
+     * account the diff between each root flow emission.
+     *
+     * This is needed to minimize the number of [getDisplayFromDisplayManager] in this class. Note
+     * that if the [createValue] returns a null element, it will not be added in the output set.
+     */
+    private fun <T, V> Flow<Set<T>>.mapElementsLazily(createValue: (T) -> V?): Flow<Set<V>> {
+        data class State<T, V>(
+            val previousSet: Set<T>,
+            // Caches T values from the previousSet that were already converted to V
+            val valueMap: Map<T, V>,
+            val resultSet: Set<V>,
+        )
+
+        val emptyInitialState = State(emptySet<T>(), emptyMap(), emptySet<V>())
+        return this.scan(emptyInitialState) { state, currentSet ->
+                if (currentSet == state.previousSet) {
+                    state
+                } else {
+                    val removed = state.previousSet - currentSet
+                    val added = currentSet - state.previousSet
+                    val newMap = state.valueMap.toMutableMap()
+
+                    added.forEach { key -> createValue(key)?.let { newMap[key] = it } }
+                    removed.forEach { key -> newMap.remove(key) }
+
+                    val resultSet = newMap.values.toSet()
+                    State(currentSet, newMap, resultSet)
+                }
+            }
+            .filter { it != emptyInitialState }
+            .map { it.resultSet }
+    }
+
+    private companion object {
+        const val TAG = "DisplayRepository"
+        val DEBUG = Log.isLoggable(TAG, Log.DEBUG)
+    }
+}
+
+/** Used to provide default implementations for all methods. */
+private interface DisplayConnectionListener : DisplayListener {
+
+    override fun onDisplayConnected(id: Int) {}
+
+    override fun onDisplayDisconnected(id: Int) {}
+
+    override fun onDisplayAdded(id: Int) {}
+
+    override fun onDisplayRemoved(id: Int) {}
+
+    override fun onDisplayChanged(id: Int) {}
+}
+
+private sealed interface DisplayEvent {
+    val displayId: Int
+
+    data class Added(override val displayId: Int) : DisplayEvent
+
+    data class Removed(override val displayId: Int) : DisplayEvent
+
+    data class Changed(override val displayId: Int) : DisplayEvent
+}
+
+/**
+ * Returns a new [Flow] that combines the two most recent emissions from [this] using [transform].
+ * Note that the new Flow will not start emitting until it has received two emissions from the
+ * upstream Flow.
+ *
+ * Useful for code that needs to compare the current value to the previous value.
+ */
+// TODO b/401305290 - This should be moved to a shared lib, as it's also used by SystemUI.
+fun <T, R> Flow<T>.pairwiseBy(transform: suspend (old: T, new: T) -> R): Flow<R> = flow {
+    val noVal = Any()
+    var previousValue: Any? = noVal
+    collect { newVal ->
+        if (previousValue != noVal) {
+            @Suppress("UNCHECKED_CAST") emit(transform(previousValue as T, newVal))
+        }
+        previousValue = newVal
+    }
+}
diff --git a/displaylib/src/com/android/app/displaylib/InstanceLifecycleManager.kt b/displaylib/src/com/android/app/displaylib/InstanceLifecycleManager.kt
new file mode 100644
index 0000000..c80315b
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/InstanceLifecycleManager.kt
@@ -0,0 +1,37 @@
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
+package com.android.app.displaylib
+
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+
+/**
+ * Reports the display ids that should have a per-display instance, if any.
+ *
+ * This can be overridden to support different policies (e.g. display being connected, display
+ * having decorations, etc..). A [PerDisplayRepository] instance is expected to be cleaned up when a
+ * displayId is removed from this set.
+ */
+interface DisplayInstanceLifecycleManager {
+    /** Set of display ids that are allowed to have an instance. */
+    val displayIds: StateFlow<Set<Int>>
+}
+
+/** Meant to be used in tests. */
+class FakeDisplayInstanceLifecycleManager : DisplayInstanceLifecycleManager {
+    override val displayIds = MutableStateFlow<Set<Int>>(emptySet())
+}
diff --git a/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt b/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt
new file mode 100644
index 0000000..13bd44a
--- /dev/null
+++ b/displaylib/src/com/android/app/displaylib/PerDisplayRepository.kt
@@ -0,0 +1,268 @@
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
+package com.android.app.displaylib
+
+import android.util.Log
+import android.view.Display
+import com.android.app.tracing.coroutines.flow.stateInTraced
+import com.android.app.tracing.coroutines.launchTraced as launch
+import com.android.app.tracing.traceSection
+import dagger.assisted.Assisted
+import dagger.assisted.AssistedFactory
+import dagger.assisted.AssistedInject
+import java.util.concurrent.ConcurrentHashMap
+import javax.inject.Qualifier
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.combine
+
+/**
+ * Used to create instances of type `T` for a specific display.
+ *
+ * This is useful for resources or objects that need to be managed independently for each connected
+ * display (e.g., UI state, rendering contexts, or display-specific configurations).
+ *
+ * Note that in most cases this can be implemented by a simple `@AssistedFactory` with `displayId`
+ * parameter
+ *
+ * ```kotlin
+ * class SomeType @AssistedInject constructor(@Assisted displayId: Int,..)
+ *      @AssistedFactory
+ *      interface Factory {
+ *         fun create(displayId: Int): SomeType
+ *      }
+ *  }
+ * ```
+ *
+ * Then it can be used to create a [PerDisplayRepository] as follows:
+ * ```kotlin
+ * // Injected:
+ * val repositoryFactory: PerDisplayRepositoryImpl.Factory
+ * val instanceFactory: PerDisplayRepositoryImpl.Factory
+ * // repository creation:
+ * repositoryFactory.create(instanceFactory::create)
+ * ```
+ *
+ * @see PerDisplayRepository For how to retrieve and manage instances created by this factory.
+ */
+fun interface PerDisplayInstanceProvider<T> {
+    /** Creates an instance for a display. */
+    fun createInstance(displayId: Int): T?
+}
+
+/**
+ * Extends [PerDisplayInstanceProvider], adding support for destroying the instance.
+ *
+ * This is useful for releasing resources associated with a display when it is disconnected or when
+ * the per-display instance is no longer needed.
+ */
+interface PerDisplayInstanceProviderWithTeardown<T> : PerDisplayInstanceProvider<T> {
+    /** Destroys a previously created instance of `T` forever. */
+    fun destroyInstance(instance: T)
+}
+
+/**
+ * Provides access to per-display instances of type `T`.
+ *
+ * Acts as a repository, managing the caching and retrieval of instances created by a
+ * [PerDisplayInstanceProvider]. It ensures that only one instance of `T` exists per display ID.
+ */
+interface PerDisplayRepository<T> {
+    /** Gets the cached instance or create a new one for a given display. */
+    operator fun get(displayId: Int): T?
+
+    /** Debug name for this repository, mainly for tracing and logging. */
+    val debugName: String
+
+    /**
+     * Callback to run when a given repository is initialized.
+     *
+     * This allows the caller to perform custom logic when the repository is ready to be used, e.g.
+     * register to dumpManager.
+     *
+     * Note that the instance is *leaked* outside of this class, so it should only be done when
+     * repository is meant to live as long as the caller. In systemUI this is ok because the
+     * repository lives as long as the process itself.
+     */
+    fun interface InitCallback {
+        fun onInit(debugName: String, instance: Any)
+    }
+}
+
+/** Qualifier for [CoroutineScope] used for displaylib background tasks. */
+@Qualifier @Retention(AnnotationRetention.RUNTIME) annotation class DisplayLibBackground
+
+/**
+ * Default implementation of [PerDisplayRepository].
+ *
+ * This class manages a cache of per-display instances of type `T`, creating them using a provided
+ * [PerDisplayInstanceProvider] and optionally tearing them down using a
+ * [PerDisplayInstanceProviderWithTeardown] when based on [lifecycleManager].
+ *
+ * An instance will be destroyed when either
+ * - The display is not connected anymore
+ * - or based on [lifecycleManager]. If no lifecycle manager is provided, instances are destroyed
+ *   when the display is disconnected.
+ *
+ * [DisplayInstanceLifecycleManager] can decide to delete instances for a display even before it is
+ * disconnected. An example of usecase for it, is to delete instances when screen decorations are
+ * removed.
+ *
+ * Note that this is a [PerDisplayStoreImpl] 2.0 that doesn't require [CoreStartable] bindings,
+ * providing all args in the constructor.
+ */
+class PerDisplayInstanceRepositoryImpl<T>
+@AssistedInject
+constructor(
+    @Assisted override val debugName: String,
+    @Assisted private val instanceProvider: PerDisplayInstanceProvider<T>,
+    @Assisted lifecycleManager: DisplayInstanceLifecycleManager? = null,
+    @DisplayLibBackground bgApplicationScope: CoroutineScope,
+    private val displayRepository: DisplayRepository,
+    private val initCallback: PerDisplayRepository.InitCallback,
+) : PerDisplayRepository<T> {
+
+    private val perDisplayInstances = ConcurrentHashMap<Int, T?>()
+
+    private val allowedDisplays: StateFlow<Set<Int>> =
+        if (lifecycleManager == null) {
+                displayRepository.displayIds
+            } else {
+                // If there is a lifecycle manager, we still consider the smallest subset between
+                // the ones connected and the ones from the lifecycle. This is to safeguard against
+                // leaks, in case of lifecycle manager misbehaving (as it's provided by clients, and
+                // we can't guarantee it's correct).
+                combine(lifecycleManager.displayIds, displayRepository.displayIds) {
+                    lifecycleAllowedDisplayIds,
+                    connectedDisplays ->
+                    lifecycleAllowedDisplayIds.intersect(connectedDisplays)
+                }
+            }
+            .stateInTraced(
+                "allowed displays for $debugName",
+                bgApplicationScope,
+                SharingStarted.WhileSubscribed(),
+                setOf(Display.DEFAULT_DISPLAY),
+            )
+
+    init {
+        bgApplicationScope.launch("$debugName#start") { start() }
+    }
+
+    private suspend fun start() {
+        initCallback.onInit(debugName, this)
+        allowedDisplays.collectLatest { displayIds ->
+            val toRemove = perDisplayInstances.keys - displayIds
+            toRemove.forEach { displayId ->
+                Log.d(TAG, "<$debugName> destroying instance for displayId=$displayId.")
+                perDisplayInstances.remove(displayId)?.let { instance ->
+                    (instanceProvider as? PerDisplayInstanceProviderWithTeardown)?.destroyInstance(
+                        instance
+                    )
+                }
+            }
+        }
+    }
+
+    override fun get(displayId: Int): T? {
+        if (displayRepository.getDisplay(displayId) == null) {
+            Log.e(TAG, "<$debugName: Display with id $displayId doesn't exist.")
+            return null
+        }
+
+        if (displayId !in allowedDisplays.value) {
+            Log.e(
+                TAG,
+                "<$debugName: Display with id $displayId exists but it's not " +
+                    "allowed by lifecycle manager.",
+            )
+            return null
+        }
+
+        // If it doesn't exist, create it and put it in the map.
+        return perDisplayInstances.computeIfAbsent(displayId) { key ->
+            Log.d(TAG, "<$debugName> creating instance for displayId=$key, as it wasn't available.")
+            val instance =
+                traceSection({ "creating instance of $debugName for displayId=$key" }) {
+                    instanceProvider.createInstance(key)
+                }
+            if (instance == null) {
+                Log.e(
+                    TAG,
+                    "<$debugName> returning null because createInstance($key) returned null.",
+                )
+            }
+            instance
+        }
+    }
+
+    @AssistedFactory
+    interface Factory<T> {
+        fun create(
+            debugName: String,
+            instanceProvider: PerDisplayInstanceProvider<T>,
+            overrideLifecycleManager: DisplayInstanceLifecycleManager? = null,
+        ): PerDisplayInstanceRepositoryImpl<T>
+    }
+
+    companion object {
+        private const val TAG = "PerDisplayInstanceRepo"
+    }
+
+    override fun toString(): String {
+        return "PerDisplayInstanceRepositoryImpl(" +
+            "debugName='$debugName', instances=$perDisplayInstances)"
+    }
+}
+
+/**
+ * Provides an instance of a given class **only** for the default display, even if asked for another
+ * display.
+ *
+ * This is useful in case of **flag refactors**: it can be provided instead of an instance of
+ * [PerDisplayInstanceRepositoryImpl] when a flag related to multi display refactoring is off.
+ *
+ * Note that this still requires all instances to be provided by a [PerDisplayInstanceProvider]. If
+ * you want to provide an existing instance instead for the default display, either implement it in
+ * a custom [PerDisplayInstanceProvider] (e.g. inject it in the constructor and return it if the
+ * displayId is zero), or use [SingleInstanceRepositoryImpl].
+ */
+class DefaultDisplayOnlyInstanceRepositoryImpl<T>(
+    override val debugName: String,
+    private val instanceProvider: PerDisplayInstanceProvider<T>,
+) : PerDisplayRepository<T> {
+    private val lazyDefaultDisplayInstance by lazy {
+        instanceProvider.createInstance(Display.DEFAULT_DISPLAY)
+    }
+
+    override fun get(displayId: Int): T? = lazyDefaultDisplayInstance
+}
+
+/**
+ * Always returns [instance] for any display.
+ *
+ * This can be used to provide a single instance based on a flag value during a refactor. Similar to
+ * [DefaultDisplayOnlyInstanceRepositoryImpl], but also avoids creating the
+ * [PerDisplayInstanceProvider]. This is useful when you want to provide an existing instance only,
+ * without even instantiating a [PerDisplayInstanceProvider].
+ */
+class SingleInstanceRepositoryImpl<T>(override val debugName: String, private val instance: T) :
+    PerDisplayRepository<T> {
+    override fun get(displayId: Int): T? = instance
+}
diff --git a/displaylib/tests/Android.bp b/displaylib/tests/Android.bp
new file mode 100644
index 0000000..2c7d115
--- /dev/null
+++ b/displaylib/tests/Android.bp
@@ -0,0 +1,34 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+    name: "displaylib_tests",
+    manifest: "AndroidManifest.xml",
+    static_libs: [
+        "displaylib",
+        "androidx.test.ext.junit",
+        "androidx.test.rules",
+        "truth",
+        "//frameworks/libs/systemui:tracinglib-platform",
+    ],
+    srcs: [
+        "tests/src/**/*.kt",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+    test_suites: ["device-tests"],
+}
diff --git a/displaylib/tests/AndroidManifest.xml b/displaylib/tests/AndroidManifest.xml
new file mode 100644
index 0000000..b45a4ec
--- /dev/null
+++ b/displaylib/tests/AndroidManifest.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+     Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.app.displaylib">
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:label="Tests for DisplayLib"
+        android:targetPackage="com.android.app.displaylib" />
+</manifest>
diff --git a/tracinglib/demo/src/MainApplication.kt b/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
similarity index 60%
rename from tracinglib/demo/src/MainApplication.kt
rename to displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
index 0d98bbe..7e244d3 100644
--- a/tracinglib/demo/src/MainApplication.kt
+++ b/displaylib/tests/src/com/android/app/displaylib/DisplayRepositoryTest.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,10 +13,15 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.example.tracing.demo
+package com.android.app.displaylib
 
-import android.app.Application
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SmallTest
+import org.junit.runner.RunWith
 
-class MainApplication : Application() {
-    val appComponent: ApplicationComponent = DaggerApplicationComponent.create()
+@SmallTest
+@RunWith(AndroidJUnit4::class)
+class DisplayRepositoryTest {
+
+    // TODO b/401305290 - Move tests from The SystemUI DisplayRepositoryImpl to here.
 }
diff --git a/iconloaderlib/build.gradle.kts b/iconloaderlib/build.gradle.kts
index 2678433..15112bd 100644
--- a/iconloaderlib/build.gradle.kts
+++ b/iconloaderlib/build.gradle.kts
@@ -16,5 +16,5 @@ android {
 
 dependencies {
     implementation("androidx.core:core")
-    api(project(":NexusLauncher.Flags"))
+    api(project(":NexusLauncher:Flags"))
 }
diff --git a/iconloaderlib/res/values/config.xml b/iconloaderlib/res/values/config.xml
index 893f955..71a38f2 100644
--- a/iconloaderlib/res/values/config.xml
+++ b/iconloaderlib/res/values/config.xml
@@ -27,4 +27,7 @@
     <string name="calendar_component_name" translatable="false"></string>
     <string name="clock_component_name" translatable="false"></string>
 
+    <!-- Configures whether to enable forced theme icon, disabled by default -->
+    <bool name="enable_forced_themed_icon">false</bool>
+
 </resources>
\ No newline at end of file
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
index f3f9d1e..5f66114 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
@@ -1,5 +1,6 @@
 package com.android.launcher3.icons;
 
+import static android.graphics.Color.BLACK;
 import static android.graphics.Paint.ANTI_ALIAS_FLAG;
 import static android.graphics.Paint.DITHER_FLAG;
 import static android.graphics.Paint.FILTER_BITMAP_FLAG;
@@ -7,6 +8,7 @@ import static android.graphics.drawable.AdaptiveIconDrawable.getExtraInsetFracti
 
 import static com.android.launcher3.icons.BitmapInfo.FLAG_INSTANT;
 import static com.android.launcher3.icons.ShadowGenerator.BLUR_FACTOR;
+import static com.android.launcher3.icons.ShadowGenerator.ICON_SCALE_FOR_SHADOWS;
 
 import static java.lang.annotation.RetentionPolicy.SOURCE;
 
@@ -21,8 +23,8 @@ import android.graphics.Canvas;
 import android.graphics.Color;
 import android.graphics.Paint;
 import android.graphics.PaintFlagsDrawFilter;
+import android.graphics.Path;
 import android.graphics.Rect;
-import android.graphics.RectF;
 import android.graphics.drawable.AdaptiveIconDrawable;
 import android.graphics.drawable.BitmapDrawable;
 import android.graphics.drawable.ColorDrawable;
@@ -38,6 +40,7 @@ import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.launcher3.Flags;
 import com.android.launcher3.icons.BitmapInfo.Extender;
 import com.android.launcher3.util.FlagOp;
 import com.android.launcher3.util.UserIconInfo;
@@ -81,47 +84,41 @@ public class BaseIconFactory implements AutoCloseable {
     @NonNull
     private final PackageManager mPm;
 
-    @NonNull
-    private final ColorExtractor mColorExtractor;
-
     protected final int mFullResIconDpi;
     protected final int mIconBitmapSize;
 
     protected IconThemeController mThemeController;
 
-    @Nullable
-    private IconNormalizer mNormalizer;
-
     @Nullable
     private ShadowGenerator mShadowGenerator;
 
-    private final boolean mShapeDetection;
-
     // Shadow bitmap used as background for theme icons
     private Bitmap mWhiteShadowLayer;
 
-    private Drawable mWrapperIcon;
     private int mWrapperBackgroundColor = DEFAULT_WRAPPER_BACKGROUND;
 
     private static int PLACEHOLDER_BACKGROUND_COLOR = Color.rgb(245, 245, 245);
 
+    private final boolean mShouldForceThemeIcon;
+
     protected BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize,
-            boolean shapeDetection) {
+            boolean unused) {
+        this(context, fullResIconDpi, iconBitmapSize);
+    }
+
+    public BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize) {
         mContext = context.getApplicationContext();
-        mShapeDetection = shapeDetection;
         mFullResIconDpi = fullResIconDpi;
         mIconBitmapSize = iconBitmapSize;
 
         mPm = mContext.getPackageManager();
-        mColorExtractor = new ColorExtractor();
 
         mCanvas = new Canvas();
         mCanvas.setDrawFilter(new PaintFlagsDrawFilter(DITHER_FLAG, FILTER_BITMAP_FLAG));
         clear();
-    }
 
-    public BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize) {
-        this(context, fullResIconDpi, iconBitmapSize, false);
+        mShouldForceThemeIcon = mContext.getResources().getBoolean(
+                R.bool.enable_forced_themed_icon);
     }
 
     protected void clear() {
@@ -136,14 +133,6 @@ public class BaseIconFactory implements AutoCloseable {
         return mShadowGenerator;
     }
 
-    @NonNull
-    public IconNormalizer getNormalizer() {
-        if (mNormalizer == null) {
-            mNormalizer = new IconNormalizer(mContext, mIconBitmapSize, mShapeDetection);
-        }
-        return mNormalizer;
-    }
-
     @Nullable
     public IconThemeController getThemeController() {
         return mThemeController;
@@ -191,7 +180,7 @@ public class BaseIconFactory implements AutoCloseable {
             icon = createIconBitmap(new BitmapDrawable(mContext.getResources(), icon), 1f);
         }
 
-        return BitmapInfo.of(icon, mColorExtractor.findDominantColorByHue(icon));
+        return BitmapInfo.of(icon, ColorExtractor.findDominantColorByHue(icon));
     }
 
     /**
@@ -232,18 +221,25 @@ public class BaseIconFactory implements AutoCloseable {
             // Need to convert to Adaptive Icon with insets to avoid cropping.
             tempIcon = createShapedAdaptiveIcon(bitmapDrawable.getBitmap());
         }
-        AdaptiveIconDrawable adaptiveIcon = normalizeAndWrapToAdaptiveIcon(tempIcon, null, scale);
+        AdaptiveIconDrawable adaptiveIcon = normalizeAndWrapToAdaptiveIcon(tempIcon, scale);
         Bitmap bitmap = createIconBitmap(adaptiveIcon, scale[0],
                 options == null ? MODE_WITH_SHADOW : options.mGenerationMode);
 
         int color = (options != null && options.mExtractedColor != null)
-                ? options.mExtractedColor : mColorExtractor.findDominantColorByHue(bitmap);
+                ? options.mExtractedColor : ColorExtractor.findDominantColorByHue(bitmap);
         BitmapInfo info = BitmapInfo.of(bitmap, color);
 
-        if (adaptiveIcon instanceof BitmapInfo.Extender extender) {
+        if (adaptiveIcon instanceof Extender extender) {
             info = extender.getExtendedInfo(bitmap, color, this, scale[0]);
         } else if (IconProvider.ATLEAST_T && mThemeController != null && adaptiveIcon != null) {
-            info.setThemedBitmap(mThemeController.createThemedBitmap(adaptiveIcon, info, this));
+            info.setThemedBitmap(
+                    mThemeController.createThemedBitmap(
+                        adaptiveIcon,
+                        info,
+                        this,
+                        options == null ? null : options.mSourceHint
+                    )
+            );
         }
         info = info.withFlags(getBitmapFlagOp(options));
         return info;
@@ -268,6 +264,13 @@ public class BaseIconFactory implements AutoCloseable {
         return op;
     }
 
+    /**
+     * @return True if forced theme icon is enabled
+     */
+    public boolean shouldForceThemeIcon() {
+        return mShouldForceThemeIcon;
+    }
+
     @NonNull
     protected UserIconInfo getUserInfo(@NonNull UserHandle user) {
         int key = user.hashCode();
@@ -286,6 +289,15 @@ public class BaseIconFactory implements AutoCloseable {
         return info;
     }
 
+    @NonNull
+    public Path getShapePath(AdaptiveIconDrawable drawable, Rect iconBounds) {
+        return drawable.getIconMask();
+    }
+
+    public float getIconScale() {
+        return 1f;
+    }
+
     @NonNull
     public Bitmap getWhiteShadowLayer() {
         if (mWhiteShadowLayer == null) {
@@ -298,11 +310,9 @@ public class BaseIconFactory implements AutoCloseable {
 
     @NonNull
     public Bitmap createScaledBitmap(@NonNull Drawable icon, @BitmapGenerationMode int mode) {
-        RectF iconBounds = new RectF();
         float[] scale = new float[1];
-        icon = normalizeAndWrapToAdaptiveIcon(icon, iconBounds, scale);
-        return createIconBitmap(icon,
-                Math.min(scale[0], ShadowGenerator.getScaleForBounds(iconBounds)), mode);
+        icon = normalizeAndWrapToAdaptiveIcon(icon, scale);
+        return createIconBitmap(icon, Math.min(scale[0], ICON_SCALE_FOR_SHADOWS), mode);
     }
 
     /**
@@ -313,18 +323,14 @@ public class BaseIconFactory implements AutoCloseable {
     }
 
     @Nullable
-    protected AdaptiveIconDrawable normalizeAndWrapToAdaptiveIcon(@Nullable Drawable icon,
-            @Nullable final RectF outIconBounds, @NonNull final float[] outScale) {
+    protected AdaptiveIconDrawable normalizeAndWrapToAdaptiveIcon(
+            @Nullable Drawable icon, @NonNull final float[] outScale) {
         if (icon == null) {
             return null;
         }
 
-        AdaptiveIconDrawable adaptiveIcon;
-        float scale;
-        adaptiveIcon = wrapToAdaptiveIcon(icon, outIconBounds);
-        scale = getNormalizer().getScale(adaptiveIcon, outIconBounds, null, null);
-        outScale[0] = scale;
-        return adaptiveIcon;
+        outScale[0] = IconNormalizer.ICON_VISIBLE_AREA_FACTOR;
+        return wrapToAdaptiveIcon(icon);
     }
 
     /**
@@ -348,8 +354,7 @@ public class BaseIconFactory implements AutoCloseable {
     /**
      * Wraps the provided icon in an adaptive icon drawable
      */
-    public AdaptiveIconDrawable wrapToAdaptiveIcon(@NonNull Drawable icon,
-            @Nullable final RectF outIconBounds) {
+    public AdaptiveIconDrawable wrapToAdaptiveIcon(@NonNull Drawable icon) {
         if (icon instanceof AdaptiveIconDrawable aid) {
             return aid;
         } else {
@@ -357,13 +362,8 @@ public class BaseIconFactory implements AutoCloseable {
             AdaptiveIconDrawable dr = new AdaptiveIconDrawable(
                     new ColorDrawable(mWrapperBackgroundColor), foreground);
             dr.setBounds(0, 0, 1, 1);
-            boolean[] outShape = new boolean[1];
-            float scale = getNormalizer().getScale(icon, outIconBounds, dr.getIconMask(), outShape);
-            if (!outShape[0]) {
-                foreground.setDrawable(createScaledDrawable(icon, scale * LEGACY_ICON_SCALE));
-            } else {
-                foreground.setDrawable(createScaledDrawable(icon, 1 - getExtraInsetFraction()));
-            }
+            float scale = new IconNormalizer(mIconBitmapSize).getScale(icon);
+            foreground.setDrawable(createScaledDrawable(icon, scale * LEGACY_ICON_SCALE));
             return dr;
         }
     }
@@ -401,31 +401,31 @@ public class BaseIconFactory implements AutoCloseable {
         return bitmap;
     }
 
-    private void drawIconBitmap(@NonNull Canvas canvas, @Nullable final Drawable icon,
+    private void drawIconBitmap(@NonNull Canvas canvas, @Nullable Drawable icon,
             final float scale, @BitmapGenerationMode int bitmapGenerationMode,
             @Nullable Bitmap targetBitmap) {
         final int size = mIconBitmapSize;
         mOldBounds.set(icon.getBounds());
-
-        if (icon instanceof AdaptiveIconDrawable) {
+        if (icon instanceof AdaptiveIconDrawable aid) {
             // We are ignoring KEY_SHADOW_DISTANCE because regular icons ignore this at the
             // moment b/298203449
             int offset = Math.max((int) Math.ceil(BLUR_FACTOR * size),
                     Math.round(size * (1 - scale) / 2));
             // b/211896569: AdaptiveIconDrawable do not work properly for non top-left bounds
-            icon.setBounds(0, 0, size - offset - offset, size - offset - offset);
+            int newBounds = size - offset * 2;
+            icon.setBounds(0, 0, newBounds, newBounds);
+            Path shapePath = getShapePath(aid, icon.getBounds());
             int count = canvas.save();
             canvas.translate(offset, offset);
             if (bitmapGenerationMode == MODE_WITH_SHADOW
                     || bitmapGenerationMode == MODE_HARDWARE_WITH_SHADOW) {
-                getShadowGenerator().addPathShadow(
-                        ((AdaptiveIconDrawable) icon).getIconMask(), canvas);
+                getShadowGenerator().addPathShadow(shapePath, canvas);
             }
 
-            if (icon instanceof BitmapInfo.Extender) {
+            if (icon instanceof Extender) {
                 ((Extender) icon).drawForPersistence(canvas);
             } else {
-                icon.draw(canvas);
+                drawAdaptiveIcon(canvas, aid, shapePath);
             }
             canvas.restoreToCount(count);
         } else {
@@ -473,6 +473,31 @@ public class BaseIconFactory implements AutoCloseable {
         icon.setBounds(mOldBounds);
     }
 
+    /**
+     * Draws AdaptiveIconDrawable onto canvas.
+     * @param canvas canvas to draw on
+     * @param drawable AdaptiveIconDrawable to draw
+     * @param overridePath path to clip icon with for shapes
+     */
+    protected void drawAdaptiveIcon(
+            @NonNull Canvas canvas,
+            @NonNull AdaptiveIconDrawable drawable,
+            @NonNull Path overridePath
+    ) {
+        if (!Flags.enableLauncherIconShapes()) {
+            drawable.draw(canvas);
+            return;
+        }
+        canvas.clipPath(overridePath);
+        canvas.drawColor(BLACK);
+        if (drawable.getBackground() != null) {
+            drawable.getBackground().draw(canvas);
+        }
+        if (drawable.getForeground() != null) {
+            drawable.getForeground().draw(canvas);
+        }
+    }
+
     @Override
     public void close() {
         clear();
@@ -508,6 +533,8 @@ public class BaseIconFactory implements AutoCloseable {
         @Nullable
         Integer mExtractedColor;
 
+        @Nullable
+        SourceHint mSourceHint;
 
         /**
          * User for this icon, in case of badging
@@ -562,6 +589,15 @@ public class BaseIconFactory implements AutoCloseable {
             mGenerationMode = generationMode;
             return this;
         }
+
+        /**
+         * User for this icon, in case of badging
+         */
+        @NonNull
+        public IconOptions setSourceHint(@Nullable SourceHint sourceHint) {
+            mSourceHint = sourceHint;
+            return this;
+        }
     }
 
     /**
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
index 480061a..62ca2ed 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
@@ -15,16 +15,20 @@
  */
 package com.android.launcher3.icons;
 
+import static com.android.launcher3.icons.cache.CacheLookupFlag.DEFAULT_LOOKUP_FLAG;
+
 import android.content.Context;
 import android.graphics.Bitmap;
 import android.graphics.Bitmap.Config;
 import android.graphics.Canvas;
+import android.graphics.Path;
 import android.graphics.drawable.Drawable;
 
 import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.launcher3.icons.cache.CacheLookupFlag;
 import com.android.launcher3.util.FlagOp;
 
 public class BitmapInfo {
@@ -56,6 +60,7 @@ public class BitmapInfo {
 
     public static final String TAG = "BitmapInfo";
 
+    @NonNull
     public final Bitmap icon;
     public final int color;
 
@@ -63,9 +68,13 @@ public class BitmapInfo {
     private ThemedBitmap mThemedBitmap;
 
     public @BitmapInfoFlags int flags;
+
+    // b/377618519: These are saved to debug why work badges sometimes don't show up on work apps
+    public @DrawableCreationFlags int creationFlags;
+
     private BitmapInfo badgeInfo;
 
-    public BitmapInfo(Bitmap icon, int color) {
+    public BitmapInfo(@NonNull Bitmap icon, int color) {
         this.icon = icon;
         this.color = color;
     }
@@ -120,6 +129,13 @@ public class BitmapInfo {
         return LOW_RES_ICON == icon;
     }
 
+    /**
+     * Returns the lookup flag to match this current state of this info
+     */
+    public CacheLookupFlag getMatchingLookupFlag() {
+        return DEFAULT_LOOKUP_FLAG.withUseLowRes(isLowRes());
+    }
+
     /**
      * BitmapInfo can be stored on disk or other persistent storage
      */
@@ -138,6 +154,19 @@ public class BitmapInfo {
      * Creates a drawable for the provided BitmapInfo
      */
     public FastBitmapDrawable newIcon(Context context, @DrawableCreationFlags int creationFlags) {
+        return newIcon(context, creationFlags, null);
+    }
+
+    /**
+     * Creates a drawable for the provided BitmapInfo
+     *
+     * @param context Context
+     * @param creationFlags Flags for creating the FastBitmapDrawable
+     * @param badgeShape Optional Path for masking icon badges to a shape. Should be 100x100.
+     * @return FastBitmapDrawable
+     */
+    public FastBitmapDrawable newIcon(Context context, @DrawableCreationFlags int creationFlags,
+            @Nullable Path badgeShape) {
         FastBitmapDrawable drawable;
         if (isLowRes()) {
             drawable = new PlaceHolderIconDrawable(this, context);
@@ -146,53 +175,68 @@ public class BitmapInfo {
         } else {
             drawable = new FastBitmapDrawable(this);
         }
-        applyFlags(context, drawable, creationFlags);
+        applyFlags(context, drawable, creationFlags, badgeShape);
         return drawable;
     }
 
     protected void applyFlags(Context context, FastBitmapDrawable drawable,
-            @DrawableCreationFlags int creationFlags) {
+            @DrawableCreationFlags int creationFlags, @Nullable Path badgeShape) {
+        this.creationFlags = creationFlags;
         drawable.mDisabledAlpha = GraphicsUtils.getFloat(context, R.attr.disabledIconAlpha, 1f);
         drawable.mCreationFlags = creationFlags;
         if ((creationFlags & FLAG_NO_BADGE) == 0) {
             Drawable badge = getBadgeDrawable(context, (creationFlags & FLAG_THEMED) != 0,
-                    (creationFlags & FLAG_SKIP_USER_BADGE) != 0);
+                    (creationFlags & FLAG_SKIP_USER_BADGE) != 0, badgeShape);
             if (badge != null) {
                 drawable.setBadge(badge);
             }
         }
     }
 
-    public Drawable getBadgeDrawable(Context context, boolean isThemed) {
-        return getBadgeDrawable(context, isThemed, false);
+    /**
+     * Gets Badge drawable based on current flags
+     * @param context Context
+     * @param isThemed If Drawable is themed.
+     * @param badgeShape Optional Path to mask badges to a shape. Should be 100x100.
+     * @return Drawable for the badge.
+     */
+    public Drawable getBadgeDrawable(Context context, boolean isThemed, @Nullable Path badgeShape) {
+        return getBadgeDrawable(context, isThemed, false, badgeShape);
     }
 
+
     /**
-     * Returns a drawable representing the badge for this info
+     * Creates a Drawable for an icon badge for this BitmapInfo
+     * @param context Context
+     * @param isThemed If the drawable is themed.
+     * @param skipUserBadge If should skip User Profile badging.
+     * @param badgeShape Optional Path to mask badge Drawable to a shape. Should be 100x100.
+     * @return Drawable for an icon Badge.
      */
     @Nullable
-    private Drawable getBadgeDrawable(Context context, boolean isThemed, boolean skipUserBadge) {
+    private Drawable getBadgeDrawable(Context context, boolean isThemed, boolean skipUserBadge,
+            @Nullable Path badgeShape) {
         if (badgeInfo != null) {
             int creationFlag = isThemed ? FLAG_THEMED : 0;
             if (skipUserBadge) {
                 creationFlag |= FLAG_SKIP_USER_BADGE;
             }
-            return badgeInfo.newIcon(context, creationFlag);
+            return badgeInfo.newIcon(context, creationFlag, badgeShape);
         }
         if (skipUserBadge) {
             return null;
         } else if ((flags & FLAG_INSTANT) != 0) {
             return new UserBadgeDrawable(context, R.drawable.ic_instant_app_badge,
-                    R.color.badge_tint_instant, isThemed);
+                    R.color.badge_tint_instant, isThemed, badgeShape);
         } else if ((flags & FLAG_WORK) != 0) {
             return new UserBadgeDrawable(context, R.drawable.ic_work_app_badge,
-                    R.color.badge_tint_work, isThemed);
+                    R.color.badge_tint_work, isThemed, badgeShape);
         } else if ((flags & FLAG_CLONE) != 0) {
             return new UserBadgeDrawable(context, R.drawable.ic_clone_app_badge,
-                    R.color.badge_tint_clone, isThemed);
+                    R.color.badge_tint_clone, isThemed, badgeShape);
         } else if ((flags & FLAG_PRIVATE) != 0) {
             return new UserBadgeDrawable(context, R.drawable.ic_private_profile_app_badge,
-                    R.color.badge_tint_private, isThemed);
+                    R.color.badge_tint_private, isThemed, badgeShape);
         }
         return null;
     }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BubbleIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/BubbleIconFactory.java
index 86ffa48..b36dc06 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BubbleIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BubbleIconFactory.java
@@ -77,9 +77,7 @@ public class BubbleIconFactory extends BaseIconFactory {
         if (outScale == null) {
             outScale = new float[1];
         }
-        icon = normalizeAndWrapToAdaptiveIcon(icon,
-                null /* outscale */,
-                outScale);
+        icon = normalizeAndWrapToAdaptiveIcon(icon, outScale);
         return createIconBitmap(icon, outScale[0], MODE_WITH_SHADOW);
     }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
index 664294e..1311904 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
@@ -29,6 +29,7 @@ import android.graphics.Canvas;
 import android.graphics.Color;
 import android.graphics.ColorFilter;
 import android.graphics.Paint;
+import android.graphics.Path;
 import android.graphics.Rect;
 import android.graphics.drawable.AdaptiveIconDrawable;
 import android.graphics.drawable.ColorDrawable;
@@ -283,7 +284,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         @Override
         @TargetApi(Build.VERSION_CODES.TIRAMISU)
         public FastBitmapDrawable newIcon(Context context,
-                @DrawableCreationFlags  int creationFlags) {
+                @DrawableCreationFlags  int creationFlags, Path badgeShape) {
             AnimationInfo info;
             Bitmap bg;
             int themedFgColor;
@@ -306,9 +307,9 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
                 return super.newIcon(context, creationFlags);
             }
             ClockIconDrawable.ClockConstantState cs = new ClockIconDrawable.ClockConstantState(
-                    icon, color, themedFgColor, boundsOffset, info, bg, bgFilter);
+                    this, themedFgColor, boundsOffset, info, bg, bgFilter);
             FastBitmapDrawable d = cs.newDrawable();
-            applyFlags(context, d, creationFlags);
+            applyFlags(context, d, creationFlags, null);
             return d;
         }
 
@@ -341,7 +342,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         private final float mCanvasScale;
 
         ClockIconDrawable(ClockConstantState cs) {
-            super(cs.mBitmap, cs.mIconColor);
+            super(cs.mBitmapInfo);
             mBoundsOffset = cs.mBoundsOffset;
             mAnimInfo = cs.mAnimInfo;
 
@@ -447,7 +448,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
 
         @Override
         public FastBitmapConstantState newConstantState() {
-            return new ClockConstantState(mBitmap, mIconColor, mThemedFgColor, mBoundsOffset,
+            return new ClockConstantState(mBitmapInfo, mThemedFgColor, mBoundsOffset,
                     mAnimInfo, mBG, mBgPaint.getColorFilter());
         }
 
@@ -459,9 +460,9 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
             private final ColorFilter mBgFilter;
             private final int mThemedFgColor;
 
-            ClockConstantState(Bitmap bitmap, int color, int themedFgColor,
+            ClockConstantState(BitmapInfo info, int themedFgColor,
                     float boundsOffset, AnimationInfo animInfo, Bitmap bg, ColorFilter bgFilter) {
-                super(bitmap, color);
+                super(info);
                 mBoundsOffset = boundsOffset;
                 mAnimInfo = animInfo;
                 mBG = bg;
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.java b/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.java
deleted file mode 100644
index 5a5e7d0..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.java
+++ /dev/null
@@ -1,138 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-package com.android.launcher3.icons;
-
-import android.graphics.Bitmap;
-import android.graphics.Color;
-import android.util.SparseArray;
-
-import androidx.annotation.NonNull;
-
-import java.util.Arrays;
-
-/**
- * Utility class for extracting colors from a bitmap.
- */
-public class ColorExtractor {
-
-    private final int NUM_SAMPLES = 20;
-
-    @NonNull
-    private final float[] mTmpHsv = new float[3];
-
-    @NonNull
-    private final float[] mTmpHueScoreHistogram = new float[360];
-
-    @NonNull
-    private final int[] mTmpPixels = new int[NUM_SAMPLES];
-
-    @NonNull
-    private final SparseArray<Float> mTmpRgbScores = new SparseArray<>();
-
-    /**
-     * This picks a dominant color, looking for high-saturation, high-value, repeated hues.
-     * @param bitmap The bitmap to scan
-     */
-    public int findDominantColorByHue(@NonNull final Bitmap bitmap) {
-        return findDominantColorByHue(bitmap, NUM_SAMPLES);
-    }
-
-    /**
-     * This picks a dominant color, looking for high-saturation, high-value, repeated hues.
-     * @param bitmap The bitmap to scan
-     */
-    protected int findDominantColorByHue(@NonNull final Bitmap bitmap, final int samples) {
-        final int height = bitmap.getHeight();
-        final int width = bitmap.getWidth();
-        int sampleStride = (int) Math.sqrt((height * width) / samples);
-        if (sampleStride < 1) {
-            sampleStride = 1;
-        }
-
-        // This is an out-param, for getting the hsv values for an rgb
-        float[] hsv = mTmpHsv;
-        Arrays.fill(hsv, 0);
-
-        // First get the best hue, by creating a histogram over 360 hue buckets,
-        // where each pixel contributes a score weighted by saturation, value, and alpha.
-        float[] hueScoreHistogram = mTmpHueScoreHistogram;
-        Arrays.fill(hueScoreHistogram, 0);
-        float highScore = -1;
-        int bestHue = -1;
-
-        int[] pixels = mTmpPixels;
-        Arrays.fill(pixels, 0);
-        int pixelCount = 0;
-
-        for (int y = 0; y < height; y += sampleStride) {
-            for (int x = 0; x < width; x += sampleStride) {
-                int argb = bitmap.getPixel(x, y);
-                int alpha = 0xFF & (argb >> 24);
-                if (alpha < 0x80) {
-                    // Drop mostly-transparent pixels.
-                    continue;
-                }
-                // Remove the alpha channel.
-                int rgb = argb | 0xFF000000;
-                Color.colorToHSV(rgb, hsv);
-                // Bucket colors by the 360 integer hues.
-                int hue = (int) hsv[0];
-                if (hue < 0 || hue >= hueScoreHistogram.length) {
-                    // Defensively avoid array bounds violations.
-                    continue;
-                }
-                if (pixelCount < samples) {
-                    pixels[pixelCount++] = rgb;
-                }
-                float score = hsv[1] * hsv[2];
-                hueScoreHistogram[hue] += score;
-                if (hueScoreHistogram[hue] > highScore) {
-                    highScore = hueScoreHistogram[hue];
-                    bestHue = hue;
-                }
-            }
-        }
-
-        SparseArray<Float> rgbScores = mTmpRgbScores;
-        rgbScores.clear();
-        int bestColor = 0xff000000;
-        highScore = -1;
-        // Go back over the RGB colors that match the winning hue,
-        // creating a histogram of weighted s*v scores, for up to 100*100 [s,v] buckets.
-        // The highest-scoring RGB color wins.
-        for (int i = 0; i < pixelCount; i++) {
-            int rgb = pixels[i];
-            Color.colorToHSV(rgb, hsv);
-            int hue = (int) hsv[0];
-            if (hue == bestHue) {
-                float s = hsv[1];
-                float v = hsv[2];
-                int bucket = (int) (s * 100) + (int) (v * 10000);
-                // Score by cumulative saturation * value.
-                float score = s * v;
-                Float oldTotal = rgbScores.get(bucket);
-                float newTotal = oldTotal == null ? score : oldTotal + score;
-                rgbScores.put(bucket, newTotal);
-                if (newTotal > highScore) {
-                    highScore = newTotal;
-                    // All the colors in the winning bucket are very similar. Last in wins.
-                    bestColor = rgb;
-                }
-            }
-        }
-        return bestColor;
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.kt b/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.kt
new file mode 100644
index 0000000..9fef2b0
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/ColorExtractor.kt
@@ -0,0 +1,107 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+package com.android.launcher3.icons
+
+import android.graphics.Bitmap
+import android.graphics.Color
+import android.util.SparseArray
+import kotlin.math.sqrt
+
+/** Utility class for extracting colors from a bitmap. */
+object ColorExtractor {
+    private const val NUM_SAMPLES = 20
+
+    /**
+     * This picks a dominant color, looking for high-saturation, high-value, repeated hues.
+     *
+     * @param bitmap The bitmap to scan
+     */
+    @JvmStatic
+    fun findDominantColorByHue(bitmap: Bitmap): Int {
+        val height = bitmap.height
+        val width = bitmap.width
+        val sampleStride = sqrt((height * width) / NUM_SAMPLES.toDouble()).toInt().coerceAtLeast(1)
+
+        // This is an out-param, for getting the hsv values for an rgb
+        val hsv = FloatArray(3)
+
+        // First get the best hue, by creating a histogram over 360 hue buckets,
+        // where each pixel contributes a score weighted by saturation, value, and alpha.
+        val hueScoreHistogram = FloatArray(360)
+        var highScore = -1f
+        var bestHue = -1
+
+        val pixels = IntArray(NUM_SAMPLES)
+        var pixelCount = 0
+
+        for (y in 0..<height step sampleStride) {
+            for (x in 0..<width step sampleStride) {
+                val argb = bitmap.getPixel(x, y)
+                val alpha = 0xFF and (argb shr 24)
+                if (alpha < 0x80) {
+                    // Drop mostly-transparent pixels.
+                    continue
+                }
+                // Remove the alpha channel.
+                val rgb = argb or -0x1000000
+                Color.colorToHSV(rgb, hsv)
+                // Bucket colors by the 360 integer hues.
+                val hue = hsv[0].toInt()
+                if (hue < 0 || hue >= hueScoreHistogram.size) {
+                    // Defensively avoid array bounds violations.
+                    continue
+                }
+                if (pixelCount < NUM_SAMPLES) {
+                    pixels[pixelCount++] = rgb
+                }
+                val score = hsv[1] * hsv[2]
+                hueScoreHistogram[hue] += score
+                if (hueScoreHistogram[hue] > highScore) {
+                    highScore = hueScoreHistogram[hue]
+                    bestHue = hue
+                }
+            }
+        }
+
+        val rgbScores = SparseArray<Float>()
+        var bestColor = -0x1000000
+        highScore = -1f
+        // Go back over the RGB colors that match the winning hue,
+        // creating a histogram of weighted s*v scores, for up to 100*100 [s,v] buckets.
+        // The highest-scoring RGB color wins.
+        for (i in 0..<pixelCount) {
+            val rgb = pixels[i]
+            Color.colorToHSV(rgb, hsv)
+            val hue = hsv[0].toInt()
+            if (hue == bestHue) {
+                val s = hsv[1]
+                val v = hsv[2]
+                val bucket = (s * 100).toInt() + (v * 10000).toInt()
+                // Score by cumulative saturation * value.
+                val score = s * v
+                val oldTotal = rgbScores[bucket]
+                val newTotal = if (oldTotal == null) score else oldTotal + score
+                rgbScores.put(bucket, newTotal)
+                if (newTotal > highScore) {
+                    highScore = newTotal
+                    // All the colors in the winning bucket are very similar. Last in wins.
+                    bestColor = rgb
+                }
+            }
+        }
+        return bestColor
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
index 50ca8d6..f6ad4d1 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
@@ -65,8 +65,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
     private static boolean sFlagHoverEnabled = false;
 
     protected final Paint mPaint = new Paint(Paint.FILTER_BITMAP_FLAG | Paint.ANTI_ALIAS_FLAG);
-    protected final Bitmap mBitmap;
-    protected final int mIconColor;
+    public final BitmapInfo mBitmapInfo;
 
     @Nullable private ColorFilter mColorFilter;
 
@@ -97,18 +96,26 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
 
     private Drawable mBadge;
 
+    private boolean mHoverScaleEnabledForDisplay = true;
+
+    protected FastBitmapDrawable(Bitmap b, int iconColor) {
+        this(BitmapInfo.of(b, iconColor));
+    }
+
     public FastBitmapDrawable(Bitmap b) {
-        this(b, Color.TRANSPARENT);
+        this(BitmapInfo.fromBitmap(b));
     }
 
     public FastBitmapDrawable(BitmapInfo info) {
-        this(info.icon, info.color);
+        mBitmapInfo = info;
+        setFilterBitmap(true);
     }
 
-    protected FastBitmapDrawable(Bitmap b, int iconColor) {
-        mBitmap = b;
-        mIconColor = iconColor;
-        setFilterBitmap(true);
+    /**
+     * Returns true if the drawable points to the same bitmap icon object
+     */
+    public boolean isSameInfo(BitmapInfo info) {
+        return mBitmapInfo == info;
     }
 
     @Override
@@ -143,7 +150,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
     }
 
     protected void drawInternal(Canvas canvas, Rect bounds) {
-        canvas.drawBitmap(mBitmap, null, bounds, mPaint);
+        canvas.drawBitmap(mBitmapInfo.icon, null, bounds, mPaint);
     }
 
     /**
@@ -151,7 +158,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
      */
     public int getIconColor() {
         int whiteScrim = setColorAlphaBound(Color.WHITE, WHITE_SCRIM_ALPHA);
-        return ColorUtils.compositeColors(whiteScrim, mIconColor);
+        return ColorUtils.compositeColors(whiteScrim, mBitmapInfo.color);
     }
 
     /**
@@ -218,12 +225,12 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
 
     @Override
     public int getIntrinsicWidth() {
-        return mBitmap.getWidth();
+        return mBitmapInfo.icon.getWidth();
     }
 
     @Override
     public int getIntrinsicHeight() {
-        return mBitmap.getHeight();
+        return mBitmapInfo.icon.getHeight();
     }
 
     @Override
@@ -254,7 +261,9 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
             if (s == android.R.attr.state_pressed) {
                 isPressed = true;
                 break;
-            } else if (sFlagHoverEnabled && s == android.R.attr.state_hovered) {
+            } else if (sFlagHoverEnabled
+                    && s == android.R.attr.state_hovered
+                    && mHoverScaleEnabledForDisplay) {
                 isHovered = true;
                 // Do not break on hovered state, as pressed state should take precedence.
             }
@@ -292,6 +301,9 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
     public void setIsDisabled(boolean isDisabled) {
         if (mIsDisabled != isDisabled) {
             mIsDisabled = isDisabled;
+            if (mBadge instanceof FastBitmapDrawable fbd) {
+                fbd.setIsDisabled(isDisabled);
+            }
             updateFilter();
         }
     }
@@ -329,7 +341,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
     }
 
     protected FastBitmapConstantState newConstantState() {
-        return new FastBitmapConstantState(mBitmap, mIconColor);
+        return new FastBitmapConstantState(mBitmapInfo);
     }
 
     @Override
@@ -414,9 +426,12 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
         sFlagHoverEnabled = isFlagHoverEnabled;
     }
 
+    public void setHoverScaleEnabledForDisplay(boolean hoverScaleEnabledForDisplay) {
+        mHoverScaleEnabledForDisplay = hoverScaleEnabledForDisplay;
+    }
+
     public static class FastBitmapConstantState extends ConstantState {
-        protected final Bitmap mBitmap;
-        protected final int mIconColor;
+        protected final BitmapInfo mBitmapInfo;
 
         // These are initialized later so that subclasses don't need to
         // pass everything in constructor
@@ -426,12 +441,15 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
         @DrawableCreationFlags int mCreationFlags = 0;
 
         public FastBitmapConstantState(Bitmap bitmap, int color) {
-            mBitmap = bitmap;
-            mIconColor = color;
+            this(BitmapInfo.of(bitmap, color));
+        }
+
+        public FastBitmapConstantState(BitmapInfo info) {
+            mBitmapInfo = info;
         }
 
         protected FastBitmapDrawable createDrawable() {
-            return new FastBitmapDrawable(mBitmap, mIconColor);
+            return new FastBitmapDrawable(mBitmapInfo);
         }
 
         @Override
diff --git a/iconloaderlib/src/com/android/launcher3/icons/GraphicsUtils.java b/iconloaderlib/src/com/android/launcher3/icons/GraphicsUtils.java
index 3455dba..1abac90 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/GraphicsUtils.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/GraphicsUtils.java
@@ -16,22 +16,14 @@
 package com.android.launcher3.icons;
 
 import android.content.Context;
-import android.content.res.Resources;
 import android.content.res.TypedArray;
 import android.graphics.Bitmap;
-import android.graphics.Color;
-import android.graphics.Matrix;
-import android.graphics.Path;
 import android.graphics.Rect;
 import android.graphics.Region;
 import android.graphics.RegionIterator;
-import android.graphics.drawable.AdaptiveIconDrawable;
-import android.graphics.drawable.ColorDrawable;
 import android.util.Log;
 
 import androidx.annotation.ColorInt;
-import androidx.annotation.NonNull;
-import androidx.core.graphics.PathParser;
 
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
@@ -39,7 +31,6 @@ import java.io.IOException;
 public class GraphicsUtils {
 
     private static final String TAG = "GraphicsUtils";
-    private static final float MASK_SIZE = 100f;
 
     public static Runnable sOnNewBitmapRunnable = () -> { };
 
@@ -99,30 +90,6 @@ public class GraphicsUtils {
         sOnNewBitmapRunnable.run();
     }
 
-
-    /**
-     * Returns the default path to be used by an icon
-     */
-    public static Path getShapePath(@NonNull Context context, int size) {
-        if (IconProvider.CONFIG_ICON_MASK_RES_ID != Resources.ID_NULL) {
-            Path path = PathParser.createPathFromPathData(
-                    context.getString(IconProvider.CONFIG_ICON_MASK_RES_ID));
-            if (path != null) {
-                if (size != MASK_SIZE) {
-                    Matrix m = new Matrix();
-                    float scale = ((float) size) / MASK_SIZE;
-                    m.setScale(scale, scale);
-                    path.transform(m);
-                }
-                return path;
-            }
-        }
-        AdaptiveIconDrawable drawable = new AdaptiveIconDrawable(
-                new ColorDrawable(Color.BLACK), new ColorDrawable(Color.BLACK));
-        drawable.setBounds(0, 0, size, size);
-        return new Path(drawable.getIconMask());
-    }
-
     /**
      * Returns the color associated with the attribute
      */
diff --git a/iconloaderlib/src/com/android/launcher3/icons/IconNormalizer.java b/iconloaderlib/src/com/android/launcher3/icons/IconNormalizer.java
index d699225..dc8d8b2 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/IconNormalizer.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/IconNormalizer.java
@@ -16,34 +16,19 @@
 
 package com.android.launcher3.icons;
 
-import android.annotation.TargetApi;
-import android.content.Context;
-import android.content.res.Resources;
 import android.graphics.Bitmap;
 import android.graphics.Canvas;
 import android.graphics.Color;
-import android.graphics.Matrix;
-import android.graphics.Paint;
-import android.graphics.Path;
-import android.graphics.PorterDuff;
-import android.graphics.PorterDuffXfermode;
 import android.graphics.Rect;
-import android.graphics.RectF;
-import android.graphics.Region;
 import android.graphics.drawable.AdaptiveIconDrawable;
 import android.graphics.drawable.Drawable;
-import android.os.Build;
-import android.util.Log;
-
-import java.nio.ByteBuffer;
 
 import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
+
+import java.nio.ByteBuffer;
 
 public class IconNormalizer {
 
-    private static final String TAG = "IconNormalizer";
-    private static final boolean DEBUG = false;
     // Ratio of icon visible area to full icon size for a square shaped icon
     private static final float MAX_SQUARE_AREA_FACTOR = 375.0f / 576;
     // Ratio of icon visible area to full icon size for a circular shaped icon
@@ -57,35 +42,21 @@ public class IconNormalizer {
 
     private static final int MIN_VISIBLE_ALPHA = 40;
 
-    // Shape detection related constants
-    private static final float BOUND_RATIO_MARGIN = .05f;
-    private static final float PIXEL_DIFF_PERCENTAGE_THRESHOLD = 0.005f;
-    private static final float SCALE_NOT_INITIALIZED = 0;
-
     // Ratio of the diameter of an normalized circular icon to the actual icon size.
     public static final float ICON_VISIBLE_AREA_FACTOR = 0.92f;
 
     private final int mMaxSize;
     private final Bitmap mBitmap;
     private final Canvas mCanvas;
-    private final Paint mPaintMaskShape;
-    private final Paint mPaintMaskShapeOutline;
     private final byte[] mPixels;
 
-    private final RectF mAdaptiveIconBounds;
-    private float mAdaptiveIconScale;
-
-    private boolean mEnableShapeDetection;
-
     // for each y, stores the position of the leftmost x and the rightmost x
     private final float[] mLeftBorder;
     private final float[] mRightBorder;
     private final Rect mBounds;
-    private final Path mShapePath;
-    private final Matrix mMatrix;
 
     /** package private **/
-    IconNormalizer(Context context, int iconBitmapSize, boolean shapeDetection) {
+    public IconNormalizer(int iconBitmapSize) {
         // Use twice the icon size as maximum size to avoid scaling down twice.
         mMaxSize = iconBitmapSize * 2;
         mBitmap = Bitmap.createBitmap(mMaxSize, mMaxSize, Bitmap.Config.ALPHA_8);
@@ -94,24 +65,6 @@ public class IconNormalizer {
         mLeftBorder = new float[mMaxSize];
         mRightBorder = new float[mMaxSize];
         mBounds = new Rect();
-        mAdaptiveIconBounds = new RectF();
-
-        mPaintMaskShape = new Paint();
-        mPaintMaskShape.setColor(Color.RED);
-        mPaintMaskShape.setStyle(Paint.Style.FILL);
-        mPaintMaskShape.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.XOR));
-
-        mPaintMaskShapeOutline = new Paint();
-        mPaintMaskShapeOutline.setStrokeWidth(
-                2 * context.getResources().getDisplayMetrics().density);
-        mPaintMaskShapeOutline.setStyle(Paint.Style.STROKE);
-        mPaintMaskShapeOutline.setColor(Color.BLACK);
-        mPaintMaskShapeOutline.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
-
-        mShapePath = new Path();
-        mMatrix = new Matrix();
-        mAdaptiveIconScale = SCALE_NOT_INITIALIZED;
-        mEnableShapeDetection = shapeDetection;
     }
 
     private static float getScale(float hullArea, float boundingArea, float fullArea) {
@@ -128,100 +81,6 @@ public class IconNormalizer {
         return areaScale > scaleRequired ? (float) Math.sqrt(scaleRequired / areaScale) : 1;
     }
 
-    /**
-     * @param d Should be AdaptiveIconDrawable
-     * @param size Canvas size to use
-     */
-    @TargetApi(Build.VERSION_CODES.O)
-    public static float normalizeAdaptiveIcon(Drawable d, int size, @Nullable RectF outBounds) {
-        Rect tmpBounds = new Rect(d.getBounds());
-        d.setBounds(0, 0, size, size);
-
-        Path path = ((AdaptiveIconDrawable) d).getIconMask();
-        Region region = new Region();
-        region.setPath(path, new Region(0, 0, size, size));
-
-        Rect hullBounds = region.getBounds();
-        int hullArea = GraphicsUtils.getArea(region);
-
-        if (outBounds != null) {
-            float sizeF = size;
-            outBounds.set(
-                    hullBounds.left / sizeF,
-                    hullBounds.top / sizeF,
-                    1 - (hullBounds.right / sizeF),
-                    1 - (hullBounds.bottom / sizeF));
-        }
-        d.setBounds(tmpBounds);
-        return getScale(hullArea, hullArea, size * size);
-    }
-
-    /**
-     * Returns if the shape of the icon is same as the path.
-     * For this method to work, the shape path bounds should be in [0,1]x[0,1] bounds.
-     */
-    private boolean isShape(Path maskPath) {
-        // Condition1:
-        // If width and height of the path not close to a square, then the icon shape is
-        // not same as the mask shape.
-        float iconRatio = ((float) mBounds.width()) / mBounds.height();
-        if (Math.abs(iconRatio - 1) > BOUND_RATIO_MARGIN) {
-            if (DEBUG) {
-                Log.d(TAG, "Not same as mask shape because width != height. " + iconRatio);
-            }
-            return false;
-        }
-
-        // Condition 2:
-        // Actual icon (white) and the fitted shape (e.g., circle)(red) XOR operation
-        // should generate transparent image, if the actual icon is equivalent to the shape.
-
-        // Fit the shape within the icon's bounding box
-        mMatrix.reset();
-        mMatrix.setScale(mBounds.width(), mBounds.height());
-        mMatrix.postTranslate(mBounds.left, mBounds.top);
-        maskPath.transform(mMatrix, mShapePath);
-
-        // XOR operation
-        mCanvas.drawPath(mShapePath, mPaintMaskShape);
-
-        // DST_OUT operation around the mask path outline
-        mCanvas.drawPath(mShapePath, mPaintMaskShapeOutline);
-
-        // Check if the result is almost transparent
-        return isTransparentBitmap();
-    }
-
-    /**
-     * Used to determine if certain the bitmap is transparent.
-     */
-    private boolean isTransparentBitmap() {
-        ByteBuffer buffer = ByteBuffer.wrap(mPixels);
-        buffer.rewind();
-        mBitmap.copyPixelsToBuffer(buffer);
-
-        int y = mBounds.top;
-        // buffer position
-        int index = y * mMaxSize;
-        // buffer shift after every row, width of buffer = mMaxSize
-        int rowSizeDiff = mMaxSize - mBounds.right;
-
-        int sum = 0;
-        for (; y < mBounds.bottom; y++) {
-            index += mBounds.left;
-            for (int x = mBounds.left; x < mBounds.right; x++) {
-                if ((mPixels[index] & 0xFF) > MIN_VISIBLE_ALPHA) {
-                    sum++;
-                }
-                index++;
-            }
-            index += rowSizeDiff;
-        }
-
-        float percentageDiffPixels = ((float) sum) / (mBounds.width() * mBounds.height());
-        return percentageDiffPixels < PIXEL_DIFF_PERCENTAGE_THRESHOLD;
-    }
-
     /**
      * Returns the amount by which the {@param d} should be scaled (in both dimensions) so that it
      * matches the design guidelines for a launcher icon.
@@ -233,19 +92,10 @@ public class IconNormalizer {
      *
      * This closeness is used to determine the ratio of hull area to the full icon size.
      * Refer {@link #MAX_CIRCLE_AREA_FACTOR} and {@link #MAX_SQUARE_AREA_FACTOR}
-     *
-     * @param outBounds optional rect to receive the fraction distance from each edge.
      */
-    public synchronized float getScale(@NonNull Drawable d, @Nullable RectF outBounds,
-            @Nullable Path path, @Nullable boolean[] outMaskShape) {
+    public synchronized float getScale(@NonNull Drawable d) {
         if (d instanceof AdaptiveIconDrawable) {
-            if (mAdaptiveIconScale == SCALE_NOT_INITIALIZED) {
-                mAdaptiveIconScale = normalizeAdaptiveIcon(d, mMaxSize, mAdaptiveIconBounds);
-            }
-            if (outBounds != null) {
-                outBounds.set(mAdaptiveIconBounds);
-            }
-            return mAdaptiveIconScale;
+            return ICON_VISIBLE_AREA_FACTOR;
         }
         int width = d.getIntrinsicWidth();
         int height = d.getIntrinsicHeight();
@@ -334,14 +184,6 @@ public class IconNormalizer {
         mBounds.top = topY;
         mBounds.bottom = bottomY;
 
-        if (outBounds != null) {
-            outBounds.set(((float) mBounds.left) / width, ((float) mBounds.top) / height,
-                    1 - ((float) mBounds.right) / width,
-                    1 - ((float) mBounds.bottom) / height);
-        }
-        if (outMaskShape != null && mEnableShapeDetection && outMaskShape.length > 0) {
-            outMaskShape[0] = isShape(path);
-        }
         // Area of the rectangle required to fit the convex hull
         float rectArea = (bottomY + 1 - topY) * (rightX + 1 - leftX);
         return getScale(area, rectArea, width * height);
@@ -400,12 +242,4 @@ public class IconNormalizer {
             last = i;
         }
     }
-
-    /**
-     * @return The diameter of the normalized circle that fits inside of the square (size x size).
-     */
-    public static int getNormalizedCircleSize(int size) {
-        float area = size * size * MAX_CIRCLE_AREA_FACTOR;
-        return (int) Math.round(Math.sqrt((4 * area) / Math.PI));
-    }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
index 594db35..9410100 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
@@ -41,7 +41,6 @@ import android.graphics.drawable.InsetDrawable;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.Handler;
-import android.os.PatternMatcher;
 import android.os.Process;
 import android.os.UserHandle;
 import android.os.UserManager;
@@ -62,10 +61,6 @@ import java.util.Objects;
  */
 public class IconProvider {
 
-    private final String ACTION_OVERLAY_CHANGED = "android.intent.action.OVERLAY_CHANGED";
-    static final int CONFIG_ICON_MASK_RES_ID = Resources.getSystem().getIdentifier(
-            "config_icon_mask", "string", "android");
-
     private static final String TAG = "IconProvider";
     private static final boolean DEBUG = false;
     public static final boolean ATLEAST_T = BuildCompat.isAtLeastT();
@@ -79,7 +74,7 @@ public class IconProvider {
     private final ComponentName mClock;
 
     @NonNull
-    private String mSystemState = "";
+    protected String mSystemState = "";
 
     public IconProvider(Context context) {
         mContext = context;
@@ -181,22 +176,28 @@ public class IconProvider {
                 final Resources resources = mContext.getPackageManager()
                         .getResourcesForApplication(appInfo);
                 // Try to load the package item icon first
-                if (info.icon != 0) {
+                if (info != appInfo && info.icon != 0) {
                     try {
                         icon = resources.getDrawableForDensity(info.icon, density);
                     } catch (Resources.NotFoundException exc) { }
                 }
                 if (icon == null && appInfo.icon != 0) {
                     // Load the fallback app icon
-                    try {
-                        icon = resources.getDrawableForDensity(appInfo.icon, density);
-                    } catch (Resources.NotFoundException exc) { }
+                    icon = loadAppInfoIcon(appInfo, resources, density);
                 }
             } catch (NameNotFoundException | Resources.NotFoundException exc) { }
         }
         return icon != null ? icon : getFullResDefaultActivityIcon(density);
     }
 
+    @Nullable
+    protected Drawable loadAppInfoIcon(ApplicationInfo info, Resources resources, int density) {
+        try {
+            return resources.getDrawableForDensity(info.icon, density);
+        } catch (Resources.NotFoundException exc) { }
+        return null;
+    }
+
     @TargetApi(Build.VERSION_CODES.TIRAMISU)
     private Drawable loadCalendarDrawable(int iconDpi, @Nullable ThemeData td) {
         PackageManager pm = mContext.getPackageManager();
@@ -290,14 +291,6 @@ public class IconProvider {
         return TextUtils.isEmpty(cn) ? null : ComponentName.unflattenFromString(cn);
     }
 
-    /**
-     * Returns a string representation of the current system icon state
-     */
-    public String getSystemIconState() {
-        return (CONFIG_ICON_MASK_RES_ID == ID_NULL
-                ? "" : mContext.getResources().getString(CONFIG_ICON_MASK_RES_ID));
-    }
-
     /**
      * Registers a callback to listen for various system dependent icon changes.
      */
@@ -330,18 +323,9 @@ public class IconProvider {
     private class IconChangeReceiver extends BroadcastReceiver implements SafeCloseable {
 
         private final IconChangeListener mCallback;
-        private String mIconState;
 
         IconChangeReceiver(IconChangeListener callback, Handler handler) {
             mCallback = callback;
-            mIconState = getSystemIconState();
-
-
-            IntentFilter packageFilter = new IntentFilter(ACTION_OVERLAY_CHANGED);
-            packageFilter.addDataScheme("package");
-            packageFilter.addDataSchemeSpecificPart("android", PatternMatcher.PATTERN_LITERAL);
-            mContext.registerReceiver(this, packageFilter, null, handler);
-
             if (mCalendar != null || mClock != null) {
                 final IntentFilter filter = new IntentFilter(ACTION_TIMEZONE_CHANGED);
                 if (mCalendar != null) {
@@ -369,20 +353,14 @@ public class IconProvider {
                         }
                     }
                     break;
-                case ACTION_OVERLAY_CHANGED: {
-                    String newState = getSystemIconState();
-                    if (!mIconState.equals(newState)) {
-                        mIconState = newState;
-                        mCallback.onSystemIconStateChanged(mIconState);
-                    }
-                    break;
-                }
             }
         }
 
         @Override
         public void close() {
-            mContext.unregisterReceiver(this);
+            try {
+                mContext.unregisterReceiver(this);
+            } catch (Exception ignored) { }
         }
     }
 
@@ -395,10 +373,5 @@ public class IconProvider {
          * Called when the icon for a particular app changes
          */
         void onAppIconChanged(String packageName, UserHandle user);
-
-        /**
-         * Called when the global icon state changed, which can typically affect all icons
-         */
-        void onSystemIconStateChanged(String iconState);
     }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
index dc4ded8..ae71236 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
@@ -27,6 +27,7 @@ import android.graphics.ColorFilter;
 import android.graphics.ColorMatrix;
 import android.graphics.ColorMatrixColorFilter;
 import android.graphics.Paint;
+import android.graphics.Path;
 import android.graphics.PixelFormat;
 import android.graphics.Rect;
 import android.graphics.drawable.AdaptiveIconDrawable;
@@ -82,7 +83,6 @@ public class MonochromeIconFactory extends Drawable {
         // Crate a color matrix which converts the icon to grayscale and then uses the average
         // of RGB components as the alpha component.
         ColorMatrix satMatrix = new ColorMatrix();
-        satMatrix.setSaturation(0);
         float[] vals = satMatrix.getArray();
         vals[15] = vals[16] = vals[17] = .3333f;
         vals[18] = vals[19] = 0;
@@ -100,12 +100,12 @@ public class MonochromeIconFactory extends Drawable {
      * Creates a monochrome version of the provided drawable
      */
     @WorkerThread
-    public Drawable wrap(AdaptiveIconDrawable icon) {
+    public Drawable wrap(AdaptiveIconDrawable icon, Path shapePath, Float iconScale) {
         mFlatCanvas.drawColor(Color.BLACK);
         drawDrawable(icon.getBackground());
         drawDrawable(icon.getForeground());
         generateMono();
-        return new ClippedMonoDrawable(this);
+        return new ClippedMonoDrawable(this, shapePath, iconScale);
     }
 
     @WorkerThread
@@ -145,6 +145,29 @@ public class MonochromeIconFactory extends Drawable {
                 int p2 = Math.round((p - min) * 0xFF / range);
                 mPixels[i] = flipColor ? (byte) (255 - p2) : (byte) (p2);
             }
+
+            // Second phase of processing, aimed on increasing the contrast
+            for (int i = 0; i < mPixels.length; i++) {
+                int p = mPixels[i] & 0xFF;
+                int p2;
+                double coefficient;
+                if (p > 128) {
+                    coefficient = (1 - (double) (p - 128) / 128);
+                    p2 = 255 - (int) (coefficient * (255 - p));
+                } else {
+                    coefficient = (1 - (double) (128 - p) / 128);
+                    p2 = (int) (coefficient * p);
+                }
+
+                if (p2 > 255) {
+                    p2 = 255;
+                } else if (p2 < 0) {
+                    p2 = 0;
+                }
+
+                mPixels[i] = (byte) p2;
+            }
+
             buffer.rewind();
             mAlphaBitmap.copyPixelsFromBuffer(buffer);
         }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
index 71a80cb..00f1942 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/PlaceHolderIconDrawable.java
@@ -25,6 +25,8 @@ import android.graphics.Path;
 import android.graphics.PorterDuff;
 import android.graphics.PorterDuffColorFilter;
 import android.graphics.Rect;
+import android.graphics.drawable.AdaptiveIconDrawable;
+import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
 
 import androidx.core.graphics.ColorUtils;
@@ -39,12 +41,22 @@ public class PlaceHolderIconDrawable extends FastBitmapDrawable {
 
     public PlaceHolderIconDrawable(BitmapInfo info, Context context) {
         super(info);
-
-        mProgressPath = GraphicsUtils.getShapePath(context, 100);
+        mProgressPath = getDefaultPath();
         mPaint.setColor(ColorUtils.compositeColors(
                 GraphicsUtils.getAttrColor(context, R.attr.loadingIconColor), info.color));
     }
 
+    /**
+     * Gets the current default icon mask {@link Path}.
+     * @return Shaped {@link Path} scaled to [0, 0, 100, 100] bounds
+     */
+    private Path getDefaultPath() {
+        AdaptiveIconDrawable drawable = new AdaptiveIconDrawable(
+                new ColorDrawable(Color.BLACK), new ColorDrawable(Color.BLACK));
+        drawable.setBounds(0, 0, 100, 100);
+        return new Path(drawable.getIconMask());
+    }
+
     @Override
     protected void drawInternal(Canvas canvas, Rect bounds) {
         int saveCount = canvas.save();
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ShadowGenerator.java b/iconloaderlib/src/com/android/launcher3/icons/ShadowGenerator.java
index 7aab47c..5cd05c5 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ShadowGenerator.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/ShadowGenerator.java
@@ -45,6 +45,11 @@ public class ShadowGenerator {
     private static final float HALF_DISTANCE = 0.5f;
     private static final int AMBIENT_SHADOW_ALPHA = 25;
 
+    // Amount by which an icon should be scaled down to make room for shadows.
+    // We are ignoring KEY_SHADOW_DISTANCE because regular icons also ignore this: b/298203449
+    public static final float ICON_SCALE_FOR_SHADOWS =
+            (HALF_DISTANCE - BLUR_FACTOR) / HALF_DISTANCE;
+
     private final int mIconSize;
 
     private final Paint mBlurPaint;
@@ -95,30 +100,6 @@ public class ShadowGenerator {
         }
     }
 
-    /**
-     * Returns the minimum amount by which an icon with {@param bounds} should be scaled
-     * so that the shadows do not get clipped.
-     */
-    public static float getScaleForBounds(RectF bounds) {
-        float scale = 1;
-
-        if (ENABLE_SHADOWS) {
-            // For top, left & right, we need same space.
-            float minSide = Math.min(Math.min(bounds.left, bounds.right), bounds.top);
-            if (minSide < BLUR_FACTOR) {
-                scale = (HALF_DISTANCE - BLUR_FACTOR) / (HALF_DISTANCE - minSide);
-            }
-
-            // We are ignoring KEY_SHADOW_DISTANCE because regular icons ignore this at the moment b/298203449
-            float bottomSpace = BLUR_FACTOR;
-            if (bounds.bottom < bottomSpace) {
-                scale = Math.min(scale,
-                        (HALF_DISTANCE - bottomSpace) / (HALF_DISTANCE - bounds.bottom));
-            }
-        }
-        return scale;
-    }
-
     public static class Builder {
 
         public final RectF bounds = new RectF();
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
index 27b4619..6c937db 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
@@ -18,6 +18,8 @@ package com.android.launcher3.icons
 
 import android.content.Context
 import android.graphics.drawable.AdaptiveIconDrawable
+import com.android.launcher3.icons.cache.CachingLogic
+import com.android.launcher3.util.ComponentKey
 
 /** Represents a themed version of a BitmapInfo */
 interface ThemedBitmap {
@@ -30,13 +32,21 @@ interface ThemedBitmap {
 
 interface IconThemeController {
 
+    val themeID: String
+
     fun createThemedBitmap(
         icon: AdaptiveIconDrawable,
         info: BitmapInfo,
         factory: BaseIconFactory,
+        sourceHint: SourceHint? = null,
     ): ThemedBitmap?
 
-    fun decode(data: ByteArray, info: BitmapInfo, factory: BaseIconFactory): ThemedBitmap?
+    fun decode(
+        data: ByteArray,
+        info: BitmapInfo,
+        factory: BaseIconFactory,
+        sourceHint: SourceHint,
+    ): ThemedBitmap?
 
     fun createThemedAdaptiveIcon(
         context: Context,
@@ -44,3 +54,10 @@ interface IconThemeController {
         info: BitmapInfo?,
     ): AdaptiveIconDrawable?
 }
+
+data class SourceHint(
+    val key: ComponentKey,
+    val logic: CachingLogic<*>,
+    val freshnessId: String? = null,
+    val isFileDrawable: Boolean = false,
+)
diff --git a/iconloaderlib/src/com/android/launcher3/icons/UserBadgeDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/UserBadgeDrawable.java
index 1d06e60..07e12ef 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/UserBadgeDrawable.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/UserBadgeDrawable.java
@@ -25,8 +25,11 @@ import android.graphics.Color;
 import android.graphics.ColorFilter;
 import android.graphics.ColorMatrix;
 import android.graphics.ColorMatrixColorFilter;
+import android.graphics.Matrix;
 import android.graphics.Paint;
+import android.graphics.Path;
 import android.graphics.Rect;
+import android.graphics.RectF;
 import android.graphics.drawable.Drawable;
 import android.graphics.drawable.DrawableWrapper;
 
@@ -57,13 +60,24 @@ public class UserBadgeDrawable extends DrawableWrapper {
     private final int mBaseColor;
     private final int mBgColor;
     private boolean mShouldDrawBackground = true;
+    @Nullable private Path mShape;
+
+    private Matrix mShapeMatrix = new Matrix();
 
     @VisibleForTesting
     public final boolean mIsThemed;
 
-    public UserBadgeDrawable(Context context, int badgeRes, int colorRes, boolean isThemed) {
+    public UserBadgeDrawable(Context context, int badgeRes, int colorRes, boolean isThemed,
+            @Nullable Path shape) {
         super(context.getDrawable(badgeRes));
-
+        mShape = shape;
+        mShapeMatrix = new Matrix();
+        if (mShape != null) {
+            mShapeMatrix.setRectToRect(new RectF(0f, 0f, 100f, 100f),
+                    new RectF(0f, 0f, CENTER * 2, CENTER * 2),
+                    Matrix.ScaleToFit.CENTER);
+            mShape.transform(mShapeMatrix);
+        }
         mIsThemed = isThemed;
         if (isThemed) {
             mutate();
@@ -94,11 +108,17 @@ public class UserBadgeDrawable extends DrawableWrapper {
             canvas.scale(b.width() / VIEWPORT_SIZE, b.height() / VIEWPORT_SIZE);
 
             mPaint.setColor(blendDrawableAlpha(SHADOW_COLOR));
-            canvas.drawCircle(CENTER, CENTER + SHADOW_OFFSET_Y, SHADOW_RADIUS, mPaint);
-
+            if (mShape != null) {
+                canvas.drawPath(mShape, mPaint);
+            } else {
+                canvas.drawCircle(CENTER, CENTER + SHADOW_OFFSET_Y, SHADOW_RADIUS, mPaint);
+            }
             mPaint.setColor(blendDrawableAlpha(mBgColor));
-            canvas.drawCircle(CENTER, CENTER, BG_RADIUS, mPaint);
-
+            if (mShape != null) {
+                canvas.drawPath(mShape, mPaint);
+            } else {
+                canvas.drawCircle(CENTER, CENTER, BG_RADIUS, mPaint);
+            }
             canvas.restoreToCount(saveCount);
         }
         super.draw(canvas);
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/AppInfoCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/AppInfoCachingLogic.kt
new file mode 100644
index 0000000..8de6a7c
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/AppInfoCachingLogic.kt
@@ -0,0 +1,73 @@
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
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.Context
+import android.content.pm.ApplicationInfo
+import android.content.pm.PackageManager
+import android.os.UserHandle
+import com.android.launcher3.icons.BaseIconFactory.IconOptions
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconProvider
+import com.android.launcher3.icons.cache.BaseIconCache.Companion.EMPTY_CLASS_NAME
+
+/** Caching logic for ApplicationInfo */
+class AppInfoCachingLogic(
+    private val pm: PackageManager,
+    private val instantAppResolver: (ApplicationInfo) -> Boolean,
+    private val errorLogger: (String, Exception?) -> Unit = { _, _ -> },
+) : CachingLogic<ApplicationInfo> {
+
+    override fun getComponent(info: ApplicationInfo) =
+        ComponentName(info.packageName, info.packageName + EMPTY_CLASS_NAME)
+
+    override fun getUser(info: ApplicationInfo) = UserHandle.getUserHandleForUid(info.uid)
+
+    override fun getLabel(info: ApplicationInfo) = info.loadLabel(pm)
+
+    override fun getApplicationInfo(info: ApplicationInfo) = info
+
+    override fun loadIcon(
+        context: Context,
+        cache: BaseIconCache,
+        info: ApplicationInfo,
+    ): BitmapInfo {
+        // Load the full res icon for the application, but if useLowResIcon is set, then
+        // only keep the low resolution icon instead of the larger full-sized icon
+        val appIcon = cache.iconProvider.getIcon(info)
+        if (context.packageManager.isDefaultApplicationIcon(appIcon)) {
+            errorLogger.invoke(
+                String.format("Default icon returned for %s", info.packageName),
+                null,
+            )
+        }
+
+        return cache.iconFactory.use { li ->
+            li.createBadgedIconBitmap(
+                appIcon,
+                IconOptions()
+                    .setUser(getUser(info))
+                    .setInstantApp(instantAppResolver.invoke(info))
+                    .setSourceHint(getSourceHint(info, cache)),
+            )
+        }
+    }
+
+    override fun getFreshnessIdentifier(item: ApplicationInfo, iconProvider: IconProvider) =
+        iconProvider.getStateForApp(item)
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
deleted file mode 100644
index 959f14d..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
+++ /dev/null
@@ -1,816 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-package com.android.launcher3.icons.cache;
-
-import static android.content.pm.PackageManager.MATCH_UNINSTALLED_PACKAGES;
-import static android.graphics.BitmapFactory.decodeByteArray;
-
-import static com.android.launcher3.Flags.forceMonochromeAppIcons;
-import static com.android.launcher3.icons.BitmapInfo.LOW_RES_ICON;
-import static com.android.launcher3.icons.GraphicsUtils.flattenBitmap;
-import static com.android.launcher3.icons.GraphicsUtils.setColorAlphaBound;
-
-import static java.util.Objects.requireNonNull;
-
-import android.content.ComponentName;
-import android.content.ContentValues;
-import android.content.Context;
-import android.content.pm.ActivityInfo;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.LauncherApps;
-import android.content.pm.PackageManager;
-import android.content.pm.PackageManager.NameNotFoundException;
-import android.database.Cursor;
-import android.database.sqlite.SQLiteDatabase;
-import android.database.sqlite.SQLiteException;
-import android.database.sqlite.SQLiteReadOnlyDatabaseException;
-import android.graphics.Bitmap;
-import android.graphics.Bitmap.Config;
-import android.graphics.BitmapFactory;
-import android.graphics.drawable.Drawable;
-import android.os.Handler;
-import android.os.Looper;
-import android.os.Trace;
-import android.os.UserHandle;
-import android.text.TextUtils;
-import android.util.Log;
-import android.util.SparseArray;
-
-import androidx.annotation.IntDef;
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-import androidx.annotation.VisibleForTesting;
-import androidx.annotation.WorkerThread;
-
-import com.android.launcher3.icons.BaseIconFactory;
-import com.android.launcher3.icons.BaseIconFactory.IconOptions;
-import com.android.launcher3.icons.BitmapInfo;
-import com.android.launcher3.icons.IconProvider;
-import com.android.launcher3.icons.IconThemeController;
-import com.android.launcher3.icons.ThemedBitmap;
-import com.android.launcher3.util.ComponentKey;
-import com.android.launcher3.util.FlagOp;
-import com.android.launcher3.util.SQLiteCacheHelper;
-
-import java.lang.annotation.Retention;
-import java.lang.annotation.RetentionPolicy;
-import java.util.AbstractMap;
-import java.util.Arrays;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.Map;
-import java.util.Set;
-import java.util.function.Supplier;
-
-public abstract class BaseIconCache {
-
-    private static final String TAG = "BaseIconCache";
-    private static final boolean DEBUG = false;
-
-    private static final int INITIAL_ICON_CACHE_CAPACITY = 50;
-    // A format string which returns the original string as is.
-    private static final String IDENTITY_FORMAT_STRING = "%1$s";
-
-    // Empty class name is used for storing package default entry.
-    public static final String EMPTY_CLASS_NAME = ".";
-
-    @Retention(RetentionPolicy.SOURCE)
-    @IntDef(value = {
-            LookupFlag.DEFAULT,
-            LookupFlag.USE_LOW_RES,
-            LookupFlag.USE_PACKAGE_ICON,
-            LookupFlag.SKIP_ADD_TO_MEM_CACHE
-    }, flag = true)
-    /** Various options to control cache lookup */
-    public @interface LookupFlag {
-        /**
-         * Default behavior of cache lookup is to load high-res icon with no fallback
-         */
-        int DEFAULT = 0;
-
-        /**
-         * When specified, the cache tries to load the low res version of the entry unless a
-         * high-res is already in memory
-         */
-        int USE_LOW_RES = 1 << 0;
-        /**
-         * When specified, the cache tries to lookup the package entry for the item, if the object
-         * entry fails
-         */
-        int USE_PACKAGE_ICON = 1 << 1;
-        /**
-         * When specified, the entry will not be added to the memory cache if it was not already
-         * added by a previous lookup
-         */
-        int SKIP_ADD_TO_MEM_CACHE = 1 << 2;
-    }
-
-    public static class CacheEntry {
-
-        @NonNull
-        public BitmapInfo bitmap = BitmapInfo.LOW_RES_INFO;
-        @NonNull
-        public CharSequence title = "";
-        @NonNull
-        public CharSequence contentDescription = "";
-    }
-
-    @NonNull
-    protected final Context mContext;
-
-    @NonNull
-    protected final PackageManager mPackageManager;
-
-    @NonNull
-    protected final IconProvider mIconProvider;
-
-    @NonNull
-    private final Map<ComponentKey, CacheEntry> mCache;
-
-    public final Object iconUpdateToken = new Object();
-
-    @NonNull
-    public final Handler workerHandler;
-
-    protected int mIconDpi;
-
-    @NonNull
-    protected IconDB mIconDb;
-
-    @Nullable
-    private BitmapInfo mDefaultIcon;
-
-    @NonNull
-    private final SparseArray<FlagOp> mUserFlagOpMap = new SparseArray<>();
-
-    private final SparseArray<String> mUserFormatString = new SparseArray<>();
-
-    @Nullable
-    private final String mDbFileName;
-
-    @NonNull
-    private final Looper mBgLooper;
-
-    public BaseIconCache(@NonNull final Context context, @Nullable final String dbFileName,
-            @NonNull final Looper bgLooper, final int iconDpi, final int iconPixelSize,
-            final boolean inMemoryCache) {
-        this(context, dbFileName, bgLooper, iconDpi, iconPixelSize, inMemoryCache,
-                new IconProvider(context));
-    }
-
-    public BaseIconCache(@NonNull final Context context, @Nullable final String dbFileName,
-            @NonNull final Looper bgLooper, final int iconDpi, final int iconPixelSize,
-            final boolean inMemoryCache, @NonNull IconProvider iconProvider) {
-        mContext = context;
-        mDbFileName = dbFileName;
-        mIconProvider = iconProvider;
-        mPackageManager = context.getPackageManager();
-        mBgLooper = bgLooper;
-        workerHandler = new Handler(mBgLooper);
-
-        if (inMemoryCache) {
-            mCache = new HashMap<>(INITIAL_ICON_CACHE_CAPACITY);
-        } else {
-            // Use a dummy cache
-            mCache = new AbstractMap<>() {
-                @Override
-                public Set<Entry<ComponentKey, CacheEntry>> entrySet() {
-                    return Collections.emptySet();
-                }
-
-                @Override
-                public CacheEntry put(ComponentKey key, CacheEntry value) {
-                    return value;
-                }
-            };
-        }
-
-        updateSystemState();
-        mIconDpi = iconDpi;
-        mIconDb = new IconDB(context, dbFileName, iconPixelSize);
-    }
-
-    /**
-     * Returns the persistable serial number for {@param user}. Subclass should implement proper
-     * caching strategy to avoid making binder call every time.
-     */
-    protected abstract long getSerialNumberForUser(@NonNull final UserHandle user);
-
-    /**
-     * Return true if the given app is an instant app and should be badged appropriately.
-     */
-    protected abstract boolean isInstantApp(@NonNull final ApplicationInfo info);
-
-    /**
-     * Opens and returns an icon factory. The factory is recycled by the caller.
-     */
-    @NonNull
-    public abstract BaseIconFactory getIconFactory();
-
-    public void updateIconParams(final int iconDpi, final int iconPixelSize) {
-        workerHandler.post(() -> updateIconParamsBg(iconDpi, iconPixelSize));
-    }
-
-    private synchronized void updateIconParamsBg(final int iconDpi, final int iconPixelSize) {
-        try {
-            mIconDpi = iconDpi;
-            mDefaultIcon = null;
-            mUserFlagOpMap.clear();
-            mIconDb.clear();
-            mIconDb.close();
-            mIconDb = new IconDB(mContext, mDbFileName, iconPixelSize);
-            mCache.clear();
-        } catch (SQLiteReadOnlyDatabaseException e) {
-            // This is known to happen during repeated backup and restores, if the Launcher is in
-            // restricted mode. When the launcher is loading and the backup restore is being cleared
-            // there can be a conflict where one DB is trying to delete the DB file, and the other
-            // is attempting to write to it. The effect is that launcher crashes, then the backup /
-            // restore process fails, then the user's home screen icons fail to restore. Adding this
-            // try / catch will stop the crash, and LoaderTask will sanitize any residual icon data,
-            // leading to a completed backup / restore and a better experience for our customers.
-            Log.e(TAG, "failed to clear the launcher's icon db or cache.", e);
-        }
-    }
-
-    @Nullable
-    public Drawable getFullResIcon(@NonNull final ActivityInfo info) {
-        return mIconProvider.getIcon(info, mIconDpi);
-    }
-
-    /**
-     * Remove any records for the supplied ComponentName.
-     */
-    public synchronized void remove(@NonNull final ComponentName componentName,
-            @NonNull final UserHandle user) {
-        mCache.remove(new ComponentKey(componentName, user));
-    }
-
-    /**
-     * Remove any records for the supplied package name from memory.
-     */
-    private void removeFromMemCacheLocked(@Nullable final String packageName,
-            @Nullable final UserHandle user) {
-        HashSet<ComponentKey> forDeletion = new HashSet<>();
-        for (ComponentKey key : mCache.keySet()) {
-            if (key.componentName.getPackageName().equals(packageName)
-                    && key.user.equals(user)) {
-                forDeletion.add(key);
-            }
-        }
-        for (ComponentKey condemned : forDeletion) {
-            mCache.remove(condemned);
-        }
-    }
-
-    /**
-     * Removes the entries related to the given package in memory and persistent DB.
-     */
-    public synchronized void removeIconsForPkg(@NonNull final String packageName,
-            @NonNull final UserHandle user) {
-        removeFromMemCacheLocked(packageName, user);
-        long userSerial = getSerialNumberForUser(user);
-        mIconDb.delete(
-                IconDB.COLUMN_COMPONENT + " LIKE ? AND " + IconDB.COLUMN_USER + " = ?",
-                new String[]{packageName + "/%", Long.toString(userSerial)});
-    }
-
-    @NonNull
-    public IconCacheUpdateHandler getUpdateHandler() {
-        updateSystemState();
-
-        // Remove all active icon update tasks.
-        workerHandler.removeCallbacksAndMessages(iconUpdateToken);
-
-        return new IconCacheUpdateHandler(this, mIconDb, workerHandler);
-    }
-
-    /**
-     * Refreshes the system state definition used to check the validity of the cache. It
-     * incorporates all the properties that can affect the cache like the list of enabled locale
-     * and system-version.
-     */
-    private void updateSystemState() {
-        mIconProvider.updateSystemState();
-        mUserFormatString.clear();
-    }
-
-    public IconProvider getIconProvider() {
-        return mIconProvider;
-    }
-
-    public CharSequence getUserBadgedLabel(CharSequence label, UserHandle user) {
-        int key = user.hashCode();
-        int index = mUserFormatString.indexOfKey(key);
-        String format;
-        if (index < 0) {
-            format = mPackageManager.getUserBadgedLabel(IDENTITY_FORMAT_STRING, user).toString();
-            if (TextUtils.equals(IDENTITY_FORMAT_STRING, format)) {
-                format = null;
-            }
-            mUserFormatString.put(key, format);
-        } else {
-            format = mUserFormatString.valueAt(index);
-        }
-        return format == null ? label : String.format(format, label);
-    }
-
-    /**
-     * Adds/updates an entry into the DB and the in-memory cache. The update is skipped if the
-     * entry fails to load
-     */
-    protected synchronized <T> void addIconToDBAndMemCache(@NonNull final T object,
-            @NonNull final CachingLogic<T> cachingLogic, final long userSerial) {
-        UserHandle user = cachingLogic.getUser(object);
-        ComponentName componentName = cachingLogic.getComponent(object);
-        final ComponentKey key = new ComponentKey(componentName, user);
-
-        BitmapInfo bitmapInfo = cachingLogic.loadIcon(mContext, this, object);
-
-        // Icon can't be loaded from cachingLogic, which implies alternative icon was loaded
-        // (e.g. fallback icon, default icon). So we drop here since there's no point in caching
-        // an empty entry.
-        if (bitmapInfo.isNullOrLowRes() || isDefaultIcon(bitmapInfo, user)) {
-            return;
-        }
-
-        CharSequence entryTitle = cachingLogic.getLabel(object);
-        if (TextUtils.isEmpty(entryTitle)) {
-            entryTitle = componentName.getPackageName();
-        }
-
-        // Only add an entry in memory, if there was already something previously
-        if (mCache.get(key) != null) {
-            CacheEntry entry = new CacheEntry();
-            entry.bitmap = bitmapInfo;
-            entry.title = entryTitle;
-            entry.contentDescription = getUserBadgedLabel(entryTitle, user);
-            mCache.put(key, entry);
-        }
-
-        String freshnessId = cachingLogic.getFreshnessIdentifier(object, mIconProvider);
-        if (freshnessId != null) {
-            addOrUpdateCacheDbEntry(bitmapInfo, entryTitle, componentName, userSerial, freshnessId);
-        }
-    }
-
-    @NonNull
-    public synchronized BitmapInfo getDefaultIcon(@NonNull final UserHandle user) {
-        if (mDefaultIcon == null) {
-            try (BaseIconFactory li = getIconFactory()) {
-                mDefaultIcon = li.makeDefaultIcon(mIconProvider);
-            }
-        }
-        return mDefaultIcon.withFlags(getUserFlagOpLocked(user));
-    }
-
-    @NonNull
-    protected FlagOp getUserFlagOpLocked(@NonNull final UserHandle user) {
-        int key = user.hashCode();
-        int index;
-        if ((index = mUserFlagOpMap.indexOfKey(key)) >= 0) {
-            return mUserFlagOpMap.valueAt(index);
-        } else {
-            try (BaseIconFactory li = getIconFactory()) {
-                FlagOp op = li.getBitmapFlagOp(new IconOptions().setUser(user));
-                mUserFlagOpMap.put(key, op);
-                return op;
-            }
-        }
-    }
-
-    public boolean isDefaultIcon(@NonNull final BitmapInfo icon, @NonNull final UserHandle user) {
-        return getDefaultIcon(user).icon == icon.icon;
-    }
-
-    /**
-     * Retrieves the entry from the cache. If the entry is not present, it creates a new entry.
-     * This method is not thread safe, it must be called from a synchronized method.
-     */
-    @NonNull
-    protected <T> CacheEntry cacheLocked(
-            @NonNull final ComponentName componentName, @NonNull final UserHandle user,
-            @NonNull final Supplier<T> infoProvider, @NonNull final CachingLogic<T> cachingLogic,
-            @LookupFlag int lookupFlags) {
-        return cacheLocked(
-                componentName,
-                user,
-                infoProvider,
-                cachingLogic,
-                lookupFlags,
-                null);
-    }
-
-    @NonNull
-    protected <T> CacheEntry cacheLocked(
-            @NonNull final ComponentName componentName, @NonNull final UserHandle user,
-            @NonNull final Supplier<T> infoProvider, @NonNull final CachingLogic<T> cachingLogic,
-            @LookupFlag int lookupFlags, @Nullable final Cursor cursor) {
-        assertWorkerThread();
-        ComponentKey cacheKey = new ComponentKey(componentName, user);
-        CacheEntry entry = mCache.get(cacheKey);
-        final boolean useLowResIcon = (lookupFlags & LookupFlag.USE_LOW_RES) != 0;
-        if (entry == null || (entry.bitmap.isLowRes() && !useLowResIcon)) {
-            boolean addToMemCache = entry != null
-                    || (lookupFlags & LookupFlag.SKIP_ADD_TO_MEM_CACHE) == 0;
-            entry = new CacheEntry();
-            if (addToMemCache) {
-                mCache.put(cacheKey, entry);
-            }
-
-            // Check the DB first.
-            T object = null;
-            boolean providerFetchedOnce = false;
-            boolean cacheEntryUpdated = cursor == null
-                    ? getEntryFromDBLocked(cacheKey, entry, useLowResIcon)
-                    : updateTitleAndIconLocked(cacheKey, entry, cursor, useLowResIcon);
-            if (!cacheEntryUpdated) {
-                object = infoProvider.get();
-                providerFetchedOnce = true;
-
-                loadFallbackIcon(
-                        object,
-                        entry,
-                        cachingLogic,
-                        (lookupFlags & LookupFlag.USE_PACKAGE_ICON) != 0,
-                        /* usePackageTitle= */ true,
-                        componentName,
-                        user);
-            }
-
-            if (TextUtils.isEmpty(entry.title)) {
-                if (object == null && !providerFetchedOnce) {
-                    object = infoProvider.get();
-                    providerFetchedOnce = true;
-                }
-                if (object != null) {
-                    loadFallbackTitle(object, entry, cachingLogic, user);
-                }
-            }
-        }
-        return entry;
-    }
-
-    /**
-     * Fallback method for loading an icon bitmap.
-     */
-    protected <T> void loadFallbackIcon(@Nullable final T object, @NonNull final CacheEntry entry,
-            @NonNull final CachingLogic<T> cachingLogic, final boolean usePackageIcon,
-            final boolean usePackageTitle, @NonNull final ComponentName componentName,
-            @NonNull final UserHandle user) {
-        if (object != null) {
-            entry.bitmap = cachingLogic.loadIcon(mContext, this, object);
-        } else {
-            if (usePackageIcon) {
-                CacheEntry packageEntry = getEntryForPackageLocked(
-                        componentName.getPackageName(), user, false);
-                if (DEBUG) {
-                    Log.d(TAG, "using package default icon for "
-                            + componentName.toShortString());
-                }
-                entry.bitmap = packageEntry.bitmap;
-                entry.contentDescription = packageEntry.contentDescription;
-
-                if (usePackageTitle) {
-                    entry.title = packageEntry.title;
-                }
-            }
-            if (entry.bitmap == null) {
-                // TODO: entry.bitmap can never be null, so this should not happen at all.
-                Log.wtf(TAG, "using default icon for " + componentName.toShortString());
-                entry.bitmap = getDefaultIcon(user);
-            }
-        }
-    }
-
-    /**
-     * Fallback method for loading an app title.
-     */
-    protected <T> void loadFallbackTitle(
-            @NonNull final T object, @NonNull final CacheEntry entry,
-            @NonNull final CachingLogic<T> cachingLogic, @NonNull final UserHandle user) {
-        entry.title = cachingLogic.getLabel(object);
-        if (TextUtils.isEmpty(entry.title)) {
-            entry.title = cachingLogic.getComponent(object).getPackageName();
-        }
-        entry.contentDescription = getUserBadgedLabel(entry.title, user);
-    }
-
-    public synchronized void clearMemoryCache() {
-        assertWorkerThread();
-        mCache.clear();
-    }
-
-    /**
-     * Adds a default package entry in the cache. This entry is not persisted and will be removed
-     * when the cache is flushed.
-     */
-    protected synchronized void cachePackageInstallInfo(@NonNull final String packageName,
-            @NonNull final UserHandle user, @Nullable final Bitmap icon,
-            @Nullable final CharSequence title) {
-        removeFromMemCacheLocked(packageName, user);
-
-        ComponentKey cacheKey = getPackageKey(packageName, user);
-        CacheEntry entry = mCache.get(cacheKey);
-
-        // For icon caching, do not go through DB. Just update the in-memory entry.
-        if (entry == null) {
-            entry = new CacheEntry();
-        }
-        if (!TextUtils.isEmpty(title)) {
-            entry.title = title;
-        }
-        if (icon != null) {
-            BaseIconFactory li = getIconFactory();
-            entry.bitmap = li.createBadgedIconBitmap(
-                    li.createShapedAdaptiveIcon(icon),
-                    new IconOptions().setUser(user)
-            );
-            li.close();
-        }
-        if (!TextUtils.isEmpty(title) && entry.bitmap.icon != null) {
-            mCache.put(cacheKey, entry);
-        }
-    }
-
-    @NonNull
-    public static ComponentKey getPackageKey(@NonNull final String packageName,
-            @NonNull final UserHandle user) {
-        ComponentName cn = new ComponentName(packageName, packageName + EMPTY_CLASS_NAME);
-        return new ComponentKey(cn, user);
-    }
-
-    /**
-     * Returns the package entry if it has already been cached in memory, null otherwise
-     */
-    @Nullable
-    protected CacheEntry getInMemoryPackageEntryLocked(@NonNull final String packageName,
-            @NonNull final UserHandle user) {
-        return getInMemoryEntryLocked(getPackageKey(packageName, user));
-    }
-
-    @VisibleForTesting
-    public CacheEntry getInMemoryEntryLocked(ComponentKey key) {
-        assertWorkerThread();
-        return mCache.get(key);
-    }
-
-    /**
-     * Gets an entry for the package, which can be used as a fallback entry for various components.
-     * This method is not thread safe, it must be called from a synchronized method.
-     */
-    @WorkerThread
-    @NonNull
-    @SuppressWarnings("NewApi")
-    protected CacheEntry getEntryForPackageLocked(@NonNull final String packageName,
-            @NonNull final UserHandle user, final boolean useLowResIcon) {
-        assertWorkerThread();
-        ComponentKey cacheKey = getPackageKey(packageName, user);
-        CacheEntry entry = mCache.get(cacheKey);
-
-        if (entry == null || (entry.bitmap.isLowRes() && !useLowResIcon)) {
-            entry = new CacheEntry();
-            boolean entryUpdated = true;
-
-            // Check the DB first.
-            if (!getEntryFromDBLocked(cacheKey, entry, useLowResIcon)) {
-                try {
-                    ApplicationInfo appInfo = mContext.getSystemService(LauncherApps.class)
-                            .getApplicationInfo(packageName, MATCH_UNINSTALLED_PACKAGES, user);
-                    if (appInfo == null) {
-                        NameNotFoundException e =
-                                new NameNotFoundException("ApplicationInfo is null");
-                        logdPersistently(TAG,
-                                String.format("ApplicationInfo is null for %s", packageName), e);
-                        throw e;
-                    }
-
-                    BaseIconFactory li = getIconFactory();
-                    // Load the full res icon for the application, but if useLowResIcon is set, then
-                    // only keep the low resolution icon instead of the larger full-sized icon
-                    Drawable appIcon = mIconProvider.getIcon(appInfo);
-                    if (mPackageManager.isDefaultApplicationIcon(appIcon)) {
-                        logdPersistently(TAG,
-                                String.format("Default icon returned for %s", appInfo.packageName),
-                                null);
-                    }
-                    BitmapInfo iconInfo = li.createBadgedIconBitmap(appIcon,
-                            new IconOptions().setUser(user).setInstantApp(isInstantApp(appInfo)));
-                    li.close();
-
-                    entry.title = appInfo.loadLabel(mPackageManager);
-                    entry.contentDescription = getUserBadgedLabel(entry.title, user);
-                    entry.bitmap = useLowResIcon
-                            ? BitmapInfo.of(LOW_RES_ICON, iconInfo.color)
-                            : iconInfo;
-
-                    // Add the icon in the DB here, since these do not get written during
-                    // package updates.
-                    String freshnessId = mIconProvider.getStateForApp(appInfo);
-                    if (freshnessId != null) {
-                        addOrUpdateCacheDbEntry(
-                                iconInfo, entry.title, cacheKey.componentName,
-                                getSerialNumberForUser(user), freshnessId);
-                    }
-                } catch (NameNotFoundException e) {
-                    if (DEBUG) Log.d(TAG, "Application not installed " + packageName);
-                    entryUpdated = false;
-                }
-            }
-
-            // Only add a filled-out entry to the cache
-            if (entryUpdated) {
-                mCache.put(cacheKey, entry);
-            }
-        }
-        return entry;
-    }
-
-    protected boolean getEntryFromDBLocked(@NonNull final ComponentKey cacheKey,
-            @NonNull final CacheEntry entry, final boolean lowRes) {
-        Cursor c = null;
-        Trace.beginSection("loadIconIndividually");
-        try {
-            c = mIconDb.query(
-                    lowRes ? IconDB.COLUMNS_LOW_RES : IconDB.COLUMNS_HIGH_RES,
-                    IconDB.COLUMN_COMPONENT + " = ? AND " + IconDB.COLUMN_USER + " = ?",
-                    new String[]{
-                            cacheKey.componentName.flattenToString(),
-                            Long.toString(getSerialNumberForUser(cacheKey.user))});
-            if (c.moveToNext()) {
-                return updateTitleAndIconLocked(cacheKey, entry, c, lowRes);
-            }
-        } catch (SQLiteException e) {
-            Log.d(TAG, "Error reading icon cache", e);
-        } finally {
-            if (c != null) {
-                c.close();
-            }
-            Trace.endSection();
-        }
-        return false;
-    }
-
-    private boolean updateTitleAndIconLocked(
-            @NonNull final ComponentKey cacheKey, @NonNull final CacheEntry entry,
-            @NonNull final Cursor c, final boolean lowRes) {
-        // Set the alpha to be 255, so that we never have a wrong color
-        entry.bitmap = BitmapInfo.of(LOW_RES_ICON,
-                setColorAlphaBound(c.getInt(IconDB.INDEX_COLOR), 255));
-        entry.title = c.getString(IconDB.INDEX_TITLE);
-        if (entry.title == null) {
-            entry.title = "";
-            entry.contentDescription = "";
-        } else {
-            entry.contentDescription = getUserBadgedLabel(entry.title, cacheKey.user);
-        }
-
-        if (!lowRes) {
-            byte[] data = c.getBlob(IconDB.INDEX_ICON);
-            if (data == null) {
-                return false;
-            }
-            try {
-                BitmapFactory.Options decodeOptions = new BitmapFactory.Options();
-                decodeOptions.inPreferredConfig = Config.HARDWARE;
-                entry.bitmap = BitmapInfo.of(
-                        requireNonNull(decodeByteArray(data, 0, data.length, decodeOptions)),
-                        entry.bitmap.color);
-            } catch (Exception e) {
-                return false;
-            }
-
-            // Decode theme bitmap
-            try (BaseIconFactory factory = getIconFactory()) {
-                IconThemeController themeController = factory.getThemeController();
-                data = c.getBlob(IconDB.INDEX_MONO_ICON);
-                if (themeController != null && data != null) {
-                    entry.bitmap.setThemedBitmap(
-                            themeController.decode(data, entry.bitmap, factory));
-                }
-            }
-        }
-        entry.bitmap.flags = c.getInt(IconDB.INDEX_FLAGS);
-        entry.bitmap = entry.bitmap.withFlags(getUserFlagOpLocked(cacheKey.user));
-        return entry.bitmap != null;
-    }
-
-    /**
-     * Returns a cursor for an arbitrary query to the cache db
-     */
-    public synchronized Cursor queryCacheDb(String[] columns, String selection,
-            String[] selectionArgs) {
-        return mIconDb.query(columns, selection, selectionArgs);
-    }
-
-    /**
-     * Cache class to store the actual entries on disk
-     */
-    public static final class IconDB extends SQLiteCacheHelper {
-        // Ensures archived app icons are invalidated after flag is flipped.
-        // TODO: Remove conditional with FLAG_USE_NEW_ICON_FOR_ARCHIVED_APPS
-        private static final int RELEASE_VERSION = forceMonochromeAppIcons() ? 3 : 2;
-
-        public static final String TABLE_NAME = "icons";
-        public static final String COLUMN_ROWID = "rowid";
-        public static final String COLUMN_COMPONENT = "componentName";
-        public static final String COLUMN_USER = "profileId";
-        public static final String COLUMN_FRESHNESS_ID = "freshnessId";
-        public static final String COLUMN_ICON = "icon";
-        public static final String COLUMN_ICON_COLOR = "icon_color";
-        public static final String COLUMN_MONO_ICON = "mono_icon";
-        public static final String COLUMN_FLAGS = "flags";
-        public static final String COLUMN_LABEL = "label";
-
-        public static final String[] COLUMNS_LOW_RES = new String[]{
-                COLUMN_COMPONENT,
-                COLUMN_LABEL,
-                COLUMN_ICON_COLOR,
-                COLUMN_FLAGS};
-        public static final String[] COLUMNS_HIGH_RES = Arrays.copyOf(COLUMNS_LOW_RES,
-                COLUMNS_LOW_RES.length + 2, String[].class);
-
-        static {
-            COLUMNS_HIGH_RES[COLUMNS_LOW_RES.length] = COLUMN_ICON;
-            COLUMNS_HIGH_RES[COLUMNS_LOW_RES.length + 1] = COLUMN_MONO_ICON;
-        }
-
-        private static final int INDEX_TITLE = Arrays.asList(COLUMNS_LOW_RES).indexOf(COLUMN_LABEL);
-        private static final int INDEX_COLOR = Arrays.asList(COLUMNS_LOW_RES)
-                .indexOf(COLUMN_ICON_COLOR);
-        private static final int INDEX_FLAGS = Arrays.asList(COLUMNS_LOW_RES).indexOf(COLUMN_FLAGS);
-        private static final int INDEX_ICON = COLUMNS_LOW_RES.length;
-        private static final int INDEX_MONO_ICON = INDEX_ICON + 1;
-
-        public IconDB(Context context, String dbFileName, int iconPixelSize) {
-            super(context, dbFileName, (RELEASE_VERSION << 16) + iconPixelSize, TABLE_NAME);
-        }
-
-        @Override
-        protected void onCreateTable(SQLiteDatabase db) {
-            db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
-                    + COLUMN_COMPONENT + " TEXT NOT NULL, "
-                    + COLUMN_USER + " INTEGER NOT NULL, "
-                    + COLUMN_FRESHNESS_ID + " TEXT, "
-                    + COLUMN_ICON + " BLOB, "
-                    + COLUMN_MONO_ICON + " BLOB, "
-                    + COLUMN_ICON_COLOR + " INTEGER NOT NULL DEFAULT 0, "
-                    + COLUMN_FLAGS + " INTEGER NOT NULL DEFAULT 0, "
-                    + COLUMN_LABEL + " TEXT, "
-                    + "PRIMARY KEY (" + COLUMN_COMPONENT + ", " + COLUMN_USER + ") "
-                    + ");");
-        }
-    }
-
-    @NonNull
-    private void addOrUpdateCacheDbEntry(
-            @NonNull final BitmapInfo bitmapInfo,
-            @NonNull final CharSequence label,
-            @NonNull final ComponentName key,
-            final long userSerial,
-            @NonNull final String freshnessId) {
-        ContentValues values = new ContentValues();
-        if (bitmapInfo.canPersist()) {
-            values.put(IconDB.COLUMN_ICON, flattenBitmap(bitmapInfo.icon));
-
-            ThemedBitmap themedBitmap = bitmapInfo.getThemedBitmap();
-            values.put(IconDB.COLUMN_MONO_ICON,
-                    themedBitmap != null ? themedBitmap.serialize() : null);
-        } else {
-            values.put(IconDB.COLUMN_ICON, (byte[]) null);
-            values.put(IconDB.COLUMN_MONO_ICON, (byte[]) null);
-        }
-        values.put(IconDB.COLUMN_ICON_COLOR, bitmapInfo.color);
-        values.put(IconDB.COLUMN_FLAGS, bitmapInfo.flags);
-        values.put(IconDB.COLUMN_LABEL, label.toString());
-
-        values.put(IconDB.COLUMN_COMPONENT, key.flattenToString());
-        values.put(IconDB.COLUMN_USER, userSerial);
-        values.put(IconDB.COLUMN_FRESHNESS_ID, freshnessId);
-        mIconDb.insertOrReplace(values);
-    }
-
-    private void assertWorkerThread() {
-        if (Looper.myLooper() != mBgLooper) {
-            throw new IllegalStateException("Cache accessed on wrong thread " + Looper.myLooper());
-        }
-    }
-
-    /** Log to Log.d. Subclasses can override this method to log persistently for debugging. */
-    protected void logdPersistently(String tag, String message, @Nullable Exception e) {
-        Log.d(tag, message, e);
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt
new file mode 100644
index 0000000..780ef80
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.kt
@@ -0,0 +1,682 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.ContentValues
+import android.content.Context
+import android.content.pm.ActivityInfo
+import android.content.pm.ApplicationInfo
+import android.content.pm.LauncherApps
+import android.content.pm.PackageManager
+import android.content.pm.PackageManager.NameNotFoundException
+import android.database.Cursor
+import android.database.sqlite.SQLiteDatabase
+import android.database.sqlite.SQLiteException
+import android.database.sqlite.SQLiteReadOnlyDatabaseException
+import android.graphics.Bitmap
+import android.graphics.Bitmap.Config.HARDWARE
+import android.graphics.BitmapFactory
+import android.graphics.BitmapFactory.Options
+import android.graphics.drawable.Drawable
+import android.os.Handler
+import android.os.Looper
+import android.os.Trace
+import android.os.UserHandle
+import android.text.TextUtils
+import android.util.Log
+import android.util.SparseArray
+import androidx.annotation.VisibleForTesting
+import androidx.annotation.WorkerThread
+import com.android.launcher3.Flags
+import com.android.launcher3.icons.BaseIconFactory
+import com.android.launcher3.icons.BaseIconFactory.IconOptions
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.GraphicsUtils
+import com.android.launcher3.icons.IconProvider
+import com.android.launcher3.icons.SourceHint
+import com.android.launcher3.icons.cache.CacheLookupFlag.Companion.DEFAULT_LOOKUP_FLAG
+import com.android.launcher3.util.ComponentKey
+import com.android.launcher3.util.FlagOp
+import com.android.launcher3.util.SQLiteCacheHelper
+import java.util.function.Supplier
+import kotlin.collections.MutableMap.MutableEntry
+
+abstract class BaseIconCache
+@JvmOverloads
+constructor(
+    @JvmField protected val context: Context,
+    private val dbFileName: String?,
+    private val bgLooper: Looper,
+    private var iconDpi: Int,
+    iconPixelSize: Int,
+    inMemoryCache: Boolean,
+    val iconProvider: IconProvider = IconProvider(context),
+) {
+    class CacheEntry {
+        @JvmField var bitmap: BitmapInfo = BitmapInfo.LOW_RES_INFO
+        @JvmField var title: CharSequence = ""
+        @JvmField var contentDescription: CharSequence = ""
+    }
+
+    private val packageManager: PackageManager = context.packageManager
+
+    private val cache: MutableMap<ComponentKey, CacheEntry?> =
+        if (inMemoryCache) {
+            HashMap(INITIAL_ICON_CACHE_CAPACITY)
+        } else {
+            object : AbstractMutableMap<ComponentKey, CacheEntry?>() {
+                override fun put(key: ComponentKey, value: CacheEntry?): CacheEntry? = value
+
+                override val entries: MutableSet<MutableEntry<ComponentKey, CacheEntry?>> =
+                    mutableSetOf()
+            }
+        }
+
+    val iconUpdateToken = Any()
+
+    @JvmField val workerHandler = Handler(bgLooper)
+
+    @JvmField protected var iconDb = IconDB(context, dbFileName, iconPixelSize)
+
+    private var defaultIcon: BitmapInfo? = null
+    private val userFlagOpMap = SparseArray<FlagOp>()
+    private val userFormatString = SparseArray<String?>()
+
+    private val appInfoCachingLogic =
+        AppInfoCachingLogic(
+            pm = context.packageManager,
+            instantAppResolver = this::isInstantApp,
+            errorLogger = this::logPersistently,
+        )
+
+    init {
+        updateSystemState()
+    }
+
+    /**
+     * Returns the persistable serial number for {@param user}. Subclass should implement proper
+     * caching strategy to avoid making binder call every time.
+     */
+    abstract fun getSerialNumberForUser(user: UserHandle): Long
+
+    /** Return true if the given app is an instant app and should be badged appropriately. */
+    protected abstract fun isInstantApp(info: ApplicationInfo): Boolean
+
+    /** Opens and returns an icon factory. The factory is recycled by the caller. */
+    abstract val iconFactory: BaseIconFactory
+
+    fun updateIconParams(iconDpi: Int, iconPixelSize: Int) =
+        workerHandler.post { updateIconParamsBg(iconDpi, iconPixelSize) }
+
+    @Synchronized
+    private fun updateIconParamsBg(iconDpi: Int, iconPixelSize: Int) {
+        try {
+            this.iconDpi = iconDpi
+            defaultIcon = null
+            userFlagOpMap.clear()
+            iconDb.clear()
+            iconDb.close()
+            iconDb = IconDB(context, dbFileName, iconPixelSize)
+            cache.clear()
+        } catch (e: SQLiteReadOnlyDatabaseException) {
+            // This is known to happen during repeated backup and restores, if the Launcher is in
+            // restricted mode. When the launcher is loading and the backup restore is being cleared
+            // there can be a conflict where one DB is trying to delete the DB file, and the other
+            // is attempting to write to it. The effect is that launcher crashes, then the backup /
+            // restore process fails, then the user's home screen icons fail to restore. Adding this
+            // try / catch will stop the crash, and LoaderTask will sanitize any residual icon data,
+            // leading to a completed backup / restore and a better experience for our customers.
+            Log.e(TAG, "failed to clear the launcher's icon db or cache.", e)
+        }
+    }
+
+    fun getFullResIcon(info: ActivityInfo): Drawable? = iconProvider.getIcon(info, iconDpi)
+
+    /** Remove any records for the supplied ComponentName. */
+    @Synchronized
+    fun remove(componentName: ComponentName, user: UserHandle) =
+        cache.remove(ComponentKey(componentName, user))
+
+    /** Remove any records for the supplied package name from memory. */
+    private fun removeFromMemCacheLocked(packageName: String, user: UserHandle) =
+        cache.keys.removeIf { it.componentName.packageName == packageName && it.user == user }
+
+    /** Removes the entries related to the given package in memory and persistent DB. */
+    @Synchronized
+    fun removeIconsForPkg(packageName: String, user: UserHandle) {
+        removeFromMemCacheLocked(packageName, user)
+        iconDb.delete(
+            "$COLUMN_COMPONENT LIKE ? AND $COLUMN_USER = ?",
+            arrayOf("$packageName/%", getSerialNumberForUser(user).toString()),
+        )
+    }
+
+    fun getUpdateHandler(): IconCacheUpdateHandler {
+        updateSystemState()
+        // Remove all active icon update tasks.
+        workerHandler.removeCallbacksAndMessages(iconUpdateToken)
+        return IconCacheUpdateHandler(this, iconDb, workerHandler)
+    }
+
+    /**
+     * Refreshes the system state definition used to check the validity of the cache. It
+     * incorporates all the properties that can affect the cache like the list of enabled locale and
+     * system-version.
+     */
+    private fun updateSystemState() {
+        iconProvider.updateSystemState()
+        userFormatString.clear()
+    }
+
+    fun getUserBadgedLabel(label: CharSequence, user: UserHandle): CharSequence {
+        val key = user.hashCode()
+        val index = userFormatString.indexOfKey(key)
+        var format: String?
+        if (index < 0) {
+            format = packageManager.getUserBadgedLabel(IDENTITY_FORMAT_STRING, user).toString()
+            if (TextUtils.equals(IDENTITY_FORMAT_STRING, format)) {
+                format = null
+            }
+            userFormatString.put(key, format)
+        } else {
+            format = userFormatString.valueAt(index)
+        }
+        return if (format == null) label else String.format(format, label)
+    }
+
+    /**
+     * Adds/updates an entry into the DB and the in-memory cache. The update is skipped if the entry
+     * fails to load
+     */
+    @Synchronized
+    fun <T : Any> addIconToDBAndMemCache(obj: T, cachingLogic: CachingLogic<T>, userSerial: Long) {
+        val user = cachingLogic.getUser(obj)
+        val componentName = cachingLogic.getComponent(obj)
+        val key = ComponentKey(componentName, user)
+        val bitmapInfo = cachingLogic.loadIcon(context, this, obj)
+
+        // Icon can't be loaded from cachingLogic, which implies alternative icon was loaded
+        // (e.g. fallback icon, default icon). So we drop here since there's no point in caching
+        // an empty entry.
+        if (bitmapInfo.isNullOrLowRes || isDefaultIcon(bitmapInfo, user)) {
+            return
+        }
+        val entryTitle =
+            cachingLogic.getLabel(obj).let {
+                if (it.isNullOrEmpty()) componentName.packageName else it
+            }
+
+        // Only add an entry in memory, if there was already something previously
+        if (cache[key] != null) {
+            val entry = CacheEntry()
+            entry.bitmap = bitmapInfo
+            entry.title = entryTitle
+            entry.contentDescription = getUserBadgedLabel(entryTitle, user)
+            cache[key] = entry
+        }
+
+        val freshnessId = cachingLogic.getFreshnessIdentifier(obj, iconProvider)
+        if (freshnessId != null) {
+            addOrUpdateCacheDbEntry(bitmapInfo, entryTitle, componentName, userSerial, freshnessId)
+        }
+    }
+
+    @Synchronized
+    fun getDefaultIcon(user: UserHandle): BitmapInfo {
+        if (defaultIcon == null) {
+            iconFactory.use { li -> defaultIcon = li.makeDefaultIcon(iconProvider) }
+        }
+        return defaultIcon!!.withFlags(getUserFlagOpLocked(user))
+    }
+
+    protected fun getUserFlagOpLocked(user: UserHandle): FlagOp {
+        val key = user.hashCode()
+        val index = userFlagOpMap.indexOfKey(key)
+        if (index >= 0) {
+            return userFlagOpMap.valueAt(index)
+        } else {
+            iconFactory.use { li ->
+                val op = li.getBitmapFlagOp(IconOptions().setUser(user))
+                userFlagOpMap.put(key, op)
+                return op
+            }
+        }
+    }
+
+    fun isDefaultIcon(icon: BitmapInfo, user: UserHandle) = getDefaultIcon(user).icon == icon.icon
+
+    /**
+     * Retrieves the entry from the cache. If the entry is not present, it creates a new entry. This
+     * method is not thread safe, it must be called from a synchronized method.
+     */
+    @JvmOverloads
+    protected fun <T : Any> cacheLocked(
+        componentName: ComponentName,
+        user: UserHandle,
+        infoProvider: Supplier<T?>,
+        cachingLogic: CachingLogic<T>,
+        lookupFlags: CacheLookupFlag,
+        cursor: Cursor? = null,
+    ): CacheEntry {
+        assertWorkerThread()
+        val cacheKey = ComponentKey(componentName, user)
+        var entry = cache[cacheKey]
+        if (entry == null || entry.bitmap.matchingLookupFlag.isVisuallyLessThan(lookupFlags)) {
+            val addToMemCache = entry != null || !lookupFlags.skipAddToMemCache()
+            entry = CacheEntry()
+            if (addToMemCache) cache[cacheKey] = entry
+            // Check the DB first.
+            val cacheEntryUpdated =
+                if (cursor == null) getEntryFromDBLocked(cacheKey, entry, lookupFlags, cachingLogic)
+                else updateTitleAndIconLocked(cacheKey, entry, cursor, lookupFlags, cachingLogic)
+
+            val obj: T? by lazy { infoProvider.get() }
+            if (!cacheEntryUpdated) {
+                loadFallbackIcon(
+                    obj,
+                    entry,
+                    cachingLogic,
+                    lookupFlags.usePackageIcon(),
+                    /* usePackageTitle= */ true,
+                    componentName,
+                    user,
+                )
+            }
+
+            if (TextUtils.isEmpty(entry.title)) {
+                obj?.let { loadFallbackTitle(it, entry, cachingLogic, user) }
+            }
+        }
+        return entry
+    }
+
+    /** Fallback method for loading an icon bitmap. */
+    protected fun <T : Any> loadFallbackIcon(
+        obj: T?,
+        entry: CacheEntry,
+        cachingLogic: CachingLogic<T>,
+        usePackageIcon: Boolean,
+        usePackageTitle: Boolean,
+        componentName: ComponentName,
+        user: UserHandle,
+    ) {
+        if (obj != null) {
+            entry.bitmap = cachingLogic.loadIcon(context, this, obj)
+        } else {
+            if (usePackageIcon) {
+                val packageEntry = getEntryForPackageLocked(componentName.packageName, user)
+                if (DEBUG) {
+                    Log.d(TAG, "using package default icon for " + componentName.toShortString())
+                }
+                entry.bitmap = packageEntry.bitmap
+                entry.contentDescription = packageEntry.contentDescription
+
+                if (usePackageTitle) {
+                    entry.title = packageEntry.title
+                }
+            }
+        }
+    }
+
+    /** Fallback method for loading an app title. */
+    protected fun <T : Any> loadFallbackTitle(
+        obj: T,
+        entry: CacheEntry,
+        cachingLogic: CachingLogic<T>,
+        user: UserHandle,
+    ) {
+        entry.title =
+            cachingLogic.getLabel(obj).let {
+                if (it.isNullOrEmpty()) cachingLogic.getComponent(obj).packageName else it
+            }
+        entry.contentDescription = getUserBadgedLabel(entry.title, user)
+    }
+
+    @Synchronized
+    fun clearMemoryCache() {
+        assertWorkerThread()
+        cache.clear()
+    }
+
+    /**
+     * Adds a default package entry in the cache. This entry is not persisted and will be removed
+     * when the cache is flushed.
+     */
+    @Synchronized
+    protected fun cachePackageInstallInfo(
+        packageName: String,
+        user: UserHandle,
+        icon: Bitmap?,
+        title: CharSequence?,
+    ) {
+        removeFromMemCacheLocked(packageName, user)
+        val cacheKey = getPackageKey(packageName, user)
+
+        // For icon caching, do not go through DB. Just update the in-memory entry.
+        val entry = cache[cacheKey] ?: CacheEntry()
+        if (!title.isNullOrEmpty()) {
+            entry.title = title
+        }
+
+        if (icon != null) {
+            iconFactory.use { li ->
+                entry.bitmap =
+                    li.createBadgedIconBitmap(
+                        li.createShapedAdaptiveIcon(icon),
+                        IconOptions().setUser(user),
+                    )
+            }
+        }
+        if (!TextUtils.isEmpty(title) && entry.bitmap.icon != null) {
+            cache[cacheKey] = entry
+        }
+    }
+
+    /** Returns the package entry if it has already been cached in memory, null otherwise */
+    protected fun getInMemoryPackageEntryLocked(
+        packageName: String,
+        user: UserHandle,
+    ): CacheEntry? = getInMemoryEntryLocked(getPackageKey(packageName, user))
+
+    @VisibleForTesting
+    fun getInMemoryEntryLocked(key: ComponentKey): CacheEntry? {
+        assertWorkerThread()
+        return cache[key]
+    }
+
+    /**
+     * Gets an entry for the package, which can be used as a fallback entry for various components.
+     * This method is not thread safe, it must be called from a synchronized method.
+     */
+    @WorkerThread
+    protected fun getEntryForPackageLocked(
+        packageName: String,
+        user: UserHandle,
+        lookupFlags: CacheLookupFlag = DEFAULT_LOOKUP_FLAG,
+    ): CacheEntry {
+        assertWorkerThread()
+        val cacheKey = getPackageKey(packageName, user)
+        var entry = cache[cacheKey]
+
+        if (entry == null || entry.bitmap.matchingLookupFlag.isVisuallyLessThan(lookupFlags)) {
+            entry = CacheEntry()
+            var entryUpdated = true
+
+            // Check the DB first.
+            if (!getEntryFromDBLocked(cacheKey, entry, lookupFlags, appInfoCachingLogic)) {
+                try {
+                    val appInfo =
+                        context
+                            .getSystemService(LauncherApps::class.java)!!
+                            .getApplicationInfo(
+                                packageName,
+                                PackageManager.MATCH_UNINSTALLED_PACKAGES,
+                                user,
+                            )
+                    if (appInfo == null) {
+                        throw NameNotFoundException("ApplicationInfo is null").also {
+                            logPersistently(
+                                String.format("ApplicationInfo is null for %s", packageName),
+                                it,
+                            )
+                        }
+                    }
+
+                    // Load the full res icon for the application, but if useLowResIcon is set, then
+                    // only keep the low resolution icon instead of the larger full-sized icon
+                    val iconInfo = appInfoCachingLogic.loadIcon(context, this, appInfo)
+                    entry.bitmap =
+                        if (lookupFlags.useLowRes())
+                            BitmapInfo.of(BitmapInfo.LOW_RES_ICON, iconInfo.color)
+                        else iconInfo
+
+                    loadFallbackTitle(appInfo, entry, appInfoCachingLogic, user)
+
+                    // Add the icon in the DB here, since these do not get written during
+                    // package updates.
+                    appInfoCachingLogic.getFreshnessIdentifier(appInfo, iconProvider)?.let {
+                        freshnessId ->
+                        addOrUpdateCacheDbEntry(
+                            iconInfo,
+                            entry.title,
+                            cacheKey.componentName,
+                            getSerialNumberForUser(user),
+                            freshnessId,
+                        )
+                    }
+                } catch (e: NameNotFoundException) {
+                    if (DEBUG) Log.d(TAG, "Application not installed $packageName")
+                    entryUpdated = false
+                }
+            }
+
+            val shouldAddToCache =
+                !(lookupFlags.skipAddToMemCache() && Flags.restoreArchivedAppIconsFromDb())
+            // Only add a filled-out entry to the cache
+            if (entryUpdated && shouldAddToCache) {
+                cache[cacheKey] = entry
+            }
+        }
+        return entry
+    }
+
+    protected fun getEntryFromDBLocked(
+        cacheKey: ComponentKey,
+        entry: CacheEntry,
+        lookupFlags: CacheLookupFlag,
+        cachingLogic: CachingLogic<*>,
+    ): Boolean {
+        var c: Cursor? = null
+        Trace.beginSection("loadIconIndividually")
+        try {
+            c =
+                iconDb.query(
+                    lookupFlags.toLookupColumns(),
+                    "$COLUMN_COMPONENT = ? AND $COLUMN_USER = ?",
+                    arrayOf(
+                        cacheKey.componentName.flattenToString(),
+                        getSerialNumberForUser(cacheKey.user).toString(),
+                    ),
+                )
+            if (c.moveToNext()) {
+                return updateTitleAndIconLocked(cacheKey, entry, c, lookupFlags, cachingLogic)
+            }
+        } catch (e: SQLiteException) {
+            Log.d(TAG, "Error reading icon cache", e)
+        } finally {
+            c?.close()
+            Trace.endSection()
+        }
+        return false
+    }
+
+    private fun updateTitleAndIconLocked(
+        cacheKey: ComponentKey,
+        entry: CacheEntry,
+        c: Cursor,
+        lookupFlags: CacheLookupFlag,
+        logic: CachingLogic<*>,
+    ): Boolean {
+        // Set the alpha to be 255, so that we never have a wrong color
+        entry.bitmap =
+            BitmapInfo.of(
+                BitmapInfo.LOW_RES_ICON,
+                GraphicsUtils.setColorAlphaBound(c.getInt(INDEX_COLOR), 255),
+            )
+        c.getString(INDEX_TITLE).let {
+            if (it.isNullOrEmpty()) {
+                entry.title = ""
+                entry.contentDescription = ""
+            } else {
+                entry.title = it
+                entry.contentDescription = getUserBadgedLabel(it, cacheKey.user)
+            }
+        }
+
+        if (!lookupFlags.useLowRes()) {
+            try {
+                val data: ByteArray = c.getBlob(INDEX_ICON) ?: return false
+                entry.bitmap =
+                    BitmapInfo.of(
+                        BitmapFactory.decodeByteArray(
+                            data,
+                            0,
+                            data.size,
+                            Options().apply { inPreferredConfig = HARDWARE },
+                        )!!,
+                        entry.bitmap.color,
+                    )
+            } catch (e: Exception) {
+                return false
+            }
+
+            iconFactory.use { factory ->
+                val themeController = factory.themeController
+                val monoIconData = c.getBlob(INDEX_MONO_ICON)
+                if (themeController != null && monoIconData != null) {
+                    entry.bitmap.themedBitmap =
+                        themeController.decode(
+                            data = monoIconData,
+                            info = entry.bitmap,
+                            factory = factory,
+                            sourceHint =
+                                SourceHint(cacheKey, logic, c.getString(INDEX_FRESHNESS_ID)),
+                        )
+                }
+            }
+        }
+        entry.bitmap.flags = c.getInt(INDEX_FLAGS)
+        entry.bitmap = entry.bitmap.withFlags(getUserFlagOpLocked(cacheKey.user))
+        return true
+    }
+
+    private fun addOrUpdateCacheDbEntry(
+        bitmapInfo: BitmapInfo,
+        label: CharSequence,
+        key: ComponentName,
+        userSerial: Long,
+        freshnessId: String,
+    ) {
+        val values = ContentValues()
+        if (bitmapInfo.canPersist()) {
+            values.put(COLUMN_ICON, GraphicsUtils.flattenBitmap(bitmapInfo.icon))
+            values.put(COLUMN_MONO_ICON, bitmapInfo.themedBitmap?.serialize())
+        } else {
+            values.put(COLUMN_ICON, null as ByteArray?)
+            values.put(COLUMN_MONO_ICON, null as ByteArray?)
+        }
+
+        values.put(COLUMN_ICON_COLOR, bitmapInfo.color)
+        values.put(COLUMN_FLAGS, bitmapInfo.flags)
+        values.put(COLUMN_LABEL, label.toString())
+
+        values.put(COLUMN_COMPONENT, key.flattenToString())
+        values.put(COLUMN_USER, userSerial)
+        values.put(COLUMN_FRESHNESS_ID, freshnessId)
+        iconDb.insertOrReplace(values)
+    }
+
+    private fun assertWorkerThread() {
+        check(Looper.myLooper() == bgLooper) {
+            "Cache accessed on wrong thread " + Looper.myLooper()
+        }
+    }
+
+    /** Log to Log.d. Subclasses can override this method to log persistently for debugging. */
+    protected open fun logPersistently(message: String, e: Exception?) {
+        Log.d(TAG, message, e)
+    }
+
+    /** Cache class to store the actual entries on disk */
+    class IconDB(context: Context, dbFileName: String?, iconPixelSize: Int) :
+        SQLiteCacheHelper(
+            context,
+            dbFileName,
+            (RELEASE_VERSION shl 16) + iconPixelSize,
+            TABLE_NAME,
+        ) {
+
+        override fun onCreateTable(db: SQLiteDatabase) {
+            db.execSQL(
+                ("CREATE TABLE IF NOT EXISTS $TABLE_NAME (" +
+                    "$COLUMN_COMPONENT TEXT NOT NULL, " +
+                    "$COLUMN_USER INTEGER NOT NULL, " +
+                    "$COLUMN_FRESHNESS_ID TEXT, " +
+                    "$COLUMN_ICON BLOB, " +
+                    "$COLUMN_MONO_ICON BLOB, " +
+                    "$COLUMN_ICON_COLOR INTEGER NOT NULL DEFAULT 0, " +
+                    "$COLUMN_FLAGS INTEGER NOT NULL DEFAULT 0, " +
+                    "$COLUMN_LABEL TEXT, " +
+                    "PRIMARY KEY ($COLUMN_COMPONENT, $COLUMN_USER) " +
+                    ");")
+            )
+        }
+    }
+
+    companion object {
+        protected const val TAG = "BaseIconCache"
+        private const val DEBUG = false
+
+        private const val INITIAL_ICON_CACHE_CAPACITY = 50
+
+        // A format string which returns the original string as is.
+        private const val IDENTITY_FORMAT_STRING = "%1\$s"
+
+        // Empty class name is used for storing package default entry.
+        const val EMPTY_CLASS_NAME: String = "."
+
+        fun getPackageKey(packageName: String, user: UserHandle) =
+            ComponentKey(ComponentName(packageName, packageName + EMPTY_CLASS_NAME), user)
+
+        // Ensures themed bitmaps in the icon cache are invalidated
+        @JvmField val RELEASE_VERSION = if (Flags.forceMonochromeAppIcons()) 10 else 9
+
+        @JvmField val TABLE_NAME = "icons"
+        @JvmField val COLUMN_ROWID = "rowid"
+        @JvmField val COLUMN_COMPONENT = "componentName"
+        @JvmField val COLUMN_USER = "profileId"
+        @JvmField val COLUMN_FRESHNESS_ID = "freshnessId"
+        @JvmField val COLUMN_ICON = "icon"
+        @JvmField val COLUMN_ICON_COLOR = "icon_color"
+        @JvmField val COLUMN_MONO_ICON = "mono_icon"
+        @JvmField val COLUMN_FLAGS = "flags"
+        @JvmField val COLUMN_LABEL = "label"
+
+        @JvmField
+        val COLUMNS_LOW_RES =
+            arrayOf(COLUMN_COMPONENT, COLUMN_LABEL, COLUMN_ICON_COLOR, COLUMN_FLAGS)
+
+        @JvmField
+        val COLUMNS_HIGH_RES =
+            COLUMNS_LOW_RES.copyOf(COLUMNS_LOW_RES.size + 3).apply {
+                this[size - 3] = COLUMN_ICON
+                this[size - 2] = COLUMN_MONO_ICON
+                this[size - 1] = COLUMN_FRESHNESS_ID
+            }
+
+        @JvmField val INDEX_TITLE = COLUMNS_HIGH_RES.indexOf(COLUMN_LABEL)
+        @JvmField val INDEX_COLOR = COLUMNS_HIGH_RES.indexOf(COLUMN_ICON_COLOR)
+        @JvmField val INDEX_FLAGS = COLUMNS_HIGH_RES.indexOf(COLUMN_FLAGS)
+        @JvmField val INDEX_ICON = COLUMNS_HIGH_RES.indexOf(COLUMN_ICON)
+        @JvmField val INDEX_MONO_ICON = COLUMNS_HIGH_RES.indexOf(COLUMN_MONO_ICON)
+        @JvmField val INDEX_FRESHNESS_ID = COLUMNS_HIGH_RES.indexOf(COLUMN_FRESHNESS_ID)
+
+        @JvmStatic
+        fun CacheLookupFlag.toLookupColumns() =
+            if (useLowRes()) COLUMNS_LOW_RES else COLUMNS_HIGH_RES
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt
new file mode 100644
index 0000000..42fda24
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CacheLookupFlag.kt
@@ -0,0 +1,72 @@
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
+package com.android.launcher3.icons.cache
+
+import androidx.annotation.IntDef
+import kotlin.annotation.AnnotationRetention.SOURCE
+
+/** Flags to control cache lookup behavior */
+data class CacheLookupFlag private constructor(@LookupFlag private val flag: Int) {
+
+    /**
+     * Cache will try to load the low res version of the entry unless a high-res is already in
+     * memory
+     */
+    fun useLowRes() = hasFlag(USE_LOW_RES)
+
+    @JvmOverloads fun withUseLowRes(useLowRes: Boolean = true) = updateMask(USE_LOW_RES, useLowRes)
+
+    /** Cache will try to lookup the package entry for the item, if the object entry fails */
+    fun usePackageIcon() = hasFlag(USE_PACKAGE_ICON)
+
+    @JvmOverloads
+    fun withUsePackageIcon(usePackageIcon: Boolean = true) =
+        updateMask(USE_PACKAGE_ICON, usePackageIcon)
+
+    /**
+     * Entry will not be added to the memory cache if it was not already added by a previous lookup
+     */
+    fun skipAddToMemCache() = hasFlag(SKIP_ADD_TO_MEM_CACHE)
+
+    @JvmOverloads
+    fun withSkipAddToMemCache(skipAddToMemCache: Boolean = true) =
+        updateMask(SKIP_ADD_TO_MEM_CACHE, skipAddToMemCache)
+
+    private fun hasFlag(@LookupFlag mask: Int) = flag.and(mask) != 0
+
+    private fun updateMask(@LookupFlag mask: Int, addMask: Boolean) =
+        if (addMask) flagCache[flag.or(mask)] else flagCache[flag.and(mask.inv())]
+
+    /** Returns `true` if this flag has less UI information then [other] */
+    fun isVisuallyLessThan(other: CacheLookupFlag): Boolean {
+        return useLowRes() && !other.useLowRes()
+    }
+
+    @Retention(SOURCE)
+    @IntDef(value = [USE_LOW_RES, USE_PACKAGE_ICON, SKIP_ADD_TO_MEM_CACHE], flag = true)
+    /** Various options to control cache lookup */
+    private annotation class LookupFlag
+
+    companion object {
+        private const val USE_LOW_RES: Int = 1 shl 0
+        private const val USE_PACKAGE_ICON: Int = 1 shl 1
+        private const val SKIP_ADD_TO_MEM_CACHE: Int = 1 shl 2
+
+        private val flagCache = Array(8) { CacheLookupFlag(it) }
+
+        @JvmField val DEFAULT_LOOKUP_FLAG = CacheLookupFlag(0)
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
index 0266939..f583135 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
@@ -35,7 +35,10 @@ object CachedObjectCachingLogic : CachingLogic<CachedObject> {
     override fun loadIcon(context: Context, cache: BaseIconCache, info: CachedObject): BitmapInfo {
         val d = info.getFullResIcon(cache) ?: return BitmapInfo.LOW_RES_INFO
         cache.iconFactory.use { li ->
-            return li.createBadgedIconBitmap(d, IconOptions().setUser(info.user))
+            return li.createBadgedIconBitmap(
+                d,
+                IconOptions().setUser(info.user).setSourceHint(getSourceHint(info, cache)),
+            )
         }
     }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
deleted file mode 100644
index 6dce880..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
+++ /dev/null
@@ -1,60 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-package com.android.launcher3.icons.cache;
-
-import android.content.ComponentName;
-import android.content.Context;
-import android.content.pm.ApplicationInfo;
-import android.os.UserHandle;
-
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-
-import com.android.launcher3.icons.BitmapInfo;
-import com.android.launcher3.icons.IconProvider;
-
-public interface CachingLogic<T> {
-
-    @NonNull
-    ComponentName getComponent(@NonNull final T object);
-
-    @NonNull
-    UserHandle getUser(@NonNull final T object);
-
-    /**
-     * Loads the user visible label for the object
-     */
-    @Nullable
-    CharSequence getLabel(@NonNull final T object);
-
-    /**
-     * Returns the application info associated with the object. This is used to maintain the
-     * "freshness" of the disk cache. If null, the item will not be persisted to the disk
-     */
-    @Nullable
-    ApplicationInfo getApplicationInfo(@NonNull T object);
-
-    @NonNull
-    BitmapInfo loadIcon(@NonNull Context context, @NonNull BaseIconCache cache, @NonNull T object);
-
-    /**
-     * Returns a persistable string that can be used to indicate indicate the correctness of the
-     * cache for the provided item
-     */
-    @Nullable
-    String getFreshnessIdentifier(@NonNull T item, @NonNull IconProvider iconProvider);
-
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.kt
new file mode 100644
index 0000000..98149d7
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.kt
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.Context
+import android.content.pm.ApplicationInfo
+import android.os.UserHandle
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconProvider
+import com.android.launcher3.icons.SourceHint
+import com.android.launcher3.util.ComponentKey
+
+interface CachingLogic<T> {
+    /** Returns the source hint for this object that can be sued by theme controllers */
+    fun getSourceHint(item: T, cache: BaseIconCache): SourceHint {
+        return SourceHint(
+            key = ComponentKey(getComponent(item), getUser(item)),
+            logic = this,
+            freshnessId = getFreshnessIdentifier(item, cache.iconProvider),
+        )
+    }
+
+    fun getComponent(item: T): ComponentName
+
+    fun getUser(item: T): UserHandle
+
+    /** Loads the user visible label for the object */
+    fun getLabel(item: T): CharSequence?
+
+    /**
+     * Returns the application info associated with the object. This is used to maintain the
+     * "freshness" of the disk cache. If null, the item will not be persisted to the disk
+     */
+    fun getApplicationInfo(item: T): ApplicationInfo?
+
+    fun loadIcon(context: Context, cache: BaseIconCache, item: T): BitmapInfo
+
+    /**
+     * Returns a persistable string that can be used to indicate indicate the correctness of the
+     * cache for the provided item
+     */
+    fun getFreshnessIdentifier(item: T, iconProvider: IconProvider): String?
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt
index 9db9a09..a44b11f 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt
@@ -23,7 +23,6 @@ import android.os.SystemClock
 import android.os.UserHandle
 import android.util.ArrayMap
 import android.util.Log
-import com.android.launcher3.icons.cache.BaseIconCache.IconDB
 import com.android.launcher3.util.ComponentKey
 import com.android.launcher3.util.SQLiteCacheHelper
 import java.util.ArrayDeque
@@ -107,19 +106,19 @@ class IconCacheUpdateHandler(
             cacheDb
                 .query(
                     arrayOf(
-                        IconDB.COLUMN_ROWID,
-                        IconDB.COLUMN_COMPONENT,
-                        IconDB.COLUMN_FRESHNESS_ID,
+                        BaseIconCache.COLUMN_ROWID,
+                        BaseIconCache.COLUMN_COMPONENT,
+                        BaseIconCache.COLUMN_FRESHNESS_ID,
                     ),
-                    "${IconDB.COLUMN_USER} = ? ",
+                    "${BaseIconCache.COLUMN_USER} = ? ",
                     arrayOf(userSerial.toString()),
                 )
                 .use { c ->
                     var ignorePackages = packagesToIgnore[user] ?: emptySet()
 
-                    val indexComponent = c.getColumnIndex(IconDB.COLUMN_COMPONENT)
-                    val indexFreshnessId = c.getColumnIndex(IconDB.COLUMN_FRESHNESS_ID)
-                    val rowIndex = c.getColumnIndex(IconDB.COLUMN_ROWID)
+                    val indexComponent = c.getColumnIndex(BaseIconCache.COLUMN_COMPONENT)
+                    val indexFreshnessId = c.getColumnIndex(BaseIconCache.COLUMN_FRESHNESS_ID)
+                    val rowIndex = c.getColumnIndex(BaseIconCache.COLUMN_ROWID)
 
                     while (c.moveToNext()) {
                         val rowId = c.getInt(rowIndex)
@@ -232,7 +231,7 @@ class IconCacheUpdateHandler(
         // Commit all deletes
         if (itemsToDelete.isNotEmpty()) {
             val r = itemsToDelete.joinToString { it.rowId.toString() }
-            cacheDb.delete("${IconDB.COLUMN_ROWID} IN ($r)", null)
+            cacheDb.delete("${BaseIconCache.COLUMN_ROWID} IN ($r)", null)
             Log.d(TAG, "Deleting obsolete entries, count=" + itemsToDelete.size)
         }
     }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
index 85902d2..bfaa925 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
@@ -45,9 +45,13 @@ object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
     ): BitmapInfo {
         cache.iconFactory.use { li ->
             val iconOptions: IconOptions = IconOptions().setUser(info.user)
-            iconOptions.setIsArchived(
-                useNewIconForArchivedApps() && VERSION.SDK_INT >= 35 && info.activityInfo.isArchived
-            )
+            iconOptions
+                .setIsArchived(
+                    useNewIconForArchivedApps() &&
+                        VERSION.SDK_INT >= 35 &&
+                        info.activityInfo.isArchived
+                )
+                .setSourceHint(getSourceHint(info, cache))
             val iconDrawable = cache.iconProvider.getIcon(info.activityInfo, li.fullResIconDpi)
             if (context.packageManager.isDefaultApplicationIcon(iconDrawable)) {
                 Log.w(
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
index cdaf05f..1c73dac 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
@@ -25,6 +25,8 @@ import android.graphics.BlendMode.SRC_IN
 import android.graphics.BlendModeColorFilter
 import android.graphics.Canvas
 import android.graphics.Color
+import android.graphics.Path
+import android.graphics.Rect
 import android.graphics.drawable.AdaptiveIconDrawable
 import android.graphics.drawable.BitmapDrawable
 import android.graphics.drawable.ColorDrawable
@@ -33,33 +35,42 @@ import android.graphics.drawable.InsetDrawable
 import android.os.Build
 import com.android.launcher3.Flags
 import com.android.launcher3.icons.BaseIconFactory
+import com.android.launcher3.icons.BaseIconFactory.MODE_ALPHA
 import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconNormalizer.ICON_VISIBLE_AREA_FACTOR
 import com.android.launcher3.icons.IconThemeController
 import com.android.launcher3.icons.MonochromeIconFactory
+import com.android.launcher3.icons.SourceHint
 import com.android.launcher3.icons.ThemedBitmap
-import com.android.launcher3.icons.mono.ThemedIconDrawable.Companion.getColors
 import java.nio.ByteBuffer
 
 @TargetApi(Build.VERSION_CODES.TIRAMISU)
-class MonoIconThemeController : IconThemeController {
+class MonoIconThemeController(
+    private val colorProvider: (Context) -> IntArray = ThemedIconDrawable.Companion::getColors
+) : IconThemeController {
+
+    override val themeID = "with-theme"
 
     override fun createThemedBitmap(
         icon: AdaptiveIconDrawable,
         info: BitmapInfo,
         factory: BaseIconFactory,
+        sourceHint: SourceHint?,
     ): ThemedBitmap? {
-        val mono = getMonochromeDrawable(icon, info)
+        val mono =
+            getMonochromeDrawable(
+                icon,
+                info,
+                factory.getShapePath(icon, Rect(0, 0, info.icon.width, info.icon.height)),
+                factory.iconScale,
+                sourceHint?.isFileDrawable ?: false,
+                factory.shouldForceThemeIcon(),
+            )
         if (mono != null) {
-            val scale =
-                factory.normalizer.getScale(
-                    AdaptiveIconDrawable(ColorDrawable(Color.BLACK), null),
-                    null,
-                    null,
-                    null,
-                )
             return MonoThemedBitmap(
-                factory.createIconBitmap(mono, scale, BaseIconFactory.MODE_ALPHA),
+                factory.createIconBitmap(mono, ICON_VISIBLE_AREA_FACTOR, MODE_ALPHA),
                 factory.whiteShadowLayer,
+                colorProvider,
             )
         }
         return null
@@ -70,13 +81,20 @@ class MonoIconThemeController : IconThemeController {
      *
      * @param base the original icon
      */
-    private fun getMonochromeDrawable(base: AdaptiveIconDrawable, info: BitmapInfo): Drawable? {
+    private fun getMonochromeDrawable(
+        base: AdaptiveIconDrawable,
+        info: BitmapInfo,
+        shapePath: Path,
+        iconScale: Float,
+        isFileDrawable: Boolean,
+        shouldForceThemeIcon: Boolean,
+    ): Drawable? {
         val mono = base.monochrome
         if (mono != null) {
-            return ClippedMonoDrawable(mono)
+            return ClippedMonoDrawable(mono, shapePath, iconScale)
         }
-        if (Flags.forceMonochromeAppIcons()) {
-            return MonochromeIconFactory(info.icon.width).wrap(base)
+        if (Flags.forceMonochromeAppIcons() && shouldForceThemeIcon && !isFileDrawable) {
+            return MonochromeIconFactory(info.icon.width).wrap(base, shapePath, iconScale)
         }
         return null
     }
@@ -85,6 +103,7 @@ class MonoIconThemeController : IconThemeController {
         data: ByteArray,
         info: BitmapInfo,
         factory: BaseIconFactory,
+        sourceHint: SourceHint,
     ): ThemedBitmap? {
         val icon = info.icon
         if (data.size != icon.height * icon.width) return null
@@ -97,7 +116,7 @@ class MonoIconThemeController : IconThemeController {
             monoBitmap.recycle()
             monoBitmap = hwMonoBitmap
         }
-        return MonoThemedBitmap(monoBitmap, factory.whiteShadowLayer)
+        return MonoThemedBitmap(monoBitmap, factory.whiteShadowLayer, colorProvider)
     }
 
     override fun createThemedAdaptiveIcon(
@@ -105,7 +124,7 @@ class MonoIconThemeController : IconThemeController {
         originalIcon: AdaptiveIconDrawable,
         info: BitmapInfo?,
     ): AdaptiveIconDrawable? {
-        val colors = getColors(context)
+        val colors = colorProvider(context)
         originalIcon.mutate()
         var monoDrawable = originalIcon.monochrome?.apply { setTint(colors[1]) }
 
@@ -130,14 +149,23 @@ class MonoIconThemeController : IconThemeController {
         return monoDrawable?.let { AdaptiveIconDrawable(ColorDrawable(colors[0]), it) }
     }
 
-    class ClippedMonoDrawable(base: Drawable?) :
-        InsetDrawable(base, -AdaptiveIconDrawable.getExtraInsetFraction()) {
+    class ClippedMonoDrawable(
+        base: Drawable?,
+        private val shapePath: Path,
+        private val iconScale: Float,
+    ) : InsetDrawable(base, -AdaptiveIconDrawable.getExtraInsetFraction()) {
+        // TODO(b/399666950): remove this after launcher icon shapes is fully enabled
         private val mCrop = AdaptiveIconDrawable(ColorDrawable(Color.BLACK), null)
 
         override fun draw(canvas: Canvas) {
             mCrop.bounds = bounds
             val saveCount = canvas.save()
-            canvas.clipPath(mCrop.iconMask)
+            if (Flags.enableLauncherIconShapes()) {
+                canvas.clipPath(shapePath)
+                canvas.scale(iconScale, iconScale, bounds.width() / 2f, bounds.height() / 2f)
+            } else {
+                canvas.clipPath(mCrop.iconMask)
+            }
             super.draw(canvas)
             canvas.restoreToCount(saveCount)
         }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt
index dc6030e..2edd0b7 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt
@@ -24,10 +24,14 @@ import com.android.launcher3.icons.ThemedBitmap
 import com.android.launcher3.icons.mono.ThemedIconDrawable.ThemedConstantState
 import java.nio.ByteBuffer
 
-class MonoThemedBitmap(val mono: Bitmap, private val whiteShadowLayer: Bitmap) : ThemedBitmap {
+class MonoThemedBitmap(
+    val mono: Bitmap,
+    private val whiteShadowLayer: Bitmap,
+    private val colorProvider: (Context) -> IntArray = ThemedIconDrawable.Companion::getColors,
+) : ThemedBitmap {
 
     override fun newDrawable(info: BitmapInfo, context: Context): FastBitmapDrawable {
-        val colors = ThemedIconDrawable.getColors(context)
+        val colors = colorProvider(context)
         return ThemedConstantState(info, mono, whiteShadowLayer, colors[0], colors[1]).newDrawable()
     }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
index 59fb245..64aeb35 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
@@ -28,8 +28,7 @@ import com.android.launcher3.icons.R
 
 /** Class to handle monochrome themed app icons */
 class ThemedIconDrawable(constantState: ThemedConstantState) :
-    FastBitmapDrawable(constantState.getBitmap(), constantState.colorFg) {
-    val bitmapInfo = constantState.bitmapInfo
+    FastBitmapDrawable(constantState.getBitmapInfo()) {
     private val colorFg = constantState.colorFg
     private val colorBg = constantState.colorBg
 
@@ -66,21 +65,21 @@ class ThemedIconDrawable(constantState: ThemedConstantState) :
     override fun isThemed() = true
 
     override fun newConstantState() =
-        ThemedConstantState(bitmapInfo, monoIcon, bgBitmap, colorBg, colorFg)
+        ThemedConstantState(mBitmapInfo, monoIcon, bgBitmap, colorBg, colorFg)
 
     override fun getIconColor() = colorFg
 
     class ThemedConstantState(
-        val bitmapInfo: BitmapInfo,
+        bitmapInfo: BitmapInfo,
         val mono: Bitmap,
         val whiteShadowLayer: Bitmap,
         val colorBg: Int,
         val colorFg: Int,
-    ) : FastBitmapConstantState(bitmapInfo.icon, bitmapInfo.color) {
+    ) : FastBitmapConstantState(bitmapInfo) {
 
         public override fun createDrawable() = ThemedIconDrawable(this)
 
-        fun getBitmap(): Bitmap = mBitmap
+        fun getBitmapInfo(): BitmapInfo = mBitmapInfo
     }
 
     companion object {
diff --git a/iconloaderlib/src_full_lib/com/android/launcher3/icons/SimpleIconCache.java b/iconloaderlib/src_full_lib/com/android/launcher3/icons/SimpleIconCache.java
index 63ba887..af2aff8 100644
--- a/iconloaderlib/src_full_lib/com/android/launcher3/icons/SimpleIconCache.java
+++ b/iconloaderlib/src_full_lib/com/android/launcher3/icons/SimpleIconCache.java
@@ -66,7 +66,7 @@ public class SimpleIconCache extends BaseIconCache {
     }
 
     @Override
-    protected long getSerialNumberForUser(@NonNull UserHandle user) {
+    public long getSerialNumberForUser(@NonNull UserHandle user) {
         synchronized (mUserSerialMap) {
             int index = mUserSerialMap.indexOfKey(user.getIdentifier());
             if (index >= 0) {
@@ -92,7 +92,7 @@ public class SimpleIconCache extends BaseIconCache {
     @NonNull
     @Override
     public BaseIconFactory getIconFactory() {
-        return IconFactory.obtain(mContext);
+        return IconFactory.obtain(context);
     }
 
     public static SimpleIconCache getIconCache(Context context) {
diff --git a/mechanics/Android.bp b/mechanics/Android.bp
index ae00b5f..a091c09 100644
--- a/mechanics/Android.bp
+++ b/mechanics/Android.bp
@@ -31,7 +31,9 @@ android_library {
     min_sdk_version: "current",
     static_libs: [
         "androidx.compose.runtime_runtime",
+        "androidx.compose.material3_material3",
         "androidx.compose.ui_ui-util",
+        "androidx.compose.foundation_foundation-layout",
     ],
     srcs: [
         ":mechanics-srcs",
diff --git a/mechanics/benchmark/AndroidManifest.xml b/mechanics/benchmark/AndroidManifest.xml
new file mode 100644
index 0000000..405595c
--- /dev/null
+++ b/mechanics/benchmark/AndroidManifest.xml
@@ -0,0 +1,15 @@
+<?xml version="1.0" encoding="utf-8"?>
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools">
+
+    <!--
+      Important: disable debugging for accurate performance results
+
+      In a com.android.library project, this flag must be disabled from this
+      manifest, as it is not possible to override this flag from Gradle.
+    -->
+    <application
+        android:debuggable="false"
+        tools:ignore="HardcodedDebugMode"
+        tools:replace="android:debuggable" />
+</manifest>
\ No newline at end of file
diff --git a/mechanics/benchmark/benchmark-proguard-rules.pro b/mechanics/benchmark/benchmark-proguard-rules.pro
new file mode 100644
index 0000000..e4061d2
--- /dev/null
+++ b/mechanics/benchmark/benchmark-proguard-rules.pro
@@ -0,0 +1,37 @@
+# Add project specific ProGuard rules here.
+# You can control the set of applied configuration files using the
+# proguardFiles setting in build.gradle.
+#
+# For more details, see
+#   http://developer.android.com/guide/developing/tools/proguard.html
+
+# If your project uses WebView with JS, uncomment the following
+# and specify the fully qualified class name to the JavaScript interface
+# class:
+#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
+#   public *;
+#}
+
+# Uncomment this to preserve the line number information for
+# debugging stack traces.
+#-keepattributes SourceFile,LineNumberTable
+
+# If you keep the line number information, uncomment this to
+# hide the original source file name.
+#-renamesourcefileattribute SourceFile
+
+-dontobfuscate
+
+-ignorewarnings
+
+-keepattributes *Annotation*
+
+-dontnote junit.framework.**
+-dontnote junit.runner.**
+
+-dontwarn androidx.test.**
+-dontwarn org.junit.**
+-dontwarn org.hamcrest.**
+-dontwarn com.squareup.javawriter.JavaWriter
+
+-keepclasseswithmembers @org.junit.runner.RunWith public class *
\ No newline at end of file
diff --git a/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt
new file mode 100644
index 0000000..2c38860
--- /dev/null
+++ b/mechanics/benchmark/tests/src/com/android/mechanics/benchmark/MotionValueBenchmark.kt
@@ -0,0 +1,81 @@
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
+package com.android.mechanics.benchmark
+
+import androidx.benchmark.junit4.BenchmarkRule
+import androidx.benchmark.junit4.measureRepeated
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.DistanceGestureContext
+import com.android.mechanics.MotionValue
+import com.android.mechanics.spec.InputDirection
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+/** Benchmark, which will execute on an Android device. Previous results: go/mm-microbenchmarks */
+@RunWith(AndroidJUnit4::class)
+class MotionValueBenchmark {
+    @get:Rule val benchmarkRule = BenchmarkRule()
+
+    @Test
+    fun createMotionValue() {
+        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
+        val currentInput = { 0f }
+        benchmarkRule.measureRepeated { MotionValue(currentInput, gestureContext) }
+    }
+
+    @Test
+    fun changeInput_readOutput() {
+        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
+        val a = mutableFloatStateOf(0f)
+        val motionValue = MotionValue(a::floatValue, gestureContext)
+
+        benchmarkRule.measureRepeated {
+            runWithMeasurementDisabled { a.floatValue += 1f }
+            motionValue.floatValue
+        }
+    }
+
+    @Test
+    fun readOutputMultipleTimes() {
+        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
+        val a = mutableFloatStateOf(0f)
+        val motionValue = MotionValue(a::floatValue, gestureContext)
+
+        benchmarkRule.measureRepeated {
+            runWithMeasurementDisabled {
+                a.floatValue += 1f
+                motionValue.output
+            }
+            motionValue.output
+        }
+    }
+
+    @Test
+    fun readOutputMultipleTimesMeasureAll() {
+        val gestureContext = DistanceGestureContext(0f, InputDirection.Max, 2f)
+        val currentInput = mutableFloatStateOf(0f)
+        val motionValue = MotionValue(currentInput::floatValue, gestureContext)
+
+        benchmarkRule.measureRepeated {
+            currentInput.floatValue += 1f
+            motionValue.output
+            motionValue.output
+        }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/GestureContext.kt b/mechanics/src/com/android/mechanics/GestureContext.kt
index 00665f8..88e9ef8 100644
--- a/mechanics/src/com/android/mechanics/GestureContext.kt
+++ b/mechanics/src/com/android/mechanics/GestureContext.kt
@@ -52,16 +52,27 @@ interface GestureContext {
     /**
      * The gesture distance of the current gesture, in pixels.
      *
-     * Used solely for the [GestureDistance] [Guarantee]. Can be hard-coded to a static value if
+     * Used solely for the [GestureDragDelta] [Guarantee]. Can be hard-coded to a static value if
      * this type of [Guarantee] is not used.
      */
-    val distance: Float
+    val dragOffset: Float
+}
+
+/**
+ * [GestureContext] with a mutable [dragOffset].
+ *
+ * The implementation class defines whether the [direction] is updated accordingly.
+ */
+interface MutableDragOffsetGestureContext : GestureContext {
+    /** The gesture distance of the current gesture, in pixels. */
+    override var dragOffset: Float
 }
 
 /** [GestureContext] implementation for manually set values. */
-class ProvidedGestureContext(direction: InputDirection, distance: Float) : GestureContext {
+class ProvidedGestureContext(dragOffset: Float, direction: InputDirection) :
+    MutableDragOffsetGestureContext {
     override var direction by mutableStateOf(direction)
-    override var distance by mutableFloatStateOf(distance)
+    override var dragOffset by mutableFloatStateOf(dragOffset)
 }
 
 /**
@@ -70,16 +81,16 @@ class ProvidedGestureContext(direction: InputDirection, distance: Float) : Gestu
  * The direction is determined from the gesture input, where going further than
  * [directionChangeSlop] in the opposite direction toggles the direction.
  *
- * @param initialDistance The initial [distance] of the [GestureContext]
+ * @param initialDragOffset The initial [dragOffset] of the [GestureContext]
  * @param initialDirection The initial [direction] of the [GestureContext]
- * @param directionChangeSlop the amount [distance] must be moved in the opposite direction for the
- *   [direction] to flip.
+ * @param directionChangeSlop the amount [dragOffset] must be moved in the opposite direction for
+ *   the [direction] to flip.
  */
 class DistanceGestureContext(
-    initialDistance: Float,
+    initialDragOffset: Float,
     initialDirection: InputDirection,
     directionChangeSlop: Float,
-) : GestureContext {
+) : MutableDragOffsetGestureContext {
     init {
         require(directionChangeSlop > 0) {
             "directionChangeSlop must be greater than 0, was $directionChangeSlop"
@@ -89,37 +100,38 @@ class DistanceGestureContext(
     override var direction by mutableStateOf(initialDirection)
         private set
 
-    private var furthestDistance by mutableFloatStateOf(initialDistance)
-    private var _distance by mutableFloatStateOf(initialDistance)
+    private var furthestDragOffset by mutableFloatStateOf(initialDragOffset)
+
+    private var _dragOffset by mutableFloatStateOf(initialDragOffset)
 
-    override var distance: Float
-        get() = _distance
+    override var dragOffset: Float
+        get() = _dragOffset
         /**
-         * Updates the [distance].
+         * Updates the [dragOffset].
          *
          * This flips the [direction], if the [value] is further than [directionChangeSlop] away
          * from the furthest recorded value regarding to the current [direction].
          */
         set(value) {
-            _distance = value
+            _dragOffset = value
             this.direction =
                 when (direction) {
                     InputDirection.Max -> {
-                        if (furthestDistance - value > directionChangeSlop) {
-                            furthestDistance = value
+                        if (furthestDragOffset - value > directionChangeSlop) {
+                            furthestDragOffset = value
                             InputDirection.Min
                         } else {
-                            furthestDistance = max(value, furthestDistance)
+                            furthestDragOffset = max(value, furthestDragOffset)
                             InputDirection.Max
                         }
                     }
 
                     InputDirection.Min -> {
-                        if (value - furthestDistance > directionChangeSlop) {
-                            furthestDistance = value
+                        if (value - furthestDragOffset > directionChangeSlop) {
+                            furthestDragOffset = value
                             InputDirection.Max
                         } else {
-                            furthestDistance = min(value, furthestDistance)
+                            furthestDragOffset = min(value, furthestDragOffset)
                             InputDirection.Min
                         }
                     }
@@ -143,14 +155,14 @@ class DistanceGestureContext(
 
             when (direction) {
                 InputDirection.Max -> {
-                    if (furthestDistance - distance > directionChangeSlop) {
-                        furthestDistance = distance
+                    if (furthestDragOffset - dragOffset > directionChangeSlop) {
+                        furthestDragOffset = dragOffset
                         direction = InputDirection.Min
                     }
                 }
                 InputDirection.Min -> {
-                    if (distance - furthestDistance > directionChangeSlop) {
-                        furthestDistance = value
+                    if (dragOffset - furthestDragOffset > directionChangeSlop) {
+                        furthestDragOffset = value
                         direction = InputDirection.Max
                     }
                 }
@@ -158,14 +170,14 @@ class DistanceGestureContext(
         }
 
     /**
-     * Sets [distance] and [direction] to the specified values.
+     * Sets [dragOffset] and [direction] to the specified values.
      *
-     * This also resets memoized [furthestDistance], which is used to determine the direction
+     * This also resets memoized [furthestDragOffset], which is used to determine the direction
      * change.
      */
-    fun reset(distance: Float, direction: InputDirection) {
-        this.distance = distance
+    fun reset(dragOffset: Float, direction: InputDirection) {
+        this.dragOffset = dragOffset
         this.direction = direction
-        this.furthestDistance = distance
+        this.furthestDragOffset = dragOffset
     }
 }
diff --git a/mechanics/src/com/android/mechanics/MotionValue.kt b/mechanics/src/com/android/mechanics/MotionValue.kt
new file mode 100644
index 0000000..8ba09be
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/MotionValue.kt
@@ -0,0 +1,457 @@
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
+package com.android.mechanics
+
+import androidx.compose.runtime.FloatState
+import androidx.compose.runtime.derivedStateOf
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.mutableLongStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.referentialEqualityPolicy
+import androidx.compose.runtime.setValue
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.runtime.withFrameNanos
+import com.android.mechanics.debug.DebugInspector
+import com.android.mechanics.debug.FrameData
+import com.android.mechanics.impl.Computations
+import com.android.mechanics.impl.DiscontinuityAnimation
+import com.android.mechanics.impl.GuaranteeState
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spring.SpringState
+import java.util.concurrent.atomic.AtomicInteger
+import kotlinx.coroutines.CoroutineName
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.withContext
+
+/**
+ * Computes an animated [output] value, by mapping the [currentInput] according to the [spec].
+ *
+ * A [MotionValue] represents a single animated value within a larger animation. It takes a
+ * numerical [currentInput] value, typically a spatial value like width, height, or gesture length,
+ * and transforms it into an [output] value using a [MotionSpec].
+ *
+ * ## Mapping Input to Output
+ *
+ * The [MotionSpec] defines the relationship between the input and output values. It does this by
+ * specifying a series of [Mapping] functions and [Breakpoint]s. Breakpoints divide the input domain
+ * into segments. Each segment has an associated [Mapping] function, which determines how input
+ * values within that segment are transformed into output values.
+ *
+ * These [Mapping] functions can be arbitrary, as long as they are
+ * 1. deterministic: When invoked repeatedly for the same input, they must produce the same output.
+ * 2. continuous: meaning infinitesimally small changes in input result in infinitesimally small
+ *    changes in output
+ *
+ * A valid [Mapping] function is one whose graph could be drawn without lifting your pen from the
+ * paper, meaning there are no abrupt jumps or breaks.
+ *
+ * ## Animating Discontinuities
+ *
+ * When the input value crosses a breakpoint, there might be a discontinuity in the output value due
+ * to the switch between mapping functions. `MotionValue` automatically animates these
+ * discontinuities using a spring animation. The spring parameters are defined for each
+ * [Breakpoint].
+ *
+ * ## Guarantees for Choreography
+ *
+ * Breakpoints can also define [Guarantee]s. These guarantees can make the spring animation finish
+ * faster, in response to quick input value changes. Thus, [Guarantee]s allows to maintain a
+ * predictable choreography, even as the input is unpredictably changed by a user's gesture.
+ *
+ * ## Updating the MotionSpec
+ *
+ * The [spec] property can be changed at any time. If the new spec produces a different output for
+ * the current input, the difference will be animated using the spring parameters defined in
+ * [MotionSpec.resetSpring].
+ *
+ * ## Gesture Context
+ *
+ * The [GestureContext] augments the [currentInput] value with the user's intent. The
+ * [GestureContext] is created wherever gesture input is handled. If the motion value is not driven
+ * by a gesture, it is OK for the [GestureContext] to return static values.
+ *
+ * ## Usage
+ *
+ * The [MotionValue] does animate the [output] implicitly, whenever a change in [currentInput],
+ * [spec], or [gestureContext] requires it. The animated value is computed whenever the [output]
+ * property is read, or the latest once the animation frame is complete.
+ * 1. Create an instance, providing the input value, gesture context, and an initial spec.
+ * 2. Call [keepRunning] in a coroutine scope, and keep the coroutine running while the
+ *    `MotionValue` is in use.
+ * 3. Access the animated output value through the [output] property.
+ *
+ * Internally, the [keepRunning] coroutine is automatically suspended if there is nothing to
+ * animate.
+ *
+ * @param currentInput Provides the current input value.
+ * @param gestureContext The [GestureContext] augmenting the [currentInput].
+ * @param label An optional label to aid in debugging.
+ * @param stableThreshold A threshold value (in output units) that determines when the
+ *   [MotionValue]'s internal spring animation is considered stable.
+ */
+class MotionValue(
+    currentInput: () -> Float,
+    gestureContext: GestureContext,
+    initialSpec: MotionSpec = MotionSpec.Empty,
+    label: String? = null,
+    stableThreshold: Float = StableThresholdEffect,
+) : FloatState {
+    private val impl =
+        ObservableComputations(currentInput, gestureContext, initialSpec, stableThreshold, label)
+
+    /** The [MotionSpec] describing the mapping of this [MotionValue]'s input to the output. */
+    var spec: MotionSpec by impl::spec
+
+    /** Animated [output] value. */
+    val output: Float by impl::output
+
+    /**
+     * [output] value, but without animations.
+     *
+     * This value always reports the target value, even before a animation is finished.
+     *
+     * While [isStable], [outputTarget] and [output] are the same value.
+     */
+    val outputTarget: Float by impl::outputTarget
+
+    /** The [output] exposed as [FloatState]. */
+    override val floatValue: Float by impl::output
+
+    /** Whether an animation is currently running. */
+    val isStable: Boolean by impl::isStable
+
+    /**
+     * Keeps the [MotionValue]'s animated output running.
+     *
+     * Clients must call [keepRunning], and keep the coroutine running while the [MotionValue] is in
+     * use. When disposing this [MotionValue], cancel the coroutine.
+     *
+     * Internally, this method does suspend, unless there are animations ongoing.
+     */
+    suspend fun keepRunning(): Nothing {
+        withContext(CoroutineName("MotionValue($label)")) { impl.keepRunning { true } }
+
+        // `keepRunning` above will never finish,
+        throw AssertionError("Unreachable code")
+    }
+
+    /**
+     * Keeps the [MotionValue]'s animated output running while [continueRunning] returns `true`.
+     *
+     * When [continueRunning] returns `false`, the coroutine will end by the next frame.
+     *
+     * To keep the [MotionValue] running until the current animations are complete, check for
+     * `isStable` as well.
+     *
+     * ```kotlin
+     * motionValue.keepRunningWhile { !shouldEnd() || !isStable }
+     * ```
+     */
+    suspend fun keepRunningWhile(continueRunning: MotionValue.() -> Boolean) =
+        withContext(CoroutineName("MotionValue($label)")) {
+            impl.keepRunning { continueRunning.invoke(this@MotionValue) }
+        }
+
+    val label: String? by impl::label
+
+    companion object {
+        /** Creates a [MotionValue] whose [currentInput] is the animated [output] of [source]. */
+        fun createDerived(
+            source: MotionValue,
+            initialSpec: MotionSpec = MotionSpec.Empty,
+            label: String? = null,
+            stableThreshold: Float = 0.01f,
+        ): MotionValue {
+            return MotionValue(
+                currentInput = source::output,
+                gestureContext = source.impl.gestureContext,
+                initialSpec = initialSpec,
+                label = label,
+                stableThreshold = stableThreshold,
+            )
+        }
+
+        const val StableThresholdEffect = 0.01f
+        const val StableThresholdSpatial = 1f
+
+        internal const val TAG = "MotionValue"
+    }
+
+    private var debugInspectorRefCount = AtomicInteger(0)
+
+    private fun onDisposeDebugInspector() {
+        if (debugInspectorRefCount.decrementAndGet() == 0) {
+            impl.debugInspector = null
+        }
+    }
+
+    /**
+     * Provides access to internal state for debug tooling and tests.
+     *
+     * The returned [DebugInspector] must be [DebugInspector.dispose]d when no longer needed.
+     */
+    fun debugInspector(): DebugInspector {
+        if (debugInspectorRefCount.getAndIncrement() == 0) {
+            impl.debugInspector =
+                DebugInspector(
+                    FrameData(
+                        impl.lastInput,
+                        impl.lastSegment.direction,
+                        impl.lastGestureDragOffset,
+                        impl.lastFrameTimeNanos,
+                        impl.lastSpringState,
+                        impl.lastSegment,
+                        impl.lastAnimation,
+                    ),
+                    impl.isActive,
+                    impl.debugIsAnimating,
+                    ::onDisposeDebugInspector,
+                )
+        }
+
+        return checkNotNull(impl.debugInspector)
+    }
+}
+
+private class ObservableComputations(
+    val input: () -> Float,
+    val gestureContext: GestureContext,
+    initialSpec: MotionSpec = MotionSpec.Empty,
+    override val stableThreshold: Float,
+    override val label: String?,
+) : Computations {
+
+    // ----  CurrentFrameInput ---------------------------------------------------------------------
+
+    override var spec by mutableStateOf(initialSpec)
+    override val currentInput: Float
+        get() = input.invoke()
+
+    override val currentDirection: InputDirection
+        get() = gestureContext.direction
+
+    override val currentGestureDragOffset: Float
+        get() = gestureContext.dragOffset
+
+    override var currentAnimationTimeNanos by mutableLongStateOf(-1L)
+
+    // ----  LastFrameState ---------------------------------------------------------------------
+
+    override var lastSegment: SegmentData by
+        mutableStateOf(
+            spec.segmentAtInput(currentInput, currentDirection),
+            referentialEqualityPolicy(),
+        )
+
+    override var lastGuaranteeState: GuaranteeState
+        get() = GuaranteeState(_lastGuaranteeStatePacked)
+        set(value) {
+            _lastGuaranteeStatePacked = value.packedValue
+        }
+
+    private var _lastGuaranteeStatePacked: Long by
+        mutableLongStateOf(GuaranteeState.Inactive.packedValue)
+
+    override var lastAnimation: DiscontinuityAnimation by
+        mutableStateOf(DiscontinuityAnimation.None, referentialEqualityPolicy())
+
+    override var directMappedVelocity: Float = 0f
+
+    override var lastSpringState: SpringState
+        get() = SpringState(_lastSpringStatePacked)
+        set(value) {
+            _lastSpringStatePacked = value.packedValue
+        }
+
+    private var _lastSpringStatePacked: Long by
+        mutableLongStateOf(lastAnimation.springStartState.packedValue)
+
+    override var lastFrameTimeNanos by mutableLongStateOf(-1L)
+
+    override var lastInput by mutableFloatStateOf(currentInput)
+
+    override var lastGestureDragOffset by mutableFloatStateOf(currentGestureDragOffset)
+
+    // ---- Computations ---------------------------------------------------------------------------
+
+    override val currentSegment by derivedStateOf { computeCurrentSegment() }
+    override val currentGuaranteeState by derivedStateOf { computeCurrentGuaranteeState() }
+    override val currentAnimation by derivedStateOf { computeCurrentAnimation() }
+    override val currentSpringState by derivedStateOf { computeCurrentSpringState() }
+
+    suspend fun keepRunning(continueRunning: () -> Boolean) {
+        check(!isActive) { "MotionValue($label) is already running" }
+        isActive = true
+
+        // These `captured*` values will be applied to the `last*` values, at the beginning
+        // of the each new frame.
+        // TODO(b/397837971): Encapsulate the state in a StateRecord.
+        var capturedSegment = currentSegment
+        var capturedGuaranteeState = currentGuaranteeState
+        var capturedAnimation = currentAnimation
+        var capturedSpringState = currentSpringState
+        var capturedFrameTimeNanos = currentAnimationTimeNanos
+        var capturedInput = currentInput
+        var capturedGestureDragOffset = currentGestureDragOffset
+        var capturedDirection = currentDirection
+
+        try {
+            debugIsAnimating = true
+
+            // indicates whether withFrameNanos is called continuously (as opposed to being
+            // suspended for an undetermined amount of time in between withFrameNanos).
+            // This is essential after `withFrameNanos` returned: if true at this point,
+            // currentAnimationTimeNanos - lastFrameNanos is the duration of the last frame.
+            var isAnimatingUninterrupted = false
+
+            while (continueRunning()) {
+
+                withFrameNanos { frameTimeNanos ->
+                    currentAnimationTimeNanos = frameTimeNanos
+
+                    // With the new frame started, copy
+
+                    lastSegment = capturedSegment
+                    lastGuaranteeState = capturedGuaranteeState
+                    lastAnimation = capturedAnimation
+                    lastSpringState = capturedSpringState
+                    lastFrameTimeNanos = capturedFrameTimeNanos
+                    lastInput = capturedInput
+                    lastGestureDragOffset = capturedGestureDragOffset
+                }
+
+                // At this point, the complete frame is done (including layout, drawing and
+                // everything else), and this MotionValue has been updated.
+
+                // Capture the `current*` MotionValue state, so that it can be applied as the
+                // `last*` state when the next frame starts. Its imperative to capture at this point
+                // already (since the input could change before the next frame starts), while at the
+                // same time not already applying the `last*` state (as this would cause a
+                // re-computation if the current state is being read before the next frame).
+                if (isAnimatingUninterrupted) {
+                    val currentDirectMapped = currentDirectMapped
+                    val lastDirectMapped =
+                        lastSegment.mapping.map(lastInput) - lastAnimation.targetValue
+
+                    val frameDuration =
+                        (currentAnimationTimeNanos - lastFrameTimeNanos) / 1_000_000_000.0
+                    val staticDelta = (currentDirectMapped - lastDirectMapped)
+                    directMappedVelocity = (staticDelta / frameDuration).toFloat()
+                } else {
+                    directMappedVelocity = 0f
+                }
+
+                var scheduleNextFrame = !isStable
+                if (capturedSegment != currentSegment) {
+                    capturedSegment = currentSegment
+                    scheduleNextFrame = true
+                }
+
+                if (capturedGuaranteeState != currentGuaranteeState) {
+                    capturedGuaranteeState = currentGuaranteeState
+                    scheduleNextFrame = true
+                }
+
+                if (capturedAnimation != currentAnimation) {
+                    capturedAnimation = currentAnimation
+                    scheduleNextFrame = true
+                }
+
+                if (capturedSpringState != currentSpringState) {
+                    capturedSpringState = currentSpringState
+                    scheduleNextFrame = true
+                }
+
+                if (capturedInput != currentInput) {
+                    capturedInput = currentInput
+                    scheduleNextFrame = true
+                }
+
+                if (capturedGestureDragOffset != currentGestureDragOffset) {
+                    capturedGestureDragOffset = currentGestureDragOffset
+                    scheduleNextFrame = true
+                }
+
+                if (capturedDirection != currentDirection) {
+                    capturedDirection = currentDirection
+                    scheduleNextFrame = true
+                }
+
+                capturedFrameTimeNanos = currentAnimationTimeNanos
+
+                debugInspector?.run {
+                    frame =
+                        FrameData(
+                            capturedInput,
+                            capturedDirection,
+                            capturedGestureDragOffset,
+                            capturedFrameTimeNanos,
+                            capturedSpringState,
+                            capturedSegment,
+                            capturedAnimation,
+                        )
+                }
+
+                isAnimatingUninterrupted = scheduleNextFrame
+                if (scheduleNextFrame) {
+                    continue
+                }
+
+                debugIsAnimating = false
+                snapshotFlow {
+                        val wakeup =
+                            !continueRunning() ||
+                                spec != capturedSegment.spec ||
+                                currentInput != capturedInput ||
+                                currentDirection != capturedDirection ||
+                                currentGestureDragOffset != capturedGestureDragOffset
+                        wakeup
+                    }
+                    .first { it }
+                debugIsAnimating = true
+            }
+        } finally {
+            isActive = false
+            debugIsAnimating = false
+        }
+    }
+
+    /** Whether a [keepRunning] coroutine is active currently. */
+    var isActive = false
+        set(value) {
+            field = value
+            debugInspector?.isActive = value
+        }
+
+    /**
+     * `false` whenever the [keepRunning] coroutine is suspended while no animation is running and
+     * the input is not changing.
+     */
+    var debugIsAnimating = false
+        set(value) {
+            field = value
+            debugInspector?.isAnimating = value
+        }
+
+    var debugInspector: DebugInspector? = null
+}
diff --git a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt
new file mode 100644
index 0000000..2d9f7f9
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerBackground.kt
@@ -0,0 +1,195 @@
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
+package com.android.mechanics.behavior
+
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.drawWithCache
+import androidx.compose.ui.geometry.CornerRadius
+import androidx.compose.ui.geometry.Offset
+import androidx.compose.ui.geometry.Rect
+import androidx.compose.ui.geometry.Size
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.graphics.drawscope.ContentDrawScope
+import androidx.compose.ui.graphics.drawscope.clipRect
+import androidx.compose.ui.graphics.layer.GraphicsLayer
+import androidx.compose.ui.graphics.layer.drawLayer
+import androidx.compose.ui.node.DrawModifierNode
+import androidx.compose.ui.node.ModifierNodeElement
+import androidx.compose.ui.node.requireGraphicsContext
+import androidx.compose.ui.util.fastCoerceAtLeast
+import androidx.compose.ui.util.fastCoerceIn
+import androidx.compose.ui.util.lerp
+import kotlin.math.min
+
+/**
+ * Draws the background of a vertically container, and applies clipping to it.
+ *
+ * Intended to be used with a [VerticalExpandContainerSpec] motion.
+ */
+fun Modifier.verticalExpandContainerBackground(
+    backgroundColor: Color,
+    spec: VerticalExpandContainerSpec,
+): Modifier =
+    this.then(
+        if (spec.isFloating) {
+            Modifier.verticalFloatingExpandContainerBackground(backgroundColor, spec)
+        } else {
+            Modifier.verticalEdgeExpandContainerBackground(backgroundColor, spec)
+        }
+    )
+
+/**
+ * Draws the background of an floating container, and applies clipping to it.
+ *
+ * Intended to be used with a [VerticalExpandContainerSpec] motion.
+ */
+internal fun Modifier.verticalFloatingExpandContainerBackground(
+    backgroundColor: Color,
+    spec: VerticalExpandContainerSpec,
+): Modifier =
+    this.drawWithCache {
+        val targetRadiusPx = spec.radius.toPx()
+        val currentRadiusPx = min(targetRadiusPx, min(size.width, size.height) / 2f)
+        val horizontalInset = targetRadiusPx - currentRadiusPx
+        val shapeTopLeft = Offset(horizontalInset, 0f)
+        val shapeSize = Size(size.width - (horizontalInset * 2f), size.height)
+
+        val layer =
+            obtainGraphicsLayer().apply {
+                clip = true
+                setRoundRectOutline(shapeTopLeft, shapeSize, cornerRadius = currentRadiusPx)
+
+                record { drawContent() }
+            }
+
+        onDrawWithContent {
+            drawRoundRect(
+                color = backgroundColor,
+                topLeft = shapeTopLeft,
+                size = shapeSize,
+                cornerRadius = CornerRadius(currentRadiusPx),
+            )
+
+            drawLayer(layer)
+        }
+    }
+
+/**
+ * Draws the background of an edge container, and applies clipping to it.
+ *
+ * Intended to be used with a [VerticalExpandContainerSpec] motion.
+ */
+internal fun Modifier.verticalEdgeExpandContainerBackground(
+    backgroundColor: Color,
+    spec: VerticalExpandContainerSpec,
+): Modifier = this.then(EdgeContainerExpansionBackgroundElement(backgroundColor, spec))
+
+internal class EdgeContainerExpansionBackgroundNode(
+    var backgroundColor: Color,
+    var spec: VerticalExpandContainerSpec,
+) : Modifier.Node(), DrawModifierNode {
+
+    private var graphicsLayer: GraphicsLayer? = null
+    private var lastOutlineSize = Size.Zero
+
+    fun invalidateOutline() {
+        lastOutlineSize = Size.Zero
+    }
+
+    override fun onAttach() {
+        graphicsLayer = requireGraphicsContext().createGraphicsLayer().apply { clip = true }
+    }
+
+    override fun onDetach() {
+        requireGraphicsContext().releaseGraphicsLayer(checkNotNull(graphicsLayer))
+    }
+
+    override fun ContentDrawScope.draw() {
+        val height = size.height
+
+        // The width is growing between visibleHeight and detachHeight
+        val visibleHeight = spec.visibleHeight.toPx()
+        val widthFraction =
+            ((height - visibleHeight) / (spec.detachHeight.toPx() - visibleHeight)).fastCoerceIn(
+                0f,
+                1f,
+            )
+        val width = size.width - lerp(spec.widthOffset.toPx(), 0f, widthFraction)
+        val horizontalInset = (size.width - width) / 2f
+
+        // The radius is growing at the beginning of the transition
+        val radius = height.fastCoerceIn(spec.minRadius.toPx(), spec.radius.toPx())
+
+        // Draw (at most) the bottom half of the rounded corner rectangle, aligned to the bottom.
+        val upperHeight = height - radius
+
+        // The rounded rect is drawn at 2x the radius height, to avoid smaller corner radii.
+        // The clipRect limits this to the relevant part (-1 to avoid a hairline gap being visible
+        // between this and the fill below.
+        clipRect(top = (upperHeight - 1).fastCoerceAtLeast(0f)) {
+            drawRoundRect(
+                color = backgroundColor,
+                cornerRadius = CornerRadius(radius),
+                size = Size(width, radius * 2f),
+                topLeft = Offset(horizontalInset, size.height - radius * 2f),
+            )
+        }
+
+        if (upperHeight > 0) {
+            // Fill the space above the bottom shape.
+            drawRect(
+                color = backgroundColor,
+                topLeft = Offset(horizontalInset, 0f),
+                size = Size(width, upperHeight),
+            )
+        }
+
+        // Draw the node's content in a separate layer.
+        val graphicsLayer = checkNotNull(graphicsLayer)
+        graphicsLayer.record { this@draw.drawContent() }
+
+        if (size != lastOutlineSize) {
+            // The clip outline is a rounded corner shape matching the bottom of the shape.
+            // At the top, the rounded corner shape extends by radiusPx above top.
+            // This clipping thus would not prevent the containers content to overdraw at the top,
+            // however this is off-screen anyways.
+            val top = min(-radius, height - radius * 2f)
+
+            val rect = Rect(left = horizontalInset, top = top, right = width, bottom = height)
+            graphicsLayer.setRoundRectOutline(rect.topLeft, rect.size, radius)
+            lastOutlineSize = size
+        }
+
+        this.drawLayer(graphicsLayer)
+    }
+}
+
+private data class EdgeContainerExpansionBackgroundElement(
+    val backgroundColor: Color,
+    val spec: VerticalExpandContainerSpec,
+) : ModifierNodeElement<EdgeContainerExpansionBackgroundNode>() {
+    override fun create(): EdgeContainerExpansionBackgroundNode =
+        EdgeContainerExpansionBackgroundNode(backgroundColor, spec)
+
+    override fun update(node: EdgeContainerExpansionBackgroundNode) {
+        node.backgroundColor = backgroundColor
+        if (node.spec != spec) {
+            node.spec = spec
+            node.invalidateOutline()
+        }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt
new file mode 100644
index 0000000..e7fb688
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/behavior/VerticalExpandContainerSpec.kt
@@ -0,0 +1,161 @@
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
+@file:OptIn(ExperimentalMaterial3ExpressiveApi::class)
+
+package com.android.mechanics.behavior
+
+import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
+import androidx.compose.material3.MotionScheme
+import androidx.compose.ui.unit.Density
+import androidx.compose.ui.unit.Dp
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.util.fastCoerceIn
+import androidx.compose.ui.util.lerp
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.OnChangeSegmentHandler
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spec.buildDirectionalMotionSpec
+import com.android.mechanics.spec.builder
+import com.android.mechanics.spec.reverseBuilder
+import com.android.mechanics.spring.SpringParameters
+
+/** Motion spec for a vertically expandable container. */
+class VerticalExpandContainerSpec(
+    val isFloating: Boolean,
+    val minRadius: Dp = Defaults.MinRadius,
+    val radius: Dp = Defaults.Radius,
+    val visibleHeight: Dp = Defaults.VisibleHeight,
+    val preDetachRatio: Float = Defaults.PreDetachRatio,
+    val detachHeight: Dp = if (isFloating) radius * 3 else Defaults.DetachHeight,
+    val attachHeight: Dp = if (isFloating) radius * 2 else Defaults.AttachHeight,
+    val widthOffset: Dp = Defaults.WidthOffset,
+    val attachSpring: SpringParameters = Defaults.AttachSpring,
+    val detachSpring: SpringParameters = Defaults.DetachSpring,
+    val opacitySpring: SpringParameters = Defaults.OpacitySpring,
+) {
+    fun createHeightSpec(motionScheme: MotionScheme, density: Density): MotionSpec {
+        return with(density) {
+            val spatialSpring = SpringParameters(motionScheme.defaultSpatialSpec())
+
+            val detachSpec =
+                DirectionalMotionSpec.builder(
+                        initialMapping = Mapping.Zero,
+                        defaultSpring = spatialSpring,
+                    )
+                    .toBreakpoint(0f, key = Breakpoints.Attach)
+                    .continueWith(Mapping.Linear(preDetachRatio))
+                    .toBreakpoint(detachHeight.toPx(), key = Breakpoints.Detach)
+                    .completeWith(Mapping.Identity, detachSpring)
+
+            val attachSpec =
+                DirectionalMotionSpec.reverseBuilder(defaultSpring = spatialSpring)
+                    .toBreakpoint(attachHeight.toPx(), key = Breakpoints.Detach)
+                    .completeWith(mapping = Mapping.Zero, attachSpring)
+
+            val segmentHandlers =
+                mapOf<SegmentKey, OnChangeSegmentHandler>(
+                    SegmentKey(Breakpoints.Detach, Breakpoint.maxLimit.key, InputDirection.Min) to
+                        { currentSegment, _, newDirection ->
+                            if (newDirection != currentSegment.direction) currentSegment else null
+                        },
+                    SegmentKey(Breakpoints.Attach, Breakpoints.Detach, InputDirection.Max) to
+                        { currentSegment: SegmentData, newInput: Float, newDirection: InputDirection
+                            ->
+                            if (newDirection != currentSegment.direction && newInput >= 0)
+                                currentSegment
+                            else null
+                        },
+                )
+
+            MotionSpec(
+                maxDirection = detachSpec,
+                minDirection = attachSpec,
+                segmentHandlers = segmentHandlers,
+            )
+        }
+    }
+
+    fun createWidthSpec(
+        intrinsicWidth: Float,
+        motionScheme: MotionScheme,
+        density: Density,
+    ): MotionSpec {
+        return with(density) {
+            if (isFloating) {
+                MotionSpec(buildDirectionalMotionSpec(Mapping.Fixed(intrinsicWidth)))
+            } else {
+                MotionSpec(
+                    buildDirectionalMotionSpec({ input ->
+                        val fraction = (input / detachHeight.toPx()).fastCoerceIn(0f, 1f)
+                        intrinsicWidth - lerp(widthOffset.toPx(), 0f, fraction)
+                    })
+                )
+            }
+        }
+    }
+
+    fun createAlphaSpec(motionScheme: MotionScheme, density: Density): MotionSpec {
+        return with(density) {
+            val detachSpec =
+                DirectionalMotionSpec.builder(
+                        SpringParameters(motionScheme.defaultEffectsSpec()),
+                        initialMapping = Mapping.Zero,
+                    )
+                    .toBreakpoint(visibleHeight.toPx())
+                    .completeWith(Mapping.One, opacitySpring)
+
+            val attachSpec =
+                DirectionalMotionSpec.builder(
+                        SpringParameters(motionScheme.defaultEffectsSpec()),
+                        initialMapping = Mapping.Zero,
+                    )
+                    .toBreakpoint(visibleHeight.toPx())
+                    .completeWith(Mapping.One, opacitySpring)
+
+            MotionSpec(maxDirection = detachSpec, minDirection = attachSpec)
+        }
+    }
+
+    companion object {
+        object Breakpoints {
+            val Attach = BreakpointKey("EdgeContainerExpansion::Attach")
+            val Detach = BreakpointKey("EdgeContainerExpansion::Detach")
+        }
+
+        object Defaults {
+            val VisibleHeight = 24.dp
+            val PreDetachRatio = .25f
+            val DetachHeight = 80.dp
+            val AttachHeight = 40.dp
+
+            val WidthOffset = 28.dp
+
+            val MinRadius = 28.dp
+            val Radius = 46.dp
+
+            val AttachSpring = SpringParameters(stiffness = 380f, dampingRatio = 0.9f)
+            val DetachSpring = SpringParameters(stiffness = 380f, dampingRatio = 0.9f)
+            val OpacitySpring = SpringParameters(stiffness = 1200f, dampingRatio = 0.99f)
+        }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/debug/DebugInspector.kt b/mechanics/src/com/android/mechanics/debug/DebugInspector.kt
new file mode 100644
index 0000000..0eb015f
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/debug/DebugInspector.kt
@@ -0,0 +1,84 @@
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
+package com.android.mechanics.debug
+
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.setValue
+import com.android.mechanics.MotionValue
+import com.android.mechanics.impl.DiscontinuityAnimation
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spec.SegmentKey
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.spring.SpringState
+import kotlinx.coroutines.DisposableHandle
+
+/** Utility to gain inspection access to internal [MotionValue] state. */
+class DebugInspector
+internal constructor(
+    initialFrameData: FrameData,
+    initialIsActive: Boolean,
+    initialIsAnimating: Boolean,
+    disposableHandle: DisposableHandle,
+) : DisposableHandle by disposableHandle {
+
+    /** The last completed frame's data. */
+    var frame: FrameData by mutableStateOf(initialFrameData)
+        internal set
+
+    /** Whether a [MotionValue.keepRunning] coroutine is active currently. */
+    var isActive: Boolean by mutableStateOf(initialIsActive)
+        internal set
+
+    /**
+     * `false` whenever the [MotionValue.keepRunning] coroutine internally is suspended while no
+     * animation is running and the input is not changing.
+     */
+    var isAnimating: Boolean by mutableStateOf(initialIsAnimating)
+        internal set
+}
+
+/** The input, output and internal state of a [MotionValue] for the frame. */
+data class FrameData
+internal constructor(
+    val input: Float,
+    val gestureDirection: InputDirection,
+    val gestureDragOffset: Float,
+    val frameTimeNanos: Long,
+    val springState: SpringState,
+    private val segment: SegmentData,
+    private val animation: DiscontinuityAnimation,
+) {
+    val isStable: Boolean
+        get() = springState == SpringState.AtRest
+
+    val springParameters: SpringParameters
+        get() = animation.springParameters
+
+    val segmentKey: SegmentKey
+        get() = segment.key
+
+    val output: Float
+        get() = currentDirectMapped + (animation.targetValue + springState.displacement)
+
+    val outputTarget: Float
+        get() = currentDirectMapped + animation.targetValue
+
+    private val currentDirectMapped: Float
+        get() = segment.mapping.map(input) - animation.targetValue
+}
diff --git a/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt b/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt
new file mode 100644
index 0000000..38140a3
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/debug/DebugVisualization.kt
@@ -0,0 +1,489 @@
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
+package com.android.mechanics.debug
+
+import androidx.compose.foundation.layout.Spacer
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.DisposableEffect
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateListOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.setValue
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.runtime.withFrameNanos
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.drawBehind
+import androidx.compose.ui.geometry.Offset
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.graphics.StrokeCap
+import androidx.compose.ui.graphics.drawscope.ContentDrawScope
+import androidx.compose.ui.graphics.drawscope.DrawScope
+import androidx.compose.ui.graphics.drawscope.Stroke
+import androidx.compose.ui.graphics.drawscope.scale
+import androidx.compose.ui.graphics.drawscope.translate
+import androidx.compose.ui.node.DrawModifierNode
+import androidx.compose.ui.node.ModifierNodeElement
+import androidx.compose.ui.node.ObserverModifierNode
+import androidx.compose.ui.node.observeReads
+import androidx.compose.ui.platform.InspectorInfo
+import androidx.compose.ui.unit.dp
+import androidx.compose.ui.util.fastCoerceAtLeast
+import androidx.compose.ui.util.fastCoerceAtMost
+import androidx.compose.ui.util.fastForEachIndexed
+import com.android.mechanics.MotionValue
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SegmentKey
+import kotlin.math.max
+import kotlin.math.min
+import kotlinx.coroutines.flow.first
+import kotlinx.coroutines.launch
+
+/**
+ * A debug visualization of the [motionValue].
+ *
+ * Draws both the [MotionValue.spec], as well as the input and output.
+ *
+ * NOTE: This is a debug tool, do not enable in production.
+ *
+ * @param motionValue The [MotionValue] to inspect.
+ * @param inputRange The relevant range of the input (x) axis, for which to draw the graph.
+ * @param maxAgeMillis Max age of the elements in the history trail.
+ */
+@Composable
+fun DebugMotionValueVisualization(
+    motionValue: MotionValue,
+    inputRange: ClosedFloatingPointRange<Float>,
+    modifier: Modifier = Modifier,
+    maxAgeMillis: Long = 1000L,
+) {
+    val spec = motionValue.spec
+    val outputRange = remember(spec, inputRange) { spec.computeOutputValueRange(inputRange) }
+
+    val inspector = remember(motionValue) { motionValue.debugInspector() }
+
+    DisposableEffect(inspector) { onDispose { inspector.dispose() } }
+
+    val colorScheme = MaterialTheme.colorScheme
+    val axisColor = colorScheme.outline
+    val specColor = colorScheme.tertiary
+    val valueColor = colorScheme.primary
+
+    val primarySpec = motionValue.spec.get(inspector.frame.gestureDirection)
+    val activeSegment = inspector.frame.segmentKey
+
+    Spacer(
+        modifier =
+            modifier
+                .debugMotionSpecGraph(
+                    primarySpec,
+                    inputRange,
+                    outputRange,
+                    axisColor,
+                    specColor,
+                    activeSegment,
+                )
+                .debugMotionValueGraph(
+                    motionValue,
+                    valueColor,
+                    inputRange,
+                    outputRange,
+                    maxAgeMillis,
+                )
+    )
+}
+
+/**
+ * Draws a full-sized debug visualization of [spec].
+ *
+ * NOTE: This is a debug tool, do not enable in production.
+ *
+ * @param inputRange The range of the input (x) axis
+ * @param outputRange The range of the output (y) axis.
+ */
+fun Modifier.debugMotionSpecGraph(
+    spec: DirectionalMotionSpec,
+    inputRange: ClosedFloatingPointRange<Float>,
+    outputRange: ClosedFloatingPointRange<Float>,
+    axisColor: Color = Color.Gray,
+    specColor: Color = Color.Blue,
+    activeSegment: SegmentKey? = null,
+): Modifier = drawBehind {
+    drawAxis(axisColor)
+    drawDirectionalSpec(spec, inputRange, outputRange, specColor, activeSegment)
+}
+
+/**
+ * Draws a full-sized debug visualization of the [motionValue] state.
+ *
+ * This can be combined with [debugMotionSpecGraph], when [inputRange] and [outputRange] are the
+ * same.
+ *
+ * NOTE: This is a debug tool, do not enable in production.
+ *
+ * @param color Color for the dots indicating the value
+ * @param inputRange The range of the input (x) axis
+ * @param outputRange The range of the output (y) axis.
+ * @param maxAgeMillis Max age of the elements in the history trail.
+ */
+@Composable
+fun Modifier.debugMotionValueGraph(
+    motionValue: MotionValue,
+    color: Color,
+    inputRange: ClosedFloatingPointRange<Float>,
+    outputRange: ClosedFloatingPointRange<Float>,
+    maxAgeMillis: Long = 1000L,
+): Modifier =
+    this then
+        DebugMotionValueGraphElement(motionValue, color, inputRange, outputRange, maxAgeMillis)
+
+/**
+ * Utility to compute the min/max output values of the spec for the given input.
+ *
+ * Note: this only samples at breakpoint locations. For segment mappings that produce smaller/larger
+ * values in between two breakpoints, this method might might not produce a correct result.
+ */
+fun MotionSpec.computeOutputValueRange(
+    inputRange: ClosedFloatingPointRange<Float>
+): ClosedFloatingPointRange<Float> {
+    return if (isUnidirectional) {
+        maxDirection.computeOutputValueRange(inputRange)
+    } else {
+        val maxRange = maxDirection.computeOutputValueRange(inputRange)
+        val minRange = minDirection.computeOutputValueRange(inputRange)
+
+        val start = min(minRange.start, maxRange.start)
+        val endInclusive = max(minRange.endInclusive, maxRange.endInclusive)
+
+        start..endInclusive
+    }
+}
+
+/**
+ * Utility to compute the min/max output values of the spec for the given input.
+ *
+ * Note: this only samples at breakpoint locations. For segment mappings that produce smaller/larger
+ * values in between two breakpoints, this method might might not produce a correct result.
+ */
+fun DirectionalMotionSpec.computeOutputValueRange(
+    inputRange: ClosedFloatingPointRange<Float>
+): ClosedFloatingPointRange<Float> {
+
+    val start = findBreakpointIndex(inputRange.start)
+    val end = findBreakpointIndex(inputRange.endInclusive)
+
+    val samples = buildList {
+        add(mappings[start].map(inputRange.start))
+
+        for (breakpointIndex in (start + 1)..end) {
+
+            val position = breakpoints[breakpointIndex].position
+
+            add(mappings[breakpointIndex - 1].map(position))
+            add(mappings[breakpointIndex].map(position))
+        }
+
+        add(mappings[end].map(inputRange.endInclusive))
+    }
+
+    return samples.min()..samples.max()
+}
+
+private data class DebugMotionValueGraphElement(
+    val motionValue: MotionValue,
+    val color: Color,
+    val inputRange: ClosedFloatingPointRange<Float>,
+    val outputRange: ClosedFloatingPointRange<Float>,
+    val maxAgeMillis: Long,
+) : ModifierNodeElement<DebugMotionValueGraphNode>() {
+
+    init {
+        require(maxAgeMillis > 0)
+    }
+
+    override fun create() =
+        DebugMotionValueGraphNode(motionValue, color, inputRange, outputRange, maxAgeMillis)
+
+    override fun update(node: DebugMotionValueGraphNode) {
+        node.motionValue = motionValue
+        node.color = color
+        node.inputRange = inputRange
+        node.outputRange = outputRange
+        node.maxAgeMillis = maxAgeMillis
+    }
+
+    override fun InspectorInfo.inspectableProperties() {
+        // intentionally empty
+    }
+}
+
+private class DebugMotionValueGraphNode(
+    motionValue: MotionValue,
+    var color: Color,
+    var inputRange: ClosedFloatingPointRange<Float>,
+    var outputRange: ClosedFloatingPointRange<Float>,
+    var maxAgeMillis: Long,
+) : DrawModifierNode, ObserverModifierNode, Modifier.Node() {
+
+    private var debugInspector by mutableStateOf<DebugInspector?>(null)
+    private val history = mutableStateListOf<FrameData>()
+
+    var motionValue = motionValue
+        set(value) {
+            if (value != field) {
+                disposeDebugInspector()
+                field = value
+
+                if (isAttached) {
+                    acquireDebugInspector()
+                }
+            }
+        }
+
+    override fun onAttach() {
+        acquireDebugInspector()
+
+        coroutineScope.launch {
+            while (true) {
+                if (history.size > 1) {
+
+                    withFrameNanos { thisFrameTime ->
+                        while (
+                            history.size > 1 &&
+                                (thisFrameTime - history.first().frameTimeNanos) >
+                                    maxAgeMillis * 1_000_000
+                        ) {
+                            history.removeFirst()
+                        }
+                    }
+                }
+
+                snapshotFlow { history.size > 1 }.first { it }
+            }
+        }
+    }
+
+    override fun onDetach() {
+        disposeDebugInspector()
+    }
+
+    private fun acquireDebugInspector() {
+        debugInspector = motionValue.debugInspector()
+        observeFrameAndAddToHistory()
+    }
+
+    private fun disposeDebugInspector() {
+        debugInspector?.dispose()
+        debugInspector = null
+        history.clear()
+    }
+
+    override fun ContentDrawScope.draw() {
+        if (history.isNotEmpty()) {
+            drawDirectionAndAnimationStatus(history.last())
+        }
+        drawInputOutputTrail(history, inputRange, outputRange, color)
+        drawContent()
+    }
+
+    private fun observeFrameAndAddToHistory() {
+        var lastFrame: FrameData? = null
+
+        observeReads { lastFrame = debugInspector?.frame }
+
+        lastFrame?.also { history.add(it) }
+    }
+
+    override fun onObservedReadsChanged() {
+        observeFrameAndAddToHistory()
+    }
+}
+
+private val MotionSpec.isUnidirectional: Boolean
+    get() = maxDirection == minDirection
+
+private fun DrawScope.mapPointInInputToX(
+    input: Float,
+    inputRange: ClosedFloatingPointRange<Float>,
+): Float {
+    val inputExtent = (inputRange.endInclusive - inputRange.start)
+    return ((input - inputRange.start) / (inputExtent)) * size.width
+}
+
+private fun DrawScope.mapPointInOutputToY(
+    output: Float,
+    outputRange: ClosedFloatingPointRange<Float>,
+): Float {
+    val outputExtent = (outputRange.endInclusive - outputRange.start)
+    return (1 - (output - outputRange.start) / (outputExtent)) * size.height
+}
+
+private fun DrawScope.drawDirectionalSpec(
+    spec: DirectionalMotionSpec,
+    inputRange: ClosedFloatingPointRange<Float>,
+    outputRange: ClosedFloatingPointRange<Float>,
+    color: Color,
+    activeSegment: SegmentKey?,
+) {
+
+    val startSegment = spec.findBreakpointIndex(inputRange.start)
+    val endSegment = spec.findBreakpointIndex(inputRange.endInclusive)
+
+    for (segmentIndex in startSegment..endSegment) {
+        val isActiveSegment =
+            activeSegment?.let { spec.findSegmentIndex(it) == segmentIndex } ?: false
+
+        val mapping = spec.mappings[segmentIndex]
+        val startBreakpoint = spec.breakpoints[segmentIndex]
+        val segmentStart = startBreakpoint.position
+        val fromInput = segmentStart.fastCoerceAtLeast(inputRange.start)
+        val endBreakpoint = spec.breakpoints[segmentIndex + 1]
+        val segmentEnd = endBreakpoint.position
+        val toInput = segmentEnd.fastCoerceAtMost(inputRange.endInclusive)
+
+        // TODO add support for functions that are not linear
+        val fromY = mapPointInOutputToY(mapping.map(fromInput), outputRange)
+        val toY = mapPointInOutputToY(mapping.map(toInput), outputRange)
+
+        val start = Offset(mapPointInInputToX(fromInput, inputRange), fromY)
+        val end = Offset(mapPointInInputToX(toInput, inputRange), toY)
+
+        val strokeWidth = if (isActiveSegment) 2.dp.toPx() else Stroke.HairlineWidth
+        val dotSize = if (isActiveSegment) 4.dp.toPx() else 2.dp.toPx()
+
+        drawLine(color, start, end, strokeWidth = strokeWidth)
+
+        if (segmentStart == fromInput) {
+            drawCircle(color, dotSize, start)
+        }
+
+        if (segmentEnd == toInput) {
+            drawCircle(color, dotSize, end)
+        }
+
+        val guarantee = startBreakpoint.guarantee
+        if (guarantee is Guarantee.InputDelta) {
+            val guaranteePos = segmentStart + guarantee.delta
+            if (guaranteePos > inputRange.start) {
+
+                val guaranteeOffset =
+                    Offset(
+                        mapPointInInputToX(guaranteePos, inputRange),
+                        mapPointInOutputToY(mapping.map(guaranteePos), outputRange),
+                    )
+
+                val arrowSize = 4.dp.toPx()
+
+                drawLine(
+                    color,
+                    guaranteeOffset,
+                    guaranteeOffset.plus(Offset(arrowSize, -arrowSize)),
+                )
+                drawLine(color, guaranteeOffset, guaranteeOffset.plus(Offset(arrowSize, arrowSize)))
+            }
+        }
+    }
+}
+
+private fun DrawScope.drawDirectionAndAnimationStatus(currentFrame: FrameData) {
+    val indicatorSize = min(this.size.height, 24.dp.toPx())
+
+    this.scale(
+        scaleX = if (currentFrame.gestureDirection == InputDirection.Max) 1f else -1f,
+        scaleY = 1f,
+    ) {
+        val color = if (currentFrame.isStable) Color.Green else Color.Red
+        val strokeWidth = 1.dp.toPx()
+        val d1 = indicatorSize / 2f
+        val d2 = indicatorSize / 3f
+
+        translate(left = 2.dp.toPx()) {
+            drawLine(
+                color,
+                Offset(center.x - d2, center.y - d1),
+                center,
+                strokeWidth = strokeWidth,
+                cap = StrokeCap.Round,
+            )
+            drawLine(
+                color,
+                Offset(center.x - d2, center.y + d1),
+                center,
+                strokeWidth = strokeWidth,
+                cap = StrokeCap.Round,
+            )
+        }
+        translate(left = -2.dp.toPx()) {
+            drawLine(
+                color,
+                Offset(center.x - d2, center.y - d1),
+                center,
+                strokeWidth = strokeWidth,
+                cap = StrokeCap.Round,
+            )
+            drawLine(
+                color,
+                Offset(center.x - d2, center.y + d1),
+                center,
+                strokeWidth = strokeWidth,
+                cap = StrokeCap.Round,
+            )
+        }
+    }
+}
+
+private fun DrawScope.drawInputOutputTrail(
+    history: List<FrameData>,
+    inputRange: ClosedFloatingPointRange<Float>,
+    outputRange: ClosedFloatingPointRange<Float>,
+    color: Color,
+) {
+    history.fastForEachIndexed { index, frame ->
+        val x = mapPointInInputToX(frame.input, inputRange)
+        val y = mapPointInOutputToY(frame.output, outputRange)
+
+        drawCircle(color, 2.dp.toPx(), Offset(x, y), alpha = index / history.size.toFloat())
+    }
+}
+
+private fun DrawScope.drawAxis(color: Color) {
+
+    drawXAxis(color)
+    drawYAxis(color)
+}
+
+private fun DrawScope.drawYAxis(color: Color, atX: Float = 0f) {
+
+    val arrowSize = 4.dp.toPx()
+
+    drawLine(color, Offset(atX, size.height), Offset(atX, 0f))
+    drawLine(color, Offset(atX, 0f), Offset(atX + arrowSize, arrowSize))
+    drawLine(color, Offset(atX, 0f), Offset(atX - arrowSize, arrowSize))
+}
+
+private fun DrawScope.drawXAxis(color: Color, atY: Float = size.height) {
+
+    val arrowSize = 4.dp.toPx()
+
+    drawLine(color, Offset(0f, atY), Offset(size.width, atY))
+    drawLine(color, Offset(size.width, atY), Offset(size.width - arrowSize, atY + arrowSize))
+    drawLine(color, Offset(size.width, atY), Offset(size.width - arrowSize, atY - arrowSize))
+}
diff --git a/mechanics/src/com/android/mechanics/debug/MotionValueDebugger.kt b/mechanics/src/com/android/mechanics/debug/MotionValueDebugger.kt
new file mode 100644
index 0000000..3c0109d
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/debug/MotionValueDebugger.kt
@@ -0,0 +1,130 @@
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
+package com.android.mechanics.debug
+
+import androidx.compose.runtime.mutableStateListOf
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.node.DelegatableNode
+import androidx.compose.ui.node.ModifierNodeElement
+import androidx.compose.ui.node.TraversableNode
+import androidx.compose.ui.node.findNearestAncestor
+import androidx.compose.ui.platform.InspectorInfo
+import com.android.mechanics.MotionValue
+import com.android.mechanics.debug.MotionValueDebuggerNode.Companion.TRAVERSAL_NODE_KEY
+import kotlinx.coroutines.DisposableHandle
+
+/** State for the [MotionValueDebugger]. */
+sealed interface MotionValueDebuggerState {
+    val observedMotionValues: List<MotionValue>
+}
+
+/** Factory for [MotionValueDebugger]. */
+fun MotionValueDebuggerState(): MotionValueDebuggerState {
+    return MotionValueDebuggerStateImpl()
+}
+
+/** Collector for [MotionValue]s in the Node subtree that should be observed for debug purposes. */
+fun Modifier.motionValueDebugger(state: MotionValueDebuggerState): Modifier =
+    this.then(MotionValueDebuggerElement(state as MotionValueDebuggerStateImpl))
+
+/**
+ * [motionValueDebugger]'s interface, nodes in the subtree of a [motionValueDebugger] can retrieve
+ * it using [findMotionValueDebugger].
+ */
+sealed interface MotionValueDebugger {
+    fun register(motionValue: MotionValue): DisposableHandle
+}
+
+/** Finds a [MotionValueDebugger] that was registered via a [motionValueDebugger] modifier. */
+fun DelegatableNode.findMotionValueDebugger(): MotionValueDebugger? {
+    return findNearestAncestor(TRAVERSAL_NODE_KEY) as? MotionValueDebugger
+}
+
+/** Registers the motion value for debugging with the parent [MotionValue]. */
+fun Modifier.debugMotionValue(motionValue: MotionValue): Modifier =
+    this.then(DebugMotionValueElement(motionValue))
+
+internal class MotionValueDebuggerNode(internal var state: MotionValueDebuggerStateImpl) :
+    Modifier.Node(), TraversableNode, MotionValueDebugger {
+
+    override val traverseKey = TRAVERSAL_NODE_KEY
+
+    override fun register(motionValue: MotionValue): DisposableHandle {
+        val state = state
+        state.observedMotionValues.add(motionValue)
+        return DisposableHandle { state.observedMotionValues.remove(motionValue) }
+    }
+
+    companion object {
+        const val TRAVERSAL_NODE_KEY = "com.android.mechanics.debug.DEBUG_CONNECTOR_NODE_KEY"
+    }
+}
+
+private data class MotionValueDebuggerElement(val state: MotionValueDebuggerStateImpl) :
+    ModifierNodeElement<MotionValueDebuggerNode>() {
+    override fun create(): MotionValueDebuggerNode = MotionValueDebuggerNode(state)
+
+    override fun InspectorInfo.inspectableProperties() {
+        // Intentionally empty
+    }
+
+    override fun update(node: MotionValueDebuggerNode) {
+        check(node.state === state)
+    }
+}
+
+internal class DebugMotionValueNode(motionValue: MotionValue) : Modifier.Node() {
+
+    private var debugger: MotionValueDebugger? = null
+
+    internal var motionValue = motionValue
+        set(value) {
+            registration?.dispose()
+            registration = debugger?.register(value)
+            field = value
+        }
+
+    internal var registration: DisposableHandle? = null
+
+    override fun onAttach() {
+        debugger = findMotionValueDebugger()
+        registration = debugger?.register(motionValue)
+    }
+
+    override fun onDetach() {
+        debugger = null
+        registration?.dispose()
+        registration = null
+    }
+}
+
+private data class DebugMotionValueElement(val motionValue: MotionValue) :
+    ModifierNodeElement<DebugMotionValueNode>() {
+    override fun create(): DebugMotionValueNode = DebugMotionValueNode(motionValue)
+
+    override fun InspectorInfo.inspectableProperties() {
+        // Intentionally empty
+    }
+
+    override fun update(node: DebugMotionValueNode) {
+        node.motionValue = motionValue
+    }
+}
+
+internal class MotionValueDebuggerStateImpl : MotionValueDebuggerState {
+    override val observedMotionValues: MutableList<MotionValue> = mutableStateListOf()
+}
diff --git a/mechanics/src/com/android/mechanics/impl/ComputationInput.kt b/mechanics/src/com/android/mechanics/impl/ComputationInput.kt
new file mode 100644
index 0000000..23ac183
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/impl/ComputationInput.kt
@@ -0,0 +1,101 @@
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
+package com.android.mechanics.impl
+
+import com.android.mechanics.MotionValue
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spring.SpringState
+
+/** Static configuration that remains constant over a MotionValue's lifecycle. */
+internal interface StaticConfig {
+    /**
+     * A threshold value (in output units) that determines when the [MotionValue]'s internal spring
+     * animation is considered stable.
+     */
+    val stableThreshold: Float
+
+    /** Optional label for identifying a MotionValue for debugging purposes. */
+    val label: String?
+}
+
+/** The up-to-date [MotionValue] input, used by [Computations] to calculate the updated output. */
+internal interface CurrentFrameInput {
+    val spec: MotionSpec
+    val currentInput: Float
+    val currentAnimationTimeNanos: Long
+    val currentDirection: InputDirection
+    val currentGestureDragOffset: Float
+}
+
+/**
+ * The [MotionValue] state of the last completed frame.
+ *
+ * The values must be published at the start of the frame, together with the
+ * [CurrentFrameInput.currentAnimationTimeNanos].
+ */
+internal interface LastFrameState {
+    /**
+     * The segment in use, defined by the min/max [Breakpoint]s and the [Mapping] in between. This
+     * implicitly also captures the [InputDirection] and [MotionSpec].
+     */
+    val lastSegment: SegmentData
+    /**
+     * State of the [Guarantee]. Its interpretation is defined by the [lastSegment]'s
+     * [SegmentData.entryBreakpoint]'s [Breakpoint.guarantee]. If that breakpoint has no guarantee,
+     * this value will be [GuaranteeState.Inactive].
+     *
+     * This is the maximal guarantee value seen so far, as well as the guarantee's start value, and
+     * is used to compute the spring-tightening fraction.
+     */
+    val lastGuaranteeState: GuaranteeState
+    /**
+     * The state of an ongoing animation of a discontinuity.
+     *
+     * The spring animation is described by the [DiscontinuityAnimation.springStartState], which
+     * tracks the oscillation of the spring until the displacement is guaranteed not to exceed
+     * [stableThreshold] anymore. The spring animation started at
+     * [DiscontinuityAnimation.springStartTimeNanos], and uses the
+     * [DiscontinuityAnimation.springParameters]. The displacement's origin is at
+     * [DiscontinuityAnimation.targetValue].
+     *
+     * This state does not have to be updated every frame, even as an animation is ongoing: the
+     * spring animation can be computed with the same start parameters, and as time progresses, the
+     * [SpringState.calculateUpdatedState] is passed an ever larger `elapsedNanos` on each frame.
+     *
+     * The [DiscontinuityAnimation.targetValue] is a delta to the direct mapped output value from
+     * the [SegmentData.mapping]. It might accumulate the target value - it is not required to reset
+     * when the animation ends.
+     */
+    val lastAnimation: DiscontinuityAnimation
+    /**
+     * Last frame's spring state, based on initial origin values in [lastAnimation], carried-forward
+     * to [lastFrameTimeNanos].
+     */
+    val lastSpringState: SpringState
+    /** The time of the last frame, in nanoseconds. */
+    val lastFrameTimeNanos: Long
+    /** The [currentInput] of the last frame */
+    val lastInput: Float
+    val lastGestureDragOffset: Float
+
+    val directMappedVelocity: Float
+}
diff --git a/mechanics/src/com/android/mechanics/impl/Computations.kt b/mechanics/src/com/android/mechanics/impl/Computations.kt
new file mode 100644
index 0000000..124333f
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/impl/Computations.kt
@@ -0,0 +1,438 @@
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
+package com.android.mechanics.impl
+
+import android.util.Log
+import androidx.compose.ui.util.fastCoerceAtLeast
+import androidx.compose.ui.util.fastCoerceIn
+import androidx.compose.ui.util.fastIsFinite
+import androidx.compose.ui.util.lerp
+import com.android.mechanics.MotionValue.Companion.TAG
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.SegmentData
+import com.android.mechanics.spring.SpringState
+import com.android.mechanics.spring.calculateUpdatedState
+
+internal interface ComputeSegment : CurrentFrameInput, LastFrameState, StaticConfig {
+    /**
+     * The current segment, which defines the [Mapping] function used to transform the input to the
+     * output.
+     *
+     * While both [spec] and [currentDirection] remain the same, and [currentInput] is within the
+     * segment (see [SegmentData.isValidForInput]), this is [lastSegment].
+     *
+     * Otherwise, [MotionSpec.onChangeSegment] is queried for an up-dated segment.
+     */
+    fun computeCurrentSegment(): SegmentData {
+        val lastSegment = lastSegment
+        val input = currentInput
+        val direction = currentDirection
+
+        val specChanged = lastSegment.spec != spec
+        return if (specChanged || !lastSegment.isValidForInput(input, direction)) {
+            spec.onChangeSegment(lastSegment, input, direction)
+        } else {
+            lastSegment
+        }
+    }
+}
+
+internal interface ComputeGuaranteeState : ComputeSegment {
+    val currentSegment: SegmentData
+
+    /** Computes the [SegmentChangeType] between [lastSegment] and [currentSegment]. */
+    val segmentChangeType: SegmentChangeType
+        get() {
+            val currentSegment = currentSegment
+            val lastSegment = lastSegment
+
+            if (currentSegment.key == lastSegment.key) {
+                return SegmentChangeType.Same
+            }
+
+            if (
+                currentSegment.key.minBreakpoint == lastSegment.key.minBreakpoint &&
+                    currentSegment.key.maxBreakpoint == lastSegment.key.maxBreakpoint
+            ) {
+                return SegmentChangeType.SameOppositeDirection
+            }
+
+            val currentSpec = currentSegment.spec
+            val lastSpec = lastSegment.spec
+            if (currentSpec !== lastSpec) {
+                // Determine/guess whether the segment change was due to the changed spec, or
+                // whether lastSpec would return the same segment key for the update input.
+                val lastSpecSegmentForSameInput =
+                    lastSpec.segmentAtInput(currentInput, currentDirection).key
+                if (currentSegment.key != lastSpecSegmentForSameInput) {
+                    // Note: this might not be correct if the new [MotionSpec.segmentHandlers] were
+                    // involved.
+                    return SegmentChangeType.Spec
+                }
+            }
+
+            return if (currentSegment.direction == lastSegment.direction) {
+                SegmentChangeType.Traverse
+            } else {
+                SegmentChangeType.Direction
+            }
+        }
+
+    /**
+     * Computes the fraction of [position] between [lastInput] and [currentInput].
+     *
+     * Essentially, this determines fractionally when [position] was crossed, between the current
+     * frame and the last frame.
+     *
+     * Since frames are updated periodically, not continuously, crossing a breakpoint happened
+     * sometime between the last frame's start and this frame's start.
+     *
+     * This fraction is used to estimate the time when a breakpoint was crossed since last frame,
+     * and simplifies the logic of crossing multiple breakpoints in one frame, as it offers the
+     * springs and guarantees time to be updated correctly.
+     *
+     * Of course, this is a simplification that assumes the input velocity was uniform during the
+     * last frame, but that is likely good enough.
+     */
+    fun lastFrameFractionOfPosition(position: Float): Float {
+        return ((position - lastInput) / (currentInput - lastInput)).fastCoerceIn(0f, 1f)
+    }
+
+    /**
+     * The [GuaranteeState] for [currentSegment].
+     *
+     * Without a segment change, this carries forward [lastGuaranteeState], adjusted to the new
+     * input if needed.
+     *
+     * If a segment change happened, this is a new [GuaranteeState] for the [currentSegment]. Any
+     * remaining [lastGuaranteeState] will be consumed in [currentAnimation].
+     */
+    fun computeCurrentGuaranteeState(): GuaranteeState {
+        val currentSegment = currentSegment
+        val entryBreakpoint = currentSegment.entryBreakpoint
+
+        // First, determine the origin of the guarantee computations
+        val guaranteeOriginState =
+            when (segmentChangeType) {
+                // Still in the segment, the origin is carried over from the last frame
+                SegmentChangeType.Same -> lastGuaranteeState
+                // The direction changed within the same segment, no guarantee to enforce.
+                SegmentChangeType.SameOppositeDirection -> return GuaranteeState.Inactive
+                // The spec changes, there is no guarantee associated with the animation.
+                SegmentChangeType.Spec -> return GuaranteeState.Inactive
+                SegmentChangeType.Direction -> {
+                    // Direction changed over a segment boundary. To make up for the
+                    // directionChangeSlop, the guarantee starts at the current input.
+                    GuaranteeState.withStartValue(
+                        when (entryBreakpoint.guarantee) {
+                            is Guarantee.InputDelta -> currentInput
+                            is Guarantee.GestureDragDelta -> currentGestureDragOffset
+                            is Guarantee.None -> return GuaranteeState.Inactive
+                        }
+                    )
+                }
+
+                SegmentChangeType.Traverse -> {
+                    // Traversed over a segment boundary, the guarantee going forward is determined
+                    // by the [entryBreakpoint].
+                    GuaranteeState.withStartValue(
+                        when (entryBreakpoint.guarantee) {
+                            is Guarantee.InputDelta -> entryBreakpoint.position
+                            is Guarantee.GestureDragDelta -> {
+                                // Guess the GestureDragDelta origin - since the gesture dragOffset
+                                // is sampled, interpolate it according to when the breakpoint was
+                                // crossed in the last frame.
+                                val fractionalBreakpointPos =
+                                    lastFrameFractionOfPosition(entryBreakpoint.position)
+
+                                lerp(
+                                    lastGestureDragOffset,
+                                    currentGestureDragOffset,
+                                    fractionalBreakpointPos,
+                                )
+                            }
+
+                            // No guarantee to enforce.
+                            is Guarantee.None -> return GuaranteeState.Inactive
+                        }
+                    )
+                }
+            }
+
+        // Finally, update the origin state with the current guarantee value.
+        return guaranteeOriginState.withCurrentValue(
+            when (entryBreakpoint.guarantee) {
+                is Guarantee.InputDelta -> currentInput
+                is Guarantee.GestureDragDelta -> currentGestureDragOffset
+                is Guarantee.None -> return GuaranteeState.Inactive
+            },
+            currentSegment.direction,
+        )
+    }
+}
+
+internal interface ComputeAnimation : ComputeGuaranteeState {
+    val currentGuaranteeState: GuaranteeState
+
+    /**
+     * The [DiscontinuityAnimation] in effect for the current frame.
+     *
+     * This describes the starting condition of the spring animation, and is only updated if the
+     * spring animation must restarted: that is, if yet another discontinuity must be animated as a
+     * result of a segment change, or if the [currentGuaranteeState] requires the spring to be
+     * tightened.
+     *
+     * See [currentSpringState] for the continuously updated, animated spring values.
+     */
+    fun computeCurrentAnimation(): DiscontinuityAnimation {
+        val currentSegment = currentSegment
+        val lastSegment = lastSegment
+        val currentSpec = spec
+        val currentInput = currentInput
+        val lastAnimation = lastAnimation
+
+        return when (segmentChangeType) {
+            SegmentChangeType.Same -> {
+                if (lastAnimation.isAtRest) {
+                    // Nothing to update if no animation is ongoing
+                    lastAnimation
+                } else if (lastGuaranteeState == currentGuaranteeState) {
+                    // Nothing to update if the spring must not be tightened.
+                    lastAnimation
+                } else {
+                    // Compute the updated spring parameters
+                    val tightenedSpringParameters =
+                        currentGuaranteeState.updatedSpringParameters(
+                            currentSegment.entryBreakpoint
+                        )
+
+                    lastAnimation.copy(
+                        springStartState = lastSpringState,
+                        springParameters = tightenedSpringParameters,
+                        springStartTimeNanos = lastFrameTimeNanos,
+                    )
+                }
+            }
+
+            SegmentChangeType.SameOppositeDirection,
+            SegmentChangeType.Direction,
+            SegmentChangeType.Spec -> {
+                // Determine the delta in the output, as produced by the old and new mapping.
+                val currentMapping = currentSegment.mapping.map(currentInput)
+                val lastMapping = lastSegment.mapping.map(currentInput)
+                val delta = currentMapping - lastMapping
+
+                val deltaIsFinite = delta.fastIsFinite()
+                if (!deltaIsFinite) {
+                    Log.wtf(
+                        TAG,
+                        "Delta between mappings is undefined!\n" +
+                            "  MotionValue: $label\n" +
+                            "  input: $currentInput\n" +
+                            "  lastMapping: $lastMapping (lastSegment: $lastSegment)\n" +
+                            "  currentMapping: $currentMapping (currentSegment: $currentSegment)",
+                    )
+                }
+
+                if (delta == 0f || !deltaIsFinite) {
+                    // Nothing new to animate.
+                    lastAnimation
+                } else {
+                    val springParameters =
+                        if (segmentChangeType == SegmentChangeType.Direction) {
+                            currentSegment.entryBreakpoint.spring
+                        } else {
+                            currentSpec.resetSpring
+                        }
+
+                    val newTarget = delta - lastSpringState.displacement
+                    DiscontinuityAnimation(
+                        newTarget,
+                        SpringState(-newTarget, lastSpringState.velocity + directMappedVelocity),
+                        springParameters,
+                        lastFrameTimeNanos,
+                    )
+                }
+            }
+
+            SegmentChangeType.Traverse -> {
+                // Process all breakpoints traversed, in order.
+                // This is involved due to the guarantees - they have to be applied, one after the
+                // other, before crossing the next breakpoint.
+                val currentDirection = currentSegment.direction
+
+                with(currentSpec[currentDirection]) {
+                    val targetIndex = findSegmentIndex(currentSegment.key)
+                    val sourceIndex = findSegmentIndex(lastSegment.key)
+                    check(targetIndex != sourceIndex)
+
+                    val directionOffset = if (targetIndex > sourceIndex) 1 else -1
+
+                    var lastBreakpoint = lastSegment.entryBreakpoint
+                    var lastAnimationTime = lastFrameTimeNanos
+                    var guaranteeState = lastGuaranteeState
+                    var springState = lastSpringState
+                    var springTarget = lastAnimation.targetValue
+                    var springParameters = lastAnimation.springParameters
+
+                    var segmentIndex = sourceIndex
+                    while (segmentIndex != targetIndex) {
+                        val nextBreakpoint =
+                            breakpoints[segmentIndex + directionOffset.fastCoerceAtLeast(0)]
+
+                        val nextBreakpointFrameFraction =
+                            lastFrameFractionOfPosition(nextBreakpoint.position)
+
+                        val nextBreakpointCrossTime =
+                            lerp(
+                                lastFrameTimeNanos,
+                                currentAnimationTimeNanos,
+                                nextBreakpointFrameFraction,
+                            )
+                        if (
+                            guaranteeState != GuaranteeState.Inactive &&
+                                springState != SpringState.AtRest
+                        ) {
+                            val guaranteeValueAtNextBreakpoint =
+                                when (lastBreakpoint.guarantee) {
+                                    is Guarantee.InputDelta -> nextBreakpoint.position
+                                    is Guarantee.GestureDragDelta ->
+                                        lerp(
+                                            lastGestureDragOffset,
+                                            currentGestureDragOffset,
+                                            nextBreakpointFrameFraction,
+                                        )
+
+                                    is Guarantee.None ->
+                                        error(
+                                            "guaranteeState ($guaranteeState) is not Inactive, guarantee is missing"
+                                        )
+                                }
+
+                            guaranteeState =
+                                guaranteeState.withCurrentValue(
+                                    guaranteeValueAtNextBreakpoint,
+                                    currentDirection,
+                                )
+
+                            springParameters =
+                                guaranteeState.updatedSpringParameters(lastBreakpoint)
+                        }
+
+                        springState =
+                            springState.calculateUpdatedState(
+                                nextBreakpointCrossTime - lastAnimationTime,
+                                springParameters,
+                            )
+                        lastAnimationTime = nextBreakpointCrossTime
+
+                        val mappingBefore = mappings[segmentIndex]
+                        val beforeBreakpoint = mappingBefore.map(nextBreakpoint.position)
+                        val mappingAfter = mappings[segmentIndex + directionOffset]
+                        val afterBreakpoint = mappingAfter.map(nextBreakpoint.position)
+
+                        val delta = afterBreakpoint - beforeBreakpoint
+                        val deltaIsFinite = delta.fastIsFinite()
+                        if (!deltaIsFinite) {
+                            Log.wtf(
+                                TAG,
+                                "Delta between breakpoints is undefined!\n" +
+                                    "  MotionValue: $label\n" +
+                                    "  position: ${nextBreakpoint.position}\n" +
+                                    "  before: $beforeBreakpoint (mapping: $mappingBefore)\n" +
+                                    "  after: $afterBreakpoint (mapping: $mappingAfter)",
+                            )
+                        }
+
+                        if (deltaIsFinite) {
+                            springTarget += delta
+                            springState = springState.nudge(displacementDelta = -delta)
+                        }
+                        segmentIndex += directionOffset
+                        lastBreakpoint = nextBreakpoint
+                        guaranteeState =
+                            when (nextBreakpoint.guarantee) {
+                                is Guarantee.InputDelta ->
+                                    GuaranteeState.withStartValue(nextBreakpoint.position)
+
+                                is Guarantee.GestureDragDelta ->
+                                    GuaranteeState.withStartValue(
+                                        lerp(
+                                            lastGestureDragOffset,
+                                            currentGestureDragOffset,
+                                            nextBreakpointFrameFraction,
+                                        )
+                                    )
+
+                                is Guarantee.None -> GuaranteeState.Inactive
+                            }
+                    }
+
+                    if (springState.displacement != 0f) {
+                        springState = springState.nudge(velocityDelta = directMappedVelocity)
+                    }
+
+                    val tightened =
+                        currentGuaranteeState.updatedSpringParameters(
+                            currentSegment.entryBreakpoint
+                        )
+
+                    DiscontinuityAnimation(springTarget, springState, tightened, lastAnimationTime)
+                }
+            }
+        }
+    }
+}
+
+internal interface ComputeSpringState : ComputeAnimation {
+    val currentAnimation: DiscontinuityAnimation
+
+    fun computeCurrentSpringState(): SpringState {
+        with(currentAnimation) {
+            if (isAtRest) return SpringState.AtRest
+
+            val nanosSinceAnimationStart = currentAnimationTimeNanos - springStartTimeNanos
+            val updatedSpringState =
+                springStartState.calculateUpdatedState(nanosSinceAnimationStart, springParameters)
+
+            return if (updatedSpringState.isStable(springParameters, stableThreshold)) {
+                SpringState.AtRest
+            } else {
+                updatedSpringState
+            }
+        }
+    }
+}
+
+internal interface Computations : ComputeSpringState {
+    val currentSpringState: SpringState
+
+    val currentDirectMapped: Float
+        get() = currentSegment.mapping.map(currentInput) - currentAnimation.targetValue
+
+    val currentAnimatedDelta: Float
+        get() = currentAnimation.targetValue + currentSpringState.displacement
+
+    val output: Float
+        get() = currentDirectMapped + currentAnimatedDelta
+
+    val outputTarget: Float
+        get() = currentDirectMapped + currentAnimation.targetValue
+
+    val isStable: Boolean
+        get() = currentSpringState == SpringState.AtRest
+}
diff --git a/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt b/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt
new file mode 100644
index 0000000..131aaa3
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/impl/DiscontinuityAnimation.kt
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
+package com.android.mechanics.impl
+
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.spring.SpringState
+
+/**
+ * Captures the start-state of a spring-animation to smooth over a discontinuity.
+ *
+ * Discontinuities are caused by segment changes, where the new and old segment produce different
+ * output values for the same input.
+ */
+internal data class DiscontinuityAnimation(
+    val targetValue: Float,
+    val springStartState: SpringState,
+    val springParameters: SpringParameters,
+    val springStartTimeNanos: Long,
+) {
+    val isAtRest: Boolean
+        get() = springStartState == SpringState.AtRest
+
+    companion object {
+        val None =
+            DiscontinuityAnimation(
+                targetValue = 0f,
+                springStartState = SpringState.AtRest,
+                springParameters = SpringParameters.Snap,
+                springStartTimeNanos = 0L,
+            )
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/impl/GuaranteeState.kt b/mechanics/src/com/android/mechanics/impl/GuaranteeState.kt
new file mode 100644
index 0000000..0c4f291
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/impl/GuaranteeState.kt
@@ -0,0 +1,77 @@
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
+package com.android.mechanics.impl
+
+import androidx.compose.ui.util.fastCoerceAtLeast
+import androidx.compose.ui.util.packFloats
+import androidx.compose.ui.util.unpackFloat1
+import androidx.compose.ui.util.unpackFloat2
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spring.SpringParameters
+import kotlin.math.max
+
+/**
+ * Captures the origin of a guarantee, and the maximal distance the input has been away from the
+ * origin at most.
+ */
+@JvmInline
+internal value class GuaranteeState(val packedValue: Long) {
+    private val start: Float
+        get() = unpackFloat1(packedValue)
+
+    private val maxDelta: Float
+        get() = unpackFloat2(packedValue)
+
+    private val isInactive: Boolean
+        get() = this == Inactive
+
+    fun withCurrentValue(value: Float, direction: InputDirection): GuaranteeState {
+        if (isInactive) return Inactive
+
+        val delta = ((value - start) * direction.sign).fastCoerceAtLeast(0f)
+        return GuaranteeState(start, max(delta, maxDelta))
+    }
+
+    fun updatedSpringParameters(breakpoint: Breakpoint): SpringParameters {
+        if (isInactive) return breakpoint.spring
+
+        val denominator =
+            when (val guarantee = breakpoint.guarantee) {
+                is Guarantee.None -> return breakpoint.spring
+                is Guarantee.InputDelta -> guarantee.delta
+                is Guarantee.GestureDragDelta -> guarantee.delta
+            }
+
+        val springTighteningFraction = maxDelta / denominator
+        return com.android.mechanics.spring.lerp(
+            breakpoint.spring,
+            SpringParameters.Snap,
+            springTighteningFraction,
+        )
+    }
+
+    companion object {
+        val Inactive = GuaranteeState(packFloats(Float.NaN, Float.NaN))
+
+        fun withStartValue(start: Float) = GuaranteeState(packFloats(start, 0f))
+    }
+}
+
+internal fun GuaranteeState(start: Float, maxDelta: Float) =
+    GuaranteeState(packFloats(start, maxDelta))
diff --git a/mechanics/src/com/android/mechanics/impl/SegmentChangeType.kt b/mechanics/src/com/android/mechanics/impl/SegmentChangeType.kt
new file mode 100644
index 0000000..b8c68bc
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/impl/SegmentChangeType.kt
@@ -0,0 +1,67 @@
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
+package com.android.mechanics.impl
+
+/**
+ * Describes how the [currentSegment] is different from last frame's [lastSegment].
+ *
+ * This affects how the discontinuities are animated and [Guarantee]s applied.
+ */
+internal enum class SegmentChangeType {
+    /**
+     * The segment has the same key, this is considered equivalent.
+     *
+     * Only the [GuaranteeState] needs to be kept updated.
+     */
+    Same,
+
+    /**
+     * The segment's direction changed, however the min / max breakpoints remain the same: This is a
+     * direction change within a segment.
+     *
+     * The delta between the mapping must be animated with the reset spring, and there is no
+     * guarantee associated with the change.
+     */
+    SameOppositeDirection,
+
+    /**
+     * The segment and its direction change. This is a direction change that happened over a segment
+     * boundary.
+     *
+     * The direction change might have happened outside the [lastSegment] already, since a segment
+     * can't be exited at the entry side.
+     */
+    Direction,
+
+    /**
+     * The segment changed, due to the [currentInput] advancing in the [currentDirection], crossing
+     * one or more breakpoints.
+     *
+     * The guarantees of all crossed breakpoints have to be applied. The [GuaranteeState] must be
+     * reset, and a new [DiscontinuityAnimation] is started.
+     */
+    Traverse,
+
+    /**
+     * The spec was changed and added or removed the previous and/or current segment.
+     *
+     * The [MotionValue] does not have a semantic understanding of this change, hence the difference
+     * output produced by the previous and current mapping are animated with the
+     * [MotionSpec.resetSpring]
+     */
+    Spec,
+}
diff --git a/mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt
new file mode 100644
index 0000000..50df9fc
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/DirectionalMotionSpecBuilder.kt
@@ -0,0 +1,479 @@
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
+package com.android.mechanics.spec
+
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Builds a [DirectionalMotionSpec] by defining a sequence of ([Breakpoint], [Mapping]) pairs.
+ *
+ * This function simplifies the creation of complex motion specifications. It allows you to define a
+ * series of motion segments, each with its own behavior, separated by breakpoints. The breakpoints
+ * and their corresponding segments will always be ordered from min to max value, regardless of how
+ * the `DirectionalMotionSpec` is applied.
+ *
+ * Example Usage:
+ * ```kotlin
+ * val motionSpec = buildDirectionalMotionSpec(
+ *     defaultSpring = materialSpatial,
+ *
+ *     // Start as a constant transition, always 0.
+ *     initialMapping = Mapping.Zero
+ * ) {
+ *     // At breakpoint 10: Linear transition from 0 to 50.
+ *     target(breakpoint = 10f, from = 0f, to = 50f)
+ *
+ *     // At breakpoint 20: Jump +5, and constant value 55.
+ *     constantValueFromCurrent(breakpoint = 20f, delta = 5f)
+ *
+ *     // At breakpoint 30: Jump to 40. Linear mapping using: progress_since_breakpoint * fraction.
+ *     fractionalInput(breakpoint = 30f, from = 40f, fraction = 2f)
+ * }
+ * ```
+ *
+ * @param defaultSpring The default [SpringParameters] to use for all breakpoints.
+ * @param initialMapping The initial [Mapping] for the first segment (defaults to
+ *   [Mapping.Identity]).
+ * @param init A lambda function that configures the [DirectionalMotionSpecBuilder]. The lambda
+ *   should return a [CanBeLastSegment] to indicate the end of the spec.
+ * @return The constructed [DirectionalMotionSpec].
+ */
+fun buildDirectionalMotionSpec(
+    defaultSpring: SpringParameters,
+    initialMapping: Mapping = Mapping.Identity,
+    init: DirectionalMotionSpecBuilder.() -> CanBeLastSegment,
+): DirectionalMotionSpec {
+    return DirectionalMotionSpecBuilderImpl(defaultSpring)
+        .also { it.mappings += initialMapping }
+        .also { it.init() }
+        .build()
+}
+
+/**
+ * Builds a simple [DirectionalMotionSpec] with a single segment.
+ *
+ * @param mapping The [Mapping] to apply to the segment. Defaults to [Mapping.Identity].
+ * @return A new [DirectionalMotionSpec] instance configured with the provided parameters.
+ */
+fun buildDirectionalMotionSpec(mapping: Mapping = Mapping.Identity): DirectionalMotionSpec {
+    return DirectionalMotionSpec(listOf(Breakpoint.minLimit, Breakpoint.maxLimit), listOf(mapping))
+}
+
+/**
+ * Defines the contract for building a [DirectionalMotionSpec].
+ *
+ * Provides methods to define breakpoints and mappings for the motion specification.
+ */
+interface DirectionalMotionSpecBuilder {
+    /** The default [SpringParameters] used for breakpoints. */
+    val defaultSpring: SpringParameters
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to
+     * linearly interpolate from a starting value ([from]) to the desired target value ([to]).
+     *
+     * Note: This segment cannot be used as the last segment in the specification, as it requires a
+     * subsequent breakpoint to define the target value.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param from The output value at the previous breakpoint, explicitly setting the starting
+     *   point for the linear mapping.
+     * @param to The desired output value at the new breakpoint.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun target(
+        breakpoint: Float,
+        from: Float,
+        to: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    )
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to
+     * linearly interpolate from the current output value (optionally with an offset of [delta]) to
+     * the desired target value ([to]).
+     *
+     * Note: This segment cannot be used as the last segment in the specification, as it requires a
+     * subsequent breakpoint to define the target value.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param to The desired output value at the new breakpoint.
+     * @param delta An optional offset to apply to the calculated starting value. Defaults to 0f.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun targetFromCurrent(
+        breakpoint: Float,
+        to: Float,
+        delta: Float = 0f,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    )
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to
+     * linearly interpolate from a starting value ([from]) and then continue with a fractional input
+     * ([fraction]).
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param from The output value at the previous breakpoint, explicitly setting the starting
+     *   point for the linear mapping.
+     * @param fraction The fractional multiplier applied to the input difference between
+     *   breakpoints.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun fractionalInput(
+        breakpoint: Float,
+        from: Float,
+        fraction: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    ): CanBeLastSegment
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to
+     * linearly interpolate from the current output value (optionally with an offset of [delta]) and
+     * then continue with a fractional input ([fraction]).
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param fraction The fractional multiplier applied to the input difference between
+     *   breakpoints.
+     * @param delta An optional offset to apply to the calculated starting value. Defaults to 0f.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun fractionalInputFromCurrent(
+        breakpoint: Float,
+        fraction: Float,
+        delta: Float = 0f,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    ): CanBeLastSegment
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to output
+     * a constant value ([value]).
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param value The constant output value for this segment.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun constantValue(
+        breakpoint: Float,
+        value: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    ): CanBeLastSegment
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment to output
+     * a constant value derived from the current output value (optionally with an offset of
+     * [delta]).
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param delta An optional offset to apply to the mapped value to determine the constant value.
+     *   Defaults to 0f.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     */
+    fun constantValueFromCurrent(
+        breakpoint: Float,
+        delta: Float = 0f,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+    ): CanBeLastSegment
+
+    /**
+     * Ends the current segment at the [breakpoint] position and defines the next segment using the
+     * provided [mapping].
+     *
+     * Note: This segment can be used as the last segment in the specification.
+     *
+     * @param breakpoint The breakpoint defining the end of the current segment and the start of the
+     *   next.
+     * @param spring The [SpringParameters] for the transition to this breakpoint. Defaults to
+     *   [defaultSpring].
+     * @param guarantee The animation guarantee for this transition. Defaults to [Guarantee.None].
+     * @param key A unique [BreakpointKey] for this breakpoint. Defaults to a newly generated key.
+     * @param mapping The custom [Mapping] to use.
+     */
+    fun mapping(
+        breakpoint: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+        key: BreakpointKey = BreakpointKey(),
+        mapping: Mapping,
+    ): CanBeLastSegment
+}
+
+/** Marker interface to indicate that a segment can be the last one in a [DirectionalMotionSpec]. */
+sealed interface CanBeLastSegment
+
+private data object CanBeLastSegmentImpl : CanBeLastSegment
+
+private class DirectionalMotionSpecBuilderImpl(override val defaultSpring: SpringParameters) :
+    DirectionalMotionSpecBuilder {
+    private val breakpoints = mutableListOf(Breakpoint.minLimit)
+    val mappings = mutableListOf<Mapping>()
+
+    private var sourceValue: Float = Float.NaN
+    private var targetValue: Float = Float.NaN
+    private var fractionalMapping: Float = Float.NaN
+    private var breakpointPosition: Float = Float.NaN
+    private var breakpointKey: BreakpointKey? = null
+
+    override fun target(
+        breakpoint: Float,
+        from: Float,
+        to: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ) {
+        toBreakpointImpl(breakpoint, key)
+        jumpToImpl(from, spring, guarantee)
+        continueWithTargetValueImpl(to)
+    }
+
+    override fun targetFromCurrent(
+        breakpoint: Float,
+        to: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ) {
+        toBreakpointImpl(breakpoint, key)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithTargetValueImpl(to)
+    }
+
+    override fun fractionalInput(
+        breakpoint: Float,
+        from: Float,
+        fraction: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key)
+        jumpToImpl(from, spring, guarantee)
+        continueWithFractionalInputImpl(fraction)
+        return CanBeLastSegmentImpl
+    }
+
+    override fun fractionalInputFromCurrent(
+        breakpoint: Float,
+        fraction: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithFractionalInputImpl(fraction)
+        return CanBeLastSegmentImpl
+    }
+
+    override fun constantValue(
+        breakpoint: Float,
+        value: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key)
+        jumpToImpl(value, spring, guarantee)
+        continueWithConstantValueImpl()
+        return CanBeLastSegmentImpl
+    }
+
+    override fun constantValueFromCurrent(
+        breakpoint: Float,
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key)
+        jumpByImpl(delta, spring, guarantee)
+        continueWithConstantValueImpl()
+        return CanBeLastSegmentImpl
+    }
+
+    override fun mapping(
+        breakpoint: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+        key: BreakpointKey,
+        mapping: Mapping,
+    ): CanBeLastSegment {
+        toBreakpointImpl(breakpoint, key)
+        continueWithImpl(mapping, spring, guarantee)
+        return CanBeLastSegmentImpl
+    }
+
+    fun build(): DirectionalMotionSpec {
+        completeImpl()
+        return DirectionalMotionSpec(breakpoints.toList(), mappings.toList())
+    }
+
+    private fun continueWithTargetValueImpl(target: Float) {
+        check(sourceValue.isFinite())
+
+        targetValue = target
+    }
+
+    private fun continueWithFractionalInputImpl(fraction: Float) {
+        check(sourceValue.isFinite())
+
+        fractionalMapping = fraction
+    }
+
+    private fun continueWithConstantValueImpl() {
+        check(sourceValue.isFinite())
+
+        mappings.add(Mapping.Fixed(sourceValue))
+        sourceValue = Float.NaN
+    }
+
+    private fun jumpToImpl(value: Float, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        doAddBreakpointImpl(spring, guarantee)
+        sourceValue = value
+    }
+
+    private fun jumpByImpl(delta: Float, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        val breakpoint = doAddBreakpointImpl(spring, guarantee)
+        sourceValue = mappings.last().map(breakpoint.position) + delta
+    }
+
+    private fun continueWithImpl(mapping: Mapping, spring: SpringParameters, guarantee: Guarantee) {
+        check(sourceValue.isNaN())
+
+        doAddBreakpointImpl(spring, guarantee)
+        mappings.add(mapping)
+    }
+
+    private fun toBreakpointImpl(atPosition: Float, key: BreakpointKey) {
+        check(breakpointPosition.isNaN())
+        check(breakpointKey == null)
+
+        if (!targetValue.isNaN() || !fractionalMapping.isNaN()) {
+            check(!sourceValue.isNaN())
+
+            val sourcePosition = breakpoints.last().position
+            val breakpointDistance = atPosition - sourcePosition
+            val mapping =
+                if (breakpointDistance == 0f) {
+                    Mapping.Fixed(sourceValue)
+                } else {
+
+                    if (fractionalMapping.isNaN()) {
+                        val delta = targetValue - sourceValue
+                        fractionalMapping = delta / (atPosition - sourcePosition)
+                    } else {
+                        val delta = (atPosition - sourcePosition) * fractionalMapping
+                        targetValue = sourceValue + delta
+                    }
+
+                    val offset = sourceValue - (sourcePosition * fractionalMapping)
+                    Mapping.Linear(fractionalMapping, offset)
+                }
+
+            mappings.add(mapping)
+            targetValue = Float.NaN
+            sourceValue = Float.NaN
+            fractionalMapping = Float.NaN
+        }
+
+        breakpointPosition = atPosition
+        breakpointKey = key
+    }
+
+    private fun completeImpl() {
+        check(targetValue.isNaN()) { "cant specify target value for last segment" }
+
+        if (!fractionalMapping.isNaN()) {
+            check(!sourceValue.isNaN())
+
+            val sourcePosition = breakpoints.last().position
+
+            mappings.add(
+                Mapping.Linear(
+                    fractionalMapping,
+                    sourceValue - (sourcePosition * fractionalMapping),
+                )
+            )
+        }
+
+        breakpoints.add(Breakpoint.maxLimit)
+    }
+
+    private fun doAddBreakpointImpl(
+        springSpec: SpringParameters,
+        guarantee: Guarantee,
+    ): Breakpoint {
+        check(breakpointPosition.isFinite())
+        return Breakpoint(checkNotNull(breakpointKey), breakpointPosition, springSpec, guarantee)
+            .also {
+                breakpoints.add(it)
+                breakpointPosition = Float.NaN
+                breakpointKey = null
+            }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
index 297c949..774d4b6 100644
--- a/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
+++ b/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
@@ -305,20 +305,26 @@ private class FluentSpecBuilder<R>(
             check(!sourceValue.isNaN())
 
             val sourcePosition = breakpoints.last().position
-
-            if (fractionalMapping.isNaN()) {
-                val delta = targetValue - sourceValue
-                fractionalMapping = delta / (atPosition - sourcePosition)
-            } else {
-                val delta = (atPosition - sourcePosition) * fractionalMapping
-                targetValue = sourceValue + delta
-            }
-
-            val offset =
-                if (buildForward) sourceValue - (sourcePosition * fractionalMapping)
-                else targetValue - (atPosition * fractionalMapping)
-
-            mappings.add(Mapping.Linear(fractionalMapping, offset))
+            val breakpointDistance = atPosition - sourcePosition
+            val mapping =
+                if (breakpointDistance == 0f) {
+                    Mapping.Fixed(sourceValue)
+                } else {
+                    if (fractionalMapping.isNaN()) {
+                        val delta = targetValue - sourceValue
+                        fractionalMapping = delta / breakpointDistance
+                    } else {
+                        val delta = breakpointDistance * fractionalMapping
+                        targetValue = sourceValue + delta
+                    }
+
+                    val offset =
+                        if (buildForward) sourceValue - (sourcePosition * fractionalMapping)
+                        else targetValue - (atPosition * fractionalMapping)
+                    Mapping.Linear(fractionalMapping, offset)
+                }
+
+            mappings.add(mapping)
             targetValue = Float.NaN
             sourceValue = Float.NaN
             fractionalMapping = Float.NaN
diff --git a/mechanics/src/com/android/mechanics/spec/Guarantee.kt b/mechanics/src/com/android/mechanics/spec/Guarantee.kt
index 33185ea..12981cc 100644
--- a/mechanics/src/com/android/mechanics/spec/Guarantee.kt
+++ b/mechanics/src/com/android/mechanics/spec/Guarantee.kt
@@ -38,8 +38,8 @@ sealed class Guarantee {
     data class InputDelta(val delta: Float) : Guarantee()
 
     /**
-     * Guarantees to complete the animation before the gesture is [distance] away from the gesture
+     * Guarantees to complete the animation before the gesture is [delta] away from the gesture
      * position captured when the breakpoint was crossed.
      */
-    data class GestureDistance(val distance: Float) : Guarantee()
+    data class GestureDragDelta(val delta: Float) : Guarantee()
 }
diff --git a/mechanics/src/com/android/mechanics/spec/Segment.kt b/mechanics/src/com/android/mechanics/spec/Segment.kt
index 14b1f40..d3e95ad 100644
--- a/mechanics/src/com/android/mechanics/spec/Segment.kt
+++ b/mechanics/src/com/android/mechanics/spec/Segment.kt
@@ -95,6 +95,10 @@ fun interface Mapping {
 
     /** `f(x) = value` */
     data class Fixed(val value: Float) : Mapping {
+        init {
+            require(value.isFinite())
+        }
+
         override fun map(input: Float): Float {
             return value
         }
@@ -102,11 +106,29 @@ fun interface Mapping {
 
     /** `f(x) = factor*x + offset` */
     data class Linear(val factor: Float, val offset: Float = 0f) : Mapping {
+        init {
+            require(factor.isFinite())
+            require(offset.isFinite())
+        }
+
         override fun map(input: Float): Float {
             return input * factor + offset
         }
     }
 
+    data class Tanh(val scaling: Float, val tilt: Float, val offset: Float = 0f) : Mapping {
+
+        init {
+            require(scaling.isFinite())
+            require(tilt.isFinite())
+            require(offset.isFinite())
+        }
+
+        override fun map(input: Float): Float {
+            return scaling * kotlin.math.tanh((input + offset) / (scaling * tilt))
+        }
+    }
+
     companion object {
         val Zero = Fixed(0f)
         val One = Fixed(1f)
diff --git a/mechanics/src/com/android/mechanics/spring/MaterialSpringParameters.kt b/mechanics/src/com/android/mechanics/spring/MaterialSpringParameters.kt
new file mode 100644
index 0000000..81af8a4
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spring/MaterialSpringParameters.kt
@@ -0,0 +1,49 @@
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
+@file:OptIn(ExperimentalMaterial3ExpressiveApi::class)
+
+package com.android.mechanics.spring
+
+import androidx.compose.animation.core.FiniteAnimationSpec
+import androidx.compose.animation.core.SpringSpec
+import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.runtime.Composable
+
+/** Converts a [SpringSpec] into its [SpringParameters] equivalent. */
+fun SpringParameters(springSpec: SpringSpec<out Any>) =
+    with(springSpec) { SpringParameters(stiffness, dampingRatio) }
+
+/**
+ * Converts a [FiniteAnimationSpec] from the [MotionScheme] into its [SpringParameters] equivalent.
+ */
+@ExperimentalMaterial3ExpressiveApi
+fun SpringParameters(animationSpec: FiniteAnimationSpec<out Any>): SpringParameters {
+    check(animationSpec is SpringSpec) {
+        "animationSpec is expected to be a SpringSpec, but is $animationSpec"
+    }
+    return SpringParameters(animationSpec)
+}
+
+@Composable
+fun defaultSpatialSpring(): SpringParameters {
+    return SpringParameters(MaterialTheme.motionScheme.defaultSpatialSpec())
+}
+
+@Composable
+fun defaultEffectSpring(): SpringParameters {
+    return SpringParameters(MaterialTheme.motionScheme.defaultEffectsSpec())
+}
diff --git a/mechanics/src/com/android/mechanics/spring/SpringParameters.kt b/mechanics/src/com/android/mechanics/spring/SpringParameters.kt
index 98b64e8..828527a 100644
--- a/mechanics/src/com/android/mechanics/spring/SpringParameters.kt
+++ b/mechanics/src/com/android/mechanics/spring/SpringParameters.kt
@@ -16,6 +16,7 @@
 
 package com.android.mechanics.spring
 
+import androidx.compose.ui.util.fastCoerceIn
 import androidx.compose.ui.util.lerp
 import androidx.compose.ui.util.packFloats
 import androidx.compose.ui.util.unpackFloat1
@@ -31,7 +32,7 @@ import kotlin.math.pow
  * @see SpringParameters function to create this value.
  */
 @JvmInline
-value class SpringParameters(private val packedValue: Long) {
+value class SpringParameters(val packedValue: Long) {
     val stiffness: Float
         get() = unpackFloat1(packedValue)
 
@@ -71,7 +72,7 @@ fun SpringParameters(stiffness: Float, dampingRatio: Float): SpringParameters {
  * The [fraction] is clamped to a `0..1` range.
  */
 fun lerp(start: SpringParameters, stop: SpringParameters, fraction: Float): SpringParameters {
-    val f = fraction.coerceIn(0f, 1f)
+    val f = fraction.fastCoerceIn(0f, 1f)
     val stiffness = start.stiffness.pow(1 - f) * stop.stiffness.pow(f)
     val dampingRatio = lerp(start.dampingRatio, stop.dampingRatio, f)
     return SpringParameters(packFloats(stiffness, dampingRatio))
diff --git a/mechanics/src/com/android/mechanics/spring/SpringState.kt b/mechanics/src/com/android/mechanics/spring/SpringState.kt
index 57de280..bdf7c33 100644
--- a/mechanics/src/com/android/mechanics/spring/SpringState.kt
+++ b/mechanics/src/com/android/mechanics/spring/SpringState.kt
@@ -31,7 +31,7 @@ import kotlin.math.sqrt
  * @see SpringState function to create this value.
  */
 @JvmInline
-value class SpringState(private val packedValue: Long) {
+value class SpringState(val packedValue: Long) {
     val displacement: Float
         get() = unpackFloat1(packedValue)
 
@@ -51,6 +51,11 @@ value class SpringState(private val packedValue: Long) {
         return currentEnergy <= maxStableEnergy
     }
 
+    /** Adds the specified [displacementDelta] and [velocityDelta] to the returned state. */
+    fun nudge(displacementDelta: Float = 0f, velocityDelta: Float = 0f): SpringState {
+        return SpringState(displacement + displacementDelta, velocity + velocityDelta)
+    }
+
     override fun toString(): String {
         return "MechanicsSpringState(displacement=$displacement, velocity=$velocity)"
     }
diff --git a/mechanics/tests/Android.bp b/mechanics/tests/Android.bp
index f892ef1..8fdf904 100644
--- a/mechanics/tests/Android.bp
+++ b/mechanics/tests/Android.bp
@@ -20,6 +20,7 @@ package {
 android_test {
     name: "mechanics_tests",
     manifest: "AndroidManifest.xml",
+    defaults: ["MotionTestDefaults"],
     test_suites: ["device-tests"],
 
     srcs: [
@@ -32,13 +33,16 @@ android_test {
     static_libs: [
         // ":mechanics" dependencies
         "androidx.compose.runtime_runtime",
+        "androidx.compose.material3_material3",
         "androidx.compose.ui_ui-util",
+        "androidx.compose.foundation_foundation-layout",
 
         // ":mechanics_tests" dependencies
         "androidx.compose.animation_animation-core",
         "platform-test-annotations",
-        "PlatformMotionTesting",
+        "PlatformMotionTestingCompose",
         "androidx.compose.ui_ui-test-junit4",
+        "androidx.compose.ui_ui-test-manifest",
         "androidx.test.runner",
         "androidx.test.ext.junit",
         "kotlin-test",
diff --git a/mechanics/tests/AndroidManifest.xml b/mechanics/tests/AndroidManifest.xml
index edbbcbf..636ebb8 100644
--- a/mechanics/tests/AndroidManifest.xml
+++ b/mechanics/tests/AndroidManifest.xml
@@ -17,10 +17,6 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.mechanics.tests">
 
-    <application>
-        <uses-library android:name="android.test.runner" />
-    </application>
-
     <instrumentation
         android:name="androidx.test.runner.AndroidJUnitRunner"
         android:label="Tests for Motion Mechanics"
diff --git a/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json b/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json
new file mode 100644
index 0000000..9fd0087
--- /dev/null
+++ b/mechanics/tests/goldens/changeDirection_flipsBetweenDirectionalSegments.json
@@ -0,0 +1,202 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2,
+        1.6,
+        1.2,
+        0.8000001,
+        0.40000007,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.12146205,
+        0.3364076,
+        0.53597057,
+        0.69039464,
+        0.79985267,
+        0.8735208,
+        0.92143244,
+        0.95184386,
+        0.97079945,
+        0.9824491,
+        0.98952854,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json b/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json
new file mode 100644
index 0000000..510426b
--- /dev/null
+++ b/mechanics/tests/goldens/changingInput_addsAnimationToMapping_becomesStable.json
@@ -0,0 +1,82 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1.1,
+        1.1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0.05119291,
+        0.095428914
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0.55,
+        0.55
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json b/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json
new file mode 100644
index 0000000..873df80
--- /dev/null
+++ b/mechanics/tests/goldens/derivedValue_hasAnimationLifecycleOnItsOwn.json
@@ -0,0 +1,553 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.1,
+        0.2,
+        0.3,
+        0.4,
+        0.5,
+        0.6,
+        0.70000005,
+        0.8000001,
+        0.9000001,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "derived-input",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "derived-gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "derived-output",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0.9953138,
+        0.89982635,
+        0.74407,
+        0.5794298,
+        0.43098712,
+        0.308447,
+        0.21313858,
+        0.1423173,
+        0.091676354,
+        0.056711912,
+        0.0333848,
+        0.01837182,
+        0.009094477,
+        0.003640592,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "derived-outputTarget",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "derived-outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "derived-isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json b/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json
new file mode 100644
index 0000000..e4bd600
--- /dev/null
+++ b/mechanics/tests/goldens/derivedValue_reflectsInputChangeInSameFrame.json
@@ -0,0 +1,477 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.1,
+        0.2,
+        0.3,
+        0.4,
+        0.5,
+        0.6,
+        0.70000005,
+        0.8000001,
+        0.9000001,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "derived-input",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "derived-gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "derived-output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "derived-outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "derived-outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "derived-isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json b/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json
new file mode 100644
index 0000000..c015899
--- /dev/null
+++ b/mechanics/tests/goldens/directionChange_maxToMin_appliesGuarantee_afterDirectionChange.json
@@ -0,0 +1,182 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2,
+        1.5,
+        1,
+        0.5,
+        0,
+        -0.5,
+        -1,
+        -1.5,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0.9303996,
+        0.48961937,
+        0.1611222,
+        0.04164827,
+        0.008622885,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json b/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json
new file mode 100644
index 0000000..37b9396
--- /dev/null
+++ b/mechanics/tests/goldens/directionChange_maxToMin_changesSegmentWithDirectionChange.json
@@ -0,0 +1,262 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2,
+        1.5,
+        1,
+        0.5,
+        0,
+        -0.5,
+        -1,
+        -1.5,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2,
+        -2
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0.9303996,
+        0.7829481,
+        0.61738,
+        0.46381497,
+        0.3348276,
+        0.2332502,
+        0.15701783,
+        0.10203475,
+        0.06376374,
+        0.038021922,
+        0.021308899,
+        0.010875165,
+        0.0046615005,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json b/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json
new file mode 100644
index 0000000..0c034c2
--- /dev/null
+++ b/mechanics/tests/goldens/directionChange_minToMax_changesSegmentWithDirectionChange.json
@@ -0,0 +1,262 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1.5,
+        2,
+        2.5,
+        3,
+        3.5,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4,
+        4
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json b/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json
new file mode 100644
index 0000000..70d62ab
--- /dev/null
+++ b/mechanics/tests/goldens/emptySpec_outputMatchesInput_withoutAnimation.json
@@ -0,0 +1,112 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        20,
+        40,
+        60,
+        80,
+        100,
+        100
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json
new file mode 100644
index 0000000..e378671
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_atSpringStart.json
@@ -0,0 +1,282 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11,
+        11
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        10.58992,
+        13.213701,
+        15.27689,
+        16.823486,
+        17.93786,
+        18.712797,
+        19.23355,
+        19.571312,
+        19.781933,
+        19.907185,
+        19.977114,
+        20.01258,
+        20.02758,
+        20.031174,
+        20.029,
+        20.024399,
+        20.019238,
+        20.014452,
+        20.010433,
+        20,
+        20
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20,
+        20
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json
new file mode 100644
index 0000000..e37510d
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice.json
@@ -0,0 +1,322 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400,
+    416,
+    432
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        12,
+        15,
+        18,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21,
+        21
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        14.22027,
+        20.881996,
+        27.33559,
+        33.145477,
+        36.971085,
+        39.13093,
+        40.246414,
+        40.73661,
+        40.874382,
+        40.830643,
+        40.70759,
+        40.56272,
+        40.42557,
+        40.30897,
+        40.21637,
+        40.146416,
+        40.095673,
+        40.060165,
+        40.036156,
+        40.020485,
+        40.01064,
+        40.00473,
+        40,
+        40
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        3,
+        6,
+        9,
+        32,
+        35,
+        38,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40,
+        40
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json b/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json
new file mode 100644
index 0000000..6eb0987
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance.json
@@ -0,0 +1,132 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.13920438,
+        0.45275474,
+        0.772992,
+        0.9506903,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1600.4729,
+          "dampingRatio": 0.9166666
+        },
+        {
+          "stiffness": 3659.3052,
+          "dampingRatio": 0.9333333
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 19129.314,
+          "dampingRatio": 0.9666667
+        },
+        {
+          "stiffness": 43737.062,
+          "dampingRatio": 0.98333335
+        },
+        {
+          "stiffness": 43737.062,
+          "dampingRatio": 0.98333335
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json b/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json
new file mode 100644
index 0000000..9ca1bfa
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_guaranteeInputDelta_springCompletesWithinDistance.json
@@ -0,0 +1,142 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1.5,
+        2,
+        2.5,
+        3,
+        3.5,
+        4,
+        4
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.13920438,
+        0.45275474,
+        0.772992,
+        0.9506903,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1600.4729,
+          "dampingRatio": 0.9166666
+        },
+        {
+          "stiffness": 3659.3052,
+          "dampingRatio": 0.9333333
+        },
+        {
+          "stiffness": 8366.601,
+          "dampingRatio": 0.95
+        },
+        {
+          "stiffness": 19129.314,
+          "dampingRatio": 0.9666667
+        },
+        {
+          "stiffness": 43737.062,
+          "dampingRatio": 0.98333335
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json b/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json
new file mode 100644
index 0000000..fe6c211
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_guaranteeNone_springAnimatesIndependentOfInput.json
@@ -0,0 +1,222 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1.5,
+        2,
+        2.5,
+        3,
+        3.5,
+        4,
+        4.5,
+        5,
+        5,
+        5,
+        5,
+        5,
+        5,
+        5,
+        5
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json b/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json
new file mode 100644
index 0000000..e78a244
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_inMaxDirection_animatedWhenReachingBreakpoint.json
@@ -0,0 +1,222 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.6651724,
+        0.7667498,
+        0.8429822,
+        0.89796525,
+        0.93623626,
+        0.9619781,
+        0.9786911,
+        0.98912483,
+        0.9953385,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json b/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json
new file mode 100644
index 0000000..0ad35c3
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_inMaxDirection_springAnimationStartedRetroactively.json
@@ -0,0 +1,212 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0.01973492,
+        0.1381998,
+        0.29998195,
+        0.4619913,
+        0.6040878,
+        0.71933174,
+        0.80780226,
+        0.8728444,
+        0.9189145,
+        0.95043683,
+        0.971274,
+        0.9845492,
+        0.9926545,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json b/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json
new file mode 100644
index 0000000..333387e
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_inMinDirection_animatedWhenReachingBreakpoint.json
@@ -0,0 +1,222 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2,
+        1.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        1,
+        0.9303996,
+        0.7829481,
+        0.61738,
+        0.46381497,
+        0.3348276,
+        0.2332502,
+        0.15701783,
+        0.10203475,
+        0.06376374,
+        0.038021922,
+        0.021308899,
+        0.010875165,
+        0.0046615005,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json b/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json
new file mode 100644
index 0000000..87337cc
--- /dev/null
+++ b/mechanics/tests/goldens/segmentChange_inMinDirection_springAnimationStartedRetroactively.json
@@ -0,0 +1,212 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2,
+        1.5,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1,
+        1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        0.9802651,
+        0.8618002,
+        0.70001805,
+        0.5380087,
+        0.39591217,
+        0.28066826,
+        0.19219774,
+        0.1271556,
+        0.0810855,
+        0.04956317,
+        0.028725982,
+        0.015450776,
+        0.0073454976,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1,
+        1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json b/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json
new file mode 100644
index 0000000..2f23446
--- /dev/null
+++ b/mechanics/tests/goldens/specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange.json
@@ -0,0 +1,192 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1.5,
+        1.7,
+        1.9,
+        1.7769231,
+        1.356505,
+        0.92442614,
+        0.5804193,
+        0.33967388,
+        0.18536365,
+        0.093348265,
+        0.042140007,
+        0.015731335,
+        0.0033904314,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1.5,
+        1.7,
+        1.9,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json b/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json
new file mode 100644
index 0000000..0be0241
--- /dev/null
+++ b/mechanics/tests/goldens/specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange.json
@@ -0,0 +1,172 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5,
+        0.5
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        1.5,
+        1.3,
+        1.1,
+        0.84658206,
+        0.579976,
+        0.36567324,
+        0.21482599,
+        0.11771333,
+        0.05957961,
+        0.027098536,
+        0.010269046,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        1.5,
+        1.3,
+        1.1,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1400,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json
new file mode 100644
index 0000000..79fd8b3
--- /dev/null
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity.json
@@ -0,0 +1,212 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5,
+        2.5
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        1.0034066,
+        1.0953252,
+        1.250015,
+        1.4148881,
+        1.5641418,
+        1.6876622,
+        1.783909,
+        1.855533,
+        1.9068143,
+        1.9422642,
+        1.9659443,
+        1.981205,
+        1.9906502,
+        1.996214,
+        2,
+        2
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json
new file mode 100644
index 0000000..a2765d1
--- /dev/null
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees.json
@@ -0,0 +1,152 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        2.5,
+        0.4,
+        0.3,
+        0.20000002,
+        0.10000002,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min",
+        "Min"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        2,
+        1.8607992,
+        1.5158144,
+        1.0649259,
+        0.62475336,
+        0.29145694,
+        0.11132395,
+        0.036348104,
+        0.009979486,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        2,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 1149.7095,
+          "dampingRatio": 0.90999997
+        },
+        {
+          "stiffness": 1888.3324,
+          "dampingRatio": 0.91999996
+        },
+        {
+          "stiffness": 3101.4778,
+          "dampingRatio": 0.93000007
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        },
+        {
+          "stiffness": 5094,
+          "dampingRatio": 0.94000006
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json
new file mode 100644
index 0000000..418a6de
--- /dev/null
+++ b/mechanics/tests/goldens/traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees.json
@@ -0,0 +1,182 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1,
+        2.1
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        5.000347,
+        5.12011,
+        5.3309407,
+        5.534604,
+        5.6969075,
+        5.8133464,
+        5.8910213,
+        5.93988,
+        5.969008,
+        5.9854507,
+        5.9941716,
+        6,
+        6
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6,
+        6
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        },
+        {
+          "stiffness": 1214.8745,
+          "dampingRatio": 0.91111106
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json b/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json
new file mode 100644
index 0000000..35ede9c
--- /dev/null
+++ b/mechanics/tests/goldens/traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation.json
@@ -0,0 +1,302 @@
+{
+  "frame_ids": [
+    0,
+    16,
+    32,
+    48,
+    64,
+    80,
+    96,
+    112,
+    128,
+    144,
+    160,
+    176,
+    192,
+    208,
+    224,
+    240,
+    256,
+    272,
+    288,
+    304,
+    320,
+    336,
+    352,
+    368,
+    384,
+    400
+  ],
+  "features": [
+    {
+      "name": "input",
+      "type": "float",
+      "data_points": [
+        0,
+        0.2,
+        0.4,
+        0.6,
+        0.8,
+        1,
+        1.2,
+        1.4000001,
+        1.6000001,
+        1.8000002,
+        2.0000002,
+        2.2000003,
+        2.4000003,
+        2.6000004,
+        2.8000004,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3,
+        3
+      ]
+    },
+    {
+      "name": "gestureDirection",
+      "type": "string",
+      "data_points": [
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max",
+        "Max"
+      ]
+    },
+    {
+      "name": "output",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        0,
+        0.0696004,
+        0.21705192,
+        0.38261998,
+        0.536185,
+        0.66517246,
+        0.8363503,
+        1.0600344,
+        1.2805854,
+        1.4724215,
+        1.6271507,
+        1.745441,
+        1.8321071,
+        1.8933039,
+        1.9350511,
+        1.9625617,
+        1.9800283,
+        1.9906485,
+        1.996761,
+        2,
+        2
+      ]
+    },
+    {
+      "name": "outputTarget",
+      "type": "float",
+      "data_points": [
+        0,
+        0,
+        0,
+        0,
+        0,
+        1,
+        1,
+        1,
+        1,
+        1,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2,
+        2
+      ]
+    },
+    {
+      "name": "outputSpring",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        },
+        {
+          "stiffness": 700,
+          "dampingRatio": 0.9
+        }
+      ]
+    },
+    {
+      "name": "isStable",
+      "type": "boolean",
+      "data_points": [
+        true,
+        true,
+        true,
+        true,
+        true,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt b/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt
index 4784f9e..20b49a8 100644
--- a/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt
+++ b/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt
@@ -31,13 +31,13 @@ class DistanceGestureContextTest {
     fun setDistance_maxDirection_increasingInput_keepsDirection() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Max,
                 directionChangeSlop = 5f,
             )
 
         for (value in 0..6) {
-            underTest.distance = value.toFloat()
+            underTest.dragOffset = value.toFloat()
             assertThat(underTest.direction).isEqualTo(InputDirection.Max)
         }
     }
@@ -46,13 +46,13 @@ class DistanceGestureContextTest {
     fun setDistance_minDirection_decreasingInput_keepsDirection() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Min,
                 directionChangeSlop = 5f,
             )
 
         for (value in 0 downTo -6) {
-            underTest.distance = value.toFloat()
+            underTest.dragOffset = value.toFloat()
             assertThat(underTest.direction).isEqualTo(InputDirection.Min)
         }
     }
@@ -61,12 +61,12 @@ class DistanceGestureContextTest {
     fun setDistance_maxDirection_decreasingInput_keepsDirection_belowDirectionChangeSlop() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Max,
                 directionChangeSlop = 5f,
             )
 
-        underTest.distance = -5f
+        underTest.dragOffset = -5f
         assertThat(underTest.direction).isEqualTo(InputDirection.Max)
     }
 
@@ -74,12 +74,12 @@ class DistanceGestureContextTest {
     fun setDistance_maxDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Max,
                 directionChangeSlop = 5f,
             )
 
-        underTest.distance = (-5f).nextDown()
+        underTest.dragOffset = (-5f).nextDown()
         assertThat(underTest.direction).isEqualTo(InputDirection.Min)
     }
 
@@ -87,12 +87,12 @@ class DistanceGestureContextTest {
     fun setDistance_minDirection_increasingInput_keepsDirection_belowDirectionChangeSlop() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Min,
                 directionChangeSlop = 5f,
             )
 
-        underTest.distance = 5f
+        underTest.dragOffset = 5f
         assertThat(underTest.direction).isEqualTo(InputDirection.Min)
     }
 
@@ -100,12 +100,12 @@ class DistanceGestureContextTest {
     fun setDistance_minDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 0f,
+                initialDragOffset = 0f,
                 initialDirection = InputDirection.Min,
                 directionChangeSlop = 5f,
             )
 
-        underTest.distance = 5f.nextUp()
+        underTest.dragOffset = 5f.nextUp()
         assertThat(underTest.direction).isEqualTo(InputDirection.Max)
     }
 
@@ -113,39 +113,39 @@ class DistanceGestureContextTest {
     fun reset_resetsFurthestValue() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 10f,
+                initialDragOffset = 10f,
                 initialDirection = InputDirection.Max,
                 directionChangeSlop = 1f,
             )
 
         underTest.reset(5f, direction = InputDirection.Max)
         assertThat(underTest.direction).isEqualTo(InputDirection.Max)
-        assertThat(underTest.distance).isEqualTo(5f)
+        assertThat(underTest.dragOffset).isEqualTo(5f)
 
-        underTest.distance -= 1f
+        underTest.dragOffset -= 1f
         assertThat(underTest.direction).isEqualTo(InputDirection.Max)
-        assertThat(underTest.distance).isEqualTo(4f)
+        assertThat(underTest.dragOffset).isEqualTo(4f)
 
-        underTest.distance = underTest.distance.nextDown()
+        underTest.dragOffset = underTest.dragOffset.nextDown()
         assertThat(underTest.direction).isEqualTo(InputDirection.Min)
-        assertThat(underTest.distance).isWithin(0.0001f).of(4f)
+        assertThat(underTest.dragOffset).isWithin(0.0001f).of(4f)
     }
 
     @Test
     fun setDirectionChangeSlop_smallerThanCurrentDelta_switchesDirection() {
         val underTest =
             DistanceGestureContext(
-                initialDistance = 10f,
+                initialDragOffset = 10f,
                 initialDirection = InputDirection.Max,
                 directionChangeSlop = 5f,
             )
 
-        underTest.distance -= 2f
+        underTest.dragOffset -= 2f
         assertThat(underTest.direction).isEqualTo(InputDirection.Max)
-        assertThat(underTest.distance).isEqualTo(8f)
+        assertThat(underTest.dragOffset).isEqualTo(8f)
 
         underTest.directionChangeSlop = 1f
         assertThat(underTest.direction).isEqualTo(InputDirection.Min)
-        assertThat(underTest.distance).isEqualTo(8f)
+        assertThat(underTest.dragOffset).isEqualTo(8f)
     }
 }
diff --git a/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt b/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt
new file mode 100644
index 0000000..218067c
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/MotionValueTest.kt
@@ -0,0 +1,716 @@
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
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
+package com.android.mechanics
+
+import android.util.Log
+import android.util.Log.TerribleFailureHandler
+import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.snapshotFlow
+import androidx.compose.ui.test.ExperimentalTestApi
+import androidx.compose.ui.test.TestMonotonicFrameClock
+import androidx.compose.ui.test.junit4.createComposeRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Guarantee
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.spec.MotionSpec
+import com.android.mechanics.spec.builder
+import com.android.mechanics.spec.reverseBuilder
+import com.android.mechanics.testing.DefaultSprings.matStandardDefault
+import com.android.mechanics.testing.DefaultSprings.matStandardFast
+import com.android.mechanics.testing.MotionValueToolkit
+import com.android.mechanics.testing.MotionValueToolkit.Companion.dataPoints
+import com.android.mechanics.testing.MotionValueToolkit.Companion.input
+import com.android.mechanics.testing.MotionValueToolkit.Companion.isStable
+import com.android.mechanics.testing.MotionValueToolkit.Companion.output
+import com.android.mechanics.testing.VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
+import com.android.mechanics.testing.VerifyTimeSeriesResult.SkipGoldenVerification
+import com.android.mechanics.testing.goldenTest
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.TestCoroutineScheduler
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.withContext
+import org.junit.Rule
+import org.junit.Test
+import org.junit.rules.ExternalResource
+import org.junit.runner.RunWith
+import platform.test.motion.MotionTestRule
+import platform.test.motion.testing.createGoldenPathManager
+
+@RunWith(AndroidJUnit4::class)
+class MotionValueTest {
+    private val goldenPathManager =
+        createGoldenPathManager("frameworks/libs/systemui/mechanics/tests/goldens")
+
+    @get:Rule(order = 0) val rule = createComposeRule()
+    @get:Rule(order = 1) val motion = MotionTestRule(MotionValueToolkit(rule), goldenPathManager)
+    @get:Rule(order = 2) val wtfLog = WtfLogRule()
+
+    @Test
+    fun emptySpec_outputMatchesInput_withoutAnimation() =
+        motion.goldenTest(
+            spec = MotionSpec.Empty,
+            verifyTimeSeries = {
+                // Output always matches the input
+                assertThat(output).containsExactlyElementsIn(input).inOrder()
+                // There must never be an ongoing animation.
+                assertThat(isStable).doesNotContain(false)
+
+                AssertTimeSeriesMatchesGolden
+            },
+        ) {
+            animateValueTo(100f)
+        }
+
+    // TODO the tests should describe the expected values not only in terms of goldens, but
+    // also explicitly in verifyTimeSeries
+
+    @Test
+    fun changingInput_addsAnimationToMapping_becomesStable() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping.Linear(factor = 0.5f))
+        ) {
+            animateValueTo(1.1f, changePerFrame = 0.5f)
+            while (underTest.isStable) {
+                updateValue(input + 0.5f)
+                awaitFrames()
+            }
+        }
+
+    @Test
+    fun segmentChange_inMaxDirection_animatedWhenReachingBreakpoint() =
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_inMinDirection_animatedWhenReachingBreakpoint() =
+        motion.goldenTest(
+            initialValue = 2f,
+            initialDirection = InputDirection.Min,
+            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_inMaxDirection_springAnimationStartedRetroactively() =
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(.75f).completeWith(Mapping.One)
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_inMinDirection_springAnimationStartedRetroactively() =
+        motion.goldenTest(
+            initialValue = 2f,
+            initialDirection = InputDirection.Min,
+            spec = specBuilder(Mapping.Zero).toBreakpoint(1.25f).completeWith(Mapping.One),
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_guaranteeNone_springAnimatesIndependentOfInput() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping.One, guarantee = Guarantee.None)
+        ) {
+            animateValueTo(5f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_guaranteeInputDelta_springCompletesWithinDistance() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping.One, guarantee = Guarantee.InputDelta(3f))
+        ) {
+            animateValueTo(4f, changePerFrame = 0.5f)
+        }
+
+    @Test
+    fun segmentChange_guaranteeGestureDragDelta_springCompletesWithinDistance() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping.One, guarantee = Guarantee.GestureDragDelta(3f))
+        ) {
+            animateValueTo(1f, changePerFrame = 0.5f)
+            while (!underTest.isStable) {
+                gestureContext.dragOffset += 0.5f
+                awaitFrames()
+            }
+        }
+
+    @Test
+    fun segmentChange_appliesOutputVelocity_atSpringStart() =
+        motion.goldenTest(spec = specBuilder().toBreakpoint(10f).completeWith(Mapping.Fixed(20f))) {
+            animateValueTo(11f, changePerFrame = 3f)
+            awaitStable()
+        }
+
+    @Test
+    fun segmentChange_appliesOutputVelocity_springVelocityIsNotAppliedTwice() =
+        motion.goldenTest(
+            spec =
+                specBuilder()
+                    .toBreakpoint(10f)
+                    .continueWith(Mapping.Linear(factor = 1f, offset = 20f))
+                    .toBreakpoint(20f)
+                    .completeWith(Mapping.Fixed(40f))
+        ) {
+            animateValueTo(21f, changePerFrame = 3f)
+            awaitStable()
+        }
+
+    @Test
+    fun specChange_shiftSegmentBackwards_doesNotAnimateWithinSegment_animatesSegmentChange() {
+        fun generateSpec(offset: Float) =
+            specBuilder(Mapping.Zero)
+                .toBreakpoint(offset, B1)
+                .jumpTo(1f)
+                .continueWithTargetValue(2f)
+                .toBreakpoint(offset + 1f, B2)
+                .completeWith(Mapping.Zero)
+
+        motion.goldenTest(spec = generateSpec(0f), initialValue = .5f) {
+            var offset = 0f
+            repeat(4) {
+                offset -= .2f
+                underTest.spec = generateSpec(offset)
+                awaitFrames()
+            }
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun specChange_shiftSegmentForward_doesNotAnimateWithinSegment_animatesSegmentChange() {
+        fun generateSpec(offset: Float) =
+            specBuilder(Mapping.Zero)
+                .toBreakpoint(offset, B1)
+                .jumpTo(1f)
+                .continueWithTargetValue(2f)
+                .toBreakpoint(offset + 1f, B2)
+                .completeWith(Mapping.Zero)
+
+        motion.goldenTest(spec = generateSpec(0f), initialValue = .5f) {
+            var offset = 0f
+            repeat(4) {
+                offset += .2f
+                underTest.spec = generateSpec(offset)
+                awaitFrames()
+            }
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun directionChange_maxToMin_changesSegmentWithDirectionChange() =
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+            initialValue = 2f,
+            initialDirection = InputDirection.Max,
+            directionChangeSlop = 3f,
+        ) {
+            animateValueTo(-2f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun directionChange_minToMax_changesSegmentWithDirectionChange() =
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One),
+            initialValue = 0f,
+            initialDirection = InputDirection.Min,
+            directionChangeSlop = 3f,
+        ) {
+            animateValueTo(4f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun directionChange_maxToMin_appliesGuarantee_afterDirectionChange() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping.One, guarantee = Guarantee.InputDelta(1f)),
+            initialValue = 2f,
+            initialDirection = InputDirection.Max,
+            directionChangeSlop = 3f,
+        ) {
+            animateValueTo(-2f, changePerFrame = 0.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun traverseSegments_maxDirection_noGuarantee_addsDiscontinuityToOngoingAnimation() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .continueWith(Mapping.One)
+                    .toBreakpoint(2f)
+                    .completeWith(Mapping.Two)
+        ) {
+            animateValueTo(3f, changePerFrame = 0.2f)
+            awaitStable()
+        }
+
+    @Test
+    fun traverseSegmentsInOneFrame_noGuarantee_combinesDiscontinuity() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .continueWith(Mapping.One)
+                    .toBreakpoint(2f)
+                    .completeWith(Mapping.Two)
+        ) {
+            updateValue(2.5f)
+            awaitStable()
+        }
+
+    @Test
+    fun traverseSegmentsInOneFrame_withGuarantee_appliesGuarantees() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .jumpBy(5f, guarantee = Guarantee.InputDelta(.9f))
+                    .continueWithConstantValue()
+                    .toBreakpoint(2f)
+                    .jumpBy(1f, guarantee = Guarantee.InputDelta(.9f))
+                    .continueWithConstantValue()
+                    .complete()
+        ) {
+            updateValue(2.1f)
+            awaitStable()
+        }
+
+    @Test
+    fun traverseSegmentsInOneFrame_withDirectionChange_appliesGuarantees() =
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .continueWith(Mapping.One, guarantee = Guarantee.InputDelta(1f))
+                    .toBreakpoint(2f)
+                    .completeWith(Mapping.Two),
+            initialValue = 2.5f,
+            initialDirection = InputDirection.Max,
+            directionChangeSlop = 1f,
+        ) {
+            updateValue(.5f)
+            animateValueTo(0f)
+            awaitStable()
+        }
+
+    @Test
+    fun changeDirection_flipsBetweenDirectionalSegments() {
+        val spec =
+            MotionSpec(
+                maxDirection = forwardSpecBuilder(Mapping.Zero).complete(),
+                minDirection = reverseSpecBuilder(Mapping.One).complete(),
+            )
+
+        motion.goldenTest(
+            spec = spec,
+            initialValue = 2f,
+            initialDirection = InputDirection.Max,
+            directionChangeSlop = 1f,
+        ) {
+            animateValueTo(0f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun derivedValue_reflectsInputChangeInSameFrame() {
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(0.5f).completeWith(Mapping.One),
+            createDerived = { primary ->
+                listOf(MotionValue.createDerived(primary, MotionSpec.Empty, label = "derived"))
+            },
+            verifyTimeSeries = {
+                // the output of the derived value must match the primary value
+                assertThat(output)
+                    .containsExactlyElementsIn(dataPoints<Float>("derived-output"))
+                    .inOrder()
+                // and its never animated.
+                assertThat(dataPoints<Float>("derived-isStable")).doesNotContain(false)
+
+                AssertTimeSeriesMatchesGolden
+            },
+        ) {
+            animateValueTo(1f, changePerFrame = 0.1f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun derivedValue_hasAnimationLifecycleOnItsOwn() {
+        motion.goldenTest(
+            spec = specBuilder(Mapping.Zero).toBreakpoint(0.5f).completeWith(Mapping.One),
+            createDerived = { primary ->
+                listOf(
+                    MotionValue.createDerived(
+                        primary,
+                        specBuilder(Mapping.One).toBreakpoint(0.5f).completeWith(Mapping.Zero),
+                        label = "derived",
+                    )
+                )
+            },
+        ) {
+            animateValueTo(1f, changePerFrame = 0.1f)
+            awaitStable()
+        }
+    }
+
+    @Test
+    fun nonFiniteNumbers_producesNaN_recoversOnSubsequentFrames() {
+        motion.goldenTest(
+            spec = specBuilder(Mapping { if (it >= 1f) Float.NaN else 0f }).complete(),
+            verifyTimeSeries = {
+                assertThat(output.drop(1).take(5))
+                    .containsExactlyElementsIn(listOf(0f, Float.NaN, Float.NaN, 0f, 0f))
+                    .inOrder()
+                SkipGoldenVerification
+            },
+        ) {
+            animatedInputSequence(0f, 1f, 1f, 0f, 0f)
+        }
+
+        assertThat(wtfLog.loggedFailures).isEmpty()
+    }
+
+    @Test
+    fun nonFiniteNumbers_segmentChange_skipsAnimation() {
+        motion.goldenTest(
+            spec = MotionSpec.Empty,
+            verifyTimeSeries = {
+                // The mappings produce a non-finite number during a segment change.
+                // The animation thereof is skipped to avoid poisoning the state with non-finite
+                // numbers
+                assertThat(output.drop(1).take(5))
+                    .containsExactlyElementsIn(listOf(0f, 1f, Float.NaN, 0f, 0f))
+                    .inOrder()
+                SkipGoldenVerification
+            },
+        ) {
+            animatedInputSequence(0f, 1f)
+            underTest.spec =
+                specBuilder()
+                    .toBreakpoint(0f)
+                    .completeWith(Mapping { if (it >= 1f) Float.NaN else 0f })
+            awaitFrames()
+
+            animatedInputSequence(0f, 0f)
+        }
+
+        assertThat(wtfLog.loggedFailures).hasSize(1)
+        assertThat(wtfLog.loggedFailures.first()).startsWith("Delta between mappings is undefined")
+    }
+
+    @Test
+    fun nonFiniteNumbers_segmentTraverse_skipsAnimation() {
+        motion.goldenTest(
+            spec =
+                specBuilder(Mapping.Zero)
+                    .toBreakpoint(1f)
+                    .completeWith(Mapping { if (it < 2f) Float.NaN else 2f }),
+            verifyTimeSeries = {
+                // The mappings produce a non-finite number during a breakpoint traversal.
+                // The animation thereof is skipped to avoid poisoning the state with non-finite
+                // numbers
+                assertThat(output.drop(1).take(6))
+                    .containsExactlyElementsIn(listOf(0f, 0f, Float.NaN, Float.NaN, 2f, 2f))
+                    .inOrder()
+                SkipGoldenVerification
+            },
+        ) {
+            animatedInputSequence(0f, 0.5f, 1f, 1.5f, 2f, 3f)
+        }
+        assertThat(wtfLog.loggedFailures).hasSize(1)
+        assertThat(wtfLog.loggedFailures.first())
+            .startsWith("Delta between breakpoints is undefined")
+    }
+
+    @Test
+    fun keepRunning_concurrentInvocationThrows() = runTestWithFrameClock { testScheduler, _ ->
+        val underTest = MotionValue({ 1f }, FakeGestureContext, label = "Foo")
+        val realJob = launch { underTest.keepRunning() }
+        testScheduler.runCurrent()
+
+        assertThat(realJob.isActive).isTrue()
+        try {
+            underTest.keepRunning()
+            // keepRunning returns Nothing, will never get here
+        } catch (e: Throwable) {
+            assertThat(e).isInstanceOf(IllegalStateException::class.java)
+            assertThat(e).hasMessageThat().contains("MotionValue(Foo) is already running")
+        }
+        assertThat(realJob.isActive).isTrue()
+        realJob.cancel()
+    }
+
+    @Test
+    fun keepRunning_suspendsWithoutAnAnimation() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
+
+        val inspector = underTest.debugInspector()
+        var framesCount = 0
+        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
+
+        rule.awaitIdle()
+        framesCount = 0
+        rule.mainClock.autoAdvance = false
+
+        assertThat(inspector.isActive).isTrue()
+        assertThat(inspector.isAnimating).isFalse()
+
+        // Update the value, but WITHOUT causing an animation
+        input.floatValue = 0.5f
+        rule.awaitIdle()
+
+        // Still on the old frame..
+        assertThat(framesCount).isEqualTo(0)
+        // ... [underTest] is now waiting for an animation frame
+        assertThat(inspector.isAnimating).isTrue()
+
+        rule.mainClock.advanceTimeByFrame()
+        rule.awaitIdle()
+
+        // Produces the frame..
+        assertThat(framesCount).isEqualTo(1)
+        // ... and is suspended again.
+        assertThat(inspector.isAnimating).isTrue()
+
+        rule.mainClock.advanceTimeByFrame()
+        rule.awaitIdle()
+
+        // Produces the frame..
+        assertThat(framesCount).isEqualTo(2)
+        // ... and is suspended again.
+        assertThat(inspector.isAnimating).isFalse()
+
+        rule.mainClock.autoAdvance = true
+        rule.awaitIdle()
+        // Ensure that no more frames are produced
+        assertThat(framesCount).isEqualTo(2)
+    }
+
+    @Test
+    fun keepRunning_remainsActiveWhileAnimating() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+        rule.setContent { LaunchedEffect(Unit) { underTest.keepRunning() } }
+
+        val inspector = underTest.debugInspector()
+        var framesCount = 0
+        backgroundScope.launch { snapshotFlow { inspector.frame }.collect { framesCount++ } }
+
+        rule.awaitIdle()
+        framesCount = 0
+        rule.mainClock.autoAdvance = false
+
+        assertThat(inspector.isActive).isTrue()
+        assertThat(inspector.isAnimating).isFalse()
+
+        // Update the value, WITH triggering an animation
+        input.floatValue = 1.5f
+        rule.awaitIdle()
+
+        // Still on the old frame..
+        assertThat(framesCount).isEqualTo(0)
+        // ... [underTest] is now waiting for an animation frame
+        assertThat(inspector.isAnimating).isTrue()
+
+        // A couple frames should be generated without pausing
+        repeat(5) {
+            rule.mainClock.advanceTimeByFrame()
+            rule.awaitIdle()
+
+            // The spring is still settling...
+            assertThat(inspector.frame.isStable).isFalse()
+            // ... animation keeps going ...
+            assertThat(inspector.isAnimating).isTrue()
+            // ... and frames are produces...
+            assertThat(framesCount).isEqualTo(it + 1)
+        }
+
+        val timeBeforeAutoAdvance = rule.mainClock.currentTime
+
+        // But this will stop as soon as the animation is finished. Skip forward.
+        rule.mainClock.autoAdvance = true
+        rule.awaitIdle()
+
+        // At which point the spring is stable again...
+        assertThat(inspector.frame.isStable).isTrue()
+        // ... and animations are suspended again.
+        assertThat(inspector.isAnimating).isFalse()
+
+        rule.awaitIdle()
+
+        // Stabilizing the spring during awaitIdle() took 160ms (obtained from looking at reference
+        // test runs). That time is expected to be 100% reproducible, given the starting
+        // state/configuration of the spring before awaitIdle().
+        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeAutoAdvance + 160)
+    }
+
+    @Test
+    fun keepRunningWhile_stopRunningWhileStable_endsImmediately() = runTest {
+        val input = mutableFloatStateOf(0f)
+        val spec = specBuilder(Mapping.Zero).toBreakpoint(1f).completeWith(Mapping.One)
+        val underTest = MotionValue(input::value, FakeGestureContext, spec)
+
+        val continueRunning = mutableStateOf(true)
+
+        rule.setContent {
+            LaunchedEffect(Unit) { underTest.keepRunningWhile { continueRunning.value } }
+        }
+
+        val inspector = underTest.debugInspector()
+
+        rule.awaitIdle()
+
+        assertWithMessage("isActive").that(inspector.isActive).isTrue()
+        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
+
+        val timeBeforeStopRunning = rule.mainClock.currentTime
+        continueRunning.value = false
+        rule.awaitIdle()
+
+        assertWithMessage("isActive").that(inspector.isActive).isFalse()
+        assertWithMessage("isAnimating").that(inspector.isAnimating).isFalse()
+        assertThat(rule.mainClock.currentTime).isEqualTo(timeBeforeStopRunning)
+    }
+
+    @Test
+    fun debugInspector_sameInstance_whileInUse() {
+        val underTest = MotionValue({ 1f }, FakeGestureContext)
+
+        val originalInspector = underTest.debugInspector()
+        assertThat(underTest.debugInspector()).isSameInstanceAs(originalInspector)
+    }
+
+    @Test
+    fun debugInspector_newInstance_afterUnused() {
+        val underTest = MotionValue({ 1f }, FakeGestureContext)
+
+        val originalInspector = underTest.debugInspector()
+        originalInspector.dispose()
+        assertThat(underTest.debugInspector()).isNotSameInstanceAs(originalInspector)
+    }
+
+    @OptIn(ExperimentalTestApi::class)
+    private fun runTestWithFrameClock(
+        testBody:
+            suspend CoroutineScope.(
+                testScheduler: TestCoroutineScheduler, backgroundScope: CoroutineScope,
+            ) -> Unit
+    ) = runTest {
+        val testScope: TestScope = this
+        withContext(TestMonotonicFrameClock(testScope, FrameDelayNanos)) {
+            testBody(testScope.testScheduler, testScope.backgroundScope)
+        }
+    }
+
+    class WtfLogRule : ExternalResource() {
+        val loggedFailures = mutableListOf<String>()
+
+        private lateinit var oldHandler: TerribleFailureHandler
+
+        override fun before() {
+            oldHandler =
+                Log.setWtfHandler { tag, what, _ ->
+                    if (tag == MotionValue.TAG) {
+                        loggedFailures.add(checkNotNull(what.message))
+                    }
+                }
+        }
+
+        override fun after() {
+            Log.setWtfHandler(oldHandler)
+        }
+    }
+
+    companion object {
+        val B1 = BreakpointKey("breakpoint1")
+        val B2 = BreakpointKey("breakpoint2")
+        val FakeGestureContext =
+            object : GestureContext {
+                override val direction: InputDirection
+                    get() = InputDirection.Max
+
+                override val dragOffset: Float
+                    get() = 0f
+            }
+        private val FrameDelayNanos: Long = 16_000_000L
+
+        fun specBuilder(firstSegment: Mapping = Mapping.Identity) =
+            MotionSpec.builder(
+                defaultSpring = matStandardDefault,
+                resetSpring = matStandardFast,
+                initialMapping = firstSegment,
+            )
+
+        fun forwardSpecBuilder(firstSegment: Mapping = Mapping.Identity) =
+            DirectionalMotionSpec.builder(
+                defaultSpring = matStandardDefault,
+                initialMapping = firstSegment,
+            )
+
+        fun reverseSpecBuilder(firstSegment: Mapping = Mapping.Identity) =
+            DirectionalMotionSpec.reverseBuilder(
+                defaultSpring = matStandardDefault,
+                initialMapping = firstSegment,
+            )
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/debug/MotionValueDebuggerTest.kt b/mechanics/tests/src/com/android/mechanics/debug/MotionValueDebuggerTest.kt
new file mode 100644
index 0000000..dfe69b8
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/debug/MotionValueDebuggerTest.kt
@@ -0,0 +1,94 @@
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
+package com.android.mechanics.debug
+
+import androidx.compose.foundation.layout.Box
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.test.junit4.createComposeRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.MotionValue
+import com.android.mechanics.ProvidedGestureContext
+import com.android.mechanics.spec.InputDirection
+import com.google.common.truth.Truth.assertThat
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MotionValueDebuggerTest {
+
+    private val input: () -> Float = { 0f }
+    private val gestureContext =
+        ProvidedGestureContext(dragOffset = 0f, direction = InputDirection.Max)
+
+    @get:Rule(order = 0) val rule = createComposeRule()
+
+    @Test
+    fun debugMotionValue_registersMotionValue_whenAddingToComposition() {
+        val debuggerState = MotionValueDebuggerState()
+        var hasValue by mutableStateOf(false)
+
+        rule.setContent {
+            Box(modifier = Modifier.motionValueDebugger(debuggerState)) {
+                if (hasValue) {
+                    val toDebug = remember { MotionValue(input, gestureContext) }
+                    Box(modifier = Modifier.debugMotionValue(toDebug))
+                }
+            }
+        }
+
+        assertThat(debuggerState.observedMotionValues).isEmpty()
+
+        hasValue = true
+        rule.waitForIdle()
+
+        assertThat(debuggerState.observedMotionValues).hasSize(1)
+    }
+
+    @Test
+    fun debugMotionValue_unregistersMotionValue_whenLeavingComposition() {
+        val debuggerState = MotionValueDebuggerState()
+        var hasValue by mutableStateOf(true)
+
+        rule.setContent {
+            Box(modifier = Modifier.motionValueDebugger(debuggerState)) {
+                if (hasValue) {
+                    val toDebug = remember { MotionValue(input, gestureContext) }
+                    Box(modifier = Modifier.debugMotionValue(toDebug))
+                }
+            }
+        }
+
+        assertThat(debuggerState.observedMotionValues).hasSize(1)
+
+        hasValue = false
+        rule.waitForIdle()
+        assertThat(debuggerState.observedMotionValues).isEmpty()
+    }
+
+    @Test
+    fun debugMotionValue_noDebugger_isNoOp() {
+        rule.setContent {
+            val toDebug = remember { MotionValue(input, gestureContext) }
+            Box(modifier = Modifier.debugMotionValue(toDebug))
+        }
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt
new file mode 100644
index 0000000..52a0ab7
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecBuilderTest.kt
@@ -0,0 +1,170 @@
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
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.DirectionalMotionSpecSubject.Companion.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class DirectionalMotionSpecBuilderTest {
+
+    @Test
+    fun directionalSpec_buildEmptySpec() {
+        val result = buildDirectionalMotionSpec()
+
+        assertThat(result).breakpoints().isEmpty()
+        assertThat(result).mappings().containsExactly(Mapping.Identity)
+    }
+
+    @Test
+    fun directionalSpec_addBreakpointsAndMappings() {
+        val result =
+            buildDirectionalMotionSpec(Spring, Mapping.Zero) {
+                mapping(breakpoint = 0f, mapping = Mapping.One, key = B1)
+                mapping(breakpoint = 10f, mapping = Mapping.Two, key = B2)
+            }
+
+        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
+        assertThat(result).breakpoints().withKey(B1).isAt(0f)
+        assertThat(result).breakpoints().withKey(B2).isAt(10f)
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_setsDefaultSpring() {
+        val result =
+            buildDirectionalMotionSpec(Spring) { constantValue(breakpoint = 10f, value = 20f) }
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(Spring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canOverrideDefaultSpring() {
+        val otherSpring = SpringParameters(stiffness = 10f, dampingRatio = 0.1f)
+        val result =
+            buildDirectionalMotionSpec(Spring) {
+                constantValue(breakpoint = 10f, value = 20f, spring = otherSpring)
+            }
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(otherSpring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_defaultsToNoGuarantee() {
+        val result =
+            buildDirectionalMotionSpec(Spring) { constantValue(breakpoint = 10f, value = 20f) }
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(Guarantee.None)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canSetGuarantee() {
+        val guarantee = Guarantee.InputDelta(10f)
+        val result =
+            buildDirectionalMotionSpec(Spring) {
+                constantValue(breakpoint = 10f, value = 20f, guarantee = guarantee)
+            }
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(guarantee)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpTo_setsAbsoluteValue() {
+        val result =
+            buildDirectionalMotionSpec(Spring, Mapping.Fixed(99f)) {
+                constantValue(breakpoint = 10f, value = 20f)
+            }
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isConstantValue(20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpBy_setsRelativeValue() {
+        val result =
+            buildDirectionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
+                // At 10f the current value is 5f (10f * 0.5f)
+                constantValueFromCurrent(breakpoint = 10f, delta = 30f)
+            }
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isConstantValue(35f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithConstantValue_usesSourceValue() {
+        val result =
+            buildDirectionalMotionSpec(Spring, Mapping.Linear(factor = 0.5f)) {
+                // At 5f the current value is 2.5f (5f * 0.5f)
+                constantValueFromCurrent(breakpoint = 5f)
+            }
+
+        assertThat(result).mappings().atOrAfter(5f).isConstantValue(2.5f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithFractionalInput_matchesLinearMapping() {
+        val result =
+            buildDirectionalMotionSpec(Spring) {
+                fractionalInput(breakpoint = 5f, from = 1f, fraction = .1f)
+            }
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithTargetValue_matchesLinearMapping() {
+        val result =
+            buildDirectionalMotionSpec(Spring) {
+                target(breakpoint = 5f, from = 1f, to = 20f)
+                mapping(breakpoint = 30f, mapping = Mapping.Identity)
+            }
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_breakpointsAtSamePosition_producesValidSegment() {
+        val result =
+            buildDirectionalMotionSpec(Spring) {
+                target(breakpoint = 5f, from = 1f, to = 20f)
+                mapping(breakpoint = 5f, mapping = Mapping.Identity)
+            }
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Identity, Mapping.Fixed(1f), Mapping.Identity)
+            .inOrder()
+    }
+
+    companion object {
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        val B1 = BreakpointKey("One")
+        val B2 = BreakpointKey("Two")
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
index e950bc7..1c20be9 100644
--- a/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
+++ b/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
@@ -245,6 +245,22 @@ class FluentSpecBuilderTest {
             .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
     }
 
+    @Test
+    fun directionalSpec_mappingBuilder_breakpointsAtSamePosition_producesValidSegment() {
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(5f)
+                .jumpTo(1f)
+                .continueWithTargetValue(target = 20f)
+                .toBreakpoint(5f)
+                .completeWith(Mapping.Identity)
+
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Identity, Mapping.Fixed(1f), Mapping.Identity)
+            .inOrder()
+    }
+
     companion object {
         val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
         val B1 = BreakpointKey("One")
diff --git a/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt b/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt
new file mode 100644
index 0000000..3d43d34
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/testing/DefaultSprings.kt
@@ -0,0 +1,72 @@
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
+package com.android.mechanics.testing
+
+import com.android.mechanics.spring.SpringParameters
+
+object DefaultSprings {
+    val matStandardDefault =
+        SpringParameters(
+            stiffness = StandardMotionTokens.SpringDefaultSpatialStiffness,
+            dampingRatio = StandardMotionTokens.SpringDefaultSpatialDamping,
+        )
+    val matStandardFast =
+        SpringParameters(
+            stiffness = StandardMotionTokens.SpringFastSpatialStiffness,
+            dampingRatio = StandardMotionTokens.SpringFastSpatialDamping,
+        )
+    val matExpressiveDefault =
+        SpringParameters(
+            stiffness = ExpressiveMotionTokens.SpringDefaultSpatialStiffness,
+            dampingRatio = ExpressiveMotionTokens.SpringDefaultSpatialDamping,
+        )
+    val matExpressiveFast =
+        SpringParameters(
+            stiffness = ExpressiveMotionTokens.SpringFastSpatialStiffness,
+            dampingRatio = ExpressiveMotionTokens.SpringFastSpatialDamping,
+        )
+
+    internal object StandardMotionTokens {
+        val SpringDefaultSpatialDamping = 0.9f
+        val SpringDefaultSpatialStiffness = 700.0f
+        val SpringDefaultEffectsDamping = 1.0f
+        val SpringDefaultEffectsStiffness = 1600.0f
+        val SpringFastSpatialDamping = 0.9f
+        val SpringFastSpatialStiffness = 1400.0f
+        val SpringFastEffectsDamping = 1.0f
+        val SpringFastEffectsStiffness = 3800.0f
+        val SpringSlowSpatialDamping = 0.9f
+        val SpringSlowSpatialStiffness = 300.0f
+        val SpringSlowEffectsDamping = 1.0f
+        val SpringSlowEffectsStiffness = 800.0f
+    }
+
+    internal object ExpressiveMotionTokens {
+        val SpringDefaultSpatialDamping = 0.8f
+        val SpringDefaultSpatialStiffness = 380.0f
+        val SpringDefaultEffectsDamping = 1.0f
+        val SpringDefaultEffectsStiffness = 1600.0f
+        val SpringFastSpatialDamping = 0.6f
+        val SpringFastSpatialStiffness = 800.0f
+        val SpringFastEffectsDamping = 1.0f
+        val SpringFastEffectsStiffness = 3800.0f
+        val SpringSlowSpatialDamping = 0.8f
+        val SpringSlowSpatialStiffness = 200.0f
+        val SpringSlowEffectsDamping = 1.0f
+        val SpringSlowEffectsStiffness = 800.0f
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt b/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
index 1a83e06..cd58a48 100644
--- a/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
+++ b/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
@@ -127,9 +127,9 @@ internal constructor(failureMetadata: FailureMetadata, private val actual: Break
 
     companion object {
         val BreakpointKeys =
-            Correspondence.transforming<Breakpoint, BreakpointKey>({ it?.key }, "key")
+            Correspondence.transforming<Breakpoint, BreakpointKey>({ it.key }, "key")
         val BreakpointPositions =
-            Correspondence.transforming<Breakpoint, Float>({ it?.position }, "position")
+            Correspondence.transforming<Breakpoint, Float>({ it.position }, "position")
 
         /** Returns a factory to be used with [Truth.assertAbout]. */
         val SubjectFactory =
diff --git a/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt b/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt
new file mode 100644
index 0000000..e33865f
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/testing/MotionValueToolkit.kt
@@ -0,0 +1,305 @@
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
+@file:OptIn(ExperimentalTestApi::class, ExperimentalCoroutinesApi::class)
+
+package com.android.mechanics.testing
+
+import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.test.ExperimentalTestApi
+import androidx.compose.ui.test.junit4.ComposeContentTestRule
+import com.android.mechanics.DistanceGestureContext
+import com.android.mechanics.MotionValue
+import com.android.mechanics.debug.FrameData
+import com.android.mechanics.spec.InputDirection
+import com.android.mechanics.spec.MotionSpec
+import kotlin.math.abs
+import kotlin.math.floor
+import kotlin.math.sign
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.NonDisposableHandle.dispose
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+import kotlinx.coroutines.flow.drop
+import kotlinx.coroutines.flow.take
+import kotlinx.coroutines.flow.takeWhile
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.runCurrent
+import kotlinx.coroutines.test.runTest
+import platform.test.motion.MotionTestRule
+import platform.test.motion.RecordedMotion.Companion.create
+import platform.test.motion.golden.Feature
+import platform.test.motion.golden.FrameId
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.TimestampFrameId
+import platform.test.motion.golden.ValueDataPoint
+import platform.test.motion.golden.asDataPoint
+
+/** Toolkit to support [MotionValue] motion tests. */
+class MotionValueToolkit(val composeTestRule: ComposeContentTestRule) {
+    companion object {
+
+        val TimeSeries.input: List<Float>
+            get() = dataPoints("input")
+
+        val TimeSeries.output: List<Float>
+            get() = dataPoints("output")
+
+        val TimeSeries.outputTarget: List<Float>
+            get() = dataPoints("outputTarget")
+
+        val TimeSeries.isStable: List<Boolean>
+            get() = dataPoints("isStable")
+
+        internal const val TAG = "MotionValueToolkit"
+
+        fun <T> TimeSeries.dataPoints(featureName: String): List<T> {
+            @Suppress("UNCHECKED_CAST")
+            return (features[featureName] as Feature<T>).dataPoints.map {
+                require(it is ValueDataPoint)
+                it.value
+            }
+        }
+    }
+}
+
+interface InputScope {
+    val input: Float
+    val gestureContext: DistanceGestureContext
+    val underTest: MotionValue
+
+    suspend fun awaitStable()
+
+    suspend fun awaitFrames(frames: Int = 1)
+
+    var directionChangeSlop: Float
+
+    fun updateValue(position: Float)
+
+    suspend fun animateValueTo(
+        targetValue: Float,
+        changePerFrame: Float = abs(input - targetValue) / 5f,
+    )
+
+    suspend fun animatedInputSequence(vararg values: Float)
+
+    fun reset(position: Float, direction: InputDirection)
+}
+
+enum class VerifyTimeSeriesResult {
+    SkipGoldenVerification,
+    AssertTimeSeriesMatchesGolden,
+}
+
+fun MotionTestRule<MotionValueToolkit>.goldenTest(
+    spec: MotionSpec,
+    createDerived: (underTest: MotionValue) -> List<MotionValue> = { emptyList() },
+    initialValue: Float = 0f,
+    initialDirection: InputDirection = InputDirection.Max,
+    directionChangeSlop: Float = 5f,
+    stableThreshold: Float = 0.01f,
+    verifyTimeSeries: TimeSeries.() -> VerifyTimeSeriesResult = {
+        VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden
+    },
+    testInput: suspend InputScope.() -> Unit,
+) = runTest {
+    with(toolkit.composeTestRule) {
+        val frameEmitter = MutableStateFlow<Long>(0)
+
+        val testHarness =
+            MotionValueTestHarness(
+                initialValue,
+                initialDirection,
+                spec,
+                stableThreshold,
+                directionChangeSlop,
+                frameEmitter.asStateFlow(),
+                createDerived,
+            )
+        val underTest = testHarness.underTest
+        val derived = testHarness.derived
+
+        val inspectors = buildMap {
+            put(underTest, underTest.debugInspector())
+            derived.forEach { put(it, it.debugInspector()) }
+        }
+
+        setContent {
+            LaunchedEffect(Unit) {
+                launch { underTest.keepRunning() }
+                derived.forEach { launch { it.keepRunning() } }
+            }
+        }
+
+        val recordingJob = launch { testInput.invoke(testHarness) }
+
+        waitForIdle()
+        mainClock.autoAdvance = false
+
+        val frameIds = mutableListOf<FrameId>()
+        val frameData = mutableMapOf<MotionValue, MutableList<FrameData>>()
+
+        fun recordFrame(frameId: TimestampFrameId) {
+            frameIds.add(frameId)
+            inspectors.forEach { (motionValue, inspector) ->
+                frameData.computeIfAbsent(motionValue) { mutableListOf() }.add(inspector.frame)
+            }
+        }
+
+        val startFrameTime = mainClock.currentTime
+        recordFrame(TimestampFrameId(mainClock.currentTime - startFrameTime))
+        while (!recordingJob.isCompleted) {
+            frameEmitter.tryEmit(mainClock.currentTime + 16)
+            runCurrent()
+            mainClock.advanceTimeByFrame()
+            recordFrame(TimestampFrameId(mainClock.currentTime - startFrameTime))
+        }
+
+        val timeSeries =
+            TimeSeries(
+                frameIds.toList(),
+                buildList {
+                    frameData.forEach { (motionValue, frames) ->
+                        val prefix = if (motionValue == underTest) "" else "${motionValue.label}-"
+
+                        add(Feature("${prefix}input", frames.map { it.input.asDataPoint() }))
+                        add(
+                            Feature(
+                                "${prefix}gestureDirection",
+                                frames.map { it.gestureDirection.name.asDataPoint() },
+                            )
+                        )
+                        add(Feature("${prefix}output", frames.map { it.output.asDataPoint() }))
+                        add(
+                            Feature(
+                                "${prefix}outputTarget",
+                                frames.map { it.outputTarget.asDataPoint() },
+                            )
+                        )
+                        add(
+                            Feature(
+                                "${prefix}outputSpring",
+                                frames.map { it.springParameters.asDataPoint() },
+                            )
+                        )
+                        add(Feature("${prefix}isStable", frames.map { it.isStable.asDataPoint() }))
+                    }
+                },
+            )
+
+        inspectors.values.forEach { it.dispose() }
+
+        val recordedMotion = create(timeSeries, screenshots = null)
+        val skipGoldenVerification = verifyTimeSeries.invoke(recordedMotion.timeSeries)
+        if (skipGoldenVerification == VerifyTimeSeriesResult.AssertTimeSeriesMatchesGolden) {
+            assertThat(recordedMotion).timeSeriesMatchesGolden()
+        }
+    }
+}
+
+private class MotionValueTestHarness(
+    initialInput: Float,
+    initialDirection: InputDirection,
+    spec: MotionSpec,
+    stableThreshold: Float,
+    directionChangeSlop: Float,
+    val onFrame: StateFlow<Long>,
+    createDerived: (underTest: MotionValue) -> List<MotionValue>,
+) : InputScope {
+
+    override var input by mutableFloatStateOf(initialInput)
+    override val gestureContext: DistanceGestureContext =
+        DistanceGestureContext(initialInput, initialDirection, directionChangeSlop)
+
+    override val underTest =
+        MotionValue(
+            { input },
+            gestureContext,
+            stableThreshold = stableThreshold,
+            initialSpec = spec,
+        )
+
+    val derived = createDerived(underTest)
+
+    override fun updateValue(position: Float) {
+        input = position
+        gestureContext.dragOffset = position
+    }
+
+    override var directionChangeSlop: Float
+        get() = gestureContext.directionChangeSlop
+        set(value) {
+            gestureContext.directionChangeSlop = value
+        }
+
+    override suspend fun awaitStable() {
+        val debugInspectors = buildList {
+            add(underTest.debugInspector())
+            addAll(derived.map { it.debugInspector() })
+        }
+        try {
+
+            onFrame
+                // Since this is a state-flow, the current frame is counted too.
+                .drop(1)
+                .takeWhile { debugInspectors.any { !it.frame.isStable } }
+                .collect {}
+        } finally {
+            debugInspectors.forEach { it.dispose() }
+        }
+    }
+
+    override suspend fun awaitFrames(frames: Int) {
+        onFrame
+            // Since this is a state-flow, the current frame is counted too.
+            .drop(1)
+            .take(frames)
+            .collect {}
+    }
+
+    override suspend fun animateValueTo(targetValue: Float, changePerFrame: Float) {
+        require(changePerFrame > 0f)
+        var currentValue = input
+        val delta = targetValue - currentValue
+        val step = changePerFrame * delta.sign
+
+        val stepCount = floor((abs(delta) / changePerFrame) - 1).toInt()
+        repeat(stepCount) {
+            currentValue += step
+            updateValue(currentValue)
+            awaitFrames()
+        }
+
+        updateValue(targetValue)
+        awaitFrames()
+    }
+
+    override suspend fun animatedInputSequence(vararg values: Float) {
+        values.forEach {
+            updateValue(it)
+            awaitFrames()
+        }
+    }
+
+    override fun reset(position: Float, direction: InputDirection) {
+        input = position
+        gestureContext.reset(position, direction)
+    }
+}
diff --git a/monet/src/com/android/systemui/monet/CustomDynamicColors.java b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
index 77d0f28..26bd612 100644
--- a/monet/src/com/android/systemui/monet/CustomDynamicColors.java
+++ b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
@@ -24,11 +24,11 @@ import com.google.ux.material.libmonet.dynamiccolor.TonePolarity;
 
 import java.util.function.Supplier;
 
-class CustomDynamicColors {
+public class CustomDynamicColors {
     private final MaterialDynamicColors mMdc;
     public final Supplier<DynamicColor>[] allColors;
 
-    CustomDynamicColors(boolean isExtendedFidelity) {
+    public CustomDynamicColors(boolean isExtendedFidelity) {
         this.mMdc = new MaterialDynamicColors(isExtendedFidelity);
 
         allColors = new Supplier[]{
@@ -79,7 +79,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 4.0, 5.0, 15.0),
+                /* contrastCurve= */ new ContrastCurve(4.0, 4.0, 5.0, 15.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(clockHour(), clockMinute(), 10.0, TonePolarity.DARKER,
                         false));
@@ -93,7 +93,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 6.5, 10.0, 15.0),
+                /* contrastCurve= */ new ContrastCurve(6.5, 6.5, 10.0, 15.0),
                 /* toneDeltaPair= */ null);
     }
 
@@ -105,7 +105,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 5.0, 70.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(5.0, 5.0, 70.0, 11.0),
                 /* toneDeltaPair= */ null);
     }
 
@@ -117,7 +117,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 5.0, 70.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(5.0, 5.0, 70.0, 11.0),
                 /* toneDeltaPair= */ null);
     }
 
@@ -143,7 +143,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> themeApp(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 7.0, 10.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 7.0, 10.0),
                 /* toneDeltaPair= */ null);
     }
 
@@ -183,7 +183,7 @@ class CustomDynamicColors {
                 /* isBackground= */ true,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 7.0, 17.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 7.0, 17.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(brandA(), brandB(), 10.0, TonePolarity.NEARER, false));
     }
@@ -196,7 +196,7 @@ class CustomDynamicColors {
                 /* isBackground= */ true,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 3.0, 6.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 3.0, 6.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(brandB(), brandC(), 10.0, TonePolarity.NEARER, false));
     }
@@ -209,7 +209,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 4.0, 9.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.0, 9.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(brandC(), brandD(), 10.0, TonePolarity.NEARER, false));
     }
@@ -222,7 +222,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 4.0, 13.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.0, 13.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(brandD(), brandA(), 10.0, TonePolarity.NEARER, false));
     }
@@ -246,10 +246,10 @@ class CustomDynamicColors {
                 /* name= */ "shade_active",
                 /* palette= */ (s) -> s.primaryPalette,
                 /* tone= */ (s) -> 90.0,
-                /* isBackground= */ false,
+                /* isBackground= */ true,
                 /* background= */ (s) -> underSurface(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 3.0, 4.5, 7.0),
+                /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.5, 7.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(shadeActive(), shadeInactive(), 30.0, TonePolarity.LIGHTER,
                         false));
@@ -263,7 +263,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> shadeActive(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 4.5, 7.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(onShadeActive(), onShadeActiveVariant(), 20.0,
                         TonePolarity.NEARER, false));
@@ -277,7 +277,7 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> shadeActive(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 4.5, 7.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(onShadeActiveVariant(), onShadeActive(), 20.0,
                         TonePolarity.NEARER, false));
@@ -301,10 +301,10 @@ class CustomDynamicColors {
                 /* name= */ "on_shade_inactive",
                 /* palette= */ (s) -> s.neutralVariantPalette,
                 /* tone= */ (s) -> 90.0,
-                /* isBackground= */ true,
+                /* isBackground= */ false,
                 /* background= */ (s) -> shadeInactive(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 4.5, 7.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
                 /* toneDeltaPair= */
                 (s) -> new ToneDeltaPair(onShadeInactive(), onShadeInactiveVariant(), 10.0,
                         TonePolarity.NEARER, false));
@@ -318,9 +318,9 @@ class CustomDynamicColors {
                 /* isBackground= */ false,
                 /* background= */ (s) -> shadeInactive(),
                 /* secondBackground= */ null,
-                /* contrastCurve= */ new ContrastCurve(1.0, 4.5, 7.0, 11.0),
+                /* contrastCurve= */ new ContrastCurve(4.5, 4.5, 7.0, 11.0),
                 /* toneDeltaPair= */
-                (s) -> new ToneDeltaPair(onShadeInactiveVariant(), onShadeInactive(), 10.0,
+                (s) -> new ToneDeltaPair(onShadeInactive(), onShadeInactiveVariant(), 10.0,
                         TonePolarity.NEARER, false));
     }
 
diff --git a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
index 7555907..81979a2 100644
--- a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
+++ b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
@@ -308,12 +308,12 @@ internal class MSDLRepositoryImpl : MSDLRepository {
                         HapticComposition(
                             listOf(
                                 HapticCompositionPrimitive(
-                                    VibrationEffect.Composition.PRIMITIVE_TICK,
-                                    scale = 0.7f,
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.5f,
                                     delayMillis = 0,
                                 )
                             ),
-                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
                         )
                     },
                 HapticToken.KEYPRESS_SPACEBAR to
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/TorusEngine.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/TorusEngine.kt
index 25850cf..ccb0b59 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/TorusEngine.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/TorusEngine.kt
@@ -17,6 +17,8 @@
 package com.google.android.torus.core.engine
 
 import android.app.WallpaperManager
+import android.app.wallpaper.WallpaperDescription
+import android.service.wallpaper.WallpaperService.Engine
 import com.google.android.torus.core.wallpaper.LiveWallpaper
 
 /**
@@ -25,25 +27,30 @@ import com.google.android.torus.core.wallpaper.LiveWallpaper
  */
 interface TorusEngine {
     /**
-     * Called when the engine is created. You should load the assets and initialize the
-     * resources here.
+     * Called when the engine is created. You should load the assets and initialize the resources
+     * here.
      *
      * IMPORTANT: When this function is called, the surface used to render the engine has to be
      * ready.
      *
      * @param isFirstActiveInstance Whether this is the first Engine instance (since the last time
-     * that all instances were destroyed).
+     *   that all instances were destroyed).
      */
     fun create(isFirstActiveInstance: Boolean = true)
 
     /**
-     * Called when the [TorusEngine] resumes.
+     * Called when the event [Engine.onApplyWallpaper] is called.
+     *
+     * @see Engine.onApplyWallpaper
      */
+    fun applyWallpaper(which: Int): WallpaperDescription? {
+        return null
+    }
+
+    /** Called when the [TorusEngine] resumes. */
     fun resume()
 
-    /**
-     * Called when the [TorusEngine] is paused.
-     */
+    /** Called when the [TorusEngine] is paused. */
     fun pause()
 
     /**
@@ -62,8 +69,8 @@ interface TorusEngine {
     fun destroy(isLastActiveInstance: Boolean = true)
 
     /**
-     * Called when the engine changes its destination flag. The destination indicates whether
-     * the wallpaper is drawn on home screen, lock screen, or both. It is a combination of
+     * Called when the engine changes its destination flag. The destination indicates whether the
+     * wallpaper is drawn on home screen, lock screen, or both. It is a combination of
      * [WallpaperManager.FLAG_LOCK] and/or [WallpaperManager.FLAG_SYSTEM]
      */
     fun onWallpaperFlagsChanged(which: Int) {}
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/listener/TorusTouchListener.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/listener/TorusTouchListener.kt
index 4ceba4a..b54cecb 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/listener/TorusTouchListener.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/engine/listener/TorusTouchListener.kt
@@ -20,14 +20,27 @@ import android.view.MotionEvent
 import com.google.android.torus.core.engine.TorusEngine
 
 /**
- * Allows to receive Touch events.
- * The Interface must be implemented by a [TorusEngine] instance,
+ * Allows to receive Touch events. The Interface must be implemented by a [TorusEngine] instance,
  */
 interface TorusTouchListener {
     /**
-     * Called when a touch event has been triggered.
+     * Called when a touch event has been triggered. If the engine is set as a wallpaper and the
+     * device is locked, touch events may be restricted. Only taps on the lock screen's focal area
+     * will be delivered via [onLockscreenFocalAreaTap]. See [onLockscreenFocalAreaTap] for details.
      *
      * @param event The new [MotionEvent].
      */
     fun onTouchEvent(event: MotionEvent)
-}
\ No newline at end of file
+
+    /**
+     * Called when a short tap occurs on the wallpaper's focal area on the lock screen.
+     *
+     * The wallpaper's focal area is the interactive region of the wallpaper that is not obscured by
+     * other lock screen elements. The wallpaper is scaled on the lock screen. These coordinates are
+     * relative to the unscaled wallpaper.
+     *
+     * @param x The x-coordinate of the tap, relative to the unscaled wallpaper dimensions.
+     * @param y The y-coordinate of the tap, relative to the unscaled wallpaper dimensions.
+     */
+    fun onLockscreenFocalAreaTap(x: Int, y: Int) {}
+}
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
index 533a95e..66ff79b 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
@@ -17,6 +17,7 @@
 package com.google.android.torus.core.wallpaper
 
 import android.app.WallpaperColors
+import android.app.wallpaper.WallpaperDescription
 import android.content.BroadcastReceiver
 import android.content.Context
 import android.content.Intent
@@ -51,6 +52,8 @@ abstract class LiveWallpaper : WallpaperService() {
         const val COMMAND_GOING_TO_SLEEP = "android.wallpaper.goingtosleep"
         const val COMMAND_PREVIEW_INFO = "android.wallpaper.previewinfo"
         const val COMMAND_LOCKSCREEN_LAYOUT_CHANGED = "android.wallpaper.lockscreen_layout_changed"
+        const val COMMAND_LOCKSCREEN_TAP = "android.wallpaper.lockscreen_tap"
+        const val COMMAND_KEYGUARD_APPEARING = "android.wallpaper.keyguardappearing"
         const val WALLPAPER_FLAG_NOT_FOUND = -1
     }
 
@@ -133,7 +136,11 @@ abstract class LiveWallpaper : WallpaperService() {
      * well). You can track the lifecycle when *any* Engine is active using the
      * is{First/Last}ActiveInstance parameters of the create/destroy methods.
      */
-    abstract fun getWallpaperEngine(context: Context, surfaceHolder: SurfaceHolder): TorusEngine
+    abstract fun getWallpaperEngine(
+        context: Context,
+        surfaceHolder: SurfaceHolder,
+        wallpaperDescription: WallpaperDescription? = null,
+    ): TorusEngine
 
     /**
      * returns a new instance of [LiveWallpaperEngineWrapper]. Caution: This function should not be
@@ -145,6 +152,12 @@ abstract class LiveWallpaper : WallpaperService() {
         return wrapper
     }
 
+    override fun onCreateEngine(description: WallpaperDescription): Engine? {
+        val wrapper = LiveWallpaperEngineWrapper(description)
+        wakeStateChangeListeners.add(WeakReference(wrapper))
+        return wrapper
+    }
+
     override fun onConfigurationChanged(newConfig: Configuration) {
         super.onConfigurationChanged(newConfig)
 
@@ -197,9 +210,7 @@ abstract class LiveWallpaper : WallpaperService() {
             return false
         }
 
-        /**
-         * Returns the information if the wallpaper is visible.
-         */
+        /** Returns the information if the wallpaper is visible. */
         fun isVisible(): Boolean {
             this.wallpaperServiceEngine?.let {
                 return it.isVisible
@@ -242,7 +253,9 @@ abstract class LiveWallpaper : WallpaperService() {
      * engine is created. Also, wrapping our [TorusEngine] inside [WallpaperService.Engine] allow us
      * to reuse [TorusEngine] in other places, like Activities.
      */
-    private inner class LiveWallpaperEngineWrapper : WallpaperService.Engine() {
+    private inner class LiveWallpaperEngineWrapper(
+        private val wallpaperDescription: WallpaperDescription? = null
+    ) : WallpaperService.Engine() {
         private lateinit var wallpaperEngine: TorusEngine
 
         override fun onCreate(surfaceHolder: SurfaceHolder) {
@@ -261,7 +274,7 @@ abstract class LiveWallpaper : WallpaperService() {
                     this@LiveWallpaper
                 }
 
-            wallpaperEngine = getWallpaperEngine(context, surfaceHolder)
+            wallpaperEngine = getWallpaperEngine(context, surfaceHolder, wallpaperDescription)
             numEngines++
 
             /*
@@ -272,6 +285,11 @@ abstract class LiveWallpaper : WallpaperService() {
             if (wallpaperEngine is TorusTouchListener) setTouchEventsEnabled(true)
         }
 
+        override fun onApplyWallpaper(which: Int): WallpaperDescription? {
+            super.onApplyWallpaper(which)
+            return wallpaperEngine.applyWallpaper(which)
+        }
+
         override fun onSurfaceCreated(holder: SurfaceHolder) {
             super.onSurfaceCreated(holder)
 
@@ -401,6 +419,14 @@ abstract class LiveWallpaper : WallpaperService() {
                         onLockscreenLayoutChanged(extras)
                     }
                 }
+                COMMAND_LOCKSCREEN_TAP -> {
+                    if (extras != null) {
+                        onLockscreenFocalAreaTap(x, y)
+                    }
+                }
+                COMMAND_KEYGUARD_APPEARING -> {
+                    onKeyguardAppearing()
+                }
             }
 
             if (resultRequested) return extras
@@ -453,6 +479,12 @@ abstract class LiveWallpaper : WallpaperService() {
             }
         }
 
+        fun onKeyguardAppearing() {
+            if (wallpaperEngine is LiveWallpaperKeyguardEventListener) {
+                (wallpaperEngine as LiveWallpaperKeyguardEventListener).onKeyguardAppearing()
+            }
+        }
+
         fun onPreviewInfoReceived(extras: Bundle?) {
             if (wallpaperEngine is LiveWallpaperEventListener) {
                 (wallpaperEngine as LiveWallpaperEventListener).onPreviewInfoReceived(extras)
@@ -464,5 +496,11 @@ abstract class LiveWallpaper : WallpaperService() {
                 (wallpaperEngine as LiveWallpaperEventListener).onLockscreenLayoutChanged(extras)
             }
         }
+
+        fun onLockscreenFocalAreaTap(x: Int, y: Int) {
+            if (wallpaperEngine is TorusTouchListener) {
+                (wallpaperEngine as TorusTouchListener).onLockscreenFocalAreaTap(x, y)
+            }
+        }
     }
 }
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
index 6b05517..a3a2c95 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
@@ -110,19 +110,44 @@ interface LiveWallpaperEventListener {
     fun shouldZoomOutWallpaper() = false
 
     /**
-     * React to COMMAND_LOCKSCREEN_LAYOUT_CHANGED from SystemUI. Current usage is to show the
-     * remaining space in lockscreen to bound the position for wallpaper shape effects. We also pass
-     * the bottom of smartspace as a reference.
-     *
-     * @param extras contains the necessary value from lockscreen layout currently for magic
-     *   portrait, it contains
-     * - "screenLeft": the left of the screen
-     * - "screenRight": the left of the screen
-     * - "smartspaceBottom": the bottom of the smartspace date and weather part, not bc smartspace
-     * - "shortCutTop": the top of the shortcut in locksreen
-     * - "notificationBottom": the bottom of notifications in lockscreen With smartspaceBottom,
-     *   screenLeft, screenRight, shortCutTop, we can get the remaining space bounds in lockscreen
-     *   without notifications. And with notificationBottom, we have bounds with notifications
+     * React to COMMAND_LOCKSCREEN_LAYOUT_CHANGED from SystemUI to give wallpaper focal area on
+     * lockscreen
+     *
+     * @param extras contains the wallpaper focal area bounds from lockscreen
+     *
+     * For handheld,
+     *
+     * when there's notification, the focal area should be below notification stack, and above
+     * shortcut, and horizontally constrained by screen width. i.e. (screenLeft,
+     * notificationStackBottom, screenRight, shortcutTop)
+     *
+     * when there's no notification, the only difference is the top of focal area, which is below
+     * smartspace. i.e. (screenLeft, smartspaceBottom, screenRight, shortcutTop)
+     *
+     * For tablet portrait, we have the similar logic with handheld, but we have its width
+     * constrained by a maxFocalAreaWidth, which is 500dp. i.e. left = screenCenterX -
+     * maxFocalAreaWidth / 2, top = smartspaceBottom or notificationStackBottom, right =
+     * screenCenterX + maxFocalAreaWidth / 2, bottom = shortcutTop.
+     *
+     * For tablet landscape, focal area is always in the center of screen, and we need to have a top
+     * margin as margin from the shortcut top to the screen bottom to make focal area vertically
+     * symmetric i.e. left = screenCenterX - maxFocalAreaWidth / 2, top =
+     * shortcutMarginToScreenBottom, right = screenCenterX + maxFocalAreaWidth / 2, bottom =
+     * shortcutTop
+     *
+     * For foldable fold mode, we have the same logic with handheld.
+     *
+     * For foldable unfold portrait, we have same logic with tablet portrait.
+     *
+     * For foldable unfold landscape, when there's notification, focal area is in left half screen,
+     * top to bottom of smartspace, bottom to top of shortcut, left and right is constrained by half
+     * screen width, i.e. (screenLeft, smartspaceBottom, screenCenterX, shortcutTop)
+     *
+     * when there's no notification, focal area is in right half screen, top to bottom of
+     * smartspace, bottom to top of shortcut, left and right is constrained by half screen width.
+     * i.e. (screenCenterX, smartspaceBottom, screenRight, shortcutTop)
      */
+    // TODO: when smartspace is moved from below small clock to the right of the clock, we need to
+    // change all smartspace bottom mentioned above to small clock bottom
     fun onLockscreenLayoutChanged(extras: Bundle) {}
 }
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperKeyguardEventListener.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperKeyguardEventListener.kt
index 70b15e5..cea1680 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperKeyguardEventListener.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperKeyguardEventListener.kt
@@ -21,4 +21,6 @@ interface LiveWallpaperKeyguardEventListener {
 
     /** Called when the keyguard is going away. */
     fun onKeyguardGoingAway()
+
+    fun onKeyguardAppearing()
 }
diff --git a/tracinglib/README.md b/tracinglib/README.md
index 924df41..86d863a 100644
--- a/tracinglib/README.md
+++ b/tracinglib/README.md
@@ -1,17 +1,18 @@
 # Coroutine Tracing
 
 This library contains utilities for tracing coroutines. Coroutines cannot be traced using the
-`android.os.Trace` APIs because suspension points will lead to malformed trace sections. This is
-because each `Trace.beginSection` must have a matching `Trace.endSection`; if a coroutine suspends
-before `Trace.endSection` is called, the trace section will remain open while other unrelated work
-executes.
+`android.os.Trace` APIs normally because suspension points will lead to malformed trace sections.
+This is because each `Trace.beginSection()` call must have a matching `Trace.endSection()` call; if
+a coroutine suspends before `Trace.endSection()` is called, the trace section will remain open while
+other unrelated work executes on the thread.
 
 To address this, we introduce a function `traceCoroutine("name") { ... }` that can be used for
 tracing sections of coroutine code. When invoked, a trace section with the given name will start
-immediately, and its name will also be written to an object in the current `CoroutineContext` used
-for coroutine-local storage. When the coroutine suspends, all trace sections will end immediately.
-When resumed, the coroutine will read the names of the previous sections from coroutine-local
-storage, and it will begin the sections again.
+immediately, and its name will also be written to an object in thread-local storage which is managed
+by an object in the current `CoroutineContext`, making it safe, "coroutine-local" storage. When the
+coroutine suspends, all trace sections will end immediately. When resumed, the coroutine will read
+the names of the previous sections from coroutine-local storage, and it will begin the sections
+again.
 
 For example, the following coroutine code will be traced as follows:
 
@@ -51,9 +52,9 @@ Thread #2 |                              [==== Slice ====]
 This library also provides wrappers for some of the coroutine functions provided in the
 `kotlinx.coroutines.*` package.  For example, instead of:
 `launch { traceCoroutine("my-launch") { /* block */ } }`, you can instead write:
-`launch("my-launch") { /* block */ }`.
+`launchTraced("my-launch") { /* block */ }`.
 
-It also provides a wrapper for tracing Flow emissions. For example,
+It also provides a wrapper for tracing `Flow` collections. For example,
 
 ```
 val coldFlow = flow {
@@ -71,8 +72,9 @@ coldFlow.collect("F") {
 Would be traced as follows:
 
 ```
-Thread #1 |  [====== collect:F ======]    [==== collect:F =====]    [====== collect:F ======]
-          |    [== collect:F:emit ==]     [== collect:F:emit ==]    [== collect:F:emit ==]
+Thread #1 |  [===== collect:F =====]    [=== collect:F ====]    [===== collect:F =====]
+          |    [= collect:F:emit =]     [= collect:F:emit =]    [= collect:F:emit =]
+          |            ^ "1" printed           ^ "2" printed            ^ "3" printed
 ```
 
 # Building and Running
@@ -95,6 +97,16 @@ adb shell device_config override systemui com.android.systemui.coroutine_tracing
 adb shell am restart
 ```
 
+## Extra Debug Flags
+
+The behavior of coroutine tracing can be further fine-tuned using the following sysprops:
+
+ - `debug.coroutine_tracing.walk_stack_override`
+ - `debug.coroutine_tracing.count_continuations_override`
+
+See [`createCoroutineTracingContext()`](core/src/coroutines/TraceContextElement.kt) for
+documentation.
+
 ## Demo App
 
 Build and install the app using Soong and adevice:
diff --git a/tracinglib/benchmark/src/ThreadLocalMicroBenchmark.kt b/tracinglib/benchmark/src/ThreadLocalMicroBenchmark.kt
new file mode 100644
index 0000000..d922f1e
--- /dev/null
+++ b/tracinglib/benchmark/src/ThreadLocalMicroBenchmark.kt
@@ -0,0 +1,96 @@
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
+package com.android.app.tracing.benchmark
+
+import android.os.Trace
+import android.perftests.utils.PerfStatusReporter
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import android.platform.test.rule.EnsureDeviceSettingsRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SmallTest
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import java.util.concurrent.atomic.AtomicInteger
+import org.junit.After
+import org.junit.Assert
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@SmallTest
+@RunWith(AndroidJUnit4::class)
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class ThreadLocalMicroBenchmark {
+
+    @get:Rule val setFlagsRule = SetFlagsRule()
+
+    @get:Rule val ensureDeviceSettingsRule = EnsureDeviceSettingsRule()
+
+    @get:Rule val perfStatusReporter = PerfStatusReporter()
+
+    @Before
+    fun before() {
+        Assert.assertTrue(Trace.isEnabled())
+    }
+
+    @After
+    fun after() {
+        Assert.assertTrue(Trace.isEnabled())
+    }
+
+    @Test
+    fun testIntegerIncrement() {
+        val state = perfStatusReporter.benchmarkState
+        val count: ThreadLocal<Int> = ThreadLocal()
+        count.set(0)
+        while (state.keepRunning()) {
+            count.set(count.get()!! + 1)
+        }
+    }
+
+    @Test
+    fun testAtomicIntegerIncrement() {
+        val state = perfStatusReporter.benchmarkState
+        val count: ThreadLocal<AtomicInteger> = ThreadLocal()
+        count.set(AtomicInteger(0))
+        while (state.keepRunning()) {
+            count.get()!!.getAndIncrement()
+        }
+    }
+
+    @Test
+    fun testIntArrayIncrement() {
+        val state = perfStatusReporter.benchmarkState
+        val count: ThreadLocal<Array<Int>> = ThreadLocal()
+        count.set(arrayOf(0))
+        while (state.keepRunning()) {
+            val arr = count.get()!!
+            arr[0]++
+        }
+    }
+
+    @Test
+    fun testMutableIntIncrement() {
+        val state = perfStatusReporter.benchmarkState
+        class MutableInt(var value: Int)
+        val count: ThreadLocal<MutableInt> = ThreadLocal()
+        count.set(MutableInt(0))
+        while (state.keepRunning()) {
+            count.get()!!.value++
+        }
+    }
+}
diff --git a/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt b/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt
index 5f25bf6..0d32aee 100644
--- a/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt
+++ b/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt
@@ -24,35 +24,30 @@ import android.platform.test.rule.EnsureDeviceSettingsRule
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.filters.SmallTest
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
-import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.launchTraced
 import com.android.app.tracing.coroutines.traceCoroutine
-import com.android.systemui.Flags
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
 import kotlinx.coroutines.delay
-import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withContext
 import kotlinx.coroutines.yield
 import org.junit.After
 import org.junit.Assert
 import org.junit.Before
-import org.junit.ClassRule
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
 
-private val TAG: String = TraceContextMicroBenchmark::class.java.simpleName
-
+@SmallTest
 @RunWith(AndroidJUnit4::class)
-@EnableFlags(Flags.FLAG_COROUTINE_TRACING)
+@EnableFlags(FLAG_COROUTINE_TRACING)
 class TraceContextMicroBenchmark {
 
-    @get:Rule val perfStatusReporter = PerfStatusReporter()
-
     @get:Rule val setFlagsRule = SetFlagsRule()
 
-    companion object {
-        @JvmField @ClassRule(order = 1) var ensureDeviceSettingsRule = EnsureDeviceSettingsRule()
-    }
+    @get:Rule val ensureDeviceSettingsRule = EnsureDeviceSettingsRule()
+
+    @get:Rule val perfStatusReporter = PerfStatusReporter()
 
     @Before
     fun before() {
@@ -70,7 +65,6 @@ class TraceContextMicroBenchmark {
         state.resumeTiming()
     }
 
-    @SmallTest
     @Test
     fun testSingleTraceSection() {
         val state = perfStatusReporter.benchmarkState
@@ -81,13 +75,12 @@ class TraceContextMicroBenchmark {
         }
     }
 
-    @SmallTest
     @Test
     fun testNestedContext() {
         val state = perfStatusReporter.benchmarkState
 
         val context1 = createCoroutineTracingContext("scope1")
-        val context2 = nameCoroutine("scope2")
+        val context2 = createCoroutineTracingContext("scope2")
         runBlocking {
             while (state.keepRunning()) {
                 withContext(context1) {
@@ -108,14 +101,13 @@ class TraceContextMicroBenchmark {
         }
     }
 
-    @SmallTest
     @Test
     fun testInterleavedLaunch() {
         val state = perfStatusReporter.benchmarkState
 
         runBlocking(createCoroutineTracingContext("root")) {
             val job1 =
-                launch(nameCoroutine("scope1")) {
+                launchTraced("scope1") {
                     while (true) {
                         traceCoroutine("hello") {
                             traceCoroutine("world") { yield() }
@@ -124,7 +116,7 @@ class TraceContextMicroBenchmark {
                     }
                 }
             val job2 =
-                launch(nameCoroutine("scope2")) {
+                launchTraced("scope2") {
                     while (true) {
                         traceCoroutine("hallo") {
                             traceCoroutine("welt") { yield() }
diff --git a/tracinglib/core/Android.bp b/tracinglib/core/Android.bp
index 339e8fc..f292898 100644
--- a/tracinglib/core/Android.bp
+++ b/tracinglib/core/Android.bp
@@ -31,9 +31,6 @@ java_library {
     ],
     kotlincflags: [
         "-Xjvm-default=all",
-        "-opt-in=kotlin.ExperimentalStdlibApi",
-        "-opt-in=kotlinx.coroutines.DelicateCoroutinesApi",
-        "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
         "-Xexplicit-api=strict",
     ],
     srcs: [":tracinglib-core-srcs"],
diff --git a/tracinglib/core/src/TraceUtils.kt b/tracinglib/core/src/TraceUtils.kt
index ede2610..9dfdfa1 100644
--- a/tracinglib/core/src/TraceUtils.kt
+++ b/tracinglib/core/src/TraceUtils.kt
@@ -18,8 +18,12 @@ package com.android.app.tracing
 
 import android.annotation.SuppressLint
 import android.os.Trace
+import com.android.app.tracing.TrackGroupUtils.trackGroup
 import com.android.app.tracing.coroutines.traceCoroutine
 import java.util.concurrent.ThreadLocalRandom
+import kotlin.contracts.ExperimentalContracts
+import kotlin.contracts.InvocationKind
+import kotlin.contracts.contract
 
 /**
  * Writes a trace message to indicate that a given section of code has begun running __on the
@@ -88,7 +92,9 @@ internal fun endSlice() {
  * Run a block within a [Trace] section. Calls [Trace.beginSection] before and [Trace.endSection]
  * after the passed block.
  */
+@OptIn(ExperimentalContracts::class)
 public inline fun <T> traceSection(tag: String, block: () -> T): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
     val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag)
     return try {
@@ -104,7 +110,12 @@ public inline fun <T> traceSection(tag: String, block: () -> T): T {
  * Same as [traceSection], but the tag is provided as a lambda to help avoiding creating expensive
  * strings when not needed.
  */
+@OptIn(ExperimentalContracts::class)
 public inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
+    contract {
+        callsInPlace(tag, InvocationKind.AT_MOST_ONCE)
+        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+    }
     val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag())
     return try {
@@ -114,6 +125,23 @@ public inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
     }
 }
 
+/**
+ * Like [com.android.app.tracing.traceSection], but uses `crossinline` so we don't accidentally
+ * introduce non-local returns. This is less convenient to use, but it ensures we will not
+ * accidentally pass a suspending function to this method.
+ */
+@OptIn(ExperimentalContracts::class)
+internal inline fun <T> traceBlocking(sectionName: String, crossinline block: () -> T): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    Trace.traceBegin(Trace.TRACE_TAG_APP, sectionName)
+    return try {
+        block()
+    } finally {
+        Trace.traceEnd(Trace.TRACE_TAG_APP)
+    }
+}
+
+@OptIn(ExperimentalContracts::class)
 public object TraceUtils {
     public const val TAG: String = "TraceUtils"
     public const val DEFAULT_TRACK_NAME: String = "AsyncTraces"
@@ -180,18 +208,78 @@ public object TraceUtils {
     /**
      * Creates an async slice in a track with [trackName] while [block] runs.
      *
-     * This can be used to trace coroutine code. [method] will be the name of the slice, [trackName]
-     * of the track. The track is one of the rows visible in a perfetto trace inside the app
-     * process.
+     * This can be used to trace coroutine code. [sliceName] will be the name of the slice,
+     * [trackName] of the track. The track is one of the rows visible in a perfetto trace inside the
+     * app process.
      */
     @JvmStatic
-    public inline fun <T> traceAsync(trackName: String, method: String, block: () -> T): T {
+    public inline fun <T> traceAsync(trackName: String, sliceName: String, block: () -> T): T {
+        contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+        return traceAsync(Trace.TRACE_TAG_APP, trackName, sliceName, block)
+    }
+
+    /** Creates an async slice in a track with [trackName] while [block] runs. */
+    @JvmStatic
+    public inline fun <T> traceAsync(
+        traceTag: Long,
+        trackName: String,
+        sliceName: String,
+        block: () -> T,
+    ): T {
+        contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
         val cookie = ThreadLocalRandom.current().nextInt()
-        Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, trackName, method, cookie)
+        Trace.asyncTraceForTrackBegin(traceTag, trackName, sliceName, cookie)
         try {
             return block()
         } finally {
-            Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, trackName, cookie)
+            Trace.asyncTraceForTrackEnd(traceTag, trackName, cookie)
         }
     }
+
+    /** Creates an async slice in a track with [trackName] while [block] runs. */
+    @JvmStatic
+    public inline fun <T> traceAsync(
+        traceTag: Long,
+        trackName: String,
+        sliceName: () -> String,
+        block: () -> T,
+    ): T {
+        contract {
+            callsInPlace(sliceName, InvocationKind.AT_MOST_ONCE)
+            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+        }
+        val tracingEnabled = Trace.isEnabled()
+        return if (tracingEnabled) {
+            return traceAsync(traceTag, trackName, sliceName(), block)
+        } else {
+            block()
+        }
+    }
+
+    /** Starts an async slice, and returns a runnable that stops the slice. */
+    @JvmStatic
+    public fun traceAsyncClosable(
+        traceTag: Long = Trace.TRACE_TAG_APP,
+        trackName: String,
+        sliceName: String,
+    ): () -> Unit {
+        val cookie = ThreadLocalRandom.current().nextInt()
+        Trace.asyncTraceForTrackBegin(traceTag, trackName, sliceName, cookie)
+        return { Trace.asyncTraceForTrackEnd(traceTag, trackName, cookie) }
+    }
+
+    /** Starts an async slice, and returns a runnable that stops the slice. */
+    @JvmStatic
+    @JvmOverloads
+    public fun traceAsyncClosable(
+        traceTag: Long = Trace.TRACE_TAG_APP,
+        trackGroupName: String,
+        trackName: String,
+        sliceName: String,
+    ): () -> Unit {
+        val groupedTrackName = trackGroup(trackGroupName, trackName)
+        val cookie = ThreadLocalRandom.current().nextInt()
+        Trace.asyncTraceForTrackBegin(traceTag, groupedTrackName, sliceName, cookie)
+        return { Trace.asyncTraceForTrackEnd(traceTag, groupedTrackName, cookie) }
+    }
 }
diff --git a/tracinglib/core/src/TrackGroupUtils.kt b/tracinglib/core/src/TrackGroupUtils.kt
new file mode 100644
index 0000000..f757a05
--- /dev/null
+++ b/tracinglib/core/src/TrackGroupUtils.kt
@@ -0,0 +1,32 @@
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
+package com.android.app.tracing
+
+public object TrackGroupUtils {
+    /**
+     * Generates a track name in a way that perfetto can group tracks together.
+     *
+     * This leverages the "Create process workspace" perfetto plugin. This plugins parses all the
+     * tracks that follow the "groupName##trackName" format, nesting "trackName" under "groupName".
+     *
+     * This allows to easily group tracks that are related under a single summary track (e.g. all
+     * "shade" related tracks will appear together, under the "shade" track in the process
+     * workspace).
+     */
+    @JvmStatic
+    public fun trackGroup(groupName: String, trackName: String): String = "$groupName##$trackName"
+}
diff --git a/tracinglib/core/src/coroutines/CoroutineTracing.kt b/tracinglib/core/src/coroutines/CoroutineTracing.kt
index d86d13d..8ca6ca3 100644
--- a/tracinglib/core/src/coroutines/CoroutineTracing.kt
+++ b/tracinglib/core/src/coroutines/CoroutineTracing.kt
@@ -14,9 +14,11 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalContracts::class, ExperimentalContracts::class)
+
 package com.android.app.tracing.coroutines
 
-import com.android.systemui.Flags
+import com.android.app.tracing.traceSection
 import kotlin.contracts.ExperimentalContracts
 import kotlin.contracts.InvocationKind
 import kotlin.contracts.contract
@@ -28,21 +30,31 @@ import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.async
 import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.collect
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withContext
 
-@OptIn(ExperimentalContracts::class)
+/** @see kotlinx.coroutines.coroutineScope */
+public suspend inline fun <R> coroutineScopeTraced(
+    crossinline spanName: () -> String,
+    crossinline block: suspend CoroutineScope.() -> R,
+): R {
+    contract {
+        callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
+        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+    }
+    return coroutineScope { traceCoroutine(spanName) { block() } }
+}
+
+/** @see kotlinx.coroutines.coroutineScope */
 public suspend inline fun <R> coroutineScopeTraced(
     traceName: String,
     crossinline block: suspend CoroutineScope.() -> R,
 ): R {
     contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
-    return coroutineScope {
-        traceCoroutine(traceName) {
-            return@coroutineScope block()
-        }
-    }
+    return coroutineScopeTraced({ traceName }, block)
 }
 
 /**
@@ -56,7 +68,8 @@ public inline fun CoroutineScope.launchTraced(
     start: CoroutineStart = CoroutineStart.DEFAULT,
     noinline block: suspend CoroutineScope.() -> Unit,
 ): Job {
-    return launch(nameCoroutine(spanName) + context, start, block)
+    contract { callsInPlace(spanName, InvocationKind.AT_MOST_ONCE) }
+    return launch(addName(spanName, context), start, block)
 }
 
 /**
@@ -69,7 +82,23 @@ public fun CoroutineScope.launchTraced(
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     block: suspend CoroutineScope.() -> Unit,
-): Job = launchTraced({ spanName ?: block::class.simpleName ?: "launch" }, context, start, block)
+): Job {
+    return launchTraced({ spanName ?: block.traceName }, context, start, block)
+}
+
+/** @see kotlinx.coroutines.flow.launchIn */
+public inline fun <T> Flow<T>.launchInTraced(
+    crossinline spanName: () -> String,
+    scope: CoroutineScope,
+): Job {
+    contract { callsInPlace(spanName, InvocationKind.AT_MOST_ONCE) }
+    return scope.launchTraced(spanName) { collect() }
+}
+
+/** @see kotlinx.coroutines.flow.launchIn */
+public fun <T> Flow<T>.launchInTraced(spanName: String, scope: CoroutineScope): Job {
+    return scope.launchTraced({ spanName }) { collect() }
+}
 
 /**
  * Convenience function for calling [CoroutineScope.async] with [traceCoroutine] enable tracing
@@ -77,11 +106,14 @@ public fun CoroutineScope.launchTraced(
  * @see traceCoroutine
  */
 public inline fun <T> CoroutineScope.asyncTraced(
-    spanName: () -> String,
+    crossinline spanName: () -> String,
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     noinline block: suspend CoroutineScope.() -> T,
-): Deferred<T> = async(nameCoroutine(spanName) + context, start, block)
+): Deferred<T> {
+    contract { callsInPlace(spanName, InvocationKind.AT_MOST_ONCE) }
+    return async(addName(spanName, context), start, block)
+}
 
 /**
  * Convenience function for calling [CoroutineScope.async] with [traceCoroutine] enable tracing.
@@ -93,52 +125,63 @@ public fun <T> CoroutineScope.asyncTraced(
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     block: suspend CoroutineScope.() -> T,
-): Deferred<T> =
-    asyncTraced({ spanName ?: block::class.simpleName ?: "async" }, context, start, block)
+): Deferred<T> {
+    return asyncTraced({ spanName ?: block.traceName }, context, start, block)
+}
 
 /**
- * Convenience function for calling [runBlocking] with [traceCoroutine] to enable tracing.
+ * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-public inline fun <T> runBlockingTraced(
-    spanName: () -> String,
+public suspend inline fun <T> withContextTraced(
+    crossinline spanName: () -> String,
     context: CoroutineContext,
     noinline block: suspend CoroutineScope.() -> T,
-): T = runBlocking(nameCoroutine(spanName) + context, block)
-
-/**
- * Convenience function for calling [runBlocking] with [traceCoroutine] to enable tracing.
- *
- * @see traceCoroutine
- */
-public fun <T> runBlockingTraced(
-    spanName: String? = null,
-    context: CoroutineContext,
-    block: suspend CoroutineScope.() -> T,
-): T = runBlockingTraced({ spanName ?: block::class.simpleName ?: "runBlocking" }, context, block)
+): T {
+    contract {
+        callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
+        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+    }
+    return traceCoroutine(spanName) { withContext(context, block) }
+}
 
 /**
  * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-public suspend fun <T> withContextTraced(
+public suspend inline fun <T> withContextTraced(
     spanName: String? = null,
     context: CoroutineContext,
-    block: suspend CoroutineScope.() -> T,
-): T = withContextTraced({ spanName ?: block::class.simpleName ?: "withContext" }, context, block)
+    noinline block: suspend CoroutineScope.() -> T,
+): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    return withContextTraced({ spanName ?: block.traceName }, context, block)
+}
 
-/**
- * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
- *
- * @see traceCoroutine
- */
-public suspend inline fun <T> withContextTraced(
-    spanName: () -> String,
+/** @see kotlinx.coroutines.runBlocking */
+public inline fun <T> runBlockingTraced(
+    crossinline spanName: () -> String,
     context: CoroutineContext,
     noinline block: suspend CoroutineScope.() -> T,
-): T = withContext(nameCoroutine(spanName) + context, block)
+): T {
+    contract {
+        callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
+        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+    }
+    return traceSection(spanName) { runBlocking(context, block) }
+}
+
+/** @see kotlinx.coroutines.runBlocking */
+public fun <T> runBlockingTraced(
+    spanName: String?,
+    context: CoroutineContext,
+    block: suspend CoroutineScope.() -> T,
+): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    return runBlockingTraced({ spanName ?: block.traceName }, context, block)
+}
 
 /**
  * Traces a section of work of a `suspend` [block]. The trace sections will appear on the thread
@@ -170,25 +213,77 @@ public suspend inline fun <T> withContextTraced(
  * @param spanName The name of the code section to appear in the trace
  * @see traceCoroutine
  */
-@OptIn(ExperimentalContracts::class)
-public inline fun <T> traceCoroutine(spanName: () -> String, block: () -> T): T {
+public inline fun <T, R> R.traceCoroutine(crossinline spanName: () -> String, block: R.() -> T): T {
     contract {
         callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
         callsInPlace(block, InvocationKind.EXACTLY_ONCE)
     }
+    // For coroutine tracing to work, trace spans must be added and removed even when
+    // tracing is not active (i.e. when TRACE_TAG_APP is disabled). Otherwise, when the
+    // coroutine resumes when tracing is active, we won't know its name.
+    try {
+        if (com.android.systemui.Flags.coroutineTracing()) {
+            traceThreadLocal.get()?.beginCoroutineTrace(spanName())
+        }
+        return block()
+    } finally {
+        if (com.android.systemui.Flags.coroutineTracing()) {
+            traceThreadLocal.get()?.endCoroutineTrace()
+        }
+    }
+}
 
+public inline fun <T> traceCoroutine(crossinline spanName: () -> String, block: () -> T): T {
+    contract {
+        callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
+        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+    }
     // For coroutine tracing to work, trace spans must be added and removed even when
     // tracing is not active (i.e. when TRACE_TAG_APP is disabled). Otherwise, when the
     // coroutine resumes when tracing is active, we won't know its name.
-    val traceData = if (Flags.coroutineTracing()) traceThreadLocal.get() else null
-    traceData?.beginSpan(spanName())
     try {
+        if (com.android.systemui.Flags.coroutineTracing()) {
+            traceThreadLocal.get()?.beginCoroutineTrace(spanName())
+        }
         return block()
     } finally {
-        traceData?.endSpan()
+        if (com.android.systemui.Flags.coroutineTracing()) {
+            traceThreadLocal.get()?.endCoroutineTrace()
+        }
     }
 }
 
 /** @see traceCoroutine */
-public inline fun <T> traceCoroutine(spanName: String, block: () -> T): T =
-    traceCoroutine({ spanName }, block)
+public inline fun <T, R> R.traceCoroutine(spanName: String, block: R.() -> T): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    return traceCoroutine({ spanName }, block)
+}
+
+/** @see traceCoroutine */
+public inline fun <T> traceCoroutine(spanName: String, block: () -> T): T {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    return traceCoroutine({ spanName }, block)
+}
+
+/**
+ * Returns the passed context if [com.android.systemui.Flags.coroutineTracing] is false. Otherwise,
+ * returns a new context by adding [CoroutineTraceName] to the given context. The
+ * [CoroutineTraceName] in the passed context will take precedence over the new
+ * [CoroutineTraceName].
+ */
+@PublishedApi
+internal inline fun addName(
+    crossinline spanName: () -> String,
+    context: CoroutineContext,
+): CoroutineContext {
+    contract { callsInPlace(spanName, InvocationKind.AT_MOST_ONCE) }
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        CoroutineTraceName(spanName()) + context
+    } else {
+        context
+    }
+}
+
+@PublishedApi
+internal inline val <reified T : Any> T.traceName: String
+    inline get() = this::class.java.name.substringAfterLast(".")
diff --git a/tracinglib/core/src/coroutines/TraceContextElement.kt b/tracinglib/core/src/coroutines/TraceContextElement.kt
index 3e87e18..466b0c6 100644
--- a/tracinglib/core/src/coroutines/TraceContextElement.kt
+++ b/tracinglib/core/src/coroutines/TraceContextElement.kt
@@ -17,10 +17,10 @@
 package com.android.app.tracing.coroutines
 
 import android.annotation.SuppressLint
+import android.os.PerfettoTrace
 import android.os.SystemProperties
 import android.os.Trace
 import android.util.Log
-import com.android.systemui.Flags
 import java.lang.StackWalker.StackFrame
 import java.util.concurrent.ThreadLocalRandom
 import java.util.concurrent.atomic.AtomicInteger
@@ -28,16 +28,16 @@ import java.util.stream.Stream
 import kotlin.contracts.ExperimentalContracts
 import kotlin.contracts.InvocationKind
 import kotlin.contracts.contract
+import kotlin.coroutines.AbstractCoroutineContextKey
 import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
+import kotlin.coroutines.getPolymorphicElement
+import kotlin.coroutines.minusPolymorphicKey
 import kotlinx.coroutines.CopyableThreadContextElement
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 
-/** Use a final subclass to avoid virtual calls (b/316642146). */
-@PublishedApi internal class TraceDataThreadLocal : ThreadLocal<TraceData?>()
-
 /**
  * Thread-local storage for tracking open trace sections in the current coroutine context; it should
  * only be used when paired with a [TraceContextElement].
@@ -51,8 +51,14 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
  */
 @PublishedApi internal val traceThreadLocal: TraceDataThreadLocal = TraceDataThreadLocal()
 
-private val alwaysEnableStackWalker: Boolean by lazy {
-    SystemProperties.getBoolean("debug.coroutine_tracing.walk_stack_override", false)
+internal object DebugSysProps {
+    @JvmField
+    val alwaysEnableStackWalker =
+        SystemProperties.getBoolean("debug.coroutine_tracing.walk_stack_override", false)
+
+    @JvmField
+    val alwaysEnableContinuationCounting =
+        SystemProperties.getBoolean("debug.coroutine_tracing.count_continuations_override", false)
 }
 
 /**
@@ -78,97 +84,85 @@ private val alwaysEnableStackWalker: Boolean by lazy {
  * }
  * ```
  *
- * **NOTE:** The sysprop `debug.coroutine_tracing.walk_stack_override` can be used to override the
- * `walkStackForDefaultNames` parameter, forcing it to always be `true`. If the sysprop is `false`
- * (or does not exist), the value of `walkStackForDefaultNames` is used, whether `true` or `false`.
+ * **NOTE:** The sysprops `debug.coroutine_tracing.walk_stack_override` and
+ * `debug.coroutine_tracing.count_continuations_override` can be used to override the parameters
+ * `walkStackForDefaultNames` and `countContinuations` respectively, forcing them to always be
+ * `true`. If the sysprop is `false` (or does not exist), the value of the parameter is passed here
+ * is used. If `true`, all calls to [createCoroutineTracingContext] will be overwritten with that
+ * parameter set to `true`. Importantly, this means that the sysprops can be used to globally turn
+ * ON `walkStackForDefaultNames` or `countContinuations`, but they cannot be used to globally turn
+ * OFF either parameter.
  *
  * @param name the name of the coroutine scope. Since this should only be installed on top-level
  *   coroutines, this should be the name of the root [CoroutineScope].
  * @param walkStackForDefaultNames whether to walk the stack and use the class name of the current
  *   suspending function if child does not have a name that was manually specified. Walking the
  *   stack is very expensive so this should not be used in production.
- * @param includeParentNames whether to concatenate parent names and sibling counts with the name of
- *   the child. This should only be used for testing because it can result in extremely long trace
- *   names.
- * @param strictMode whether to add additional checks to coroutine tracing machinery. These checks
- *   are expensive and should only be used for testing.
+ * @param countContinuations whether to include extra info in the trace section indicating the total
+ *   number of times a coroutine has suspended and resumed (e.g. ";n=#")
+ * @param countDepth whether to include extra info in the trace section indicating the how far from
+ *   the root trace context this coroutine is (e.g. ";d=#")
+ * @param testMode changes behavior is several ways: 1) parent names and sibling counts are
+ *   concatenated with the name of the child. This can result in extremely long trace names, which
+ *   is why it is only for testing. 2) additional strict-mode checks are added to coroutine tracing
+ *   machinery. These checks are expensive and should only be used for testing. 3) omits "coroutine
+ *   execution" trace slices, and omits coroutine metadata slices. If [testMode] is enabled,
+ *   [countContinuations] and [countDepth] are ignored.
  * @param shouldIgnoreClassName lambda that takes binary class name (as returned from
  *   [StackFrame.getClassName] and returns true if it should be ignored (e.g. search for relevant
- *   class name should continue) or false otherwise
+ *   class name should continue) or false otherwise.
  */
 public fun createCoroutineTracingContext(
     name: String = "UnnamedScope",
+    countContinuations: Boolean = false,
+    countDepth: Boolean = false,
+    testMode: Boolean = false,
     walkStackForDefaultNames: Boolean = false,
-    includeParentNames: Boolean = false,
-    strictMode: Boolean = false,
-    shouldIgnoreClassName: (String) -> Boolean = { false },
+    shouldIgnoreClassName: ((String) -> Boolean)? = null,
 ): CoroutineContext {
-    return if (Flags.coroutineTracing()) {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
         TraceContextElement(
             name = name,
-            // Minor perf optimization: no need to create TraceData() for root scopes since all
-            // launches require creation of child via [copyForChild] or [mergeForChild].
-            contextTraceData = null,
-            inheritedTracePrefix = "",
-            coroutineDepth = 0,
-            parentId = -1,
-            TraceConfig(
-                walkStackForDefaultNames = walkStackForDefaultNames || alwaysEnableStackWalker,
-                includeParentNames = includeParentNames,
-                strictMode = strictMode,
-                shouldIgnoreClassName = shouldIgnoreClassName,
-            ),
+            isRoot = true,
+            countContinuations =
+                !testMode && (countContinuations || DebugSysProps.alwaysEnableContinuationCounting),
+            walkStackForDefaultNames =
+                walkStackForDefaultNames || DebugSysProps.alwaysEnableStackWalker,
+            shouldIgnoreClassName = shouldIgnoreClassName,
+            parentId = null,
+            inheritedTracePrefix = if (testMode) "" else null,
+            coroutineDepth = if (!testMode && countDepth) 0 else -1,
         )
     } else {
         EmptyCoroutineContext
     }
 }
 
-/**
- * Returns a new [CoroutineTraceName] (or [EmptyCoroutineContext] if `coroutine_tracing` feature is
- * flagged off). When the current [CoroutineScope] has a [TraceContextElement] installed,
- * [CoroutineTraceName] can be used to name the child scope under construction.
- *
- * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
- */
-public fun nameCoroutine(name: String): CoroutineContext = nameCoroutine { name }
+private object PerfettoTraceConfig {
+    // cc = coroutine continuations
+    @JvmField val COROUTINE_CATEGORY: PerfettoTrace.Category = PerfettoTrace.Category("cc")
 
-/**
- * Returns a new [CoroutineTraceName] (or [EmptyCoroutineContext] if `coroutine_tracing` feature is
- * flagged off). When the current [CoroutineScope] has a [TraceContextElement] installed,
- * [CoroutineTraceName] can be used to name the child scope under construction.
- *
- * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
- *
- * @param name lazy string to only be called if feature is enabled
- */
-@OptIn(ExperimentalContracts::class)
-public inline fun nameCoroutine(name: () -> String): CoroutineContext {
-    contract { callsInPlace(name, InvocationKind.AT_MOST_ONCE) }
-    return if (Flags.coroutineTracing()) CoroutineTraceName(name()) else EmptyCoroutineContext
+    init {
+        if (android.os.Flags.perfettoSdkTracingV2()) {
+            PerfettoTrace.register(/* isBackendInProcess */ false)
+            COROUTINE_CATEGORY.register()
+        }
+    }
 }
 
-/**
- * Common base class of [TraceContextElement] and [CoroutineTraceName]. For internal use only.
- *
- * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
- *
- * @property name the name of the current coroutine
- */
-/**
- * A coroutine context element that can be used for naming the child coroutine under construction.
- *
- * @property name the name to be used for the child under construction
- * @see nameCoroutine
- */
 @PublishedApi
-internal open class CoroutineTraceName(internal val name: String) : CoroutineContext.Element {
-    internal companion object Key : CoroutineContext.Key<CoroutineTraceName>
+internal open class CoroutineTraceName(internal val name: String?) : CoroutineContext.Element {
+    companion object Key : CoroutineContext.Key<CoroutineTraceName>
 
-    public override val key: CoroutineContext.Key<*>
+    override val key: CoroutineContext.Key<*>
         get() = Key
 
-    protected val currentId: Int = ThreadLocalRandom.current().nextInt(1, Int.MAX_VALUE)
+    @OptIn(ExperimentalStdlibApi::class)
+    override fun <E : CoroutineContext.Element> get(key: CoroutineContext.Key<E>): E? =
+        getPolymorphicElement(key)
+
+    @OptIn(ExperimentalStdlibApi::class)
+    override fun minusKey(key: CoroutineContext.Key<*>): CoroutineContext = minusPolymorphicKey(key)
 
     @Deprecated(
         message =
@@ -181,24 +175,27 @@ internal open class CoroutineTraceName(internal val name: String) : CoroutineCon
         """,
         level = DeprecationLevel.ERROR,
     )
-    public operator fun plus(other: CoroutineTraceName): CoroutineTraceName {
-        debug { "#plus(${other.currentId})" }
+    operator fun plus(other: CoroutineTraceName): CoroutineTraceName {
         return other
     }
 
-    @OptIn(ExperimentalContracts::class)
-    protected inline fun debug(message: () -> String) {
-        contract { callsInPlace(message, InvocationKind.AT_MOST_ONCE) }
-        if (DEBUG) Log.d(TAG, "${this::class.java.simpleName}@$currentId${message()}")
+    @Deprecated(
+        message =
+            """
+         Operator `+` on two BaseTraceElement objects is meaningless. If used, the context element
+         to the right of `+` would simply replace the element to the left. To properly use
+         `BaseTraceElement`, `TraceContextElement` should be used when creating a top-level
+         `CoroutineScope` and `CoroutineTraceName` should be passed to the child context that is
+         under construction.
+        """,
+        level = DeprecationLevel.ERROR,
+    )
+    operator fun plus(other: TraceContextElement): TraceContextElement {
+        return other
     }
 }
 
-internal data class TraceConfig(
-    val walkStackForDefaultNames: Boolean,
-    val includeParentNames: Boolean,
-    val strictMode: Boolean,
-    val shouldIgnoreClassName: (String) -> Boolean,
-)
+private fun nextRandomInt(): Int = ThreadLocalRandom.current().nextInt(1, Int.MAX_VALUE)
 
 /**
  * Used for tracking parent-child relationship of coroutines and persisting [TraceData] when
@@ -206,52 +203,95 @@ internal data class TraceConfig(
  *
  * This is internal machinery for [traceCoroutine] and should not be used directly.
  *
- * @param name the name of the current coroutine. Since this should only be installed on top-level
+ * @param name The name of the current coroutine. Since this should only be installed on top-level
  *   coroutines, this should be the name of the root [CoroutineScope].
  * @property contextTraceData [TraceData] to be saved to thread-local storage.
- * @param inheritedTracePrefix prefix containing metadata for parent scopes. Each child is separated
+ * @property config Configuration parameters
+ * @param parentId The ID of the parent coroutine, as defined in [BaseTraceElement]
+ * @param inheritedTracePrefix Prefix containing metadata for parent scopes. Each child is separated
  *   by a `:` and prefixed by a counter indicating the ordinal of this child relative to its
  *   siblings. Thus, the prefix such as `root-name:3^child-name` would indicate this is the 3rd
  *   child (of any name) to be started on `root-scope`. If the child has no name, an empty string
  *   would be used instead: `root-scope:3^`
- * @property coroutineDepth how deep the coroutine is relative to the top-level [CoroutineScope]
+ * @param coroutineDepth How deep the coroutine is relative to the top-level [CoroutineScope]
  *   containing the original [TraceContextElement] from which this [TraceContextElement] was copied.
- * @param parentId the ID of the parent coroutine, as defined in [BaseTraceElement]
- * @param walkStackForDefaultNames whether to walk the stack and use the class name of the current
- *   suspending function if child does not have a name that was manually specified. Walking the
- *   stack is very expensive so this should not be used in production.
- * @param includeParentNames whether to concatenate parent names and sibling counts with the name of
- *   the child. This should only be used for testing because it can result in extremely long trace
- *   names.
- * @param strictMode whether to add additional checks to coroutine machinery. These checks are
- *   expensive and should only be used for testing.
- * @param shouldIgnoreClassName lambda that takes binary class name (as returned from
- *   [StackFrame.getClassName] and returns true if it should be ignored (e.g. search for relevant
- *   class name should continue) or false otherwise
+ *   If -1, counting depth is disabled
  * @see createCoroutineTracingContext
  * @see nameCoroutine
  * @see traceCoroutine
  */
+@SuppressLint("UnclosedTrace")
 @OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
 internal class TraceContextElement(
     name: String,
-    internal val contextTraceData: TraceData?,
-    inheritedTracePrefix: String,
-    private val coroutineDepth: Int,
-    parentId: Int,
-    private val config: TraceConfig,
-) : CopyableThreadContextElement<TraceData?>, CoroutineTraceName(name) {
+    private val isRoot: Boolean,
+    countContinuations: Boolean,
+    private val walkStackForDefaultNames: Boolean,
+    private val shouldIgnoreClassName: ((String) -> Boolean)?,
+    parentId: Int?,
+    inheritedTracePrefix: String?,
+    coroutineDepth: Int,
+) : CopyableThreadContextElement<TraceData?>, CoroutineTraceName(name), CoroutineContext.Element {
+    @OptIn(ExperimentalStdlibApi::class)
+    companion object Key :
+        AbstractCoroutineContextKey<CoroutineTraceName, TraceContextElement>(
+            CoroutineTraceName,
+            { it as? TraceContextElement },
+        )
 
-    private var childCoroutineCount = AtomicInteger(0)
+    private val currentId: Int = nextRandomInt()
+    private val nameWithId =
+        "${if (isRoot) "ROOT-" else ""}$name;c=$currentId;p=${parentId ?: "none"}"
 
-    private val fullCoroutineTraceName =
-        if (config.includeParentNames) "$inheritedTracePrefix$name" else ""
-    private val continuationTraceMessage =
-        "$fullCoroutineTraceName;$name;d=$coroutineDepth;c=$currentId;p=$parentId"
+    // Don't use Perfetto SDK when inherited trace prefixes are used since it is a feature only
+    // intended for testing, and only the `android.os.Trace` APIs currently have test shadows:
+    private val usePerfettoSdk =
+        android.os.Flags.perfettoSdkTracingV2() && inheritedTracePrefix == null
+
+    private var continuationId = if (usePerfettoSdk) nextRandomInt() else 0
 
     init {
-        debug { "#init: name=$name" }
-        Trace.instant(Trace.TRACE_TAG_APP, continuationTraceMessage)
+        val traceSection = "TCE#init;$nameWithId"
+        debug { traceSection }
+        if (usePerfettoSdk) {
+            PerfettoTrace.begin(PerfettoTraceConfig.COROUTINE_CATEGORY, traceSection).emit()
+        } else {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, traceSection) // begin: "TCE#init"
+        }
+    }
+
+    // Minor perf optimization: no need to create TraceData() for root scopes since all launches
+    // require creation of child via [copyForChild] or [mergeForChild].
+    internal val contextTraceData: TraceData? =
+        if (isRoot) null else TraceData(currentId, strictMode = inheritedTracePrefix != null)
+
+    private var coroutineTraceName: String =
+        if (inheritedTracePrefix == null) {
+            COROUTINE_EXECUTION +
+                nameWithId +
+                (if (coroutineDepth == -1) "" else ";d=$coroutineDepth") +
+                (if (countContinuations) ";n=" else "")
+        } else {
+            "$inheritedTracePrefix$name"
+        }
+
+    private var continuationCount = if (countContinuations) 0 else Int.MIN_VALUE
+    private val childDepth =
+        if (inheritedTracePrefix != null || coroutineDepth == -1) -1 else coroutineDepth + 1
+
+    private val childCoroutineCount = if (inheritedTracePrefix != null) AtomicInteger(0) else null
+
+    private val copyForChildTraceMessage = "TCE#copy;$nameWithId"
+    private val mergeForChildTraceMessage = "TCE#merge;$nameWithId"
+
+    init {
+        if (usePerfettoSdk) {
+            PerfettoTrace.end(PerfettoTraceConfig.COROUTINE_CATEGORY)
+                .setFlow(continuationId.toLong())
+                .emit()
+        } else {
+            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: "TCE#init"
+        }
     }
 
     /**
@@ -269,19 +309,28 @@ internal class TraceContextElement(
      * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
      * `^` is a suspension point)
      */
-    @SuppressLint("UnclosedTrace")
-    public override fun updateThreadContext(context: CoroutineContext): TraceData? {
-        val oldState = traceThreadLocal.get()
-        debug { "#updateThreadContext oldState=$oldState" }
-        if (oldState !== contextTraceData) {
-            Trace.traceBegin(Trace.TRACE_TAG_APP, continuationTraceMessage)
-            traceThreadLocal.set(contextTraceData)
-            // Calls to `updateThreadContext` will not happen in parallel on the same context, and
-            // they cannot happen before the prior suspension point. Additionally,
-            // `restoreThreadContext` does not modify `traceData`, so it is safe to iterate over the
-            // collection here:
-            contextTraceData?.beginAllOnThread()
+    override fun updateThreadContext(context: CoroutineContext): TraceData? {
+        debug { "TCE#update;$nameWithId" }
+        // Calls to `updateThreadContext` will not happen in parallel on the same context,
+        // and they cannot happen before the prior suspension point. Additionally,
+        // `restoreThreadContext` does not modify `traceData`, so it is safe to iterate over
+        // the collection here:
+        val storage = traceThreadLocal.get() ?: return null
+        val oldState = storage.data
+        if (oldState === contextTraceData) return oldState
+        if (usePerfettoSdk) {
+            PerfettoTrace.begin(
+                    PerfettoTraceConfig.COROUTINE_CATEGORY,
+                    coroutineTraceName + if (continuationCount < 0) "" else continuationCount,
+                )
+                .setTerminatingFlow(continuationId.toLong())
+                .emit()
+            continuationId = nextRandomInt()
+        } else {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, coroutineTraceName)
         }
+        if (continuationCount >= 0) continuationCount++
+        storage.updateDataForContinuation(contextTraceData, continuationId)
         return oldState
     }
 
@@ -302,9 +351,11 @@ internal class TraceContextElement(
      * OR
      *
      * ```
-     * Thread #1 |                                 [restoreThreadContext]
+     * Thread #1 |  [update].x..^  [   ...    restore    ...   ]              [update].x..^[restore]
+     * --------------------------------------------------------------------------------------------
+     * Thread #2 |                 [update]...x....x..^[restore]
      * --------------------------------------------------------------------------------------------
-     * Thread #2 |     [updateThreadContext]...x....x..^[restoreThreadContext]
+     * Thread #3 |                                     [ ... update ... ] ...^  [restore]
      * ```
      *
      * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
@@ -312,57 +363,63 @@ internal class TraceContextElement(
      *
      * ```
      */
-    public override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
-        debug { "#restoreThreadContext restoring=$oldState" }
+    override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
+        debug { "TCE#restore;$nameWithId restoring=${oldState?.currentId}" }
         // We not use the `TraceData` object here because it may have been modified on another
         // thread after the last suspension point. This is why we use a [TraceStateHolder]:
         // so we can end the correct number of trace sections, restoring the thread to its state
         // prior to the last call to [updateThreadContext].
-        if (oldState !== traceThreadLocal.get()) {
-            contextTraceData?.endAllOnThread()
-            traceThreadLocal.set(oldState)
-            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: currentScopeTraceMessage
+        val storage = traceThreadLocal.get() ?: return
+        if (storage.data === oldState) return
+        val contId = storage.restoreDataForSuspension(oldState)
+        if (usePerfettoSdk) {
+            PerfettoTrace.end(PerfettoTraceConfig.COROUTINE_CATEGORY)
+                .setFlow(contId.toLong())
+                .emit()
+        } else {
+            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: coroutineTraceName
         }
     }
 
-    public override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
-        debug { "#copyForChild" }
-        return createChildContext()
+    override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
+        debug { copyForChildTraceMessage }
+        try {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, copyForChildTraceMessage) // begin: TCE#copy
+            // Root is a special case in which the name is copied to the child by default.
+            // Otherwise, everything launched on a coroutine would have an empty name by default
+            return createChildContext(if (isRoot) name else null)
+        } finally {
+            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: TCE#copy
+        }
     }
 
-    public override fun mergeForChild(
-        overwritingElement: CoroutineContext.Element
-    ): CoroutineContext {
-        debug { "#mergeForChild" }
-        if (DEBUG) {
-            (overwritingElement as? TraceContextElement)?.let {
-                Log.e(
-                    TAG,
-                    "${this::class.java.simpleName}@$currentId#mergeForChild(@${it.currentId}): " +
-                        "current name=\"$name\", overwritingElement name=\"${it.name}\". " +
-                        UNEXPECTED_TRACE_DATA_ERROR_MESSAGE,
-                )
-            }
+    override fun mergeForChild(overwritingElement: CoroutineContext.Element): CoroutineContext {
+        debug { mergeForChildTraceMessage }
+        try {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, mergeForChildTraceMessage) // begin: TCE#merge
+            return createChildContext(overwritingElement[CoroutineTraceName]?.name)
+        } finally {
+            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: TCE#merge
         }
-        val nameForChild = (overwritingElement as CoroutineTraceName).name
-        return createChildContext(nameForChild)
     }
 
-    private fun createChildContext(
-        name: String =
-            if (config.walkStackForDefaultNames) walkStackForClassName(config.shouldIgnoreClassName)
-            else ""
-    ): TraceContextElement {
-        debug { "#createChildContext: \"$name\" has new child with name \"${name}\"" }
-        val childCount = childCoroutineCount.incrementAndGet()
+    private fun createChildContext(name: String?): TraceContextElement {
         return TraceContextElement(
-            name = name,
-            contextTraceData = TraceData(config.strictMode),
-            inheritedTracePrefix =
-                if (config.includeParentNames) "$fullCoroutineTraceName:$childCount^" else "",
-            coroutineDepth = coroutineDepth + 1,
+            name =
+                if (name == null && walkStackForDefaultNames)
+                    walkStackForClassName(shouldIgnoreClassName)
+                else name ?: "",
+            isRoot = false,
+            countContinuations = continuationCount >= 0,
+            walkStackForDefaultNames = walkStackForDefaultNames,
+            shouldIgnoreClassName = shouldIgnoreClassName,
             parentId = currentId,
-            config = config,
+            inheritedTracePrefix =
+                if (childCoroutineCount != null) {
+                    val childCount = childCoroutineCount.incrementAndGet()
+                    "${if (isRoot) "" else "$coroutineTraceName:"}$childCount^"
+                } else null,
+            coroutineDepth = childDepth,
         )
     }
 }
@@ -372,9 +429,7 @@ internal class TraceContextElement(
  *
  * @param additionalDropPredicate additional checks for whether class should be ignored
  */
-private fun walkStackForClassName(
-    additionalDropPredicate: (String) -> Boolean = { false }
-): String {
+private fun walkStackForClassName(additionalDropPredicate: ((String) -> Boolean)? = null): String {
     Trace.traceBegin(Trace.TRACE_TAG_APP, "walkStackForClassName")
     try {
         var frame = ""
@@ -383,7 +438,7 @@ private fun walkStackForClassName(
                     val className = f.className
                     className.startsWith("kotlin") ||
                         className.startsWith("com.android.app.tracing.") ||
-                        additionalDropPredicate(className)
+                        (additionalDropPredicate != null && additionalDropPredicate(className))
                 }
                 .findFirst()
                 .ifPresent { frame = it.className.substringAfterLast(".") + "." + it.methodName }
@@ -401,6 +456,18 @@ private const val UNEXPECTED_TRACE_DATA_ERROR_MESSAGE =
     "Overwriting context element with non-empty trace data. There should only be one " +
         "TraceContextElement per coroutine, and it should be installed in the root scope. "
 
+@PublishedApi internal const val COROUTINE_EXECUTION: String = "coroutine execution;"
+
 @PublishedApi internal const val TAG: String = "CoroutineTracing"
 
 @PublishedApi internal const val DEBUG: Boolean = false
+
+@OptIn(ExperimentalContracts::class)
+private inline fun debug(message: () -> String) {
+    contract { callsInPlace(message, InvocationKind.AT_MOST_ONCE) }
+    if (DEBUG) {
+        val msg = message()
+        Trace.instant(Trace.TRACE_TAG_APP, msg)
+        Log.d(TAG, msg)
+    }
+}
diff --git a/tracinglib/core/src/coroutines/TraceData.kt b/tracinglib/core/src/coroutines/TraceData.kt
index 49cea0d..fcf2d27 100644
--- a/tracinglib/core/src/coroutines/TraceData.kt
+++ b/tracinglib/core/src/coroutines/TraceData.kt
@@ -14,11 +14,17 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalContracts::class)
+
 package com.android.app.tracing.coroutines
 
+import android.os.Trace
 import com.android.app.tracing.beginSlice
 import com.android.app.tracing.endSlice
 import java.util.ArrayDeque
+import kotlin.contracts.ExperimentalContracts
+import kotlin.math.max
+import kotlinx.coroutines.CoroutineStart.UNDISPATCHED
 
 /**
  * Represents a section of code executing in a coroutine. This may be split up into multiple slices
@@ -28,9 +34,121 @@ import java.util.ArrayDeque
  */
 private typealias TraceSection = String
 
-private class TraceCountThreadLocal : ThreadLocal<Int>() {
-    override fun initialValue(): Int {
-        return 0
+/** Use a final subclass to avoid virtual calls (b/316642146). */
+@PublishedApi
+internal class TraceDataThreadLocal : ThreadLocal<TraceStorage?>() {
+    override fun initialValue(): TraceStorage? {
+        return if (com.android.systemui.Flags.coroutineTracing()) {
+            TraceStorage(null)
+        } else {
+            null
+        }
+    }
+}
+
+/**
+ * There should only be one instance of this class per thread.
+ *
+ * @param openSliceCount ThreadLocal counter for how many open trace sections there are on the
+ *   current thread. This is needed because it is possible that on a multi-threaded dispatcher, one
+ *   of the threads could be slow, and [TraceContextElement.restoreThreadContext] might be invoked
+ *   _after_ the coroutine has already resumed and modified [TraceData] - either adding or removing
+ *   trace sections and changing the count. If we did not store this thread-locally, then we would
+ *   incorrectly end too many or too few trace sections.
+ */
+@PublishedApi
+internal class TraceStorage(internal var data: TraceData?) {
+
+    /**
+     * Counter for tracking which index to use in the [continuationIds] and [openSliceCount] arrays.
+     * `contIndex` is used to keep track of the stack used for managing tracing state when
+     * coroutines are resumed and suspended in a nested way.
+     * * `-1` indicates no coroutine is currently running
+     * * `0` indicates one coroutine is running
+     * * `>1` indicates the current coroutine is resumed inside another coroutine, e.g. due to an
+     *   unconfined dispatcher or [UNDISPATCHED] launch.
+     */
+    private var contIndex = -1
+
+    /**
+     * Count of slices opened on the current thread due to current [TraceData] that must be closed
+     * when it is removed. If another [data] overwrites the current one, all trace sections due to
+     * current [data] must be closed. The overwriting [data] will handle updating itself when
+     * [TraceContextElement.updateThreadContext] is called for it.
+     *
+     * Expected nesting should never exceed 255, so use a [ByteArray]. If nesting _does_ exceed 255,
+     * it indicates there is already something very wrong with the trace, so we will not waste CPU
+     * cycles error checking.
+     */
+    private var openSliceCount = ByteArray(INITIAL_THREAD_LOCAL_STACK_SIZE)
+
+    private var continuationIds: IntArray? =
+        if (android.os.Flags.perfettoSdkTracingV2()) IntArray(INITIAL_THREAD_LOCAL_STACK_SIZE)
+        else null
+
+    private val debugCounterTrack: String? =
+        if (DEBUG) "TCE#${Thread.currentThread().threadId()}" else null
+
+    /**
+     * Adds a new trace section to the current trace data. The slice will be traced on the current
+     * thread immediately. This slice will not propagate to parent coroutines, or to child
+     * coroutines that have already started.
+     */
+    @PublishedApi
+    internal fun beginCoroutineTrace(name: String) {
+        val data = data ?: return
+        data.beginSpan(name)
+        if (0 <= contIndex && contIndex < openSliceCount.size) {
+            openSliceCount[contIndex]++
+        }
+    }
+
+    /**
+     * Ends the trace section and validates it corresponds with an earlier call to
+     * [beginCoroutineTrace]. The trace slice will immediately be removed from the current thread.
+     * This information will not propagate to parent coroutines, or to child coroutines that have
+     * already started.
+     *
+     * @return true if span was ended, `false` if not
+     */
+    @PublishedApi
+    internal fun endCoroutineTrace() {
+        if (data?.endSpan() == true && 0 <= contIndex && contIndex < openSliceCount.size) {
+            openSliceCount[contIndex]--
+        }
+    }
+
+    /** Update [data] for continuation */
+    fun updateDataForContinuation(contextTraceData: TraceData?, contId: Int) {
+        data = contextTraceData
+        val n = ++contIndex
+        if (DEBUG) Trace.traceCounter(Trace.TRACE_TAG_APP, debugCounterTrack!!, n)
+        if (n < 0 || MAX_THREAD_LOCAL_STACK_SIZE <= n) return // fail-safe
+        var size = openSliceCount.size
+        if (n >= size) {
+            size = max(2 * size, MAX_THREAD_LOCAL_STACK_SIZE)
+            openSliceCount = openSliceCount.copyInto(ByteArray(size))
+            continuationIds = continuationIds?.copyInto(IntArray(size))
+        }
+        openSliceCount[n] = data?.beginAllOnThread() ?: 0
+        if (0 < contId) continuationIds?.set(n, contId)
+    }
+
+    /** Update [data] for suspension */
+    fun restoreDataForSuspension(oldState: TraceData?): Int {
+        data = oldState
+        val n = contIndex--
+        if (DEBUG) Trace.traceCounter(Trace.TRACE_TAG_APP, debugCounterTrack!!, n)
+        if (n < 0 || openSliceCount.size <= n) return 0 // fail-safe
+        if (Trace.isTagEnabled(Trace.TRACE_TAG_APP)) {
+            val lastState = openSliceCount[n]
+            var i = 0
+            while (i < lastState) {
+                endSlice()
+                i++
+            }
+        }
+        return continuationIds?.let { if (n < it.size) it[n] else null } ?: 0
     }
 }
 
@@ -38,40 +156,35 @@ private class TraceCountThreadLocal : ThreadLocal<Int>() {
  * Used for storing trace sections so that they can be added and removed from the currently running
  * thread when the coroutine is suspended and resumed.
  *
+ * @property currentId ID of associated TraceContextElement
  * @property strictMode Whether to add additional checks to the coroutine machinery, throwing a
  *   `ConcurrentModificationException` if TraceData is modified from the wrong thread. This should
  *   only be set for testing.
  * @see traceCoroutine
  */
 @PublishedApi
-internal class TraceData(private val strictMode: Boolean) {
+internal class TraceData(internal val currentId: Int, private val strictMode: Boolean) {
 
-    internal var slices: ArrayDeque<TraceSection>? = null
+    internal lateinit var slices: ArrayDeque<TraceSection>
 
     /**
-     * ThreadLocal counter for how many open trace sections there are. This is needed because it is
-     * possible that on a multi-threaded dispatcher, one of the threads could be slow, and
-     * `restoreThreadContext` might be invoked _after_ the coroutine has already resumed and
-     * modified TraceData - either adding or removing trace sections and changing the count. If we
-     * did not store this thread-locally, then we would incorrectly end too many or too few trace
-     * sections.
+     * Adds current trace slices back to the current thread. Called when coroutine is resumed.
+     *
+     * @return number of new trace sections started
      */
-    private val openSliceCount = TraceCountThreadLocal()
-
-    /** Adds current trace slices back to the current thread. Called when coroutine is resumed. */
-    internal fun beginAllOnThread() {
-        strictModeCheck()
-        slices?.descendingIterator()?.forEach { beginSlice(it) }
-        openSliceCount.set(slices?.size ?: 0)
-    }
-
-    /**
-     * Removes all current trace slices from the current thread. Called when coroutine is suspended.
-     */
-    internal fun endAllOnThread() {
-        strictModeCheck()
-        repeat(openSliceCount.get() ?: 0) { endSlice() }
-        openSliceCount.set(0)
+    internal fun beginAllOnThread(): Byte {
+        if (Trace.isTagEnabled(Trace.TRACE_TAG_APP)) {
+            strictModeCheck()
+            if (::slices.isInitialized) {
+                var count: Byte = 0
+                slices.descendingIterator().forEach { sectionName ->
+                    beginSlice(sectionName)
+                    count++
+                }
+                return count
+            }
+        }
+        return 0
     }
 
     /**
@@ -80,14 +193,12 @@ internal class TraceData(private val strictMode: Boolean) {
      * coroutines, or to child coroutines that have already started. The unique ID is used to verify
      * that the [endSpan] is corresponds to a [beginSpan].
      */
-    @PublishedApi
     internal fun beginSpan(name: String) {
         strictModeCheck()
-        if (slices == null) {
-            slices = ArrayDeque()
+        if (!::slices.isInitialized) {
+            slices = ArrayDeque<TraceSection>(4)
         }
-        slices!!.push(name)
-        openSliceCount.set(slices!!.size)
+        slices.push(name)
         beginSlice(name)
     }
 
@@ -95,31 +206,47 @@ internal class TraceData(private val strictMode: Boolean) {
      * Ends the trace section and validates it corresponds with an earlier call to [beginSpan]. The
      * trace slice will immediately be removed from the current thread. This information will not
      * propagate to parent coroutines, or to child coroutines that have already started.
+     *
+     * @return `true` if [endSlice] was called, `false` otherwise
      */
-    @PublishedApi
-    internal fun endSpan() {
+    internal fun endSpan(): Boolean {
         strictModeCheck()
         // Should never happen, but we should be defensive rather than crash the whole application
-        if (slices != null && slices!!.size > 0) {
-            slices!!.pop()
-            openSliceCount.set(slices!!.size)
+        if (::slices.isInitialized && !slices.isEmpty()) {
+            slices.pop()
             endSlice()
+            return true
         } else if (strictMode) {
             throw IllegalStateException(INVALID_SPAN_END_CALL_ERROR_MESSAGE)
         }
+        return false
     }
 
     public override fun toString(): String =
-        if (DEBUG) "{${slices?.joinToString(separator = "\", \"", prefix = "\"", postfix = "\"")}}"
-        else super.toString()
+        if (DEBUG) {
+            if (::slices.isInitialized) {
+                "{${slices.joinToString(separator = "\", \"", prefix = "\"", postfix = "\"")}}"
+            } else {
+                "{<uninitialized>}"
+            } + "@${hashCode()}"
+        } else super.toString()
 
     private fun strictModeCheck() {
-        if (strictMode && traceThreadLocal.get() !== this) {
+        if (strictMode && traceThreadLocal.get()?.data !== this) {
             throw ConcurrentModificationException(STRICT_MODE_ERROR_MESSAGE)
         }
     }
 }
 
+private const val INITIAL_THREAD_LOCAL_STACK_SIZE = 4
+
+/**
+ * The maximum allowed stack size for coroutine re-entry. Anything above this will cause malformed
+ * traces. It should be set to a high number that should never happen, meaning if it were to occur,
+ * there is likely an underlying bug.
+ */
+private const val MAX_THREAD_LOCAL_STACK_SIZE = 512
+
 private const val INVALID_SPAN_END_CALL_ERROR_MESSAGE =
     "TraceData#endSpan called when there were no active trace sections in its scope."
 
diff --git a/tracinglib/core/src/coroutines/TrackTracer.kt b/tracinglib/core/src/coroutines/TrackTracer.kt
new file mode 100644
index 0000000..48f90ae
--- /dev/null
+++ b/tracinglib/core/src/coroutines/TrackTracer.kt
@@ -0,0 +1,130 @@
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
+package com.android.app.tracing.coroutines
+
+import android.os.Trace
+import com.android.app.tracing.TraceUtils
+import com.android.app.tracing.TrackGroupUtils.trackGroup
+import java.io.Closeable
+import java.util.concurrent.ThreadLocalRandom
+import kotlin.contracts.ExperimentalContracts
+import kotlin.contracts.InvocationKind
+import kotlin.contracts.contract
+
+/**
+ * Wrapper to trace to a single perfetto track elegantly, without duplicating trace tag and track
+ * name all the times.
+ *
+ * The intended use is the following:
+ * ```kotlin
+ * class SomeClass {
+ *    privat val t = TrackTracer("SomeTrackName")
+ *
+ *    ...
+ *    t.instant { "some instant" }
+ *    t.traceAsync("Some slice name") { ... }
+ * }
+ * ```
+ */
+@OptIn(ExperimentalContracts::class)
+public class TrackTracer(
+    trackName: String,
+    public val traceTag: Long = Trace.TRACE_TAG_APP,
+    public val trackGroup: String? = null,
+) {
+    public val trackName: String =
+        if (trackGroup != null) trackGroup(trackGroup, trackName) else trackName
+
+    /** See [Trace.instantForTrack]. */
+    public inline fun instant(s: () -> String) {
+        if (!Trace.isEnabled()) return
+        Trace.instantForTrack(traceTag, trackName, s())
+    }
+
+    /** See [Trace.asyncTraceForTrackBegin]. */
+    public inline fun <T> traceAsync(sliceName: () -> String, block: () -> T): T {
+        contract {
+            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+            callsInPlace(sliceName, InvocationKind.AT_MOST_ONCE)
+        }
+        return TraceUtils.traceAsync(traceTag, trackName, sliceName, block)
+    }
+
+    /** See [Trace.asyncTraceForTrackBegin]. */
+    public inline fun <T> traceAsync(sliceName: String, block: () -> T): T {
+        contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+        return TraceUtils.traceAsync(traceTag, trackName, sliceName, block)
+    }
+
+    /** See [Trace.asyncTraceForTrackBegin]. */
+    public fun traceAsyncBegin(sliceName: String): Closeable {
+        val cookie = ThreadLocalRandom.current().nextInt()
+        Trace.asyncTraceForTrackBegin(traceTag, trackName, sliceName, cookie)
+        return Closeable { Trace.asyncTraceForTrackEnd(traceTag, trackName, cookie) }
+    }
+
+    /** Traces [block] both sync and async. */
+    public fun traceSyncAndAsync(sliceName: () -> String, block: () -> Unit) {
+        contract {
+            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
+            callsInPlace(sliceName, InvocationKind.AT_MOST_ONCE)
+        }
+        if (Trace.isEnabled()) {
+            val name = sliceName()
+            TraceUtils.trace(name) { traceAsync(name, block) }
+        } else {
+            block()
+        }
+    }
+
+    public companion object {
+        /**
+         * Creates an instant event for a track called [trackName] inside [groupName]. See
+         * [trackGroup] for details on how the rendering in groups works.
+         */
+        @JvmStatic
+        public fun instantForGroup(groupName: String, trackName: String, i: Int) {
+            Trace.traceCounter(Trace.TRACE_TAG_APP, trackGroup(groupName, trackName), i)
+        }
+
+        /**
+         * Creates an instant event for a track called [trackName] inside [groupName]. See
+         * [trackGroup] for details on how the rendering in groups works.
+         */
+        @JvmStatic
+        public fun instantForGroup(groupName: String, trackName: String, event: () -> String) {
+            if (!Trace.isEnabled()) return
+            Trace.instantForTrack(Trace.TRACE_TAG_APP, trackGroup(groupName, trackName), event())
+        }
+
+        /** Creates an instant event for [groupName] grgorp, see [instantForGroup]. */
+        @JvmStatic
+        public inline fun instantForGroup(groupName: String, trackName: () -> String, i: Int) {
+            if (!Trace.isEnabled()) return
+            instantForGroup(groupName, trackName(), i)
+        }
+
+        /**
+         * Creates an instant event, see [instantForGroup], converting [i] to an int by multiplying
+         * it by 100.
+         */
+        @JvmStatic
+        public fun instantForGroup(groupName: String, trackName: String, i: Float) {
+            instantForGroup(groupName, trackName, (i * 100).toInt())
+        }
+    }
+}
diff --git a/tracinglib/core/src/coroutines/flow/FlowExt.kt b/tracinglib/core/src/coroutines/flow/FlowExt.kt
index 0a41e37..19819fa 100644
--- a/tracinglib/core/src/coroutines/flow/FlowExt.kt
+++ b/tracinglib/core/src/coroutines/flow/FlowExt.kt
@@ -16,25 +16,40 @@
 
 package com.android.app.tracing.coroutines.flow
 
-import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.CoroutineTraceName
 import com.android.app.tracing.coroutines.traceCoroutine
-import com.android.systemui.Flags
+import com.android.app.tracing.coroutines.traceName
+import com.android.app.tracing.traceBlocking
 import kotlin.experimental.ExperimentalTypeInference
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.FlowCollector
+import kotlinx.coroutines.flow.MutableSharedFlow
+import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharedFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asSharedFlow
+import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.collect
 import kotlinx.coroutines.flow.collectLatest
 import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.flow as safeFlow
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.mapLatest
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.flow.stateIn
 import kotlinx.coroutines.flow.transform
 
 /** @see kotlinx.coroutines.flow.internal.unsafeFlow */
+@OptIn(ExperimentalTypeInference::class)
 @PublishedApi
 internal inline fun <T> unsafeFlow(
-    crossinline block: suspend FlowCollector<T>.() -> Unit
+    @BuilderInference crossinline block: suspend FlowCollector<T>.() -> Unit
 ): Flow<T> {
     return object : Flow<T> {
         override suspend fun collect(collector: FlowCollector<T>) {
@@ -49,43 +64,154 @@ internal inline fun <T, R> Flow<T>.unsafeTransform(
     crossinline transform: suspend FlowCollector<R>.(value: T) -> Unit
 ): Flow<R> = unsafeFlow { collect { value -> transform(value) } }
 
+@OptIn(ExperimentalForInheritanceCoroutinesApi::class)
+private open class TracedSharedFlow<out T>(
+    private val name: String,
+    private val flow: SharedFlow<T>,
+) : SharedFlow<T> {
+    override val replayCache: List<T>
+        get() = traceBlocking("replayCache:$name") { flow.replayCache }
+
+    override suspend fun collect(collector: FlowCollector<T>): Nothing {
+        traceCoroutine("collect:$name") {
+            flow.collect { traceCoroutine("emit:$name") { collector.emit(it) } }
+        }
+    }
+}
+
+@OptIn(ExperimentalForInheritanceCoroutinesApi::class)
+private open class TracedStateFlow<out T>(
+    private val name: String,
+    private val flow: StateFlow<T>,
+) : StateFlow<T>, TracedSharedFlow<T>(name, flow) {
+    override val value: T
+        get() = traceBlocking("get:$name") { flow.value }
+}
+
+@OptIn(ExperimentalForInheritanceCoroutinesApi::class)
+private open class TracedMutableSharedFlow<T>(
+    private val name: String,
+    private val flow: MutableSharedFlow<T>,
+) : MutableSharedFlow<T>, TracedSharedFlow<T>(name, flow) {
+    override val subscriptionCount: StateFlow<Int>
+        get() = traceBlocking("subscriptionCount:$name") { flow.subscriptionCount }
+
+    @ExperimentalCoroutinesApi
+    override fun resetReplayCache() {
+        traceBlocking("resetReplayCache:$name") { flow.resetReplayCache() }
+    }
+
+    override suspend fun emit(value: T) {
+        traceCoroutine("emit:$name") { flow.emit(value) }
+    }
+
+    override fun tryEmit(value: T): Boolean {
+        return traceBlocking("tryEmit:$name") { flow.tryEmit(value) }
+    }
+}
+
+@OptIn(ExperimentalForInheritanceCoroutinesApi::class)
+private class TracedMutableStateFlow<T>(
+    private val name: String,
+    private val flow: MutableStateFlow<T>,
+) : MutableStateFlow<T>, TracedMutableSharedFlow<T>(name, flow) {
+    override var value: T
+        get() = traceBlocking("get:$name") { flow.value }
+        set(newValue) {
+            traceBlocking("updateState:$name") { flow.value = newValue }
+        }
+
+    override fun compareAndSet(expect: T, update: T): Boolean {
+        return traceBlocking("compareAndSet:$name") { flow.compareAndSet(expect, update) }
+    }
+}
+
 /**
- * Helper for naming the coroutine a flow is collected in. This only has an effect if the flow
- * changes contexts (e.g. `flowOn()` is used to change the dispatcher), meaning a new coroutine is
- * created during collection.
+ * Helper for adding trace sections for when a trace is collected.
  *
- * For example, the following would `emit(1)` from a trace section named "a" and collect in section
- * named "b".
+ * For example, the following would `emit(1)` from a trace section named "my-flow" and collect in a
+ * coroutine scope named "my-launch".
  *
  * ```
- *   launch(nameCoroutine("b") {
- *     val flow {
- *       emit(1)
- *     }
- *     .flowName("a")
- *     .flowOn(Dispatchers.Default)
+ *   val flow {
+ *     // The open trace section here would be:
+ *     // "coroutine execution;my-launch", and "collect:my-flow"
+ *     emit(1)
+ *   }
+ *   launchTraced("my-launch") {
+ *     .flowName("my-flow")
  *     .collect {
+ *       // The open trace sections here would be:
+ *       // "coroutine execution;my-launch", "collect:my-flow", and "emit:my-flow"
  *     }
  *   }
  * ```
- */
-public fun <T> Flow<T>.flowName(name: String): Flow<T> = flowOn(nameCoroutine(name))
-
-/**
- * Applying [flowName][Flow.flowName] to [SharedFlow] has no effect. See the [SharedFlow]
- * documentation on Operator Fusion.
  *
- * @see SharedFlow.flowOn
+ * TODO(b/334171711): Rename via @Deprecated("Renamed to .traceAs()", ReplaceWith("traceAs(name)"))
  */
-@Deprecated(
-    level = DeprecationLevel.ERROR,
-    message =
-        "Applying 'flowName' to SharedFlow has no effect. See the SharedFlow documentation on Operator Fusion.",
-    replaceWith = ReplaceWith("this"),
-)
-@Suppress("UnusedReceiverParameter")
-public fun <T> SharedFlow<T>.flowName(@Suppress("UNUSED_PARAMETER") name: String): Flow<T> =
-    throw UnsupportedOperationException("Not implemented, should not be called")
+public fun <T> Flow<T>.flowName(name: String): Flow<T> = traceAs(name)
+
+public fun <T> Flow<T>.traceAs(name: String): Flow<T> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        return when (this) {
+            is SharedFlow -> traceAs(name)
+            else ->
+                unsafeFlow {
+                    traceCoroutine("collect:$name") {
+                        collect { value -> traceCoroutine("emit:$name") { emit(value) } }
+                    }
+                }
+        }
+    } else {
+        this
+    }
+}
+
+public fun <T> SharedFlow<T>.traceAs(name: String): SharedFlow<T> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        when (this) {
+            is MutableSharedFlow -> traceAs(name)
+            is StateFlow -> traceAs(name)
+            else -> TracedSharedFlow(name, this)
+        }
+    } else {
+        this
+    }
+}
+
+public fun <T> StateFlow<T>.traceAs(name: String): StateFlow<T> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        when (this) {
+            is MutableStateFlow -> traceAs(name)
+            else -> TracedStateFlow(name, this)
+        }
+    } else {
+        this
+    }
+}
+
+public fun <T> MutableSharedFlow<T>.traceAs(name: String): MutableSharedFlow<T> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        when (this) {
+            is MutableStateFlow -> traceAs(name)
+            else -> TracedMutableSharedFlow(name, this)
+        }
+    } else {
+        this
+    }
+}
+
+public fun <T> MutableStateFlow<T>.traceAs(name: String): MutableStateFlow<T> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        TracedMutableStateFlow(name, this)
+    } else {
+        this
+    }
+}
+
+public fun <T> Flow<T>.onEachTraced(name: String, action: suspend (T) -> Unit): Flow<T> {
+    return onEach { value -> traceCoroutine(name) { action(value) } }
+}
 
 /**
  * NOTE: [Flow.collect] is a member function and takes precedence if this function is imported as
@@ -100,47 +226,76 @@ public fun <T> SharedFlow<T>.flowName(@Suppress("UNUSED_PARAMETER") name: String
  * flowOf(1).collect { ... } // this will call `Flow.collect`
  * flowOf(1).collect(null) { ... } // this will call `collectTraced`
  * ```
+ *
+ * @see kotlinx.coroutines.flow.collect
  */
 public suspend fun <T> Flow<T>.collectTraced(name: String, collector: FlowCollector<T>) {
-    if (Flags.coroutineTracing()) {
-        val collectName = "collect:$name"
-        val emitName = "$collectName:emit"
-        traceCoroutine(collectName) { collect { traceCoroutine(emitName) { collector.emit(it) } } }
+    if (com.android.systemui.Flags.coroutineTracing()) {
+        traceAs(name).collect(collector)
     } else {
         collect(collector)
     }
 }
 
-/** @see Flow.collectTraced */
+/** @see kotlinx.coroutines.flow.collect */
+public suspend fun <T> Flow<T>.collectTraced(name: String) {
+    if (com.android.systemui.Flags.coroutineTracing()) {
+        traceAs(name).collect()
+    } else {
+        collect()
+    }
+}
+
+/** @see kotlinx.coroutines.flow.collect */
 public suspend fun <T> Flow<T>.collectTraced(collector: FlowCollector<T>) {
-    if (Flags.coroutineTracing()) {
-        collectTraced(
-            name = collector::class.java.name.substringAfterLast("."),
-            collector = collector,
-        )
+    if (com.android.systemui.Flags.coroutineTracing()) {
+        collectTraced(name = collector.traceName, collector = collector)
     } else {
         collect(collector)
     }
 }
 
+@OptIn(ExperimentalTypeInference::class)
+@ExperimentalCoroutinesApi
+public fun <T, R> Flow<T>.mapLatestTraced(
+    name: String,
+    @BuilderInference transform: suspend (value: T) -> R,
+): Flow<R> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        traceAs("mapLatest:$name").mapLatest { traceCoroutine(name) { transform(it) } }
+    } else {
+        mapLatest(transform)
+    }
+}
+
+@OptIn(ExperimentalTypeInference::class)
+@ExperimentalCoroutinesApi
+public fun <T, R> Flow<T>.mapLatestTraced(
+    @BuilderInference transform: suspend (value: T) -> R
+): Flow<R> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        mapLatestTraced(transform.traceName, transform)
+    } else {
+        mapLatestTraced(transform)
+    }
+}
+
+/** @see kotlinx.coroutines.flow.collectLatest */
 internal suspend fun <T> Flow<T>.collectLatestTraced(
     name: String,
     action: suspend (value: T) -> Unit,
 ) {
-    if (Flags.coroutineTracing()) {
-        val collectName = "collectLatest:$name"
-        val actionName = "$collectName:action"
-        return traceCoroutine(collectName) {
-            collectLatest { traceCoroutine(actionName) { action(it) } }
-        }
+    if (com.android.systemui.Flags.coroutineTracing()) {
+        return traceAs("collectLatest:$name").collectLatest { traceCoroutine(name) { action(it) } }
     } else {
         collectLatest(action)
     }
 }
 
+/** @see kotlinx.coroutines.flow.collectLatest */
 public suspend fun <T> Flow<T>.collectLatestTraced(action: suspend (value: T) -> Unit) {
-    if (Flags.coroutineTracing()) {
-        collectLatestTraced(action::class.java.name.substringAfterLast("."), action)
+    if (com.android.systemui.Flags.coroutineTracing()) {
+        collectLatestTraced(action.traceName, action)
     } else {
         collectLatest(action)
     }
@@ -151,47 +306,92 @@ public suspend fun <T> Flow<T>.collectLatestTraced(action: suspend (value: T) ->
 public inline fun <T, R> Flow<T>.transformTraced(
     name: String,
     @BuilderInference crossinline transform: suspend FlowCollector<R>.(value: T) -> Unit,
-): Flow<R> =
-    if (Flags.coroutineTracing()) {
-        val emitName = "$name:emit"
-        safeFlow { collect { value -> traceCoroutine(emitName) { transform(value) } } }
+): Flow<R> {
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        // Safe flow must be used because collector is exposed to the caller
+        safeFlow {
+            collect { value ->
+                traceCoroutine(name) {
+                    return@collect transform(value)
+                }
+            }
+        }
     } else {
         transform(transform)
     }
+}
 
+/** @see kotlinx.coroutines.flow.filter */
 public inline fun <T> Flow<T>.filterTraced(
     name: String,
     crossinline predicate: suspend (T) -> Boolean,
 ): Flow<T> {
-    if (Flags.coroutineTracing()) {
-        val predicateName = "filter:$name:predicate"
-        val emitName = "filter:$name:emit"
-        return unsafeTransform { value ->
-            if (traceCoroutine(predicateName) { predicate(value) }) {
-                traceCoroutine(emitName) {
-                    return@unsafeTransform emit(value)
-                }
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        unsafeTransform { value ->
+            if (traceCoroutine(name) { predicate(value) }) {
+                emit(value)
             }
         }
     } else {
-        return filter(predicate)
+        filter(predicate)
     }
 }
 
+/** @see kotlinx.coroutines.flow.map */
 public inline fun <T, R> Flow<T>.mapTraced(
     name: String,
     crossinline transform: suspend (value: T) -> R,
 ): Flow<R> {
-    if (Flags.coroutineTracing()) {
-        val transformName = "map:$name:transform"
-        val emitName = "map:$name:emit"
-        return unsafeTransform { value ->
-            val transformedValue = traceCoroutine(transformName) { transform(value) }
-            traceCoroutine(emitName) {
-                return@unsafeTransform emit(transformedValue)
-            }
+    return if (com.android.systemui.Flags.coroutineTracing()) {
+        unsafeTransform { value ->
+            val transformedValue = traceCoroutine(name) { transform(value) }
+            emit(transformedValue)
         }
     } else {
-        return map(transform)
+        map(transform)
     }
 }
+
+/** @see kotlinx.coroutines.flow.shareIn */
+public fun <T> Flow<T>.shareInTraced(
+    name: String,
+    scope: CoroutineScope,
+    started: SharingStarted,
+    replay: Int = 0,
+): SharedFlow<T> {
+    // .shareIn calls this.launch(context), where this === scope, and the previous upstream flow's
+    // context is passed to launch (caveat: the upstream context is only passed to the downstream
+    // SharedFlow if certain conditions are met). For instead, if the upstream is a SharedFlow,
+    // the `.flowOn()` operator will have no effect.
+    return maybeFuseTraceName(name).shareIn(scope, started, replay).traceAs(name)
+}
+
+/** @see kotlinx.coroutines.flow.stateIn */
+public fun <T> Flow<T>.stateInTraced(
+    name: String,
+    scope: CoroutineScope,
+    started: SharingStarted,
+    initialValue: T,
+): StateFlow<T> {
+    // .stateIn calls this.launch(context), where this === scope, and the previous upstream flow's
+    // context is passed to launch
+    return maybeFuseTraceName(name).stateIn(scope, started, initialValue).traceAs(name)
+}
+
+/** @see kotlinx.coroutines.flow.stateIn */
+public suspend fun <T> Flow<T>.stateInTraced(name: String, scope: CoroutineScope): StateFlow<T> {
+    // .stateIn calls this.launch(context), where this === scope, and the previous upstream flow's
+    // context is passed to launch
+    return maybeFuseTraceName(name).stateIn(scope).traceAs(name)
+}
+
+public fun <T> MutableSharedFlow<T>.asSharedFlowTraced(name: String): SharedFlow<T> {
+    return asSharedFlow().traceAs(name)
+}
+
+public fun <T> MutableStateFlow<T>.asStateFlowTraced(name: String): StateFlow<T> {
+    return asStateFlow().traceAs(name)
+}
+
+private fun <T> Flow<T>.maybeFuseTraceName(name: String): Flow<T> =
+    if (com.android.systemui.Flags.coroutineTracing()) flowOn(CoroutineTraceName(name)) else this
diff --git a/tracinglib/demo/Android.bp b/tracinglib/demo/Android.bp
index c8c83cd..1f28c6b 100644
--- a/tracinglib/demo/Android.bp
+++ b/tracinglib/demo/Android.bp
@@ -18,18 +18,27 @@ package {
 
 android_app {
     name: "CoroutineTracingDemoApp",
+
     platform_apis: true,
+    system_ext_specific: true,
     certificate: "platform",
-    min_sdk_version: "34",
-    target_sdk_version: "34",
-    use_resource_processor: true,
+
     srcs: ["src/**/*.kt"],
-    manifest: "app-manifest.xml",
-    resource_dirs: ["res"],
+    use_resource_processor: true,
+
     static_libs: [
         "tracinglib-platform",
         "dagger2",
         "jsr330",
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.animation_animation",
+        "androidx.compose.material_material",
+        "androidx.compose.material3_material3",
+        "androidx.compose.material_material-icons-extended",
+        "androidx.activity_activity-compose",
+        "androidx.navigation_navigation-compose",
+        "androidx.appcompat_appcompat",
     ],
+
     plugins: ["dagger2-compiler"],
 }
diff --git a/tracinglib/demo/app-manifest.xml b/tracinglib/demo/AndroidManifest.xml
similarity index 64%
rename from tracinglib/demo/app-manifest.xml
rename to tracinglib/demo/AndroidManifest.xml
index 6db5580..a487da6 100644
--- a/tracinglib/demo/app-manifest.xml
+++ b/tracinglib/demo/AndroidManifest.xml
@@ -13,18 +13,22 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-        package="com.example.tracing.demo">
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.example.tracing.demo">
     <application
-        android:name=".MainApplication"
-        android:label="@string/app_name">
+        android:label="@string/app_name"
+        android:appComponentFactory="com.example.tracing.demo.MainAppComponentFactory"
+        tools:replace="android:appComponentFactory">
         <activity
-            android:name=".MainActivity"
-            android:theme="@style/ActivityTheme"
+            android:name="com.example.tracing.demo.MainActivity"
+            android:theme="@style/Theme.ActivityTheme"
+            android:launchMode="singleInstance"
             android:exported="true">
             <intent-filter>
-                <action android:name="android.intent.action.MAIN" />
-                <category android:name="android.intent.category.LAUNCHER" />
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
             </intent-filter>
         </activity>
     </application>
diff --git a/tracinglib/demo/res/layout/activity_main.xml b/tracinglib/demo/res/layout/activity_main.xml
deleted file mode 100644
index 432d958..0000000
--- a/tracinglib/demo/res/layout/activity_main.xml
+++ /dev/null
@@ -1,48 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
-     Copyright (C) 2024 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:tools="http://schemas.android.com/tools"
-    android:layout_width="match_parent"
-    android:layout_height="match_parent"
-    android:orientation="vertical"
-    android:layout_marginTop="40dp"
-    tools:context=".MainActivity">
-
-    <TextView
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:text="@string/app_name"
-        android:layout_gravity="center"
-        android:textAppearance="@style/Title"/>
-
-    <LinearLayout
-        android:id="@+id/experiment_list"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:orientation="vertical" />
-
-    <ScrollView
-        android:id="@+id/log_container"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content">
-
-        <TextView
-            android:id="@+id/logger_view"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:fontFamily="monospace" />
-    </ScrollView>
-</LinearLayout>
\ No newline at end of file
diff --git a/tracinglib/demo/res/layout/experiment_buttons.xml b/tracinglib/demo/res/layout/experiment_buttons.xml
deleted file mode 100644
index 26da571..0000000
--- a/tracinglib/demo/res/layout/experiment_buttons.xml
+++ /dev/null
@@ -1,48 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
-     Copyright (C) 2024 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:tools="http://schemas.android.com/tools"
-    android:layout_width="match_parent"
-    android:layout_height="wrap_content"
-    android:orientation="vertical">
-
-    <TextView android:id="@+id/description"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content" />
-
-    <LinearLayout
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:orientation="horizontal">
-
-        <Button
-            android:id="@+id/start_button"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:text="Start" />
-
-        <Button
-            android:id="@+id/cancel_button"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content"
-            android:text="Stop" />
-
-        <TextView android:id="@+id/current_state"
-            android:layout_width="wrap_content"
-            android:layout_height="wrap_content" />
-
-    </LinearLayout>
-</LinearLayout>
\ No newline at end of file
diff --git a/tracinglib/demo/res/values/strings.xml b/tracinglib/demo/res/values/strings.xml
index 157c6a9..84dabfa 100644
--- a/tracinglib/demo/res/values/strings.xml
+++ b/tracinglib/demo/res/values/strings.xml
@@ -1,5 +1,4 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
+<?xml version="1.0" encoding="utf-8"?><!--
      Copyright (C) 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
@@ -16,5 +15,7 @@
 -->
 <resources>
     <string name="app_name">CoroutineTracingDemoApp</string>
-    <string name="run_experiment_button_text">%1$s\n%2$s</string>
+    <string name="run_experiment">Run experiment</string>
+    <string name="show_more">Show more</string>
+    <string name="show_less">Show less</string>
 </resources>
diff --git a/tracinglib/demo/res/values/styles.xml b/tracinglib/demo/res/values/styles.xml
index 49d50e0..6755001 100644
--- a/tracinglib/demo/res/values/styles.xml
+++ b/tracinglib/demo/res/values/styles.xml
@@ -15,10 +15,5 @@
   ~ limitations under the License.
   -->
 <resources>
-    <style name="ActivityTheme" parent="@android:style/Theme.DeviceDefault.NoActionBar">
-        <item name="android:windowLayoutInDisplayCutoutMode">
-            never
-        </item>
-    </style>
-    <style name="Title" parent="@android:style/TextAppearance.Material.Title" />
+    <style name="Theme.ActivityTheme" parent="android:Theme.Material.Light.NoActionBar" />
 </resources>
\ No newline at end of file
diff --git a/tracinglib/demo/src/ApplicationComponent.kt b/tracinglib/demo/src/ApplicationComponent.kt
index 5a47064..f0fff66 100644
--- a/tracinglib/demo/src/ApplicationComponent.kt
+++ b/tracinglib/demo/src/ApplicationComponent.kt
@@ -15,139 +15,155 @@
  */
 package com.example.tracing.demo
 
+import android.app.Activity
+import android.content.Intent
+import android.os.Handler
+import android.os.HandlerThread
+import android.os.Process
+import android.os.Trace
+import androidx.core.app.AppComponentFactory
+import com.example.tracing.demo.experiments.BasicTracingTutorial
 import com.example.tracing.demo.experiments.CancellableSharedFlow
 import com.example.tracing.demo.experiments.CollectFlow
 import com.example.tracing.demo.experiments.CombineDeferred
 import com.example.tracing.demo.experiments.Experiment
+import com.example.tracing.demo.experiments.FlowTracingTutorial
 import com.example.tracing.demo.experiments.LaunchNested
 import com.example.tracing.demo.experiments.LaunchSequentially
+import com.example.tracing.demo.experiments.LaunchStressTest
 import com.example.tracing.demo.experiments.LeakySharedFlow
 import com.example.tracing.demo.experiments.SharedFlowUsage
-import com.example.tracing.demo.experiments.startThreadWithLooper
-import dagger.Binds
 import dagger.Component
 import dagger.Module
 import dagger.Provides
-import dagger.multibindings.ClassKey
-import dagger.multibindings.IntoMap
-import javax.inject.Provider
 import javax.inject.Qualifier
 import javax.inject.Singleton
 import kotlin.annotation.AnnotationRetention.RUNTIME
 import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.android.asCoroutineDispatcher
+import kotlinx.coroutines.newFixedThreadPoolContext
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Main
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread0
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Default
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread1
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class IO
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread2
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Unconfined
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread3
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadA
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread4
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadB
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedPool
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadC
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadD
+// Initialize threads in the top-level to force their creation in a specific order:
+internal val delayHandler = startThreadWithLooper("delay-thread")
+private val thread0 = startThreadWithLooper("Thread:0")
+private val thread1 = startThreadWithLooper("Thread:1")
+private val thread2 = startThreadWithLooper("Thread:2")
+private val thread3 = startThreadWithLooper("Thread:3")
+private val thread4 = startThreadWithLooper("Thread:4")
+@OptIn(DelicateCoroutinesApi::class)
+private val fixedThreadPool = newFixedThreadPoolContext(4, "ThreadPool")
 
 @Module
 class ConcurrencyModule {
-
-    @Provides
-    @Singleton
-    @Default
-    fun provideDefaultDispatcher(): CoroutineDispatcher {
-        return Dispatchers.Default
-    }
-
     @Provides
     @Singleton
-    @IO
-    fun provideIODispatcher(): CoroutineDispatcher {
-        return Dispatchers.IO
-    }
+    @FixedThread0
+    fun provideDispatcher0(): CoroutineDispatcher = thread0.asCoroutineDispatcher()
 
     @Provides
     @Singleton
-    @Unconfined
-    fun provideUnconfinedDispatcher(): CoroutineDispatcher {
-        return Dispatchers.Unconfined
-    }
+    @FixedThread1
+    fun provideDispatcher1(): CoroutineDispatcher = thread1.asCoroutineDispatcher()
 
     @Provides
     @Singleton
-    @FixedThreadA
-    fun provideDispatcherA(): CoroutineDispatcher {
-        return startThreadWithLooper("Thread:A").threadHandler.asCoroutineDispatcher()
-    }
+    @FixedThread2
+    fun provideDispatcher2(): CoroutineDispatcher = thread2.asCoroutineDispatcher()
 
     @Provides
     @Singleton
-    @FixedThreadB
-    fun provideDispatcherB(): CoroutineDispatcher {
-        return startThreadWithLooper("Thread:B").threadHandler.asCoroutineDispatcher()
-    }
+    @FixedThread3
+    fun provideDispatcher3(): CoroutineDispatcher = thread3.asCoroutineDispatcher()
 
     @Provides
     @Singleton
-    @FixedThreadC
-    fun provideDispatcherC(): CoroutineDispatcher {
-        return startThreadWithLooper("Thread:C").threadHandler.asCoroutineDispatcher()
-    }
+    @FixedThread4
+    fun provideDispatcher4(): CoroutineDispatcher = thread4.asCoroutineDispatcher()
 
     @Provides
     @Singleton
-    @FixedThreadD
-    fun provideDispatcherD(): CoroutineDispatcher {
-        return startThreadWithLooper("Thread:D").threadHandler.asCoroutineDispatcher()
-    }
+    @FixedPool
+    fun provideFixedThreadPoolDispatcher(): CoroutineDispatcher = fixedThreadPool
 }
 
 @Module
-interface ExperimentModule {
-    @Binds
-    @IntoMap
-    @ClassKey(CollectFlow::class)
-    fun bindCollectFlow(service: CollectFlow): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(SharedFlowUsage::class)
-    fun bindSharedFlowUsage(service: SharedFlowUsage): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(LeakySharedFlow::class)
-    fun bindLeakySharedFlow(service: LeakySharedFlow): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(CancellableSharedFlow::class)
-    fun bindCancellableSharedFlow(service: CancellableSharedFlow): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(CombineDeferred::class)
-    fun bindCombineDeferred(service: CombineDeferred): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(LaunchNested::class)
-    fun bindLaunchNested(service: LaunchNested): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(LaunchSequentially::class)
-    fun bindLaunchSequentially(service: LaunchSequentially): Experiment
+class ExperimentModule {
+    @Provides
+    @Singleton
+    fun provideExperimentList(
+        basicTracingTutorial: BasicTracingTutorial,
+        flowTracingTutorial: FlowTracingTutorial,
+        launchSequentially: LaunchSequentially,
+        launchNested: LaunchNested,
+        launchStressTest: LaunchStressTest,
+        combineDeferred: CombineDeferred,
+        sharedFlowUsage: SharedFlowUsage,
+        cancellableSharedFlow: CancellableSharedFlow,
+        collectFlow: CollectFlow,
+        leakySharedFlow: LeakySharedFlow,
+    ): List<Experiment> =
+        listOf(
+            basicTracingTutorial,
+            flowTracingTutorial,
+            launchSequentially,
+            launchNested,
+            launchStressTest,
+            combineDeferred,
+            sharedFlowUsage,
+            cancellableSharedFlow,
+            collectFlow,
+            leakySharedFlow,
+        )
 }
 
 @Singleton
 @Component(modules = [ConcurrencyModule::class, ExperimentModule::class])
 interface ApplicationComponent {
     /** Returns [Experiment]s that should be used with the application. */
-    @Singleton fun getAllExperiments(): Map<Class<*>, Provider<Experiment>>
+    @Singleton fun getExperimentList(): List<Experiment>
+
+    @Singleton @FixedThread0 fun getExperimentDefaultCoroutineDispatcher(): CoroutineDispatcher
+}
+
+class MainAppComponentFactory : AppComponentFactory() {
+
+    init {
+        Trace.registerWithPerfetto()
+    }
+
+    private val appComponent: ApplicationComponent = DaggerApplicationComponent.create()
+
+    override fun instantiateActivityCompat(
+        cl: ClassLoader,
+        className: String,
+        intent: Intent?,
+    ): Activity {
+        val activityClass = cl.loadClass(className)
+        return if (activityClass == MainActivity::class.java) {
+            MainActivity(appComponent)
+        } else {
+            super.instantiateActivityCompat(cl, className, intent)
+        }
+    }
+}
+
+private fun startThreadWithLooper(name: String): Handler {
+    val thread = HandlerThread(name, Process.THREAD_PRIORITY_FOREGROUND)
+    thread.start()
+    val looper = thread.looper
+    looper.setTraceTag(Trace.TRACE_TAG_APP)
+    return Handler.createAsync(looper)
 }
diff --git a/tracinglib/demo/src/MainActivity.kt b/tracinglib/demo/src/MainActivity.kt
index 19c9f72..6522379 100644
--- a/tracinglib/demo/src/MainActivity.kt
+++ b/tracinglib/demo/src/MainActivity.kt
@@ -15,107 +15,200 @@
  */
 package com.example.tracing.demo
 
-import android.app.Activity
 import android.os.Bundle
 import android.os.Trace
-import android.view.LayoutInflater
-import android.view.View
-import android.view.ViewGroup
-import android.widget.Button
-import android.widget.LinearLayout
-import android.widget.ScrollView
-import android.widget.TextView
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import androidx.activity.ComponentActivity
+import androidx.activity.compose.setContent
+import androidx.activity.enableEdgeToEdge
+import androidx.compose.animation.animateContentSize
+import androidx.compose.animation.core.Spring
+import androidx.compose.animation.core.spring
+import androidx.compose.foundation.layout.Column
+import androidx.compose.foundation.layout.Row
+import androidx.compose.foundation.layout.RowScope
+import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.layout.safeDrawingPadding
+import androidx.compose.foundation.lazy.LazyColumn
+import androidx.compose.foundation.lazy.items
+import androidx.compose.material.icons.Icons.Filled
+import androidx.compose.material.icons.filled.ExpandLess
+import androidx.compose.material.icons.filled.ExpandMore
+import androidx.compose.material.icons.filled.PlayCircleOutline
+import androidx.compose.material.icons.filled.StopCircle
+import androidx.compose.material3.Card
+import androidx.compose.material3.CardDefaults
+import androidx.compose.material3.Icon
+import androidx.compose.material3.IconButton
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Surface
+import androidx.compose.material3.Text
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.CompositionLocalProvider
+import androidx.compose.runtime.compositionLocalOf
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateListOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.rememberCoroutineScope
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.res.stringResource
+import androidx.compose.ui.text.font.FontFamily
+import androidx.compose.ui.text.font.FontStyle
+import androidx.compose.ui.unit.dp
+import com.android.app.tracing.coroutines.launchTraced as launch
 import com.example.tracing.demo.experiments.Experiment
 import com.example.tracing.demo.experiments.TRACK_NAME
-import kotlin.coroutines.cancellation.CancellationException
+import com.example.tracing.demo.ui.theme.BasicsCodelabTheme
 import kotlin.random.Random
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.Job
-import kotlinx.coroutines.launch
+import kotlinx.coroutines.CancellationException
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.cancelChildren
+import kotlinx.coroutines.job
 
-class MainActivity : Activity() {
+val AllExperiments = compositionLocalOf<List<Experiment>> { error("No Experiments found!") }
 
-    private val allExperiments by lazy {
-        (applicationContext as MainApplication).appComponent.getAllExperiments()
+val Experiment = compositionLocalOf<Experiment> { error("No found!") }
+
+val ExperimentLaunchDispatcher =
+    compositionLocalOf<CoroutineDispatcher> {
+        error("No @ExperimentLauncher CoroutineDispatcher found!")
     }
 
-    val mainScope: CoroutineScope =
-        CoroutineScope(
-            Dispatchers.Main +
-                createCoroutineTracingContext("test-scope", walkStackForDefaultNames = true)
-        )
+class MainActivity(private val appComponent: ApplicationComponent) : ComponentActivity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        enableEdgeToEdge()
+        setContent {
+            BasicsCodelabTheme {
+                CompositionLocalProvider(
+                    AllExperiments provides appComponent.getExperimentList(),
+                    ExperimentLaunchDispatcher provides
+                        appComponent.getExperimentDefaultCoroutineDispatcher(),
+                ) {
+                    DemoApp(modifier = Modifier.safeDrawingPadding())
+                }
+            }
+        }
+    }
+}
 
-    private var logContainer: ScrollView? = null
-    private var loggerView: TextView? = null
+@Composable
+fun DemoApp(modifier: Modifier = Modifier) {
+    Surface(modifier) { ExperimentList() }
+}
 
-    private fun <T : Experiment> connectButtonsForExperiment(demo: T, view: ViewGroup) {
-        val className = demo::class.simpleName
-        view.findViewById<TextView>(R.id.description).text =
-            baseContext.getString(R.string.run_experiment_button_text, className, demo.description)
-        val currentState = view.findViewById<TextView>(R.id.current_state)
+@Composable
+private fun ExperimentList(modifier: Modifier = Modifier) {
+    val allExperiments = AllExperiments.current
 
-        val launchedJobs = mutableListOf<Job>()
+    LazyColumn(modifier = modifier.padding(vertical = 4.dp)) {
+        items(items = allExperiments.stream().toList()) { experiment ->
+            CompositionLocalProvider(Experiment provides experiment) { ExperimentCard() }
+        }
+    }
+}
 
-        view.findViewById<Button>(R.id.start_button).setOnClickListener {
-            val cookie = Random.nextInt()
-            Trace.asyncTraceForTrackBegin(
-                Trace.TRACE_TAG_APP,
-                TRACK_NAME,
-                "Running: $className",
-                cookie,
-            )
+@Composable
+private fun ExperimentCard(modifier: Modifier = Modifier) {
+    Card(
+        modifier = modifier.padding(vertical = 4.dp, horizontal = 8.dp),
+        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primary),
+    ) {
+        ExperimentContentRow()
+    }
+}
 
-            val job = mainScope.launch { demo.start() }
-            job.invokeOnCompletion { cause ->
-                Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
-                val message =
-                    when (cause) {
-                        null -> "completed normally"
-                        is CancellationException -> "cancelled normally"
-                        else -> "failed"
-                    }
-                mainExecutor.execute {
-                    currentState.text = message
-                    appendLine("$className $message")
-                }
-            }
+@Composable
+private fun ExperimentContentRow(modifier: Modifier = Modifier) {
+    Row(
+        modifier =
+            modifier
+                .padding(12.dp)
+                .animateContentSize(
+                    animationSpec =
+                        spring(
+                            dampingRatio = Spring.DampingRatioNoBouncy,
+                            stiffness = Spring.StiffnessMedium,
+                        )
+                )
+    ) {
+        ExperimentContent()
+    }
+}
 
-            launchedJobs.add(job)
+@Composable
+private fun RowScope.ExperimentContent(modifier: Modifier = Modifier) {
+    val experiment = Experiment.current
+    val launcherDispatcher = ExperimentLaunchDispatcher.current
+    val scope = rememberCoroutineScope { launcherDispatcher + experiment.context }
 
-            currentState.text = "started"
-            appendLine("$className started")
-        }
+    var isRunning by remember { mutableStateOf(false) }
+    var expanded by remember { mutableStateOf(false) }
+    val statusMessages = remember { mutableStateListOf<String>() }
+    val className = experiment.javaClass.simpleName
 
-        view.findViewById<Button>(R.id.cancel_button).setOnClickListener {
-            var activeJobs = 0
-            launchedJobs.forEach {
-                if (it.isActive) activeJobs++
-                it.cancel()
-            }
-            appendLine(if (activeJobs == 0) "Nothing to cancel." else "Cancelled $activeJobs jobs.")
-            launchedJobs.clear()
+    Column(modifier = modifier.weight(1f).padding(12.dp)) {
+        Text(text = experiment.javaClass.simpleName, style = MaterialTheme.typography.headlineSmall)
+        Text(
+            text = experiment.description,
+            style = MaterialTheme.typography.bodyMedium.copy(fontStyle = FontStyle.Italic),
+        )
+        if (expanded) {
+            Text(
+                text = statusMessages.joinToString(separator = "\n") { it },
+                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
+            )
         }
     }
 
-    override fun onCreate(savedInstanceState: Bundle?) {
-        super.onCreate(savedInstanceState)
-        setContentView(R.layout.activity_main)
-        logContainer = requireViewById(R.id.log_container)
-        loggerView = requireViewById(R.id.logger_view)
-        val experimentList = requireViewById<LinearLayout>(R.id.experiment_list)
-        val inflater = LayoutInflater.from(baseContext)
-        allExperiments.forEach {
-            val experimentButtons =
-                inflater.inflate(R.layout.experiment_buttons, experimentList, false) as ViewGroup
-            connectButtonsForExperiment(it.value.get(), experimentButtons)
-            experimentList.addView(experimentButtons)
+    IconButton(
+        onClick = {
+            if (isRunning) {
+                scope.coroutineContext.job.cancelChildren()
+            } else {
+                val cookie = Random.nextInt()
+                Trace.asyncTraceForTrackBegin(
+                    Trace.TRACE_TAG_APP,
+                    TRACK_NAME,
+                    "Running: $className",
+                    cookie,
+                )
+                statusMessages += "Started"
+                expanded = true
+                isRunning = true
+                scope
+                    .launch("$className#runExperiment") { experiment.runExperiment() }
+                    .invokeOnCompletion { cause ->
+                        Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
+                        isRunning = false
+                        statusMessages +=
+                            when (cause) {
+                                null -> "completed normally"
+                                is CancellationException -> "cancelled normally: ${cause.message}"
+                                else -> "failed"
+                            }
+                    }
+            }
         }
+    ) {
+        Icon(
+            imageVector = if (isRunning) Filled.StopCircle else Filled.PlayCircleOutline,
+            contentDescription = stringResource(R.string.run_experiment),
+        )
     }
-
-    private fun appendLine(message: String) {
-        loggerView?.append("$message\n")
-        logContainer?.fullScroll(View.FOCUS_DOWN)
+    IconButton(
+        onClick = {
+            expanded = !expanded
+            if (!expanded) statusMessages.clear()
+        },
+        enabled = !expanded || !isRunning,
+    ) {
+        Icon(
+            imageVector = if (expanded) Filled.ExpandLess else Filled.ExpandMore,
+            contentDescription =
+                if (expanded) stringResource(R.string.show_less)
+                else stringResource(R.string.show_more),
+        )
     }
 }
diff --git a/tracinglib/demo/src/experiments/BasicTracingTutorial.kt b/tracinglib/demo/src/experiments/BasicTracingTutorial.kt
new file mode 100644
index 0000000..dd7fefe
--- /dev/null
+++ b/tracinglib/demo/src/experiments/BasicTracingTutorial.kt
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.TraceUtils.traceAsync
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.launchTraced
+import com.example.tracing.demo.FixedThread1
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlin.contracts.ExperimentalContracts
+import kotlin.contracts.InvocationKind
+import kotlin.contracts.contract
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlin.coroutines.coroutineContext
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.job
+import kotlinx.coroutines.launch
+
+@Singleton
+class BasicTracingTutorial
+@Inject
+constructor(@FixedThread1 private var handlerDispatcher: CoroutineDispatcher) : Experiment() {
+
+    override val description: String = "Basic tracing tutorial"
+
+    @OptIn(ExperimentalContracts::class)
+    private suspend inline fun runStep(stepNumber: Int = 0, crossinline block: (Job) -> Unit) {
+        contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+        traceAsync(TRACK_NAME, "Step #$stepNumber") { block(coroutineContext.job) }
+        traceAsync(TRACK_NAME, "cooldown") { delay(10) }
+    }
+
+    /** 1: Untraced coroutine on default dispatcher */
+    private fun step1UntracedCoroutineOnDefaultDispatcher(job: Job) {
+        // First, we will start with a basic coroutine that has no tracing:
+        val scope = CoroutineScope(job + EmptyCoroutineContext)
+        scope.launch { delay(1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on the default dispatcher. The thread runs,
+        then stops, and then runs again
+
+        There is not much useful information in the trace. We see the thread runs, then
+        stops running due to the `delay(1)` call, then runs again after the delay.
+         */
+    }
+
+    /** 2: Untraced coroutine on traced Looper thread */
+    private fun step2UntracedCoroutineOnTracedLooperThread(job: Job) {
+        /*
+        Next, we will switch from the default dispatcher to a single-threaded dispatcher
+        backed by an Android `Looper`. We will also set a trace tag for the `Looper` so
+        that the `Runnable` class names appear in the trace:
+        Next, we'll launch a coroutine with a delay:
+        */
+        val scope = CoroutineScope(job + handlerDispatcher)
+        scope.launch { delay(1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on the "demo-main-thread" thread. The
+        trace shows trace sections with the names `android.os.Handler:
+        kotlinx.coroutines.internal.DispatchedContinuation` and `android.os.Handler:
+        kotlinx.coroutines.android.HandlerContext$scheduleResumeAfterDelay$$inlined$Runnable$1`.
+        This is better; we now trace sections for `android.os.Handler:
+        kotlinx.coroutines.internal.DispatchedContinuation` and `android.os.Handler:
+        kotlinx.coroutines.android.HandlerContext$scheduleResumeAfterDelay$$inlined$Runnable$1`,
+        but this still does not give us much useful information.
+        */
+    }
+
+    /** 3: Replacing `delay` with `forceSuspend` */
+    private fun step3ReplaceDelayWithForceSuspend(job: Job) {
+        /*
+        Next, for clarity, we will replace `delay()` with our own implementation called
+        `forceSuspend`.
+
+        `forceSuspend` is similar to `delay` except that it is guaranteed to always
+        suspend. It also has backed by a `Looper`, and it emits trace sections for
+        demonstration purposes. We will also pass it a tag, "A", to make our call
+        identifiable in the trace later.
+        */
+        val scope = CoroutineScope(job + handlerDispatcher)
+        scope.launch { forceSuspend("A", 1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on a handler dispatcher. The trace shows
+        the
+        kotlinx.coroutines.android.HandlerContext$scheduleResumeAfterDelay$$inlined$Runnable$1
+        coroutine
+
+        We see a trace section when `forceSuspend` schedules a `Runnable` on the
+        `Handler`, and later there is a trace section when the `Runnable` resumes the
+        continuation.
+        */
+    }
+
+    /** 4: Coroutine with `TraceContextElement` installed */
+    private fun step4CoroutineWithTraceContextElement(job: Job) {
+        // Next, we'll install a `TraceContextElement` to the top-level coroutine:
+        val scope = CoroutineScope(job + handlerDispatcher + createCoroutineTracingContext())
+        scope.launch { forceSuspend("A", 1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on a handler dispatcher with a
+        `TraceContextElement` installed
+
+        A new trace section named `coroutine execution` appears. Underneath it, an
+        additional slice contains metadata, which in this case looks like:
+        `;d=1;c=988384889;p=1577051477`
+
+        The string before the first semicolon (`;`) is the name of the resumed
+        coroutine. In the above example, no name was given to `launch`, and the tracing
+        context was not created with options to automatically infer a name, so the name
+        is blank.
+
+        The other fields are as follows:
+
+        *   `d=` is the depth, or how many parent coroutines there are until we reach
+            the top-level coroutine.
+        *   `c=` is the ID of the current coroutine.
+        *   `p=` is the ID of the parent coroutine.
+
+        Thus, in the above example slice, if we want to find slices belonging to the
+        parent coroutine, we would search the trace for `;c=1577051477;`.
+
+        Note: The parent coroutine will only be included in the Perfetto trace if it
+        happens to run sometime during when the trace was captured. Parent coroutines
+        may run in parallel to their children, so it is not necessarily the case that
+        the child has to be created *after* tracing has started to know the parent name
+        (although that helps).
+
+        In the above trace, we also see `delay(1) ["A"]` is now traced as well. That's
+        because `forceSuspend()` calls `traceCoroutine("forceSuspend") {}`.
+
+        `traceCoroutine("[trace-name]") { }` can be used for tracing sections of
+        suspending code. The trace name will start and end as the coroutine suspends and
+        resumes.
+         */
+    }
+
+    /** 5: Enable `walkStackForDefaultNames` */
+    private fun step5EnableStackWalker(job: Job) {
+        // Next, we'll enable `walkStackForDefaultNames`:
+        val scope =
+            CoroutineScope(
+                job +
+                    handlerDispatcher +
+                    createCoroutineTracingContext(walkStackForDefaultNames = true)
+            )
+        scope.launch { forceSuspend("A", 1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on a handler dispatcher with
+        `walkStackForDefaultNames` enabled. The trace shows that `launch` has the name
+        `BasicTracingTutorial.step5EnableStackWalker;d=1;c=1560424941;p=1105235868`
+
+        Now, we can see our coroutine has a name:
+        `BasicTracingTutorial.step5EnableStackWalker;d=1;c=1560424941;p=1105235868`.
+
+        We can also see a slice named `walkStackForClassName` that occurs before the
+        `launch`. This is where the coroutine trace context infers the name of the
+        newly launched coroutine by inspecting the stack trace to see where it was
+        created.
+
+        One downside of using `walkStackForDefaultNames = true` is that it is expensive,
+        sometimes taking longer than 1 millisecond to infer the name of a class,
+        so it should be used sparingly. As we'll see further on, some parts of
+        `kotlinx.coroutines` are written such that there is no way for us to insert a
+        custom coroutine context, thus making `walkStackForClassName` unavoidable.
+         */
+    }
+
+    /** 6: Replace `launch` with `launchTraced` */
+    private fun step6UseLaunchedTraced(job: Job) {
+        // Walking the stack is an expensive operation, so next we'll replace our call to
+        // `launch` with `launchTraced`:
+        val scope =
+            CoroutineScope(
+                job +
+                    handlerDispatcher +
+                    createCoroutineTracingContext(walkStackForDefaultNames = true)
+            )
+        scope.launchTraced { forceSuspend("A", 1) }
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on a handler dispatcher with `launchTraced` instead of
+        `launch`
+
+        Now we see the trace section is named:
+        `BasicTracingTutorial$step6$1;d=1;c=1529321599;p=1334272881`. This is almost the
+        same as the name in the previous step, except this name is derived using the
+        classname of the supplied lambda, `block::class.simpleName`, which is much
+        faster. We also see that `walkStackForClassName` was not called.
+         */
+    }
+
+    /** 7: Call `launchTraced` with an explicit name */
+    private fun step7ExplicitLaunchName(job: Job) {
+        // Finally, we'll pass an explicit name to `launchTraced` instead of using the
+        // inline name:
+        val scope =
+            CoroutineScope(
+                job +
+                    handlerDispatcher +
+                    createCoroutineTracingContext(walkStackForDefaultNames = true)
+            )
+        scope.launchTraced("my-launch") { forceSuspend("A", 1) }
+
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine launched on a handler dispatcher with an explicit name
+
+        Now we see the trace name is: `my-launch;d=1;c=1148426666;p=1556983557`.
+         */
+    }
+
+    /** 8: Enable `countContinuations` */
+    private fun step8CountContinuations(job: Job) {
+        // The config parameter `countContinuations` can be used to count how many times a
+        // coroutine has run, in total, since its creation:
+        val scope =
+            CoroutineScope(
+                job +
+                    handlerDispatcher +
+                    createCoroutineTracingContext(
+                        walkStackForDefaultNames = true,
+                        countContinuations = true,
+                    )
+            )
+        scope.launchTraced("my-launch") {
+            forceSuspend("A", 1)
+            forceSuspend("B", 1)
+            forceSuspend("C", 1)
+        }
+        /*
+        Expected trace output (image alt text):
+        Trace showing a coroutine resuming after a delay, in which the continuation
+        counter has incremented to 3
+
+        In the above trace, the coroutine suspends 3 times. The counter is `0` for the
+        first resumption, and the last resumption is `3`.
+         */
+    }
+
+    override suspend fun runExperiment() {
+        runStep(1, ::step1UntracedCoroutineOnDefaultDispatcher)
+        runStep(2, ::step2UntracedCoroutineOnTracedLooperThread)
+        runStep(3, ::step3ReplaceDelayWithForceSuspend)
+        runStep(4, ::step4CoroutineWithTraceContextElement)
+        runStep(5, ::step5EnableStackWalker)
+        runStep(6, ::step6UseLaunchedTraced)
+        runStep(7, ::step7ExplicitLaunchName)
+        runStep(8, ::step8CountContinuations)
+    }
+}
diff --git a/tracinglib/demo/src/experiments/CancellableSharedFlow.kt b/tracinglib/demo/src/experiments/CancellableSharedFlow.kt
index 8e7d633..ac56372 100644
--- a/tracinglib/demo/src/experiments/CancellableSharedFlow.kt
+++ b/tracinglib/demo/src/experiments/CancellableSharedFlow.kt
@@ -15,28 +15,32 @@
  */
 package com.example.tracing.demo.experiments
 
-import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThread1
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.shareIn
 
 @Singleton
 class CancellableSharedFlow
 @Inject
-constructor(@FixedThreadB private var dispatcherB: CoroutineDispatcher) : Experiment {
-
+constructor(@FixedThread1 private var dispatcher1: CoroutineDispatcher) : TracedExperiment() {
     override val description: String = "Create shared flows that can be cancelled by the parent"
 
-    override suspend fun start() {
+    override suspend fun runExperiment(): Unit = coroutineScope {
         // GOOD - launched into child scope, parent can cancel this
-        coroutineScope {
-            coldCounterFlow("good")
-                .flowOn(dispatcherB)
-                .shareIn(this, SharingStarted.Eagerly, replay = 10)
-        }
+        flow {
+                var n = 0
+                while (true) {
+                    emit(n++)
+                    forceSuspend(timeMillis = 5)
+                }
+            }
+            .flowOn(dispatcher1)
+            .shareIn(this, SharingStarted.Eagerly, replay = 10)
     }
 }
diff --git a/tracinglib/demo/src/experiments/CollectFlow.kt b/tracinglib/demo/src/experiments/CollectFlow.kt
index d06acf2..b2369c7 100644
--- a/tracinglib/demo/src/experiments/CollectFlow.kt
+++ b/tracinglib/demo/src/experiments/CollectFlow.kt
@@ -18,50 +18,66 @@ package com.example.tracing.demo.experiments
 import android.os.Trace
 import com.android.app.tracing.coroutines.flow.collectTraced
 import com.android.app.tracing.coroutines.flow.filterTraced as filter
+import com.android.app.tracing.coroutines.flow.filterTraced
 import com.android.app.tracing.coroutines.flow.flowName
 import com.android.app.tracing.coroutines.flow.mapTraced as map
-import com.android.app.tracing.coroutines.launchTraced as launch
-import com.example.tracing.demo.FixedThreadA
-import com.example.tracing.demo.FixedThreadB
-import com.example.tracing.demo.FixedThreadC
+import com.android.app.tracing.coroutines.flow.mapTraced
+import com.android.app.tracing.coroutines.flow.onEachTraced
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import com.example.tracing.demo.FixedThread3
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
 
 @Singleton
 class CollectFlow
 @Inject
 constructor(
-    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
-    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
-    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
-) : Experiment {
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+    @FixedThread3 private val dispatcher3: CoroutineDispatcher,
+) : TracedExperiment() {
     override val description: String = "Collect a cold flow with intermediate operators"
 
     private val coldFlow =
-        coldCounterFlow("count", 4)
-            .flowName("original-cold-flow-scope")
-            .flowOn(dispatcherA)
+        flow {
+                var n = 0
+                while (true) {
+                    Trace.instant(Trace.TRACE_TAG_APP, "emit:$n")
+                    emit(n++)
+                    forceSuspend(timeMillis = 8)
+                }
+            }
+            .mapTraced("A") {
+                Trace.instant(Trace.TRACE_TAG_APP, "map:$it")
+                it
+            }
+            .onEachTraced("B") { Trace.instant(Trace.TRACE_TAG_APP, "onEach:$it") }
+            .filterTraced("C") {
+                Trace.instant(Trace.TRACE_TAG_APP, "filter:$it")
+                true
+            }
+            .flowOn(dispatcher3)
+            .flowName("inner-flow")
             .filter("evens") {
-                forceSuspend("B", 20)
+                forceSuspend(timeMillis = 4)
+                Trace.instant(Trace.TRACE_TAG_APP, "filter-evens")
                 it % 2 == 0
             }
-            .flowOn(dispatcherB)
-            .flowName("even-filter-scope")
+            .flowName("middle-flow")
+            .flowOn(dispatcher2)
             .map("3x") {
-                forceSuspend("C", 15)
+                forceSuspend(timeMillis = 2)
+                Trace.instant(Trace.TRACE_TAG_APP, "3x")
                 it * 3
             }
-            .flowOn(dispatcherC)
+            .flowOn(dispatcher1)
+            .flowName("outer-flow")
 
-    override suspend fun start(): Unit = coroutineScope {
-        launch(context = dispatcherA) {
-            coldFlow.collectTraced {
-                Trace.instant(Trace.TRACE_TAG_APP, "got: $it")
-                forceSuspend("A2", 60)
-            }
-        }
+    override suspend fun runExperiment() {
+        coldFlow.collectTraced("collect-flow") { Trace.instant(Trace.TRACE_TAG_APP, "got: $it") }
     }
 }
diff --git a/tracinglib/demo/src/experiments/CombineDeferred.kt b/tracinglib/demo/src/experiments/CombineDeferred.kt
index 7ef09ce..4ab0219 100644
--- a/tracinglib/demo/src/experiments/CombineDeferred.kt
+++ b/tracinglib/demo/src/experiments/CombineDeferred.kt
@@ -15,17 +15,17 @@
  */
 package com.example.tracing.demo.experiments
 
-import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.asyncTraced
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.traceSection
-import com.example.tracing.demo.FixedThreadA
-import com.example.tracing.demo.FixedThreadB
-import com.example.tracing.demo.FixedThreadC
-import com.example.tracing.demo.Unconfined
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import com.example.tracing.demo.FixedThread3
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineStart.LAZY
+import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.async
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.launch
@@ -34,54 +34,53 @@ import kotlinx.coroutines.launch
 class CombineDeferred
 @Inject
 constructor(
-    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
-    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
-    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
-    @Unconfined private var unconfinedContext: CoroutineDispatcher,
-) : Experiment {
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+    @FixedThread3 private val dispatcher3: CoroutineDispatcher,
+) : Experiment() {
     override val description: String = "async{} then start()"
 
-    override suspend fun start(): Unit = coroutineScope {
+    override suspend fun runExperiment(): Unit = coroutineScope {
         // deferred10 -> deferred20 -> deferred30
         val deferred30 =
-            async(start = LAZY, context = dispatcherB) {
-                traceCoroutine("async#30") { forceSuspend("deferred30", 250) }
+            async(start = LAZY, context = dispatcher2) {
+                traceCoroutine("async#30") { forceSuspend("deferred30", 25) }
             }
         val deferred20 =
-            async(start = LAZY, context = unconfinedContext) {
-                traceCoroutine("async#20") { forceSuspend("deferred20", 250) }
+            async(start = LAZY, context = Dispatchers.Unconfined) {
+                traceCoroutine("async#20") { forceSuspend("deferred20", 25) }
                 traceSection("start30") { deferred30.start() }
             }
         val deferred10 =
-            async(start = LAZY, context = dispatcherC) {
-                traceCoroutine("async#10") { forceSuspend("deferred10", 250) }
+            async(start = LAZY, context = dispatcher3) {
+                traceCoroutine("async#10") { forceSuspend("deferred10", 25) }
                 traceSection("start20") { deferred20.start() }
             }
 
         // deferredA -> deferredB -> deferredC
         val deferredC =
-            async(start = LAZY, context = dispatcherB) {
-                traceCoroutine("async#C") { forceSuspend("deferredC", 250) }
+            async(start = LAZY, context = dispatcher2) {
+                traceCoroutine("async#C") { forceSuspend("deferredC", 25) }
             }
         val deferredB =
-            async(start = LAZY, context = unconfinedContext) {
-                traceCoroutine("async#B") { forceSuspend("deferredB", 250) }
+            async(start = LAZY, context = Dispatchers.Unconfined) {
+                traceCoroutine("async#B") { forceSuspend("deferredB", 25) }
                 traceSection("startC") { deferredC.start() }
             }
         val deferredA =
-            async(start = LAZY, context = dispatcherC) {
-                traceCoroutine("async#A") { forceSuspend("deferredA", 250) }
+            async(start = LAZY, context = dispatcher3) {
+                traceCoroutine("async#A") { forceSuspend("deferredA", 25) }
                 traceSection("startB") { deferredB.start() }
             }
 
         // no dispatcher specified, so will inherit dispatcher from whoever called
         // run(), meaning the main thread
         val deferredE =
-            async(nameCoroutine("overridden-scope-name-for-deferredE")) {
-                traceCoroutine("async#E") { forceSuspend("deferredE", 250) }
+            asyncTraced("overridden-scope-name-for-deferredE") {
+                traceCoroutine("async#E") { forceSuspend("deferredE", 25) }
             }
 
-        launch(dispatcherA) {
+        launch(dispatcher1) {
             traceSection("start10") { deferred10.start() }
             traceSection("startA") { deferredA.start() }
             traceSection("startE") { deferredE.start() }
diff --git a/tracinglib/demo/src/experiments/Experiment.kt b/tracinglib/demo/src/experiments/Experiment.kt
index 9851825..f30e743 100644
--- a/tracinglib/demo/src/experiments/Experiment.kt
+++ b/tracinglib/demo/src/experiments/Experiment.kt
@@ -15,12 +15,23 @@
  */
 package com.example.tracing.demo.experiments
 
-interface Experiment {
-    /** The track name for async traces */
-    val tag: String
-        get() = "Experiment:${this::class.simpleName}"
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
 
-    val description: String
+sealed class Experiment {
+    abstract val description: String
 
-    suspend fun start()
+    open val context: CoroutineContext = EmptyCoroutineContext
+
+    abstract suspend fun runExperiment()
+}
+
+sealed class TracedExperiment : Experiment() {
+    override val context: CoroutineContext =
+        createCoroutineTracingContext(
+            this::class.simpleName!!,
+            walkStackForDefaultNames = true,
+            countContinuations = true,
+        )
 }
diff --git a/tracinglib/demo/src/experiments/FlowTracingTutorial.kt b/tracinglib/demo/src/experiments/FlowTracingTutorial.kt
new file mode 100644
index 0000000..51ad534
--- /dev/null
+++ b/tracinglib/demo/src/experiments/FlowTracingTutorial.kt
@@ -0,0 +1,226 @@
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
+package com.example.tracing.demo.experiments
+
+import android.os.Trace
+import com.android.app.tracing.TraceUtils.traceAsync
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.flow.asStateFlowTraced
+import com.android.app.tracing.coroutines.flow.filterTraced
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapTraced
+import com.android.app.tracing.coroutines.flow.shareInTraced
+import com.android.app.tracing.coroutines.flow.stateInTraced
+import com.android.app.tracing.coroutines.flow.traceAs
+import com.android.app.tracing.coroutines.launchInTraced
+import com.android.app.tracing.coroutines.launchTraced
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlin.contracts.ExperimentalContracts
+import kotlin.contracts.InvocationKind
+import kotlin.contracts.contract
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.cancelChildren
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.job
+
+@Singleton
+class FlowTracingTutorial
+@Inject
+constructor(
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+) : Experiment() {
+
+    override val description: String = "Flow tracing tutorial"
+
+    private lateinit var scope: CoroutineScope
+    private lateinit var bgScope: CoroutineScope
+
+    @OptIn(ExperimentalContracts::class)
+    private suspend inline fun runStep(stepName: String, crossinline block: () -> Unit) {
+        contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+        traceAsync(TRACK_NAME, "Step #$stepName") {
+            block()
+            traceAsync(TRACK_NAME, "running") { forceSuspend(timeMillis = 40) }
+            traceAsync(TRACK_NAME, "cleanup") {
+                traceAsync(TRACK_NAME, "cancel-main") { scope.coroutineContext.cancelChildren() }
+                traceAsync(TRACK_NAME, "cancel-bg") { bgScope.coroutineContext.cancelChildren() }
+                forceSuspend(timeMillis = 10)
+            }
+        }
+    }
+
+    private fun createTracingContext(name: String): CoroutineContext {
+        return createCoroutineTracingContext(
+            name = name,
+            walkStackForDefaultNames = true,
+            countContinuations = true,
+        )
+    }
+
+    /** 1.1: */
+    private fun step1p1() {
+        scope.launchTraced("LAUNCH_FOR_COLLECT_1.1") {
+            fibFlow.collect { Trace.instant(Trace.TRACE_TAG_APP, "got:$it") }
+        }
+    }
+
+    /** 1.2: */
+    private fun step1p2() {
+        fibFlow.launchInTraced("LAUNCH_FOR_COLLECT_1.2", scope)
+    }
+
+    /** 2.1: */
+    private fun step2p1() {
+        val coldFlow = fibFlow.flowName("FIB_FLOW_NAME_2.1")
+        coldFlow.launchInTracedForDemo("LAUNCH_NAME_2.1", scope)
+    }
+
+    /** 2.2: */
+    private fun step2p2() {
+        val coldFlow = fibFlow.flowName("FIB_FLOW_NAME_2.2").flowOn(dispatcher2)
+        coldFlow.launchInTracedForDemo("LAUNCH_NAME_2.2", scope)
+    }
+
+    /** 2.3: */
+    private fun step2p3() {
+        val coldFlow = fibFlow.flowOn(dispatcher2).flowName("FIB_FLOW_NAME_2.3")
+        coldFlow.launchInTracedForDemo("LAUNCH_NAME_2.3", scope)
+    }
+
+    /** 2.4: */
+    private fun step2p4() {
+        val coldFlow = fibFlow.flowName("FIB_AAA").flowOn(dispatcher2).flowName("FIB_BBB")
+        coldFlow.launchInTracedForDemo("LAUNCH_NAME_2.4", scope)
+    }
+
+    /** 3: */
+    private fun step3() {
+        val coldFlow =
+            fibFlow
+                .mapTraced("x2") { it * 2 }
+                .filterTraced("%3==0") { it % 3 == 0 }
+                .flowName("(fib x 2) % 3 == 0")
+        coldFlow.launchInTracedForDemo("LAUNCH_NAME_3", scope)
+    }
+
+    /** 4: */
+    private fun step4() {
+        val sharedFlow =
+            fibFlow.shareInTraced("SHARED_FLOW_NAME_4", bgScope, SharingStarted.Eagerly, 3)
+        scope.launchTraced("LAUNCH_NAME_4") {
+            forceSuspend("before-collect", 5)
+            sharedFlow.collect(::traceInstant)
+        }
+    }
+
+    /** 5.1: */
+    private fun step5p1() {
+        val sharedFlow =
+            fibFlow.stateInTraced("STATE_FLOW_NAME_5.1", bgScope, SharingStarted.Eagerly, 3)
+        scope.launchTraced("LAUNCH_NAME_5.1") {
+            forceSuspend("before-collect", 5)
+            sharedFlow.collect(::traceInstant)
+        }
+    }
+
+    /** 5.2: */
+    private fun step5p2() {
+        val sharedFlow =
+            fibFlow.shareInTraced("STATE_FLOW_NAME_5.2", bgScope, SharingStarted.Eagerly, 3)
+        val stateFlow = sharedFlow.stateInTraced("", bgScope, SharingStarted.Eagerly, 2)
+        scope.launchTraced("LAUNCH_NAME_5.2") {
+            forceSuspend("before-collect", 5)
+            stateFlow.collect(::traceInstant)
+        }
+    }
+
+    /** 6.1: */
+    private fun step6p1() {
+        val state = MutableStateFlow(1).traceAs("MUTABLE_STATE_FLOW_6.1")
+        state.launchInTraced("LAUNCH_FOR_STATE_FLOW_COLLECT_6.1", scope)
+        bgScope.launchTraced("FWD_FIB_TO_STATE_6.1") {
+            forceSuspend("before-collect", 5)
+            fibFlow.collect {
+                traceInstant(it)
+                // Manually forward values from the cold flow to the MutableStateFlow
+                state.value = it
+            }
+        }
+    }
+
+    /** 6.2: */
+    private fun step6p2() {
+        val state = MutableStateFlow(1).traceAs("MUTABLE_STATE_FLOW_6.2")
+        val readOnlyState = state.asStateFlowTraced("READ_ONLY_STATE_6.2")
+        readOnlyState.launchInTraced("LAUNCH_FOR_STATE_FLOW_COLLECT_6.2", scope)
+        bgScope.launchTraced("FWD_FIB_TO_STATE_6.2") {
+            fibFlow.collect {
+                traceInstant(it)
+                // Manually forward values from the cold flow to the MutableStateFlow
+                state.value = it
+            }
+        }
+    }
+
+    override suspend fun runExperiment(): Unit = coroutineScope {
+        val job = coroutineContext.job
+        scope = CoroutineScope(job + dispatcher1 + createTracingContext("main-scope"))
+        bgScope = CoroutineScope(job + dispatcher2 + createTracingContext("bg-scope"))
+        runStep("1.1", ::step1p1)
+        runStep("1.2", ::step1p2)
+        runStep("2.1", ::step2p1)
+        runStep("2.2", ::step2p2)
+        runStep("2.3", ::step2p3)
+        runStep("2.4", ::step2p4)
+        runStep("3", ::step3)
+        runStep("4", ::step4)
+        runStep("5.1", ::step5p1)
+        runStep("5.2", ::step5p2)
+        runStep("6.1", ::step6p1)
+        runStep("6.2", ::step6p2)
+    }
+}
+
+private fun <T> Flow<T>.launchInTracedForDemo(name: String, scope: CoroutineScope) {
+    scope.launchTraced(name) { collect(::traceInstant) }
+}
+
+private fun <T> traceInstant(value: T) {
+    Trace.instant(Trace.TRACE_TAG_APP, "got:$value")
+}
+
+private val fibFlow = flow {
+    var n0 = 0
+    var n1 = 1
+    while (true) {
+        emit(n0)
+        val n2 = n0 + n1
+        n0 = n1
+        n1 = n2
+        forceSuspend("after-emit", 1)
+    }
+}
diff --git a/tracinglib/demo/src/experiments/LaunchNested.kt b/tracinglib/demo/src/experiments/LaunchNested.kt
index ad1ebf7..9175ea8 100644
--- a/tracinglib/demo/src/experiments/LaunchNested.kt
+++ b/tracinglib/demo/src/experiments/LaunchNested.kt
@@ -15,42 +15,33 @@
  */
 package com.example.tracing.demo.experiments
 
-import com.android.app.tracing.coroutines.launchTraced as launch
-import com.example.tracing.demo.Default
-import com.example.tracing.demo.FixedThreadA
-import com.example.tracing.demo.FixedThreadB
-import com.example.tracing.demo.FixedThreadC
-import com.example.tracing.demo.IO
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.example.tracing.demo.FixedThread1
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.withContext
 
 @Singleton
-class LaunchNested
-@Inject
-constructor(
-    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
-    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
-    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
-    @Default private var defaultContext: CoroutineDispatcher,
-    @IO private var ioContext: CoroutineDispatcher,
-) : Experiment {
+class LaunchNested @Inject constructor(@FixedThread1 private var dispatcher1: CoroutineDispatcher) :
+    TracedExperiment() {
     override val description: String = "launch{launch{launch{launch{}}}}"
 
-    override suspend fun start(): Unit = coroutineScope {
-        launch("launch(threadA)", dispatcherA) {
-            forceSuspend("A", 250)
-            launch("launch(threadB)", dispatcherB) {
-                forceSuspend("B", 250)
-                launch("launch(threadC)", dispatcherC) {
-                    forceSuspend("C", 250)
-                    launch("launch(Dispatchers.Default)", defaultContext) {
-                        forceSuspend("D", 250)
-                        launch("launch(Dispatchers.IO)", ioContext) { forceSuspend("E", 250) }
-                    }
+    override suspend fun runExperiment(): Unit = coroutineScope {
+        fun CoroutineScope.recursivelyLaunch(n: Int) {
+            if (n == 400) return
+            launchTraced("launch#$n", start = CoroutineStart.UNDISPATCHED) {
+                traceCoroutine("trace-span") {
+                    recursivelyLaunch(n + 1)
+                    delay(1)
                 }
             }
         }
+        withContext(dispatcher1) { recursivelyLaunch(0) }
     }
 }
diff --git a/tracinglib/demo/src/experiments/LaunchSequentially.kt b/tracinglib/demo/src/experiments/LaunchSequentially.kt
index 028b7da..8e38108 100644
--- a/tracinglib/demo/src/experiments/LaunchSequentially.kt
+++ b/tracinglib/demo/src/experiments/LaunchSequentially.kt
@@ -16,12 +16,9 @@
 package com.example.tracing.demo.experiments
 
 import com.android.app.tracing.coroutines.launchTraced as launch
-import com.example.tracing.demo.Default
-import com.example.tracing.demo.FixedThreadA
-import com.example.tracing.demo.FixedThreadB
-import com.example.tracing.demo.FixedThreadC
-import com.example.tracing.demo.IO
-import com.example.tracing.demo.Unconfined
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import com.example.tracing.demo.FixedThread3
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
@@ -31,22 +28,16 @@ import kotlinx.coroutines.coroutineScope
 class LaunchSequentially
 @Inject
 constructor(
-    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
-    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
-    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
-    @Default private var defaultContext: CoroutineDispatcher,
-    @IO private var ioContext: CoroutineDispatcher,
-    @Unconfined private var unconfinedContext: CoroutineDispatcher,
-) : Experiment {
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+    @FixedThread3 private val dispatcher3: CoroutineDispatcher,
+) : TracedExperiment() {
     override val description: String = "launch{};launch{};launch{};launch{}"
 
-    override suspend fun start(): Unit = coroutineScope {
-        launch("launch(threadA)", dispatcherA) { forceSuspend("A", 250) }
-        launch("launch(threadB)", dispatcherB) { forceSuspend("B", 250) }
-        launch("launch(threadC)", dispatcherC) { forceSuspend("C", 250) }
-        launch("launch(Dispatchers.Default)", defaultContext) { forceSuspend("D", 250) }
-        launch("launch(EmptyCoroutineContext)") { forceSuspend("E", 250) }
-        launch("launch(Dispatchers.IO)", ioContext) { forceSuspend("F", 250) }
-        launch("launch(Dispatchers.Unconfined)", unconfinedContext) { forceSuspend("G", 250) }
+    override suspend fun runExperiment(): Unit = coroutineScope {
+        launch("launch(empty)") { forceSuspend("000", 5) }
+        launch("launch(thread1)", dispatcher1) { forceSuspend("111", 5) }
+        launch("launch(thread2)", dispatcher2) { forceSuspend("222", 5) }
+        launch("launch(thread3)", dispatcher3) { forceSuspend("333", 5) }
     }
 }
diff --git a/tracinglib/demo/src/experiments/LaunchStressTest.kt b/tracinglib/demo/src/experiments/LaunchStressTest.kt
new file mode 100644
index 0000000..3d11001
--- /dev/null
+++ b/tracinglib/demo/src/experiments/LaunchStressTest.kt
@@ -0,0 +1,68 @@
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.withContextTraced
+import com.example.tracing.demo.FixedPool
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import com.example.tracing.demo.FixedThread3
+import com.example.tracing.demo.FixedThread4
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.delay
+
+@Singleton
+class LaunchStressTest
+@Inject
+constructor(
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+    @FixedThread3 private val dispatcher3: CoroutineDispatcher,
+    @FixedThread4 private val dispatcher4: CoroutineDispatcher,
+    @FixedPool private var fixedPoolDispatcher: CoroutineDispatcher,
+) : TracedExperiment() {
+
+    override val description: String = "Simultaneous launch{} calls on different threads"
+
+    override suspend fun runExperiment(): Unit = coroutineScope {
+        repeat(16) { n ->
+            launchTraced("launch#$n", fixedPoolDispatcher) {
+                withContextTraced("context-switch-pool", fixedPoolDispatcher) {
+                    withContextTraced("context-switch-1", dispatcher1) {
+                        traceCoroutine("delay#$n:1") { delay(5) }
+                    }
+                    traceCoroutine("delay#$n:2") { delay(5) }
+                    withContextTraced("context-switch-2", dispatcher2) {
+                        traceCoroutine("delay#$n:3") { delay(5) }
+                    }
+                }
+                withContextTraced("context-switch-3", dispatcher3) {
+                    traceCoroutine("delay#$n:3") {
+                        traceCoroutine("delay#$n:4") { delay(5) }
+                        withContextTraced("context-switch-4", dispatcher4) {
+                            traceCoroutine("delay#$n:5") { delay(5) }
+                        }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/LeakySharedFlow.kt b/tracinglib/demo/src/experiments/LeakySharedFlow.kt
index 3ece62d..4bfc8c1 100644
--- a/tracinglib/demo/src/experiments/LeakySharedFlow.kt
+++ b/tracinglib/demo/src/experiments/LeakySharedFlow.kt
@@ -15,35 +15,55 @@
  */
 package com.example.tracing.demo.experiments
 
+import android.os.Trace
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
-import com.example.tracing.demo.FixedThreadA
+import com.android.app.tracing.coroutines.flow.flowName
+import com.example.tracing.demo.FixedThread1
 import javax.inject.Inject
 import javax.inject.Singleton
+import kotlin.random.Random
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.job
 
 @Singleton
 class LeakySharedFlow
 @Inject
-constructor(@FixedThreadA private var dispatcherA: CoroutineDispatcher) : Experiment {
+constructor(@FixedThread1 private var handlerDispatcher: CoroutineDispatcher) : TracedExperiment() {
 
     override val description: String = "Create a shared flow that cannot be cancelled by the caller"
 
-    private val leakedScope =
-        CoroutineScope(dispatcherA + createCoroutineTracingContext("flow-scope"))
+    private val counter = flow {
+        var n = 0
+        while (true) {
+            emit(n++)
+            forceSuspend(timeMillis = 5)
+        }
+    }
 
-    override suspend fun start() {
+    override suspend fun runExperiment() {
+        val cookie = Random.nextInt()
+        Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, TRACK_NAME, "leaky-flow", cookie)
         // BAD - does not follow structured concurrency. This creates a new job each time it is
         // called. There is no way to cancel the shared flow because the parent does not know about
         // it
-        coldCounterFlow("leaky1").shareIn(leakedScope, SharingStarted.Eagerly, replay = 10)
+        val leakedScope =
+            CoroutineScope(
+                handlerDispatcher +
+                    createCoroutineTracingContext(
+                        "leaky-flow-scope",
+                        walkStackForDefaultNames = true,
+                    )
+            )
+        counter
+            .flowName("leakySharedFlow")
+            .shareIn(leakedScope, SharingStarted.Eagerly, replay = 10)
 
-        // BAD - this also leaks
-        coroutineScope {
-            coldCounterFlow("leaky2").shareIn(leakedScope, SharingStarted.Eagerly, replay = 10)
+        leakedScope.coroutineContext.job.invokeOnCompletion {
+            Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
         }
     }
 }
diff --git a/tracinglib/demo/src/experiments/SharedFlowUsage.kt b/tracinglib/demo/src/experiments/SharedFlowUsage.kt
index 60929a5..b428489 100644
--- a/tracinglib/demo/src/experiments/SharedFlowUsage.kt
+++ b/tracinglib/demo/src/experiments/SharedFlowUsage.kt
@@ -20,82 +20,80 @@ import com.android.app.tracing.coroutines.flow.collectTraced
 import com.android.app.tracing.coroutines.flow.filterTraced as filter
 import com.android.app.tracing.coroutines.flow.flowName
 import com.android.app.tracing.coroutines.flow.mapTraced as map
+import com.android.app.tracing.coroutines.flow.stateInTraced
 import com.android.app.tracing.coroutines.launchTraced as launch
-import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.coroutines.traceCoroutine
-import com.example.tracing.demo.FixedThreadA
-import com.example.tracing.demo.FixedThreadB
-import com.example.tracing.demo.FixedThreadC
-import com.example.tracing.demo.FixedThreadD
+import com.example.tracing.demo.FixedThread1
+import com.example.tracing.demo.FixedThread2
+import com.example.tracing.demo.FixedThread3
+import com.example.tracing.demo.FixedThread4
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
-import kotlinx.coroutines.flow.stateIn
 
 @Singleton
 class SharedFlowUsage
 @Inject
 constructor(
-    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
-    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
-    @FixedThreadC private var dispatcherC: CoroutineDispatcher,
-    @FixedThreadD private var dispatcherD: CoroutineDispatcher,
-) : Experiment {
+    @FixedThread1 private var dispatcher1: CoroutineDispatcher,
+    @FixedThread2 private var dispatcher2: CoroutineDispatcher,
+    @FixedThread3 private var dispatcher3: CoroutineDispatcher,
+    @FixedThread4 private var dispatcher4: CoroutineDispatcher,
+) : TracedExperiment() {
 
     override val description: String = "Create a shared flow and collect from it"
 
     private val coldFlow =
-        coldCounterFlow("shared", 10)
-            // this trace name is NOT used because the dispatcher did NOT change
-            .flowName("UNUSED_NAME")
+        flow {
+                var n = 0
+                while (n < 20) {
+                    emit(n++)
+                    forceSuspend(timeMillis = 5)
+                }
+            }
             .map("pow2") {
                 val rv = it * it
                 forceSuspend("map($it) -> $rv", 50)
                 rv
             }
             // this trace name is used here because the dispatcher changed
-            .flowOn(dispatcherC + nameCoroutine("NEW_COLD_FLOW_NAME"))
+            .flowOn(dispatcher3)
             .filter("mod4") {
                 val rv = it % 4 == 0
                 forceSuspend("filter($it) -> $rv", 50)
                 rv
             }
-            // this trace name is used, because the scope it is collected in has a
-            // CoroutineTracingContext
             .flowName("COLD_FLOW")
 
-    override suspend fun start() {
-        coroutineScope {
-            val stateFlow = coldFlow.stateIn(this, SharingStarted.Eagerly, 10)
-            launch("launchAAAA", dispatcherA) {
-                stateFlow.collect("collectAAAA") {
-                    traceCoroutine("AAAA collected: $it") { forceSuspend("AAAA", 15) }
-                }
-            }
-            launch("launchBBBB", dispatcherB) {
-                // Don't pass a string. Instead, rely on default behavior to walk the stack for the
-                // name. This results in trace sections like:
-                // `collect:SharedFlowUsage$start$1$2:emit`
-                // NOTE: `Flow.collect` is a member function and takes precedence, so we need
-                // to invoke `collectTraced` using its original name instead of its `collect` alias
-                stateFlow.collectTraced {
-                    traceCoroutine("BBBB collected: $it") { forceSuspend("BBBB", 30) }
-                }
+    override suspend fun runExperiment(): Unit = coroutineScope {
+        val stateFlow = coldFlow.stateInTraced("My-StateFlow", this, SharingStarted.Eagerly, 10)
+        launch("launchAAAA", dispatcher1) {
+            stateFlow.collect("collectAAAA") {
+                traceCoroutine("AAAA collected: $it") { forceSuspend("AAAA", 15) }
             }
-            launch("launchCCCC", dispatcherC) {
-                stateFlow.collect("collectCCCC") {
-                    traceCoroutine("CCCC collected: $it") { forceSuspend("CCCC", 60) }
-                }
+        }
+        launch("launchBBBB", dispatcher2) {
+            // Don't pass a string. Instead, rely on default behavior to walk the stack for the
+            // name. This results in trace sections like:
+            // `collect:SharedFlowUsage$start$1$2:emit`
+            // NOTE: `Flow.collect` is a member function and takes precedence, so we need
+            // to invoke `collectTraced` using its original name instead of its `collect` alias
+            stateFlow.collectTraced {
+                traceCoroutine("BBBB collected: $it") { forceSuspend("BBBB", 30) }
             }
-            launch("launchDDDD", dispatcherD) {
-                // Uses Flow.collect member function instead of collectTraced:
-                stateFlow.collect {
-                    traceCoroutine("DDDD collected: $it") { forceSuspend("DDDD", 90) }
-                }
+        }
+        launch("launchCCCC", dispatcher3) {
+            stateFlow.collect("collectCCCC") {
+                traceCoroutine("CCCC collected: $it") { forceSuspend("CCCC", 60) }
             }
         }
+        launch("launchDDDD", dispatcher4) {
+            // Uses Flow.collect member function instead of collectTraced:
+            stateFlow.collect { traceCoroutine("DDDD collected: $it") { forceSuspend("DDDD", 90) } }
+        }
     }
 }
diff --git a/tracinglib/demo/src/experiments/Util.kt b/tracinglib/demo/src/experiments/Util.kt
index 2cb61ec..2c28d1f 100644
--- a/tracinglib/demo/src/experiments/Util.kt
+++ b/tracinglib/demo/src/experiments/Util.kt
@@ -15,61 +15,54 @@
  */
 package com.example.tracing.demo.experiments
 
-import android.os.HandlerThread
 import android.os.Trace
 import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.traceSection
+import com.example.tracing.demo.delayHandler
+import kotlin.coroutines.Continuation
 import kotlin.coroutines.resume
 import kotlin.random.Random
 import kotlinx.coroutines.delay
-import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.suspendCancellableCoroutine
 
-fun coldCounterFlow(name: String, maxCount: Int = Int.MAX_VALUE) = flow {
-    for (n in 0..maxCount) {
-        emit(n)
-        forceSuspend("coldCounterFlow:$name:$n", 25)
+private class DelayedContinuationRunner(
+    private val continuation: Continuation<Unit>,
+    private val traceName: String,
+    private val cookie: Int,
+) : Runnable {
+    override fun run() {
+        Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
+        Trace.traceBegin(Trace.TRACE_TAG_APP, "resume after $traceName")
+        try {
+            continuation.resume(Unit)
+        } finally {
+            Trace.traceEnd(Trace.TRACE_TAG_APP)
+        }
     }
 }
 
-private val delayHandler by lazy { startThreadWithLooper("Thread:forceSuspend").threadHandler }
-
 /** Like [delay], but naively implemented so that it always suspends. */
-suspend fun forceSuspend(traceName: String, timeMillis: Long) {
-    val traceMessage = "forceSuspend:$traceName"
-    return traceCoroutine(traceMessage) {
-        val cookie = Random.nextInt()
+suspend fun forceSuspend(traceName: String? = null, timeMillis: Long) {
+    val traceMessage = "delay($timeMillis)${traceName?.let { " [$it]" } ?: ""}"
+    val cookie = Random.nextInt()
+    Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, TRACK_NAME, traceMessage, cookie)
+    traceCoroutine(traceMessage) {
         suspendCancellableCoroutine { continuation ->
-            Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, TRACK_NAME, traceMessage, cookie)
-            Trace.instant(Trace.TRACE_TAG_APP, "will resume in ${timeMillis}ms")
-            continuation.invokeOnCancellation { cause ->
-                Trace.instant(
-                    Trace.TRACE_TAG_APP,
-                    "forceSuspend:$traceName, cancelled due to ${cause?.javaClass}",
-                )
-                Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
-            }
-            delayHandler.postDelayed(
-                {
-                    Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
-                    Trace.traceBegin(Trace.TRACE_TAG_APP, "resume")
-                    try {
-                        continuation.resume(Unit)
-                    } finally {
-                        Trace.traceEnd(Trace.TRACE_TAG_APP)
+            traceSection("scheduling DelayedContinuationRunner for $traceName") {
+                val delayedRunnable = DelayedContinuationRunner(continuation, traceMessage, cookie)
+                if (delayHandler.postDelayed(delayedRunnable, timeMillis)) {
+                    continuation.invokeOnCancellation { cause ->
+                        Trace.instant(
+                            Trace.TRACE_TAG_APP,
+                            "$traceMessage, cancelled due to ${cause?.javaClass}",
+                        )
+                        delayHandler.removeCallbacks(delayedRunnable)
+                        Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
                     }
-                },
-                timeMillis,
-            )
+                }
+            }
         }
     }
 }
 
-fun startThreadWithLooper(name: String): HandlerThread {
-    val thread = HandlerThread(name)
-    thread.start()
-    val looper = thread.looper
-    looper.setTraceTag(Trace.TRACE_TAG_APP)
-    return thread
-}
-
-const val TRACK_NAME = "Async events"
+const val TRACK_NAME = "async-trace-events"
diff --git a/tracinglib/robolectric/src/util/Util.kt b/tracinglib/demo/src/ui/theme/Color.kt
similarity index 74%
rename from tracinglib/robolectric/src/util/Util.kt
rename to tracinglib/demo/src/ui/theme/Color.kt
index 15349d2..58a3af1 100644
--- a/tracinglib/robolectric/src/util/Util.kt
+++ b/tracinglib/demo/src/ui/theme/Color.kt
@@ -14,6 +14,11 @@
  * limitations under the License.
  */
 
-package com.android.test.tracing.coroutines.util
+package com.example.tracing.demo.ui.theme
 
-internal fun currentThreadId(): Long = Thread.currentThread().id
+import androidx.compose.ui.graphics.Color
+
+val Navy = Color(0xFF073042)
+val Blue = Color(0xFF4285F4)
+val LightBlue = Color(0xFFD7EFFE)
+val Chartreuse = Color(0xFFEFF7CF)
diff --git a/tracinglib/demo/src/ui/theme/Theme.kt b/tracinglib/demo/src/ui/theme/Theme.kt
new file mode 100644
index 0000000..bf19000
--- /dev/null
+++ b/tracinglib/demo/src/ui/theme/Theme.kt
@@ -0,0 +1,67 @@
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
+package com.example.tracing.demo.ui.theme
+
+import android.app.Activity
+import android.os.Build
+import androidx.compose.foundation.isSystemInDarkTheme
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.darkColorScheme
+import androidx.compose.material3.dynamicDarkColorScheme
+import androidx.compose.material3.dynamicLightColorScheme
+import androidx.compose.material3.lightColorScheme
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.SideEffect
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.graphics.toArgb
+import androidx.compose.ui.platform.LocalContext
+import androidx.compose.ui.platform.LocalView
+import androidx.core.view.ViewCompat
+
+private val DarkColorScheme =
+    darkColorScheme(surface = Blue, onSurface = Navy, primary = Navy, onPrimary = Chartreuse)
+
+private val LightColorScheme =
+    lightColorScheme(surface = Blue, onSurface = Color.White, primary = LightBlue, onPrimary = Navy)
+
+@Suppress("DEPRECATION")
+@Composable
+fun BasicsCodelabTheme(
+    darkTheme: Boolean = isSystemInDarkTheme(),
+    // Dynamic color is available on Android 12+
+    dynamicColor: Boolean = true,
+    content: @Composable () -> Unit,
+) {
+    val colorScheme =
+        when {
+            dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
+                val context = LocalContext.current
+                if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
+            }
+            darkTheme -> DarkColorScheme
+            else -> LightColorScheme
+        }
+    val view = LocalView.current
+    if (!view.isInEditMode) {
+        SideEffect {
+            (view.context as Activity).window.statusBarColor = colorScheme.primary.toArgb()
+            ViewCompat.getWindowInsetsController(view)?.isAppearanceLightStatusBars = darkTheme
+        }
+    }
+
+    MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
+}
diff --git a/tracinglib/demo/src/ui/theme/Type.kt b/tracinglib/demo/src/ui/theme/Type.kt
new file mode 100644
index 0000000..4ff3936
--- /dev/null
+++ b/tracinglib/demo/src/ui/theme/Type.kt
@@ -0,0 +1,35 @@
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
+package com.example.tracing.demo.ui.theme
+
+import androidx.compose.material3.Typography
+import androidx.compose.ui.text.TextStyle
+import androidx.compose.ui.text.font.FontFamily
+import androidx.compose.ui.text.font.FontWeight
+import androidx.compose.ui.unit.sp
+
+val Typography =
+    Typography(
+        bodyLarge =
+            TextStyle(
+                fontFamily = FontFamily.Default,
+                fontWeight = FontWeight.Normal,
+                fontSize = 16.sp,
+                lineHeight = 24.sp,
+                letterSpacing = 0.5.sp,
+            )
+    )
diff --git a/tracinglib/robolectric/Android.bp b/tracinglib/robolectric/Android.bp
index 74625a7..38b2b62 100644
--- a/tracinglib/robolectric/Android.bp
+++ b/tracinglib/robolectric/Android.bp
@@ -41,6 +41,5 @@ android_robolectric_test {
         "androidx.test.ext.junit",
     ],
     instrumentation_for: "tracinglib-test-app",
-    upstream: true,
     strict_mode: false,
 }
diff --git a/tracinglib/robolectric/src/BackgroundThreadTracingTest.kt b/tracinglib/robolectric/src/BackgroundThreadTracingTest.kt
new file mode 100644
index 0000000..a20839f
--- /dev/null
+++ b/tracinglib/robolectric/src/BackgroundThreadTracingTest.kt
@@ -0,0 +1,98 @@
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
+@file:OptIn(
+    DelicateCoroutinesApi::class,
+    ExperimentalCoroutinesApi::class,
+    ExperimentalStdlibApi::class,
+)
+
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.TraceContextElement
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.withContextTraced
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.currentCoroutineContext
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.plus
+import org.junit.Assert.assertTrue
+import org.junit.Test
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class BackgroundThreadTracingTest : TestBase() {
+
+    @Test
+    fun withContext_reuseOuterDispatcher() =
+        runTest(finalEvent = 5) {
+            val originalDispatcher = currentCoroutineContext()[CoroutineDispatcher]!!
+            val otherScope = scope.plus(bgThread1)
+            expect(1, "1^main")
+            otherScope
+                .launchTraced("AAA") {
+                    expect(2, "2^AAA")
+                    withContextTraced("inside-withContext", originalDispatcher) {
+                        assertTrue(coroutineContext[CoroutineTraceName] is TraceContextElement)
+                        expect(3, "2^AAA", "inside-withContext")
+                        delay(1)
+                        expect(4, "2^AAA", "inside-withContext")
+                    }
+                    expect(5, "2^AAA")
+                }
+                .join()
+        }
+
+    @Test
+    fun withContext_reentryToSameContext() =
+        runTest(totalEvents = 10) {
+            val otherScope = scope.plus(bgThread1)
+            expect("1^main")
+            otherScope
+                .launchTraced("AAA") {
+                    expect("2^AAA")
+                    var job: Job? = null
+                    launchTraced("BBB") {
+                            expect("2^AAA:1^BBB")
+                            job =
+                                scope.launchTraced("CCC") {
+                                    withContextTraced("DDD", bgThread1) {
+                                        expect("3^CCC", "DDD")
+                                        delay(1)
+                                        expect("3^CCC", "DDD")
+                                    }
+                                    withContextTraced("EEE", EmptyCoroutineContext) {
+                                        expect("3^CCC", "EEE")
+                                        delay(1)
+                                        expect("3^CCC", "EEE")
+                                    }
+                                }
+                            expect("2^AAA:1^BBB")
+                        }
+                        .join()
+                    job!!.join()
+                    expect("2^AAA")
+                }
+                .join()
+            expect("1^main")
+        }
+}
diff --git a/tracinglib/robolectric/src/CallbackFlowTracingTest.kt b/tracinglib/robolectric/src/CallbackFlowTracingTest.kt
index dfc7f42..18f84e5 100644
--- a/tracinglib/robolectric/src/CallbackFlowTracingTest.kt
+++ b/tracinglib/robolectric/src/CallbackFlowTracingTest.kt
@@ -18,16 +18,12 @@ package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
-import com.android.app.tracing.coroutines.flow.collectTraced
-import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.stateInTraced
 import com.android.app.tracing.coroutines.launchTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
 import java.util.concurrent.Executor
-import kotlin.coroutines.CoroutineContext
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.DelicateCoroutinesApi
-import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.asExecutor
 import kotlinx.coroutines.cancel
 import kotlinx.coroutines.channels.awaitClose
@@ -42,8 +38,7 @@ import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.onEach
 import kotlinx.coroutines.flow.onStart
-import kotlinx.coroutines.flow.stateIn
-import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.job
 import org.junit.Test
 
 data class ExampleInfo(val a: Int, val b: Boolean, val c: String)
@@ -108,9 +103,13 @@ private class ExampleRepositoryImpl(
                 )
                 awaitClose { tracker.removeCallback(callback) }
             }
-            .onEach { testBase.expect("bg:1^currentInfo") }
-            .flowName("currentInfo")
-            .stateIn(bgScope, SharingStarted.Eagerly, initialValue = tracker.info)
+            .onEach { testBase.expect("1^currentInfo") }
+            .stateInTraced(
+                "currentInfo",
+                bgScope,
+                SharingStarted.Eagerly,
+                initialValue = tracker.info,
+            )
 
     override val otherState = MutableStateFlow(false)
 
@@ -120,47 +119,45 @@ private class ExampleRepositoryImpl(
             combine(currentInfo, otherState, ::Pair)
                 .map { it.first.b && it.second }
                 .distinctUntilChanged()
-                .onEach { testBase.expect("bg:2^combinedState:1^:2^") }
+                .onEach { testBase.expect("2^combinedState:1^:2^") }
                 .onStart { emit(false) }
-                .flowName("combinedState")
-                .stateIn(
+                .stateInTraced(
+                    "combinedState",
                     scope = bgScope,
                     started = SharingStarted.WhileSubscribed(),
                     initialValue = false,
                 )
 }
 
-@OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class CallbackFlowTracingTest : TestBase() {
 
-    override val extraCoroutineContext: CoroutineContext
-        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+    private val bgScope: CoroutineScope by lazy {
+        CoroutineScope(
+            createCoroutineTracingContext("bg", testMode = true) +
+                bgThread1 +
+                scope.coroutineContext.job
+        )
+    }
 
     @Test
-    fun callbackFlow1() {
+    fun callbackFlow() {
         val exampleTracker = ExampleStateTrackerImpl()
-        val bgScope =
-            CoroutineScope(
-                createCoroutineTracingContext("bg", includeParentNames = true, strictMode = true) +
-                    newSingleThreadContext("bg-thread")
-            )
         val repository = ExampleRepositoryImpl(this, bgScope, exampleTracker)
-
-        expect(1)
-        runTest {
+        runTest(totalEvents = 15) {
             launchTraced("collectCombined") {
-                repository.combinedState.collectTraced("combined-states") {
+                // upstream flow already has tracing, so tracing with a collect call here would be
+                // redundant. That's why we call `collect` instead of `collectTraced`
+                repository.combinedState.collect {
                     expect(
-                        listOf(2, 4, 5, 6),
-                        "main:1^:1^collectCombined",
-                        "collect:combined-states",
-                        "collect:combined-states:emit",
+                        "1^main:1^collectCombined",
+                        "collect:combinedState",
+                        "emit:combinedState",
                     )
                 }
             }
             delay(10)
-            expect(3, "main:1^")
+            expect("1^main")
             delay(10)
             exampleTracker.forceUpdate(1, false, "A") // <-- no change
             delay(10)
@@ -176,7 +173,7 @@ class CallbackFlowTracingTest : TestBase() {
             delay(10)
             repository.otherState.value = true // <-- should update `combinedState`
             delay(10)
-            finish(7, "main:1^")
+            expect("1^main")
             cancel("Cancelled normally for test")
         }
         bgScope.cancel("Cancelled normally for test")
diff --git a/tracinglib/robolectric/src/CoroutineTraceNameTest.kt b/tracinglib/robolectric/src/CoroutineTraceNameTest.kt
new file mode 100644
index 0000000..031418b
--- /dev/null
+++ b/tracinglib/robolectric/src/CoroutineTraceNameTest.kt
@@ -0,0 +1,46 @@
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
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.TraceContextElement
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.launch
+import org.junit.Test
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class CoroutineTraceNameTest : TestBase() {
+
+    // BAD: CoroutineTraceName should not be installed on the root like this:
+    override val extraContext: CoroutineContext by lazy { CoroutineTraceName("MainName") }
+
+    @Test
+    fun nameMergedWithTraceContext() = runTest {
+        expectD()
+        val otherTraceContext =
+            createCoroutineTracingContext("TraceContextName", testMode = true)
+                as TraceContextElement
+        // MainName is never used. It is overwritten by the CoroutineTracingContext:
+        launch(otherTraceContext) { expectD("1^TraceContextName") }
+        expectD()
+        launch(otherTraceContext) { expectD("2^TraceContextName") }
+        launch { expectD() }
+    }
+}
diff --git a/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt b/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt
index a82c7de..253d7ed 100644
--- a/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt
+++ b/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt
@@ -14,11 +14,14 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
 import com.android.app.tracing.coroutines.TraceContextElement
 import com.android.app.tracing.coroutines.TraceData
+import com.android.app.tracing.coroutines.TraceStorage
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.launchTraced
 import com.android.app.tracing.coroutines.traceCoroutine
@@ -27,30 +30,30 @@ import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
 import java.util.concurrent.CyclicBarrier
 import java.util.concurrent.Executors
 import java.util.concurrent.TimeUnit
+import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
-import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.currentCoroutineContext
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.newSingleThreadContext
-import kotlinx.coroutines.withContext
 import org.junit.Assert.assertArrayEquals
+import org.junit.Assert.assertNotNull
 import org.junit.Assert.assertNotSame
 import org.junit.Assert.assertNull
 import org.junit.Assert.assertSame
+import org.junit.Assert.assertThrows
 import org.junit.Test
 
-@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class CoroutineTracingMachineryTest : TestBase() {
 
+    override val extraContext: CoroutineContext by lazy { EmptyCoroutineContext }
+
     @Test
     fun missingTraceContextObjects() = runTest {
         val channel = Channel<Int>()
-        val context1 = newSingleThreadContext("thread-#1")
-        val context2 =
-            newSingleThreadContext("thread-#2") +
-                createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+        val context1 = bgThread1
+        val context2 = bgThread2 + createCoroutineTracingContext("main", testMode = true)
 
         launchTraced("launch#1", context1) {
             expect()
@@ -61,18 +64,18 @@ class CoroutineTracingMachineryTest : TestBase() {
                 // "launch#2" is not traced because TraceContextElement was installed too
                 // late; it is not part of the scope that was launched (i.e., the `this` in
                 // `this.launch {}`)
-                expect("main:1^")
+                expect("1^main")
                 channel.receive()
-                traceCoroutine("span-2") { expect("main:1^", "span-2") }
-                expect("main:1^")
+                traceCoroutine("span-2") { expect("1^main", "span-2") }
+                expect("1^main")
                 launch {
                     // ...it won't appear in the child scope either because in
-                    // launchTraced("string"), it
-                    // adds: `CoroutineTraceName` + `TraceContextElement`. This demonstrates why
-                    // it is important to only use `TraceContextElement` in the root scope. In this
-                    // case, the `TraceContextElement`  overwrites the name, so the name is dropped.
+                    // `launchTraced("string"), it adds:
+                    // `CoroutineTraceName` + `TraceContextElement`. This demonstrates why it is
+                    // important to only use `TraceContextElement` in the root scope. In this case,
+                    // the `TraceContextElement`  overwrites the name, so the name is dropped.
                     // Tracing still works with a default, empty name, however.
-                    expect("main:1^:1^")
+                    expect("1^main:1^")
                 }
             }
             expect()
@@ -83,7 +86,7 @@ class CoroutineTracingMachineryTest : TestBase() {
         channel.send(2)
 
         launch(context1) { expect() }
-        launch(context2) { expect("main:2^") }
+        launch(context2) { expect("2^main") }
     }
 
     /**
@@ -95,15 +98,18 @@ class CoroutineTracingMachineryTest : TestBase() {
      * ```
      *
      * This test checks for issues with concurrent modification of the trace state. For example, the
-     * test should fail if [TraceData.endAllOnThread] uses the size of the slices array as follows
-     * instead of using the ThreadLocal count:
+     * test should fail if [TraceContextElement.restoreThreadContext] uses the size of the slices
+     * array in [TraceData] as follows instead of using the `ThreadLocal` count stored in the
+     * [TraceStorage.openSliceCount] array:
      * ```
      * class TraceData {
      *   ...
+     *   // BAD:
      *   fun endAllOnThread() {
-     *     repeat(slices.size) {
+     *     repeat(data.slices.size) {
      *       // THIS WOULD BE AN ERROR. If the thread is slow, the TraceData object could have been
-     *       // modified by another thread
+     *       // modified by another thread, meaning `data.slices.size` would be incorrect for the
+     *       // current thread.
      *       endSlice()
      *     }
      *   ...
@@ -113,7 +119,8 @@ class CoroutineTracingMachineryTest : TestBase() {
      */
     @Test
     fun coroutineMachinery() {
-        assertNull(traceThreadLocal.get())
+        assertNotNull(traceThreadLocal.get())
+        assertNull(traceThreadLocal.get()?.data)
 
         val thread1ResumptionPoint = CyclicBarrier(2)
         val thread1SuspensionPoint = CyclicBarrier(2)
@@ -124,23 +131,32 @@ class CoroutineTracingMachineryTest : TestBase() {
         val slicesForThread2 = listOf("b", "d", "f", "h")
         var failureOnThread1: Error? = null
         var failureOnThread2: Error? = null
-
-        val expectedTraceForThread1 = arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g")
+        val expectedTraceForThread1 =
+            arrayOf("main", "1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g")
 
         val traceContext =
-            createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
-                as TraceContextElement
+            TraceContextElement(
+                name = "main",
+                isRoot = false,
+                countContinuations = false,
+                walkStackForDefaultNames = false,
+                shouldIgnoreClassName = { false },
+                parentId = null,
+                inheritedTracePrefix = "",
+                coroutineDepth = -1,
+            )
         thread1.execute {
-            try {
-                slicesForThread1.forEachIndexed { index, sliceName ->
-                    assertNull(traceThreadLocal.get())
-                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
+            slicesForThread1.forEachIndexed { index, sliceName ->
+                try {
+                    assertNotNull(traceThreadLocal.get())
+                    assertNull(traceThreadLocal.get()?.data)
+                    val oldTrace = traceContext.updateThreadContext(traceContext)
                     // await() AFTER updateThreadContext, thus thread #1 always resumes the
                     // coroutine before thread #2
-                    assertSame(traceThreadLocal.get(), traceContext.contextTraceData)
+                    assertSame(traceThreadLocal.get()!!.data, traceContext.contextTraceData)
 
                     // coroutine body start {
-                    (traceThreadLocal.get() as TraceData).beginSpan("1:$sliceName")
+                    (traceThreadLocal.get() as TraceStorage).beginCoroutineTrace("1:$sliceName")
 
                     // At the end, verify the interleaved trace sections look correct:
                     if (index == slicesForThread1.size - 1) {
@@ -148,33 +164,34 @@ class CoroutineTracingMachineryTest : TestBase() {
                     }
 
                     // simulate a slow thread, wait to call restoreThreadContext until after thread
-                    // A
-                    // has resumed
+                    // A has resumed
                     thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
                     Thread.sleep(500)
                     // } coroutine body end
 
                     traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
                     thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
-                    assertNull(traceThreadLocal.get())
+                    assertNotNull(traceThreadLocal.get())
+                    assertNull(traceThreadLocal.get()?.data)
+                } catch (e: Error) {
+                    failureOnThread1 = e
                 }
-            } catch (e: Error) {
-                failureOnThread1 = e
             }
         }
 
         val expectedTraceForThread2 =
-            arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g", "2:h")
+            arrayOf("main", "1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g", "2:h")
         thread2.execute {
-            try {
-                slicesForThread2.forEachIndexed { i, n ->
-                    assertNull(traceThreadLocal.get())
+            slicesForThread2.forEachIndexed { i, n ->
+                try {
+                    assertNotNull(traceThreadLocal.get())
+                    assertNull(traceThreadLocal.get()?.data)
                     thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
 
-                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
+                    val oldTrace = traceContext.updateThreadContext(traceContext)
 
                     // coroutine body start {
-                    (traceThreadLocal.get() as TraceData).beginSpan("2:$n")
+                    (traceThreadLocal.get() as TraceStorage).beginCoroutineTrace("2:$n")
 
                     // At the end, verify the interleaved trace sections look correct:
                     if (i == slicesForThread2.size - 1) {
@@ -184,10 +201,11 @@ class CoroutineTracingMachineryTest : TestBase() {
 
                     traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
                     thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
-                    assertNull(traceThreadLocal.get())
+                    assertNotNull(traceThreadLocal.get())
+                    assertNull(traceThreadLocal.get()?.data)
+                } catch (e: Error) {
+                    failureOnThread2 = e
                 }
-            } catch (e: Error) {
-                failureOnThread2 = e
             }
         }
 
@@ -204,30 +222,45 @@ class CoroutineTracingMachineryTest : TestBase() {
     fun traceContextIsCopied() = runTest {
         expect()
         val traceContext =
-            createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
-                as TraceContextElement
-        withContext(traceContext) {
-            // Not the same object because it should be copied into the current context
-            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
-            // slices is lazily created, so it should be null:
-            assertNull((traceThreadLocal.get() as TraceData).slices)
-            assertNull(traceContext.contextTraceData?.slices)
-            expect("main:1^")
-            traceCoroutine("hello") {
-                assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
+            createCoroutineTracingContext("main", testMode = true) as TraceContextElement
+        // Root does not have slices:
+        assertNull(traceContext.contextTraceData)
+        launch(traceContext) {
+                // After copying during launch, root still does not have slices:
+                assertNull(traceContext.contextTraceData)
+                // However, the copied object has slices:
+                val currentTce = currentCoroutineContext()[TraceContextElement]
+                assertNotNull(currentTce)
+                assertNotNull(currentTce!!.contextTraceData)
+                assertSame(traceThreadLocal.get()!!.data, currentTce.contextTraceData)
+                // slices is lazily created, so it should not be initialized yet:
+                assertThrows(UninitializedPropertyAccessException::class.java) {
+                    (traceThreadLocal.get()!!.data as TraceData).slices
+                }
+                assertThrows(UninitializedPropertyAccessException::class.java) {
+                    currentTce.contextTraceData!!.slices
+                }
+                expect("1^main")
+                traceCoroutine("hello") {
+                    // Not the same object because it should be copied into the current context
+                    assertNotSame(traceThreadLocal.get()!!.data, traceContext.contextTraceData)
+                    assertArrayEquals(
+                        arrayOf("hello"),
+                        (traceThreadLocal.get()!!.data as TraceData).slices.toArray(),
+                    )
+                    assertNull(traceContext.contextTraceData?.slices)
+                }
+                assertNotSame(traceThreadLocal.get()!!.data, traceContext.contextTraceData)
+                // Because slices is lazily created, it will no longer be uninitialized after it was
+                // used to trace "hello", but this time it will be empty
                 assertArrayEquals(
-                    arrayOf("hello"),
-                    (traceThreadLocal.get() as TraceData).slices?.toArray(),
+                    arrayOf(),
+                    (traceThreadLocal.get()!!.data as TraceData).slices.toArray(),
                 )
                 assertNull(traceContext.contextTraceData?.slices)
+                expect("1^main")
             }
-            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
-            // Because slices is lazily created, it will no longer be null after it was used to
-            // trace "hello", but this time it will be empty
-            assertArrayEquals(arrayOf(), (traceThreadLocal.get() as TraceData).slices?.toArray())
-            assertNull(traceContext.contextTraceData?.slices)
-            expect("main:1^")
-        }
+            .join()
         expect()
     }
 }
diff --git a/tracinglib/robolectric/src/CoroutineTracingTest.kt b/tracinglib/robolectric/src/CoroutineTracingTest.kt
index 8cc3e2e..9d96450 100644
--- a/tracinglib/robolectric/src/CoroutineTracingTest.kt
+++ b/tracinglib/robolectric/src/CoroutineTracingTest.kt
@@ -14,111 +14,231 @@
  * limitations under the License.
  */
 
+@file:OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
+
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.TraceContextElement
 import com.android.app.tracing.coroutines.coroutineScopeTraced
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.launchTraced
-import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.withContextTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CompletableDeferred
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.cancelChildren
+import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
+import kotlinx.coroutines.withContext
 import org.junit.Assert.assertEquals
+import org.junit.Assert.assertTrue
 import org.junit.Test
 
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class CoroutineTracingTest : TestBase() {
 
-    override val extraCoroutineContext: CoroutineContext
-        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+    @Test
+    fun simpleTraceSection() =
+        runTest(finalEvent = 2) {
+            expect(1, "1^main")
+            delay(1)
+            expect(2, "1^main")
+        }
 
     @Test
-    fun simpleTraceSection() = runTest {
-        expectD(1, "main:1^")
-        traceCoroutine("hello") { expectD(2, "main:1^", "hello") }
-        finish(3, "main:1^")
-    }
+    fun traceSectionFromScope() =
+        runTest(finalEvent = 2) {
+            traceCoroutine("hello") {
+                expect(1, "1^main", "hello")
+                delay(1)
+                expect(2, "1^main", "hello")
+            }
+        }
 
     @Test
-    fun simpleNestedTraceSection() = runTest {
-        expectD(1, "main:1^")
-        traceCoroutine("hello") {
-            expectD(2, "main:1^", "hello")
-            traceCoroutine("world") { expectD(3, "main:1^", "hello", "world") }
-            expectD(4, "main:1^", "hello")
-        }
-        finish(5, "main:1^")
-    }
+    fun testCoroutineScope() =
+        runTest(finalEvent = 2) {
+            coroutineScope { expect(1, "1^main") }
+            expect(2, "1^main")
+        }
 
     @Test
-    fun simpleLaunch() = runTest {
-        expectD(1, "main:1^")
-        traceCoroutine("hello") {
-            expectD(2, "main:1^", "hello")
-            launch {
-                // "hello" is not passed to child scope
-                finish(4, "main:1^:1^")
+    fun simpleNestedTraceSection() =
+        runTest(finalEvent = 10) {
+            expect(1, "1^main")
+            delay(1)
+            expect(2, "1^main")
+            traceCoroutine("hello") {
+                expect(3, "1^main", "hello")
+                delay(1)
+                expect(4, "1^main", "hello")
+                traceCoroutine("world") {
+                    expect(5, "1^main", "hello", "world")
+                    delay(1)
+                    expect(6, "1^main", "hello", "world")
+                }
+                expect(7, "1^main", "hello")
+                delay(1)
+                expect(8, "1^main", "hello")
             }
+            expect(9, "1^main")
+            delay(1)
+            expect(10, "1^main")
+        }
+
+    @Test
+    fun simpleLaunch() {
+        val barrier = CompletableDeferred<Unit>()
+        runTest(finalEvent = 7) {
+            expect(1, "1^main")
+            delay(1)
+            expect(2, "1^main")
+            traceCoroutine("hello") {
+                expect(3, "1^main", "hello")
+                delay(1)
+                expect(4, "1^main", "hello")
+                launch {
+                    expect(5, "1^main:1^")
+                    delay(1)
+                    // "hello" is not passed to child scope
+                    expect(6, "1^main:1^")
+                    barrier.complete(Unit)
+                }
+            }
+            barrier.await()
+            expect(7, "1^main")
         }
-        expect(3, "main:1^")
     }
 
     @Test
-    fun launchWithSuspendingLambda() = runTest {
-        val fetchData: suspend () -> String = {
-            expect(3, "main:1^:1^span-for-launch")
-            delay(1L)
-            traceCoroutine("span-for-fetchData") {
-                expect(4, "main:1^:1^span-for-launch", "span-for-fetchData")
+    fun launchWithSuspendingLambda() =
+        runTest(finalEvent = 5) {
+            val fetchData: suspend () -> String = {
+                expect(3, "1^main:1^span-for-launch")
+                delay(1L)
+                traceCoroutine("span-for-fetchData") {
+                    expect(4, "1^main:1^span-for-launch", "span-for-fetchData")
+                }
+                "stuff"
+            }
+            expect(1, "1^main")
+            launchTraced("span-for-launch") {
+                assertEquals("stuff", fetchData())
+                expect(5, "1^main:1^span-for-launch")
             }
-            "stuff"
+            expect(2, "1^main")
         }
-        expect(1, "main:1^")
-        launchTraced("span-for-launch") {
-            assertEquals("stuff", fetchData())
-            finish(5, "main:1^:1^span-for-launch")
+
+    @Test
+    fun stressTestContextSwitches() =
+        runTest(totalEvents = 800) {
+            repeat(200) {
+                listOf(bgThread1, bgThread2, bgThread3, bgThread4).forEach {
+                    launch(it) {
+                        traceCoroutine("a") {
+                            delay(1)
+                            expectEndsWith("a")
+                        }
+                    }
+                }
+            }
         }
-        expect(2, "main:1^")
+
+    @Test
+    fun stressTestContextSwitches_depth() {
+        fun CoroutineScope.recursivelyLaunch(n: Int) {
+            if (n == 0) return
+            launchTraced("launch#$n", start = CoroutineStart.UNDISPATCHED) {
+                traceCoroutine("a") {
+                    recursivelyLaunch(n - 1)
+                    delay(1)
+                    expectEndsWith("a")
+                }
+            }
+        }
+        runTest(totalEvents = 400) { recursivelyLaunch(400) }
     }
 
+    @Test
+    fun withContext_incorrectUsage() =
+        runTest(finalEvent = 4) {
+            assertTrue(coroutineContext[CoroutineTraceName] is TraceContextElement)
+            expect(1, "1^main")
+            withContext(CoroutineTraceName("inside-withContext")) { // <-- BAD, DON'T DO THIS
+                // This is why CoroutineTraceName() should not be used this way, it overwrites the
+                // TraceContextElement. Because it is not a CopyableThreadContextElement, it is
+                // not given opportunity to merge with the parent trace context.
+                // While we could make CoroutineTraceName a CopyableThreadContextElement, it would
+                // add too much overhead to tracing, especially for flows where operation fusion
+                // is common.
+                assertTrue(coroutineContext[CoroutineTraceName] is CoroutineTraceName)
+
+                // The result of replacing the `TraceContextElement` with `CoroutineTraceName` is
+                // that
+                // tracing doesn't happen:
+                expect(2, "1^main") // <-- Trace section from before withContext is open until the
+                //                          first suspension
+                delay(1)
+                expect(3)
+            }
+            expect(4, "1^main")
+        }
+
+    @Test
+    fun withContext_correctUsage() =
+        runTest(finalEvent = 4) {
+            expect(1, "1^main")
+            withContextTraced("inside-withContext", EmptyCoroutineContext) {
+                assertTrue(coroutineContext[CoroutineTraceName] is TraceContextElement)
+                expect(2, "1^main", "inside-withContext")
+                delay(1)
+                expect(3, "1^main", "inside-withContext")
+            }
+            expect(4, "1^main")
+        }
+
     @Test
     fun launchInCoroutineScope() = runTest {
         launchTraced("launch#0") {
-            expect("main:1^:1^launch#0")
+            expect("1^main:1^launch#0")
             delay(1)
-            expect("main:1^:1^launch#0")
+            expect("1^main:1^launch#0")
         }
         coroutineScopeTraced("span-for-coroutineScope-1") {
             launchTraced("launch#1") {
-                expect("main:1^:2^launch#1")
+                expect("1^main:2^launch#1")
                 delay(1)
-                expect("main:1^:2^launch#1")
+                expect("1^main:2^launch#1")
             }
             launchTraced("launch#2") {
-                expect("main:1^:3^launch#2")
+                expect("1^main:3^launch#2")
                 delay(1)
-                expect("main:1^:3^launch#2")
+                expect("1^main:3^launch#2")
             }
             coroutineScopeTraced("span-for-coroutineScope-2") {
                 launchTraced("launch#3") {
-                    expect("main:1^:4^launch#3")
+                    expect("1^main:4^launch#3")
                     delay(1)
-                    expect("main:1^:4^launch#3")
+                    expect("1^main:4^launch#3")
                 }
                 launchTraced("launch#4") {
-                    expect("main:1^:5^launch#4")
+                    expect("1^main:5^launch#4")
                     delay(1)
-                    expect("main:1^:5^launch#4")
+                    expect("1^main:5^launch#4")
                 }
             }
         }
         launchTraced("launch#5") {
-            expect("main:1^:6^launch#5")
+            expect("1^main:6^launch#5")
             delay(1)
-            expect("main:1^:6^launch#5")
+            expect("1^main:6^launch#5")
         }
     }
 
@@ -126,72 +246,144 @@ class CoroutineTracingTest : TestBase() {
     fun namedScopeMerging() = runTest {
         // to avoid race conditions in the test leading to flakes, avoid calling expectD() or
         // delaying before launching (e.g. only call expectD() in leaf blocks)
-        expect("main:1^")
+        expect("1^main")
         launchTraced("A") {
-            expect("main:1^:1^A")
-            traceCoroutine("span") { expectD("main:1^:1^A", "span") }
-            launchTraced("B") { expectD("main:1^:1^A:1^B") }
+            expect("1^main:1^A")
+            traceCoroutine("span") { expectD("1^main:1^A", "span") }
+            launchTraced("B") { expectD("1^main:1^A:1^B") }
             launchTraced("C") {
-                expect("main:1^:1^A:2^C")
-                launch { expectD("main:1^:1^A:2^C:1^") }
-                launchTraced("D") { expectD("main:1^:1^A:2^C:2^D") }
+                expect("1^main:1^A:2^C")
+                launch { expectD("1^main:1^A:2^C:1^") }
+                launchTraced("D") { expectD("1^main:1^A:2^C:2^D") }
                 launchTraced("E") {
-                    expect("main:1^:1^A:2^C:3^E")
-                    launchTraced("F") { expectD("main:1^:1^A:2^C:3^E:1^F") }
-                    expect("main:1^:1^A:2^C:3^E")
+                    expect("1^main:1^A:2^C:3^E")
+                    launchTraced("F") { expectD("1^main:1^A:2^C:3^E:1^F") }
+                    expect("1^main:1^A:2^C:3^E")
                 }
             }
-            launchTraced("G") { expectD("main:1^:1^A:3^G") }
+            launchTraced("G") { expectD("1^main:1^A:3^G") }
         }
-        launch { launch { launch { expectD("main:1^:2^:1^:1^") } } }
+        launch { launch { launch { expectD("1^main:2^:1^:1^") } } }
         delay(2)
-        launchTraced("H") { launch { launch { expectD("main:1^:3^H:1^:1^") } } }
+        launchTraced("H") { launch { launch { expectD("1^main:3^H:1^:1^") } } }
         delay(2)
         launch {
             launch {
                 launch {
-                    launch {
-                        launch { launchTraced("I") { expectD("main:1^:4^:1^:1^:1^:1^:1^I") } }
-                    }
+                    launch { launch { launchTraced("I") { expectD("1^main:4^:1^:1^:1^:1^:1^I") } } }
                 }
             }
         }
         delay(2)
         launchTraced("J") {
-            launchTraced("K") { launch { launch { expectD("main:1^:5^J:1^K:1^:1^") } } }
+            launchTraced("K") { launch { launch { expectD("1^main:5^J:1^K:1^:1^") } } }
         }
         delay(2)
         launchTraced("L") {
-            launchTraced("M") { launch { launch { expectD("main:1^:6^L:1^M:1^:1^") } } }
+            launchTraced("M") { launch { launch { expectD("1^main:6^L:1^M:1^:1^") } } }
         }
         delay(2)
         launchTraced("N") {
-            launchTraced("O") { launch { launchTraced("D") { expectD("main:1^:7^N:1^O:1^:1^D") } } }
+            launchTraced("O") { launch { launchTraced("D") { expectD("1^main:7^N:1^O:1^:1^D") } } }
         }
         delay(2)
         launchTraced("P") {
-            launchTraced("Q") { launch { launchTraced("R") { expectD("main:1^:8^P:1^Q:1^:1^R") } } }
+            launchTraced("Q") { launch { launchTraced("R") { expectD("1^main:8^P:1^Q:1^:1^R") } } }
         }
         delay(2)
-        launchTraced("S") { launchTraced("T") { launch { expectD("main:1^:9^S:1^T:1^") } } }
+        launchTraced("S") { launchTraced("T") { launch { expectD("1^main:9^S:1^T:1^") } } }
         delay(2)
-        launchTraced("U") { launchTraced("V") { launch { expectD("main:1^:10^U:1^V:1^") } } }
+        launchTraced("U") { launchTraced("V") { launch { expectD("1^main:10^U:1^V:1^") } } }
         delay(2)
-        expectD("main:1^")
+        expectD("1^main")
     }
 
     @Test
-    fun launchIntoSelf() = runTest {
-        expectD("main:1^")
-        val reusedNameContext = nameCoroutine("my-coroutine")
-        launch(reusedNameContext) {
-            expectD("main:1^:1^my-coroutine")
-            launch(reusedNameContext) { expectD("main:1^:1^my-coroutine:1^my-coroutine") }
-            expectD("main:1^:1^my-coroutine")
-            launch(reusedNameContext) { expectD("main:1^:1^my-coroutine:2^my-coroutine") }
-            expectD("main:1^:1^my-coroutine")
-        }
-        launch(reusedNameContext) { expectD("main:1^:2^my-coroutine") }
-        expectD("main:1^")
-    }
+    fun launchIntoSelf() =
+        runTest(finalEvent = 11) {
+            expect(1, "1^main")
+            delay(1)
+            expect(2, "1^main")
+            val reusedNameContext = CoroutineTraceName("my-coroutine")
+            launch(reusedNameContext) {
+                expect(3, "1^main:1^my-coroutine")
+                delay(1)
+                expect(4, "1^main:1^my-coroutine")
+                launch(reusedNameContext) {
+                    expect(5, "1^main:1^my-coroutine:1^my-coroutine")
+                    delay(5)
+                    expect(8, "1^main:1^my-coroutine:1^my-coroutine")
+                }
+                delay(1)
+                expect(6, "1^main:1^my-coroutine")
+                launch(reusedNameContext) {
+                    expect(7, "1^main:1^my-coroutine:2^my-coroutine")
+                    delay(7)
+                    expect(9, "1^main:1^my-coroutine:2^my-coroutine")
+                }
+                delay(10)
+                expect(10, "1^main:1^my-coroutine")
+            }
+            launch(reusedNameContext) {
+                delay(20)
+                expect(11, "1^main:2^my-coroutine")
+            }
+        }
+
+    @Test
+    fun undispatchedLaunch() =
+        runTest(totalEvents = 4) {
+            launchTraced("AAA", start = CoroutineStart.UNDISPATCHED) {
+                expect("1^main", "1^main:1^AAA")
+                launchTraced("BBB", start = CoroutineStart.UNDISPATCHED) {
+                    traceCoroutine("delay-5") {
+                        expect("1^main", "1^main:1^AAA", "1^main:1^AAA:1^BBB", "delay-5")
+                        delay(5)
+                        expect("1^main:1^AAA:1^BBB", "delay-5")
+                    }
+                }
+            }
+            expect("1^main")
+        }
+
+    @Test
+    fun undispatchedLaunch_cancelled() =
+        runTest(totalEvents = 11) {
+            traceCoroutine("hello") { expect("1^main", "hello") }
+            val job =
+                launchTraced("AAA", start = CoroutineStart.UNDISPATCHED) {
+                    expect("1^main", "1^main:1^AAA")
+                    traceCoroutine("delay-50") {
+                        expect("1^main", "1^main:1^AAA", "delay-50")
+                        launchTraced("BBB", start = CoroutineStart.UNDISPATCHED) {
+                                traceCoroutine("BBB:delay-25") {
+                                    expect(
+                                        "1^main",
+                                        "1^main:1^AAA",
+                                        "delay-50",
+                                        "1^main:1^AAA:1^BBB",
+                                        "BBB:delay-25",
+                                    )
+                                    delay(25)
+                                    expect("1^main:1^AAA:1^BBB", "BBB:delay-25")
+                                }
+                            }
+                            .join()
+                        expect("1^main:1^AAA", "delay-50")
+                        delay(25)
+                    }
+                }
+            launchTraced("CCC") {
+                traceCoroutine("delay-35") {
+                    expect("1^main:2^CCC", "delay-35")
+                    delay(35)
+                    expect("1^main:2^CCC", "delay-35")
+                }
+                job.cancelChildren()
+                expect("1^main:2^CCC")
+                job.join()
+                expect("1^main:2^CCC")
+            }
+            expect("1^main")
+        }
 }
diff --git a/tracinglib/robolectric/src/DefaultNamingTest.kt b/tracinglib/robolectric/src/DefaultNamingTest.kt
index d940377..91af322 100644
--- a/tracinglib/robolectric/src/DefaultNamingTest.kt
+++ b/tracinglib/robolectric/src/DefaultNamingTest.kt
@@ -14,185 +14,183 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
+
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.asyncTraced
 import com.android.app.tracing.coroutines.flow.collectLatestTraced
 import com.android.app.tracing.coroutines.flow.collectTraced
 import com.android.app.tracing.coroutines.flow.filterTraced
-import com.android.app.tracing.coroutines.flow.flowName
 import com.android.app.tracing.coroutines.flow.mapTraced
 import com.android.app.tracing.coroutines.flow.transformTraced
 import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.withContextTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.cancel
+import kotlinx.coroutines.cancelChildren
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.FlowCollector
 import kotlinx.coroutines.flow.SharingStarted
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.shareIn
-import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.job
 import kotlinx.coroutines.withContext
 import org.junit.Assert.assertEquals
 import org.junit.Test
 
-/** Tests behavior of default names, whether that's via stack walking or reflection */
+/** Tests behavior of default names using reflection */
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class DefaultNamingTest : TestBase() {
 
-    override val extraCoroutineContext: CoroutineContext
-        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
-
-    fun namedCollectFun() {}
-
     @Test
-    fun collectTraced1() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced1$1$4")
-                emit(21) // 21 * 2 = 42
-                expect(6, "main:1^", "collect:DefaultNamingTest\$collectTraced1$1$4")
-            }
-            .mapTraced("2x") {
-                expect(
-                    3,
-                    "main:1^",
-                    "collect:DefaultNamingTest\$collectTraced1$1$4",
-                    "map:2x:transform",
-                )
-                it * 2 // 42
-            }
-            .flowName("UNUSED_NAME") // unused because scope is unchanged
-            .filterTraced("mod2") {
-                expect(
-                    4,
-                    "main:1^",
-                    "collect:DefaultNamingTest\$collectTraced1$1$4",
-                    "map:2x:emit",
-                    "filter:mod2:predicate",
-                )
-                it % 2 == 0 // true
-            }
-            .collectTraced {
+    fun collectTraced1() {
+        val coldFlow =
+            flow {
+                    expect(2, "1^main", "collect:DefaultNamingTest\$collectTraced1$1$1")
+                    emit(21) // 21 * 2 = 42
+                    expect(6, "1^main", "collect:DefaultNamingTest\$collectTraced1$1$1")
+                }
+                .mapTraced("2x") {
+                    expect(3, "1^main", "collect:DefaultNamingTest\$collectTraced1$1$1", "2x")
+                    it * 2 // 42
+                }
+                .filterTraced("mod2") {
+                    expect(4, "1^main", "collect:DefaultNamingTest\$collectTraced1$1$1", "mod2")
+                    it % 2 == 0 // true
+                }
+        runTest(finalEvent = 7) {
+            expect(1, "1^main")
+            coldFlow.collectTraced {
                 assertEquals(42, it) // 21 * 2 = 42
                 expect(
                     5,
-                    "main:1^",
-                    "collect:DefaultNamingTest\$collectTraced1$1$4",
-                    "map:2x:emit",
-                    "filter:mod2:emit",
-                    "collect:DefaultNamingTest\$collectTraced1$1$4:emit",
+                    "1^main",
+                    "collect:DefaultNamingTest\$collectTraced1$1$1",
+                    "emit:DefaultNamingTest\$collectTraced1$1$1",
                 )
             }
-        finish(7, "main:1^")
+            expect(7, "1^main")
+        }
     }
 
     @Test
-    fun collectTraced2() = runTest {
-        expect(1, "main:1^") // top-level scope
-
-        flow {
-                expect(2, "main:1^:1^") // child scope used by `collectLatest {}`
-                emit(1) // should not get used by collectLatest {}
-                expect(6, "main:1^:1^")
-                emit(21) // 21 * 2 = 42
-                expect(10, "main:1^:1^")
-            }
-            .filterTraced("mod2") {
-                expect(listOf(3, 7), "main:1^:1^", "filter:mod2:predicate")
-                it % 2 == 1 // true
-            }
-            .mapTraced("2x") {
-                expect(listOf(4, 8), "main:1^:1^", "filter:mod2:emit", "map:2x:transform")
-                it * 2 // 42
-            }
-            // this name won't be used because it's not passed the scope used by mapLatest{}, which
-            // is an internal implementation detail in kotlinx
-            .flowName("UNUSED_NAME")
-            .collectLatestTraced {
+    fun collectTraced2() {
+        val coldFlow =
+            flow {
+                    expect(
+                        2,
+                        "1^main:1^",
+                        "collect:collectLatest:DefaultNamingTest\$collectTraced2$1$1",
+                    ) // child scope used by `collectLatest {}`
+                    emit(1) // should not get used by collectLatest {}
+                    expect(
+                        6,
+                        "1^main:1^",
+                        "collect:collectLatest:DefaultNamingTest\$collectTraced2$1$1",
+                    )
+                    emit(21) // 21 * 2 = 42
+                    expect(
+                        10,
+                        "1^main:1^",
+                        "collect:collectLatest:DefaultNamingTest\$collectTraced2$1$1",
+                    )
+                }
+                .filterTraced("mod2") {
+                    expect(
+                        listOf(3, 7),
+                        "1^main:1^",
+                        "collect:collectLatest:DefaultNamingTest\$collectTraced2$1$1",
+                        "mod2",
+                    )
+                    it % 2 == 1 // true
+                }
+                .mapTraced("2x") {
+                    expect(
+                        listOf(4, 8),
+                        "1^main:1^",
+                        "collect:collectLatest:DefaultNamingTest\$collectTraced2$1$1",
+                        "2x",
+                    )
+                    it * 2 // 42
+                }
+        runTest(finalEvent = 12) {
+            expect(1, "1^main") // top-level scope
+            coldFlow.collectLatestTraced {
                 expectEvent(listOf(5, 9))
-                delay(10)
+                delay(50)
                 assertEquals(42, it) // 21 * 2 = 42
-                expect(
-                    11,
-                    "main:1^:1^:2^",
-                    "collectLatest:DefaultNamingTest\$collectTraced2$1$4:action",
-                )
+                expect(11, "1^main:1^:2^", "DefaultNamingTest\$collectTraced2$1$1")
             }
-        finish(12, "main:1^")
+            expect(12, "1^main")
+        }
     }
 
     @Test
-    fun collectTraced3() = runTest {
-        expect(1, "main:1^") // top-level scope
+    fun collectTraced3() =
+        runTest(finalEvent = 8) {
+            expect(1, "1^main") // top-level scope
 
-        val sharedFlow =
-            flow {
-                    expect(2, "main:1^:1^")
-                    delay(1)
-                    emit(22)
-                    expect(3, "main:1^:1^")
-                    delay(1)
-                    emit(32)
-                    expect(4, "main:1^:1^")
-                    delay(1)
-                    emit(42)
-                    expect(5, "main:1^:1^")
-                } // there is no API for passing a custom context to the new shared flow, so weg
-                // can't pass our custom child name using `nameCoroutine()`
-                .shareIn(this, SharingStarted.Eagerly, 4)
+            val sharedFlow =
+                flow {
+                        expect(2, "1^main:1^")
+                        delay(1)
+                        emit(22)
+                        expect(3, "1^main:1^")
+                        delay(1)
+                        emit(32)
+                        expect(4, "1^main:1^")
+                        delay(1)
+                        emit(42)
+                        expect(5, "1^main:1^")
+                    } // there is no API for passing a custom context to the new shared flow, so we
+                    // can't pass our custom child name using `CoroutineTraceName()`
+                    .shareIn(this, SharingStarted.Eagerly, 4)
 
-        launchTraced("AAAA") {
-            sharedFlow.collectLatestTraced {
-                delay(10)
-                expect(
-                    6,
-                    "main:1^:2^AAAA:1^:3^",
-                    "collectLatest:DefaultNamingTest\$collectTraced3$1$1$1:action",
-                )
+            launchTraced("AAAA") {
+                sharedFlow.collectLatestTraced {
+                    delay(10)
+                    expect(6, "1^main:2^AAAA:1^:3^", "DefaultNamingTest\$collectTraced3$1$1$1")
+                }
             }
-        }
-        launchTraced("BBBB") {
-            sharedFlow.collectLatestTraced {
-                delay(40)
-                assertEquals(42, it)
-                expect(
-                    7,
-                    "main:1^:3^BBBB:1^:3^",
-                    "collectLatest:DefaultNamingTest\$collectTraced3$1$2$1:action",
-                )
+            launchTraced("BBBB") {
+                sharedFlow.collectLatestTraced {
+                    delay(40)
+                    assertEquals(42, it)
+                    expect(7, "1^main:3^BBBB:1^:3^", "DefaultNamingTest\$collectTraced3$1$2$1")
+                }
             }
-        }
 
-        delay(50)
-        finish(8, "main:1^")
-        cancel()
-    }
+            delay(70)
+            expect(8, "1^main")
+            coroutineContext.job.cancelChildren()
+        }
 
     @Test
-    fun collectTraced4() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced4$1$2")
-                emit(42)
-                expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced4$1$2")
-            }
-            .collectTraced {
-                assertEquals(42, it)
-                expect(
-                    3,
-                    "main:1^",
-                    "collect:DefaultNamingTest\$collectTraced4$1$2",
-                    "collect:DefaultNamingTest\$collectTraced4$1$2:emit",
-                )
-            }
-        finish(5, "main:1^")
-    }
+    fun collectTraced4() =
+        runTest(finalEvent = 5) {
+            expect(1, "1^main")
+            flow {
+                    expect(2, "1^main", "collect:DefaultNamingTest\$collectTraced4$1$2")
+                    emit(42)
+                    expect(4, "1^main", "collect:DefaultNamingTest\$collectTraced4$1$2")
+                }
+                .collectTraced {
+                    assertEquals(42, it)
+                    expect(
+                        3,
+                        "1^main",
+                        "collect:DefaultNamingTest\$collectTraced4$1$2",
+                        "emit:DefaultNamingTest\$collectTraced4$1$2",
+                    )
+                }
+            expect(5, "1^main")
+        }
 
     @Test
     fun collectTraced5_localFun() {
@@ -200,20 +198,20 @@ class DefaultNamingTest : TestBase() {
             assertEquals(42, value)
             expect(
                 3,
-                "main:1^",
+                "1^main",
                 "collect:DefaultNamingTest\$collectTraced5_localFun$1$2",
-                "collect:DefaultNamingTest\$collectTraced5_localFun$1$2:emit",
+                "emit:DefaultNamingTest\$collectTraced5_localFun$1$2",
             )
         }
-        return runTest {
-            expect(1, "main:1^")
+        return runTest(finalEvent = 5) {
+            expect(1, "1^main")
             flow {
-                    expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
+                    expect(2, "1^main", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
                     emit(42)
-                    expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
+                    expect(4, "1^main", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
                 }
                 .collectTraced(::localFun)
-            finish(5, "main:1^")
+            expect(5, "1^main")
         }
     }
 
@@ -221,143 +219,171 @@ class DefaultNamingTest : TestBase() {
         assertEquals(42, value)
         expect(
             3,
-            "main:1^",
+            "1^main",
             "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2",
-            "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2:emit",
+            "emit:DefaultNamingTest\$collectTraced6_memberFun$1$2",
         )
     }
 
     @Test
-    fun collectTraced6_memberFun() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
-                emit(42)
-                expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
-            }
-            .collectTraced(::memberFun)
-        finish(5, "main:1^")
-    }
-
-    @Test
-    fun collectTraced7_topLevelFun() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
-                emit(42)
-                expect(3, "main:1^", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
-            }
-            .collectTraced(::topLevelFun)
-        finish(4, "main:1^")
-    }
-
-    @Test
-    fun collectTraced8_localFlowObject() = runTest {
-        expect(1, "main:1^")
-        val flowObj =
-            object : Flow<Int> {
-                override suspend fun collect(collector: FlowCollector<Int>) {
-                    expect(
-                        2,
-                        "main:1^",
-                        "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
-                    )
-                    collector.emit(42)
-                    expect(
-                        4,
-                        "main:1^",
-                        "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
-                    )
+    fun collectTraced6_memberFun() =
+        runTest(finalEvent = 5) {
+            expect(1, "1^main")
+            flow {
+                    expect(2, "1^main", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
+                    emit(42)
+                    expect(4, "1^main", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
                 }
-            }
-        flowObj.collectTraced {
-            assertEquals(42, it)
-            expect(
-                3,
-                "main:1^",
-                "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
-                "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1:emit",
-            )
+                .collectTraced(::memberFun)
+            expect(5, "1^main")
         }
-        finish(5, "main:1^")
-    }
 
     @Test
-    fun collectTraced9_flowObjectWithClassName() = runTest {
-        expect(1, "main:1^")
-        FlowWithName(this@DefaultNamingTest).collectTraced {
-            assertEquals(42, it)
-            expect(
-                3,
-                "main:1^",
-                "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
-                "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1:emit",
-            )
+    fun collectTraced7_topLevelFun() =
+        runTest(finalEvent = 4) {
+            expect(1, "1^main")
+            flow {
+                    expect(2, "1^main", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
+                    emit(42)
+                    expect(3, "1^main", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
+                }
+                .collectTraced(::topLevelFun)
+            expect(4, "1^main")
         }
-        finish(5, "main:1^")
-    }
 
     @Test
-    fun collectTraced10_flowCollectorObjectWithClassName() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:FlowCollectorWithName")
-                emit(42)
-                expect(4, "main:1^", "collect:FlowCollectorWithName")
+    fun collectTraced8_localFlowObject() =
+        runTest(finalEvent = 5) {
+            expect(1, "1^main")
+            val flowObj =
+                object : Flow<Int> {
+                    override suspend fun collect(collector: FlowCollector<Int>) {
+                        expect(
+                            2,
+                            "1^main",
+                            "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                        )
+                        collector.emit(42)
+                        expect(
+                            4,
+                            "1^main",
+                            "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                        )
+                    }
+                }
+            flowObj.collectTraced {
+                assertEquals(42, it)
+                expect(
+                    3,
+                    "1^main",
+                    "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                    "emit:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                )
             }
-            .collectTraced(FlowCollectorWithName(this@DefaultNamingTest))
-        finish(5, "main:1^")
-    }
+            expect(5, "1^main")
+        }
 
     @Test
-    fun collectTraced11_transform() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:COLLECT")
-                emit(42)
-                expect(7, "main:1^", "collect:COLLECT")
-            }
-            .transformTraced("TRANSFORM") {
-                expect(3, "main:1^", "collect:COLLECT", "TRANSFORM:emit")
-                emit(it)
-                emit(it * 2)
-                emit(it * 4)
-            }
-            .collectTraced("COLLECT") {
+    fun collectTraced9_flowObjectWithClassName() =
+        runTest(finalEvent = 5) {
+            expect(1, "1^main")
+            FlowWithName(this@DefaultNamingTest).collectTraced {
+                assertEquals(42, it)
                 expect(
-                    listOf(4, 5, 6),
-                    "main:1^",
-                    "collect:COLLECT",
-                    "TRANSFORM:emit",
-                    "collect:COLLECT:emit",
+                    3,
+                    "1^main",
+                    "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
+                    "emit:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
                 )
             }
-        finish(8, "main:1^")
-    }
+            expect(5, "1^main")
+        }
 
-    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
     @Test
-    fun collectTraced12_badTransform() =
-        runTest(
-            expectedException = { e ->
-                return@runTest e is java.lang.IllegalStateException &&
-                    (e.message?.startsWith("Flow invariant is violated") ?: false)
-            }
-        ) {
-            val thread1 = newSingleThreadContext("thread-#1")
-            expect(1, "main:1^")
+    fun collectTraced10_flowCollectorObjectWithClassName() =
+        runTest(finalEvent = 5) {
+            expect(1, "1^main")
             flow {
-                    expect(2, "main:1^", "collect:COLLECT")
+                    expect(2, "1^main", "collect:FlowCollectorWithName")
                     emit(42)
-                    expect(4, "main:1^", "collect:COLLECT")
+                    expect(4, "1^main", "collect:FlowCollectorWithName")
+                }
+                .collectTraced(FlowCollectorWithName(this@DefaultNamingTest))
+            expect(5, "1^main")
+        }
+
+    @Test
+    fun collectTraced11_transform() =
+        runTest(finalEvent = 8) {
+            expect(1, "1^main")
+            flow {
+                    expect(2, "1^main", "collect:COLLECT")
+                    emit(42)
+                    expect(7, "1^main", "collect:COLLECT")
                 }
                 .transformTraced("TRANSFORM") {
-                    // SHOULD THROW AN EXCEPTION:
-                    withContext(thread1) { emit(it * 2) }
+                    expect(3, "1^main", "collect:COLLECT", "TRANSFORM")
+                    emit(it)
+                    emit(it * 2)
+                    emit(it * 4)
+                }
+                .collectTraced("COLLECT") {
+                    expect(
+                        listOf(4, 5, 6),
+                        "1^main",
+                        "collect:COLLECT",
+                        "TRANSFORM",
+                        "emit:COLLECT",
+                    )
                 }
-                .collectTraced("COLLECT") {}
-            finish(5, "main:1^")
+            expect(8, "1^main")
         }
+
+    @Test
+    fun collectTraced12_badTransform() =
+        runTest(
+            finalEvent = 2,
+            isExpectedException = { e ->
+                e is java.lang.IllegalStateException &&
+                    (e.message?.startsWith("Flow invariant is violated") ?: false)
+            },
+            block = {
+                val thread1 = bgThread1
+                expect(1, "1^main")
+                flow {
+                        expect(2, "1^main", "collect:COLLECT")
+                        emit(42)
+                    }
+                    .transformTraced("TRANSFORM") {
+                        // throws IllegalStateException:
+                        withContext(thread1) { emit(it * 2) } // <-- Flow invariant is violated
+                    }
+                    .collectTraced("COLLECT") {}
+            },
+        )
+
+    @Test
+    fun coroutineBuilder_defaultNames() {
+        val localFun: suspend CoroutineScope.() -> Unit = {
+            expectAny(
+                arrayOf("1^main:4^DefaultNamingTest\$coroutineBuilder_defaultNames\$localFun$1"),
+                arrayOf("1^main", "DefaultNamingTest\$coroutineBuilder_defaultNames\$localFun$1"),
+                arrayOf("1^main:2^DefaultNamingTest\$coroutineBuilder_defaultNames\$localFun$1"),
+            )
+        }
+        runTest(totalEvents = 6) {
+            launchTraced { expect("1^main:1^DefaultNamingTest\$coroutineBuilder_defaultNames$1$1") }
+                .join()
+            launchTraced(block = localFun).join()
+            asyncTraced { expect("1^main:3^DefaultNamingTest\$coroutineBuilder_defaultNames$1$2") }
+                .await()
+            asyncTraced(block = localFun).await()
+            withContextTraced(context = EmptyCoroutineContext) {
+                expect("1^main", "DefaultNamingTest\$coroutineBuilder_defaultNames$1$3")
+            }
+            withContextTraced(context = EmptyCoroutineContext, block = localFun)
+        }
+    }
 }
 
 fun topLevelFun(value: Int) {
@@ -368,13 +394,13 @@ class FlowWithName(private val test: TestBase) : Flow<Int> {
     override suspend fun collect(collector: FlowCollector<Int>) {
         test.expect(
             2,
-            "main:1^",
+            "1^main",
             "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
         )
         collector.emit(42)
         test.expect(
             4,
-            "main:1^",
+            "1^main",
             "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
         )
     }
@@ -383,11 +409,6 @@ class FlowWithName(private val test: TestBase) : Flow<Int> {
 class FlowCollectorWithName(private val test: TestBase) : FlowCollector<Int> {
     override suspend fun emit(value: Int) {
         assertEquals(42, value)
-        test.expect(
-            3,
-            "main:1^",
-            "collect:FlowCollectorWithName",
-            "collect:FlowCollectorWithName:emit",
-        )
+        test.expect(3, "1^main", "collect:FlowCollectorWithName", "emit:FlowCollectorWithName")
     }
 }
diff --git a/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt b/tracinglib/robolectric/src/FlagDisabledTest.kt
similarity index 60%
rename from tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
rename to tracinglib/robolectric/src/FlagDisabledTest.kt
index 159a85a..3c62a37 100644
--- a/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
+++ b/tracinglib/robolectric/src/FlagDisabledTest.kt
@@ -17,30 +17,28 @@
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.DisableFlags
-import android.platform.test.annotations.EnableFlags
-import com.android.app.tracing.coroutines.TraceData
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.coroutines.traceThreadLocal
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
 import com.android.test.tracing.coroutines.util.FakeTraceState
+import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.withContext
-import org.junit.Assert.assertEquals
 import org.junit.Assert.assertFalse
-import org.junit.Assert.assertNotNull
 import org.junit.Assert.assertNull
-import org.junit.Assert.assertTrue
 import org.junit.Assert.fail
 import org.junit.Test
 
-class CoroutineTracingFlagsTest : TestBase() {
+@DisableFlags(FLAG_COROUTINE_TRACING)
+class FlagDisabledTest : TestBase() {
+    override val extraContext: CoroutineContext by lazy { EmptyCoroutineContext }
 
-    @DisableFlags(FLAG_COROUTINE_TRACING)
     @Test
     fun tracingDisabledWhenFlagIsOff() = runTest {
         assertFalse(com.android.systemui.Flags.coroutineTracing())
         assertNull(traceThreadLocal.get())
-        withContext(createCoroutineTracingContext(strictMode = true)) {
+        withContext(createCoroutineTracingContext(testMode = true)) {
             assertNull(traceThreadLocal.get())
             traceCoroutine("hello") { // should not crash
                 assertNull(traceThreadLocal.get())
@@ -60,30 +58,4 @@ class CoroutineTracingFlagsTest : TestBase() {
             }
         }
     }
-
-    @EnableFlags(FLAG_COROUTINE_TRACING)
-    @Test
-    fun lazyStringIsAlwaysCalledOnDebugBuilds() = runTest {
-        FakeTraceState.isTracingEnabled = false
-        assertNull(traceThreadLocal.get())
-        withContext(createCoroutineTracingContext()) {
-            assertNotNull(traceThreadLocal.get())
-
-            // It is expected that the lazy-String is called even when tracing is disabled because
-            // otherwise the coroutine resumption points would be missing names.
-            var lazyStringCalled = false
-            traceCoroutine({
-                lazyStringCalled = true
-                "hello"
-            }) {
-                assertTrue(
-                    "Lazy string should be been called when FLAG_COROUTINE_TRACING is enabled, " +
-                        "even when Trace.isEnabled()=false",
-                    lazyStringCalled,
-                )
-                val traceData = traceThreadLocal.get() as TraceData
-                assertEquals(traceData.slices?.size, 1)
-            }
-        }
-    }
 }
diff --git a/tracinglib/robolectric/src/FlagEnabledTest.kt b/tracinglib/robolectric/src/FlagEnabledTest.kt
new file mode 100644
index 0000000..e32e6b7
--- /dev/null
+++ b/tracinglib/robolectric/src/FlagEnabledTest.kt
@@ -0,0 +1,78 @@
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
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.TraceContextElement
+import com.android.app.tracing.coroutines.TraceData
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.traceThreadLocal
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import com.android.test.tracing.coroutines.util.FakeTraceState
+import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertNotNull
+import org.junit.Assert.assertNotSame
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertTrue
+import org.junit.Test
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class FlagEnabledTest : TestBase() {
+
+    override val extraContext: CoroutineContext by lazy { EmptyCoroutineContext }
+
+    @Test
+    fun lazyStringIsAlwaysCalledOnDebugBuilds() {
+        FakeTraceState.isTracingEnabled = false
+        runTest {
+            assertNotNull(traceThreadLocal.get())
+            // Because nothing was traced yet on this thread, data should be null:
+            assertNull(traceThreadLocal.get()?.data)
+
+            val originalTraceContext = createCoroutineTracingContext(testMode = true)
+            withContext(originalTraceContext) {
+                assertNotSame(
+                    "withContext() should copy the passed TraceContextElement",
+                    originalTraceContext,
+                    coroutineContext[TraceContextElement],
+                )
+                assertNotNull(traceThreadLocal.get())
+
+                // It is expected that the lazy-String is called even when tracing is disabled
+                // because
+                // otherwise the coroutine resumption points would be missing names.
+                var lazyStringCalled = false
+                traceCoroutine({
+                    lazyStringCalled = true
+                    "hello"
+                }) {
+                    assertTrue(
+                        "Lazy string should be been called when FLAG_COROUTINE_TRACING is enabled, " +
+                            "even when Trace.isEnabled()=false",
+                        lazyStringCalled,
+                    )
+                    val traceData = traceThreadLocal.get()!!.data as TraceData
+                    assertEquals(traceData.slices.size, 1)
+                }
+            }
+        }
+    }
+}
diff --git a/tracinglib/robolectric/src/FlowTracingTest.kt b/tracinglib/robolectric/src/FlowTracingTest.kt
index 74a2aa6..39d4ed6 100644
--- a/tracinglib/robolectric/src/FlowTracingTest.kt
+++ b/tracinglib/robolectric/src/FlowTracingTest.kt
@@ -14,278 +14,860 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalCoroutinesApi::class)
+
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.CoroutineTraceName
 import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.flow.collectLatestTraced
 import com.android.app.tracing.coroutines.flow.collectTraced
 import com.android.app.tracing.coroutines.flow.filterTraced
 import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapLatestTraced
 import com.android.app.tracing.coroutines.flow.mapTraced
+import com.android.app.tracing.coroutines.flow.shareInTraced
+import com.android.app.tracing.coroutines.flow.stateInTraced
+import com.android.app.tracing.coroutines.flow.traceAs
+import com.android.app.tracing.coroutines.launchInTraced
 import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import kotlin.coroutines.CoroutineContext
 import kotlinx.coroutines.CompletableDeferred
-import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.cancel
 import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.collect
+import kotlinx.coroutines.flow.collectLatest
 import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOf
 import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.launchIn
 import kotlinx.coroutines.flow.map
-import kotlinx.coroutines.flow.stateIn
-import kotlinx.coroutines.flow.transform
-import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.flow.mapLatest
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.job
+import kotlinx.coroutines.plus
+import kotlinx.coroutines.yield
 import org.junit.Assert.assertEquals
 import org.junit.Test
 
-@OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class FlowTracingTest : TestBase() {
 
-    override val extraCoroutineContext: CoroutineContext
-        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
-
     @Test
-    fun collectFlow1() {
+    fun collectFlow_simple() {
         val coldFlow = flow {
-            expect(1, "main:1^")
-            delay(1)
-            expect(2, "main:1^")
+            expect("1^main")
+            yield()
+            expect("1^main")
             emit(42)
-            expect(4, "main:1^")
-            delay(1)
-            expect(5, "main:1^")
+            expect("1^main")
+            yield()
+            expect("1^main")
         }
-        runTest {
+
+        runTest(totalEvents = 8) {
+            expect("1^main")
             coldFlow.collect {
                 assertEquals(42, it)
-                expect(3, "main:1^")
+                expect("1^main")
+                yield()
+                expect("1^main")
             }
-            delay(1)
-            finish(6, "main:1^")
+            yield()
+            expect("1^main")
         }
     }
 
+    /** @see [CoroutineTracingTest.withContext_incorrectUsage] */
+    @Test
+    fun collectFlow_incorrectNameUsage() =
+        runTest(totalEvents = 8) {
+            val coldFlow =
+                flow {
+                        expect(
+                            "1^main"
+                        ) // <-- Trace section from before withContext is open until the
+                        //                      first suspension
+                        yield()
+                        expect()
+                        emit(42)
+                        expect("1^main") // <-- context changed due to context of collector
+                        yield()
+                        expect()
+                    }
+                    .flowOn(CoroutineTraceName("new-name")) // <-- BAD, DON'T DO THIS
+
+            expect("1^main")
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("1^main")
+                yield()
+                expect("1^main")
+            }
+            expect() // <-- trace sections erased due to context of emitter
+        }
+
     @Test
-    fun collectFlow2() {
+    fun collectFlow_correctNameUsage() {
         val coldFlow =
             flow {
-                    expect(1, "main:1^")
-                    delay(1)
-                    expect(2)
-                    emit(1)
-                    expect(5, "main:1^")
-                    delay(1)
-                    finish(6)
+                    expect(2, "1^main", "collect:new-name")
+                    yield()
+                    expect(3, "1^main", "collect:new-name")
+                    emit(42)
+                    expect(6, "1^main", "collect:new-name")
+                    yield()
+                    expect(7, "1^main", "collect:new-name")
                 }
                 .flowName("new-name")
-        runTest {
+        runTest(totalEvents = 8) {
+            expect(1, "1^main")
             coldFlow.collect {
-                expect(3, "main:1^")
-                delay(1)
-                expect(4, "main:1^")
+                assertEquals(42, it)
+                expect(4, "1^main", "collect:new-name", "emit:new-name")
+                yield()
+                expect(5, "1^main", "collect:new-name", "emit:new-name")
             }
+            expect(8, "1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_shareIn() {
+        val otherScope =
+            CoroutineScope(
+                createCoroutineTracingContext("other-scope", testMode = true) +
+                    bgThread1 +
+                    scope.coroutineContext.job
+            )
+        val sharedFlow =
+            flow {
+                    expect("1^new-name")
+                    yield()
+                    expect("1^new-name")
+                    emit(42)
+                    expect("1^new-name")
+                    yield()
+                    expect("1^new-name")
+                }
+                .shareInTraced("new-name", otherScope, SharingStarted.Eagerly, 5)
+        runTest(totalEvents = 9) {
+            yield()
+            expect("1^main")
+            val job =
+                launchTraced("launch-for-collect") {
+                    expect("1^main:1^launch-for-collect")
+                    sharedFlow.collect {
+                        assertEquals(42, it)
+                        expect("1^main:1^launch-for-collect", "collect:new-name", "emit:new-name")
+                        yield()
+                        expect("1^main:1^launch-for-collect", "collect:new-name", "emit:new-name")
+                    }
+                }
+            yield()
+            expect("1^main")
+            yield()
+            job.cancel()
+        }
+    }
+
+    @Test
+    fun collectFlow_launchIn() {
+        val coldFlow = flow {
+            expectAny(arrayOf("1^main:1^"), arrayOf("1^main:2^launchIn-for-cold"))
+            yield()
+            expectAny(arrayOf("1^main:1^"), arrayOf("1^main:2^launchIn-for-cold"))
+            emit(42)
+            expectAny(arrayOf("1^main:1^"), arrayOf("1^main:2^launchIn-for-cold"))
+            yield()
+            expectAny(arrayOf("1^main:1^"), arrayOf("1^main:2^launchIn-for-cold"))
+        }
+
+        runTest(totalEvents = 10) {
+            val sharedFlow = coldFlow.shareIn(this, SharingStarted.Eagerly, 5)
+            yield()
+            expect("1^main")
+            coldFlow.launchInTraced("launchIn-for-cold", this)
+            val job = sharedFlow.launchIn(this)
+            yield()
+            expect("1^main")
+            job.cancel()
+        }
+    }
+
+    @Test
+    fun collectFlow_launchIn_and_shareIn() {
+        val coldFlow = flow {
+            expectAny(arrayOf("1^main:1^shareIn-name"), arrayOf("1^main:2^launchIn-for-cold"))
+            yield()
+            expectAny(arrayOf("1^main:1^shareIn-name"), arrayOf("1^main:2^launchIn-for-cold"))
+            emit(42)
+            expectAny(arrayOf("1^main:1^shareIn-name"), arrayOf("1^main:2^launchIn-for-cold"))
+            yield()
+            expectAny(arrayOf("1^main:1^shareIn-name"), arrayOf("1^main:2^launchIn-for-cold"))
+        }
+
+        runTest(totalEvents = 12) {
+            val sharedFlow = coldFlow.shareInTraced("shareIn-name", this, SharingStarted.Eagerly, 5)
+            yield()
+            expect("1^main")
+            coldFlow
+                .onEach { expect("1^main:2^launchIn-for-cold") }
+                .launchInTraced("launchIn-for-cold", this)
+            val job =
+                sharedFlow
+                    .onEach {
+                        expect(
+                            "1^main:3^launchIn-for-hot",
+                            "collect:shareIn-name",
+                            "emit:shareIn-name",
+                        )
+                    }
+                    .launchInTraced("launchIn-for-hot", this)
+            expect("1^main")
+            delay(10)
+            job.cancel()
         }
     }
 
     @Test
-    fun collectFlow3() {
-        val thread1 = newSingleThreadContext("thread-#1")
+    fun collectFlow_badUsageOfCoroutineTraceName_coldFlowOnDifferentThread() {
+        val thread1 = bgThread1
+        // Example of bad usage of CoroutineTraceName. CoroutineTraceName is an internal API.
+        // It should only be used during collection, or whenever a coroutine is launched.
+        // It should not be used as an intermediate operator.
         val coldFlow =
             flow {
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^fused-name")
+                    yield()
+                    expect() // <-- empty due to CoroutineTraceName overwriting TraceContextElement
+                    emit(21)
+                    expect() // <-- empty due to CoroutineTraceName overwriting TraceContextElement
+                    yield()
+                    expect() // <-- empty due to CoroutineTraceName overwriting TraceContextElement
+                }
+                // "UNUSED_MIDDLE_NAME" is overwritten during operator fusion because the thread
+                // of the flow did not change, meaning no new coroutine needed to be created.
+                // However, using CoroutineTraceName("UNUSED_MIDDLE_NAME") is bad because it will
+                // replace CoroutineTracingContext on the resumed thread
+                .flowOn(CoroutineTraceName("UNUSED_MIDDLE_NAME") + thread1)
+                .map {
+                    expect("1^main:1^fused-name")
+                    it * 2
+                }
+                .flowOn(CoroutineTraceName("fused-name") + thread1)
+
+        runTest(totalEvents = 9) {
+            expect("1^main")
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("1^main")
+                yield()
+                expect("1^main")
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_operatorFusion_preventedByTracing() {
+        val coldFlow =
+            flow {
+                    expect("1^main:1^:1^", "collect:AAA")
+                    yield()
+                    expect("1^main:1^:1^", "collect:AAA")
                     emit(42)
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^:1^", "collect:AAA")
+                    yield()
+                    expect("1^main:1^:1^", "collect:AAA")
+                }
+                .flowName("AAA")
+                .flowOn(bgThread1)
+                // because we added tracing, work unnecessarily runs on bgThread2. This would be
+                // like adding a `.transform{}` or `.onEach{}` call between `.flowOn()` operators.
+                // The problem is not unique to tracing, but this test is to show there is still
+                // overhead when tracing is disabled, so it should not be used everywhere.
+                .flowName("BBB")
+                .flowOn(bgThread2)
+                .flowName("CCC")
+
+        runTest(totalEvents = 8) {
+            expect("1^main")
+            coldFlow.collectTraced(
+                "DDD"
+            ) { // CCC and DDD aren't fused together like how contexts are in `.flowOn()`
+                assertEquals(42, it)
+                expect("1^main", "collect:DDD", "collect:CCC", "emit:CCC", "emit:DDD")
+                yield()
+                expect("1^main", "collect:DDD", "collect:CCC", "emit:CCC", "emit:DDD")
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_operatorFusion_happensBecauseNoTracing() {
+        val coldFlow =
+            flow {
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                    emit(42)
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                }
+                .flowOn(bgThread1) // Operators are fused, and nothing ever executes on bgThread2
+                .flowOn(bgThread2)
+                .flowName("FLOW_NAME")
+
+        runTest(totalEvents = 8) {
+            expect("1^main")
+            coldFlow.collectTraced(
+                "COLLECT_NAME"
+            ) { // FLOW_NAME and COLLECT_NAME aren't fused together like how contexts
+                // are in `.flowOn()`
+                assertEquals(42, it)
+                expect(
+                    "1^main",
+                    "collect:COLLECT_NAME",
+                    "collect:FLOW_NAME",
+                    "emit:FLOW_NAME",
+                    "emit:COLLECT_NAME",
+                )
+                yield()
+                expect(
+                    "1^main",
+                    "collect:COLLECT_NAME",
+                    "collect:FLOW_NAME",
+                    "emit:FLOW_NAME",
+                    "emit:COLLECT_NAME",
+                )
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_flowOnTraced() {
+        val thread1 = bgThread1
+        val thread2 = bgThread2
+        // Example of bad usage of CoroutineTraceName. CoroutineTraceName is an internal API.
+        // It should only be used during collection, or whenever a coroutine is launched.
+        // It should not be used as an intermediate operator.
+        val op1 = flow {
+            expect("1^main:1^outer-name:1^inner-name")
+            yield()
+            expect()
+            emit(42)
+            expect()
+            yield()
+            expect()
+        }
+        val op2 = op1.flowOn(CoroutineTraceName("UNUSED_NAME") + thread2)
+        val op3 = op2.onEach { expect("1^main:1^outer-name:1^inner-name") }
+        val op4 = op3.flowOn(CoroutineTraceName("inner-name") + thread2)
+        val op5 = op4.onEach { expect("1^main:1^outer-name") }
+        val op6 = op5.flowOn(CoroutineTraceName("outer-name") + thread1)
+
+        runTest(totalEvents = 10) {
+            expect("1^main")
+            op6.collect {
+                assertEquals(42, it)
+                expect("1^main")
+                yield()
+                expect("1^main")
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_coldFlowOnDifferentThread() {
+        val thread1 = bgThread1
+        val coldFlow =
+            flow {
+                    expect("1^main:1^fused-name")
+                    yield()
+                    expect("1^main:1^fused-name")
+                    emit(21)
+                    expect("1^main:1^fused-name")
+                    yield()
+                    expect("1^main:1^fused-name")
+                }
+                .map {
+                    expect("1^main:1^fused-name")
+                    it * 2
+                }
+                .flowOn(CoroutineTraceName("fused-name") + thread1)
+
+        runTest(totalEvents = 9) {
+            expect("1^main")
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("1^main")
+                yield()
+                expect("1^main")
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectTraced_coldFlowOnDifferentThread() {
+        val thread1 = bgThread1
+        val coldFlow =
+            flow {
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                    emit(21)
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                }
+                .map {
+                    expect("1^main:1^")
+                    it * 2
                 }
-                .flowName("new-name")
                 .flowOn(thread1)
-        runTest {
+
+        runTest(totalEvents = 9) {
+            expect("1^main")
+            coldFlow.collectTraced("coldFlow") {
+                assertEquals(42, it)
+                expect("1^main", "collect:coldFlow", "emit:coldFlow")
+                yield()
+                expect("1^main", "collect:coldFlow", "emit:coldFlow")
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectTraced_collectWithTracedReceiver() {
+        val thread1 = bgThread1
+        val coldFlow =
+            flow {
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                    emit(21)
+                    expect("1^main:1^")
+                    yield()
+                    expect("1^main:1^")
+                }
+                .map {
+                    expect("1^main:1^")
+                    it * 2
+                }
+                .flowOn(thread1)
+
+        runTest(totalEvents = 9) {
+            expect("1^main")
+            coldFlow.traceCoroutine("AAA") {
+                collectTraced("coldFlow") {
+                    assertEquals(42, it)
+                    expect("1^main", "AAA", "collect:coldFlow", "emit:coldFlow")
+                    yield()
+                    expect("1^main", "AAA", "collect:coldFlow", "emit:coldFlow")
+                }
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_nameBeforeDispatcherChange() {
+        val thread1 = bgThread1
+        val coldFlow =
+            flow {
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
+                    emit(42)
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
+                }
+                .flowOn(CoroutineTraceName("new-name"))
+                .flowOn(thread1)
+        runTest(totalEvents = 6) {
             coldFlow.collect {
                 assertEquals(42, it)
-                expect("main:1^")
-                delay(1)
-                expect("main:1^")
+                expect("1^main")
+                yield()
+                expect("1^main")
             }
         }
     }
 
     @Test
-    fun collectFlow4() {
-        val thread1 = newSingleThreadContext("thread-#1")
+    fun collectFlow_nameAfterDispatcherChange() {
+        val thread1 = bgThread1
         val coldFlow =
             flow {
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
                     emit(42)
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
                 }
                 .flowOn(thread1)
-                .flowName("new-name")
-        runTest {
+                .flowOn(CoroutineTraceName("new-name"))
+        runTest(totalEvents = 6) {
             coldFlow.collect {
                 assertEquals(42, it)
-                expect("main:1^")
-                delay(1)
-                expect("main:1^")
+                expect("1^main")
+                yield()
+                expect("1^main")
             }
         }
     }
 
     @Test
-    fun collectFlow5() {
-        val thread1 = newSingleThreadContext("thread-#1")
+    fun collectFlow_nameBeforeAndAfterDispatcherChange() {
+        val thread1 = bgThread1
         val coldFlow =
             flow {
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
                     emit(42)
-                    expect("main:1^:1^new-name")
-                    delay(1)
-                    expect("main:1^:1^new-name")
+                    expect("1^main:1^new-name")
+                    yield()
+                    expect("1^main:1^new-name")
                 }
-                .flowName("new-name")
+                .flowOn(CoroutineTraceName("new-name"))
                 .flowOn(thread1)
-                .flowName("UNUSED_NAME")
+                // Unused because, when fused, the previous upstream context takes precedence
+                .flowOn(CoroutineTraceName("UNUSED_NAME"))
 
         runTest {
             coldFlow.collect {
                 assertEquals(42, it)
-                expect("main:1^")
+                expect("1^main")
             }
-            delay(1)
-            expect("main:1^")
+            yield()
+            expect("1^main")
         }
     }
 
     @Test
-    fun collectFlow6() {
+    fun collectTraced_mapLatest() {
+        val coldFlow =
+            flow {
+                    expect("1^main:1^:1^")
+                    emit(1)
+                    expect("1^main:1^:1^")
+                    emit(21)
+                    expect("1^main:1^:1^")
+                }
+                .filterTraced("mod2") {
+                    // called twice because upstream has 2 emits
+                    expect("1^main:1^:1^", "mod2")
+                    true
+                }
+                .run {
+                    traceCoroutine("CCC") {
+                        mapLatest {
+                            traceCoroutine("DDD") {
+                                expectAny(
+                                    arrayOf("1^main:1^:1^", "1^main:1^:1^:1^", "DDD"),
+                                    arrayOf("1^main:1^:1^", "1^main:1^:1^:2^", "DDD"),
+                                )
+                                it * 2
+                            }
+                        }
+                    }
+                }
+
+        runTest(totalEvents = 10) {
+            expect("1^main") // top-level scope
+            traceCoroutine("AAA") {
+                coldFlow.collectLatest {
+                    traceCoroutine("BBB") {
+                        delay(50)
+                        assertEquals(42, it)
+                        expect("1^main:1^:3^", "BBB")
+                    }
+                }
+            }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_badNameUsage() {
         val barrier1 = CompletableDeferred<Unit>()
         val barrier2 = CompletableDeferred<Unit>()
-        val thread1 = newSingleThreadContext("thread-#1")
-        val thread2 = newSingleThreadContext("thread-#2")
-        val thread3 = newSingleThreadContext("thread-#3")
+        val thread1 = bgThread1
+        val thread2 = bgThread2
+        val thread3 = bgThread3
         val coldFlow =
             flow {
-                    expect(2, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
-                    delay(1)
-                    expect(3, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    expect("1^main:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    yield()
+                    expect("1^main:1^name-for-filter:1^name-for-map:1^name-for-emit")
                     emit(42)
                     barrier1.await()
-                    expect(9, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
-                    delay(1)
-                    expect(10, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    expect("1^main:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    yield()
+                    expect("1^main:1^name-for-filter:1^name-for-map:1^name-for-emit")
                     barrier2.complete(Unit)
                 }
-                .flowName("name-for-emit")
+                .flowOn(CoroutineTraceName("name-for-emit"))
                 .flowOn(thread3)
                 .map {
-                    expect(4, "main:1^:1^name-for-filter:1^name-for-map")
-                    delay(1)
-                    expect(5, "main:1^:1^name-for-filter:1^name-for-map")
+                    expect("1^main:1^name-for-filter:1^name-for-map")
+                    yield()
+                    expect("1^main:1^name-for-filter:1^name-for-map")
                     it
                 }
-                .flowName("name-for-map")
+                .flowOn(CoroutineTraceName("name-for-map")) // <-- This only works because the
+                //                   dispatcher changes; this behavior should not be relied on.
                 .flowOn(thread2)
+                .flowOn(CoroutineTraceName("UNUSED_NAME")) // <-- Unused because, when fused, the
+                //                                     previous upstream context takes precedence
                 .filter {
-                    expect(6, "main:1^:1^name-for-filter")
-                    delay(1)
-                    expect(7, "main:1^:1^name-for-filter")
+                    expect("1^main:1^name-for-filter")
+                    yield()
+                    expect("1^main:1^name-for-filter")
                     true
                 }
-                .flowName("name-for-filter")
+                .flowOn(CoroutineTraceName("name-for-filter"))
                 .flowOn(thread1)
 
-        runTest {
-            expect(1, "main:1^")
+        runTest(totalEvents = 11) {
+            expect("1^main")
             coldFlow.collect {
                 assertEquals(42, it)
-                expect(8, "main:1^")
+                expect("1^main")
                 barrier1.complete(Unit)
             }
             barrier2.await()
-            finish(11, "main:1^")
+            expect("1^main")
         }
     }
 
     @Test
-    fun collectFlow7_withIntermediateOperatorNames() = runTest {
-        expect(1, "main:1^")
-        flow {
-                expect(2, "main:1^", "collect:do-the-assert")
-                emit(21) // 42 / 2 = 21
-                expect(6, "main:1^", "collect:do-the-assert")
-            }
-            .flowName("UNUSED_NAME") // unused because scope is unchanged and operators are fused
-            .mapTraced("multiply-by-3") {
-                expect(3, "main:1^", "collect:do-the-assert", "map:multiply-by-3:transform")
-                it * 2
-            }
-            .filterTraced("mod-2") {
-                expect(
-                    4,
-                    "main:1^",
-                    "collect:do-the-assert",
-                    "map:multiply-by-3:emit",
-                    "filter:mod-2:predicate",
-                )
-                it % 2 == 0
-            }
-            .collectTraced("do-the-assert") {
+    fun collectFlow_withIntermediateOperatorNames() {
+        val coldFlow =
+            flow {
+                    expect(2, "1^main", "collect:do-the-assert")
+                    emit(21) // 42 / 2 = 21
+                    expect(6, "1^main", "collect:do-the-assert")
+                }
+                .mapTraced("multiply-by-3") {
+                    expect(3, "1^main", "collect:do-the-assert", "multiply-by-3")
+                    it * 2
+                }
+                .filterTraced("mod-2") {
+                    expect(4, "1^main", "collect:do-the-assert", "mod-2")
+                    it % 2 == 0
+                }
+        runTest(totalEvents = 7) {
+            expect(1, "1^main")
+
+            coldFlow.collectTraced("do-the-assert") {
                 assertEquals(42, it)
-                expect(
-                    5,
-                    "main:1^",
-                    "collect:do-the-assert",
-                    "map:multiply-by-3:emit",
-                    "filter:mod-2:emit",
-                    "collect:do-the-assert:emit",
+                expect(5, "1^main", "collect:do-the-assert", "emit:do-the-assert")
+            }
+            expect(7, "1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_mapLatest() {
+        val coldFlow = flowOf(1, 2, 3)
+        runTest(totalEvents = 6) {
+            expect("1^main")
+            coldFlow
+                .mapLatestTraced("AAA") {
+                    expectAny(
+                        arrayOf(
+                            "1^main:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:1^",
+                            "AAA",
+                        ),
+                        arrayOf(
+                            "1^main:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:2^",
+                            "AAA",
+                        ),
+                        arrayOf(
+                            "1^main:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:3^",
+                            "AAA",
+                        ),
+                    )
+                    delay(10)
+                    expect("1^main:1^:3^", "AAA")
+                }
+                .collect()
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_collectLatest() {
+        val coldFlow = flowOf(1, 2, 3)
+        runTest(totalEvents = 6) {
+            expect("1^main")
+            coldFlow.collectLatestTraced("CCC") {
+                expectAny(
+                    arrayOf(
+                        "1^main:1^",
+                        "collect:collectLatest:CCC",
+                        "emit:collectLatest:CCC",
+                        "1^main:1^:1^",
+                        "CCC",
+                    ),
+                    arrayOf(
+                        "1^main:1^",
+                        "collect:collectLatest:CCC",
+                        "emit:collectLatest:CCC",
+                        "1^main:1^:2^",
+                        "CCC",
+                    ),
+                    arrayOf(
+                        "1^main:1^",
+                        "collect:collectLatest:CCC",
+                        "emit:collectLatest:CCC",
+                        "1^main:1^:3^",
+                        "CCC",
+                    ),
                 )
+                delay(10)
+                expect("1^main:1^:3^", "CCC")
             }
-        finish(7, "main:1^")
+            expect("1^main")
+        }
     }
 
     @Test
-    fun collectFlow8_separateJobs() = runTest {
-        val flowThread = newSingleThreadContext("flow-thread")
-        expect(1, "main:1^")
-        val state =
-            flowOf(1, 2, 3, 4)
-                .transform {
-                    expect("main:1^:1^:1^FLOW_NAME")
-                    emit(it)
-                }
-                .flowName("unused-name")
-                .transform {
-                    expect("main:1^:1^:1^FLOW_NAME")
-                    emit(it)
+    fun collectFlow_mapLatest_collectLatest() {
+        val coldFlow = flowOf(1, 2, 3)
+        runTest(totalEvents = 7) {
+            expect("1^main")
+            coldFlow
+                .mapLatestTraced("AAA") {
+                    expectAny(
+                        arrayOf(
+                            "1^main:1^:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:1^:1^",
+                            "AAA",
+                        ),
+                        arrayOf(
+                            "1^main:1^:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:1^:2^",
+                            "AAA",
+                        ),
+                        arrayOf(
+                            "1^main:1^:1^",
+                            "collect:mapLatest:AAA",
+                            "emit:mapLatest:AAA",
+                            "1^main:1^:1^:3^",
+                            "AAA",
+                        ),
+                    )
+                    delay(10)
+                    expect("1^main:1^:1^:3^", "AAA")
                 }
-                .flowName("FLOW_NAME")
-                .flowOn(flowThread)
-                .transform {
-                    expect("main:1^:1^")
-                    emit(it)
+                .collectLatestTraced("CCC") {
+                    expect(
+                        "1^main:1^",
+                        "collect:collectLatest:CCC",
+                        "emit:collectLatest:CCC",
+                        "1^main:1^:2^",
+                        "CCC",
+                    )
+                }
+            expect("1^main")
+        }
+    }
+
+    @Test
+    fun collectFlow_stateIn() {
+        val otherScope =
+            CoroutineScope(
+                createCoroutineTracingContext("other-scope", testMode = true) +
+                    bgThread1 +
+                    scope.coroutineContext.job
+            )
+        val coldFlow =
+            flowOf(1, 2)
+                .onEach {
+                    delay(2)
+                    expectAny(arrayOf("1^STATE_1"), arrayOf("2^STATE_2"))
                 }
-                .stateIn(this)
+                .flowOn(bgThread2)
 
-        launchTraced("LAUNCH_CALL") {
-            state.collectTraced("state-flow") {
-                expect(2, "main:1^:2^LAUNCH_CALL", "collect:state-flow", "collect:state-flow:emit")
-            }
+        runTest(totalEvents = 10) {
+            expect("1^main")
+
+            val state1 = coldFlow.stateInTraced("STATE_1", otherScope.plus(bgThread2))
+            val state2 = coldFlow.stateInTraced("STATE_2", otherScope, SharingStarted.Lazily, 42)
+
+            delay(20)
+
+            val job1 =
+                state1
+                    .onEach { expect("1^main:1^LAUNCH_1", "collect:STATE_1", "emit:STATE_1") }
+                    .launchInTraced("LAUNCH_1", this)
+            assertEquals(42, state2.value)
+            val job2 =
+                state2
+                    .onEach { expect("1^main:2^LAUNCH_2", "collect:STATE_2", "emit:STATE_2") }
+                    .launchInTraced("LAUNCH_2", this)
+
+            delay(10)
+            expect("1^main")
+
+            delay(10)
+
+            job1.cancel()
+            job2.cancel()
         }
+    }
 
-        delay(50)
-        finish(3, "main:1^")
-        cancel()
+    @Test
+    fun tracedMutableStateFlow_collection() {
+        val state = MutableStateFlow(1).traceAs("NAME")
+
+        runTest(totalEvents = 3) {
+            expect("1^main")
+            launchTraced("LAUNCH") {
+                delay(10)
+                state.value = 2
+            }
+            val job =
+                launchTraced("LAUNCH_FOR_COLLECT") {
+                    state.collect {
+                        expect("1^main:2^LAUNCH_FOR_COLLECT", "collect:NAME", "emit:NAME")
+                    }
+                }
+            delay(100)
+            job.cancel()
+        }
     }
 }
diff --git a/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
index 8c30a53..75a665d 100644
--- a/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
+++ b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
@@ -17,257 +17,262 @@
 package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.launchTraced
-import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.coroutines.traceThreadLocal
 import com.android.app.tracing.coroutines.withContextTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import kotlin.coroutines.CoroutineContext
 import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineStart
-import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.channels.Channel
 import kotlinx.coroutines.delay
+import kotlinx.coroutines.isActive
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.newSingleThreadContext
 import kotlinx.coroutines.withContext
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertNotNull
 import org.junit.Test
 
-@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
 class MultiThreadedCoroutineTracingTest : TestBase() {
 
-    override val extraCoroutineContext: CoroutineContext
-        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
-
     @Test
     fun unconfinedLaunch() = runTest {
         val barrier1 = CompletableDeferred<Unit>()
         val barrier2 = CompletableDeferred<Unit>()
         val barrier3 = CompletableDeferred<Unit>()
-        val thread1 = newSingleThreadContext("thread-#1")
-        val thread2 = newSingleThreadContext("thread-#1")
+        val thread1 = bgThread1
+        val thread2 = bgThread2
         // Do NOT assert order. Doing so will make this test flaky due to its use of
         // Dispatchers.Unconfined
-        expect("main:1^")
+        expect("1^main")
         launchTraced("unconfined-launch", Dispatchers.Unconfined) {
-                launchTraced("thread1-launch", thread1) {
-                    traceCoroutine("thread1-inner") {
-                        barrier1.await()
-                        expect("main:1^:1^unconfined-launch:1^thread1-launch", "thread1-inner")
+                launchTraced("thread2-launch", thread2) {
+                    traceCoroutine("thread2-inner") {
+                        barrier3.await()
+                        expect("1^main:1^unconfined-launch:1^thread2-launch", "thread2-inner")
                         barrier2.complete(Unit)
                     }
                 }
                 launchTraced("default-launch", Dispatchers.Unconfined) {
                     traceCoroutine("default-inner") {
                         barrier2.await()
-                        expect(
-                            "main:1^",
-                            "main:1^:1^unconfined-launch:2^default-launch",
-                            "default-inner",
+                        expectAny(
+                            arrayOf(
+                                "1^main",
+                                "1^main:1^unconfined-launch:2^default-launch",
+                                "default-inner",
+                            ),
+                            arrayOf(
+                                "1^main:1^unconfined-launch:3^thread1-launch",
+                                "thread1-inner",
+                                "1^main:1^unconfined-launch:2^default-launch",
+                                "default-inner",
+                            ),
                         )
                         barrier3.complete(Unit)
                     }
                 }
-                launchTraced("thread2-launch", thread2) {
-                    traceCoroutine("thread2-inner") {
-                        barrier3.await()
-                        expect("main:1^:1^unconfined-launch:3^thread2-launch", "thread2-inner")
+                launchTraced("thread1-launch", thread1) {
+                    traceCoroutine("thread1-inner") {
+                        barrier1.await()
+                        expect("1^main:1^unconfined-launch:3^thread1-launch", "thread1-inner")
                         barrier2.complete(Unit)
                     }
                 }
                 withContextTraced("unconfined-withContext", Dispatchers.Unconfined) {
-                    expect("main:1^", "main:1^:1^unconfined-launch")
+                    expect("1^main", "1^main:1^unconfined-launch", "unconfined-withContext")
                     barrier1.complete(Unit)
-                    expect("main:1^", "main:1^:1^unconfined-launch")
+                    expect("1^main", "1^main:1^unconfined-launch", "unconfined-withContext")
                 }
             }
             .join()
-        expect("main:1^")
+        expect("1^main")
     }
 
     @Test
-    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() = runTest {
-        traceCoroutine("parent-span") {
-            expect(1, "main:1^", "parent-span")
-            launch(Dispatchers.Unconfined) {
-                // This may appear unusual, but it is expected behavior:
-                //   1) The parent has an open trace section called "parent-span".
-                //   2) The child launches, derives a new scope name from its parent, and resumes
-                //      immediately due to its use of the unconfined dispatcher.
-                //   3) The child emits all the trace sections known to its scope. The parent
-                //      does not have an opportunity to restore its context yet.
-                //   4) After the suspension point, the parent restores its context, and the
-                //      child
-                //
-                // [parent's active trace sections]
-                //               /           \      [new trace section for child scope]
-                //              /             \                \
-                expect(2, "main:1^", "parent-span", "main:1^:1^")
-                traceCoroutine("child-span") {
-                    expect(3, "main:1^", "parent-span", "main:1^:1^", "child-span")
-                    delay(10) // <-- delay will give parent a chance to restore its context
-                    // After a delay, the parent resumes, finishing its trace section, so we are
-                    // left with only those in the child's scope
-                    finish(5, "main:1^:1^", "child-span")
+    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() =
+        runTest(finalEvent = 5) {
+            traceCoroutine("parent-span") {
+                expect(1, "1^main", "parent-span")
+                launch(Dispatchers.Unconfined) {
+                    // This may appear unusual, but it is expected behavior:
+                    //   1) The parent has an open trace section called "parent-span".
+                    //   2) The child launches, derives a new scope name from its parent, and
+                    // resumes
+                    //      immediately due to its use of the unconfined dispatcher.
+                    //   3) The child emits all the trace sections known to its scope. The parent
+                    //      does not have an opportunity to restore its context yet.
+                    //   4) After the suspension point, the parent restores its context, and the
+                    //      child
+                    //
+                    // [parent's active trace sections]
+                    //               /           \      [new trace section for child scope]
+                    //              /             \                \
+                    expect(2, "1^main", "parent-span", "1^main:1^")
+                    traceCoroutine("child-span") {
+                        expect(3, "1^main", "parent-span", "1^main:1^", "child-span")
+                        delay(10) // <-- delay will give parent a chance to restore its context
+                        // After a delay, the parent resumes, finishing its trace section, so we are
+                        // left with only those in the child's scope
+                        expect(5, "1^main:1^", "child-span")
+                    }
                 }
             }
+            expect(4, "1^main") // <-- because of the delay above, this is not the last event
         }
-        expect(4, "main:1^") // <-- because of the delay above, this is not the last event
-    }
 
     /** @see nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher */
     @Test
-    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() = runTest {
-        traceCoroutine("parent-span") {
-            launch(start = CoroutineStart.UNDISPATCHED) {
-                traceCoroutine("child-span") {
-                    expect(1, "main:1^", "parent-span", "main:1^:1^", "child-span")
-                    delay(1) // <-- delay will give parent a chance to restore its context
-                    finish(3, "main:1^:1^", "child-span")
+    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() {
+        val barrier = CompletableDeferred<Unit>()
+        runTest(finalEvent = 4) {
+            expect(1, "1^main")
+            traceCoroutine("parent-span") {
+                launch(start = CoroutineStart.UNDISPATCHED) {
+                    traceCoroutine("child-span") {
+                        expect(2, "1^main", "parent-span", "1^main:1^", "child-span")
+                        barrier.await() // <-- give parent a chance to restore its context
+                        expect(4, "1^main:1^", "child-span")
+                    }
                 }
             }
+            expect(3, "1^main")
+            barrier.complete(Unit)
         }
-        expect(2, "main:1^")
     }
 
     @Test
-    fun launchOnSeparateThread_defaultDispatcher() = runTest {
-        val channel = Channel<Int>()
-        val thread1 = newSingleThreadContext("thread-#1")
-        expect("main:1^")
-        traceCoroutine("hello") {
-            expect(1, "main:1^", "hello")
-            launch(thread1) {
-                expect(2, "main:1^:1^")
-                traceCoroutine("world") {
-                    expect("main:1^:1^", "world")
-                    channel.send(1)
-                    expect(3, "main:1^:1^", "world")
+    fun launchOnSeparateThread_defaultDispatcher() =
+        runTest(finalEvent = 4) {
+            val channel = Channel<Int>()
+            val thread1 = bgThread1
+            expect("1^main")
+            traceCoroutine("hello") {
+                expect(1, "1^main", "hello")
+                launch(thread1) {
+                    expect(2, "1^main:1^")
+                    traceCoroutine("world") {
+                        expect("1^main:1^", "world")
+                        channel.send(1)
+                        expect(3, "1^main:1^", "world")
+                    }
                 }
+                expect("1^main", "hello")
             }
-            expect("main:1^", "hello")
+            expect("1^main")
+            assertEquals(1, channel.receive())
+            expect(4, "1^main")
         }
-        expect("main:1^")
-        assertEquals(1, channel.receive())
-        finish(4, "main:1^")
-    }
 
     @Test
-    fun testTraceStorage() = runTest {
-        val thread1 = newSingleThreadContext("thread-#1")
-        val thread2 = newSingleThreadContext("thread-#2")
-        val thread3 = newSingleThreadContext("thread-#3")
-        val thread4 = newSingleThreadContext("thread-#4")
+    fun testTraceStorage() {
+        val thread1 = bgThread1
+        val thread2 = bgThread2
+        val thread3 = bgThread3
+        val thread4 = bgThread4
         val channel = Channel<Int>()
         val threadContexts = listOf(thread1, thread2, thread3, thread4)
         val finishedLaunches = Channel<Int>()
         // Start 1000 coroutines waiting on [channel]
-        val job = launch {
-            repeat(1000) {
-                launchTraced("span-for-launch", threadContexts[it % threadContexts.size]) {
-                    assertNotNull(traceThreadLocal.get())
-                    traceCoroutine("span-for-fetchData") {
-                        channel.receive()
-                        expectEndsWith("span-for-fetchData")
+        runTest {
+            val job = launch {
+                repeat(1000) {
+                    launchTraced("span-for-launch", threadContexts[it % threadContexts.size]) {
+                        assertNotNull(traceThreadLocal.get())
+                        traceCoroutine("span-for-fetchData") {
+                            channel.receive()
+                            expectEndsWith("span-for-fetchData")
+                        }
+                        assertNotNull(traceThreadLocal.get())
+                        finishedLaunches.send(it)
                     }
-                    assertNotNull(traceThreadLocal.get())
-                    finishedLaunches.send(it)
+                    expect("1^main:1^")
                 }
-                expect("main:1^:1^")
             }
+            // Resume half the coroutines that are waiting on this channel
+            repeat(500) { channel.send(1) }
+            var receivedClosures = 0
+            repeat(500) {
+                finishedLaunches.receive()
+                receivedClosures++
+            }
+            // ...and cancel the rest
+            job.cancel()
         }
-        // Resume half the coroutines that are waiting on this channel
-        repeat(500) { channel.send(1) }
-        var receivedClosures = 0
-        repeat(500) {
-            finishedLaunches.receive()
-            receivedClosures++
-        }
-        // ...and cancel the rest
-        job.cancel()
     }
 
     @Test
     fun nestedTraceSectionsMultiThreaded() = runTest {
-        val context1 = newSingleThreadContext("thread-#1") + nameCoroutine("coroutineA")
-        val context2 = newSingleThreadContext("thread-#2") + nameCoroutine("coroutineB")
-        val context3 = context1 + nameCoroutine("coroutineC")
-
-        launchTraced("launch#1", context1) {
-            expect("main:1^:1^coroutineA")
+        launchTraced("launch#1", bgThread1) {
+            expect("1^main:1^launch#1")
             delay(1L)
-            traceCoroutine("span-1") { expect("main:1^:1^coroutineA", "span-1") }
-            expect("main:1^:1^coroutineA")
-            expect("main:1^:1^coroutineA")
-            launchTraced("launch#2", context2) {
-                expect("main:1^:1^coroutineA:1^coroutineB")
+            traceCoroutine("span-1") { expect("1^main:1^launch#1", "span-1") }
+            expect("1^main:1^launch#1")
+            expect("1^main:1^launch#1")
+            launchTraced("launch#2", bgThread2) {
+                expect("1^main:1^launch#1:1^launch#2")
                 delay(1L)
-                traceCoroutine("span-2") { expect("main:1^:1^coroutineA:1^coroutineB", "span-2") }
-                expect("main:1^:1^coroutineA:1^coroutineB")
-                expect("main:1^:1^coroutineA:1^coroutineB")
-                launchTraced("launch#3", context3) {
+                traceCoroutine("span-2") { expect("1^main:1^launch#1:1^launch#2", "span-2") }
+                expect("1^main:1^launch#1:1^launch#2")
+                expect("1^main:1^launch#1:1^launch#2")
+                launchTraced("launch#3", bgThread1) {
                     // "launch#3" is dropped because context has a TraceContextElement.
                     // The CoroutineScope (i.e. `this` in `this.launch {}`) should have a
                     // TraceContextElement, but using TraceContextElement in the passed context is
                     // incorrect.
-                    expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC")
-                    launchTraced("launch#4", context1) {
-                        expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC:1^coroutineA")
+                    expect("1^main:1^launch#1:1^launch#2:1^launch#3")
+                    launchTraced("launch#4", bgThread1) {
+                        expect("1^main:1^launch#1:1^launch#2:1^launch#3:1^launch#4")
                     }
                 }
             }
-            expect("main:1^:1^coroutineA")
+            expect("1^main:1^launch#1")
         }
-        expect("main:1^")
+        expect("1^main")
 
         // Launching without the trace extension won't result in traces
-        launch(context1) { expect("main:1^:2^coroutineA") }
-        launch(context2) { expect("main:1^:3^coroutineB") }
+        launch(bgThread1) { expect("1^main:2^") }
+        launch(bgThread2) { expect("1^main:3^") }
     }
 
     @Test
     fun scopeReentry_withContextFastPath() = runTest {
-        val thread1 = newSingleThreadContext("thread-#1")
+        val thread1 = bgThread1
         val channel = Channel<Int>()
         val job =
             launchTraced("#1", thread1) {
-                expect("main:1^:1^#1")
+                expect("1^main:1^#1")
                 var i = 0
-                while (true) {
-                    expect("main:1^:1^#1")
+                while (isActive) {
+                    expect("1^main:1^#1")
                     channel.send(i++)
-                    expect("main:1^:1^#1")
+                    expect("1^main:1^#1")
                     // when withContext is passed the same scope, it takes a fast path, dispatching
                     // immediately. This means that in subsequent loops, if we do not handle reentry
                     // correctly in TraceContextElement, the trace may become deeply nested:
                     // "#1", "#1", "#1", ... "#2"
                     withContext(thread1) {
-                        expect("main:1^:1^#1")
+                        expect("1^main:1^#1")
                         traceCoroutine("#2") {
-                            expect("main:1^:1^#1", "#2")
+                            expect("1^main:1^#1", "#2")
                             channel.send(i++)
-                            expect("main:1^:1^#1", "#2")
+                            expect("1^main:1^#1", "#2")
                         }
-                        expect("main:1^:1^#1")
+                        expect("1^main:1^#1")
                     }
                 }
             }
         repeat(1000) {
-            expect("main:1^")
+            expect("1^main")
             traceCoroutine("receive") {
-                expect("main:1^", "receive")
+                expect("1^main", "receive")
                 val receivedVal = channel.receive()
                 assertEquals(it, receivedVal)
-                expect("main:1^", "receive")
+                expect("1^main", "receive")
             }
-            expect("main:1^")
+            expect("1^main")
         }
         job.cancel()
     }
diff --git a/tracinglib/robolectric/src/NestedCoroutineTracingTest.kt b/tracinglib/robolectric/src/NestedCoroutineTracingTest.kt
new file mode 100644
index 0000000..70948c2
--- /dev/null
+++ b/tracinglib/robolectric/src/NestedCoroutineTracingTest.kt
@@ -0,0 +1,61 @@
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
+@file:OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
+
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.delay
+import org.junit.Test
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class NestedCoroutineTracingTest : TestBase() {
+
+    override val extraContext: CoroutineContext by lazy { createCoroutineTracingContext("main") }
+
+    @Test
+    fun stressTestContextSwitches_depth() {
+        fun CoroutineScope.recursivelyLaunch(n: Int) {
+            if (n == 400) return
+            launchTraced("launch#$n", start = CoroutineStart.UNDISPATCHED) {
+                traceCoroutine("a") {
+                    if (n == 350) {
+                        val expectedBeforeDelay = mutableListOf("main")
+                        repeat(n + 1) {
+                            expectedBeforeDelay.add("launch#$it")
+                            expectedBeforeDelay.add("a")
+                        }
+                        expect(*expectedBeforeDelay.toTypedArray())
+                    }
+                    recursivelyLaunch(n + 1)
+                    delay(1)
+                    expect("launch#$n", "a")
+                }
+            }
+        }
+        runTest(totalEvents = 401) { recursivelyLaunch(0) }
+    }
+}
diff --git a/tracinglib/robolectric/src/TestBase.kt b/tracinglib/robolectric/src/TestBase.kt
index e3be00d..946b379 100644
--- a/tracinglib/robolectric/src/TestBase.kt
+++ b/tracinglib/robolectric/src/TestBase.kt
@@ -14,132 +14,176 @@
  * limitations under the License.
  */
 
+@file:OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
+
 package com.android.test.tracing.coroutines
 
-import android.os.Looper
 import android.platform.test.flag.junit.SetFlagsRule
 import androidx.test.ext.junit.runners.AndroidJUnit4
-import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.COROUTINE_EXECUTION
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.traceThreadLocal
 import com.android.test.tracing.coroutines.util.FakeTraceState
 import com.android.test.tracing.coroutines.util.FakeTraceState.getOpenTraceSectionsOnCurrentThread
 import com.android.test.tracing.coroutines.util.ShadowTrace
 import java.io.PrintWriter
 import java.io.StringWriter
-import java.util.concurrent.TimeUnit.MILLISECONDS
 import java.util.concurrent.atomic.AtomicInteger
 import kotlin.coroutines.CoroutineContext
-import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.CancellationException
+import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.CoroutineExceptionHandler
 import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.Job
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.TimeoutCancellationException
+import kotlinx.coroutines.cancel
 import kotlinx.coroutines.delay
+import kotlinx.coroutines.isActive
 import kotlinx.coroutines.launch
+import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withContext
+import kotlinx.coroutines.withTimeout
 import org.junit.After
-import org.junit.Assert.assertEquals
 import org.junit.Assert.assertTrue
+import org.junit.Assert.fail
 import org.junit.Before
 import org.junit.ClassRule
 import org.junit.Rule
 import org.junit.runner.RunWith
-import org.robolectric.Shadows.shadowOf
 import org.robolectric.annotation.Config
-import org.robolectric.shadows.ShadowLooper
 
-class InvalidTraceStateException(message: String) : Exception(message)
+class InvalidTraceStateException(message: String, cause: Throwable? = null) :
+    AssertionError(message, cause)
+
+internal val mainTestDispatcher = newSingleThreadContext("test-main")
+internal val bgThread1 = newSingleThreadContext("test-bg-1")
+internal val bgThread2 = newSingleThreadContext("test-bg-2")
+internal val bgThread3 = newSingleThreadContext("test-bg-3")
+internal val bgThread4 = newSingleThreadContext("test-bg-4")
 
 @RunWith(AndroidJUnit4::class)
 @Config(shadows = [ShadowTrace::class])
-open class TestBase {
-
+abstract class TestBase {
     companion object {
         @JvmField
         @ClassRule
-        val setFlagsClassRule: SetFlagsRule.ClassRule = SetFlagsRule.ClassRule()
+        val setFlagsClassRule: SetFlagsRule.ClassRule =
+            SetFlagsRule.ClassRule(com.android.systemui.Flags::class.java)
+
+        @JvmStatic
+        private fun isRobolectricTest(): Boolean {
+            return System.getProperty("java.vm.name") != "Dalvik"
+        }
     }
 
-    @JvmField @Rule val setFlagsRule = SetFlagsRule()
+    // TODO(b/339471826): Robolectric does not execute @ClassRule correctly
+    @get:Rule
+    val setFlagsRule: SetFlagsRule =
+        if (isRobolectricTest()) SetFlagsRule() else setFlagsClassRule.createSetFlagsRule()
 
     private val eventCounter = AtomicInteger(0)
+    private val allEventCounter = AtomicInteger(0)
     private val finalEvent = AtomicInteger(INVALID_EVENT)
-    private var expectedExceptions = false
-    private lateinit var allExceptions: MutableList<Throwable>
-    private lateinit var shadowLooper: ShadowLooper
-    private lateinit var mainTraceScope: CoroutineScope
+    private val allExceptions = mutableListOf<Throwable>()
+    private val assertionErrors = mutableListOf<AssertionError>()
 
-    open val extraCoroutineContext: CoroutineContext
-        get() = EmptyCoroutineContext
+    /** The scope to be used by the test in [runTest] */
+    val scope: CoroutineScope by lazy { CoroutineScope(extraContext + mainTestDispatcher) }
+
+    /**
+     * Context passed to the scope used for the test. If the returned [CoroutineContext] contains a
+     * [CoroutineDispatcher] it will be overwritten.
+     */
+    open val extraContext: CoroutineContext by lazy {
+        createCoroutineTracingContext("main", testMode = true)
+    }
 
     @Before
     fun setup() {
         FakeTraceState.isTracingEnabled = true
-        eventCounter.set(0)
-        allExceptions = mutableListOf()
-        shadowLooper = shadowOf(Looper.getMainLooper())
-        mainTraceScope = CoroutineScope(Dispatchers.Main + extraCoroutineContext)
+        FakeTraceState.clearAll()
+
+        // Reset all thread-local state
+        traceThreadLocal.remove()
+        val dispatchers = listOf(mainTestDispatcher, bgThread1, bgThread2, bgThread3, bgThread4)
+        runBlocking { dispatchers.forEach { withContext(it) { traceThreadLocal.remove() } } }
+
+        // Initialize scope, which is a lazy type:
+        assertTrue(scope.isActive)
     }
 
     @After
     fun tearDown() {
         val sw = StringWriter()
         val pw = PrintWriter(sw)
+
         allExceptions.forEach { it.printStackTrace(pw) }
-        assertTrue("Test failed due to incorrect trace sections\n$sw", allExceptions.isEmpty())
+        assertTrue("Test failed due to unexpected exception\n$sw", allExceptions.isEmpty())
 
-        val lastEvent = eventCounter.get()
-        assertTrue(
-            "`finish()` was never called. Last seen event was #$lastEvent",
-            lastEvent == FINAL_EVENT || lastEvent == 0 || expectedExceptions,
-        )
+        assertionErrors.forEach { it.printStackTrace(pw) }
+        assertTrue("Test failed due to incorrect trace sections\n$sw", assertionErrors.isEmpty())
     }
 
+    /**
+     * Launches the test on the provided [scope], then uses [runBlocking] to wait for completion.
+     * The test will timeout if it takes longer than 200ms.
+     */
     protected fun runTest(
-        expectedException: ((Throwable) -> Boolean)? = null,
+        isExpectedException: ((Throwable) -> Boolean)? = null,
+        finalEvent: Int? = null,
+        totalEvents: Int? = null,
         block: suspend CoroutineScope.() -> Unit,
     ) {
         var foundExpectedException = false
-        if (expectedException != null) expectedExceptions = true
-        mainTraceScope.launch(
-            block = block,
-            context =
-                CoroutineExceptionHandler { _, e ->
-                    if (e is CancellationException) return@CoroutineExceptionHandler // ignore
-                    if (expectedException != null && expectedException(e)) {
-                        foundExpectedException = true
-                        return@CoroutineExceptionHandler // ignore
-                    }
-                    allExceptions.add(e)
-                },
-        )
+        try {
+            val job =
+                scope.launch(
+                    context =
+                        CoroutineExceptionHandler { _, e ->
+                            if (e is CancellationException)
+                                return@CoroutineExceptionHandler // ignore it
+                            if (isExpectedException != null && isExpectedException(e)) {
+                                foundExpectedException = true
+                            } else {
+                                allExceptions.add(e)
+                            }
+                        },
+                    block = block,
+                )
 
-        for (n in 0..1000) {
-            shadowLooper.idleFor(1, MILLISECONDS)
+            runBlocking {
+                val timeoutMs = 200L
+                try {
+                    withTimeout(timeoutMs) { job.join() }
+                } catch (e: TimeoutCancellationException) {
+                    fail("Timeout running test. Test should complete in less than $timeoutMs ms")
+                    throw e
+                } finally {
+                    scope.cancel()
+                }
+            }
+        } finally {
+            if (isExpectedException != null && !foundExpectedException) {
+                fail("Expected exceptions, but none were thrown")
+            }
         }
-
-        val names = mutableListOf<String?>()
-        var numChildren = 0
-        mainTraceScope.coroutineContext[Job]?.children?.forEach { it ->
-            names.add(it[CoroutineTraceName]?.name)
-            numChildren++
+        if (finalEvent != null) {
+            checkFinalEvent(finalEvent)
         }
-
-        val allNames =
-            names.joinToString(prefix = "{ ", separator = ", ", postfix = " }") {
-                it?.let { "\"$it\" " } ?: "unnamed"
-            }
-        assertEquals(
-            "The main test scope still has $numChildren running jobs: $allNames.",
-            0,
-            numChildren,
-        )
-        if (expectedExceptions) {
-            assertTrue("Expected exceptions, but none were thrown", foundExpectedException)
+        if (totalEvents != null) {
+            checkTotalEvents(totalEvents)
         }
     }
 
-    private fun logInvalidTraceState(message: String) {
-        allExceptions.add(InvalidTraceStateException(message))
+    private fun logInvalidTraceState(message: String, throwInsteadOfLog: Boolean = false) {
+        val e = InvalidTraceStateException(message)
+        if (throwInsteadOfLog) {
+            throw e
+        } else {
+            assertionErrors.add(e)
+        }
     }
 
     /**
@@ -152,17 +196,8 @@ open class TestBase {
         expect(*expectedOpenTraceSections)
     }
 
-    /**
-     * Same as [expect], but also call [delay] for 1ms, calling [expect] before and after the
-     * suspension point.
-     */
-    protected suspend fun expectD(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
-        expect(expectedEvent, *expectedOpenTraceSections)
-        delay(1)
-        expect(*expectedOpenTraceSections)
-    }
-
     protected fun expectEndsWith(vararg expectedOpenTraceSections: String) {
+        allEventCounter.getAndAdd(1)
         // Inspect trace output to the fake used for recording android.os.Trace API calls:
         val actualSections = getOpenTraceSectionsOnCurrentThread()
         if (expectedOpenTraceSections.size <= actualSections.size) {
@@ -192,6 +227,37 @@ open class TestBase {
         return currentEvent
     }
 
+    /**
+     * Checks the currently active trace sections on the current thread, and optionally checks the
+     * order of operations if [expectedEvent] is not null.
+     */
+    internal fun expectAny(vararg possibleOpenSections: Array<out String>) {
+        allEventCounter.getAndAdd(1)
+        val actualOpenSections = getOpenTraceSectionsOnCurrentThread()
+        val caughtExceptions = mutableListOf<AssertionError>()
+        possibleOpenSections.forEach { expectedSections ->
+            try {
+                assertTraceSectionsEquals(
+                    expectedSections,
+                    expectedEvent = null,
+                    actualOpenSections,
+                    actualEvent = null,
+                    throwInsteadOfLog = true,
+                )
+            } catch (e: AssertionError) {
+                caughtExceptions.add(e)
+            }
+        }
+        if (caughtExceptions.size == possibleOpenSections.size) {
+            val e = caughtExceptions[0]
+            val allLists =
+                possibleOpenSections.joinToString(separator = ", OR ") { it.prettyPrintList() }
+            assertionErrors.add(
+                InvalidTraceStateException("Expected $allLists. For example, ${e.message}", e.cause)
+            )
+        }
+    }
+
     internal fun expect(vararg expectedOpenTraceSections: String) {
         expect(null, *expectedOpenTraceSections)
     }
@@ -206,6 +272,7 @@ open class TestBase {
      */
     internal fun expect(possibleEventPos: List<Int>?, vararg expectedOpenTraceSections: String) {
         var currentEvent: Int? = null
+        allEventCounter.getAndAdd(1)
         if (possibleEventPos != null) {
             currentEvent = expectEvent(possibleEventPos)
         }
@@ -223,6 +290,7 @@ open class TestBase {
         expectedEvent: List<Int>?,
         actualOpenSections: Array<String>,
         actualEvent: Int?,
+        throwInsteadOfLog: Boolean = false,
     ) {
         val expectedSize = expectedOpenTraceSections.size
         val actualSize = actualOpenSections.size
@@ -234,13 +302,13 @@ open class TestBase {
                     actualOpenSections,
                     actualEvent,
                     "Size mismatch, expected size $expectedSize but was size $actualSize",
-                )
+                ),
+                throwInsteadOfLog,
             )
         } else {
-            expectedOpenTraceSections.forEachIndexed { n, expectedTrace ->
+            expectedOpenTraceSections.forEachIndexed { n, expected ->
                 val actualTrace = actualOpenSections[n]
-                val expected = expectedTrace.substringBefore(";")
-                val actual = actualTrace.substringBefore(";")
+                val actual = actualTrace.getTracedName()
                 if (expected != actual) {
                     logInvalidTraceState(
                         createFailureMessage(
@@ -249,9 +317,10 @@ open class TestBase {
                             actualOpenSections,
                             actualEvent,
                             "Differed at index #$n, expected \"$expected\" but was \"$actual\"",
-                        )
+                        ),
+                        throwInsteadOfLog,
                     )
-                    return@forEachIndexed
+                    return
                 }
             }
         }
@@ -278,28 +347,42 @@ open class TestBase {
             .trimIndent()
     }
 
-    /** Same as [expect], except that no more [expect] statements can be called after it. */
-    protected fun finish(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
+    private fun checkFinalEvent(expectedEvent: Int): Int {
         finalEvent.compareAndSet(INVALID_EVENT, expectedEvent)
         val previousEvent = eventCounter.getAndSet(FINAL_EVENT)
-        val currentEvent = previousEvent + 1
-        if (expectedEvent != currentEvent) {
+        if (expectedEvent != previousEvent) {
             logInvalidTraceState(
                 "Expected to finish with event #$expectedEvent, but " +
                     if (previousEvent == FINAL_EVENT)
                         "finish() was already called with event #${finalEvent.get()}"
-                    else "the event counter is currently at #$currentEvent"
+                    else "the event counter is currently at #$previousEvent"
             )
         }
-        assertTraceSectionsEquals(
-            expectedOpenTraceSections,
-            listOf(expectedEvent),
-            getOpenTraceSectionsOnCurrentThread(),
-            currentEvent,
-        )
+        return previousEvent
+    }
+
+    private fun checkTotalEvents(totalEvents: Int): Int {
+        allEventCounter.compareAndSet(INVALID_EVENT, totalEvents)
+        val previousEvent = allEventCounter.getAndSet(FINAL_EVENT)
+        if (totalEvents != previousEvent) {
+            logInvalidTraceState(
+                "Expected test to end with a total of $totalEvents events, but " +
+                    if (previousEvent == FINAL_EVENT)
+                        "finish() was already called at event #${finalEvent.get()}"
+                    else "instead there were $previousEvent events"
+            )
+        }
+        return previousEvent
     }
 }
 
+private fun String.getTracedName(): String =
+    if (startsWith(COROUTINE_EXECUTION))
+    // For strings like "coroutine execution;scope-name;c=1234;p=5678", extract:
+    // "scope-name"
+    substringAfter(";").substringBefore(";")
+    else substringBefore(";")
+
 private const val INVALID_EVENT = -1
 
 private const val FINAL_EVENT = Int.MIN_VALUE
@@ -322,6 +405,6 @@ private fun Array<out String>.prettyPrintList(): String {
     return if (isEmpty()) ""
     else
         toList().joinToString(separator = "\", \"", prefix = "\"", postfix = "\"") {
-            it.substringBefore(";")
+            it.getTracedName()
         }
 }
diff --git a/tracinglib/robolectric/src/util/FakeTraceState.kt b/tracinglib/robolectric/src/util/FakeTraceState.kt
index 4a0eb8c..d3c95e3 100644
--- a/tracinglib/robolectric/src/util/FakeTraceState.kt
+++ b/tracinglib/robolectric/src/util/FakeTraceState.kt
@@ -16,42 +16,52 @@
 
 package com.android.test.tracing.coroutines.util
 
+import kotlin.concurrent.Volatile
 import org.junit.Assert.assertFalse
 
+private val ALL_THREAD_STATES = hashMapOf<Thread, MutableList<String>>()
+
+private class ThreadTraceState : ThreadLocal<MutableList<String>>() {
+    override fun initialValue(): MutableList<String> {
+        synchronized(ALL_THREAD_STATES) {
+            val newValue = mutableListOf<String>()
+            ALL_THREAD_STATES[Thread.currentThread()] = newValue
+            return newValue
+        }
+    }
+}
+
+private val CURRENT_TRACE_STATE = ThreadTraceState()
+
+private fun currentThreadTraceState(): MutableList<String> {
+    return CURRENT_TRACE_STATE.get()!!
+}
+
 object FakeTraceState {
 
-    var isTracingEnabled: Boolean = true
+    @Volatile @JvmStatic var isTracingEnabled: Boolean = true
 
-    private val allThreadStates = hashMapOf<Long, MutableList<String>>()
+    fun clearAll() {
+        synchronized(ALL_THREAD_STATES) { ALL_THREAD_STATES.entries.forEach { it.value.clear() } }
+    }
 
     fun begin(sectionName: String) {
-        val threadId = currentThreadId()
-        synchronized(allThreadStates) {
-            if (allThreadStates.containsKey(threadId)) {
-                allThreadStates[threadId]!!.add(sectionName)
-            } else {
-                allThreadStates[threadId] = mutableListOf(sectionName)
-            }
-        }
+        currentThreadTraceState().add(sectionName)
     }
 
     fun end() {
-        val threadId = currentThreadId()
-        synchronized(allThreadStates) {
-            assertFalse(
-                "Attempting to close trace section on thread=$threadId, " +
-                    "but there are no open sections",
-                allThreadStates[threadId].isNullOrEmpty(),
-            )
-            allThreadStates[threadId]!!.removeLast()
-        }
+        val threadId = Thread.currentThread().threadId()
+        val traceSections = currentThreadTraceState()
+        assertFalse(
+            "Attempting to close trace section on thread #$threadId, " +
+                "but there are no open sections",
+            traceSections.isEmpty(),
+        )
+        traceSections.removeLast()
     }
 
     fun getOpenTraceSectionsOnCurrentThread(): Array<String> {
-        val threadId = currentThreadId()
-        synchronized(allThreadStates) {
-            return allThreadStates[threadId]?.toTypedArray() ?: emptyArray()
-        }
+        return currentThreadTraceState().toTypedArray()
     }
 
     /**
@@ -62,8 +72,8 @@ object FakeTraceState {
      */
     override fun toString(): String {
         val sb = StringBuilder()
-        synchronized(allThreadStates) {
-            allThreadStates.entries.forEach { sb.appendLine("${it.key} -> ${it.value}") }
+        synchronized(ALL_THREAD_STATES) {
+            ALL_THREAD_STATES.entries.forEach { sb.appendLine("${it.key} -> ${it.value}") }
         }
         return sb.toString()
     }
diff --git a/tracinglib/robolectric/src/util/ShadowTrace.kt b/tracinglib/robolectric/src/util/ShadowTrace.kt
index 683f7ab..b7512a0 100644
--- a/tracinglib/robolectric/src/util/ShadowTrace.kt
+++ b/tracinglib/robolectric/src/util/ShadowTrace.kt
@@ -29,33 +29,59 @@ object ShadowTrace {
     @Implementation
     @JvmStatic
     fun isEnabled(): Boolean {
-        return FakeTraceState.isTracingEnabled
+        return isTagEnabled(Trace.TRACE_TAG_APP)
+    }
+
+    @Implementation
+    @JvmStatic
+    fun isTagEnabled(traceTag: Long): Boolean {
+        return FakeTraceState.isTracingEnabled && traceTag == Trace.TRACE_TAG_APP
     }
 
     @Implementation
     @JvmStatic
     fun traceBegin(traceTag: Long, methodName: String) {
-        debug { "traceBegin: name=$methodName" }
-        FakeTraceState.begin(methodName)
+        if (traceTag == Trace.TRACE_TAG_APP && isTagEnabled(traceTag)) {
+            debug("traceBegin: $methodName")
+            FakeTraceState.begin(methodName)
+        } else {
+            debug("IGNORE traceBegin: $methodName")
+        }
     }
 
     @Implementation
     @JvmStatic
     fun traceEnd(traceTag: Long) {
-        debug { "traceEnd" }
-        FakeTraceState.end()
+        if (traceTag == Trace.TRACE_TAG_APP && isTagEnabled(traceTag)) {
+            debug("traceEnd")
+            FakeTraceState.end()
+        } else {
+            debug("IGNORE traceEnd")
+        }
+    }
+
+    @Implementation
+    @JvmStatic
+    fun beginSection(sectionName: String) {
+        debug("IGNORE beginSection")
+    }
+
+    @Implementation
+    @JvmStatic
+    fun endSection() {
+        debug("IGNORE endSection()")
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceBegin(traceTag: Long, methodName: String, cookie: Int) {
-        debug { "asyncTraceBegin: name=$methodName cookie=${cookie.toHexString()}" }
+        debug("IGNORE asyncTraceBegin")
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceEnd(traceTag: Long, methodName: String, cookie: Int) {
-        debug { "asyncTraceEnd: name=$methodName cookie=${cookie.toHexString()}" }
+        debug("IGNORE asyncTraceEnd")
     }
 
     @Implementation
@@ -66,35 +92,37 @@ object ShadowTrace {
         methodName: String,
         cookie: Int,
     ) {
-        debug {
-            "asyncTraceForTrackBegin: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
-        }
+        debug("IGNORE asyncTraceForTrackBegin")
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceForTrackEnd(traceTag: Long, trackName: String, methodName: String, cookie: Int) {
-        debug {
-            "asyncTraceForTrackEnd: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
-        }
+        debug("IGNORE asyncTraceForTrackEnd")
     }
 
     @Implementation
     @JvmStatic
     fun instant(traceTag: Long, eventName: String) {
-        debug { "instant: name=$eventName" }
+        debug("IGNORE instant")
     }
 
     @Implementation
     @JvmStatic
     fun instantForTrack(traceTag: Long, trackName: String, eventName: String) {
-        debug { "instantForTrack: track=$trackName name=$eventName" }
+        debug("IGNORE instantForTrack")
     }
 }
 
 private const val DEBUG = false
 
 /** Log a message with a tag indicating the current thread ID */
-private fun debug(message: () -> String) {
-    if (DEBUG) Log.d("ShadowTrace", "Thread #${currentThreadId()}: $message")
+private fun debug(message: String, e: Throwable? = null) {
+    if (DEBUG) {
+        if (e != null) {
+            Log.d("ShadowTrace", "Thread #${Thread.currentThread().threadId()}: $message", e)
+        } else {
+            Log.d("ShadowTrace", "Thread #${Thread.currentThread().threadId()}: $message")
+        }
+    }
 }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
index 33f6a95..e6f0c72 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
@@ -24,11 +24,13 @@ import android.content.Context;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.media.permission.SafeCloseable;
+import android.os.Handler;
 import android.os.HandlerThread;
 import android.os.Looper;
 import android.os.SystemClock;
 import android.os.Trace;
 import android.text.TextUtils;
+import android.util.Log;
 import android.util.SparseArray;
 import android.view.View;
 import android.view.ViewGroup;
@@ -52,6 +54,7 @@ import java.io.DataOutputStream;
 import java.io.IOException;
 import java.io.OutputStream;
 import java.util.ArrayList;
+import java.util.Collections;
 import java.util.List;
 import java.util.Optional;
 import java.util.concurrent.CompletableFuture;
@@ -60,6 +63,7 @@ import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
 import java.util.function.Predicate;
+import java.util.stream.Collectors;
 
 /**
  * Utility class for capturing view data every frame
@@ -77,6 +81,10 @@ public abstract class ViewCapture {
 
     // Number of frames to keep in memory
     private final int mMemorySize;
+
+    // Number of ViewPropertyRef to preallocate per window
+    private final int mInitPoolSize;
+
     protected static final int DEFAULT_MEMORY_SIZE = 2000;
     // Initial size of the reference pool. This is at least be 5 * total number of views in
     // Launcher. This allows the first free frames avoid object allocation during view capture.
@@ -84,18 +92,19 @@ public abstract class ViewCapture {
 
     public static final LooperExecutor MAIN_EXECUTOR = new LooperExecutor(Looper.getMainLooper());
 
-    private final List<WindowListener> mListeners = new ArrayList<>();
+    private final List<WindowListener> mListeners = Collections.synchronizedList(new ArrayList<>());
 
     protected final Executor mBgExecutor;
 
-    // Pool used for capturing view tree on the UI thread.
-    private ViewPropertyRef mPool = new ViewPropertyRef();
     private boolean mIsEnabled = true;
 
+    @VisibleForTesting
+    public boolean mIsStarted = false;
+
     protected ViewCapture(int memorySize, int initPoolSize, Executor bgExecutor) {
         mMemorySize = memorySize;
         mBgExecutor = bgExecutor;
-        mBgExecutor.execute(() -> initPool(initPoolSize));
+        mInitPoolSize = initPoolSize;
     }
 
     public static LooperExecutor createAndStartNewLooperExecutor(String name, int priority) {
@@ -104,29 +113,10 @@ public abstract class ViewCapture {
         return new LooperExecutor(thread.getLooper());
     }
 
-    @UiThread
-    private void addToPool(ViewPropertyRef start, ViewPropertyRef end) {
-        end.next = mPool;
-        mPool = start;
-    }
-
-    @WorkerThread
-    private void initPool(int initPoolSize) {
-        ViewPropertyRef start = new ViewPropertyRef();
-        ViewPropertyRef current = start;
-
-        for (int i = 0; i < initPoolSize; i++) {
-            current.next = new ViewPropertyRef();
-            current = current.next;
-        }
-
-        ViewPropertyRef finalCurrent = current;
-        MAIN_EXECUTOR.execute(() -> addToPool(start, finalCurrent));
-    }
-
     /**
      * Attaches the ViewCapture to the provided window and returns a handle to detach the listener
      */
+    @AnyThread
     @NonNull
     public SafeCloseable startCapture(@NonNull Window window) {
         String title = window.getAttributes().getTitle().toString();
@@ -138,11 +128,18 @@ public abstract class ViewCapture {
      * Attaches the ViewCapture to the provided window and returns a handle to detach the listener.
      * Verifies that ViewCapture is enabled before actually attaching an onDrawListener.
      */
+    @AnyThread
     @NonNull
     public SafeCloseable startCapture(@NonNull View view, @NonNull String name) {
+        mIsStarted = true;
         WindowListener listener = new WindowListener(view, name);
-        if (mIsEnabled) MAIN_EXECUTOR.execute(listener::attachToRoot);
+
+        if (mIsEnabled) {
+            listener.attachToRoot();
+        }
+
         mListeners.add(listener);
+
         view.getContext().registerComponentCallbacks(listener);
 
         return () -> {
@@ -150,6 +147,7 @@ public abstract class ViewCapture {
                 listener.mRoot.getContext().unregisterComponentCallbacks(listener);
             }
             mListeners.remove(listener);
+
             listener.detachFromRoot();
         };
     }
@@ -164,16 +162,22 @@ public abstract class ViewCapture {
      * are still technically enabled to allow for dumping.
      */
     @VisibleForTesting
+    @AnyThread
     public void stopCapture(@NonNull View rootView) {
+        mIsStarted = false;
         mListeners.forEach(it -> {
             if (rootView == it.mRoot) {
-                it.mRoot.getViewTreeObserver().removeOnDrawListener(it);
-                it.mRoot = null;
+                runOnUiThread(() -> {
+                    if (it.mRoot != null) {
+                        it.mRoot.getViewTreeObserver().removeOnDrawListener(it);
+                        it.mRoot = null;
+                    }
+                }, it.mRoot);
             }
         });
     }
 
-    @UiThread
+    @AnyThread
     protected void enableOrDisableWindowListeners(boolean isEnabled) {
         mIsEnabled = isEnabled;
         mListeners.forEach(WindowListener::detachFromRoot);
@@ -206,7 +210,7 @@ public abstract class ViewCapture {
     }
 
     private static List<String> toStringList(List<Class> classList) {
-        return classList.stream().map(Class::getName).toList();
+        return classList.stream().map(Class::getName).collect(Collectors.toList());
     }
 
     public CompletableFuture<Optional<MotionWindowData>> getDumpTask(View view) {
@@ -223,10 +227,15 @@ public abstract class ViewCapture {
     private CompletableFuture<List<WindowData>> getWindowData(Context context,
             ArrayList<Class> outClassList, Predicate<WindowListener> filter) {
         ViewIdProvider idProvider = new ViewIdProvider(context.getResources());
-        return CompletableFuture.supplyAsync(() ->
-                mListeners.stream().filter(filter).toList(), MAIN_EXECUTOR).thenApplyAsync(it ->
-                        it.stream().map(l -> l.dumpToProto(idProvider, outClassList)).toList(),
-                mBgExecutor);
+        return CompletableFuture.supplyAsync(
+                () -> mListeners.stream()
+                        .filter(filter)
+                        .collect(Collectors.toList()),
+                MAIN_EXECUTOR).thenApplyAsync(
+                        it -> it.stream()
+                                .map(l -> l.dumpToProto(idProvider, outClassList))
+                                .collect(Collectors.toList()),
+                        mBgExecutor);
     }
 
     @WorkerThread
@@ -234,6 +243,24 @@ public abstract class ViewCapture {
             ViewPropertyRef startFlattenedViewTree) {
     }
 
+    @AnyThread
+    void runOnUiThread(Runnable action, View view) {
+        if (view == null) {
+            // Corner case. E.g.: the capture is stopped (root view set to null),
+            // but the bg thread is still processing work.
+            Log.i(TAG, "Skipping run on UI thread. Provided view == null.");
+            return;
+        }
+
+        Handler handlerUi = view.getHandler();
+        if (handlerUi != null && handlerUi.getLooper().getThread() == Thread.currentThread()) {
+            action.run();
+            return;
+        }
+
+        view.post(action);
+    }
+
     /**
      * Once this window listener is attached to a window's root view, it traverses the entire
      * view tree on the main thread every time onDraw is called. It then saves the state of the view
@@ -283,6 +310,8 @@ public abstract class ViewCapture {
         public View mRoot;
         public final String name;
 
+        // Pool used for capturing view tree on the UI thread.
+        private ViewPropertyRef mPool = new ViewPropertyRef();
         private final ViewPropertyRef mViewPropertyRef = new ViewPropertyRef();
 
         private int mFrameIndexBg = -1;
@@ -297,6 +326,7 @@ public abstract class ViewCapture {
         WindowListener(View view, String name) {
             mRoot = view;
             this.name = name;
+            initPool(mInitPoolSize);
         }
 
         /**
@@ -306,21 +336,27 @@ public abstract class ViewCapture {
          * thread via mExecutor.
          */
         @Override
+        @UiThread
         public void onDraw() {
             Trace.beginSection("vc#onDraw");
-            captureViewTree(mRoot, mViewPropertyRef);
-            ViewPropertyRef captured = mViewPropertyRef.next;
-            if (captured != null) {
-                captured.elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
-
-                // Main thread writes volatile field:
-                // guarantee that variable changes prior the field write are visible to bg thread
-                captured.volatileCallback = mCaptureCallback;
-
-                mBgExecutor.execute(captured);
+            try {
+                View root = mRoot;
+                if (root == null) {
+                    // Handle the corner case where another (non-UI) thread
+                    // concurrently stopped the capture and set mRoot = null
+                    return;
+                }
+                captureViewTree(root, mViewPropertyRef);
+                ViewPropertyRef captured = mViewPropertyRef.next;
+                if (captured != null) {
+                    captured.callback = mCaptureCallback;
+                    captured.elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
+                    mBgExecutor.execute(captured);
+                }
+                mIsFirstFrame = false;
+            } finally {
+                Trace.endSection();
             }
-            mIsFirstFrame = false;
-            Trace.endSection();
         }
 
         /**
@@ -401,7 +437,7 @@ public abstract class ViewCapture {
                     // The compiler will complain about using a non-final variable from
                     // an outer class in a lambda if we pass in 'end' directly.
                     final ViewPropertyRef finalEnd = end;
-                    MAIN_EXECUTOR.execute(() -> addToPool(start, finalEnd));
+                    runOnUiThread(() -> addToPool(start, finalEnd), mRoot);
                     break;
                 }
                 end = end.next;
@@ -413,6 +449,7 @@ public abstract class ViewCapture {
             Trace.endSection();
         }
 
+        @WorkerThread
         private @Nullable ViewPropertyRef findInLastFrame(int hashCode) {
             int lastFrameIndex = (mFrameIndexBg == 0) ? mMemorySize - 1 : mFrameIndexBg - 1;
             ViewPropertyRef viewPropertyRef = mNodesBg[lastFrameIndex];
@@ -422,35 +459,72 @@ public abstract class ViewCapture {
             return viewPropertyRef;
         }
 
+        private void initPool(int initPoolSize) {
+            ViewPropertyRef start = new ViewPropertyRef();
+            ViewPropertyRef current = start;
+
+            for (int i = 0; i < initPoolSize; i++) {
+                current.next = new ViewPropertyRef();
+                current = current.next;
+            }
+
+            ViewPropertyRef finalCurrent = current;
+            addToPool(start, finalCurrent);
+        }
+
+        private void addToPool(ViewPropertyRef start, ViewPropertyRef end) {
+            end.next = mPool;
+            mPool = start;
+        }
+
+        @UiThread
+        private ViewPropertyRef getFromPool() {
+            ViewPropertyRef ref = mPool;
+            if (ref != null) {
+                mPool = ref.next;
+                ref.next = null;
+            } else {
+                ref = new ViewPropertyRef();
+            }
+            return ref;
+        }
+
+        @AnyThread
         void attachToRoot() {
             if (mRoot == null) return;
             mIsActive = true;
-            if (mRoot.isAttachedToWindow()) {
-                safelyEnableOnDrawListener();
-            } else {
-                mRoot.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
-                    @Override
-                    public void onViewAttachedToWindow(View v) {
-                        if (mIsActive) {
-                            safelyEnableOnDrawListener();
+            runOnUiThread(() -> {
+                if (mRoot.isAttachedToWindow()) {
+                    safelyEnableOnDrawListener();
+                } else {
+                    mRoot.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
+                        @Override
+                        public void onViewAttachedToWindow(View v) {
+                            if (mIsActive) {
+                                safelyEnableOnDrawListener();
+                            }
+                            mRoot.removeOnAttachStateChangeListener(this);
                         }
-                        mRoot.removeOnAttachStateChangeListener(this);
-                    }
 
-                    @Override
-                    public void onViewDetachedFromWindow(View v) {
-                    }
-                });
-            }
+                        @Override
+                        public void onViewDetachedFromWindow(View v) {
+                        }
+                    });
+                }
+            }, mRoot);
         }
 
+        @AnyThread
         void detachFromRoot() {
             mIsActive = false;
-            if (mRoot != null) {
-                mRoot.getViewTreeObserver().removeOnDrawListener(this);
-            }
+            runOnUiThread(() -> {
+                if (mRoot != null) {
+                    mRoot.getViewTreeObserver().removeOnDrawListener(this);
+                }
+            }, mRoot);
         }
 
+        @UiThread
         private void safelyEnableOnDrawListener() {
             if (mRoot != null) {
                 mRoot.getViewTreeObserver().removeOnDrawListener(this);
@@ -474,15 +548,9 @@ public abstract class ViewCapture {
             return builder.build();
         }
 
+        @UiThread
         private ViewPropertyRef captureViewTree(View view, ViewPropertyRef start) {
-            ViewPropertyRef ref;
-            if (mPool != null) {
-                ref = mPool;
-                mPool = mPool.next;
-                ref.next = null;
-            } else {
-                ref = new ViewPropertyRef();
-            }
+            ViewPropertyRef ref = getFromPool();
             start.next = ref;
             if (view instanceof ViewGroup) {
                 ViewGroup parent = (ViewGroup) view;
@@ -556,11 +624,9 @@ public abstract class ViewCapture {
 
         public ViewPropertyRef next;
 
+        public Consumer<ViewPropertyRef> callback = null;
         public long elapsedRealtimeNanos = 0;
 
-        // Volatile field to establish happens-before relationship between main and bg threads
-        // (see JSR-133: Java Memory Model and Thread Specification)
-        public volatile Consumer<ViewPropertyRef> volatileCallback = null;
 
         public void transferFrom(View in) {
             view = in;
@@ -657,10 +723,8 @@ public abstract class ViewCapture {
 
         @Override
         public void run() {
-            // Bg thread reads volatile field:
-            // guarantee that variable changes in main thread prior the field write are visible
-            Consumer<ViewPropertyRef> oldCallback = volatileCallback;
-            volatileCallback = null;
+            Consumer<ViewPropertyRef> oldCallback = callback;
+            callback = null;
             if (oldCallback != null) {
                 oldCallback.accept(this);
             }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
index 59e35da..416d441 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
@@ -16,57 +16,51 @@
 
 package com.android.app.viewcapture
 
+import android.content.Context
 import android.media.permission.SafeCloseable
+import android.os.IBinder
 import android.view.View
 import android.view.ViewGroup
+import android.view.Window
 import android.view.WindowManager
-
-/** Tag for debug logging. */
-private const val TAG = "ViewCaptureWindowManager"
+import android.view.WindowManagerImpl
 
 /**
- * Wrapper class for [WindowManager]. Adds [ViewCapture] to associated window when it is added to
- * view hierarchy.
+ * [WindowManager] implementation to enable view tracing. Adds [ViewCapture] to associated window
+ * when it is added to view hierarchy. Use [ViewCaptureAwareWindowManagerFactory] to create an
+ * instance of this class.
  */
-class ViewCaptureAwareWindowManager(
-    private val windowManager: WindowManager,
-    private val lazyViewCapture: Lazy<ViewCapture>,
-    private val isViewCaptureEnabled: Boolean,
-) : WindowManager by windowManager {
+internal class ViewCaptureAwareWindowManager(
+    private val context: Context,
+    private val parent: Window? = null,
+    private val windowContextToken: IBinder? = null,
+) : WindowManagerImpl(context, parent, windowContextToken) {
 
     private var viewCaptureCloseableMap: MutableMap<View, SafeCloseable> = mutableMapOf()
 
-    override fun addView(view: View, params: ViewGroup.LayoutParams?) {
-        windowManager.addView(view, params)
-        if (isViewCaptureEnabled) {
-            val viewCaptureCloseable: SafeCloseable =
-                lazyViewCapture.value.startCapture(view, getViewName(view))
-            viewCaptureCloseableMap[view] = viewCaptureCloseable
-        }
+    override fun addView(view: View, params: ViewGroup.LayoutParams) {
+        super.addView(view, params)
+        val viewCaptureCloseable: SafeCloseable =
+            ViewCaptureFactory.getInstance(context).startCapture(view, getViewName(view))
+        viewCaptureCloseableMap[view] = viewCaptureCloseable
     }
 
     override fun removeView(view: View?) {
         removeViewFromCloseableMap(view)
-        windowManager.removeView(view)
+        super.removeView(view)
     }
 
     override fun removeViewImmediate(view: View?) {
         removeViewFromCloseableMap(view)
-        windowManager.removeViewImmediate(view)
+        super.removeViewImmediate(view)
     }
 
     private fun getViewName(view: View) = "." + view.javaClass.name
 
     private fun removeViewFromCloseableMap(view: View?) {
-        if (isViewCaptureEnabled) {
-            if (viewCaptureCloseableMap.containsKey(view)) {
-                viewCaptureCloseableMap[view]?.close()
-                viewCaptureCloseableMap.remove(view)
-            }
+        if (viewCaptureCloseableMap.containsKey(view)) {
+            viewCaptureCloseableMap[view]?.close()
+            viewCaptureCloseableMap.remove(view)
         }
     }
-
-    interface Factory {
-        fun create(windowManager: WindowManager): ViewCaptureAwareWindowManager
-    }
 }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt
new file mode 100644
index 0000000..d471f27
--- /dev/null
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManagerFactory.kt
@@ -0,0 +1,63 @@
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
+package com.android.app.viewcapture
+
+import android.content.Context
+import android.os.IBinder
+import android.os.Trace
+import android.os.Trace.TRACE_TAG_APP
+import android.view.Window
+import android.view.WindowManager
+import java.lang.ref.WeakReference
+import java.util.Collections
+import java.util.WeakHashMap
+
+
+/** Factory to create [Context] specific instances of [ViewCaptureAwareWindowManager]. */
+object ViewCaptureAwareWindowManagerFactory {
+
+    /**
+     * Keeps track of [ViewCaptureAwareWindowManager] instance for a [Context]. It is a
+     * [WeakHashMap] to ensure that if a [Context] mapped in the [instanceMap] is destroyed, the map
+     * entry is garbage collected as well.
+     */
+    private val instanceMap =
+        Collections.synchronizedMap(WeakHashMap<Context, WeakReference<WindowManager>>())
+
+    /**
+     * Returns the weakly cached [ViewCaptureAwareWindowManager] instance for a given [Context]. If
+     * no instance is cached; it creates, caches and returns a new instance.
+     */
+    @JvmStatic
+    fun getInstance(
+        context: Context,
+        parent: Window? = null,
+        windowContextToken: IBinder? = null,
+    ): WindowManager {
+        Trace.traceCounter(TRACE_TAG_APP,
+            "ViewCaptureAwareWindowManagerFactory#instanceMap.size", instanceMap.size)
+
+        val cachedWindowManager = instanceMap[context]?.get()
+        if (cachedWindowManager != null) {
+            return cachedWindowManager
+        } else {
+            val windowManager = ViewCaptureAwareWindowManager(context, parent, windowContextToken)
+            instanceMap[context] = WeakReference(windowManager)
+            return windowManager
+        }
+    }
+}
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
index 2e6a783..2575dbd 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
@@ -20,7 +20,6 @@ import android.content.Context
 import android.os.Process
 import android.tracing.Flags
 import android.util.Log
-import android.view.WindowManager
 
 /**
  * Factory to create polymorphic instances of ViewCapture according to build configurations and
@@ -68,19 +67,4 @@ object ViewCaptureFactory {
         }
         return instance
     }
-
-    /** Returns an instance of [ViewCaptureAwareWindowManager]. */
-    @JvmStatic
-    fun getViewCaptureAwareWindowManagerInstance(
-        context: Context,
-        isViewCaptureTracingEnabled: Boolean,
-    ): ViewCaptureAwareWindowManager {
-        val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
-        val lazyViewCapture = lazy { getInstance(context) }
-        return ViewCaptureAwareWindowManager(
-            windowManager,
-            lazyViewCapture,
-            isViewCaptureTracingEnabled,
-        )
-    }
 }
diff --git a/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
index 174639b..9e3175d 100644
--- a/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
+++ b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
@@ -17,69 +17,42 @@
 package com.android.app.viewcapture
 
 import android.content.Context
+import android.content.Intent
 import android.testing.AndroidTestingRunner
-import android.view.View
 import android.view.WindowManager
-import androidx.test.core.app.ApplicationProvider
+import androidx.test.ext.junit.rules.ActivityScenarioRule
 import androidx.test.filters.SmallTest
-import org.junit.Before
+import androidx.test.platform.app.InstrumentationRegistry
+import org.junit.Assert.assertTrue
+import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
-import org.mockito.ArgumentMatchers.any
-import org.mockito.ArgumentMatchers.anyString
-import org.mockito.Mockito.doAnswer
-import org.mockito.Mockito.spy
-import org.mockito.Mockito.times
-import org.mockito.Mockito.verify
-import org.mockito.Mockito.`when`
-import org.mockito.invocation.InvocationOnMock
-import org.mockito.kotlin.doReturn
-import org.mockito.kotlin.mock
 
 @RunWith(AndroidTestingRunner::class)
 @SmallTest
 class ViewCaptureAwareWindowManagerTest {
-    private val context: Context = ApplicationProvider.getApplicationContext()
-    private val mockRootView = mock<View>()
-    private val windowManager = mock<WindowManager>()
-    private val viewCaptureSpy = spy(ViewCaptureFactory.getInstance(context))
-    private val lazyViewCapture = mock<Lazy<ViewCapture>> { on { value } doReturn viewCaptureSpy }
-    private var mViewCaptureAwareWindowManager: ViewCaptureAwareWindowManager? = null
+    private val mContext: Context = InstrumentationRegistry.getInstrumentation().context
+    private lateinit var mViewCaptureAwareWindowManager: ViewCaptureAwareWindowManager
 
-    @Before
-    fun setUp() {
-        doAnswer { invocation: InvocationOnMock ->
-                val view = invocation.getArgument<View>(0)
-                val lp = invocation.getArgument<WindowManager.LayoutParams>(1)
-                view.layoutParams = lp
-                null
-            }
-            .`when`(windowManager)
-            .addView(any(View::class.java), any(WindowManager.LayoutParams::class.java))
-        `when`(mockRootView.context).thenReturn(context)
-    }
+    private val activityIntent = Intent(mContext, TestActivity::class.java)
 
-    @Test
-    fun testAddView_viewCaptureEnabled_verifyStartCaptureCall() {
-        mViewCaptureAwareWindowManager =
-            ViewCaptureAwareWindowManager(
-                windowManager,
-                lazyViewCapture,
-                isViewCaptureEnabled = true
-            )
-        mViewCaptureAwareWindowManager?.addView(mockRootView, mockRootView.layoutParams)
-        verify(viewCaptureSpy).startCapture(any(), anyString())
-    }
+    @get:Rule val activityScenarioRule = ActivityScenarioRule<TestActivity>(activityIntent)
 
     @Test
-    fun testAddView_viewCaptureNotEnabled_verifyStartCaptureCall() {
-        mViewCaptureAwareWindowManager =
-            ViewCaptureAwareWindowManager(
-                windowManager,
-                lazyViewCapture,
-                isViewCaptureEnabled = false
+    fun testAddView_verifyStartCaptureCall() {
+        activityScenarioRule.scenario.onActivity { activity ->
+            mViewCaptureAwareWindowManager = ViewCaptureAwareWindowManager(mContext)
+
+            val activityDecorView = activity.window.decorView
+            // removing view since it is already added to view hierarchy on declaration
+            mViewCaptureAwareWindowManager.removeView(activityDecorView)
+            val viewCapture = ViewCaptureFactory.getInstance(mContext)
+
+            mViewCaptureAwareWindowManager.addView(
+                activityDecorView,
+                activityDecorView.layoutParams as WindowManager.LayoutParams,
             )
-        mViewCaptureAwareWindowManager?.addView(mockRootView, mockRootView.layoutParams)
-        verify(viewCaptureSpy, times(0)).startCapture(any(), anyString())
+            assertTrue(viewCapture.mIsStarted)
+        }
     }
 }
diff --git a/weathereffects/graphics/assets/shaders/glass_rain.agsl b/weathereffects/graphics/assets/shaders/glass_rain.agsl
index 001239b..0d7d9e8 100644
--- a/weathereffects/graphics/assets/shaders/glass_rain.agsl
+++ b/weathereffects/graphics/assets/shaders/glass_rain.agsl
@@ -183,8 +183,8 @@ vec3 generateStaticGlassRain(vec2 uv, half time, half intensity, vec2 gridSize)
     // Apply a curve to the time.
     normalizedTime *= normalizedTime;
 
-    vec2 pos = cellUv * (1.5 - 0.5 * cellId + normalizedTime * 50.);
-    float mask = smoothstep(0.3, 0.2, length(pos))
+     vec2 pos = cellUv * (1.5 - 0.5 * cellId + normalizedTime * 50.);
+     float mask = smoothstep(0.3, 0.2, length(pos))
                  * smoothstep(0.2, 0.06, normalizedTime)
                  * smoothstep(0., 0.45, intensity);
 
diff --git a/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl b/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl
deleted file mode 100644
index 8fdf1fc..0000000
--- a/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl
+++ /dev/null
@@ -1,105 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-uniform shader texture;
-uniform float time;
-uniform float screenAspectRatio;
-uniform float gridScale;
-uniform float2 screenSize;
-uniform half intensity;
-
-#include "shaders/constants.agsl"
-#include "shaders/utils.agsl"
-#include "shaders/glass_rain.agsl"
-#include "shaders/rain_constants.agsl"
-
-vec4 main(float2 fragCoord) {
-    // 0. Calculate UV and add a bit of noise so that the droplets are not perfect circles.
-    float2 uv = vec2(valueNoise(fragCoord) * 0.015 - 0.0025) + fragCoord / screenSize;
-
-    // 1. Generate small glass rain.
-    GlassRain smallDrippingRain = generateGlassRain(
-         uv,
-         screenAspectRatio,
-         time * 0.7,
-         /* Grid size = */ vec2(5.0, 1.6) * gridScale,
-         intensity * 0.6);
-    float dropMask = smallDrippingRain.dropMask;
-    float droppletsMask = smallDrippingRain.droppletsMask;
-    float trailMask = smallDrippingRain.trailMask;
-    vec2 dropUvMasked = smallDrippingRain.drop * dropMask;
-    vec2 droppletsUvMasked = smallDrippingRain.dropplets * droppletsMask;
-
-    // 2. Generate medium size glass rain.
-    GlassRain medDrippingRain = generateGlassRain(
-          uv,
-          screenAspectRatio,
-          time * 0.80,
-          /* Grid size = */ vec2(6., 0.945) * gridScale,
-          intensity * 0.6);
-
-    // 3. Combine those two glass rains.
-    dropMask = max(medDrippingRain.dropMask, dropMask);
-    droppletsMask = max(medDrippingRain.droppletsMask, droppletsMask);
-    trailMask = max(medDrippingRain.trailMask, trailMask);
-    dropUvMasked = mix(dropUvMasked,
-        medDrippingRain.drop * medDrippingRain.dropMask, medDrippingRain.dropMask);
-    droppletsUvMasked = mix(droppletsUvMasked,
-        medDrippingRain.dropplets * medDrippingRain.droppletsMask, medDrippingRain.droppletsMask);
-
-    // 4. Add static rain droplets on the glass surface. (They stay in place and dissapate.)
-    vec2 gridSize = vec2(12., 12.) * gridScale;
-    // Aspect ratio impacts visible cells.
-    gridSize.y /= screenAspectRatio;
-    vec3 staticRain = generateStaticGlassRain(uv, time, intensity, gridSize);
-    dropMask = max(dropMask, staticRain.z);
-    dropUvMasked = mix(dropUvMasked, staticRain.xy * staticRain.z, staticRain.z);
-
-    // 5. Distort uv for the rain drops and dropplets.
-    float distortionDrop = -0.1;
-    vec2 uvDiffractionOffsets =
-        distortionDrop * dropUvMasked;
-    vec2 s = screenSize;
-    // Ensure the diffracted image in drops is not inverted.
-    s.y *= -1;
-
-    vec4 color = texture.eval(fragCoord);
-    vec3 sampledColor = texture.eval(fragCoord + uvDiffractionOffsets * s).rgb;
-    color.rgb = mix(color.rgb, sampledColor, max(dropMask, droppletsMask));
-
-    // 6. Add color tint to the rain drops.
-    color.rgb = mix(
-        color.rgb,
-        dropTint,
-        dropTintIntensity * smoothstep(0.7, 1., max(dropMask, droppletsMask)));
-
-    // 7. Add highlight to the drops.
-    color.rgb = mix(
-        color.rgb,
-        highlightColor,
-        highlightIntensity
-            * smoothstep(0.05, 0.08, max(dropUvMasked * 1.7, droppletsUvMasked * 2.6)).x);
-
-    // 8. Add shadows to the drops.
-    color.rgb = mix(
-        color.rgb,
-        contactShadowColor,
-        dropShadowIntensity *
-            smoothstep(0.055, 0.1, max(length(dropUvMasked * 1.7),
-                length(droppletsUvMasked * 1.9))));
-
-    return color;
-}
\ No newline at end of file
diff --git a/weathereffects/graphics/assets/shaders/rain_shower.agsl b/weathereffects/graphics/assets/shaders/rain_shower.agsl
index c3afeba..97dffea 100644
--- a/weathereffects/graphics/assets/shaders/rain_shower.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_shower.agsl
@@ -41,8 +41,6 @@ Rain generateRain(
     in float rainIntensity
 ) {
     /* Grid. */
-    // Number of rows and columns (each one is a cell, a drop).
-    float cellAspectRatio = rainGridSize.x / rainGridSize.y;
     // Aspect ratio impacts visible cells.
     uv.y /= screenAspectRatio;
     // scale the UV to allocate number of rows and columns.
diff --git a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
index f039c76..76aa075 100644
--- a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
@@ -30,6 +30,7 @@ uniform mat3 transformMatrixWeather;
 #include "shaders/rain_shower.agsl"
 #include "shaders/rain_constants.agsl"
 #include "shaders/rain_splash.agsl"
+#include "shaders/glass_rain.agsl"
 
 // Controls how visible the rain drops are.
 const float rainVisibility = 0.4;
@@ -79,6 +80,7 @@ vec3 drawSplashes(vec2 uv, vec2 fragCoord, vec3 color) {
 }
 
 vec4 main(float2 fragCoord) {
+    // 1. Generate rain shower.
     // Apply transform matrix to fragCoord
     float2 uvTexture = transformPoint(transformMatrixBitmap, fragCoord);
     // Calculate uv for snow based on transformed coordinates
@@ -96,7 +98,7 @@ vec4 main(float2 fragCoord) {
     float variation = wiggle(time - uv.y * 1.1, 0.10);
     vec2 uvRot = rotateAroundPoint(uv, vec2(0.5, -1.42), variation * PI / 9.);
 
-    // 1. Generate a layer of rain behind the subject.
+    // 1.1. Generate a layer of rain behind the subject.
     Rain rain = generateRain(
           uvRot,
           screenAspectRatio,
@@ -106,7 +108,7 @@ vec4 main(float2 fragCoord) {
 
     color.rgb = mix(color.rgb, highlightColor, rainVisibility * rain.dropMask);
 
-    // 2. Generate mid layer of rain behind the subject.
+    // 1.2. Generate mid layer of rain behind the subject.
     rain = generateRain(
           uvRot,
           screenAspectRatio,
@@ -114,16 +116,16 @@ vec4 main(float2 fragCoord) {
           /* Grid size = */ vec2(30.0, 4.0) * gridScale,
           intensity);
 
-    // 3. Blend those layers.
+    // 1.3. Blend those layers.
     color.rgb = mix(color.rgb, highlightColor, rainVisibility * rain.dropMask);
 
-    // 4. Blend with the foreground. Any effect from here will be in front of the subject.
+    // 1.4. Blend with the foreground. Any effect from here will be in front of the subject.
     color.rgb = normalBlend(color.rgb, colorForeground.rgb, colorForeground.a);
 
-    // 5. Draw splashes
+    // 1.5. Draw splashes
     color.rgb = drawSplashes(uv, fragCoord, color.rgb);
 
-    // 6. Generate a layer of rain in front of the subject (bigger and faster).
+    // 1.6. Generate a layer of rain in front of the subject (bigger and faster).
     rain = generateRain(
           uvRot,
           screenAspectRatio,
@@ -134,5 +136,80 @@ vec4 main(float2 fragCoord) {
     // Closer rain drops are less visible.
     color.rgb = mix(color.rgb, highlightColor, 0.7 * rainVisibility * rain.dropMask);
 
+    // 2. Generate glass rain layer.
+    // 2.0. Calculate UV and add a bit of noise so that the droplets are not perfect circles.
+    float2 glassUv = vec2(valueNoise(fragCoord) * 0.015 - 0.0025) + fragCoord / screenSize;
+
+    // 2.1. Generate small glass rain.
+    GlassRain smallDrippingRain = generateGlassRain(
+         glassUv,
+         screenAspectRatio,
+         time * 0.7,
+         /* Grid size = */ vec2(5.0, 1.6) * gridScale,
+         intensity * 0.6);
+    float dropMask = smallDrippingRain.dropMask;
+    float droppletsMask = smallDrippingRain.droppletsMask;
+    float trailMask = smallDrippingRain.trailMask;
+    vec2 dropUvMasked = smallDrippingRain.drop * dropMask;
+    vec2 droppletsUvMasked = smallDrippingRain.dropplets * droppletsMask;
+
+    // 2.2. Generate medium size glass rain.
+    GlassRain medDrippingRain = generateGlassRain(
+          glassUv,
+          screenAspectRatio,
+          time * 0.80,
+          /* Grid size = */ vec2(6., 0.945) * gridScale,
+          intensity * 0.6);
+
+    // 2.3. Combine those two glass rains.
+    dropMask = max(medDrippingRain.dropMask, dropMask);
+    droppletsMask = max(medDrippingRain.droppletsMask, droppletsMask);
+    trailMask = max(medDrippingRain.trailMask, trailMask);
+    dropUvMasked = mix(dropUvMasked,
+        medDrippingRain.drop * medDrippingRain.dropMask, medDrippingRain.dropMask);
+    droppletsUvMasked = mix(droppletsUvMasked,
+        medDrippingRain.dropplets * medDrippingRain.droppletsMask, medDrippingRain.droppletsMask);
+
+    // 2.4. Add static rain droplets on the glass surface. (They stay in place and dissapate.)
+    vec2 gridSize = vec2(12., 12.) * gridScale;
+    // Aspect ratio impacts visible cells.
+    gridSize.y /= screenAspectRatio;
+    vec3 staticRain = generateStaticGlassRain(glassUv, time, intensity, gridSize);
+    dropMask = max(dropMask, staticRain.z);
+    dropUvMasked = mix(dropUvMasked, staticRain.xy * staticRain.z, staticRain.z);
+
+    // 2.5. Distort uv for the rain drops and dropplets.
+    float distortionDrop = -0.1;
+    vec2 uvDiffractionOffsets =
+        distortionDrop * dropUvMasked;
+     vec2  s = screenSize;
+    // Ensure the diffracted image in drops is not inverted.
+    s.y *= -1;
+
+     vec3 sampledColor = background.eval(uvTexture + uvDiffractionOffsets * s).rgb;
+    sampledColor = imageRangeConversion(sampledColor, 0.84, 0.02, noise, intensity);
+    color.rgb = mix(color.rgb, sampledColor, max(dropMask, droppletsMask));
+
+    // 2.6. Add color tint to the rain drops.
+    color.rgb = mix(
+        color.rgb,
+        dropTint,
+        dropTintIntensity * smoothstep(0.7, 1., max(dropMask, droppletsMask)));
+
+    // 2.7. Add highlight to the drops.
+    color.rgb = mix(
+        color.rgb,
+        highlightColor,
+        highlightIntensity
+            * smoothstep(0.05, 0.08, max(dropUvMasked * 1.7, droppletsUvMasked * 2.6)).x);
+
+    // 2.8. Add shadows to the drops.
+    color.rgb = mix(
+        color.rgb,
+        contactShadowColor,
+        dropShadowIntensity *
+            smoothstep(0.055, 0.1, max(length(dropUvMasked * 1.7),
+                length(droppletsUvMasked * 1.9))));
+
     return color;
 }
diff --git a/weathereffects/graphics/assets/shaders/snow.agsl b/weathereffects/graphics/assets/shaders/snow.agsl
index 79da6c8..b62ccc6 100644
--- a/weathereffects/graphics/assets/shaders/snow.agsl
+++ b/weathereffects/graphics/assets/shaders/snow.agsl
@@ -58,8 +58,8 @@ Snow generateSnow(
 
     /* Grid. */
     // Increase the last number to make each layer more separate from the previous one.
-    float depth = 0.65 + layerIndex * 0.37;
-    float speedAdj = 1. + layerIndex * 0.15;
+    float depth = 0.65 + layerIndex * 0.555;
+    float speedAdj = 1. + layerIndex * 0.225;
     float layerR = idGenerator(layerIndex);
     snowGridSize *= depth;
     time += layerR * 58.3;
@@ -116,37 +116,9 @@ Snow generateSnow(
         farLayerFadeOut;
 
     /* Cell snow flake. */
-    // Horizontal movement: Wiggle (Adjust the wiggle speed based on the distance).
-    float wiggleSpeed = map(
-        normalizedLayerIndex,
-        0.2,
-        0.7,
-        closestSnowLayerWiggleSpeed,
-        farthestSnowLayerWiggleSpeed);
-    // Adjust wiggle based on layer number (0 = closer to screen => we want less movement).
-    float wiggleAmp = 0.6 + 0.4 * smoothstep(0.5, 2.5, layerIndex);
-    // Define the start based on the cell id.
-    float horizontalStartAmp = 0.5;
-    // Add the wiggle (equation decided by testing in Grapher).
-    float horizontalWiggle = wiggle(
-        // Current uv position.
-        uv.y
-        // Adjustment so the shape is not skewed.
-        - cellUv.y / snowGridSize.y
-        // variation based on cell ID.
-        + cellId * 2.1,
-        wiggleSpeed * speedAdj);
-
-    // Add the start and wiggle and make that when we are closer to the edge, we don't wiggle much
-    // (so the drop doesn't go outside it's cell).
-    horizontalWiggle = horizontalStartAmp * wiggleAmp * horizontalWiggle;
-
-    // Calculate main cell drop.
-    float snowFlakePosUncorrected = (cellUv.x - horizontalWiggle);
-
     // Calculate snow flake.
     vec2 snowFlakeShape = vec2(0.28, 0.26);
-    vec2 snowFlakePos = vec2(snowFlakePosUncorrected, cellUv.y * cellAspectRatio);
+    vec2 snowFlakePos = vec2(cellUv.x, cellUv.y * cellAspectRatio);
     snowFlakePos -= vec2(
             0.,
             (uv.y - 0.5 / screenAspectRatio)  - cellUv.y / snowGridSize.y
diff --git a/weathereffects/graphics/assets/shaders/snow_accumulation.agsl b/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
index 0b23a03..99ff20f 100644
--- a/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
@@ -37,10 +37,8 @@ vec4 main(float2 fragCoord) {
     float dY = (aN - aS) * 0.5;
     dY = max(dY, 0.0);
 
-    float accumulatedSnow = smoothstep(0.1, 1.8, dY * 5.0);
     vec4 color = vec4(0., 0., 0., 1.);
-    color.r = accumulatedSnow;
+    color.r = dY * 10.0;
     color.g = random(uv);
-    color.b = variation;
     return color;
 }
diff --git a/weathereffects/graphics/assets/shaders/snow_effect.agsl b/weathereffects/graphics/assets/shaders/snow_effect.agsl
index 7d7e8e9..b397ff1 100644
--- a/weathereffects/graphics/assets/shaders/snow_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_effect.agsl
@@ -35,8 +35,8 @@ const vec4 snowColor = vec4(1., 1., 1., 0.95);
 const vec4 bgdTint = vec4(0.8, 0.8, 0.8, 0.07);
 
 // Indices of the different snow layers.
-const float farthestSnowLayerIndex = 9;
-const float midSnowLayerIndex = 3;
+const float farthestSnowLayerIndex = 6;
+const float midSnowLayerIndex = 2;
 const float closestSnowLayerIndex = 0;
 
 vec4 main(float2 fragCoord) {
@@ -52,7 +52,6 @@ vec4 main(float2 fragCoord) {
 
     // Apply transform matrix to fragCoord
     float2 adjustedUv = transformPoint(transformMatrixBitmap, fragCoord);
-
     // Calculate uv for snow based on transformed coordinates
     float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
     float2 uvAdjusted = vec2(uv.x, uv.y / screenAspectRatio);
@@ -74,18 +73,20 @@ vec4 main(float2 fragCoord) {
     color.rgb = normalBlendNotPremultiplied(color.rgb, bgdTint.rgb, bgdTint.a);
 
     // 2. Generate snow layers behind the subject.
-    for (float i = farthestSnowLayerIndex; i > midSnowLayerIndex; i--) {
-        Snow snow = generateSnow(
-            uv,
-            screenAspectRatio,
-            time,
-            gridSize,
-            /* layer number = */ i,
-            closestSnowLayerIndex,
-            farthestSnowLayerIndex);
-
-        color.rgb =
-            normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * snow.flakeMask);
+    if (colorForeground.a == 0) {
+        for (float i = farthestSnowLayerIndex; i > midSnowLayerIndex; i--) {
+            Snow snow = generateSnow(
+                uv,
+                screenAspectRatio,
+                time,
+                gridSize,
+                /* layer number = */ i,
+                closestSnowLayerIndex,
+                farthestSnowLayerIndex);
+
+            color.rgb =
+                normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * snow.flakeMask);
+        }
     }
 
     // 3. Add the foreground layer. Any effect from here will be in front of the subject.
@@ -100,17 +101,19 @@ vec4 main(float2 fragCoord) {
     // Get the accumulated snow buffer. r contains its mask, g contains some random noise.
     vec2 accSnow = accumulatedSnow.eval(adjustedUv).rg;
     // Sharpen the mask of the accumulated snow, but not in excess.
-    float accSnowMask = smoothstep(0.1, 0.9, /* mask= */ accSnow.r);
-    // Makes the edges of the snow layer accumulation rougher.
-    accSnowMask = map(accSnowMask, 1. - cloudsNoise.b - 0.3 * dither, 1., 0., 1.);
-    // Load snow texture and dither. Make it have gray-ish values.
-    float accSnowTexture = smoothstep(0.2, 0.7, /* noise= */ accSnow.g) * 0.7;
-    accSnowTexture = map(accSnowTexture, dither - 1, 1, 0, 1);
-    // Adjust snow texture coverage/shape.
-    accSnowTexture = map(accSnowTexture, 0.67, 0.8, 0, 1);
-    accSnowMask = map(accSnowMask, 0., 1., 0., 1.- 0.6 * accSnowTexture - 0.35 * dither);
-
-    color.rgb = normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * accSnowMask);
+    float accSnowMask = smoothstep( (1.-intensity), 1.0, /* mask= */accSnow.r);
+    if (accSnowMask > 0) {
+        // Makes the edges of the snow layer accumulation rougher.
+        accSnowMask = map(accSnowMask, 1. - cloudsNoise.b - 0.3 * dither, 1., 0., 1.);
+        // Load snow texture and dither. Make it have gray-ish values.
+        float accSnowTexture = smoothstep(0.2, 0.7, /* noise= */ accSnow.g) * 0.7;
+        accSnowTexture = map(accSnowTexture, dither - 1, 1, 0, 1);
+        // Adjust snow texture coverage/shape.
+        accSnowTexture = map(accSnowTexture, 0.67, 0.8, 0, 1);
+        accSnowMask = map(accSnowMask, 0., 1., 0., 1.- 0.6 * accSnowTexture - 0.35 * dither);
+
+        color.rgb = normalBlendNotPremultiplied(color.rgb, snowColor.rgb, snowColor.a * accSnowMask);
+    }
 
     // 5. Generate snow in front of the subject.
     for (float i = midSnowLayerIndex; i >= closestSnowLayerIndex; i--) {
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
index 6140c60..45fa039 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
@@ -68,8 +68,9 @@ interface WeatherEffect {
      * @param foreground A bitmap containing the foreground of the image, will be null when
      *   segmentation hasn't finished.
      * @param background A bitmap containing the background of the image
+     * @return True if the bitmaps have been updated. False otherwise.
      */
-    fun setBitmaps(foreground: Bitmap?, background: Bitmap)
+    fun setBitmaps(foreground: Bitmap?, background: Bitmap): Boolean
 
     /**
      * Apply matrix to transform coordinates in shaders. In Editor and preview, it's a center crop
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
index ee815a1..e2739b2 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
@@ -26,6 +26,7 @@ import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.calculateTransformDifference
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.centerCropMatrix
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScale
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.invertAndTransposeMatrix
 import kotlin.random.Random
 
@@ -47,6 +48,7 @@ abstract class WeatherEffectBase(
     // Apply to weather components not rely on image textures
     // Should be identity matrix in editor, and only change when parallax applied in homescreen
     private val transformMatrixWeather: FloatArray = FloatArray(9)
+    protected var bitmapScale = getScale(centerCropMatrix)
     protected var elapsedTime: Float = 0f
 
     abstract val shader: RuntimeShader
@@ -56,6 +58,7 @@ abstract class WeatherEffectBase(
 
     override fun setMatrix(matrix: Matrix) {
         this.parallaxMatrix.set(matrix)
+        bitmapScale = getScale(parallaxMatrix)
         adjustCropping(surfaceSize)
     }
 
@@ -93,9 +96,9 @@ abstract class WeatherEffectBase(
         colorGradingShader.setFloatUniform("intensity", colorGradingIntensity * intensity)
     }
 
-    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap): Boolean {
         if (this.foreground == foreground && this.background == background) {
-            return
+            return false
         }
         // Only when background changes, we can infer the bitmap set changes
         if (this.background != background) {
@@ -111,6 +114,7 @@ abstract class WeatherEffectBase(
                 SizeF(background.width.toFloat(), background.height.toFloat()),
             )
         parallaxMatrix.set(centerCropMatrix)
+        bitmapScale = getScale(centerCropMatrix)
         shader.setInputBuffer(
             "background",
             BitmapShader(this.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
@@ -120,6 +124,7 @@ abstract class WeatherEffectBase(
             BitmapShader(this.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
         adjustCropping(surfaceSize)
+        return true
     }
 
     open fun updateTextureUniforms() {
@@ -133,4 +138,11 @@ abstract class WeatherEffectBase(
             BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
     }
+
+    companion object {
+        // When extracting the scale from the parallax matrix, there will be a very small difference
+        // due to floating-point precision.
+        // We use FLOAT_TOLERANCE to avoid triggering actions on these insignificant scale changes.
+        const val FLOAT_TOLERANCE = 0.0001F
+    }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
index d4ac8f5..ef83d24 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
@@ -59,13 +59,15 @@ class NoEffect(
 
     override fun setIntensity(intensity: Float) {}
 
-    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap): Boolean {
         // Only when background changes, we can infer the bitmap set changes
         if (this.background != background) {
             this.background.recycle()
             this.foreground.recycle()
+            return false
         }
         this.background = background
         this.foreground = foreground ?: background
+        return true
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
index 1805731..0009aa5 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
@@ -19,7 +19,6 @@ package com.google.android.wallpaper.weathereffects.graphics.rain
 import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
-import android.graphics.Color
 import android.graphics.Paint
 import android.graphics.RenderEffect
 import android.graphics.RuntimeShader
@@ -29,7 +28,7 @@ import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
-import com.google.android.wallpaper.weathereffects.graphics.utils.SolidColorShader
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScale
 import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
 
@@ -46,12 +45,17 @@ class RainEffect(
 ) : WeatherEffectBase(foreground, background, surfaceSize) {
 
     private val rainPaint = Paint().also { it.shader = rainConfig.colorGradingShader }
-
-    // Set blur effect to reduce the outline noise. No need to set blur effect every time we
-    // re-generate the outline buffer.
+    // Outline buffer is set with bitmap size, so we need to multiply blur radius by scale to get
+    // consistent blur across different surface
     private var outlineBuffer =
         FrameBuffer(background.width, background.height).apply {
-            setRenderEffect(RenderEffect.createBlurEffect(2f, 2f, Shader.TileMode.CLAMP))
+            setRenderEffect(
+                RenderEffect.createBlurEffect(
+                    BLUR_RADIUS / bitmapScale,
+                    BLUR_RADIUS / bitmapScale,
+                    Shader.TileMode.CLAMP,
+                )
+            )
         }
     private val outlineBufferPaint = Paint().also { it.shader = rainConfig.outlineShader }
 
@@ -67,10 +71,7 @@ class RainEffect(
         elapsedTime += TimeUtils.millisToSeconds(deltaMillis)
 
         rainConfig.rainShowerShader.setFloatUniform("time", elapsedTime)
-        rainConfig.glassRainShader.setFloatUniform("time", elapsedTime)
-
-        rainConfig.glassRainShader.setInputShader("texture", rainConfig.rainShowerShader)
-        rainConfig.colorGradingShader.setInputShader("texture", rainConfig.glassRainShader)
+        rainConfig.colorGradingShader.setInputShader("texture", rainConfig.rainShowerShader)
     }
 
     override fun draw(canvas: Canvas) {
@@ -82,26 +83,26 @@ class RainEffect(
         outlineBuffer.close()
     }
 
-    override fun setIntensity(intensity: Float) {
-        super.setIntensity(intensity)
-        rainConfig.glassRainShader.setFloatUniform("intensity", intensity)
-        val thickness = 1f + intensity * 10f
-        rainConfig.outlineShader.setFloatUniform("thickness", thickness)
-
-        // Need to recreate the outline buffer as the uniform has changed.
-        createOutlineBuffer()
-    }
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap): Boolean {
+        if (!super.setBitmaps(foreground, background)) {
+            return false
+        }
+        outlineBuffer.close()
+        outlineBuffer = FrameBuffer(background.width, background.height)
+
+        bitmapScale = getScale(parallaxMatrix)
+        // Different from snow effects, we only need to change blur radius when bitmaps change
+        // it only gives the range of rain splashes and doesn't influence the visual effects
+        outlineBuffer.setRenderEffect(
+            RenderEffect.createBlurEffect(
+                BLUR_RADIUS / bitmapScale,
+                BLUR_RADIUS / bitmapScale,
+                Shader.TileMode.CLAMP,
+            )
+        )
 
-    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
-        super.setBitmaps(foreground, background)
-        outlineBuffer =
-            FrameBuffer(background.width, background.height).apply {
-                setRenderEffect(RenderEffect.createBlurEffect(2f, 2f, Shader.TileMode.CLAMP))
-            }
         updateTextureUniforms()
-
-        // Need to recreate the outline buffer as the outlineBuffer has changed due to background
-        createOutlineBuffer()
+        return true
     }
 
     override val shader: RuntimeShader
@@ -116,18 +117,6 @@ class RainEffect(
     override val colorGradingIntensity: Float
         get() = rainConfig.colorGradingIntensity
 
-    override fun adjustCropping(newSurfaceSize: SizeF) {
-        super.adjustCropping(newSurfaceSize)
-        rainConfig.glassRainShader.setFloatUniform(
-            "screenSize",
-            newSurfaceSize.width,
-            newSurfaceSize.height,
-        )
-
-        val screenAspectRatio = GraphicsUtils.getAspectRatio(newSurfaceSize)
-        rainConfig.glassRainShader.setFloatUniform("screenAspectRatio", screenAspectRatio)
-    }
-
     override fun updateTextureUniforms() {
         val foregroundBuffer =
             BitmapShader(super.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
@@ -138,9 +127,18 @@ class RainEffect(
             "background",
             BitmapShader(super.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
+        createOutlineBuffer()
     }
 
+    /**
+     * It's necessary to create outline buffer only when bitmaps change, only intensity change won't
+     * create a new one cause we refer to intensity in each cell when drawing splashes.
+     */
     private fun createOutlineBuffer() {
+        rainConfig.outlineShader.setFloatUniform(
+            "thickness",
+            MAX_RAIN_OUTLINE_THICKNESS / bitmapScale,
+        )
         val canvas = outlineBuffer.beginDrawing()
         canvas.drawPaint(outlineBufferPaint)
         outlineBuffer.endDrawing()
@@ -158,8 +156,7 @@ class RainEffect(
 
     private fun prepareColorGrading() {
         // Initialize the buffer with black, so that we don't ever draw garbage buffer.
-        rainConfig.glassRainShader.setInputShader("texture", SolidColorShader(Color.BLACK))
-        rainConfig.colorGradingShader.setInputShader("texture", rainConfig.glassRainShader)
+        rainConfig.colorGradingShader.setInputShader("texture", rainConfig.rainShowerShader)
         rainConfig.lut?.let {
             rainConfig.colorGradingShader.setInputShader(
                 "lut",
@@ -172,6 +169,10 @@ class RainEffect(
         val widthScreenScale =
             GraphicsUtils.computeDefaultGridSize(newSurfaceSize, rainConfig.pixelDensity)
         rainConfig.rainShowerShader.setFloatUniform("gridScale", widthScreenScale)
-        rainConfig.glassRainShader.setFloatUniform("gridScale", widthScreenScale)
+    }
+
+    companion object {
+        const val MAX_RAIN_OUTLINE_THICKNESS = 11f
+        const val BLUR_RADIUS = 2f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
index 7fefd72..bae6d81 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
@@ -26,8 +26,6 @@ import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 data class RainEffectConfig(
     /** The first layer of the shader, rain showering in the environment. */
     val rainShowerShader: RuntimeShader,
-    /** The second layer of the shader, rain running on the glass window. */
-    val glassRainShader: RuntimeShader,
     /** The final layer of the shader, which adds color grading. */
     val colorGradingShader: RuntimeShader,
     /** Shader that evaluates the outline based on the alpha value. */
@@ -50,17 +48,15 @@ data class RainEffectConfig(
         pixelDensity: Float,
     ) : this(
         rainShowerShader = GraphicsUtils.loadShader(assets, RAIN_SHOWER_LAYER_SHADER_PATH),
-        glassRainShader = GraphicsUtils.loadShader(assets, GLASS_RAIN_LAYER_SHADER_PATH),
         colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
         outlineShader = GraphicsUtils.loadShader(assets, OUTLINE_SHADER_PATH),
         lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
         pixelDensity,
-        COLOR_GRADING_INTENSITY
+        COLOR_GRADING_INTENSITY,
     )
 
     private companion object {
         private const val RAIN_SHOWER_LAYER_SHADER_PATH = "shaders/rain_shower_layer.agsl"
-        private const val GLASS_RAIN_LAYER_SHADER_PATH = "shaders/rain_glass_layer.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val OUTLINE_SHADER_PATH = "shaders/outline.agsl"
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/rain_lut.png"
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
index 33a0732..010b5c0 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
@@ -33,6 +33,7 @@ import com.google.android.wallpaper.weathereffects.graphics.utils.MathUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScale
 import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
+import kotlin.math.abs
 
 /** Defines and generates the rain weather effect animation. */
 class SnowEffect(
@@ -53,11 +54,13 @@ class SnowEffect(
     private var frameBuffer = FrameBuffer(background.width, background.height)
     private val frameBufferPaint = Paint().also { it.shader = snowConfig.accumulatedSnowShader }
 
-    private var scale = getScale(parallaxMatrix)
-
     init {
         frameBuffer.setRenderEffect(
-            RenderEffect.createBlurEffect(4f / scale, 4f / scale, Shader.TileMode.CLAMP)
+            RenderEffect.createBlurEffect(
+                BLUR_RADIUS / bitmapScale,
+                BLUR_RADIUS / bitmapScale,
+                Shader.TileMode.CLAMP,
+            )
         )
         updateTextureUniforms()
         adjustCropping(surfaceSize)
@@ -91,24 +94,32 @@ class SnowEffect(
          * Increase effect speed as weather intensity decreases. This compensates for the floaty
          * appearance when there are fewer particles at the original speed.
          */
-        snowSpeed = MathUtils.map(intensity, 0f, 1f, 2.5f, 1.7f)
-        this.intensity = intensity
-        // Regenerate accumulated snow since the uniform changed.
-        generateAccumulatedSnow()
+        if (this.intensity != intensity) {
+            snowSpeed = MathUtils.map(intensity, 0f, 1f, 2.5f, 1.7f)
+            this.intensity = intensity
+        }
     }
 
-    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
-        super.setBitmaps(foreground, background)
-        scale = getScale(parallaxMatrix)
-        frameBuffer =
-            FrameBuffer(background.width, background.height).apply {
-                setRenderEffect(
-                    RenderEffect.createBlurEffect(4f / scale, 4f / scale, Shader.TileMode.CLAMP)
-                )
-            }
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap): Boolean {
+        if (!super.setBitmaps(foreground, background)) {
+            return false
+        }
+
+        frameBuffer.close()
+        frameBuffer = FrameBuffer(background.width, background.height)
+        val newScale = getScale(parallaxMatrix)
+        bitmapScale = newScale
+        frameBuffer.setRenderEffect(
+            RenderEffect.createBlurEffect(
+                BLUR_RADIUS / bitmapScale,
+                BLUR_RADIUS / bitmapScale,
+                Shader.TileMode.CLAMP,
+            )
+        )
         // GenerateAccumulatedSnow needs foreground for accumulatedSnowShader, and needs frameBuffer
         // which is also changed with background
         generateAccumulatedSnow()
+        return true
     }
 
     override val shader: RuntimeShader
@@ -124,8 +135,19 @@ class SnowEffect(
         get() = snowConfig.colorGradingIntensity
 
     override fun setMatrix(matrix: Matrix) {
+        val oldScale = bitmapScale
         super.setMatrix(matrix)
-        generateAccumulatedSnow()
+        // Blur radius should change with scale because it decides the fluffiness of snow
+        if (abs(bitmapScale - oldScale) > FLOAT_TOLERANCE) {
+            frameBuffer.setRenderEffect(
+                RenderEffect.createBlurEffect(
+                    BLUR_RADIUS / bitmapScale,
+                    BLUR_RADIUS / bitmapScale,
+                    Shader.TileMode.CLAMP,
+                )
+            )
+            generateAccumulatedSnow()
+        }
     }
 
     override fun updateTextureUniforms() {
@@ -148,16 +170,17 @@ class SnowEffect(
 
     private fun generateAccumulatedSnow() {
         val renderingCanvas = frameBuffer.beginDrawing()
-        snowConfig.accumulatedSnowShader.setFloatUniform("scale", scale)
+        snowConfig.accumulatedSnowShader.setFloatUniform("scale", bitmapScale)
         snowConfig.accumulatedSnowShader.setFloatUniform(
             "snowThickness",
-            snowConfig.maxAccumulatedSnowThickness * intensity / scale,
+            SNOW_THICKNESS / bitmapScale,
         )
         snowConfig.accumulatedSnowShader.setFloatUniform("screenWidth", surfaceSize.width)
         snowConfig.accumulatedSnowShader.setInputBuffer(
             "foreground",
             BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
+
         renderingCanvas.drawPaint(frameBufferPaint)
         frameBuffer.endDrawing()
 
@@ -176,4 +199,12 @@ class SnowEffect(
         val gridSize = GraphicsUtils.computeDefaultGridSize(newSurfaceSize, snowConfig.pixelDensity)
         snowConfig.shader.setFloatUniform("gridSize", 7 * gridSize, 2f * gridSize)
     }
+
+    companion object {
+        val BLUR_RADIUS = 4f
+        // Use blur effect for both blurring the snow accumulation and generating a gradient edge
+        // so that intensity can control snow thickness by cut the gradient edge in snow_effect
+        // shader.
+        val SNOW_THICKNESS = 6f
+    }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
index dedb17c..fe8bba8 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
@@ -64,16 +64,16 @@ data class SnowEffectConfig(
         lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
         pixelDensity,
         COLOR_GRADING_INTENSITY,
-        MAX_SNOW_THICKNESS
+        MAX_SNOW_THICKNESS,
     )
 
-    private companion object {
+    companion object {
         private const val SHADER_PATH = "shaders/snow_effect.agsl"
         private const val ACCUMULATED_SNOW_SHADER_PATH = "shaders/snow_accumulation.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val NOISE_TEXTURE_PATH = "textures/clouds.png"
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/snow_lut.png"
         private const val COLOR_GRADING_INTENSITY = 0.25f
-        private const val MAX_SNOW_THICKNESS = 10f
+        const val MAX_SNOW_THICKNESS = 10f
     }
 }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
index 137a2fc..0fd6adb 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
@@ -152,6 +152,8 @@ class WeatherEngine(
         userPresenceController.onKeyguardGoingAway()
     }
 
+    override fun onKeyguardAppearing() {}
+
     override fun onOffsetChanged(xOffset: Float, xOffsetStep: Float) {
         // No-op.
     }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
index 3ab9f3f..056f6e0 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
@@ -16,6 +16,7 @@
 
 package com.google.android.wallpaper.weathereffects
 
+import android.app.wallpaper.WallpaperDescription
 import android.content.Context
 import android.view.SurfaceHolder
 import com.google.android.torus.core.engine.TorusEngine
@@ -25,7 +26,7 @@ import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteract
 import javax.inject.Inject
 import kotlinx.coroutines.CoroutineScope
 
-class WeatherWallpaperService @Inject constructor(): LiveWallpaper() {
+class WeatherWallpaperService @Inject constructor() : LiveWallpaper() {
 
     @Inject lateinit var interactor: WeatherEffectsInteractor
     @Inject @MainScope lateinit var applicationScope: CoroutineScope
@@ -35,7 +36,11 @@ class WeatherWallpaperService @Inject constructor(): LiveWallpaper() {
         WallpaperEffectsDebugApplication.graph.inject(this)
     }
 
-    override fun getWallpaperEngine(context: Context, surfaceHolder: SurfaceHolder): TorusEngine {
+    override fun getWallpaperEngine(
+        context: Context,
+        surfaceHolder: SurfaceHolder,
+        wallpaperDescription: WallpaperDescription?,
+    ): TorusEngine {
         return WeatherEngine(surfaceHolder, applicationScope, interactor, context)
     }
 }
```

