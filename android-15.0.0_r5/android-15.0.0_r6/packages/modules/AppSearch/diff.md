```diff
diff --git a/OWNERS b/OWNERS
index b18ea5b7..de6a4b58 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,6 @@
 # Bug component: 755061
 adorokhine@google.com
 yamasani@google.com
+mghiware@google.com
+tjbarron@google.com
+xyj@google.com
diff --git a/apk/AndroidManifest.xml b/apk/AndroidManifest.xml
index b649a52a..3b7bdb47 100644
--- a/apk/AndroidManifest.xml
+++ b/apk/AndroidManifest.xml
@@ -16,13 +16,9 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
   package="com.android.appsearch.apk">
 
-    <!-- Must be required by a {@link android.app.appsearch.functions.AppFunctionService},
-         to ensure that only the system can bind to it.
-         <p>Protection level: signature
-    -->
-    <permission android:name="android.permission.BIND_APP_FUNCTION_SERVICE"
-                android:protectionLevel="signature"/>
-    <!-- Allows system applications to execute app functions provided by apps through AppSearch. -->
+    <!-- TODO(b/359911502): Remove this permission along with the other app functionality that
+           exists in app search once the new app function implementation is done.
+         Allows system applications to execute app functions provided by apps through AppSearch. -->
     <permission android:name="android.permission.EXECUTE_APP_FUNCTION"
                 android:protectionLevel="internal|role" />
 
diff --git a/flags/Android.bp b/flags/Android.bp
index 46553849..da615fa1 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -13,14 +13,32 @@ aconfig_declarations {
 }
 
 java_aconfig_library {
-    name: "appsearch_flags_java_lib",
+    name: "appsearch_flags_java_exported_lib",
     aconfig_declarations: "appsearch_aconfig_flags",
     visibility: [
+        "//cts/tests/appfunctions:__subpackages__",
         "//cts/tests/appsearch:__subpackages__",
+        "//frameworks/base",
+        "//packages/modules/AppSearch/testing:__subpackages__",
+    ],
+    mode: "exported",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    min_sdk_version: "Tiramisu",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.appsearch",
+    ],
+}
+
+java_aconfig_library {
+    name: "appsearch_flags_java_lib",
+    aconfig_declarations: "appsearch_aconfig_flags",
+    visibility: [
         "//packages/modules/AppSearch:__subpackages__",
     ],
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
-    mode: "exported",
     min_sdk_version: "Tiramisu",
-    apex_available: ["com.android.appsearch"],
+    apex_available: [
+        "com.android.appsearch",
+    ],
 }
diff --git a/flags/appsearch.aconfig b/flags/appsearch.aconfig
index 206b2b87..e17cf6ab 100644
--- a/flags/appsearch.aconfig
+++ b/flags/appsearch.aconfig
@@ -113,6 +113,15 @@ flag {
     is_exported: true
 }
 
+flag {
+    name: "enable_generic_document_over_ipc"
+    namespace: "appsearch"
+    description: "Guards system API for parcelling Generic documents."
+    bug: "357551503"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
 flag {
     name: "enable_result_denied_and_result_rate_limited"
     namespace: "appsearch"
@@ -151,10 +160,73 @@ flag {
 
 
 flag {
-    name: "enable_list_filter_tokenize_function"
+    name: "enable_search_spec_search_string_parameters"
     namespace: "appsearch"
     description: "Enables the tokenize function in the list filter language"
-    bug: "332620561"
+    bug: "352780707"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "apps_indexer_enabled"
+    namespace: "appsearch"
+    description: "Enables the apps indexer module"
+    bug: "275592563"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "enable_contacts_index_first_middle_and_last_names"
+    namespace: "appsearch"
+    description: "Enables the indexing of first, middle, and last names in contacts indexer"
+    bug: "358082031"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "app_open_event_indexer_enabled"
+    namespace: "appsearch"
+    description: "Enables the app open event indexer module"
+    bug: "357835538"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "enable_result_already_exists"
+    namespace: "appsearch"
+    description: "Enable the RESULT_ALREADY_EXISTS constant in AppSearchResult"
+    bug: "357708638"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "enable_blob_store"
+    namespace: "appsearch"
+    description: "Enable the BlobHandle and putBlob APIs in AppSearch"
+    bug: "273591938"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "enable_enterprise_empty_batch_result_fix"
+    namespace: "appsearch"
+    description: "Populates the GetDocuments batch result with RESULT_NOT_FOUND when the enterprise user cannot be retrieved."
+    bug: "349805579"
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    name: "enable_apps_indexer_incremental_put"
+    namespace: "appsearch"
+    description: "Calls put only for added and updated AppFunctionStaticMetadata documents"
+    bug: "367410454"
     is_fixed_read_only: true
     is_exported: true
 }
diff --git a/framework/Android.bp b/framework/Android.bp
index 099e6850..0b2b7821 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -77,7 +77,6 @@ java_sdk_library {
     defaults: ["framework-module-defaults"],
     permitted_packages: [
         "android.app.appsearch",
-        "com.android.appsearch.flags",
     ],
     jarjar_rules: "jarjar-rules.txt",
     apex_available: ["com.android.appsearch"],
@@ -89,4 +88,7 @@ java_sdk_library {
     aconfig_declarations: [
         "appsearch_aconfig_flags",
     ],
+    lint: {
+        baseline_filename: "lint-baseline.xml",
+    },
 }
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 9b769340..cb368b57 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -39,6 +39,7 @@ package android.app.appsearch {
     method public boolean isSuccess();
     method @NonNull public static <ValueType> android.app.appsearch.AppSearchResult<ValueType> newFailedResult(int, @Nullable String);
     method @NonNull public static <ValueType> android.app.appsearch.AppSearchResult<ValueType> newSuccessfulResult(@Nullable ValueType);
+    field @FlaggedApi("com.android.appsearch.flags.enable_result_already_exists") public static final int RESULT_ALREADY_EXISTS = 12; // 0xc
     field @FlaggedApi("com.android.appsearch.flags.enable_result_denied_and_result_rate_limited") public static final int RESULT_DENIED = 9; // 0x9
     field public static final int RESULT_INTERNAL_ERROR = 2; // 0x2
     field public static final int RESULT_INVALID_ARGUMENT = 3; // 0x3
@@ -510,6 +511,7 @@ package android.app.appsearch {
     method @FlaggedApi("com.android.appsearch.flags.enable_safe_parcelable_2") public final int describeContents();
     method @NonNull public String getAdvancedRankingExpression();
     method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") public int getDefaultEmbeddingSearchMetricType();
+    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public java.util.List<android.app.appsearch.EmbeddingVector> getEmbeddingParameters();
     method @NonNull public java.util.List<java.lang.String> getFilterNamespaces();
     method @NonNull public java.util.List<java.lang.String> getFilterPackageNames();
     method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_filter_properties") @NonNull public java.util.Map<java.lang.String,java.util.List<java.lang.String>> getFilterProperties();
@@ -526,15 +528,13 @@ package android.app.appsearch {
     method public int getResultCountPerPage();
     method public int getResultGroupingLimit();
     method public int getResultGroupingTypeFlags();
-    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public java.util.List<android.app.appsearch.EmbeddingVector> getSearchEmbeddings();
     method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_set_search_source_log_tag") @Nullable public String getSearchSourceLogTag();
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public java.util.List<java.lang.String> getSearchStringParameters();
     method public int getSnippetCount();
     method public int getSnippetCountPerProperty();
     method public int getTermMatch();
-    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") public boolean isEmbeddingSearchEnabled();
     method @FlaggedApi("com.android.appsearch.flags.enable_list_filter_has_property_function") public boolean isListFilterHasPropertyFunctionEnabled();
     method public boolean isListFilterQueryLanguageEnabled();
-    method @FlaggedApi("com.android.appsearch.flags.enable_list_filter_tokenize_function") public boolean isListFilterTokenizeFunctionEnabled();
     method public boolean isNumericSearchEnabled();
     method public boolean isVerbatimSearchEnabled();
     method @FlaggedApi("com.android.appsearch.flags.enable_safe_parcelable_2") public void writeToParcel(@NonNull android.os.Parcel, int);
@@ -565,6 +565,8 @@ package android.app.appsearch {
 
   public static final class SearchSpec.Builder {
     ctor public SearchSpec.Builder();
+    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder addEmbeddingParameters(@NonNull android.app.appsearch.EmbeddingVector...);
+    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder addEmbeddingParameters(@NonNull java.util.Collection<android.app.appsearch.EmbeddingVector>);
     method @NonNull public android.app.appsearch.SearchSpec.Builder addFilterNamespaces(@NonNull java.lang.String...);
     method @NonNull public android.app.appsearch.SearchSpec.Builder addFilterNamespaces(@NonNull java.util.Collection<java.lang.String>);
     method @NonNull public android.app.appsearch.SearchSpec.Builder addFilterPackageNames(@NonNull java.lang.String...);
@@ -577,15 +579,13 @@ package android.app.appsearch {
     method @FlaggedApi("com.android.appsearch.flags.enable_informational_ranking_expressions") @NonNull public android.app.appsearch.SearchSpec.Builder addInformationalRankingExpressions(@NonNull java.util.Collection<java.lang.String>);
     method @NonNull public android.app.appsearch.SearchSpec.Builder addProjection(@NonNull String, @NonNull java.util.Collection<java.lang.String>);
     method @NonNull public android.app.appsearch.SearchSpec.Builder addProjectionPaths(@NonNull String, @NonNull java.util.Collection<android.app.appsearch.PropertyPath>);
-    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder addSearchEmbeddings(@NonNull android.app.appsearch.EmbeddingVector...);
-    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder addSearchEmbeddings(@NonNull java.util.Collection<android.app.appsearch.EmbeddingVector>);
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public android.app.appsearch.SearchSpec.Builder addSearchStringParameters(@NonNull java.lang.String...);
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public android.app.appsearch.SearchSpec.Builder addSearchStringParameters(@NonNull java.util.List<java.lang.String>);
     method @NonNull public android.app.appsearch.SearchSpec build();
     method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder setDefaultEmbeddingSearchMetricType(int);
-    method @FlaggedApi("com.android.appsearch.flags.enable_schema_embedding_property_config") @NonNull public android.app.appsearch.SearchSpec.Builder setEmbeddingSearchEnabled(boolean);
     method @NonNull public android.app.appsearch.SearchSpec.Builder setJoinSpec(@NonNull android.app.appsearch.JoinSpec);
     method @FlaggedApi("com.android.appsearch.flags.enable_list_filter_has_property_function") @NonNull public android.app.appsearch.SearchSpec.Builder setListFilterHasPropertyFunctionEnabled(boolean);
     method @NonNull public android.app.appsearch.SearchSpec.Builder setListFilterQueryLanguageEnabled(boolean);
-    method @FlaggedApi("com.android.appsearch.flags.enable_list_filter_tokenize_function") @NonNull public android.app.appsearch.SearchSpec.Builder setListFilterTokenizeFunctionEnabled(boolean);
     method @NonNull public android.app.appsearch.SearchSpec.Builder setMaxSnippetSize(@IntRange(from=0, to=0x2710) int);
     method @NonNull public android.app.appsearch.SearchSpec.Builder setNumericSearchEnabled(boolean);
     method @NonNull public android.app.appsearch.SearchSpec.Builder setOrder(int);
@@ -623,6 +623,7 @@ package android.app.appsearch {
     method @NonNull public java.util.List<java.lang.String> getFilterSchemas();
     method public int getMaximumResultCount();
     method public int getRankingStrategy();
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public java.util.List<java.lang.String> getSearchStringParameters();
     method @FlaggedApi("com.android.appsearch.flags.enable_safe_parcelable_2") public void writeToParcel(@NonNull android.os.Parcel, int);
     field @FlaggedApi("com.android.appsearch.flags.enable_safe_parcelable_2") @NonNull public static final android.os.Parcelable.Creator<android.app.appsearch.SearchSuggestionSpec> CREATOR;
     field public static final int SUGGESTION_RANKING_STRATEGY_DOCUMENT_COUNT = 0; // 0x0
@@ -640,6 +641,8 @@ package android.app.appsearch {
     method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_filter_properties") @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder addFilterPropertyPaths(@NonNull String, @NonNull java.util.Collection<android.app.appsearch.PropertyPath>);
     method @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder addFilterSchemas(@NonNull java.lang.String...);
     method @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder addFilterSchemas(@NonNull java.util.Collection<java.lang.String>);
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder addSearchStringParameters(@NonNull java.lang.String...);
+    method @FlaggedApi("com.android.appsearch.flags.enable_search_spec_search_string_parameters") @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder addSearchStringParameters(@NonNull java.util.List<java.lang.String>);
     method @NonNull public android.app.appsearch.SearchSuggestionSpec build();
     method @NonNull public android.app.appsearch.SearchSuggestionSpec.Builder setRankingStrategy(int);
   }
diff --git a/framework/api/module-lib-current.txt b/framework/api/module-lib-current.txt
index d802177e..663d8500 100644
--- a/framework/api/module-lib-current.txt
+++ b/framework/api/module-lib-current.txt
@@ -1 +1,10 @@
 // Signature format: 2.0
+package android.app.appsearch {
+
+  public class GenericDocument {
+    method @FlaggedApi("com.android.appsearch.flags.enable_generic_document_over_ipc") @NonNull public static android.app.appsearch.GenericDocument createFromParcel(@NonNull android.os.Parcel);
+    method @FlaggedApi("com.android.appsearch.flags.enable_generic_document_over_ipc") public final void writeToParcel(@NonNull android.os.Parcel, int);
+  }
+
+}
+
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
index 50c3ee41..7dc27fc4 100644
--- a/framework/jarjar-rules.txt
+++ b/framework/jarjar-rules.txt
@@ -4,3 +4,9 @@
 
 # These must be kept in sync with the sources of framework-utils-appsearch
 rule com.android.internal.util.Preconditions* android.app.appsearch.internal.util.Preconditions@1
+
+# Repackage generated flag classes.
+# Rename the class names but not literals.
+rule com.android.appsearch.flags.*FeatureFlags* android.app.appsearch.flags.@1FeatureFlags@2
+rule com.android.appsearch.flags.FeatureFlags* android.app.appsearch.flags.FeatureFlags@1
+rule com.android.appsearch.flags.Flags android.app.appsearch.flags.Flags
\ No newline at end of file
diff --git a/framework/java/android/app/appsearch/AppSearchSession.java b/framework/java/android/app/appsearch/AppSearchSession.java
index 1f0ab7e4..b01cba74 100644
--- a/framework/java/android/app/appsearch/AppSearchSession.java
+++ b/framework/java/android/app/appsearch/AppSearchSession.java
@@ -188,8 +188,7 @@ public final class AppSearchSession implements Closeable {
      * @param workExecutor Executor on which to schedule heavy client-side background work such as
      *     transforming documents.
      * @param callbackExecutor Executor on which to invoke the callback.
-     * @param callback Callback to receive errors resulting from setting the schema. If the
-     *     operation succeeds, the callback will be invoked with {@code null}.
+     * @param callback Callback to receive the result of setting the schema.
      */
     public void setSchema(
             @NonNull SetSchemaRequest request,
@@ -337,9 +336,10 @@ public final class AppSearchSession implements Closeable {
      * @param executor Executor on which to invoke the callback.
      * @param callback Callback to receive pending result of performing this operation. The keys of
      *     the returned {@link AppSearchBatchResult} are the IDs of the input documents. The values
-     *     are {@code null} if they were successfully indexed, or a failed {@link AppSearchResult}
-     *     otherwise. If an unexpected internal error occurs in the AppSearch service, {@link
-     *     BatchResultCallback#onSystemError} will be invoked with a {@link Throwable}.
+     *     are either {@code null} if the corresponding document was successfully indexed, or a
+     *     failed {@link AppSearchResult} otherwise. If an unexpected internal error occurs in the
+     *     AppSearch service, {@link BatchResultCallback#onSystemError} will be invoked with a
+     *     {@link Throwable}.
      */
     public void put(
             @NonNull PutDocumentsRequest request,
@@ -394,12 +394,14 @@ public final class AppSearchSession implements Closeable {
      * @param request a request containing a namespace and IDs to get documents for.
      * @param executor Executor on which to invoke the callback.
      * @param callback Callback to receive the pending result of performing this operation. The keys
-     *     of the returned {@link AppSearchBatchResult} are the input IDs. The values are the
-     *     returned {@link GenericDocument}s on success, or a failed {@link AppSearchResult}
-     *     otherwise. IDs that are not found will return a failed {@link AppSearchResult} with a
-     *     result code of {@link AppSearchResult#RESULT_NOT_FOUND}. If an unexpected internal error
-     *     occurs in the AppSearch service, {@link BatchResultCallback#onSystemError} will be
-     *     invoked with a {@link Throwable}.
+     *     of the {@link AppSearchBatchResult} represent the input document IDs from the {@link
+     *     GetByDocumentIdRequest} object. The values are either the corresponding {@link
+     *     GenericDocument} object for the ID on success, or an {@link AppSearchResult} object on
+     *     failure. For example, if an ID is not found, the value for that ID will be set to an
+     *     {@link AppSearchResult} object with result code: {@link
+     *     AppSearchResult#RESULT_NOT_FOUND}. If an unexpected internal error occurs in the
+     *     AppSearch service, {@link BatchResultCallback#onSystemError} will be invoked with a
+     *     {@link Throwable}.
      */
     public void getByDocumentId(
             @NonNull GetByDocumentIdRequest request,
@@ -474,8 +476,8 @@ public final class AppSearchSession implements Closeable {
      *       the "subject" property.
      * </ul>
      *
-     * <p>The above description covers the basic query operators. Additional advanced query operator
-     * features should be explicitly enabled in the SearchSpec and are described below.
+     * <p>The above description covers the query operators that are supported on all versions of
+     * AppSearch. Additional operators and their required features are described below.
      *
      * <p>LIST_FILTER_QUERY_LANGUAGE: This feature covers the expansion of the query language to
      * conform to the definition of the list filters language (https://aip.dev/160). This includes:
@@ -490,7 +492,7 @@ public final class AppSearchSession implements Closeable {
      *
      * <ul>
      *   <li>createList(String...)
-     *   <li>search(String, List&lt;String&gt;)
+     *   <li>search(String, {@code List<String>})
      *   <li>propertyDefined(String)
      * </ul>
      *
@@ -501,13 +503,13 @@ public final class AppSearchSession implements Closeable {
      * and an optional list of strings that specify the properties to be restricted to. This exists
      * as a convenience for multiple property restricts. So, for example, the query `(subject:foo OR
      * body:foo) (subject:bar OR body:bar)` could be rewritten as `search("foo bar",
-     * createList("subject", "bar"))`.
+     * createList("subject", "body"))`.
      *
      * <p>propertyDefined takes a string specifying the property of interest and matches all
      * documents of any type that defines the specified property (ex.
      * `propertyDefined("sender.name")`). Note that propertyDefined will match so long as the
-     * document's type defines the specified property. It does NOT require that the document
-     * actually hold any values for this property.
+     * document's type defines the specified property. Unlike the "hasProperty" function below, this
+     * function does NOT require that the document actually hold any values for this property.
      *
      * <p>NUMERIC_SEARCH: This feature covers numeric search expressions. In the query language, the
      * values of properties that have {@link AppSearchSchema.LongPropertyConfig#INDEXING_TYPE_RANGE}
@@ -521,6 +523,66 @@ public final class AppSearchSession implements Closeable {
      *
      * <p>Ex. `"foo/bar" OR baz` will ensure that 'foo/bar' is treated as a single 'verbatim' token.
      *
+     * <p>LIST_FILTER_HAS_PROPERTY_FUNCTION: This feature covers the "hasProperty" function in query
+     * expressions, which takes a string specifying the property of interest and matches all
+     * documents that hold values for this property. Not to be confused with the "propertyDefined"
+     * function, which checks whether a document's schema has defined the property, instead of
+     * whether a document itself has this property.
+     *
+     * <p>Ex. `foo hasProperty("sender.name")` will return all documents that have the term "foo"
+     * AND have values in the property "sender.name". Consider two documents, documentA and
+     * documentB, of the same schema with an optional property "sender.name". If documentA sets
+     * "foo" in this property but documentB does not, then `hasProperty("sender.name")` will only
+     * match documentA. However, `propertyDefined("sender.name")` will match both documentA and
+     * documentB, regardless of whether a value is actually set.
+     *
+     * <p>SCHEMA_EMBEDDING_PROPERTY_CONFIG: This feature covers the "semanticSearch" and
+     * "getEmbeddingParameter" functions in query expressions, which are used for semantic search.
+     *
+     * <p>Usage: semanticSearch(getEmbeddingParameter({embedding_index}), {low}, {high}, {metric})
+     *
+     * <ul>
+     *   <li>semanticSearch matches all documents that have at least one embedding vector with a
+     *       matching model signature (see {@link EmbeddingVector#getModelSignature()}) and a
+     *       similarity score within the range specified based on the provided metric.
+     *   <li>getEmbeddingParameter({embedding_index}) retrieves the embedding search passed in
+     *       {@link SearchSpec.Builder#addEmbeddingParameters} based on the index specified, which
+     *       starts from 0.
+     *   <li>"low" and "high" are floating point numbers that specify the similarity score range. If
+     *       omitted, they default to negative and positive infinity, respectively.
+     *   <li>"metric" is a string value that specifies how embedding similarities should be
+     *       calculated. If omitted, it defaults to the metric specified in {@link
+     *       SearchSpec.Builder#setDefaultEmbeddingSearchMetricType(int)}. Possible values:
+     *       <ul>
+     *         <li>"COSINE"
+     *         <li>"DOT_PRODUCT"
+     *         <li>"EUCLIDEAN"
+     *       </ul>
+     * </ul>
+     *
+     * <p>Examples:
+     *
+     * <ul>
+     *   <li>Basic: semanticSearch(getEmbeddingParameter(0), 0.5, 1, "COSINE")
+     *   <li>With a property restriction: property1:semanticSearch(getEmbeddingParameter(0), 0.5, 1)
+     *   <li>Hybrid: foo OR semanticSearch(getEmbeddingParameter(0), 0.5, 1)
+     *   <li>Complex: (foo OR semanticSearch(getEmbeddingParameter(0), 0.5, 1)) AND bar
+     * </ul>
+     *
+     * <p>SEARCH_SPEC_SEARCH_STRING_PARAMETERS: This feature covers the "getSearchStringParameter"
+     * function in query expressions, which substitutes the string provided at the same index in
+     * {@link SearchSpec.Builder#addSearchStringParameters} into the query as plain text. This
+     * string is then segmented, normalized and stripped of punctuation-only segments. The remaining
+     * tokens are then AND'd together. This function is useful for callers who wish to provide user
+     * input, but want to ensure that that user input does not invoke any query operators.
+     *
+     * <p>Usage: getSearchStringParameter({search_parameter_strings_index})
+     *
+     * <p>Ex. `foo OR getSearchStringParameter(0)` with {@link SearchSpec#getSearchStringParameters}
+     * returning {"bar OR baz."}. The string "bar OR baz." will be segmented into "bar", "OR",
+     * "baz", ".". Punctuation is removed and the segments are normalized to "bar", "or", "baz".
+     * This query will be equivalent to `foo OR (bar AND or AND baz)`.
+     *
      * <p>Additional search specifications, such as filtering by {@link AppSearchSchema} type or
      * adding projection, can be set by calling the corresponding {@link SearchSpec.Builder} setter.
      *
@@ -532,6 +594,8 @@ public final class AppSearchSession implements Closeable {
      *     type, etc.
      * @return a {@link SearchResults} object for retrieved matched documents.
      */
+    // TODO(b/326656531): Refine the javadoc to provide guidance on the best practice of
+    //  embedding searches and how to select an appropriate metric.
     @NonNull
     public SearchResults search(@NonNull String queryExpression, @NonNull SearchSpec searchSpec) {
         Objects.requireNonNull(queryExpression);
@@ -728,12 +792,12 @@ public final class AppSearchSession implements Closeable {
      *     index.
      * @param executor Executor on which to invoke the callback.
      * @param callback Callback to receive the pending result of performing this operation. The keys
-     *     of the returned {@link AppSearchBatchResult} are the input document IDs. The values are
-     *     {@code null} on success, or a failed {@link AppSearchResult} otherwise. IDs that are not
-     *     found will return a failed {@link AppSearchResult} with a result code of {@link
-     *     AppSearchResult#RESULT_NOT_FOUND}. If an unexpected internal error occurs in the
-     *     AppSearch service, {@link BatchResultCallback#onSystemError} will be invoked with a
-     *     {@link Throwable}.
+     *     of the returned {@link AppSearchBatchResult} represent the input IDs from the {@link
+     *     RemoveByDocumentIdRequest} object. The values are either {@code null} on success, or a
+     *     failed {@link AppSearchResult} otherwise. IDs that are not found will return a failed
+     *     {@link AppSearchResult} with a result code of {@link AppSearchResult#RESULT_NOT_FOUND}.
+     *     If an unexpected internal error occurs in the AppSearch service, {@link
+     *     BatchResultCallback#onSystemError} will be invoked with a {@link Throwable}..
      */
     public void remove(
             @NonNull RemoveByDocumentIdRequest request,
@@ -795,6 +859,9 @@ public final class AppSearchSession implements Closeable {
      * @param executor Executor on which to invoke the callback.
      * @param callback Callback to receive errors resulting from removing the documents. If the
      *     operation succeeds, the callback will be invoked with {@code null}.
+     * @throws IllegalArgumentException if the {@link SearchSpec} contains a {@link JoinSpec}.
+     *     {@link JoinSpec} lets you join docs that are not owned by the caller, so the semantics of
+     *     failures from this method would be complex.
      */
     public void remove(
             @NonNull String queryExpression,
diff --git a/framework/java/android/app/appsearch/EnterpriseGlobalSearchSession.java b/framework/java/android/app/appsearch/EnterpriseGlobalSearchSession.java
index e01f4d30..6e08f357 100644
--- a/framework/java/android/app/appsearch/EnterpriseGlobalSearchSession.java
+++ b/framework/java/android/app/appsearch/EnterpriseGlobalSearchSession.java
@@ -29,14 +29,21 @@ import java.util.concurrent.Executor;
 import java.util.function.Consumer;
 
 /**
- * Provides a connection to the work profile's AppSearch databases that explicitly allow access from
- * enterprise sessions. Databases may have additional required permissions and restricted fields
- * when accessed through an enterprise session that they normally would not have.
+ * Provides a connection to all enterprise (work profile) AppSearch databases the querying
+ * application has been granted access to.
  *
- * <p>EnterpriseGlobalSearchSession will only return results when created from the main user context
- * and when there is an associated work profile. If the given context is either not the main user or
- * does not have a work profile, queries will successfully complete with empty results, allowing
- * clients to query the work profile without having to account for whether it exists or not.
+ * <p>This session can be created from any user profile but will only properly return results when
+ * created from the main profile. If the user is not the main profile or an associated work profile
+ * does not exist, queries will still successfully complete but with empty results.
+ *
+ * <p>Schemas must be explicitly tagged enterprise and may require additional permissions to be
+ * visible from an enterprise session. Retrieved documents may also have certain fields restricted
+ * or modified unlike if they were retrieved directly from {@link GlobalSearchSession} on the work
+ * profile.
+ *
+ * <p>This class is thread safe.
+ *
+ * @see GlobalSearchSession
  */
 @FlaggedApi(Flags.FLAG_ENABLE_ENTERPRISE_GLOBAL_SEARCH_SESSION)
 public class EnterpriseGlobalSearchSession extends ReadOnlyGlobalSearchSession {
diff --git a/framework/java/android/app/appsearch/GlobalSearchSession.java b/framework/java/android/app/appsearch/GlobalSearchSession.java
index defb64a5..92a12e2c 100644
--- a/framework/java/android/app/appsearch/GlobalSearchSession.java
+++ b/framework/java/android/app/appsearch/GlobalSearchSession.java
@@ -103,11 +103,11 @@ public class GlobalSearchSession extends ReadOnlyGlobalSearchSession implements
     /**
      * Retrieves {@link GenericDocument} documents, belonging to the specified package name and
      * database name and identified by the namespace and ids in the request, from the {@link
-     * GlobalSearchSession} database.
-     *
-     * <p>If the package or database doesn't exist or if the calling package doesn't have access,
-     * the gets will be handled as failures in an {@link AppSearchBatchResult} object in the
-     * callback.
+     * GlobalSearchSession} database. When a call is successful, the result will be returned in the
+     * successes section of the {@link AppSearchBatchResult} object in the callback. If the package
+     * doesn't exist, database doesn't exist, or if the calling package doesn't have access, these
+     * failures will be reflected as {@link AppSearchResult} objects with a RESULT_NOT_FOUND status
+     * code in the failures section of the {@link AppSearchBatchResult} object.
      *
      * @param packageName the name of the package to get from
      * @param databaseName the name of the database to get from
@@ -136,10 +136,12 @@ public class GlobalSearchSession extends ReadOnlyGlobalSearchSession implements
      * Retrieves documents from all AppSearch databases that the querying application has access to.
      *
      * <p>Applications can be granted access to documents by specifying {@link
-     * SetSchemaRequest.Builder#setSchemaTypeVisibilityForPackage} when building a schema.
+     * SetSchemaRequest.Builder#setSchemaTypeVisibilityForPackage}, or {@link
+     * SetSchemaRequest.Builder#setDocumentClassVisibilityForPackage} when building a schema.
      *
      * <p>Document access can also be granted to system UIs by specifying {@link
-     * SetSchemaRequest.Builder#setSchemaTypeDisplayedBySystem} when building a schema.
+     * SetSchemaRequest.Builder#setSchemaTypeDisplayedBySystem}, or {@link
+     * SetSchemaRequest.Builder#setDocumentClassDisplayedBySystem} when building a schema.
      *
      * <p>See {@link AppSearchSession#search} for a detailed explanation on forming a query string.
      *
@@ -168,9 +170,11 @@ public class GlobalSearchSession extends ReadOnlyGlobalSearchSession implements
      *
      * @param packageName the package that owns the requested {@link AppSearchSchema} instances.
      * @param databaseName the database that owns the requested {@link AppSearchSchema} instances.
-     * @return The pending {@link GetSchemaResponse} containing the schemas that the caller has
-     *     access to or an empty GetSchemaResponse if the request package and database does not
-     *     exist, has not set a schema or contains no schemas that are accessible to the caller.
+     * @param executor Executor on which to invoke the callback.
+     * @param callback Callback to receive the pending {@link GetSchemaResponse} containing the
+     *     schemas that the caller has access to or an empty GetSchemaResponse if the request
+     *     package and database does not exist, has not set a schema or contains no schemas that are
+     *     accessible to the caller.
      */
     @Override
     public void getSchema(
@@ -258,7 +262,7 @@ public class GlobalSearchSession extends ReadOnlyGlobalSearchSession implements
      * @param spec Specification of what types of changes to listen for
      * @param executor Executor on which to call the {@code observer} callback methods.
      * @param observer Callback to trigger when a schema or document changes
-     * @throws AppSearchException If an unexpected error occurs when trying to register an observer.
+     * @throws AppSearchException if an error occurs trying to register the observer
      */
     @SuppressWarnings("unchecked")
     public void registerObserverCallback(
@@ -437,10 +441,7 @@ public class GlobalSearchSession extends ReadOnlyGlobalSearchSession implements
         }
     }
 
-    /**
-     * Closes the {@link GlobalSearchSession}. Persists all mutations, including usage reports, to
-     * disk.
-     */
+    /** Closes the {@link GlobalSearchSession}. */
     @Override
     public void close() {
         if (mIsMutated && !mIsClosed) {
diff --git a/framework/java/external/android/app/appsearch/AppSearchBlobHandle.java b/framework/java/external/android/app/appsearch/AppSearchBlobHandle.java
new file mode 100644
index 00000000..27624cf6
--- /dev/null
+++ b/framework/java/external/android/app/appsearch/AppSearchBlobHandle.java
@@ -0,0 +1,165 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.app.appsearch;
+
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.app.appsearch.safeparcel.AbstractSafeParcelable;
+import android.app.appsearch.safeparcel.SafeParcelable;
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import com.android.appsearch.flags.Flags;
+import com.android.internal.util.Preconditions;
+
+import java.util.Arrays;
+import java.util.Objects;
+
+/**
+ * An identifier to represent a Blob in AppSearch.
+ *
+ * @hide
+ */
+// TODO(b/273591938) improve the java doc when we support set blob property in GenericDocument
+// TODO(b/273591938) unhide the API once it read for API review.
+
+@FlaggedApi(Flags.FLAG_ENABLE_BLOB_STORE)
+@SafeParcelable.Class(creator = "AppSearchBlobHandleCreator")
+public class AppSearchBlobHandle extends AbstractSafeParcelable {
+    /** The length of the SHA-256 digest in bytes. SHA-256 produces a 256-bit (32-byte) digest. */
+    private static final int SHA_256_DIGEST_BYTE_LENGTH = 32;
+
+    @NonNull
+    public static final Parcelable.Creator<AppSearchBlobHandle> CREATOR =
+            new AppSearchBlobHandleCreator();
+
+    @NonNull
+    @Field(id = 1, getter = "getSha256Digest")
+    private final byte[] mSha256Digest;
+
+    @NonNull
+    @Field(id = 2, getter = "getLabel")
+    private final String mLabel;
+
+    @Nullable private Integer mHashCode;
+
+    /**
+     * Build an {@link AppSearchBlobHandle}.
+     *
+     * @hide
+     */
+    @Constructor
+    AppSearchBlobHandle(
+            @Param(id = 1) @NonNull byte[] sha256Digest, @Param(id = 2) @NonNull String label) {
+        mSha256Digest = Objects.requireNonNull(sha256Digest);
+        Preconditions.checkState(
+                sha256Digest.length == SHA_256_DIGEST_BYTE_LENGTH,
+                "The input digest isn't a sha-256 digest.");
+        mLabel = Objects.requireNonNull(label);
+    }
+
+    /**
+     * Returns the SHA-256 hash of the blob that this object is representing.
+     *
+     * <p>For two objects of {@link AppSearchBlobHandle} to be considered equal, the {@code digest}
+     * and {@code label} must be equal.
+     */
+    @NonNull
+    public byte[] getSha256Digest() {
+        return mSha256Digest;
+    }
+
+    /**
+     * Returns the label indicating what the blob is with the blob that this object is representing.
+     *
+     * <p>The label is just a simple string which contains more readable information for the digest.
+     * The string is used to indicate and describe the content represented by the digest. The label
+     * cannot be used to search {@link AppSearchBlobHandle}.
+     *
+     * <p>If the label is not set, then this method will return an empty string.
+     *
+     * <p>For two objects of {@link AppSearchBlobHandle} to be considered equal, the {@code digest}
+     * and {@code label} must be equal.
+     */
+    @NonNull
+    public String getLabel() {
+        return mLabel;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof AppSearchBlobHandle)) return false;
+
+        AppSearchBlobHandle that = (AppSearchBlobHandle) o;
+        if (!Arrays.equals(mSha256Digest, that.mSha256Digest)) return false;
+        return mLabel.equals(that.mLabel);
+    }
+
+    @Override
+    public int hashCode() {
+        if (mHashCode == null) {
+            mHashCode = Objects.hash(Arrays.hashCode(mSha256Digest), mLabel);
+        }
+        return mHashCode;
+    }
+
+    /**
+     * Create a new AppSearch blob identifier with given digest and empty label.
+     *
+     * <p>For two objects of {@link AppSearchBlobHandle} to be considered equal, the {@code digest}
+     * and {@code label} must be equal.
+     *
+     * @param digest the SHA-256 hash of the blob this is representing.
+     * @return a new instance of {@link AppSearchBlobHandle} object.
+     */
+    @NonNull
+    public static AppSearchBlobHandle createWithSha256(@NonNull byte[] digest) {
+        return new AppSearchBlobHandle(digest, /* label= */ "");
+    }
+
+    /**
+     * Create a new AppSearch blob identifier with given digest and label.
+     *
+     * <p>The label is just a simple string which contains more readable information for the digest.
+     * The string is used to indicate and describe the content represented by the digest. The label
+     * cannot be used to search {@link AppSearchBlobHandle}.
+     *
+     * <p>For two objects of {@link AppSearchBlobHandle} to be considered equal, the {@code digest}
+     * and {@code label} must be equal.
+     *
+     * @param digest the SHA-256 hash of the blob this is representing.
+     * @param label a label indicating what the blob is, that can be surfaced to the user. It is
+     *     recommended to keep this brief. The label doesn't need to be distinct.
+     * @return a new instance of {@link AppSearchBlobHandle} object.
+     */
+    @NonNull
+    public static AppSearchBlobHandle createWithSha256(
+            @NonNull byte[] digest, @NonNull String label) {
+        Objects.requireNonNull(digest);
+        Preconditions.checkArgument(
+                digest.length == SHA_256_DIGEST_BYTE_LENGTH, "The digest is not a SHA-256 digest");
+        Objects.requireNonNull(label);
+        return new AppSearchBlobHandle(digest, label);
+    }
+
+    @Override
+    public void writeToParcel(@NonNull Parcel dest, int flags) {
+        AppSearchBlobHandleCreator.writeToParcel(this, dest, flags);
+    }
+}
diff --git a/framework/java/external/android/app/appsearch/AppSearchResult.java b/framework/java/external/android/app/appsearch/AppSearchResult.java
index 52c1d6e8..47c3e401 100644
--- a/framework/java/external/android/app/appsearch/AppSearchResult.java
+++ b/framework/java/external/android/app/appsearch/AppSearchResult.java
@@ -57,7 +57,8 @@ public final class AppSearchResult<ValueType> {
                 RESULT_SECURITY_ERROR,
                 RESULT_DENIED,
                 RESULT_RATE_LIMITED,
-                RESULT_TIMED_OUT
+                RESULT_TIMED_OUT,
+                RESULT_ALREADY_EXISTS
             })
     @Retention(RetentionPolicy.SOURCE)
     public @interface ResultCode {}
@@ -119,6 +120,10 @@ public final class AppSearchResult<ValueType> {
     @FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS)
     public static final int RESULT_TIMED_OUT = 11;
 
+    /** The operation is invalid because the resource already exists and can't be replaced. */
+    @FlaggedApi(Flags.FLAG_ENABLE_RESULT_ALREADY_EXISTS)
+    public static final int RESULT_ALREADY_EXISTS = 12;
+
     @ResultCode private final int mResultCode;
     @Nullable private final ValueType mResultValue;
     @Nullable private final String mErrorMessage;
diff --git a/framework/java/external/android/app/appsearch/EmbeddingVector.java b/framework/java/external/android/app/appsearch/EmbeddingVector.java
index 4b6028b4..660df9b1 100644
--- a/framework/java/external/android/app/appsearch/EmbeddingVector.java
+++ b/framework/java/external/android/app/appsearch/EmbeddingVector.java
@@ -39,7 +39,7 @@ import java.util.Objects;
  * <p>For more details on how embedding search works, check {@link AppSearchSession#search} and
  * {@link SearchSpec.Builder#setRankingStrategy(String)}.
  *
- * @see SearchSpec.Builder#addSearchEmbeddings
+ * @see SearchSpec.Builder#addEmbeddingParameters
  * @see GenericDocument.Builder#setPropertyEmbedding
  */
 @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
diff --git a/framework/java/external/android/app/appsearch/FeatureConstants.java b/framework/java/external/android/app/appsearch/FeatureConstants.java
index feb21c98..e0846b4f 100644
--- a/framework/java/external/android/app/appsearch/FeatureConstants.java
+++ b/framework/java/external/android/app/appsearch/FeatureConstants.java
@@ -16,6 +16,7 @@
 
 package android.app.appsearch;
 
+
 /**
  * A class that encapsulates all feature constants that are accessible in AppSearch framework.
  *
@@ -42,8 +43,5 @@ public final class FeatureConstants {
     /** A feature constant for the "semanticSearch" function in {@link AppSearchSession#search}. */
     public static final String EMBEDDING_SEARCH = "EMBEDDING_SEARCH";
 
-    /** A feature constant for the "tokenize" function in {@link AppSearchSession#search}. */
-    public static final String LIST_FILTER_TOKENIZE_FUNCTION = "TOKENIZE";
-
     private FeatureConstants() {}
 }
diff --git a/framework/java/external/android/app/appsearch/GenericDocument.java b/framework/java/external/android/app/appsearch/GenericDocument.java
index ebae4c69..eb1cdb6d 100644
--- a/framework/java/external/android/app/appsearch/GenericDocument.java
+++ b/framework/java/external/android/app/appsearch/GenericDocument.java
@@ -21,11 +21,15 @@ import android.annotation.FlaggedApi;
 import android.annotation.IntRange;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.RequiresApi;
 import android.annotation.SuppressLint;
+import android.annotation.SystemApi;
 import android.app.appsearch.annotation.CanIgnoreReturnValue;
 import android.app.appsearch.safeparcel.GenericDocumentParcel;
 import android.app.appsearch.safeparcel.PropertyParcel;
 import android.app.appsearch.util.IndentingStringBuilder;
+import android.os.Build;
+import android.os.Parcel;
 import android.util.Log;
 
 import com.android.appsearch.flags.Flags;
@@ -108,6 +112,43 @@ public class GenericDocument {
         this(document.mDocumentParcel);
     }
 
+    /**
+     * Writes the {@link GenericDocument} to the given {@link Parcel}.
+     *
+     * @param dest The {@link Parcel} to write to.
+     * @param flags The flags to use for parceling.
+     * @hide
+     */
+    // GenericDocument is an open class that can be extended, whereas parcelable classes must be
+    // final in those methods. Thus, we make this a system api to avoid 3p apps depending on it
+    // and getting confused by the inheritability.
+    @SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+    @FlaggedApi(Flags.FLAG_ENABLE_GENERIC_DOCUMENT_OVER_IPC)
+    public final void writeToParcel(@NonNull Parcel dest, int flags) {
+        Objects.requireNonNull(dest);
+        dest.writeParcelable(mDocumentParcel, flags);
+    }
+
+    /**
+     * Creates a {@link GenericDocument} from a {@link Parcel}.
+     *
+     * @param parcel The {@link Parcel} to read from.
+     * @hide
+     */
+    // GenericDocument is an open class that can be extended, whereas parcelable classes must be
+    // final in those methods. Thus, we make this a system api to avoid 3p apps depending on it
+    // and getting confused by the inheritability.
+    @SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+    @RequiresApi(api = Build.VERSION_CODES.TIRAMISU)
+    @FlaggedApi(Flags.FLAG_ENABLE_GENERIC_DOCUMENT_OVER_IPC)
+    @NonNull
+    public static GenericDocument createFromParcel(@NonNull Parcel parcel) {
+        Objects.requireNonNull(parcel);
+        GenericDocumentParcel documentParcel =
+                parcel.readParcelable(GenericDocumentParcel.class.getClassLoader());
+        return new GenericDocument(documentParcel);
+    }
+
     /**
      * Returns the {@link GenericDocumentParcel} holding the values for this {@link
      * GenericDocument}.
diff --git a/framework/java/external/android/app/appsearch/SearchSpec.java b/framework/java/external/android/app/appsearch/SearchSpec.java
index 0622bcb2..359ccc24 100644
--- a/framework/java/external/android/app/appsearch/SearchSpec.java
+++ b/framework/java/external/android/app/appsearch/SearchSpec.java
@@ -139,8 +139,8 @@ public final class SearchSpec extends AbstractSafeParcelable {
     private final String mSearchSourceLogTag;
 
     @NonNull
-    @Field(id = 20, getter = "getSearchEmbeddings")
-    private final List<EmbeddingVector> mSearchEmbeddings;
+    @Field(id = 20, getter = "getEmbeddingParameters")
+    private final List<EmbeddingVector> mEmbeddingParameters;
 
     @Field(id = 21, getter = "getDefaultEmbeddingSearchMetricType")
     private final int mDefaultEmbeddingSearchMetricType;
@@ -149,6 +149,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
     @Field(id = 22, getter = "getInformationalRankingExpressions")
     private final List<String> mInformationalRankingExpressions;
 
+    @NonNull
+    @Field(id = 23, getter = "getSearchStringParameters")
+    private final List<String> mSearchStringParameters;
+
     /**
      * Default number of documents per page.
      *
@@ -356,9 +360,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
             @Param(id = 17) @NonNull String advancedRankingExpression,
             @Param(id = 18) @NonNull List<String> enabledFeatures,
             @Param(id = 19) @Nullable String searchSourceLogTag,
-            @Param(id = 20) @Nullable List<EmbeddingVector> searchEmbeddings,
+            @Param(id = 20) @Nullable List<EmbeddingVector> embeddingParameters,
             @Param(id = 21) int defaultEmbeddingSearchMetricType,
-            @Param(id = 22) @Nullable List<String> informationalRankingExpressions) {
+            @Param(id = 22) @Nullable List<String> informationalRankingExpressions,
+            @Param(id = 23) @Nullable List<String> searchStringParameters) {
         mTermMatchType = termMatchType;
         mSchemas = Collections.unmodifiableList(Objects.requireNonNull(schemas));
         mNamespaces = Collections.unmodifiableList(Objects.requireNonNull(namespaces));
@@ -378,10 +383,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
         mAdvancedRankingExpression = Objects.requireNonNull(advancedRankingExpression);
         mEnabledFeatures = Collections.unmodifiableList(Objects.requireNonNull(enabledFeatures));
         mSearchSourceLogTag = searchSourceLogTag;
-        if (searchEmbeddings != null) {
-            mSearchEmbeddings = Collections.unmodifiableList(searchEmbeddings);
+        if (embeddingParameters != null) {
+            mEmbeddingParameters = Collections.unmodifiableList(embeddingParameters);
         } else {
-            mSearchEmbeddings = Collections.emptyList();
+            mEmbeddingParameters = Collections.emptyList();
         }
         mDefaultEmbeddingSearchMetricType = defaultEmbeddingSearchMetricType;
         if (informationalRankingExpressions != null) {
@@ -390,6 +395,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
         } else {
             mInformationalRankingExpressions = Collections.emptyList();
         }
+        mSearchStringParameters =
+                (searchStringParameters != null)
+                        ? Collections.unmodifiableList(searchStringParameters)
+                        : Collections.emptyList();
     }
 
     /** Returns how the query terms should match terms in the index. */
@@ -660,11 +669,16 @@ public final class SearchSpec extends AbstractSafeParcelable {
         return mSearchSourceLogTag;
     }
 
-    /** Returns the list of {@link EmbeddingVector} for embedding search. */
+    /**
+     * Returns the list of {@link EmbeddingVector} that can be referenced in the query through the
+     * "getEmbeddingParameter({index})" function.
+     *
+     * @see AppSearchSession#search
+     */
     @NonNull
     @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
-    public List<EmbeddingVector> getSearchEmbeddings() {
-        return mSearchEmbeddings;
+    public List<EmbeddingVector> getEmbeddingParameters() {
+        return mEmbeddingParameters;
     }
 
     /**
@@ -689,6 +703,18 @@ public final class SearchSpec extends AbstractSafeParcelable {
         return mInformationalRankingExpressions;
     }
 
+    /**
+     * Returns the list of String parameters that can be referenced in the query through the
+     * "getSearchStringParameter({index})" function.
+     *
+     * @see AppSearchSession#search
+     */
+    @NonNull
+    @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+    public List<String> getSearchStringParameters() {
+        return mSearchStringParameters;
+    }
+
     /** Returns whether the NUMERIC_SEARCH feature is enabled. */
     public boolean isNumericSearchEnabled() {
         return mEnabledFeatures.contains(FeatureConstants.NUMERIC_SEARCH);
@@ -710,18 +736,6 @@ public final class SearchSpec extends AbstractSafeParcelable {
         return mEnabledFeatures.contains(FeatureConstants.LIST_FILTER_HAS_PROPERTY_FUNCTION);
     }
 
-    /** Returns whether the embedding search feature is enabled. */
-    @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
-    public boolean isEmbeddingSearchEnabled() {
-        return mEnabledFeatures.contains(FeatureConstants.EMBEDDING_SEARCH);
-    }
-
-    /** Returns whether the LIST_FILTER_TOKENIZE_FUNCTION feature is enabled. */
-    @FlaggedApi(Flags.FLAG_ENABLE_LIST_FILTER_TOKENIZE_FUNCTION)
-    public boolean isListFilterTokenizeFunctionEnabled() {
-        return mEnabledFeatures.contains(FeatureConstants.LIST_FILTER_TOKENIZE_FUNCTION);
-    }
-
     /**
      * Get the list of enabled features that the caller is intending to use in this search call.
      *
@@ -748,7 +762,8 @@ public final class SearchSpec extends AbstractSafeParcelable {
         private ArraySet<String> mEnabledFeatures = new ArraySet<>();
         private Bundle mProjectionTypePropertyMasks = new Bundle();
         private Bundle mTypePropertyWeights = new Bundle();
-        private List<EmbeddingVector> mSearchEmbeddings = new ArrayList<>();
+        private List<EmbeddingVector> mEmbeddingParameters = new ArrayList<>();
+        private List<String> mSearchStringParameters = new ArrayList<>();
 
         private int mResultCountPerPage = DEFAULT_NUM_PER_PAGE;
         @TermMatch private int mTermMatchType = TERM_MATCH_PREFIX;
@@ -790,7 +805,8 @@ public final class SearchSpec extends AbstractSafeParcelable {
                     searchSpec.getPropertyWeights().entrySet()) {
                 setPropertyWeights(entry.getKey(), entry.getValue());
             }
-            mSearchEmbeddings = new ArrayList<>(searchSpec.getSearchEmbeddings());
+            mEmbeddingParameters = new ArrayList<>(searchSpec.getEmbeddingParameters());
+            mSearchStringParameters = new ArrayList<>(searchSpec.getSearchStringParameters());
             mResultCountPerPage = searchSpec.getResultCountPerPage();
             mTermMatchType = searchSpec.getTermMatch();
             mDefaultEmbeddingSearchMetricType = searchSpec.getDefaultEmbeddingSearchMetricType();
@@ -1090,7 +1106,7 @@ public final class SearchSpec extends AbstractSafeParcelable {
          *       current document being scored. Property weights come from what's specified in
          *       {@link SearchSpec}. After normalizing, each provided weight will be divided by the
          *       maximum weight, so that each of them will be <= 1.
-         *   <li>this.matchedSemanticScores(getSearchSpecEmbedding({embedding_index}), {metric})
+         *   <li>this.matchedSemanticScores(getEmbeddingParameter({embedding_index}), {metric})
          *       <p>Returns a list of the matched similarity scores from "semanticSearch" in the
          *       query expression (see also {@link AppSearchSession#search}) based on
          *       embedding_index and metric. If metric is omitted, it defaults to the metric
@@ -1099,10 +1115,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
          *       function will return an empty list. If multiple "semanticSearch"s are called for
          *       the same embedding_index and metric, this function will return a list of their
          *       merged scores.
-         *       <p>Example: `this.matchedSemanticScores(getSearchSpecEmbedding(0), "COSINE")` will
+         *       <p>Example: `this.matchedSemanticScores(getEmbeddingParameter(0), "COSINE")` will
          *       return a list of matched scores within the range of [0.5, 1], if
-         *       `semanticSearch(getSearchSpecEmbedding(0), 0.5, 1, "COSINE")` is called in the
-         *       query expression.
+         *       `semanticSearch(getEmbeddingParameter(0), 0.5, 1, "COSINE")` is called in the query
+         *       expression.
          * </ul>
          *
          * <p>Some errors may occur when using advanced ranking.
@@ -1568,10 +1584,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
         @CanIgnoreReturnValue
         @NonNull
         @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
-        public Builder addSearchEmbeddings(@NonNull EmbeddingVector... searchEmbeddings) {
+        public Builder addEmbeddingParameters(@NonNull EmbeddingVector... searchEmbeddings) {
             Objects.requireNonNull(searchEmbeddings);
             resetIfBuilt();
-            return addSearchEmbeddings(Arrays.asList(searchEmbeddings));
+            return addEmbeddingParameters(Arrays.asList(searchEmbeddings));
         }
 
         /**
@@ -1584,10 +1600,11 @@ public final class SearchSpec extends AbstractSafeParcelable {
         @CanIgnoreReturnValue
         @NonNull
         @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
-        public Builder addSearchEmbeddings(@NonNull Collection<EmbeddingVector> searchEmbeddings) {
+        public Builder addEmbeddingParameters(
+                @NonNull Collection<EmbeddingVector> searchEmbeddings) {
             Objects.requireNonNull(searchEmbeddings);
             resetIfBuilt();
-            mSearchEmbeddings.addAll(searchEmbeddings);
+            mEmbeddingParameters.addAll(searchEmbeddings);
             return this;
         }
 
@@ -1616,6 +1633,37 @@ public final class SearchSpec extends AbstractSafeParcelable {
             return this;
         }
 
+        /**
+         * Adds Strings to the list of String parameters that can be referenced in the query through
+         * the "getSearchStringParameter({index})" function.
+         *
+         * @see AppSearchSession#search
+         */
+        @CanIgnoreReturnValue
+        @NonNull
+        @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+        public Builder addSearchStringParameters(@NonNull String... searchStringParameters) {
+            Objects.requireNonNull(searchStringParameters);
+            resetIfBuilt();
+            return addSearchStringParameters(Arrays.asList(searchStringParameters));
+        }
+
+        /**
+         * Adds Strings to the list of String parameters that can be referenced in the query through
+         * the "getSearchStringParameter({index})" function.
+         *
+         * @see AppSearchSession#search
+         */
+        @CanIgnoreReturnValue
+        @NonNull
+        @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+        public Builder addSearchStringParameters(@NonNull List<String> searchStringParameters) {
+            Objects.requireNonNull(searchStringParameters);
+            resetIfBuilt();
+            mSearchStringParameters.addAll(searchStringParameters);
+            return this;
+        }
+
         /**
          * Sets the NUMERIC_SEARCH feature as enabled/disabled according to the enabled parameter.
          *
@@ -1697,38 +1745,6 @@ public final class SearchSpec extends AbstractSafeParcelable {
             return this;
         }
 
-        /**
-         * Sets the embedding search feature as enabled/disabled according to the enabled parameter.
-         *
-         * <p>If disabled, disallows the use of the "semanticSearch" function. See {@link
-         * AppSearchSession#search} for more details about the function.
-         *
-         * @param enabled Enables the feature if true, otherwise disables it
-         */
-        @CanIgnoreReturnValue
-        @NonNull
-        @FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG)
-        public Builder setEmbeddingSearchEnabled(boolean enabled) {
-            modifyEnabledFeature(FeatureConstants.EMBEDDING_SEARCH, enabled);
-            return this;
-        }
-
-        /**
-         * Sets the LIST_FILTER_TOKENIZE_FUNCTION feature as enabled/disabled according to the
-         * enabled parameter.
-         *
-         * @param enabled Enables the feature if true, otherwise disables it
-         *     <p>If disabled, disallows the use of the "tokenize" function. See {@link
-         *     AppSearchSession#search} for more details about the function.
-         */
-        @CanIgnoreReturnValue
-        @NonNull
-        @FlaggedApi(Flags.FLAG_ENABLE_LIST_FILTER_TOKENIZE_FUNCTION)
-        public Builder setListFilterTokenizeFunctionEnabled(boolean enabled) {
-            modifyEnabledFeature(FeatureConstants.LIST_FILTER_TOKENIZE_FUNCTION, enabled);
-            return this;
-        }
-
         /**
          * Constructs a new {@link SearchSpec} from the contents of this builder.
          *
@@ -1787,9 +1803,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
                     mAdvancedRankingExpression,
                     new ArrayList<>(mEnabledFeatures),
                     mSearchSourceLogTag,
-                    mSearchEmbeddings,
+                    mEmbeddingParameters,
                     mDefaultEmbeddingSearchMetricType,
-                    mInformationalRankingExpressions);
+                    mInformationalRankingExpressions,
+                    mSearchStringParameters);
         }
 
         private void resetIfBuilt() {
@@ -1800,9 +1817,10 @@ public final class SearchSpec extends AbstractSafeParcelable {
                 mPackageNames = new ArrayList<>(mPackageNames);
                 mProjectionTypePropertyMasks = BundleUtil.deepCopy(mProjectionTypePropertyMasks);
                 mTypePropertyWeights = BundleUtil.deepCopy(mTypePropertyWeights);
-                mSearchEmbeddings = new ArrayList<>(mSearchEmbeddings);
+                mEmbeddingParameters = new ArrayList<>(mEmbeddingParameters);
                 mInformationalRankingExpressions =
                         new ArrayList<>(mInformationalRankingExpressions);
+                mSearchStringParameters = new ArrayList<>(mSearchStringParameters);
                 mBuilt = false;
             }
         }
diff --git a/framework/java/external/android/app/appsearch/SearchSuggestionSpec.java b/framework/java/external/android/app/appsearch/SearchSuggestionSpec.java
index 5c6d7475..ff12c6e3 100644
--- a/framework/java/external/android/app/appsearch/SearchSuggestionSpec.java
+++ b/framework/java/external/android/app/appsearch/SearchSuggestionSpec.java
@@ -20,6 +20,7 @@ import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.IntRange;
 import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.annotation.SuppressLint;
 import android.app.appsearch.annotation.CanIgnoreReturnValue;
 import android.app.appsearch.safeparcel.AbstractSafeParcelable;
@@ -60,19 +61,23 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
     public static final Parcelable.Creator<SearchSuggestionSpec> CREATOR =
             new SearchSuggestionSpecCreator();
 
+    @NonNull
     @Field(id = 1, getter = "getFilterNamespaces")
     private final List<String> mFilterNamespaces;
 
+    @NonNull
     @Field(id = 2, getter = "getFilterSchemas")
     private final List<String> mFilterSchemas;
 
     // Maps are not supported by SafeParcelable fields, using Bundle instead. Here the key is
     // schema type and value is a list of target property paths in that schema to search over.
+    @NonNull
     @Field(id = 3)
     final Bundle mFilterProperties;
 
     // Maps are not supported by SafeParcelable fields, using Bundle instead. Here the key is
     // namespace and value is a list of target document ids in that namespace to search over.
+    @NonNull
     @Field(id = 4)
     final Bundle mFilterDocumentIds;
 
@@ -82,6 +87,10 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
     @Field(id = 6, getter = "getMaximumResultCount")
     private final int mMaximumResultCount;
 
+    @NonNull
+    @Field(id = 7, getter = "getSearchStringParameters")
+    private final List<String> mSearchStringParameters;
+
     /** @hide */
     @Constructor
     public SearchSuggestionSpec(
@@ -90,7 +99,8 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
             @Param(id = 3) @NonNull Bundle filterProperties,
             @Param(id = 4) @NonNull Bundle filterDocumentIds,
             @Param(id = 5) @SuggestionRankingStrategy int rankingStrategy,
-            @Param(id = 6) int maximumResultCount) {
+            @Param(id = 6) int maximumResultCount,
+            @Param(id = 7) @Nullable List<String> searchStringParameters) {
         Preconditions.checkArgument(
                 maximumResultCount >= 1, "MaximumResultCount must be positive.");
         mFilterNamespaces = Objects.requireNonNull(filterNamespaces);
@@ -99,6 +109,10 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
         mFilterDocumentIds = Objects.requireNonNull(filterDocumentIds);
         mRankingStrategy = rankingStrategy;
         mMaximumResultCount = maximumResultCount;
+        mSearchStringParameters =
+                (searchStringParameters != null)
+                        ? Collections.unmodifiableList(searchStringParameters)
+                        : Collections.emptyList();
     }
 
     /**
@@ -235,6 +249,18 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
         return documentIdsMap;
     }
 
+    /**
+     * Returns the list of String parameters that can be referenced in the query through the
+     * "getSearchStringParameter({index})" function.
+     *
+     * @see AppSearchSession#search
+     */
+    @NonNull
+    @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+    public List<String> getSearchStringParameters() {
+        return mSearchStringParameters;
+    }
+
     /** Builder for {@link SearchSuggestionSpec objects}. */
     public static final class Builder {
         private ArrayList<String> mNamespaces = new ArrayList<>();
@@ -246,6 +272,7 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
         @SuggestionRankingStrategy
         private int mRankingStrategy = SUGGESTION_RANKING_STRATEGY_DOCUMENT_COUNT;
 
+        private List<String> mSearchStringParameters = new ArrayList<>();
         private boolean mBuilt = false;
 
         /**
@@ -440,6 +467,37 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
             return this;
         }
 
+        /**
+         * Adds Strings to the list of String parameters that can be referenced in the query through
+         * the "getSearchStringParameter({index})" function.
+         *
+         * @see AppSearchSession#search
+         */
+        @CanIgnoreReturnValue
+        @NonNull
+        @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+        public Builder addSearchStringParameters(@NonNull String... searchStringParameters) {
+            Objects.requireNonNull(searchStringParameters);
+            resetIfBuilt();
+            return addSearchStringParameters(Arrays.asList(searchStringParameters));
+        }
+
+        /**
+         * Adds Strings to the list of String parameters that can be referenced in the query through
+         * the "getSearchStringParameter({index})" function.
+         *
+         * @see AppSearchSession#search
+         */
+        @CanIgnoreReturnValue
+        @NonNull
+        @FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+        public Builder addSearchStringParameters(@NonNull List<String> searchStringParameters) {
+            Objects.requireNonNull(searchStringParameters);
+            resetIfBuilt();
+            mSearchStringParameters.addAll(searchStringParameters);
+            return this;
+        }
+
         /** Constructs a new {@link SearchSpec} from the contents of this builder. */
         @NonNull
         public SearchSuggestionSpec build() {
@@ -474,7 +532,8 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
                     mTypePropertyFilters,
                     mDocumentIds,
                     mRankingStrategy,
-                    mTotalResultCount);
+                    mTotalResultCount,
+                    mSearchStringParameters);
         }
 
         private void resetIfBuilt() {
@@ -483,6 +542,7 @@ public final class SearchSuggestionSpec extends AbstractSafeParcelable {
                 mSchemas = new ArrayList<>(mSchemas);
                 mTypePropertyFilters = BundleUtil.deepCopy(mTypePropertyFilters);
                 mDocumentIds = BundleUtil.deepCopy(mDocumentIds);
+                mSearchStringParameters = new ArrayList<>(mSearchStringParameters);
                 mBuilt = false;
             }
         }
diff --git a/framework/java/external/android/app/appsearch/SetSchemaRequest.java b/framework/java/external/android/app/appsearch/SetSchemaRequest.java
index 4c14e349..f8c72a4c 100644
--- a/framework/java/external/android/app/appsearch/SetSchemaRequest.java
+++ b/framework/java/external/android/app/appsearch/SetSchemaRequest.java
@@ -25,10 +25,8 @@ import android.annotation.SuppressLint;
 import android.app.appsearch.annotation.CanIgnoreReturnValue;
 import android.util.ArrayMap;
 import android.util.ArraySet;
-
 import com.android.appsearch.flags.Flags;
 import com.android.internal.util.Preconditions;
-
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 import java.util.Arrays;
@@ -106,6 +104,9 @@ public final class SetSchemaRequest {
                 READ_ASSISTANT_APP_SEARCH_DATA,
                 ENTERPRISE_ACCESS,
                 MANAGED_PROFILE_CONTACTS_ACCESS,
+                EXECUTE_APP_FUNCTIONS,
+                EXECUTE_APP_FUNCTIONS_TRUSTED,
+                PACKAGE_USAGE_STATS,
             })
     @Retention(RetentionPolicy.SOURCE)
     public @interface AppSearchSupportedPermission {}
@@ -167,6 +168,43 @@ public final class SetSchemaRequest {
      */
     public static final int MANAGED_PROFILE_CONTACTS_ACCESS = 8;
 
+    /**
+     * The AppSearch enumeration corresponding to {@link
+     * android.Manifest.permission#EXECUTE_APP_FUNCTIONS} Android permission that can be used to
+     * guard AppSearch schema type visibility in {@link
+     * SetSchemaRequest.Builder#addRequiredPermissionsForSchemaTypeVisibility}.
+     *
+     * <p>This is internally used by AppFunctions API to store app functions runtime metadata so it
+     * is visible to packages holding {@link android.Manifest.permission#EXECUTE_APP_FUNCTIONS}
+     * permission (currently associated with system assistant apps).
+     *
+     * @hide
+     */
+    public static final int EXECUTE_APP_FUNCTIONS = 9;
+
+    /**
+     * The AppSearch enumeration corresponding to {@link
+     * android.Manifest.permission#EXECUTE_APP_FUNCTIONS_TRUSTED} Android permission that can be
+     * used to guard AppSearch schema type visibility in {@link
+     * SetSchemaRequest.Builder#addRequiredPermissionsForSchemaTypeVisibility}.
+     *
+     * <p>This is internally used by AppFunctions API to store app functions runtime metadata so it
+     * is visible to packages holding {@link
+     * android.Manifest.permission#EXECUTE_APP_FUNCTIONS_TRUSTED} permission (currently associated
+     * with system packages in the {@link android.app.role.SYSTEM_UI_INTELLIGENCE} role).
+     *
+     * @hide
+     */
+    public static final int EXECUTE_APP_FUNCTIONS_TRUSTED = 10;
+
+    /**
+     * The {@link android.Manifest.permission#PACKAGE_USAGE_STATS} AppSearch supported in {@link
+     * SetSchemaRequest.Builder#addRequiredPermissionsForSchemaTypeVisibility}
+     *
+     * @hide
+     */
+    public static final int PACKAGE_USAGE_STATS = 11;
+
     private final Set<AppSearchSchema> mSchemas;
     private final Set<String> mSchemasNotDisplayedBySystem;
     private final Map<String, Set<PackageIdentifier>> mSchemasVisibleToPackages;
@@ -444,7 +482,7 @@ public final class SetSchemaRequest {
             Objects.requireNonNull(permissions);
             for (int permission : permissions) {
                 Preconditions.checkArgumentInRange(
-                        permission, READ_SMS, MANAGED_PROFILE_CONTACTS_ACCESS, "permission");
+                        permission, READ_SMS, PACKAGE_USAGE_STATS, "permission");
             }
             resetIfBuilt();
             Set<Set<Integer>> visibleToPermissions = mSchemasVisibleToPermissions.get(schemaType);
diff --git a/framework/java/external/android/app/appsearch/checker/initialization/qual/UnderInitialization.java b/framework/java/external/android/app/appsearch/checker/initialization/qual/UnderInitialization.java
index 277d045c..48ede80e 100644
--- a/framework/java/external/android/app/appsearch/checker/initialization/qual/UnderInitialization.java
+++ b/framework/java/external/android/app/appsearch/checker/initialization/qual/UnderInitialization.java
@@ -16,6 +16,7 @@
 
 package android.app.appsearch.checker.initialization.qual;
 
+
 import java.lang.annotation.ElementType;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/framework/java/external/android/app/appsearch/checker/initialization/qual/UnknownInitialization.java b/framework/java/external/android/app/appsearch/checker/initialization/qual/UnknownInitialization.java
index 6d0fb876..34f9353a 100644
--- a/framework/java/external/android/app/appsearch/checker/initialization/qual/UnknownInitialization.java
+++ b/framework/java/external/android/app/appsearch/checker/initialization/qual/UnknownInitialization.java
@@ -16,6 +16,7 @@
 
 package android.app.appsearch.checker.initialization.qual;
 
+
 import java.lang.annotation.ElementType;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/framework/java/external/android/app/appsearch/checker/nullness/qual/RequiresNonNull.java b/framework/java/external/android/app/appsearch/checker/nullness/qual/RequiresNonNull.java
index 087713b7..a84ee7a6 100644
--- a/framework/java/external/android/app/appsearch/checker/nullness/qual/RequiresNonNull.java
+++ b/framework/java/external/android/app/appsearch/checker/nullness/qual/RequiresNonNull.java
@@ -16,6 +16,7 @@
 
 package android.app.appsearch.checker.nullness.qual;
 
+
 import java.lang.annotation.ElementType;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/framework/java/external/android/app/appsearch/usagereporting/ActionConstants.java b/framework/java/external/android/app/appsearch/usagereporting/ActionConstants.java
index 2943587a..0959fb8e 100644
--- a/framework/java/external/android/app/appsearch/usagereporting/ActionConstants.java
+++ b/framework/java/external/android/app/appsearch/usagereporting/ActionConstants.java
@@ -16,6 +16,7 @@
 
 package android.app.appsearch.usagereporting;
 
+
 /**
  * Wrapper class for action constants.
  *
diff --git a/framework/lint-baseline.xml b/framework/lint-baseline.xml
new file mode 100644
index 00000000..ab9ba9d2
--- /dev/null
+++ b/framework/lint-baseline.xml
@@ -0,0 +1,675 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<issues format="6" by="lint 8.4.0-alpha08" type="baseline" client="" dependencies="true" name="" variant="all" version="8.4.0-alpha08">
+
+    <issue
+        id="FlaggedApi"
+        message="Method `AppFunctionManager()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `AppSearchManager` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="        mAppFunctionManager = new AppFunctionManager(context, service);"
+        errorLine2="                              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/android/app/appsearch/AppSearchManager.java"
+            line="136"
+            column="31"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDescription()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `appendAppSearchSchemaString` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="        builder.append(&quot;description: \&quot;&quot;).append(getDescription()).append(&quot;\&quot;,\n&quot;);"
+        errorLine2="                                                 ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="114"
+            column="50"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDescription()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `equals` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="        if (!getDescription().equals(otherSchema.getDescription())) {"
+        errorLine2="             ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="195"
+            column="14"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDescription()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `equals` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="        if (!getDescription().equals(otherSchema.getDescription())) {"
+        errorLine2="                                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="195"
+            column="38"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getParentTypes()` is a flagged API and should be inside an `if (Flags.enableGetParentTypesAndIndexableNestedProperties())` check (or annotate the surrounding method `equals` with `@FlaggedApi(Flags.FLAG_ENABLE_GET_PARENT_TYPES_AND_INDEXABLE_NESTED_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="        if (!getParentTypes().equals(otherSchema.getParentTypes())) {"
+        errorLine2="             ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="198"
+            column="14"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getParentTypes()` is a flagged API and should be inside an `if (Flags.enableGetParentTypesAndIndexableNestedProperties())` check (or annotate the surrounding method `equals` with `@FlaggedApi(Flags.FLAG_ENABLE_GET_PARENT_TYPES_AND_INDEXABLE_NESTED_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="        if (!getParentTypes().equals(otherSchema.getParentTypes())) {"
+        errorLine2="                                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="198"
+            column="38"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDescription()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `hashCode` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="        return Objects.hash(getSchemaType(), getProperties(), getParentTypes(), getDescription());"
+        errorLine2="                                                                                ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="206"
+            column="81"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getParentTypes()` is a flagged API and should be inside an `if (Flags.enableGetParentTypesAndIndexableNestedProperties())` check (or annotate the surrounding method `hashCode` with `@FlaggedApi(Flags.FLAG_ENABLE_GET_PARENT_TYPES_AND_INDEXABLE_NESTED_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="        return Objects.hash(getSchemaType(), getProperties(), getParentTypes(), getDescription());"
+        errorLine2="                                                              ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="206"
+            column="63"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDescription()` is a flagged API and should be inside an `if (Flags.enableAppFunctions())` check (or annotate the surrounding method `appendPropertyConfigString` with `@FlaggedApi(Flags.FLAG_ENABLE_APP_FUNCTIONS) to transfer requirement to caller`)"
+        errorLine1="            builder.append(&quot;description: \&quot;&quot;).append(getDescription()).append(&quot;\&quot;,\n&quot;);"
+        errorLine2="                                                     ~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="479"
+            column="54"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `EmbeddingPropertyConfig()` is a flagged API and should be inside an `if (Flags.enableSchemaEmbeddingPropertyConfig())` check (or annotate the surrounding method `fromParcel` with `@FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG) to transfer requirement to caller`)"
+        errorLine1="                    return new EmbeddingPropertyConfig(propertyConfigParcel);"
+        errorLine2="                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="618"
+            column="28"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getIndexableNestedProperties()` is a flagged API and should be inside an `if (Flags.enableGetParentTypesAndIndexableNestedProperties())` check (or annotate the surrounding method `appendDocumentPropertyConfigFields` with `@FlaggedApi(Flags.FLAG_ENABLE_GET_PARENT_TYPES_AND_INDEXABLE_NESTED_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="                    .append(getIndexableNestedProperties())"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/AppSearchSchema.java"
+            line="1554"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getParentTypes()` is a flagged API and should be inside an `if (Flags.enableGetParentTypesAndIndexableNestedProperties())` check (or annotate the surrounding method `setSchema` with `@FlaggedApi(Flags.FLAG_ENABLE_GET_PARENT_TYPES_AND_INDEXABLE_NESTED_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="            if (!schemaList.get(i).getParentTypes().isEmpty()"
+        errorLine2="                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/android/app/appsearch/AppSearchSession.java"
+            line="206"
+            column="18"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getTakenActionGenericDocuments()` is a flagged API and should be inside an `if (Flags.enablePutDocumentsRequestAddTakenActions())` check (or annotate the surrounding method `put` with `@FlaggedApi(Flags.FLAG_ENABLE_PUT_DOCUMENTS_REQUEST_ADD_TAKEN_ACTIONS) to transfer requirement to caller`)"
+        errorLine1="                        toGenericDocumentParcels(request.getTakenActionGenericDocuments()));"
+        errorLine2="                                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/android/app/appsearch/AppSearchSession.java"
+            line="355"
+            column="50"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getAllowedPackages()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getSchemaTypesVisibleToPackages` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getAllowedPackages();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="172"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getRequiredPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getRequiredPermissionsForSchemaTypeVisibility` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getRequiredPermissions();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="220"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getPubliclyVisibleSchemas` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getPubliclyVisibleTargetPackage();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="247"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setNotDisplayedBySystem()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `addSchemaTypeNotDisplayedBySystem` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            visibilityConfigBuilder.setNotDisplayedBySystem(true);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="358"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setSchemaTypeVisibleToPackages` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                visibilityConfigBuilder.addVisibleToPackage(packageIdentifier);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="392"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setRequiredPermissionsForSchemaTypeVisibility` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                visibilityConfigBuilder.addVisibleToPermissions(visibleToPermissions);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="443"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setPubliclyVisibleSchema` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            visibilityConfigBuilder.setPubliclyVisibleTargetPackage(packageIdentifier);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="468"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `build()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `build` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    visibilityConfigs.add(builder.build());"
+        errorLine2="                                          ~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="549"
+            column="43"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `Builder()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getOrCreateVisibilityConfigBuilder` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                builder = new InternalVisibilityConfig.Builder(schemaType);"
+        errorLine2="                          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="565"
+            column="27"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getPubliclyVisibleSchemas()` is a flagged API and should be inside an `if (Flags.enableSetPubliclyVisibleSchema())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_PUBLICLY_VISIBLE_SCHEMA) to transfer requirement to caller`)"
+        errorLine1="                setSchemaRequest.getPubliclyVisibleSchemas();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="60"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getSchemasVisibleToConfigs()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                setSchemaRequest.getSchemasVisibleToConfigs();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `Builder()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    new InternalVisibilityConfig.Builder(schemaType)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="68"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setNotDisplayedBySystem()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    new InternalVisibilityConfig.Builder(schemaType)"
+        errorLine2="                    ^">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="68"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToPackage(packageIdentifier);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="75"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToPermissions(visibleToPermissions);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="82"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                builder.setPubliclyVisibleTargetPackage(publiclyVisibleTargetPackage);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="88"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToConfig()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToConfig(schemaVisibilityConfig);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="94"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `build()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            result.add(builder.build());"
+        errorLine2="                       ~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="98"
+            column="24"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getInformationalRankingSignals()` is a flagged API and should be inside an `if (Flags.enableInformationalRankingExpressions())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_INFORMATIONAL_RANKING_EXPRESSIONS) to transfer requirement to caller`)"
+        errorLine1="                    new ArrayList&lt;>(searchResult.getInformationalRankingSignals());"
+        errorLine2="                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchResult.java"
+            line="268"
+            column="37"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Field `EMBEDDING_SEARCH_METRIC_TYPE_COSINE` is a flagged API and should be inside an `if (Flags.enableSchemaEmbeddingPropertyConfig())` check (or annotate the surrounding method `?` with `@FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG) to transfer requirement to caller`)"
+        errorLine1="        private int mDefaultEmbeddingSearchMetricType = EMBEDDING_SEARCH_METRIC_TYPE_COSINE;"
+        errorLine2="                                                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="757"
+            column="57"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getFilterProperties()` is a flagged API and should be inside an `if (Flags.enableSearchSpecFilterProperties())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_FILTER_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="                    searchSpec.getFilterProperties().entrySet()) {"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="781"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addFilterProperties()` is a flagged API and should be inside an `if (Flags.enableSearchSpecFilterProperties())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_FILTER_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="                addFilterProperties(entry.getKey(), entry.getValue());"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="782"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getSearchEmbeddings()` is a flagged API and should be inside an `if (Flags.enableSchemaEmbeddingPropertyConfig())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG) to transfer requirement to caller`)"
+        errorLine1="            mSearchEmbeddings = new ArrayList&lt;>(searchSpec.getSearchEmbeddings());"
+        errorLine2="                                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="793"
+            column="49"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getDefaultEmbeddingSearchMetricType()` is a flagged API and should be inside an `if (Flags.enableSchemaEmbeddingPropertyConfig())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SCHEMA_EMBEDDING_PROPERTY_CONFIG) to transfer requirement to caller`)"
+        errorLine1="            mDefaultEmbeddingSearchMetricType = searchSpec.getDefaultEmbeddingSearchMetricType();"
+        errorLine2="                                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="796"
+            column="49"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getInformationalRankingExpressions()` is a flagged API and should be inside an `if (Flags.enableInformationalRankingExpressions())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_INFORMATIONAL_RANKING_EXPRESSIONS) to transfer requirement to caller`)"
+        errorLine1="                    new ArrayList&lt;>(searchSpec.getInformationalRankingExpressions());"
+        errorLine2="                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="807"
+            column="37"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getSearchSourceLogTag()` is a flagged API and should be inside an `if (Flags.enableSearchSpecSetSearchSourceLogTag())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SET_SEARCH_SOURCE_LOG_TAG) to transfer requirement to caller`)"
+        errorLine1="            mSearchSourceLogTag = searchSpec.getSearchSourceLogTag();"
+        errorLine2="                                  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="808"
+            column="35"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getTakenActionGenericDocuments()` is a flagged API and should be inside an `if (Flags.enablePutDocumentsRequestAddTakenActions())` check (or annotate the surrounding method `put` with `@FlaggedApi(Flags.FLAG_ENABLE_PUT_DOCUMENTS_REQUEST_ADD_TAKEN_ACTIONS) to transfer requirement to caller`)"
+        errorLine1="                toGenericDocumentParcels(request.getTakenActionGenericDocuments()));"
+        errorLine2="                                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/android/app/appsearch/AppSearchSession.java"
+            line="335"
+            column="42"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getAllowedPackages()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getSchemaTypesVisibleToPackages` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getAllowedPackages();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="169"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getRequiredPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getRequiredPermissionsForSchemaTypeVisibility` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getRequiredPermissions();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="217"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getPubliclyVisibleSchemas` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                        visibilityConfig.getVisibilityConfig().getPubliclyVisibleTargetPackage();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="244"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setNotDisplayedBySystem()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `addSchemaTypeNotDisplayedBySystem` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            visibilityConfigBuilder.setNotDisplayedBySystem(true);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="354"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setSchemaTypeVisibleToPackages` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                visibilityConfigBuilder.addVisibleToPackage(packageIdentifier);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="388"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setRequiredPermissionsForSchemaTypeVisibility` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                visibilityConfigBuilder.addVisibleToPermissions(visibleToPermissions);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="437"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `setPubliclyVisibleSchema` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            visibilityConfigBuilder.setPubliclyVisibleTargetPackage(packageIdentifier);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="461"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `build()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `build` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    visibilityConfigs.add(builder.build());"
+        errorLine2="                                          ~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="541"
+            column="43"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `Builder()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `getOrCreateVisibilityConfigBuilder` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                builder = new InternalVisibilityConfig.Builder(schemaType);"
+        errorLine2="                          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/GetSchemaResponse.java"
+            line="553"
+            column="27"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getPubliclyVisibleSchemas()` is a flagged API and should be inside an `if (Flags.enableSetPubliclyVisibleSchema())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_PUBLICLY_VISIBLE_SCHEMA) to transfer requirement to caller`)"
+        errorLine1="                setSchemaRequest.getPubliclyVisibleSchemas();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="59"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getSchemasVisibleToConfigs()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                setSchemaRequest.getSchemasVisibleToConfigs();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="61"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `Builder()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    new InternalVisibilityConfig.Builder(schemaType)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="67"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setNotDisplayedBySystem()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    new InternalVisibilityConfig.Builder(schemaType)"
+        errorLine2="                    ^">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="67"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToPackage(packageIdentifier);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="74"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToPermissions()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToPermissions(visibleToPermissions);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="81"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setPubliclyVisibleTargetPackage()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                builder.setPubliclyVisibleTargetPackage(publiclyVisibleTargetPackage);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="87"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addVisibleToConfig()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="                    builder.addVisibleToConfig(schemaVisibilityConfig);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="93"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `build()` is a flagged API and should be inside an `if (Flags.enableSetSchemaVisibleToConfigs())` check (or annotate the surrounding method `toInternalVisibilityConfigs` with `@FlaggedApi(Flags.FLAG_ENABLE_SET_SCHEMA_VISIBLE_TO_CONFIGS) to transfer requirement to caller`)"
+        errorLine1="            result.add(builder.build());"
+        errorLine2="                       ~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/InternalVisibilityConfig.java"
+            line="97"
+            column="24"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getFilterProperties()` is a flagged API and should be inside an `if (Flags.enableSearchSpecFilterProperties())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_FILTER_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="                    searchSpec.getFilterProperties().entrySet()) {"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="648"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `addFilterProperties()` is a flagged API and should be inside an `if (Flags.enableSearchSpecFilterProperties())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_FILTER_PROPERTIES) to transfer requirement to caller`)"
+        errorLine1="                addFilterProperties(entry.getKey(), entry.getValue());"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="649"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `getSearchSourceLogTag()` is a flagged API and should be inside an `if (Flags.enableSearchSpecSetSearchSourceLogTag())` check (or annotate the surrounding method `Builder` with `@FlaggedApi(Flags.FLAG_ENABLE_SEARCH_SPEC_SET_SEARCH_SOURCE_LOG_TAG) to transfer requirement to caller`)"
+        errorLine1="            mSearchSourceLogTag = searchSpec.getSearchSourceLogTag();"
+        errorLine2="                                  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/AppSearch/framework/java/external/android/app/appsearch/SearchSpec.java"
+            line="671"
+            column="35"/>
+    </issue>
+
+</issues>
diff --git a/service/Android.bp b/service/Android.bp
index 730e1339..2adbb6ba 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -53,14 +53,16 @@ java_defaults {
         "icing-java-proto-lite",
         "libicing-java",
         "statslog-appsearch-lib",
+
         // Entries below this line are outside of the appsearch package tree and must be kept in
         // sync with jarjar.txt
+        "appsearch_flags_java_lib",
         "modules-utils-preconditions",
     ],
     libs: [
         "framework-appsearch.impl",
-        "framework-configinfrastructure",
-        "framework-permission-s",
+        "framework-configinfrastructure.stubs.module_lib",
+        "framework-permission-s.stubs.module_lib",
         "framework-statsd.stubs.module_lib",
     ],
     optimize: {
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
index 0b7113e4..592b5049 100644
--- a/service/jarjar-rules.txt
+++ b/service/jarjar-rules.txt
@@ -11,3 +11,9 @@ rule com.google.android.appsearch.proto.** com.android.server.appsearch.appsearc
 
 # These must be kept in sync with the sources of framework-utils-appsearch
 rule com.android.internal.util.Preconditions* com.android.server.appsearch.internal.util.Preconditions@1
+
+# Repackage generated flag classes.
+# Rename the class names but not literals.
+rule com.android.appsearch.flags.*FeatureFlags* com.android.server.appsearch.flags.@1FeatureFlags@2
+rule com.android.appsearch.flags.FeatureFlags* com.android.server.appsearch.flags.FeatureFlags@1
+rule com.android.appsearch.flags.Flags com.android.server.appsearch.flags.Flags
\ No newline at end of file
diff --git a/service/java/com/android/server/appsearch/AppSearchManagerService.java b/service/java/com/android/server/appsearch/AppSearchManagerService.java
index 5d30a112..7fe8fbe9 100644
--- a/service/java/com/android/server/appsearch/AppSearchManagerService.java
+++ b/service/java/com/android/server/appsearch/AppSearchManagerService.java
@@ -24,7 +24,6 @@ import static android.app.appsearch.AppSearchResult.RESULT_RATE_LIMITED;
 import static android.app.appsearch.AppSearchResult.RESULT_SECURITY_ERROR;
 import static android.app.appsearch.AppSearchResult.RESULT_TIMED_OUT;
 import static android.app.appsearch.AppSearchResult.throwableToFailedResult;
-import static android.app.appsearch.functions.AppFunctionManager.PERMISSION_BIND_APP_FUNCTION_SERVICE;
 import static android.os.Process.INVALID_UID;
 
 import static com.android.server.appsearch.external.localstorage.stats.SearchStats.VISIBILITY_SCOPE_GLOBAL;
@@ -110,6 +109,7 @@ import android.text.TextUtils;
 import android.util.ArraySet;
 import android.util.Log;
 
+import com.android.appsearch.flags.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.LocalManagerRegistry;
 import com.android.server.SystemService;
@@ -211,7 +211,7 @@ public class AppSearchManagerService extends SystemService {
         publishBinderService(Context.APP_SEARCH_SERVICE, new Stub());
         mPackageManager = getContext().getPackageManager();
         mRoleManager = getContext().getSystemService(RoleManager.class);
-        mServiceImplHelper = new ServiceImplHelper(mContext, mExecutorManager);
+        mServiceImplHelper = new ServiceImplHelper(mContext);
         mAppSearchUserInstanceManager = AppSearchUserInstanceManager.getInstance();
         registerReceivers();
         LocalManagerRegistry.getManager(StorageStatsManagerLocal.class)
@@ -323,23 +323,25 @@ public class AppSearchManagerService extends SystemService {
         }
         // Only clear the package's data if AppSearch exists for this user.
         if (mAppSearchEnvironment.getAppSearchDir(mContext, userHandle).exists()) {
-            mExecutorManager.getOrCreateUserExecutor(userHandle).execute(() -> {
-                try {
-                    Context userContext = mAppSearchEnvironment
-                            .createContextAsUser(mContext, userHandle);
-                    AppSearchUserInstance instance =
-                            mAppSearchUserInstanceManager.getOrCreateUserInstance(
-                                    userContext,
-                                    userHandle,
-                                    mAppSearchConfig);
-                    instance.getAppSearchImpl().clearPackageData(packageName);
-                    dispatchChangeNotifications(instance);
-                    instance.getLogger().removeCacheForPackage(packageName);
-                } catch (AppSearchException | RuntimeException e) {
-                    Log.e(TAG, "Unable to remove data for package: " + packageName, e);
-                    ExceptionUtil.handleException(e);
-                }
-            });
+            mExecutorManager.executeLambdaForUserNoCallbackAsync(
+                    userHandle,
+                    () -> {
+                        try {
+                            Context userContext = mAppSearchEnvironment
+                                    .createContextAsUser(mContext, userHandle);
+                            AppSearchUserInstance instance =
+                                    mAppSearchUserInstanceManager.getOrCreateUserInstance(
+                                            userContext,
+                                            userHandle,
+                                            mAppSearchConfig);
+                            instance.getAppSearchImpl().clearPackageData(packageName);
+                            dispatchChangeNotifications(instance);
+                            instance.getLogger().removeCacheForPackage(packageName);
+                        } catch (AppSearchException | RuntimeException e) {
+                            Log.e(TAG, "Unable to remove data for package: " + packageName, e);
+                            ExceptionUtil.handleException(e);
+                        }
+                    });
         }
     }
 
@@ -351,41 +353,44 @@ public class AppSearchManagerService extends SystemService {
 
         // Only schedule task if AppSearch exists for this user.
         if (mAppSearchEnvironment.getAppSearchDir(mContext, userHandle).exists()) {
-            mExecutorManager.getOrCreateUserExecutor(userHandle).execute(() -> {
-                // Try to prune garbage package data, this is to recover if user remove a package
-                // and reboot the device before we prune the package data.
-                try {
-                    Context userContext = mAppSearchEnvironment
-                            .createContextAsUser(mContext, userHandle);
-                    AppSearchUserInstance instance =
-                            mAppSearchUserInstanceManager.getOrCreateUserInstance(
-                                    userContext,
-                                    userHandle,
-                                    mAppSearchConfig);
-                    List<PackageInfo> installedPackageInfos = userContext
-                            .getPackageManager()
-                            .getInstalledPackages(/* flags= */ 0);
-                    Set<String> packagesToKeep = new ArraySet<>(installedPackageInfos.size());
-                    for (int i = 0; i < installedPackageInfos.size(); i++) {
-                        packagesToKeep.add(installedPackageInfos.get(i).packageName);
-                    }
-                    packagesToKeep.add(VisibilityStore.VISIBILITY_PACKAGE_NAME);
-                    instance.getAppSearchImpl().prunePackageData(packagesToKeep);
-                } catch (AppSearchException | RuntimeException e) {
-                    Log.e(TAG, "Unable to prune packages for " + user, e);
-                    ExceptionUtil.handleException(e);
-                }
+            mExecutorManager.executeLambdaForUserNoCallbackAsync(
+                    userHandle,
+                    () -> {
+                        // Try to prune garbage package data, this is to recover if user remove a
+                        // package and reboot the device before we prune the package data.
+                        try {
+                            Context userContext = mAppSearchEnvironment
+                                    .createContextAsUser(mContext, userHandle);
+                            AppSearchUserInstance instance =
+                                    mAppSearchUserInstanceManager.getOrCreateUserInstance(
+                                            userContext,
+                                            userHandle,
+                                            mAppSearchConfig);
+                            List<PackageInfo> installedPackageInfos = userContext
+                                    .getPackageManager()
+                                    .getInstalledPackages(/* flags= */ 0);
+                            Set<String> packagesToKeep =
+                                    new ArraySet<>(installedPackageInfos.size());
+                            for (int i = 0; i < installedPackageInfos.size(); i++) {
+                                packagesToKeep.add(installedPackageInfos.get(i).packageName);
+                            }
+                            packagesToKeep.add(VisibilityStore.VISIBILITY_PACKAGE_NAME);
+                            instance.getAppSearchImpl().prunePackageData(packagesToKeep);
+                        } catch (AppSearchException | RuntimeException e) {
+                            Log.e(TAG, "Unable to prune packages for " + user, e);
+                            ExceptionUtil.handleException(e);
+                        }
 
-                // Try to schedule fully persist job.
-                try {
-                    AppSearchMaintenanceService.scheduleFullyPersistJob(mContext,
-                            userHandle.getIdentifier(),
-                            mAppSearchConfig.getCachedFullyPersistJobIntervalMillis());
-                } catch (RuntimeException e) {
-                    Log.e(TAG, "Unable to schedule fully persist job for " + user, e);
-                    ExceptionUtil.handleException(e);
-                }
-            });
+                        // Try to schedule fully persist job.
+                        try {
+                            AppSearchMaintenanceService.scheduleFullyPersistJob(mContext,
+                                    userHandle.getIdentifier(),
+                                    mAppSearchConfig.getCachedFullyPersistJobIntervalMillis());
+                        } catch (RuntimeException e) {
+                            Log.e(TAG, "Unable to schedule fully persist job for " + user, e);
+                            ExceptionUtil.handleException(e);
+                        }
+                    });
         }
     }
 
@@ -450,7 +455,7 @@ public class AppSearchManagerService extends SystemService {
             long verifyIncomingCallLatencyEndTimeMillis = SystemClock.elapsedRealtime();
 
             long waitExecutorStartTimeMillis = SystemClock.elapsedRealtime();
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(
                     targetUser, callback, callingPackageName, CallStats.CALL_TYPE_SET_SCHEMA,
                     () -> {
                 long waitExecutorEndTimeMillis = SystemClock.elapsedRealtime();
@@ -583,7 +588,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, callType, () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -660,7 +665,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_GET_NAMESPACES, () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -732,7 +737,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ request.getDocumentsParcel().getTotalDocumentCount())) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_PUT_DOCUMENTS, () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -886,10 +891,25 @@ public class AppSearchManagerService extends SystemService {
             UserHandle userToQuery = mServiceImplHelper.getUserToQuery(
                     request.isForEnterprise(), targetUser);
             if (userToQuery == null) {
-                // Return an empty batch result if we tried to and couldn't get the enterprise user
-                invokeCallbackOnResult(callback, AppSearchBatchResultParcel
-                        .fromStringToGenericDocumentParcel(new AppSearchBatchResult
-                                .Builder<String, GenericDocumentParcel>().build()));
+                if (Flags.enableEnterpriseEmptyBatchResultFix()) {
+                    // Return a batch result with RESULT_NOT_FOUND for each document id if we tried
+                    // to and couldn't get the enterprise user
+                    AppSearchBatchResult.Builder<String, GenericDocumentParcel> resultBuilder =
+                            new AppSearchBatchResult.Builder<>();
+                    String namespace = request.getGetByDocumentIdRequest().getNamespace();
+                    for (String id : request.getGetByDocumentIdRequest().getIds()) {
+                        resultBuilder.setFailure(id, RESULT_NOT_FOUND,
+                                "Document (" + namespace + ", " + id + ") not found.");
+                    }
+                    invokeCallbackOnResult(callback, AppSearchBatchResultParcel
+                            .fromStringToGenericDocumentParcel(resultBuilder.build()));
+                } else {
+                    // Return an empty batch result if we tried to and couldn't get the enterprise
+                    // user
+                    invokeCallbackOnResult(callback, AppSearchBatchResultParcel
+                            .fromStringToGenericDocumentParcel(new AppSearchBatchResult
+                                    .Builder<String, GenericDocumentParcel>().build()));
+                }
                 return;
             }
             // TODO(b/319315074): consider removing local getDocument and just use globalGetDocument
@@ -908,7 +928,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ request.getGetByDocumentIdRequest().getIds().size())) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, callType, () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -1032,7 +1052,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_SEARCH, () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -1115,7 +1135,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_GLOBAL_SEARCH, () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -1210,7 +1230,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, callType, () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -1299,7 +1319,7 @@ public class AppSearchManagerService extends SystemService {
                         /* numOperations= */ 1)) {
                     return;
                 }
-                boolean callAccepted = mServiceImplHelper.executeLambdaForUserNoCallbackAsync(
+                boolean callAccepted = mExecutorManager.executeLambdaForUserNoCallbackAsync(
                         targetUser, callingPackageName,
                         CallStats.CALL_TYPE_INVALIDATE_NEXT_PAGE_TOKEN, () -> {
                     @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
@@ -1373,7 +1393,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_WRITE_SEARCH_RESULTS_TO_FILE,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
@@ -1464,7 +1484,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_PUT_DOCUMENTS_FROM_FILE,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
@@ -1593,7 +1613,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_SEARCH_SUGGESTION,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
@@ -1676,7 +1696,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_REPORT_USAGE,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
@@ -1766,7 +1786,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ request.getRemoveByDocumentIdRequest().getIds().size())) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_REMOVE_DOCUMENTS_BY_ID,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
@@ -1867,7 +1887,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_REMOVE_DOCUMENTS_BY_SEARCH,
                     () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
@@ -1950,7 +1970,7 @@ public class AppSearchManagerService extends SystemService {
                     /* numOperations= */ 1)) {
                 return;
             }
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(targetUser,
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(targetUser,
                     callback, callingPackageName, CallStats.CALL_TYPE_GET_STORAGE_INFO, () -> {
                 @AppSearchResult.ResultCode int statusCode = AppSearchResult.RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -2015,7 +2035,7 @@ public class AppSearchManagerService extends SystemService {
                         /* numOperations= */ 1)) {
                     return;
                 }
-                boolean callAccepted = mServiceImplHelper.executeLambdaForUserNoCallbackAsync(
+                boolean callAccepted = mExecutorManager.executeLambdaForUserNoCallbackAsync(
                         targetUser, callingPackageName, CallStats.CALL_TYPE_FLUSH, () -> {
                     @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                     AppSearchUserInstance instance = null;
@@ -2242,7 +2262,7 @@ public class AppSearchManagerService extends SystemService {
                         AppSearchResult.newFailedResult(RESULT_DENIED, null)));
                 return;
             }
-            mServiceImplHelper.executeLambdaForUserAsync(targetUser, callback, callingPackageName,
+            mExecutorManager.executeLambdaForUserAsync(targetUser, callback, callingPackageName,
                     CallStats.CALL_TYPE_INITIALIZE, () -> {
                 @AppSearchResult.ResultCode int statusCode = RESULT_OK;
                 AppSearchUserInstance instance = null;
@@ -2354,7 +2374,7 @@ public class AppSearchManagerService extends SystemService {
                 return;
             }
 
-            boolean callAccepted = mServiceImplHelper.executeLambdaForUserAsync(
+            boolean callAccepted = mExecutorManager.executeLambdaForUserAsync(
                     targetUser, callback, callingPackageName,
                     CallStats.CALL_TYPE_EXECUTE_APP_FUNCTION,
                     () -> executeAppFunctionUnchecked(
@@ -2390,13 +2410,17 @@ public class AppSearchManagerService extends SystemService {
                 return;
             }
             ServiceInfo serviceInfo = resolveInfo.serviceInfo;
-            if (!PERMISSION_BIND_APP_FUNCTION_SERVICE.equals(serviceInfo.permission)) {
-                safeCallback.onFailedResult(AppSearchResult.newFailedResult(
-                        RESULT_NOT_FOUND,
-                        "Failed to find a valid target service. The resolved service is missing "
-                                + "the BIND_APP_FUNCTION_SERVICE permission."));
-                return;
-            }
+            // TODO(b/359911502): Commenting out this permission check since the
+            //   BIND_APP_FUNCTION_SERVICE permission is deleted from app search.
+            //   This whole app function functionality should be removed once the new app function
+            //   manager is submitted.
+            // if (!PERMISSION_BIND_APP_FUNCTION_SERVICE.equals(serviceInfo.permission)) {
+            //     safeCallback.onFailedResult(AppSearchResult.newFailedResult(
+            //             RESULT_NOT_FOUND,
+            //             "Failed to find a valid target service. The resolved service is missing "
+            //                     + "the BIND_APP_FUNCTION_SERVICE permission."));
+            //     return;
+            // }
             serviceIntent.setComponent(
                     new ComponentName(serviceInfo.packageName, serviceInfo.name));
 
@@ -2724,24 +2748,25 @@ public class AppSearchManagerService extends SystemService {
             // We shouldn't schedule any task to locked user.
             return;
         }
-        mExecutorManager.getOrCreateUserExecutor(targetUser).execute(() -> {
-            long totalLatencyStartMillis = SystemClock.elapsedRealtime();
-            OptimizeStats.Builder builder = new OptimizeStats.Builder();
-            try {
-                instance.getAppSearchImpl().checkForOptimize(mutateBatchSize, builder);
-            } catch (Exception e) {
-                Log.w(TAG, "Error occurred when check for optimize", e);
-            } finally {
-                OptimizeStats oStats = builder
-                        .setTotalLatencyMillis(
+        mExecutorManager.executeLambdaForUserNoCallbackAsync(
+                targetUser,
+                () -> {
+                    long totalLatencyStartMillis = SystemClock.elapsedRealtime();
+                    OptimizeStats.Builder builder = new OptimizeStats.Builder();
+                    try {
+                        instance.getAppSearchImpl().checkForOptimize(mutateBatchSize, builder);
+                    } catch (Exception e) {
+                        Log.w(TAG, "Error occurred when check for optimize", e);
+                    } finally {
+                        OptimizeStats oStats = builder.setTotalLatencyMillis(
                                 (int) (SystemClock.elapsedRealtime() - totalLatencyStartMillis))
-                        .build();
-                if (oStats.getOriginalDocumentCount() > 0) {
-                    // see if optimize has been run by checking originalDocumentCount
-                    instance.getLogger().logStats(oStats);
-                }
-            }
-        });
+                                .build();
+                        if (oStats.getOriginalDocumentCount() > 0) {
+                            // see if optimize has been run by checking originalDocumentCount
+                            instance.getLogger().logStats(oStats);
+                        }
+                    }
+                });
     }
 
     @WorkerThread
@@ -2752,24 +2777,25 @@ public class AppSearchManagerService extends SystemService {
             // We shouldn't schedule any task to locked user.
             return;
         }
-        mExecutorManager.getOrCreateUserExecutor(targetUser).execute(() -> {
-            long totalLatencyStartMillis = SystemClock.elapsedRealtime();
-            OptimizeStats.Builder builder = new OptimizeStats.Builder();
-            try {
-                instance.getAppSearchImpl().checkForOptimize(builder);
-            } catch (Exception e) {
-                Log.w(TAG, "Error occurred when check for optimize", e);
-            } finally {
-                OptimizeStats oStats = builder
-                        .setTotalLatencyMillis(
+        mExecutorManager.executeLambdaForUserNoCallbackAsync(
+                targetUser,
+                () -> {
+                    long totalLatencyStartMillis = SystemClock.elapsedRealtime();
+                    OptimizeStats.Builder builder = new OptimizeStats.Builder();
+                    try {
+                        instance.getAppSearchImpl().checkForOptimize(builder);
+                    } catch (Exception e) {
+                        Log.w(TAG, "Error occurred when check for optimize", e);
+                    } finally {
+                        OptimizeStats oStats = builder.setTotalLatencyMillis(
                                 (int) (SystemClock.elapsedRealtime() - totalLatencyStartMillis))
-                        .build();
-                if (oStats.getOriginalDocumentCount() > 0) {
-                    // see if optimize has been run by checking originalDocumentCount
-                    instance.getLogger().logStats(oStats);
-                }
-            }
-        });
+                                .build();
+                        if (oStats.getOriginalDocumentCount() > 0) {
+                            // see if optimize has been run by checking originalDocumentCount
+                            instance.getLogger().logStats(oStats);
+                        }
+                    }
+                });
     }
 
     /**
diff --git a/service/java/com/android/server/appsearch/AppSearchModule.java b/service/java/com/android/server/appsearch/AppSearchModule.java
index e5a1bf8b..a2463fa6 100644
--- a/service/java/com/android/server/appsearch/AppSearchModule.java
+++ b/service/java/com/android/server/appsearch/AppSearchModule.java
@@ -28,6 +28,7 @@ import android.content.Context;
 import android.os.UserHandle;
 import android.util.Log;
 
+import com.android.appsearch.flags.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.SystemService;
 import com.android.server.appsearch.appsindexer.AppsIndexerConfig;
@@ -121,7 +122,11 @@ public class AppSearchModule {
             }
 
             AppsIndexerConfig appsIndexerConfig = new FrameworkAppsIndexerConfig();
-            if (appsIndexerConfig.isAppsIndexerEnabled()) {
+            // Flags.appsIndexerEnabled will be rolled out through gantry, and this check will be
+            // removed once it is fully rolled out. appsIndexerConfig.isAppsIndexerEnabled checks
+            // DeviceConfig, so we can keep this check here in case we need to turn off apps
+            // indexer.
+            if (Flags.appsIndexerEnabled() && appsIndexerConfig.isAppsIndexerEnabled()) {
                 mAppsIndexerManagerService =
                         createAppsIndexerManagerService(getContext(), appsIndexerConfig);
                 try {
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParser.java b/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParser.java
new file mode 100644
index 00000000..89369934
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParser.java
@@ -0,0 +1,30 @@
+package com.android.server.appsearch.appsindexer;
+
+import android.annotation.NonNull;
+import android.content.pm.PackageManager;
+
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
+
+import java.util.List;
+
+/**
+ * This class parses static metadata about App Functions from an XML file located within an app's
+ * assets.
+ */
+public interface AppFunctionStaticMetadataParser {
+
+    /**
+     * Parses static metadata about App Functions from the given XML asset file.
+     *
+     * @param packageManager The PackageManager used to access app resources.
+     * @param packageName The package name of the app whose assets contain the XML file.
+     * @param assetFilePath The path to the XML file within the app's assets.
+     * @return A list of {@link AppFunctionStaticMetadata} objects representing the parsed App
+     *     Functions. An empty list is returned if there's an error during parsing.
+     */
+    @NonNull
+    List<AppFunctionStaticMetadata> parse(
+            @NonNull PackageManager packageManager,
+            @NonNull String packageName,
+            @NonNull String assetFilePath);
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImpl.java b/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImpl.java
new file mode 100644
index 00000000..7b143889
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImpl.java
@@ -0,0 +1,194 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import android.annotation.NonNull;
+import android.content.pm.PackageManager;
+import android.content.res.AssetManager;
+import android.util.Log;
+
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
+
+import org.xmlpull.v1.XmlPullParser;
+import org.xmlpull.v1.XmlPullParserException;
+import org.xmlpull.v1.XmlPullParserFactory;
+
+import java.io.IOException;
+import java.io.InputStreamReader;
+import java.util.ArrayList;
+import java.util.Collections;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * This class parses static metadata about App Functions from an XML file located within an app's
+ * assets.
+ */
+public class AppFunctionStaticMetadataParserImpl implements AppFunctionStaticMetadataParser {
+    private static final String TAG = "AppSearchMetadataParser";
+    public static final String TAG_APPFUNCTION = "appfunction";
+
+    @NonNull private final String mIndexerPackageName;
+    private final int mMaxAppFunctions;
+
+    /**
+     * @param indexerPackageName the name of the package performing the indexing. This should be the
+     *     same as the package running the apps indexer.
+     * @param maxAppFunctions The maximum number of app functions to be parsed per app. The parser
+     *     will stop once it exceeds the limit.
+     */
+    public AppFunctionStaticMetadataParserImpl(
+            @NonNull String indexerPackageName, int maxAppFunctions) {
+        mIndexerPackageName = Objects.requireNonNull(indexerPackageName);
+        mMaxAppFunctions = maxAppFunctions;
+    }
+
+    @NonNull
+    @Override
+    public List<AppFunctionStaticMetadata> parse(
+            @NonNull PackageManager packageManager,
+            @NonNull String packageName,
+            @NonNull String assetFilePath) {
+        Objects.requireNonNull(packageManager);
+        Objects.requireNonNull(packageName);
+        Objects.requireNonNull(assetFilePath);
+        try {
+            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
+            factory.setNamespaceAware(true);
+            XmlPullParser parser = factory.newPullParser();
+            AssetManager assetManager =
+                    packageManager.getResourcesForApplication(packageName).getAssets();
+            parser.setInput(new InputStreamReader(assetManager.open(assetFilePath)));
+            return parseAppFunctions(parser, packageName);
+        } catch (Exception ex) {
+            // The code parses an XML file from another app's assets, using a broad try-catch to
+            // handle potential errors since the XML structure might be unpredictable.
+            Log.e(
+                    TAG,
+                    String.format(
+                            "Failed to parse XML from package '%s', asset file '%s'",
+                            packageName, assetFilePath),
+                    ex);
+        }
+        return Collections.emptyList();
+    }
+
+    /**
+     * Parses a sequence of `appfunction` elements from the XML into an a list of {@link
+     * AppFunctionStaticMetadata}.
+     *
+     * @param parser the XmlPullParser positioned at the start of the xml file
+     */
+    @NonNull
+    private List<AppFunctionStaticMetadata> parseAppFunctions(
+            @NonNull XmlPullParser parser, @NonNull String packageName)
+            throws XmlPullParserException, IOException {
+        List<AppFunctionStaticMetadata> appFunctions = new ArrayList<>();
+
+        int eventType = parser.getEventType();
+
+        while (eventType != XmlPullParser.END_DOCUMENT) {
+            String tagName = parser.getName();
+            if (eventType == XmlPullParser.START_TAG && TAG_APPFUNCTION.equals(tagName)) {
+                AppFunctionStaticMetadata appFunction = parseAppFunction(parser, packageName);
+                appFunctions.add(appFunction);
+                if (appFunctions.size() >= mMaxAppFunctions) {
+                    Log.d(TAG, "Exceeding the max number of app functions: " + packageName);
+                    return appFunctions;
+                }
+            }
+            eventType = parser.next();
+        }
+        return appFunctions;
+    }
+
+    /**
+     * Parses a single `appfunction` element from the XML into an {@link AppFunctionStaticMetadata}
+     * object.
+     *
+     * @param parser the XmlPullParser positioned at the start of an `appfunction` element.
+     * @return an AppFunction object populated with the data from the XML.
+     */
+    @NonNull
+    private AppFunctionStaticMetadata parseAppFunction(
+            @NonNull XmlPullParser parser, @NonNull String packageName)
+            throws XmlPullParserException, IOException {
+        String functionId = null;
+        String schemaName = null;
+        Long schemaVersion = null;
+        String schemaCategory = null;
+        Boolean enabledByDefault = null;
+        Integer displayNameStringRes = null;
+        Boolean restrictCallersWithExecuteAppFunctions = null;
+        int eventType = parser.getEventType();
+        while (!(eventType == XmlPullParser.END_TAG && TAG_APPFUNCTION.equals(parser.getName()))) {
+            if (eventType == XmlPullParser.START_TAG) {
+                String tagName = parser.getName();
+                switch (tagName) {
+                    case "function_id":
+                        functionId = parser.nextText().trim();
+                        break;
+                    case "schema_name":
+                        schemaName = parser.nextText().trim();
+                        break;
+                    case "schema_version":
+                        schemaVersion = Long.parseLong(parser.nextText().trim());
+                        break;
+                    case "schema_category":
+                        schemaCategory = parser.nextText().trim();
+                        break;
+                    case "enabled_by_default":
+                        enabledByDefault = Boolean.parseBoolean(parser.nextText().trim());
+                        break;
+                    case "restrict_callers_with_execute_app_functions":
+                        restrictCallersWithExecuteAppFunctions =
+                                Boolean.parseBoolean(parser.nextText().trim());
+                        break;
+                    case "display_name_string_res":
+                        displayNameStringRes = Integer.parseInt(parser.nextText().trim());
+                        break;
+                }
+            }
+            eventType = parser.next();
+        }
+
+        if (functionId == null) {
+            throw new XmlPullParserException("parseAppFunction: Missing functionId in the xml.");
+        }
+        AppFunctionStaticMetadata.Builder builder =
+                new AppFunctionStaticMetadata.Builder(packageName, functionId, mIndexerPackageName);
+        if (schemaName != null) {
+            builder.setSchemaName(schemaName);
+        }
+        if (schemaVersion != null) {
+            builder.setSchemaVersion(schemaVersion);
+        }
+        if (schemaCategory != null) {
+            builder.setSchemaCategory(schemaCategory);
+        }
+        if (enabledByDefault != null) {
+            builder.setEnabledByDefault(enabledByDefault);
+        }
+        if (restrictCallersWithExecuteAppFunctions != null) {
+            builder.setRestrictCallersWithExecuteAppFunctions(
+                    restrictCallersWithExecuteAppFunctions);
+        }
+        if (displayNameStringRes != null) {
+            builder.setDisplayNameStringRes(displayNameStringRes);
+        }
+        return builder.build();
+    }
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettings.java b/service/java/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettings.java
new file mode 100644
index 00000000..b286389d
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettings.java
@@ -0,0 +1,48 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import android.annotation.NonNull;
+
+import com.android.server.appsearch.indexer.IndexerSettings;
+
+import java.io.File;
+
+/**
+ * Abstract class for settings backed by a PersistableBundle.
+ *
+ * <p>Holds settings such as:
+ *
+ * <ul>
+ *   <li>getting and setting the timestamp of the last update, stored in {@link
+ *       #getLastUpdateTimestampMillis()}
+ * </ul>
+ *
+ * <p>This class is NOT thread safe (similar to {@link PersistableBundle} which it wraps).
+ */
+public class AppOpenEventIndexerSettings extends IndexerSettings {
+    static final String SETTINGS_FILE_NAME = "app_open_event_indexer_settings.pb";
+
+    public AppOpenEventIndexerSettings(@NonNull File baseDir) {
+        super(baseDir);
+    }
+
+    @Override
+    protected String getSettingsFileName() {
+        return SETTINGS_FILE_NAME;
+    }
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppSearchHelper.java b/service/java/com/android/server/appsearch/appsindexer/AppSearchHelper.java
index ef3dd523..ed29c1ce 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppSearchHelper.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppSearchHelper.java
@@ -17,14 +17,18 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchEnvironmentFactory;
 import android.app.appsearch.AppSearchManager;
 import android.app.appsearch.AppSearchResult;
 import android.app.appsearch.AppSearchSchema;
+import android.app.appsearch.AppSearchSession;
 import android.app.appsearch.BatchResultCallback;
+import android.app.appsearch.GenericDocument;
 import android.app.appsearch.PackageIdentifier;
 import android.app.appsearch.PutDocumentsRequest;
+import android.app.appsearch.RemoveByDocumentIdRequest;
 import android.app.appsearch.SearchResult;
 import android.app.appsearch.SearchSpec;
 import android.app.appsearch.SetSchemaRequest;
@@ -32,16 +36,20 @@ import android.app.appsearch.exceptions.AppSearchException;
 import android.content.Context;
 import android.util.AndroidRuntimeException;
 import android.util.ArrayMap;
+import android.util.ArraySet;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
 import java.io.Closeable;
+import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
+import java.util.Set;
 import java.util.concurrent.ExecutorService;
 
 /**
@@ -71,108 +79,160 @@ public class AppSearchHelper implements Closeable {
     public static final String APP_DATABASE = "apps-db";
     private static final int GET_APP_IDS_PAGE_SIZE = 1000;
     private final Context mContext;
-    private final ExecutorService mExecutor;
-    private final AppSearchManager mAppSearchManager;
-    private SyncAppSearchSession mSyncAppSearchSession;
-    private SyncGlobalSearchSession mSyncGlobalSearchSession;
+    // Volatile, not final due to being swapped during some tests
+    private volatile SyncAppSearchSession mSyncAppSearchSession;
+    private final SyncGlobalSearchSession mSyncGlobalSearchSession;
 
-    /** Creates and initializes an {@link AppSearchHelper} */
-    @NonNull
-    public static AppSearchHelper createAppSearchHelper(@NonNull Context context)
-            throws AppSearchException {
-        Objects.requireNonNull(context);
-
-        AppSearchHelper appSearchHelper = new AppSearchHelper(context);
-        appSearchHelper.initializeAppSearchSessions();
-        return appSearchHelper;
-    }
-
-    /** Creates an initialized {@link AppSearchHelper}. */
-    @VisibleForTesting
-    private AppSearchHelper(@NonNull Context context) {
+    /** Creates an {@link AppSearchHelper}. */
+    public AppSearchHelper(@NonNull Context context) {
         mContext = Objects.requireNonNull(context);
-
-        mAppSearchManager = context.getSystemService(AppSearchManager.class);
-        if (mAppSearchManager == null) {
+        AppSearchManager appSearchManager = mContext.getSystemService(AppSearchManager.class);
+        if (appSearchManager == null) {
             throw new AndroidRuntimeException(
                     "Can't get AppSearchManager to initialize AppSearchHelper.");
         }
-        mExecutor =
+        AppSearchManager.SearchContext searchContext =
+                new AppSearchManager.SearchContext.Builder(APP_DATABASE).build();
+        ExecutorService executor =
                 AppSearchEnvironmentFactory.getEnvironmentInstance().createSingleThreadExecutor();
+        mSyncAppSearchSession =
+                new SyncAppSearchSessionImpl(appSearchManager, searchContext, executor);
+        mSyncGlobalSearchSession = new SyncGlobalSearchSessionImpl(appSearchManager, executor);
     }
 
     /**
-     * Sets up the search session.
+     * Allows us to test various scenarios involving SyncAppSearchSession.
      *
-     * @throws AppSearchException if unable to initialize the {@link SyncAppSearchSession} or the
-     *     {@link SyncGlobalSearchSession}.
+     * <p>This method is not thread-safe, as it could be ran in the middle of a set schema, index,
+     * or search operation. It should only be called from tests, and threading safety should be
+     * handled by the test.
      */
-    private void initializeAppSearchSessions() throws AppSearchException {
-        AppSearchManager.SearchContext searchContext =
-                new AppSearchManager.SearchContext.Builder(APP_DATABASE).build();
-        mSyncAppSearchSession =
-                new SyncAppSearchSessionImpl(mAppSearchManager, searchContext, mExecutor);
-        mSyncGlobalSearchSession = new SyncGlobalSearchSessionImpl(mAppSearchManager, mExecutor);
-    }
-
-    /** Just for testing, allows us to test various scenarios involving SyncAppSearchSession. */
     @VisibleForTesting
-    /* package */ void setAppSearchSession(@NonNull SyncAppSearchSession session) {
-        // Close the old one
-        mSyncAppSearchSession.close();
+    /* package */ void setAppSearchSessionForTest(@NonNull SyncAppSearchSession session) {
+        // Close the existing one
+        if (mSyncAppSearchSession != null) {
+            mSyncAppSearchSession.close();
+        }
         mSyncAppSearchSession = Objects.requireNonNull(session);
     }
 
     /**
      * Sets the AppsIndexer database schema to correspond to the list of passed in {@link
-     * PackageIdentifier}s. Note that this means if a schema exists in AppSearch that does not get
-     * passed in to this method, it will be erased. And if a schema does not exist in AppSearch that
-     * is passed in to this method, it will be created.
+     * PackageIdentifier}s, representing app schemas, and a list of {@link PackageIdentifier}s,
+     * representing app functions. Note that this means if a schema exists in AppSearch that does
+     * not get passed in to this method, it will be erased. And if a schema does not exist in
+     * AppSearch that is passed in to this method, it will be created.
+     *
+     * @param mobileAppPkgs A list of {@link PackageIdentifier}s for which to set {@link
+     *     MobileApplication} schemas for
+     * @param appFunctionPkgs A list of {@link PackageIdentifier}s for which to set {@link
+     *     AppFunctionStaticMetadata} schemas for. These are packages with an AppFunctionService. It
+     *     is always a subset of `mobileAppPkgs`.
      */
-    public void setSchemasForPackages(@NonNull List<PackageIdentifier> pkgs)
+    @WorkerThread
+    public void setSchemasForPackages(
+            @NonNull List<PackageIdentifier> mobileAppPkgs,
+            @NonNull List<PackageIdentifier> appFunctionPkgs)
             throws AppSearchException {
-        Objects.requireNonNull(pkgs);
+        Objects.requireNonNull(mobileAppPkgs);
+        Objects.requireNonNull(appFunctionPkgs);
+
         SetSchemaRequest.Builder schemaBuilder =
                 new SetSchemaRequest.Builder()
                         // If MobileApplication schema later gets changed to a compatible schema, we
                         // should first try setting the schema with forceOverride = false.
                         .setForceOverride(true);
-        for (int i = 0; i < pkgs.size(); i++) {
-            PackageIdentifier pkg = pkgs.get(i);
+        for (int i = 0; i < mobileAppPkgs.size(); i++) {
+            PackageIdentifier pkg = mobileAppPkgs.get(i);
             // As all apps are in the same db, we have to make sure that even if it's getting
             // updated, the schema is in the list of schemas
             String packageName = pkg.getPackageName();
             AppSearchSchema schemaVariant =
                     MobileApplication.createMobileApplicationSchemaForPackage(packageName);
             schemaBuilder.addSchemas(schemaVariant);
+
             // Since the Android package of the underlying apps are different from the package name
             // that "owns" the builtin:MobileApplication corpus in AppSearch, we needed to add the
             // PackageIdentifier parameter to setPubliclyVisibleSchema.
             schemaBuilder.setPubliclyVisibleSchema(schemaVariant.getSchemaType(), pkg);
         }
 
+        // Set the base type first for AppFunctions
+        if (!appFunctionPkgs.isEmpty() && AppFunctionStaticMetadata.shouldSetParentType()) {
+            schemaBuilder.addSchemas(AppFunctionStaticMetadata.PARENT_TYPE_APPSEARCH_SCHEMA);
+        }
+        for (int i = 0; i < appFunctionPkgs.size(); i++) {
+            PackageIdentifier pkg = appFunctionPkgs.get(i);
+            String packageName = pkg.getPackageName();
+            AppSearchSchema schemaVariant =
+                    AppFunctionStaticMetadata.createAppFunctionSchemaForPackage(packageName);
+            schemaBuilder.addSchemas(schemaVariant);
+            schemaBuilder.setPubliclyVisibleSchema(schemaVariant.getSchemaType(), pkg);
+        }
+
         // TODO(b/275592563): Log app removal in metrics
         mSyncAppSearchSession.setSchema(schemaBuilder.build());
     }
 
     /**
      * Indexes a collection of apps into AppSearch. This requires that the corresponding
-     * MobileApplication schemas are already set by a previous call to {@link
-     * #setSchemasForPackages}. The call doesn't necessarily have to happen in the current sync.
+     * MobileApplication and AppFunctionStaticMetadata schemas are already set by a previous call to
+     * {@link#setSchemasForPackages}. The call doesn't necessarily have to happen in the current
+     * sync.
      *
+     * @param apps a list of MobileApplication documents to be inserted.
+     * @param currentAppFunctions a list of AppFunctionStaticMetadata documents to be inserted. Each
+     *     AppFunctionStaticMetadata should point to its corresponding MobileApplication.
+     * @param indexedAppFunctions a list of indexed AppFunctionStaticMetadata documents
      * @throws AppSearchException if indexing results in a {@link
      *     AppSearchResult#RESULT_OUT_OF_SPACE} result code. It will also throw this if the put call
      *     results in a system error as in {@link BatchResultCallback#onSystemError}. This may
      *     happen if the AppSearch service unexpectedly fails to initialize and can't be recovered,
      *     for instance.
+     * @return an {@link AppSearchBatchResult} containing the results of the put operation. The keys
+     *     of the returned {@link AppSearchBatchResult} are the IDs of the input documents. The
+     *     values are {@code null} if they were successfully indexed, or a failed {@link
+     *     AppSearchResult} otherwise.
+     * @see AppSearchSession#put
      */
-    public void indexApps(@NonNull List<MobileApplication> apps) throws AppSearchException {
+    @WorkerThread
+    public AppSearchBatchResult<String, Void> indexApps(
+            @NonNull List<MobileApplication> apps,
+            @NonNull List<AppFunctionStaticMetadata> currentAppFunctions,
+            @NonNull List<GenericDocument> indexedAppFunctions)
+            throws AppSearchException {
         Objects.requireNonNull(apps);
+        Objects.requireNonNull(currentAppFunctions);
 
-        // At this point, the document schema names have already been set to the per-package name.
-        // We can just add them to the request.
+        // For packages that we are re-indexing, we need to collect a list of stale of function IDs.
+        Set<String> packagesToReindex = new ArraySet<>();
+        Set<String> currentAppFunctionIds = new ArraySet<>();
+        for (int i = 0; i < currentAppFunctions.size(); i++) {
+            AppFunctionStaticMetadata appFunction = currentAppFunctions.get(i);
+            packagesToReindex.add(appFunction.getPackageName());
+            currentAppFunctionIds.add(appFunction.getId());
+        }
+        // Determine which indexed app functions are no longer in the apps. We should only remove
+        // functions in packages that we are re-indexing.
+        Set<String> appFunctionIdsToRemove = new ArraySet<>();
+        for (int i = 0; i < indexedAppFunctions.size(); i++) {
+            GenericDocument appFunction = indexedAppFunctions.get(i);
+            String id = appFunction.getId();
+            String packageName =
+                    appFunction.getPropertyString(AppFunctionStaticMetadata.PROPERTY_PACKAGE_NAME);
+            if (packagesToReindex.contains(packageName) && !currentAppFunctionIds.contains(id)) {
+                appFunctionIdsToRemove.add(id);
+            }
+        }
+
+        // Then, insert all the documents. At this point, the document schema names have
+        // already been set to the per-package name. We can just add them to the request.
+        // TODO(b/357551503): put only the documents that have been added or updated.
         PutDocumentsRequest request =
-                new PutDocumentsRequest.Builder().addGenericDocuments(apps).build();
+                new PutDocumentsRequest.Builder()
+                        .addGenericDocuments(apps)
+                        .addGenericDocuments(currentAppFunctions)
+                        .build();
 
         AppSearchBatchResult<String, Void> result = mSyncAppSearchSession.put(request);
         if (!result.isSuccess()) {
@@ -187,14 +247,25 @@ public class AppSearchHelper implements Closeable {
                 }
             }
         }
+
+        // Then, delete all the stale documents.
+        mSyncAppSearchSession.remove(
+                new RemoveByDocumentIdRequest.Builder(
+                                AppFunctionStaticMetadata.APP_FUNCTION_NAMESPACE)
+                        .addIds(appFunctionIdsToRemove)
+                        .build());
+        return result;
     }
 
     /**
      * Searches AppSearch and returns a Map with the package ids and their last updated times. This
      * helps us determine which app documents need to be re-indexed.
+     *
+     * @return a mapping of document id Strings to updated timestamps.
      */
     @NonNull
-    public Map<String, Long> getAppsFromAppSearch() {
+    @WorkerThread
+    public Map<String, Long> getAppsFromAppSearch() throws AppSearchException {
         SearchSpec allAppsSpec =
                 new SearchSpec.Builder()
                         .addFilterNamespaces(MobileApplication.APPS_NAMESPACE)
@@ -209,8 +280,13 @@ public class AppSearchHelper implements Closeable {
         return collectUpdatedTimestampFromAllPages(results);
     }
 
-    /** Iterates through result pages to get the last updated times */
+    /**
+     * Iterates through result pages to get the last updated times
+     *
+     * @return a mapping of document id Strings updated timestamps.
+     */
     @NonNull
+    @WorkerThread
     private Map<String, Long> collectUpdatedTimestampFromAllPages(
             @NonNull SyncSearchResults results) {
         Objects.requireNonNull(results);
@@ -240,6 +316,76 @@ public class AppSearchHelper implements Closeable {
         return appUpdatedMap;
     }
 
+    // TODO(b/357551503): Refactor/combine these two methods with the above to simplify code.
+
+    /**
+     * Searches AppSearch and returns a list of app function GenericDocuments.
+     *
+     * @return a list of app function GenericDocuments, containing just the id and package name.
+     */
+    @NonNull
+    @WorkerThread
+    public List<GenericDocument> getAppFunctionsFromAppSearch() throws AppSearchException {
+        List<GenericDocument> appFunctions = new ArrayList<>();
+        SearchSpec allAppsSpec =
+                new SearchSpec.Builder()
+                        .addFilterNamespaces(AppFunctionStaticMetadata.APP_FUNCTION_NAMESPACE)
+                        .addProjection(
+                                SearchSpec.SCHEMA_TYPE_WILDCARD,
+                                Collections.singletonList(
+                                        AppFunctionStaticMetadata.PROPERTY_PACKAGE_NAME))
+                        .addFilterPackageNames(mContext.getPackageName())
+                        .setResultCountPerPage(GET_APP_IDS_PAGE_SIZE)
+                        .build();
+        SyncSearchResults results = mSyncGlobalSearchSession.search(/* query= */ "", allAppsSpec);
+        // TODO(b/357551503): Use pagination instead of building a list of all docs.
+        try {
+            List<SearchResult> resultList = results.getNextPage();
+            while (!resultList.isEmpty()) {
+                for (int i = 0; i < resultList.size(); i++) {
+                    appFunctions.add(resultList.get(i).getGenericDocument());
+                }
+                resultList = results.getNextPage();
+            }
+        } catch (AppSearchException e) {
+            Log.e(TAG, "Error while searching for all app documents", e);
+        }
+        return appFunctions;
+    }
+
+    /**
+     * Iterates through result pages and returns a set of package name corresponding to the packages
+     * that have app functions currently indexed into AppSearch.
+     */
+    @NonNull
+    @WorkerThread
+    private Set<String> collectAppFunctionPackagesFromAllPages(@NonNull SyncSearchResults results) {
+        Objects.requireNonNull(results);
+        Set<String> packages = new ArraySet<>();
+
+        try {
+            List<SearchResult> resultList = results.getNextPage();
+
+            while (!resultList.isEmpty()) {
+                for (int i = 0; i < resultList.size(); i++) {
+                    SearchResult result = resultList.get(i);
+                    packages.add(
+                            result.getGenericDocument()
+                                    .getPropertyString(
+                                            AppFunctionStaticMetadata.PROPERTY_PACKAGE_NAME));
+                }
+
+                resultList = results.getNextPage();
+            }
+        } catch (AppSearchException e) {
+            Log.e(TAG, "Error while searching for all app documents", e);
+        }
+        // Return what we have so far. Even if this doesn't fetch all documents, that is fine as we
+        // can continue with indexing. The documents that aren't fetched will be detected as new
+        // apps and re-indexed.
+        return packages;
+    }
+
     /** Closes the AppSearch sessions. */
     @Override
     public void close() {
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerConfig.java b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerConfig.java
index 9ab105a6..efb3e72c 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerConfig.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerConfig.java
@@ -26,13 +26,19 @@ import java.util.concurrent.TimeUnit;
  * @hide
  */
 public interface AppsIndexerConfig {
-    boolean DEFAULT_APPS_INDEXER_ENABLED = false;
+    boolean DEFAULT_APPS_INDEXER_ENABLED = true;
+
     long DEFAULT_APPS_UPDATE_INTERVAL_MILLIS = TimeUnit.DAYS.toMillis(30); // 30 days.
+    /** The default maximum number of app functions per package that the app indexer will index. */
+    int DEFAULT_MAX_APP_FUNCTIONS_PER_PACKAGE = 500;
 
     /** Returns whether Apps Indexer is enabled. */
     boolean isAppsIndexerEnabled();
 
     /* Returns the minimum internal in millis for two consecutive scheduled updates. */
     long getAppsMaintenanceUpdateIntervalMillis();
+
+    /** Returns the max number of app functions the app indexer will index per package. */
+    int getMaxAppFunctionsPerPackage();
 }
 
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerImpl.java b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerImpl.java
index 7947cdd3..b8e87419 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerImpl.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerImpl.java
@@ -17,20 +17,27 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
+import android.app.appsearch.AppSearchBatchResult;
+import android.app.appsearch.AppSearchResult;
+import android.app.appsearch.GenericDocument;
 import android.app.appsearch.PackageIdentifier;
 import android.app.appsearch.exceptions.AppSearchException;
 import android.content.Context;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
-import android.content.pm.ResolveInfo;
+import android.os.SystemClock;
 import android.util.ArrayMap;
 import android.util.ArraySet;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
+import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
 import java.io.Closeable;
 import java.util.ArrayList;
+import java.util.Collection;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
@@ -48,10 +55,13 @@ public final class AppsIndexerImpl implements Closeable {
 
     private final Context mContext;
     private final AppSearchHelper mAppSearchHelper;
+    private final AppsIndexerConfig mAppsIndexerConfig;
 
-    public AppsIndexerImpl(@NonNull Context context) throws AppSearchException {
+    public AppsIndexerImpl(@NonNull Context context, @NonNull AppsIndexerConfig appsIndexerConfig)
+            throws AppSearchException {
         mContext = Objects.requireNonNull(context);
-        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(context);
+        mAppSearchHelper = new AppSearchHelper(context);
+        mAppsIndexerConfig = Objects.requireNonNull(appsIndexerConfig);
     }
 
     /**
@@ -62,21 +72,33 @@ public final class AppsIndexerImpl implements Closeable {
      *
      * @param settings contains update timestamps that help the indexer determine which apps were
      *     updated.
+     * @param appsUpdateStats contains stats about the apps indexer update. This method will
+     *     populate the fields of this {@link AppsUpdateStats} structure.
      */
     @VisibleForTesting
-    public void doUpdate(@NonNull AppsIndexerSettings settings) throws AppSearchException {
+    @WorkerThread
+    public void doUpdate(
+            @NonNull AppsIndexerSettings settings, @NonNull AppsUpdateStats appsUpdateStats)
+            throws AppSearchException {
         Objects.requireNonNull(settings);
+        Objects.requireNonNull(appsUpdateStats);
         long currentTimeMillis = System.currentTimeMillis();
 
-        PackageManager packageManager = mContext.getPackageManager();
-
         // Search AppSearch for MobileApplication objects to get a "current" list of indexed apps.
+        long beforeGetTimestamp = SystemClock.elapsedRealtime();
         Map<String, Long> appUpdatedTimestamps = mAppSearchHelper.getAppsFromAppSearch();
-        Map<PackageInfo, ResolveInfo> launchablePackages =
-                AppsUtil.getLaunchablePackages(packageManager);
-        Set<PackageInfo> packageInfos = launchablePackages.keySet();
+        appsUpdateStats.mAppSearchGetLatencyMillis =
+                SystemClock.elapsedRealtime() - beforeGetTimestamp;
+
+        long beforePackageManagerTimestamp = SystemClock.elapsedRealtime();
+        PackageManager packageManager = mContext.getPackageManager();
+        Map<PackageInfo, ResolveInfos> packagesToIndex =
+                AppsUtil.getPackagesToIndex(packageManager);
+        appsUpdateStats.mPackageManagerLatencyMillis =
+                SystemClock.elapsedRealtime() - beforePackageManagerTimestamp;
+        Set<PackageInfo> packageInfos = packagesToIndex.keySet();
 
-        Map<PackageInfo, ResolveInfo> packagesToBeAddedOrUpdated = new ArrayMap<>();
+        Map<PackageInfo, ResolveInfos> packagesToBeAddedOrUpdated = new ArrayMap<>();
         long mostRecentAppUpdatedTimestampMillis = settings.getLastAppUpdateTimestampMillis();
 
         // Prepare a set of current app IDs for efficient lookup
@@ -91,50 +113,143 @@ public final class AppsIndexerImpl implements Closeable {
 
             Long storedUpdateTime = appUpdatedTimestamps.get(packageInfo.packageName);
 
-            if (storedUpdateTime == null || packageInfo.lastUpdateTime != storedUpdateTime) {
-                // Added or updated
-                packagesToBeAddedOrUpdated.put(packageInfo, launchablePackages.get(packageInfo));
+            boolean added = storedUpdateTime == null;
+            boolean updated =
+                    storedUpdateTime != null && packageInfo.lastUpdateTime != storedUpdateTime;
+
+            if (added) {
+                appsUpdateStats.mNumberOfAppsAdded++;
+            }
+            if (updated) {
+                appsUpdateStats.mNumberOfAppsUpdated++;
+            }
+            if (added || updated) {
+                packagesToBeAddedOrUpdated.put(packageInfo, packagesToIndex.get(packageInfo));
+            } else {
+                appsUpdateStats.mNumberOfAppsUnchanged++;
             }
         }
 
+        List<GenericDocument> appSearchAppFunctions =
+                mAppSearchHelper.getAppFunctionsFromAppSearch();
+
         try {
-            if (!currentAppIds.equals(appUpdatedTimestamps.keySet())) {
-                // The current list of apps in AppSearch does not match what is in PackageManager.
-                // This means this is the first sync, an app was removed, or an app was added. In
-                // all cases, we need to call setSchema to keep AppSearch in sync with
-                // PackageManager.
+            if (!currentAppIds.equals(appUpdatedTimestamps.keySet())
+                    || requiresInsertSchemaForAppFunction(packagesToIndex, appSearchAppFunctions)) {
+                // The current list of apps/app functions in AppSearch does not match what is in
+                // PackageManager. This means this is the first sync, an app/app function was
+                // removed, or an app/app function was added. In all cases, we need to call
+                // setSchema to keep AppSearch in sync with PackageManager.
+
+                // currentAppIds comes from PackageManager, appUpdatedTimestamps comes from
+                // AppSearch. Deleted apps are those in appUpdateTimestamps and NOT in currentAppIds
+                appsUpdateStats.mNumberOfAppsRemoved = 0;
+                for (String appSearchApp : appUpdatedTimestamps.keySet()) {
+                    if (!currentAppIds.contains(appSearchApp)) {
+                        appsUpdateStats.mNumberOfAppsRemoved++;
+                    }
+                }
+
                 List<PackageIdentifier> packageIdentifiers = new ArrayList<>();
-                for (PackageInfo packageInfo : packageInfos) {
+                List<PackageIdentifier> packageIdentifiersWithAppFunctions = new ArrayList<>();
+                for (Map.Entry<PackageInfo, ResolveInfos> entry : packagesToIndex.entrySet()) {
                     // We get certificates here as getting the certificates during the previous for
                     // loop would be wasteful if we end up not needing to call set schema
+                    PackageInfo packageInfo = entry.getKey();
                     byte[] certificate = AppsUtil.getCertificate(packageInfo);
                     if (certificate == null) {
                         Log.e(TAG, "Certificate not found for package: " + packageInfo.packageName);
                         continue;
                     }
-                    packageIdentifiers.add(
-                            new PackageIdentifier(packageInfo.packageName, certificate));
+                    PackageIdentifier packageIdentifier =
+                            new PackageIdentifier(packageInfo.packageName, certificate);
+                    packageIdentifiers.add(packageIdentifier);
+                    if (entry.getValue().getAppFunctionServiceInfo() != null) {
+                        packageIdentifiersWithAppFunctions.add(packageIdentifier);
+                    }
                 }
                 // The certificate is necessary along with the package name as it is used in
                 // visibility settings.
-                mAppSearchHelper.setSchemasForPackages(packageIdentifiers);
+                long beforeSetSchemaTimestamp = SystemClock.elapsedRealtime();
+                mAppSearchHelper.setSchemasForPackages(
+                        packageIdentifiers, packageIdentifiersWithAppFunctions);
+                appsUpdateStats.mAppSearchSetSchemaLatencyMillis =
+                        SystemClock.elapsedRealtime() - beforeSetSchemaTimestamp;
             }
 
             if (!packagesToBeAddedOrUpdated.isEmpty()) {
-                mAppSearchHelper.indexApps(
+                long beforePutTimestamp = SystemClock.elapsedRealtime();
+                List<MobileApplication> mobileApplications =
                         AppsUtil.buildAppsFromPackageInfos(
-                                packageManager, packagesToBeAddedOrUpdated));
+                                packageManager, packagesToBeAddedOrUpdated);
+                List<AppFunctionStaticMetadata> appFunctions =
+                        AppsUtil.buildAppFunctionStaticMetadata(
+                                packageManager,
+                                packagesToBeAddedOrUpdated,
+                                /* indexerPackageName= */ mContext.getPackageName(),
+                                mAppsIndexerConfig.getMaxAppFunctionsPerPackage());
+
+                AppSearchBatchResult<String, Void> result =
+                        mAppSearchHelper.indexApps(
+                                mobileApplications, appFunctions, appSearchAppFunctions);
+                if (result.isSuccess()) {
+                    appsUpdateStats.mUpdateStatusCodes.add(AppSearchResult.RESULT_OK);
+                } else {
+                    Collection<AppSearchResult<Void>> values = result.getAll().values();
+
+                    for (AppSearchResult<Void> putResult : values) {
+                        appsUpdateStats.mUpdateStatusCodes.add(putResult.getResultCode());
+                    }
+                }
+                appsUpdateStats.mAppSearchPutLatencyMillis =
+                        SystemClock.elapsedRealtime() - beforePutTimestamp;
             }
 
             settings.setLastAppUpdateTimestampMillis(mostRecentAppUpdatedTimestampMillis);
             settings.setLastUpdateTimestampMillis(currentTimeMillis);
+
+            appsUpdateStats.mLastAppUpdateTimestampMillis = mostRecentAppUpdatedTimestampMillis;
         } catch (AppSearchException e) {
             // Reset the last update time stamp and app update timestamp so we can try again later.
             settings.reset();
+            appsUpdateStats.mUpdateStatusCodes.clear();
+            appsUpdateStats.mUpdateStatusCodes.add(e.getResultCode());
             throw e;
         }
     }
 
+    /** Returns whether the indexer should insert schema for app functions. */
+    private boolean requiresInsertSchemaForAppFunction(
+            @NonNull Map<PackageInfo, ResolveInfos> targetedPackages,
+            List<GenericDocument> appSearchAppFunctions)
+            throws AppSearchException {
+        // Should re-insert the schema as long as the indexed packages does not match the current
+        // set of packages.
+        Set<String> indexedAppFunctionPackages = new ArraySet<>();
+        for (int i = 0; i < appSearchAppFunctions.size(); i++) {
+            indexedAppFunctionPackages.add(
+                    appSearchAppFunctions
+                            .get(i)
+                            .getPropertyString(AppFunctionStaticMetadata.PROPERTY_PACKAGE_NAME));
+        }
+        Set<String> currentAppFunctionPackages = getCurrentAppFunctionPackages(targetedPackages);
+        return !indexedAppFunctionPackages.equals(currentAppFunctionPackages);
+    }
+
+    /** Returns a set of currently installed packages that have app functions. */
+    private Set<String> getCurrentAppFunctionPackages(
+            @NonNull Map<PackageInfo, ResolveInfos> targetedPackages) {
+        Set<String> currentAppFunctionPackages = new ArraySet<>();
+        for (Map.Entry<PackageInfo, ResolveInfos> entry : targetedPackages.entrySet()) {
+            PackageInfo packageInfo = entry.getKey();
+            ResolveInfos resolveInfos = entry.getValue();
+            if (resolveInfos.getAppFunctionServiceInfo() != null) {
+                currentAppFunctionPackages.add(packageInfo.packageName);
+            }
+        }
+        return currentAppFunctionPackages;
+    }
+
     /** Shuts down the {@link AppsIndexerImpl} and its {@link AppSearchHelper}. */
     @Override
     public void close() {
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerSettings.java b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerSettings.java
index 28c1daf6..c2ca6dc2 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerSettings.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerSettings.java
@@ -17,16 +17,10 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
-import android.os.PersistableBundle;
-import android.util.AtomicFile;
 
-import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.indexer.IndexerSettings;
 
 import java.io.File;
-import java.io.FileInputStream;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.util.Objects;
 
 /**
  * Apps indexer settings backed by a PersistableBundle.
@@ -34,44 +28,21 @@ import java.util.Objects;
  * <p>Holds settings such as:
  *
  * <ul>
- *   <li>the last time a full update was performed
- *   <li>the time of the last apps update
- *   <li>the time of the last apps deletion
+ *   <li>the timestamp of the last full update
+ *   <li>the timestamp of the last apps update
  * </ul>
- *
- * <p>This class is NOT thread safe (similar to {@link PersistableBundle} which it wraps).
- *
- * @hide
  */
-public class AppsIndexerSettings {
+public class AppsIndexerSettings extends IndexerSettings {
     static final String SETTINGS_FILE_NAME = "apps_indexer_settings.pb";
-    static final String LAST_UPDATE_TIMESTAMP_KEY = "last_update_timestamp_millis";
     static final String LAST_APP_UPDATE_TIMESTAMP_KEY = "last_app_update_timestamp_millis";
 
-    private final File mFile;
-    private PersistableBundle mBundle = new PersistableBundle();
-
     public AppsIndexerSettings(@NonNull File baseDir) {
-        Objects.requireNonNull(baseDir);
-        mFile = new File(baseDir, SETTINGS_FILE_NAME);
-    }
-
-    public void load() throws IOException {
-        mBundle = readBundle(mFile);
-    }
-
-    public void persist() throws IOException {
-        writeBundle(mFile, mBundle);
+        super(baseDir);
     }
 
-    /** Returns the timestamp of when the last full update occurred in milliseconds. */
-    public long getLastUpdateTimestampMillis() {
-        return mBundle.getLong(LAST_UPDATE_TIMESTAMP_KEY);
-    }
-
-    /** Sets the timestamp of when the last full update occurred in milliseconds. */
-    public void setLastUpdateTimestampMillis(long timestampMillis) {
-        mBundle.putLong(LAST_UPDATE_TIMESTAMP_KEY, timestampMillis);
+    @Override
+    protected String getSettingsFileName() {
+        return SETTINGS_FILE_NAME;
     }
 
     /** Returns the timestamp of when the last app was updated in milliseconds. */
@@ -79,40 +50,14 @@ public class AppsIndexerSettings {
         return mBundle.getLong(LAST_APP_UPDATE_TIMESTAMP_KEY);
     }
 
-    /** Sets the timestamp of when the last apps was updated in milliseconds. */
+    /** Sets the timestamp of when the last app was updated in milliseconds. */
     public void setLastAppUpdateTimestampMillis(long timestampMillis) {
         mBundle.putLong(LAST_APP_UPDATE_TIMESTAMP_KEY, timestampMillis);
     }
 
-    /** Resets all the settings to default values. */
+    @Override
     public void reset() {
-        setLastUpdateTimestampMillis(0);
+        super.reset();
         setLastAppUpdateTimestampMillis(0);
     }
-
-    @VisibleForTesting
-    @NonNull
-    static PersistableBundle readBundle(@NonNull File src) throws IOException {
-        AtomicFile atomicFile = new AtomicFile(src);
-        try (FileInputStream fis = atomicFile.openRead()) {
-            return PersistableBundle.readFromStream(fis);
-        }
-    }
-
-    @VisibleForTesting
-    static void writeBundle(@NonNull File dest, @NonNull PersistableBundle bundle)
-            throws IOException {
-        AtomicFile atomicFile = new AtomicFile(dest);
-        FileOutputStream fos = null;
-        try {
-            fos = atomicFile.startWrite();
-            bundle.writeToStream(fos);
-            atomicFile.finishWrite(fos);
-        } catch (IOException e) {
-            if (fos != null) {
-                atomicFile.failWrite(fos);
-            }
-            throw e;
-        }
-    }
 }
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerUserInstance.java b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerUserInstance.java
index 13f7b616..4b9b977b 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppsIndexerUserInstance.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsIndexerUserInstance.java
@@ -19,14 +19,17 @@ package com.android.server.appsearch.appsindexer;
 import static com.android.server.appsearch.indexer.IndexerMaintenanceConfig.APPS_INDEXER;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchEnvironmentFactory;
 import android.app.appsearch.exceptions.AppSearchException;
 import android.content.Context;
+import android.os.SystemClock;
 import android.util.Log;
 import android.util.Slog;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.appsearch.indexer.IndexerMaintenanceService;
+import com.android.server.appsearch.stats.AppSearchStatsLog;
 
 import java.io.File;
 import java.io.FileNotFoundException;
@@ -116,7 +119,7 @@ public final class AppsIndexerUserInstance {
         AppsIndexerUserInstance indexer =
                 new AppsIndexerUserInstance(appsDir, executorService, context, appsIndexerConfig);
         indexer.loadSettingsAsync();
-        indexer.mAppsIndexerImpl = new AppsIndexerImpl(context);
+        indexer.mAppsIndexerImpl = new AppsIndexerImpl(context, appsIndexerConfig);
 
         return indexer;
     }
@@ -171,6 +174,10 @@ public final class AppsIndexerUserInstance {
      *     for the last update timestamp.
      */
     public void updateAsync(boolean firstRun) {
+        AppsUpdateStats appsUpdateStats = new AppsUpdateStats();
+        long updateLatencyStartTimestampMillis = SystemClock.elapsedRealtime();
+        appsUpdateStats.mUpdateStartTimestampMillis = System.currentTimeMillis();
+        appsUpdateStats.mUpdateType = AppsUpdateStats.FULL_UPDATE;
         // Try to acquire a permit.
         if (!mRunningOrScheduledSemaphore.tryAcquire()) {
             // If there are none available, that means an update is running and we have ALREADY
@@ -185,7 +192,7 @@ public final class AppsIndexerUserInstance {
         // right now.
         executeOnSingleThreadedExecutor(
                 () -> {
-                    doUpdate(firstRun);
+                    doUpdate(firstRun, appsUpdateStats);
                     IndexerMaintenanceService.scheduleUpdateJob(
                             mContext,
                             mContext.getUser(),
@@ -193,6 +200,9 @@ public final class AppsIndexerUserInstance {
                             /* periodic= */ true,
                             /* intervalMillis= */ mAppsIndexerConfig
                                     .getAppsMaintenanceUpdateIntervalMillis());
+                    appsUpdateStats.mTotalLatencyMillis =
+                            SystemClock.elapsedRealtime() - updateLatencyStartTimestampMillis;
+                    logStats(appsUpdateStats);
                 });
     }
 
@@ -202,15 +212,19 @@ public final class AppsIndexerUserInstance {
      * @param firstRun when set to true, that means this was called from onUserUnlocking. If we
      *     didn't have this check, the apps indexer would run every time the phone got unlocked. It
      *     should only run the first time this happens.
+     * @param appsUpdateStats contains stats about the apps indexer update. This method will
+     *     populate the fields of this {@link AppsUpdateStats} structure.
      */
     @VisibleForTesting
-    void doUpdate(boolean firstRun) {
+    @WorkerThread
+    void doUpdate(boolean firstRun, @NonNull AppsUpdateStats appsUpdateStats) {
         try {
+            Objects.requireNonNull(appsUpdateStats);
             // Check if there was a prior run
             if (firstRun && mSettings.getLastUpdateTimestampMillis() != 0) {
                 return;
             }
-            mAppsIndexerImpl.doUpdate(mSettings);
+            mAppsIndexerImpl.doUpdate(mSettings, appsUpdateStats);
             mSettings.persist();
         } catch (IOException e) {
             Log.w(TAG, "Failed to save settings to disk", e);
@@ -283,4 +297,29 @@ public final class AppsIndexerUserInstance {
                     });
         }
     }
+
+    private void logStats(@NonNull AppsUpdateStats appsUpdateStats) {
+        Objects.requireNonNull(appsUpdateStats);
+        int[] updateStatusArr = new int[appsUpdateStats.mUpdateStatusCodes.size()];
+        int updateIdx = 0;
+        for (int updateStatus : appsUpdateStats.mUpdateStatusCodes) {
+            updateStatusArr[updateIdx] = updateStatus;
+            ++updateIdx;
+        }
+        AppSearchStatsLog.write(
+                AppSearchStatsLog.APP_SEARCH_APPS_INDEXER_STATS_REPORTED,
+                appsUpdateStats.mUpdateType,
+                updateStatusArr,
+                appsUpdateStats.mNumberOfAppsAdded,
+                appsUpdateStats.mNumberOfAppsRemoved,
+                appsUpdateStats.mNumberOfAppsUpdated,
+                appsUpdateStats.mNumberOfAppsUnchanged,
+                appsUpdateStats.mTotalLatencyMillis,
+                appsUpdateStats.mPackageManagerLatencyMillis,
+                appsUpdateStats.mAppSearchGetLatencyMillis,
+                appsUpdateStats.mAppSearchSetSchemaLatencyMillis,
+                appsUpdateStats.mAppSearchPutLatencyMillis,
+                appsUpdateStats.mUpdateStartTimestampMillis,
+                appsUpdateStats.mLastAppUpdateTimestampMillis);
+    }
 }
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsUpdateStats.java b/service/java/com/android/server/appsearch/appsindexer/AppsUpdateStats.java
new file mode 100644
index 00000000..661b0a0d
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsUpdateStats.java
@@ -0,0 +1,82 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import android.annotation.IntDef;
+import android.util.ArraySet;
+
+import com.android.server.appsearch.stats.AppSearchStatsLog;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.Set;
+
+public class AppsUpdateStats {
+    @IntDef(
+            value = {
+                UNKNOWN_UPDATE_TYPE,
+                FULL_UPDATE,
+                // TODO(b/275592563): Add package event update types
+            })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface UpdateType {}
+
+    public static final int UNKNOWN_UPDATE_TYPE =
+            AppSearchStatsLog.APP_SEARCH_APPS_INDEXER_STATS_REPORTED__UPDATE_TYPE__UNKNOWN;
+
+    /** Complete update to bring AppSearch in sync with PackageManager. */
+    public static final int FULL_UPDATE =
+            AppSearchStatsLog.APP_SEARCH_APPS_INDEXER_STATS_REPORTED__UPDATE_TYPE__FULL;
+
+    @UpdateType int mUpdateType = UNKNOWN_UPDATE_TYPE;
+
+    // Ok by default, will be set to something else if there is a failure while updating.
+    Set<Integer> mUpdateStatusCodes = new ArraySet<>();
+    int mNumberOfAppsAdded;
+    int mNumberOfAppsRemoved;
+    int mNumberOfAppsUpdated;
+    int mNumberOfAppsUnchanged;
+    long mTotalLatencyMillis;
+    long mPackageManagerLatencyMillis;
+    long mAppSearchGetLatencyMillis;
+    long mAppSearchSetSchemaLatencyMillis;
+    long mAppSearchPutLatencyMillis;
+
+    // Same as in settings
+    long mUpdateStartTimestampMillis;
+    long mLastAppUpdateTimestampMillis;
+
+    /** Resets the Apps Indexer update stats. */
+    public void clear() {
+        mUpdateType = UNKNOWN_UPDATE_TYPE;
+        mUpdateStatusCodes = new ArraySet<>();
+
+        mPackageManagerLatencyMillis = 0;
+        mAppSearchGetLatencyMillis = 0;
+        mAppSearchSetSchemaLatencyMillis = 0;
+        mAppSearchPutLatencyMillis = 0;
+        mTotalLatencyMillis = 0;
+
+        mNumberOfAppsRemoved = 0;
+        mNumberOfAppsAdded = 0;
+        mNumberOfAppsUpdated = 0;
+        mNumberOfAppsUnchanged = 0;
+
+        mLastAppUpdateTimestampMillis = 0;
+        mUpdateStartTimestampMillis = 0;
+    }
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/AppsUtil.java b/service/java/com/android/server/appsearch/appsindexer/AppsUtil.java
index d77a1c7f..13de3ff7 100644
--- a/service/java/com/android/server/appsearch/appsindexer/AppsUtil.java
+++ b/service/java/com/android/server/appsearch/appsindexer/AppsUtil.java
@@ -19,6 +19,9 @@ package com.android.server.appsearch.appsindexer;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.appsearch.util.LogUtil;
+import android.app.usage.UsageEvents;
+import android.app.usage.UsageStatsManager;
+import android.content.ComponentName;
 import android.content.ContentResolver;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
@@ -32,9 +35,9 @@ import android.net.Uri;
 import android.text.TextUtils;
 import android.util.ArrayMap;
 import android.util.Log;
-
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
-
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.util.ArrayList;
@@ -117,71 +120,197 @@ public final class AppsUtil {
     }
 
     /**
-     * Gets {@link PackageInfo}s only for packages that have a launch activity, along with their
-     * corresponding {@link ResolveInfo}. This is useful for building schemas as well as determining
-     * which packages to set schemas for.
+     * Gets {@link PackageInfo}s for packages that have a launch activity or has app functions,
+     * along with their corresponding {@link ResolveInfo}. This is useful for building schemas as
+     * well as determining which packages to set schemas for.
      *
-     * @return a mapping of {@link PackageInfo}s with their corresponding {@link ResolveInfo} for
-     *     the packages launch activity.
+     * @return a mapping of {@link PackageInfo}s with their corresponding {@link ResolveInfos} for
+     *     the packages launch activity and maybe app function resolve info.
      * @see PackageManager#getInstalledPackages
      * @see PackageManager#queryIntentActivities
+     * @see PackageManager#queryIntentServices
      */
     @NonNull
-    public static Map<PackageInfo, ResolveInfo> getLaunchablePackages(
+    public static Map<PackageInfo, ResolveInfos> getPackagesToIndex(
             @NonNull PackageManager packageManager) {
         Objects.requireNonNull(packageManager);
         List<PackageInfo> packageInfos =
                 packageManager.getInstalledPackages(
                         PackageManager.GET_META_DATA | PackageManager.GET_SIGNING_CERTIFICATES);
-        Map<PackageInfo, ResolveInfo> launchablePackages = new ArrayMap<>();
-        Intent intent = new Intent(Intent.ACTION_MAIN, null);
-        intent.addCategory(Intent.CATEGORY_LAUNCHER);
-        intent.setPackage(null);
-        List<ResolveInfo> activities = packageManager.queryIntentActivities(intent, 0);
+
+        Intent launchIntent = new Intent(Intent.ACTION_MAIN, null);
+        launchIntent.addCategory(Intent.CATEGORY_LAUNCHER);
+        launchIntent.setPackage(null);
+        List<ResolveInfo> activities = packageManager.queryIntentActivities(launchIntent, 0);
         Map<String, ResolveInfo> packageNameToLauncher = new ArrayMap<>();
         for (int i = 0; i < activities.size(); i++) {
-            ResolveInfo ri = activities.get(i);
-            packageNameToLauncher.put(ri.activityInfo.packageName, ri);
+            ResolveInfo resolveInfo = activities.get(i);
+            packageNameToLauncher.put(resolveInfo.activityInfo.packageName, resolveInfo);
+        }
+
+        // This is to workaround the android lint check.
+        // AppFunctionService.SERVICE_INTERFACE is defined in API 36 but also it is just a string
+        // literal.
+        Intent appFunctionServiceIntent = new Intent("android.app.appfunctions.AppFunctionService");
+        Map<String, ResolveInfo> packageNameToAppFunctionServiceInfo = new ArrayMap<>();
+        List<ResolveInfo> services =
+                packageManager.queryIntentServices(appFunctionServiceIntent, 0);
+        for (int i = 0; i < services.size(); i++) {
+            ResolveInfo resolveInfo = services.get(i);
+            packageNameToAppFunctionServiceInfo.put(
+                    resolveInfo.serviceInfo.packageName, resolveInfo);
         }
 
+        Map<PackageInfo, ResolveInfos> packagesToIndex = new ArrayMap<>();
         for (int i = 0; i < packageInfos.size(); i++) {
             PackageInfo packageInfo = packageInfos.get(i);
-            ResolveInfo resolveInfo = packageNameToLauncher.get(packageInfo.packageName);
-            if (resolveInfo != null) {
-                // Include the resolve info as we might need it later to build the MobileApplication
-                launchablePackages.put(packageInfo, resolveInfo);
+            ResolveInfos.Builder builder = new ResolveInfos.Builder();
+
+            ResolveInfo launchActivityResolveInfo =
+                    packageNameToLauncher.get(packageInfo.packageName);
+            if (launchActivityResolveInfo != null) {
+                builder.setLaunchActivityResolveInfo(launchActivityResolveInfo);
+            }
+
+            ResolveInfo appFunctionServiceInfo =
+                    packageNameToAppFunctionServiceInfo.get(packageInfo.packageName);
+            if (appFunctionServiceInfo != null) {
+                builder.setAppFunctionServiceResolveInfo(appFunctionServiceInfo);
             }
-        }
 
-        return launchablePackages;
+            if (launchActivityResolveInfo != null || appFunctionServiceInfo != null) {
+                packagesToIndex.put(packageInfo, builder.build());
+            }
+        }
+        return packagesToIndex;
     }
 
     /**
-     * Uses {@link PackageManager} and a Map of {@link PackageInfo}s to {@link ResolveInfo}s to
+     * Uses {@link PackageManager} and a Map of {@link PackageInfo}s to {@link ResolveInfos}s to
      * build AppSearch {@link MobileApplication} documents. Info from both are required to build app
      * documents.
      *
      * @param packageInfos a mapping of {@link PackageInfo}s and their corresponding {@link
-     *     ResolveInfo} for the packages launch activity.
+     *     ResolveInfos} for the packages launch activity.
      */
     @NonNull
     public static List<MobileApplication> buildAppsFromPackageInfos(
             @NonNull PackageManager packageManager,
-            @NonNull Map<PackageInfo, ResolveInfo> packageInfos) {
+            @NonNull Map<PackageInfo, ResolveInfos> packageInfos) {
         Objects.requireNonNull(packageManager);
         Objects.requireNonNull(packageInfos);
 
         List<MobileApplication> mobileApplications = new ArrayList<>();
-        for (Map.Entry<PackageInfo, ResolveInfo> entry : packageInfos.entrySet()) {
+        for (Map.Entry<PackageInfo, ResolveInfos> entry : packageInfos.entrySet()) {
+            ResolveInfo resolveInfo = entry.getValue().getLaunchActivityResolveInfo();
+
             MobileApplication mobileApplication =
-                    createMobileApplication(packageManager, entry.getKey(), entry.getValue());
-            if (mobileApplication != null && !mobileApplication.getDisplayName().isEmpty()) {
+                    createMobileApplication(packageManager, entry.getKey(), resolveInfo);
+            if (mobileApplication != null) {
                 mobileApplications.add(mobileApplication);
             }
         }
         return mobileApplications;
     }
 
+    /**
+     * Uses {@link PackageManager} and a Map of {@link PackageInfo}s to {@link ResolveInfos}s to
+     * build AppSearch {@link AppFunctionStaticMetadata} documents. Info from both are required to
+     * build app documents.
+     *
+     * @param packageInfos a mapping of {@link PackageInfo}s and their corresponding {@link
+     *     ResolveInfo} for the packages launch activity.
+     * @param indexerPackageName the name of the package performing the indexing. This should be the
+     *     same as the package running the apps indexer so that qualified ids are correctly created.
+     * @param maxAppFunctions the max number of app functions to be indexed per package.
+     */
+    public static List<AppFunctionStaticMetadata> buildAppFunctionStaticMetadata(
+            @NonNull PackageManager packageManager,
+            @NonNull Map<PackageInfo, ResolveInfos> packageInfos,
+            @NonNull String indexerPackageName,
+            int maxAppFunctions) {
+        AppFunctionStaticMetadataParser parser =
+                new AppFunctionStaticMetadataParserImpl(indexerPackageName, maxAppFunctions);
+        return buildAppFunctionStaticMetadata(packageManager, packageInfos, parser);
+    }
+
+    /**
+     * Similar to the above {@link #buildAppFunctionStaticMetadata}, but allows the caller to
+     * provide a custom parser. This is for testing purposes.
+     */
+    @VisibleForTesting
+    static List<AppFunctionStaticMetadata> buildAppFunctionStaticMetadata(
+            @NonNull PackageManager packageManager,
+            @NonNull Map<PackageInfo, ResolveInfos> packageInfos,
+            @NonNull AppFunctionStaticMetadataParser parser) {
+        Objects.requireNonNull(packageManager);
+        Objects.requireNonNull(packageInfos);
+        Objects.requireNonNull(parser);
+
+        List<AppFunctionStaticMetadata> appFunctions = new ArrayList<>();
+        for (Map.Entry<PackageInfo, ResolveInfos> entry : packageInfos.entrySet()) {
+            PackageInfo packageInfo = entry.getKey();
+            ResolveInfo resolveInfo = entry.getValue().getAppFunctionServiceInfo();
+            if (resolveInfo == null) {
+                continue;
+            }
+
+            String assetFilePath;
+            try {
+                PackageManager.Property property =
+                        packageManager.getProperty(
+                                "android.app.appfunctions",
+                                new ComponentName(
+                                        resolveInfo.serviceInfo.packageName,
+                                        resolveInfo.serviceInfo.name));
+                assetFilePath = property.getString();
+            } catch (PackageManager.NameNotFoundException e) {
+                Log.w(TAG, "buildAppFunctionMetadataFromPackageInfo: Failed to get property", e);
+                continue;
+            }
+            if (assetFilePath != null) {
+                appFunctions.addAll(
+                        parser.parse(packageManager, packageInfo.packageName, assetFilePath));
+            }
+        }
+        return appFunctions;
+    }
+
+    /**
+     * Gets a map of package name to a list of app open timestamps within a specific time range.
+     *
+     * @param usageStatsManager the {@link UsageStatsManager} to query for app open events.
+     * @param startTime the start time in milliseconds since the epoch.
+     * @param endTime the end time in milliseconds since the epoch.
+     * @return a map of package name to a list of app open timestamps.
+     */
+    @NonNull
+    public static Map<String, List<Long>> getAppOpenTimestamps(
+            @NonNull UsageStatsManager usageStatsManager, long startTime, long endTime) {
+
+        Map<String, List<Long>> appOpenTimestamps = new ArrayMap<>();
+
+        UsageEvents usageEvents = usageStatsManager.queryEvents(startTime, endTime);
+        while (usageEvents.hasNextEvent()) {
+            UsageEvents.Event event = new UsageEvents.Event();
+            usageEvents.getNextEvent(event);
+
+            if (event.getEventType() == UsageEvents.Event.MOVE_TO_FOREGROUND
+                    || event.getEventType() == UsageEvents.Event.ACTIVITY_RESUMED) {
+                String packageName = event.getPackageName();
+
+                List<Long> timestamps = appOpenTimestamps.get(packageName);
+                if (timestamps == null) {
+                    timestamps = new ArrayList<>();
+                    appOpenTimestamps.put(packageName, timestamps);
+                }
+                timestamps.add(event.getTimeStamp());
+            }
+        }
+
+        return appOpenTimestamps;
+    }
+
     /** Gets the SHA-256 certificate from a {@link PackageManager}, or null if it is not found */
     @Nullable
     public static byte[] getCertificate(@NonNull PackageInfo packageInfo) {
@@ -207,7 +336,8 @@ public final class AppsUtil {
     }
 
     /**
-     * Uses PackageManager to supplement packageInfos with an application display name and icon uri.
+     * Uses PackageManager to supplement packageInfos with an application display name and icon uri,
+     * if any.
      *
      * @return a MobileApplication representing the packageInfo, null if finding the signing
      *     certificate fails.
@@ -216,17 +346,9 @@ public final class AppsUtil {
     private static MobileApplication createMobileApplication(
             @NonNull PackageManager packageManager,
             @NonNull PackageInfo packageInfo,
-            @NonNull ResolveInfo resolveInfo) {
+            @Nullable ResolveInfo resolveInfo) {
         Objects.requireNonNull(packageManager);
         Objects.requireNonNull(packageInfo);
-        Objects.requireNonNull(resolveInfo);
-
-        String applicationDisplayName = resolveInfo.loadLabel(packageManager).toString();
-        if (TextUtils.isEmpty(applicationDisplayName)) {
-            applicationDisplayName = packageInfo.applicationInfo.className;
-        }
-
-        String iconUri = getActivityIconUriString(packageManager, resolveInfo.activityInfo);
 
         byte[] certificate = getCertificate(packageInfo);
         if (certificate == null) {
@@ -235,26 +357,31 @@ public final class AppsUtil {
 
         MobileApplication.Builder builder =
                 new MobileApplication.Builder(packageInfo.packageName, certificate)
-                        .setDisplayName(applicationDisplayName)
                         // TODO(b/275592563): Populate with nicknames from various sources
                         .setCreationTimestampMillis(packageInfo.firstInstallTime)
                         .setUpdatedTimestampMs(packageInfo.lastUpdateTime);
 
+        if (resolveInfo == null) {
+            return builder.build();
+        }
+        String applicationDisplayName = resolveInfo.loadLabel(packageManager).toString();
+        if (TextUtils.isEmpty(applicationDisplayName)) {
+            applicationDisplayName = packageInfo.applicationInfo.className;
+        }
+        builder.setDisplayName(applicationDisplayName);
+        String iconUri = getActivityIconUriString(packageManager, resolveInfo.activityInfo);
+        if (iconUri != null) {
+            builder.setIconUri(iconUri);
+        }
         String applicationLabel =
                 packageManager.getApplicationLabel(packageInfo.applicationInfo).toString();
         if (!applicationDisplayName.equals(applicationLabel)) {
             // This can be different from applicationDisplayName, and should be indexed
             builder.setAlternateNames(applicationLabel);
         }
-
-        if (iconUri != null) {
-            builder.setIconUri(iconUri);
-        }
-
         if (resolveInfo.activityInfo.name != null) {
             builder.setClassName(resolveInfo.activityInfo.name);
         }
         return builder.build();
     }
 }
-
diff --git a/service/java/com/android/server/appsearch/appsindexer/FrameworkAppsIndexerConfig.java b/service/java/com/android/server/appsearch/appsindexer/FrameworkAppsIndexerConfig.java
index d7c0b98d..d3c60c15 100644
--- a/service/java/com/android/server/appsearch/appsindexer/FrameworkAppsIndexerConfig.java
+++ b/service/java/com/android/server/appsearch/appsindexer/FrameworkAppsIndexerConfig.java
@@ -30,6 +30,7 @@ import android.provider.DeviceConfig;
 public class FrameworkAppsIndexerConfig implements AppsIndexerConfig {
     static final String KEY_APPS_INDEXER_ENABLED = "apps_indexer_enabled";
     static final String KEY_APPS_UPDATE_INTERVAL_MILLIS = "apps_update_interval_millis";
+    static final String KEY_MAX_APP_FUNCTIONS_PER_PACKAGE = "max_app_functions_per_package";
 
     @Override
     public boolean isAppsIndexerEnabled() {
@@ -46,5 +47,13 @@ public class FrameworkAppsIndexerConfig implements AppsIndexerConfig {
                 KEY_APPS_UPDATE_INTERVAL_MILLIS,
                 DEFAULT_APPS_UPDATE_INTERVAL_MILLIS);
     }
+
+    @Override
+    public int getMaxAppFunctionsPerPackage() {
+        return DeviceConfig.getInt(
+                DeviceConfig.NAMESPACE_APPSEARCH,
+                KEY_MAX_APP_FUNCTIONS_PER_PACKAGE,
+                DEFAULT_MAX_APP_FUNCTIONS_PER_PACKAGE);
+    }
 }
 
diff --git a/service/java/com/android/server/appsearch/appsindexer/ResolveInfos.java b/service/java/com/android/server/appsearch/appsindexer/ResolveInfos.java
new file mode 100644
index 00000000..a8cc7bcd
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/ResolveInfos.java
@@ -0,0 +1,83 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.content.pm.ResolveInfo;
+
+import java.util.Objects;
+
+/**
+ * Contains information about components in a package that will be indexed by the app indexer.
+ *
+ * @hide
+ */
+public class ResolveInfos {
+    @Nullable private ResolveInfo mAppFunctionServiceInfo;
+    @Nullable private ResolveInfo mLaunchActivityResolveInfo;
+
+    public ResolveInfos(
+            @Nullable ResolveInfo appFunctionServiceInfo,
+            @Nullable ResolveInfo launchActivityResolveInfo) {
+        mAppFunctionServiceInfo = appFunctionServiceInfo;
+        mLaunchActivityResolveInfo = launchActivityResolveInfo;
+    }
+
+    /**
+     * Return {@link ResolveInfo} for the packages AppFunction service. If {@code null}, it means
+     * this app doesn't have an app function service.
+     */
+    @Nullable
+    public ResolveInfo getAppFunctionServiceInfo() {
+        return mAppFunctionServiceInfo;
+    }
+
+    /**
+     * Return {@link ResolveInfo} for the packages launch activity. If {@code null}, it means this
+     * app doesn't have a launch activity.
+     */
+    @Nullable
+    public ResolveInfo getLaunchActivityResolveInfo() {
+        return mLaunchActivityResolveInfo;
+    }
+
+    public static class Builder {
+        @Nullable private ResolveInfo mAppFunctionServiceInfo;
+        @Nullable private ResolveInfo mLaunchActivityResolveInfo;
+
+        /** Sets the {@link ResolveInfo} for the packages AppFunction service */
+        @NonNull
+        public Builder setAppFunctionServiceResolveInfo(@NonNull ResolveInfo resolveInfo) {
+            mAppFunctionServiceInfo = Objects.requireNonNull(resolveInfo);
+            return this;
+        }
+
+        /** Sets the {@link ResolveInfo} for the packages launch activity. */
+        @NonNull
+        public Builder setLaunchActivityResolveInfo(@NonNull ResolveInfo resolveInfo) {
+            mLaunchActivityResolveInfo = Objects.requireNonNull(resolveInfo);
+            return this;
+        }
+
+        /** Builds the {@link ResolveInfos} object. */
+        @NonNull
+        public ResolveInfos build() {
+            return new ResolveInfos(mAppFunctionServiceInfo, mLaunchActivityResolveInfo);
+        }
+    }
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchBase.java b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchBase.java
index 2c38d7d7..1d00e59f 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchBase.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchBase.java
@@ -17,6 +17,7 @@ package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchResult;
 import android.app.appsearch.BatchResultCallback;
@@ -28,21 +29,29 @@ import java.util.concurrent.ExecutionException;
 import java.util.concurrent.Executor;
 import java.util.function.Consumer;
 
-/** Contains common methods for converting async methods to sync */
+/** Contains common methods for converting async methods to sync. */
 public class SyncAppSearchBase {
+    protected final Object mSessionLock = new Object();
     protected final Executor mExecutor;
 
     public SyncAppSearchBase(@NonNull Executor executor) {
         mExecutor = Objects.requireNonNull(executor);
     }
 
+    @WorkerThread
     protected <T> T executeAppSearchResultOperation(
             Consumer<Consumer<AppSearchResult<T>>> operation) throws AppSearchException {
         final CompletableFuture<AppSearchResult<T>> futureResult = new CompletableFuture<>();
 
+        // Without this catch + completeExceptionally, this crashes the device if the operation
+        // throws an error.
         mExecutor.execute(
                 () -> {
-                    operation.accept(futureResult::complete);
+                    try {
+                        operation.accept(futureResult::complete);
+                    } catch (Exception e) {
+                        futureResult.completeExceptionally(e);
+                    }
                 });
 
         try {
@@ -66,13 +75,15 @@ public class SyncAppSearchBase {
         }
     }
 
+    @WorkerThread
     protected <T, V> AppSearchBatchResult<T, V> executeAppSearchBatchResultOperation(
             Consumer<BatchResultCallback<T, V>> operation) throws AppSearchException {
         final CompletableFuture<AppSearchBatchResult<T, V>> futureResult =
                 new CompletableFuture<>();
 
         mExecutor.execute(
-                () ->
+                () -> {
+                    try {
                         operation.accept(
                                 new BatchResultCallback<>() {
                                     @Override
@@ -85,7 +96,11 @@ public class SyncAppSearchBase {
                                     public void onSystemError(@Nullable Throwable throwable) {
                                         futureResult.completeExceptionally(throwable);
                                     }
-                                }));
+                                });
+                    } catch (Exception e) {
+                        futureResult.completeExceptionally(e);
+                    }
+                });
 
         try {
             // TODO(b/275592563): Change to get timeout value from config
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSession.java b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSession.java
index 38e649d6..76368191 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSession.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSession.java
@@ -16,10 +16,12 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchSchema;
 import android.app.appsearch.AppSearchSession;
 import android.app.appsearch.PutDocumentsRequest;
+import android.app.appsearch.RemoveByDocumentIdRequest;
 import android.app.appsearch.SearchResults;
 import android.app.appsearch.SearchSpec;
 import android.app.appsearch.SetSchemaRequest;
@@ -32,8 +34,11 @@ import java.io.Closeable;
  * A synchronous wrapper around {@link AppSearchSession}. This allows us to perform operations in
  * AppSearch without needing to handle async calls.
  *
+ * <p>Note that calling the methods in this class will park the calling thread.
+ *
  * @see AppSearchSession
  */
+// TODO(b/275592563): Sort methods so that they match the order in AppSearchSession
 public interface SyncAppSearchSession extends Closeable {
     /**
      * Synchronously sets an {@link AppSearchSchema}.
@@ -41,6 +46,7 @@ public interface SyncAppSearchSession extends Closeable {
      * @see AppSearchSession#setSchema
      */
     @NonNull
+    @WorkerThread
     SetSchemaResponse setSchema(@NonNull SetSchemaRequest setSchemaRequest)
             throws AppSearchException;
 
@@ -50,9 +56,30 @@ public interface SyncAppSearchSession extends Closeable {
      * @see AppSearchSession#put
      */
     @NonNull
+    @WorkerThread
     AppSearchBatchResult<String, Void> put(@NonNull PutDocumentsRequest request)
             throws AppSearchException;
 
+    /**
+     * Synchronously removes documents from AppSearch using a query and {@link SearchSpec}.
+     *
+     * @see AppSearchSession#remove
+     */
+    @NonNull
+    @WorkerThread
+    Void remove(@NonNull String queryExpression, @NonNull SearchSpec searchSpec)
+            throws AppSearchException;
+
+    /**
+     * Synchronously removes documents from AppSearch using a list of document IDs.
+     *
+     * @see AppSearchSession#remove
+     */
+    @NonNull
+    @WorkerThread
+    AppSearchBatchResult<String, Void> remove(@NonNull RemoveByDocumentIdRequest request)
+            throws AppSearchException;
+
     /**
      * Returns a synchronous version of {@link SearchResults}.
      *
@@ -62,7 +89,9 @@ public interface SyncAppSearchSession extends Closeable {
      * @see AppSearchSession#search
      */
     @NonNull
-    SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec);
+    @WorkerThread
+    SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec)
+            throws AppSearchException;
 
     /**
      * Closes the session.
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSessionImpl.java b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSessionImpl.java
index 458da022..bb9e2c49 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSessionImpl.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncAppSearchSessionImpl.java
@@ -16,71 +16,151 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchManager;
 import android.app.appsearch.AppSearchSession;
 import android.app.appsearch.PutDocumentsRequest;
+import android.app.appsearch.RemoveByDocumentIdRequest;
 import android.app.appsearch.SearchSpec;
 import android.app.appsearch.SetSchemaRequest;
 import android.app.appsearch.SetSchemaResponse;
 import android.app.appsearch.exceptions.AppSearchException;
 
+import com.android.internal.annotations.GuardedBy;
+
 import java.util.Objects;
 import java.util.concurrent.Executor;
 
-/** SyncAppSearchSessionImpl methods are a super set of SyncGlobalSearchSessionImpl methods. */
 public class SyncAppSearchSessionImpl extends SyncAppSearchBase implements SyncAppSearchSession {
-    private final AppSearchSession mSession;
+    @GuardedBy("mSessionLock")
+    private volatile AppSearchSession mSession;
+
+    private final AppSearchManager.SearchContext mSearchContext;
+    private final AppSearchManager mAppSearchManager;
 
     public SyncAppSearchSessionImpl(
             @NonNull AppSearchManager appSearchManager,
             @NonNull AppSearchManager.SearchContext searchContext,
-            @NonNull Executor executor)
-            throws AppSearchException {
-        super(executor);
-        Objects.requireNonNull(appSearchManager);
-        Objects.requireNonNull(searchContext);
-        Objects.requireNonNull(executor);
-        mSession =
-                executeAppSearchResultOperation(
-                        resultHandler ->
-                                appSearchManager.createSearchSession(
-                                        searchContext, executor, resultHandler));
+            @NonNull Executor executor) {
+        super(Objects.requireNonNull(executor));
+        mAppSearchManager = Objects.requireNonNull(appSearchManager);
+        mSearchContext = Objects.requireNonNull(searchContext);
+    }
+
+    /**
+     * Initializes the {@link AppSearchSession}. Only one AppSearchSession will be created per
+     * {@link SyncAppSearchSessionImpl}.
+     *
+     * @throws AppSearchException if unable to initialize the {@link AppSearchSession}.
+     */
+    @WorkerThread
+    private void ensureSessionInitializedLocked() throws AppSearchException {
+        synchronized (mSessionLock) {
+            if (mSession != null) {
+                return;
+            }
+            mSession =
+                    executeAppSearchResultOperation(
+                            resultHandler ->
+                                    mAppSearchManager.createSearchSession(
+                                            mSearchContext, mExecutor, resultHandler));
+        }
     }
 
-    // Not actually asynchronous but added for convenience
+    /**
+     * Searches with a query and {@link SearchSpec}. Initializes the {@link AppSearchSession} if it
+     * hasn't been initialized already.
+     */
     @Override
     @NonNull
-    public SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec) {
+    public SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec)
+            throws AppSearchException {
         Objects.requireNonNull(query);
         Objects.requireNonNull(searchSpec);
+        ensureSessionInitializedLocked();
         return new SyncSearchResultsImpl(mSession.search(query, searchSpec), mExecutor);
     }
 
+    /**
+     * Sets schemas into AppSearch. Initializes the {@link AppSearchSession} if it hasn't been
+     * initialized already.
+     */
     @Override
     @NonNull
+    @WorkerThread
     public SetSchemaResponse setSchema(@NonNull SetSchemaRequest setSchemaRequest)
             throws AppSearchException {
         Objects.requireNonNull(setSchemaRequest);
+        ensureSessionInitializedLocked();
         return executeAppSearchResultOperation(
                 resultHandler ->
                         mSession.setSchema(setSchemaRequest, mExecutor, mExecutor, resultHandler));
     }
 
-    // Put involves an AppSearchBatchResult, so it can't be simplified through
-    // executeAppSearchResultOperation. Instead we use executeAppSearchBatchResultOperation.
+    /**
+     * Puts documents into AppSearch. Initializes the {@link AppSearchSession} if it hasn't been
+     * initialized already.
+     */
     @Override
     @NonNull
+    @WorkerThread
     public AppSearchBatchResult<String, Void> put(@NonNull PutDocumentsRequest request)
             throws AppSearchException {
         Objects.requireNonNull(request);
+        ensureSessionInitializedLocked();
+        // Put involves an AppSearchBatchResult, so it can't be simplified through
+        // executeAppSearchResultOperation. Instead we use executeAppSearchBatchResultOperation.
         return executeAppSearchBatchResultOperation(
                 resultHandler -> mSession.put(request, mExecutor, resultHandler));
     }
 
-    // Also not asynchronous but it's necessary to be able to close the session
+    /**
+     * Removes documents from AppSearch. Initializes the {@link AppSearchSession} if it hasn't been
+     * initialized already.
+     */
+    @Override
+    @NonNull
+    @WorkerThread
+    public Void remove(@NonNull String queryExpression, @NonNull SearchSpec searchSpec)
+            throws AppSearchException {
+        Objects.requireNonNull(queryExpression);
+        Objects.requireNonNull(searchSpec);
+        ensureSessionInitializedLocked();
+        return executeAppSearchResultOperation(
+                resultHandler -> {
+                    synchronized (mSessionLock) {
+                        mSession.remove(queryExpression, searchSpec, mExecutor, resultHandler);
+                    }
+                });
+    }
+
+    /**
+     * Removes documents from AppSearch using a list of ids. Initializes the {@link
+     * AppSearchSession} if it hasn't been initialized already.
+     */
+    @Override
+    @NonNull
+    @WorkerThread
+    public AppSearchBatchResult<String, Void> remove(@NonNull RemoveByDocumentIdRequest request)
+            throws AppSearchException {
+        Objects.requireNonNull(request);
+        ensureSessionInitializedLocked();
+        return executeAppSearchBatchResultOperation(
+                resultHandler -> {
+                    synchronized (mSessionLock) {
+                        mSession.remove(request, mExecutor, resultHandler);
+                    }
+                });
+    }
+
+    // Not asynchronous but it's necessary to be able to close the session
     @Override
     public void close() {
-        mSession.close();
+        synchronized (mSessionLock) {
+            if (mSession != null) {
+                mSession.close();
+            }
+        }
     }
 }
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSession.java b/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSession.java
index ca194179..639e7bc6 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSession.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSession.java
@@ -16,9 +16,11 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.GlobalSearchSession;
 import android.app.appsearch.SearchResults;
 import android.app.appsearch.SearchSpec;
+import android.app.appsearch.exceptions.AppSearchException;
 
 import java.io.Closeable;
 
@@ -26,6 +28,10 @@ import java.io.Closeable;
  * A synchronous wrapper around {@link GlobalSearchSession}. This allows us to call globalSearch
  * synchronously.
  *
+ * <p>Note that while calling the methods in this class will park the calling thread, and only one
+ * {@link GlobalSearchSession} wil be created, multiple threads may call {@link #search} at the same
+ * time. It is up to the caller of this class to ensure this does not cause issues.
+ *
  * @see GlobalSearchSession
  */
 public interface SyncGlobalSearchSession extends Closeable {
@@ -38,7 +44,9 @@ public interface SyncGlobalSearchSession extends Closeable {
      * @see GlobalSearchSession#search
      */
     @NonNull
-    SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec);
+    @WorkerThread
+    SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec)
+            throws AppSearchException;
 
     /**
      * Closes the global session.
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSessionImpl.java b/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSessionImpl.java
index 8021cef0..5c73aea9 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSessionImpl.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncGlobalSearchSessionImpl.java
@@ -16,45 +16,74 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchManager;
 import android.app.appsearch.GlobalSearchSession;
 import android.app.appsearch.SearchSpec;
 import android.app.appsearch.exceptions.AppSearchException;
 
+import com.android.internal.annotations.GuardedBy;
+
 import java.util.Objects;
 import java.util.concurrent.Executor;
 
 public class SyncGlobalSearchSessionImpl extends SyncAppSearchBase
         implements SyncGlobalSearchSession {
 
-    private final GlobalSearchSession mGlobalSession;
+    @GuardedBy("mSessionLock")
+    private volatile GlobalSearchSession mGlobalSession;
+
+    private final AppSearchManager mAppSearchManager;
 
     public SyncGlobalSearchSessionImpl(
-            @NonNull AppSearchManager appSearchManager, @NonNull Executor executor)
-            throws AppSearchException {
-        super(executor);
-        Objects.requireNonNull(appSearchManager);
-        Objects.requireNonNull(executor);
-
-        mGlobalSession =
-                executeAppSearchResultOperation(
-                        resultHandler ->
-                                appSearchManager.createGlobalSearchSession(
-                                        executor, resultHandler));
+            @NonNull AppSearchManager appSearchManager, @NonNull Executor executor) {
+        super(Objects.requireNonNull(executor));
+        mAppSearchManager = Objects.requireNonNull(appSearchManager);
     }
 
-    // Not actually asynchronous but added for convenience
+    /**
+     * Sets up the {@link GlobalSearchSession}.
+     *
+     * @throws AppSearchException if unable to initialize the {@link GlobalSearchSession}.
+     */
+    @WorkerThread
+    private void ensureSessionInitializedLocked() throws AppSearchException {
+        synchronized (mSessionLock) {
+            if (mGlobalSession != null) {
+                return;
+            }
+            // It is best to initialize search sessions in a different thread from the thread that
+            // calls onUserUnlock, which calls the constructor.
+            mGlobalSession =
+                    executeAppSearchResultOperation(
+                            resultHandler ->
+                                    mAppSearchManager.createGlobalSearchSession(
+                                            mExecutor, resultHandler));
+        }
+    }
+
+    /**
+     * Searches with a query and {@link SearchSpec}. Initializes the {@link GlobalSearchSession} if
+     * it hasn't been initialized already.
+     */
     @Override
     @NonNull
-    public SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec) {
+    @WorkerThread
+    public SyncSearchResults search(@NonNull String query, @NonNull SearchSpec searchSpec)
+            throws AppSearchException {
         Objects.requireNonNull(query);
         Objects.requireNonNull(searchSpec);
+        ensureSessionInitializedLocked();
         return new SyncSearchResultsImpl(mGlobalSession.search(query, searchSpec), mExecutor);
     }
 
-    // Also not asynchronous but it's necessary to be able to close the session
+    // Not an asynchronous call but it's necessary to be able to close the session
     @Override
     public void close() {
-        mGlobalSession.close();
+        synchronized (mSessionLock) {
+            if (mGlobalSession != null) {
+                mGlobalSession.close();
+            }
+        }
     }
 }
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncSearchResults.java b/service/java/com/android/server/appsearch/appsindexer/SyncSearchResults.java
index db26ef38..dc74ca60 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncSearchResults.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncSearchResults.java
@@ -16,6 +16,7 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.SearchResult;
 import android.app.appsearch.SearchResults;
 import android.app.appsearch.exceptions.AppSearchException;
@@ -35,5 +36,6 @@ public interface SyncSearchResults {
      * @see SearchResults#getNextPage
      */
     @NonNull
+    @WorkerThread
     List<SearchResult> getNextPage() throws AppSearchException;
 }
diff --git a/service/java/com/android/server/appsearch/appsindexer/SyncSearchResultsImpl.java b/service/java/com/android/server/appsearch/appsindexer/SyncSearchResultsImpl.java
index 6af2efd4..84242ec2 100644
--- a/service/java/com/android/server/appsearch/appsindexer/SyncSearchResultsImpl.java
+++ b/service/java/com/android/server/appsearch/appsindexer/SyncSearchResultsImpl.java
@@ -16,6 +16,7 @@
 package com.android.server.appsearch.appsindexer;
 
 import android.annotation.NonNull;
+import android.annotation.WorkerThread;
 import android.app.appsearch.SearchResult;
 import android.app.appsearch.SearchResults;
 import android.app.appsearch.exceptions.AppSearchException;
@@ -34,6 +35,7 @@ public class SyncSearchResultsImpl extends SyncAppSearchBase implements SyncSear
 
     @NonNull
     @Override
+    @WorkerThread
     public List<SearchResult> getNextPage() throws AppSearchException {
         return executeAppSearchResultOperation(
                 resultHandler -> mSearchResults.getNextPage(mExecutor, resultHandler));
diff --git a/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadata.java b/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadata.java
new file mode 100644
index 00000000..128a055f
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadata.java
@@ -0,0 +1,346 @@
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
+package com.android.server.appsearch.appsindexer.appsearchtypes;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.StringRes;
+import android.app.appsearch.AppSearchSchema;
+import android.app.appsearch.GenericDocument;
+import android.app.appsearch.util.DocumentIdUtil;
+import android.os.Build;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.appsindexer.AppSearchHelper;
+
+import java.util.Objects;
+
+/**
+ * Represents static function metadata of an app function.
+ *
+ * <p>This is a temporary solution for app function indexing, as later we would like to index the
+ * actual function signature entity class shape instead of just the schema info.
+ */
+// TODO(b/357551503): Link to canonical docs rather than duplicating once they
+// are available.
+public class AppFunctionStaticMetadata extends GenericDocument {
+    private static final String TAG = "AppSearchAppFunction";
+
+    public static final String SCHEMA_TYPE = "AppFunctionStaticMetadata";
+
+    public static final String APP_FUNCTION_NAMESPACE = "app_functions";
+    public static final String PROPERTY_FUNCTION_ID = "functionId";
+    public static final String PROPERTY_PACKAGE_NAME = "packageName";
+    public static final String PROPERTY_SCHEMA_NAME = "schemaName";
+    public static final String PROPERTY_SCHEMA_VERSION = "schemaVersion";
+    public static final String PROPERTY_SCHEMA_CATEGORY = "schemaCategory";
+    public static final String PROPERTY_DISPLAY_NAME_STRING_RES = "displayNameStringRes";
+    public static final String PROPERTY_ENABLED_BY_DEFAULT = "enabledByDefault";
+    public static final String PROPERTY_RESTRICT_CALLERS_WITH_EXECUTE_APP_FUNCTIONS =
+            "restrictCallersWithExecuteAppFunctions";
+    public static final String PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID =
+            "mobileApplicationQualifiedId";
+    public static final AppSearchSchema PARENT_TYPE_APPSEARCH_SCHEMA =
+            createAppFunctionSchemaForPackage(/* packageName= */ null);
+
+    /** Returns a per-app schema name, to store all functions for that package. */
+    public static String getSchemaNameForPackage(@NonNull String pkg) {
+        return SCHEMA_TYPE + "-" + Objects.requireNonNull(pkg);
+    }
+
+    /**
+     * Different packages have different visibility requirements. To allow for different visibility,
+     * we need to have per-package app function schemas.
+     *
+     * @param packageName The package name to create a schema for. Will create the base schema if it
+     *     is null.
+     */
+    @NonNull
+    public static AppSearchSchema createAppFunctionSchemaForPackage(@Nullable String packageName) {
+        AppSearchSchema.Builder builder =
+                new AppSearchSchema.Builder(
+                        (packageName == null) ? SCHEMA_TYPE : getSchemaNameForPackage(packageName));
+        if (shouldSetParentType() && packageName != null) {
+            // This is a child schema, setting the parent type.
+            builder.addParentType(SCHEMA_TYPE);
+        }
+        return builder.addProperty(
+                        new AppSearchSchema.StringPropertyConfig.Builder(PROPERTY_FUNCTION_ID)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setIndexingType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .INDEXING_TYPE_EXACT_TERMS)
+                                .setTokenizerType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .TOKENIZER_TYPE_VERBATIM)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.StringPropertyConfig.Builder(PROPERTY_PACKAGE_NAME)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setIndexingType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .INDEXING_TYPE_EXACT_TERMS)
+                                .setTokenizerType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .TOKENIZER_TYPE_VERBATIM)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.StringPropertyConfig.Builder(PROPERTY_SCHEMA_NAME)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setIndexingType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .INDEXING_TYPE_EXACT_TERMS)
+                                .setTokenizerType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .TOKENIZER_TYPE_VERBATIM)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.LongPropertyConfig.Builder(PROPERTY_SCHEMA_VERSION)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setIndexingType(
+                                        AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_RANGE)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.StringPropertyConfig.Builder(PROPERTY_SCHEMA_CATEGORY)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setIndexingType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .INDEXING_TYPE_EXACT_TERMS)
+                                .setTokenizerType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .TOKENIZER_TYPE_VERBATIM)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.BooleanPropertyConfig.Builder(
+                                        PROPERTY_ENABLED_BY_DEFAULT)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.BooleanPropertyConfig.Builder(
+                                        PROPERTY_RESTRICT_CALLERS_WITH_EXECUTE_APP_FUNCTIONS)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.LongPropertyConfig.Builder(
+                                        PROPERTY_DISPLAY_NAME_STRING_RES)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .build())
+                .addProperty(
+                        new AppSearchSchema.StringPropertyConfig.Builder(
+                                        PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID)
+                                .setCardinality(AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                .setJoinableValueType(
+                                        AppSearchSchema.StringPropertyConfig
+                                                .JOINABLE_VALUE_TYPE_QUALIFIED_ID)
+                                .build())
+                .build();
+    }
+
+    public AppFunctionStaticMetadata(@NonNull GenericDocument genericDocument) {
+        super(genericDocument);
+    }
+
+    /** Returns the function id. This might look like "com.example.message#send_message". */
+    @NonNull
+    public String getFunctionId() {
+        return Objects.requireNonNull(getPropertyString(PROPERTY_FUNCTION_ID));
+    }
+
+    /** Returns the package name of the package that owns this function. */
+    @NonNull
+    public String getPackageName() {
+        return Objects.requireNonNull(getPropertyString(PROPERTY_PACKAGE_NAME));
+    }
+
+    /**
+     * Returns the schema name of the schema acted on by this function. This might look like
+     * "send_message". The schema name should correspond to a schema defined in the canonical
+     * source.
+     */
+    @Nullable
+    public String getSchemaName() {
+        return getPropertyString(PROPERTY_SCHEMA_NAME);
+    }
+
+    /**
+     * Returns the schema version of the schema acted on by this function. The schema version should
+     * correspond to a schema defined in the canonical source.
+     */
+    public long getSchemaVersion() {
+        return getPropertyLong(PROPERTY_SCHEMA_VERSION);
+    }
+
+    /**
+     * Returns the category of the schema. This allows for logical grouping of schemas. For
+     * instance, all schemas related to email functionality would be categorized as 'email'.
+     */
+    @Nullable
+    public String getSchemaCategory() {
+        return getPropertyString(PROPERTY_SCHEMA_CATEGORY);
+    }
+
+    /**
+     * Returns if the function is enabled by default or not. Apps can override the enabled status in
+     * runtime. The default value is true.
+     */
+    // TODO(b/357551503): Mention the API to flip the enabled status in runtime.
+    public boolean getEnabledByDefault() {
+        return getPropertyBoolean(PROPERTY_ENABLED_BY_DEFAULT);
+    }
+
+    /**
+     * Returns a boolean indicating whether or not to restrict the callers with only the
+     * EXECUTE_APP_FUNCTIONS permission.
+     *
+     * <p>If true, callers with the EXECUTE_APP_FUNCTIONS permission cannot call this function. If
+     * false, callers with the EXECUTE_APP_FUNCTIONS permission can call this function. Note that
+     * callers with the EXECUTE_APP_FUNCTIONS_TRUSTED permission can always call this function. If
+     * not set, the default value is false.
+     */
+    public boolean getRestrictCallersWithExecuteAppFunctions() {
+        return getPropertyBoolean(PROPERTY_RESTRICT_CALLERS_WITH_EXECUTE_APP_FUNCTIONS);
+    }
+
+    /** Returns the display name of this function as a string resource. */
+    @StringRes
+    public int getDisplayNameStringRes() {
+        return (int) getPropertyLong(PROPERTY_DISPLAY_NAME_STRING_RES);
+    }
+
+    /** Returns the qualified id linking to the Apps Indexer document. */
+    @Nullable
+    @VisibleForTesting
+    public String getMobileApplicationQualifiedId() {
+        return getPropertyString(PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID);
+    }
+
+    /** Whether a parent type should be set for {@link AppFunctionStaticMetadata}. */
+    public static boolean shouldSetParentType() {
+        // addParentTypes() is also available on T Extensions 10+. However, we only need it to work
+        // on V+ devices because that is where AppFunctionManager will be available anyway. So,
+        // we're just checking for V+ here to keep it simple.
+        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM;
+    }
+
+    public static final class Builder extends GenericDocument.Builder<Builder> {
+        /**
+         * Creates a Builder for a {@link AppFunctionStaticMetadata}.
+         *
+         * @param packageName the name of the package that owns the function.
+         * @param functionId the id of the function.
+         * @param indexerPackageName the name of the package performing the indexing. This should be
+         *     the same as the package running the apps indexer so that qualified ids are correctly
+         *     created.
+         */
+        public Builder(
+                @NonNull String packageName,
+                @NonNull String functionId,
+                @NonNull String indexerPackageName) {
+            super(
+                    APP_FUNCTION_NAMESPACE,
+                    Objects.requireNonNull(packageName) + "/" + Objects.requireNonNull(functionId),
+                    getSchemaNameForPackage(packageName));
+            setPropertyString(PROPERTY_FUNCTION_ID, functionId);
+            setPropertyString(PROPERTY_PACKAGE_NAME, packageName);
+
+            // Default values of properties.
+            setPropertyBoolean(PROPERTY_ENABLED_BY_DEFAULT, true);
+
+            // Set qualified id automatically
+            setPropertyString(
+                    PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID,
+                    DocumentIdUtil.createQualifiedId(
+                            indexerPackageName,
+                            AppSearchHelper.APP_DATABASE,
+                            MobileApplication.APPS_NAMESPACE,
+                            packageName));
+        }
+
+        /**
+         * Sets the name of the schema the function uses. The schema name should correspond to a
+         * schema defined in the canonical source.
+         */
+        @NonNull
+        public Builder setSchemaName(@NonNull String schemaName) {
+            setPropertyString(PROPERTY_SCHEMA_NAME, schemaName);
+            return this;
+        }
+
+        /**
+         * Sets the version of the schema the function uses. The schema version should correspond to
+         * a schema defined in the canonical source.
+         */
+        @NonNull
+        public Builder setSchemaVersion(long schemaVersion) {
+            setPropertyLong(PROPERTY_SCHEMA_VERSION, schemaVersion);
+            return this;
+        }
+
+        /**
+         * Specifies the category of the schema used by this function. This allows for logical
+         * grouping of schemas. For instance, all schemas related to email functionality would be
+         * categorized as 'email'.
+         */
+        @NonNull
+        public Builder setSchemaCategory(@NonNull String category) {
+            setPropertyString(PROPERTY_SCHEMA_CATEGORY, category);
+            return this;
+        }
+
+        /** Sets the display name as a string resource of this function. */
+        @NonNull
+        public Builder setDisplayNameStringRes(@StringRes int displayName) {
+            setPropertyLong(PROPERTY_DISPLAY_NAME_STRING_RES, displayName);
+            return this;
+        }
+
+        /**
+         * Sets an indicator specifying if the function is enabled by default or not. Apps can
+         * override the enabled status in runtime. The default value is true.
+         */
+        // TODO(b/357551503): Mention the API to flip the enabled status in runtime.
+        @NonNull
+        public Builder setEnabledByDefault(boolean enabled) {
+            setPropertyBoolean(PROPERTY_ENABLED_BY_DEFAULT, enabled);
+            return this;
+        }
+
+        /**
+         * Sets whether this app function restricts the callers with only the EXECUTE_APP_FUNCTIONS
+         * permission.
+         *
+         * <p>If true, callers with the EXECUTE_APP_FUNCTIONS permission cannot call this function.
+         * If false, callers with the EXECUTE_APP_FUNCTIONS permission can call this function. Note
+         * that callers with the EXECUTE_APP_FUNCTIONS_TRUSTED permission can always call this
+         * function. If not set, the default value is false.
+         */
+        @NonNull
+        public Builder setRestrictCallersWithExecuteAppFunctions(
+                boolean restrictCallersWithExecuteAppFunctions) {
+            setPropertyBoolean(
+                    PROPERTY_RESTRICT_CALLERS_WITH_EXECUTE_APP_FUNCTIONS,
+                    restrictCallersWithExecuteAppFunctions);
+            return this;
+        }
+
+        /** Creates the {@link AppFunctionStaticMetadata} GenericDocument. */
+        @NonNull
+        public AppFunctionStaticMetadata build() {
+            return new AppFunctionStaticMetadata(super.build());
+        }
+    }
+}
diff --git a/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppOpenEvent.java b/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppOpenEvent.java
new file mode 100644
index 00000000..3c0b4117
--- /dev/null
+++ b/service/java/com/android/server/appsearch/appsindexer/appsearchtypes/AppOpenEvent.java
@@ -0,0 +1,166 @@
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
+package com.android.server.appsearch.appsindexer.appsearchtypes;
+
+import android.app.appsearch.annotation.CanIgnoreReturnValue;
+import android.annotation.CurrentTimeMillisLong;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.app.appsearch.AppSearchSchema;
+import android.app.appsearch.GenericDocument;
+import android.net.Uri;
+
+import com.android.internal.annotations.VisibleForTesting;
+
+import java.util.Objects;
+
+/**
+ * Represents an app open event in AppSearch. App open events track when a user opens an application
+ * and stores relevant information like package name and timestamp.
+ *
+ * @hide
+ */
+public class AppOpenEvent extends GenericDocument {
+    // Properties
+    private static final String SCHEMA_TYPE = "builtin:AppOpenEvent";
+
+    private static final String APP_OPEN_EVENT_NAMESPACE = "app-open-event";
+
+    private static final String APP_OPEN_EVENT_PROPERTY_PACKAGE_NAME = "packageName";
+    private static final String APP_OPEN_EVENT_PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID =
+            "mobileApplicationQualifiedId"; // Joins to MobileApplication
+    private static final String APP_OPEN_EVENT_PROPERTY_APP_OPEN_TIMESTAMP_MILLIS =
+            "appOpenTimestampMillis";
+
+    // Schema
+    public static final AppSearchSchema SCHEMA =
+            new AppSearchSchema.Builder(SCHEMA_TYPE)
+                    .addProperty(
+                            new AppSearchSchema.StringPropertyConfig.Builder(
+                                            APP_OPEN_EVENT_PROPERTY_PACKAGE_NAME)
+                                    .setCardinality(
+                                            AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                    .setIndexingType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .INDEXING_TYPE_PREFIXES)
+                                    .setTokenizerType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .TOKENIZER_TYPE_PLAIN)
+                                    .build())
+                    .addProperty(
+                            new AppSearchSchema.StringPropertyConfig.Builder(
+                                            APP_OPEN_EVENT_PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID)
+                                    .setJoinableValueType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .JOINABLE_VALUE_TYPE_QUALIFIED_ID)
+                                    .setCardinality(
+                                            AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                    .build())
+                    .addProperty(
+                            new AppSearchSchema.LongPropertyConfig.Builder(
+                                            APP_OPEN_EVENT_PROPERTY_APP_OPEN_TIMESTAMP_MILLIS)
+                                    .setIndexingType(
+                                            AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_RANGE)
+                                    .setCardinality(
+                                            AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                    .build())
+                    .build();
+
+    /** Constructs an {@link AppOpenEvent}. */
+    @VisibleForTesting
+    public AppOpenEvent(@NonNull GenericDocument document) {
+        super(document);
+    }
+
+    /**
+     * Returns the package name this {@link AppOpenEvent} represents. For example,
+     * "com.android.vending".
+     */
+    @NonNull
+    public String getPackageName() {
+        return getPropertyString(APP_OPEN_EVENT_PROPERTY_PACKAGE_NAME);
+    }
+
+    /**
+     * Returns the qualified id of the {@link AppOpenEvent} which links to the {@link
+     * MobileApplication} schema.
+     */
+    @NonNull
+    public String getMobileApplicationQualifiedId() {
+        return getPropertyString(APP_OPEN_EVENT_PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID);
+    }
+
+    /** Returns the timestamp associated with the app open event. */
+    @NonNull
+    @CurrentTimeMillisLong
+    public Long getAppOpenEventTimestampMillis() {
+        return getPropertyLong(APP_OPEN_EVENT_PROPERTY_APP_OPEN_TIMESTAMP_MILLIS);
+    }
+
+    /** Builder for {@link AppOpenEvent}. */
+    public static final class Builder extends GenericDocument.Builder<Builder> {
+        public Builder(
+                @NonNull String packageName,
+                @CurrentTimeMillisLong long appOpenEventTimestampMillis) {
+            // Package name + timestamp is unique, since if an app was somehow opened twice at the
+            // same time, it would be considered the same event.
+            super(
+                    APP_OPEN_EVENT_NAMESPACE,
+                    /* id= */ packageName + appOpenEventTimestampMillis,
+                    SCHEMA_TYPE);
+            setPropertyString(APP_OPEN_EVENT_PROPERTY_PACKAGE_NAME, packageName);
+            setPropertyLong(
+                    APP_OPEN_EVENT_PROPERTY_APP_OPEN_TIMESTAMP_MILLIS, appOpenEventTimestampMillis);
+        }
+
+        /** Sets the app open event timestamp. */
+        @NonNull
+        @CanIgnoreReturnValue
+        public Builder setAppOpenEventTimestampMillis(
+                @CurrentTimeMillisLong long appOpenEventTimestampMillis) {
+            setPropertyLong(
+                    APP_OPEN_EVENT_PROPERTY_APP_OPEN_TIMESTAMP_MILLIS, appOpenEventTimestampMillis);
+            return this;
+        }
+
+        /** Sets the mobile application qualified id */
+        @NonNull
+        @CanIgnoreReturnValue
+        public Builder setMobileApplicationQualifiedId(
+                @NonNull String mobileApplicationQualifiedId) {
+            setPropertyString(
+                    APP_OPEN_EVENT_PROPERTY_MOBILE_APPLICATION_QUALIFIED_ID,
+                    Objects.requireNonNull(mobileApplicationQualifiedId));
+            return this;
+        }
+
+        /** Sets the package name. */
+        @NonNull
+        @CanIgnoreReturnValue
+        public Builder setPackageName(@NonNull String packageName) {
+            setPropertyString(
+                    APP_OPEN_EVENT_PROPERTY_PACKAGE_NAME, Objects.requireNonNull(packageName));
+            return this;
+        }
+
+        @NonNull
+        @CanIgnoreReturnValue
+        public AppOpenEvent build() {
+            return new AppOpenEvent(super.build());
+        }
+    }
+}
diff --git a/service/java/com/android/server/appsearch/contactsindexer/AppSearchHelper.java b/service/java/com/android/server/appsearch/contactsindexer/AppSearchHelper.java
index fbb90540..3e552035 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/AppSearchHelper.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/AppSearchHelper.java
@@ -79,7 +79,6 @@ public class AppSearchHelper {
 
     private final Context mContext;
     private final Executor mExecutor;
-    private final ContactsIndexerConfig mContactsIndexerConfig;
     // Holds the result of an asynchronous operation to create an AppSearchSession
     // and set the builtin:Person schema in it.
     private volatile CompletableFuture<AppSearchSession> mAppSearchSessionFuture;
@@ -93,23 +92,16 @@ public class AppSearchHelper {
      */
     @NonNull
     public static AppSearchHelper createAppSearchHelper(
-            @NonNull Context context,
-            @NonNull Executor executor,
-            @NonNull ContactsIndexerConfig contactsIndexerConfig) {
-        AppSearchHelper appSearchHelper =
-                new AppSearchHelper(context, executor, contactsIndexerConfig);
+            @NonNull Context context, @NonNull Executor executor) {
+        AppSearchHelper appSearchHelper = new AppSearchHelper(context, executor);
         appSearchHelper.initializeAsync();
         return appSearchHelper;
     }
 
     @VisibleForTesting
-    AppSearchHelper(
-            @NonNull Context context,
-            @NonNull Executor executor,
-            @NonNull ContactsIndexerConfig contactsIndexerConfig) {
+    AppSearchHelper(@NonNull Context context, @NonNull Executor executor) {
         mContext = Objects.requireNonNull(context);
         mExecutor = Objects.requireNonNull(executor);
-        mContactsIndexerConfig = Objects.requireNonNull(contactsIndexerConfig);
     }
 
     /**
@@ -222,7 +214,7 @@ public class AppSearchHelper {
         CompletableFuture<AppSearchSession> future = new CompletableFuture<>();
         SetSchemaRequest.Builder schemaBuilder =
                 new SetSchemaRequest.Builder()
-                        .addSchemas(ContactPoint.SCHEMA, Person.getSchema(mContactsIndexerConfig))
+                        .addSchemas(ContactPoint.SCHEMA, Person.getSchema())
                         .addRequiredPermissionsForSchemaTypeVisibility(
                                 Person.SCHEMA_TYPE,
                                 Collections.singleton(SetSchemaRequest.READ_CONTACTS))
diff --git a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerConfig.java b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerConfig.java
index 11751aa5..b1f16a67 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerConfig.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerConfig.java
@@ -31,7 +31,6 @@ public interface ContactsIndexerConfig {
     long DEFAULT_CONTACTS_FULL_UPDATE_INTERVAL_MILLIS = TimeUnit.DAYS.toMillis(30); // 30 days.
     int DEFAULT_CONTACTS_FULL_UPDATE_INDEXING_LIMIT = 10_000;
     int DEFAULT_CONTACTS_DELTA_UPDATE_INDEXING_LIMIT = 1000;
-    boolean DEFAULT_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES = false;
     boolean DEFAULT_CONTACTS_KEEP_UPDATING_ON_ERROR = true;
 
     /** Returns whether Contacts Indexer is enabled. */
@@ -65,12 +64,6 @@ public interface ContactsIndexerConfig {
      */
     int getContactsDeltaUpdateLimit();
 
-    /**
-     * Returns whether the first, middle and last names of a contact should be indexed in addition
-     * to the full name.
-     */
-    boolean shouldIndexFirstMiddleAndLastNames();
-
     /** Returns whether full and delta updates should continue on error. */
     boolean shouldKeepUpdatingOnError();
 }
diff --git a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerSettings.java b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerSettings.java
index b52bee6a..a6c609c3 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerSettings.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerSettings.java
@@ -18,14 +18,10 @@ package com.android.server.appsearch.contactsindexer;
 
 import android.annotation.NonNull;
 import android.os.PersistableBundle;
-import android.util.AtomicFile;
 
-import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.appsearch.indexer.IndexerSettings;
 
 import java.io.File;
-import java.io.FileInputStream;
-import java.io.FileOutputStream;
-import java.io.IOException;
 import java.util.Objects;
 
 /**
@@ -44,7 +40,7 @@ import java.util.Objects;
  *
  * @hide
  */
-public class ContactsIndexerSettings {
+public class ContactsIndexerSettings extends IndexerSettings {
 
     private static final String TAG = "ContactsIndexerSettings";
 
@@ -59,20 +55,13 @@ public class ContactsIndexerSettings {
     // been kept the same for backwards compatibility
     static final String LAST_CONTACT_DELETE_TIMESTAMP_KEY = "last_delta_delete_timestamp_millis";
 
-    private final File mFile;
-    private PersistableBundle mBundle = new PersistableBundle();
-
     public ContactsIndexerSettings(@NonNull File baseDir) {
-        Objects.requireNonNull(baseDir);
-        mFile = new File(baseDir, SETTINGS_FILE_NAME);
-    }
-
-    public void load() throws IOException {
-        mBundle = readBundle(mFile);
+        super(Objects.requireNonNull(baseDir));
     }
 
-    public void persist() throws IOException {
-        writeBundle(mFile, mBundle);
+    @Override
+    protected String getSettingsFileName() {
+        return SETTINGS_FILE_NAME;
     }
 
     /** Returns the timestamp of when the last full update occurred in milliseconds. */
@@ -116,36 +105,11 @@ public class ContactsIndexerSettings {
     }
 
     /** Resets all the settings to default values. */
+    @Override
     public void reset() {
         setLastFullUpdateTimestampMillis(0);
         setLastDeltaUpdateTimestampMillis(0);
         setLastContactUpdateTimestampMillis(0);
         setLastContactDeleteTimestampMillis(0);
     }
-
-    @VisibleForTesting
-    @NonNull
-    static PersistableBundle readBundle(@NonNull File src) throws IOException {
-        AtomicFile atomicFile = new AtomicFile(src);
-        try (FileInputStream fis = atomicFile.openRead()) {
-            return PersistableBundle.readFromStream(fis);
-        }
-    }
-
-    @VisibleForTesting
-    static void writeBundle(@NonNull File dest, @NonNull PersistableBundle bundle)
-            throws IOException {
-        AtomicFile atomicFile = new AtomicFile(dest);
-        FileOutputStream fos = null;
-        try {
-            fos = atomicFile.startWrite();
-            bundle.writeToStream(fos);
-            atomicFile.finishWrite(fos);
-        } catch (IOException e) {
-            if (fos != null) {
-                atomicFile.failWrite(fos);
-            }
-            throw e;
-        }
-    }
 }
diff --git a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstance.java b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstance.java
index 443d46e1..c21ba117 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstance.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstance.java
@@ -20,6 +20,7 @@ import static com.android.server.appsearch.indexer.IndexerMaintenanceConfig.CONT
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.WorkerThread;
 import android.app.appsearch.AppSearchEnvironmentFactory;
 import android.app.appsearch.AppSearchResult;
 import android.app.appsearch.util.LogUtil;
@@ -132,8 +133,7 @@ public final class ContactsIndexerUserInstance {
         Objects.requireNonNull(executorService);
 
         AppSearchHelper appSearchHelper =
-                AppSearchHelper.createAppSearchHelper(
-                        context, executorService, contactsIndexerConfig);
+                AppSearchHelper.createAppSearchHelper(context, executorService);
         ContactsIndexerUserInstance indexer =
                 new ContactsIndexerUserInstance(
                         context,
@@ -675,6 +675,7 @@ public final class ContactsIndexerUserInstance {
                 });
     }
 
+    @WorkerThread
     private void persistSettings() {
         try {
             mSettings.persist();
diff --git a/service/java/com/android/server/appsearch/contactsindexer/FrameworkContactsIndexerConfig.java b/service/java/com/android/server/appsearch/contactsindexer/FrameworkContactsIndexerConfig.java
index 0ac97fcf..2f5446be 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/FrameworkContactsIndexerConfig.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/FrameworkContactsIndexerConfig.java
@@ -34,8 +34,6 @@ public class FrameworkContactsIndexerConfig implements ContactsIndexerConfig {
             "contacts_full_update_interval_millis";
     static final String KEY_CONTACTS_FULL_UPDATE_LIMIT = "contacts_indexer_full_update_limit";
     static final String KEY_CONTACTS_DELTA_UPDATE_LIMIT = "contacts_indexer_delta_update_limit";
-    public static final String KEY_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES =
-            "contacts_index_first_middle_and_last_names";
     static final String KEY_CONTACTS_KEEP_UPDATING_ON_ERROR = "contacts_keep_updating_on_error";
 
     @Override
@@ -81,14 +79,6 @@ public class FrameworkContactsIndexerConfig implements ContactsIndexerConfig {
                 DEFAULT_CONTACTS_DELTA_UPDATE_INDEXING_LIMIT);
     }
 
-    @Override
-    public boolean shouldIndexFirstMiddleAndLastNames() {
-        return DeviceConfig.getBoolean(
-                DeviceConfig.NAMESPACE_APPSEARCH,
-                KEY_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES,
-                DEFAULT_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES);
-    }
-
     @Override
     public boolean shouldKeepUpdatingOnError() {
         return DeviceConfig.getBoolean(
diff --git a/service/java/com/android/server/appsearch/contactsindexer/appsearchtypes/Person.java b/service/java/com/android/server/appsearch/contactsindexer/appsearchtypes/Person.java
index 871577ab..570ed2f8 100644
--- a/service/java/com/android/server/appsearch/contactsindexer/appsearchtypes/Person.java
+++ b/service/java/com/android/server/appsearch/contactsindexer/appsearchtypes/Person.java
@@ -23,9 +23,9 @@ import android.app.appsearch.AppSearchSchema;
 import android.app.appsearch.GenericDocument;
 import android.net.Uri;
 
+import com.android.appsearch.flags.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.Preconditions;
-import com.android.server.appsearch.contactsindexer.ContactsIndexerConfig;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
@@ -246,14 +246,9 @@ public class Person extends GenericDocument {
         return builder.build();
     }
 
-    /***
-     * Returns Person schema based on current value of flag
-     * 'contacts_index_first_middle_and_last_names'. If the flag value changes after the initial
-     * schema fetch, the schema returned will be different than the original schema that was set
-     * for the Person corpus.
-     */
-    public static AppSearchSchema getSchema(ContactsIndexerConfig config) {
-        return createSchema(config.shouldIndexFirstMiddleAndLastNames());
+    /** Returns Person schema based on {@link Flags#enableContactsIndexFirstMiddleAndLastNames}. */
+    public static AppSearchSchema getSchema() {
+        return createSchema(Flags.enableContactsIndexFirstMiddleAndLastNames());
     }
 
     /** Constructs a {@link Person}. */
diff --git a/service/java/com/android/server/appsearch/external/localstorage/AppSearchLogger.java b/service/java/com/android/server/appsearch/external/localstorage/AppSearchLogger.java
index 32b20e96..847d0aa8 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/AppSearchLogger.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/AppSearchLogger.java
@@ -42,28 +42,44 @@ import java.util.List;
  */
 public interface AppSearchLogger {
     /** Logs {@link CallStats} */
-    void logStats(@NonNull CallStats stats);
+    default void logStats(@NonNull CallStats stats) {
+        // no-op
+    }
 
     /** Logs {@link PutDocumentStats} */
-    void logStats(@NonNull PutDocumentStats stats);
+    default void logStats(@NonNull PutDocumentStats stats) {
+        // no-op
+    }
 
     /** Logs {@link InitializeStats} */
-    void logStats(@NonNull InitializeStats stats);
+    default void logStats(@NonNull InitializeStats stats) {
+        // no-op
+    }
 
     /** Logs {@link SearchStats} */
-    void logStats(@NonNull SearchStats stats);
+    default void logStats(@NonNull SearchStats stats) {
+        // no-op
+    }
 
     /** Logs {@link RemoveStats} */
-    void logStats(@NonNull RemoveStats stats);
+    default void logStats(@NonNull RemoveStats stats) {
+        // no-op
+    }
 
     /** Logs {@link OptimizeStats} */
-    void logStats(@NonNull OptimizeStats stats);
+    default void logStats(@NonNull OptimizeStats stats) {
+        // no-op
+    }
 
     /** Logs {@link SetSchemaStats} */
-    void logStats(@NonNull SetSchemaStats stats);
+    default void logStats(@NonNull SetSchemaStats stats) {
+        // no-op
+    }
 
     /** Logs {@link SchemaMigrationStats} */
-    void logStats(@NonNull SchemaMigrationStats stats);
+    default void logStats(@NonNull SchemaMigrationStats stats) {
+        // no-op
+    }
 
     /**
      * Logs a list of {@link SearchSessionStats}.
@@ -84,7 +100,9 @@ public interface AppSearchLogger {
      * creates 2 {@link SearchSessionStats} with search intents ["a", "app"] and ["email"]
      * respectively.
      */
-    void logStats(@NonNull List<SearchSessionStats> searchSessionsStats);
+    default void logStats(@NonNull List<SearchSessionStats> searchSessionsStats) {
+        // no-op
+    }
 
     // TODO(b/173532925) Add remaining logStats once we add all the stats.
 }
diff --git a/service/java/com/android/server/appsearch/external/localstorage/converter/ResultCodeToProtoConverter.java b/service/java/com/android/server/appsearch/external/localstorage/converter/ResultCodeToProtoConverter.java
index e8ff775b..ca1c09ad 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/converter/ResultCodeToProtoConverter.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/converter/ResultCodeToProtoConverter.java
@@ -49,6 +49,8 @@ public final class ResultCodeToProtoConverter {
                 return AppSearchResult.RESULT_NOT_FOUND;
             case INVALID_ARGUMENT:
                 return AppSearchResult.RESULT_INVALID_ARGUMENT;
+            case ALREADY_EXISTS:
+                return AppSearchResult.RESULT_ALREADY_EXISTS;
             default:
                 // Some unknown/unsupported error
                 Log.e(
diff --git a/service/java/com/android/server/appsearch/external/localstorage/converter/SchemaToProtoConverter.java b/service/java/com/android/server/appsearch/external/localstorage/converter/SchemaToProtoConverter.java
index e9e0b103..73d39fff 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/converter/SchemaToProtoConverter.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/converter/SchemaToProtoConverter.java
@@ -337,11 +337,12 @@ public final class SchemaToProtoConverter {
                 return AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_EXACT_TERMS;
             case PREFIX:
                 return AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_PREFIXES;
+            default:
+                // Avoid crashing in the 'read' path; we should try to interpret the document to the
+                // extent possible.
+                Log.w(TAG, "Invalid indexingType: " + termMatchType.getNumber());
+                return AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_NONE;
         }
-        // Avoid crashing in the 'read' path; we should try to interpret the document to the
-        // extent possible.
-        Log.w(TAG, "Invalid indexingType: " + termMatchType.getNumber());
-        return AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_NONE;
     }
 
     @NonNull
@@ -376,11 +377,12 @@ public final class SchemaToProtoConverter {
                 return AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_NONE;
             case RANGE:
                 return AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_RANGE;
+            default:
+                // Avoid crashing in the 'read' path; we should try to interpret the document to the
+                // extent possible.
+                Log.w(TAG, "Invalid indexingType: " + numericMatchType.getNumber());
+                return AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_NONE;
         }
-        // Avoid crashing in the 'read' path; we should try to interpret the document to the
-        // extent possible.
-        Log.w(TAG, "Invalid indexingType: " + numericMatchType.getNumber());
-        return AppSearchSchema.LongPropertyConfig.INDEXING_TYPE_NONE;
     }
 
     @NonNull
@@ -405,10 +407,11 @@ public final class SchemaToProtoConverter {
                 return AppSearchSchema.EmbeddingPropertyConfig.INDEXING_TYPE_NONE;
             case LINEAR_SEARCH:
                 return AppSearchSchema.EmbeddingPropertyConfig.INDEXING_TYPE_SIMILARITY;
+            default:
+                // Avoid crashing in the 'read' path; we should try to interpret the document to the
+                // extent possible.
+                Log.w(TAG, "Invalid indexingType: " + indexingType.getNumber());
+                return AppSearchSchema.EmbeddingPropertyConfig.INDEXING_TYPE_NONE;
         }
-        // Avoid crashing in the 'read' path; we should try to interpret the document to the
-        // extent possible.
-        Log.w(TAG, "Invalid indexingType: " + indexingType.getNumber());
-        return AppSearchSchema.EmbeddingPropertyConfig.INDEXING_TYPE_NONE;
     }
 }
diff --git a/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSpecToProtoConverter.java b/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSpecToProtoConverter.java
index 5f91f21c..531ab721 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSpecToProtoConverter.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSpecToProtoConverter.java
@@ -287,9 +287,10 @@ public final class SearchSpecToProtoConverter {
                         .setQuery(mQueryExpression)
                         .addAllNamespaceFilters(mTargetPrefixedNamespaceFilters)
                         .addAllSchemaTypeFilters(mTargetPrefixedSchemaFilters)
-                        .setUseReadOnlySearch(mIcingOptionsConfig.getUseReadOnlySearch());
+                        .setUseReadOnlySearch(mIcingOptionsConfig.getUseReadOnlySearch())
+                        .addAllQueryParameterStrings(mSearchSpec.getSearchStringParameters());
 
-        List<EmbeddingVector> searchEmbeddings = mSearchSpec.getSearchEmbeddings();
+        List<EmbeddingVector> searchEmbeddings = mSearchSpec.getEmbeddingParameters();
         for (int i = 0; i < searchEmbeddings.size(); i++) {
             protoBuilder.addEmbeddingQueryVectors(
                     GenericDocumentToProtoConverter.embeddingVectorToVectorProto(
diff --git a/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSuggestionSpecToProtoConverter.java b/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSuggestionSpecToProtoConverter.java
index d54c37c4..bddabb44 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSuggestionSpecToProtoConverter.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/converter/SearchSuggestionSpecToProtoConverter.java
@@ -106,7 +106,9 @@ public final class SearchSuggestionSpecToProtoConverter {
                         .setPrefix(mSuggestionQueryExpression)
                         .addAllNamespaceFilters(mTargetPrefixedNamespaceFilters)
                         .addAllSchemaTypeFilters(mTargetPrefixedSchemaFilters)
-                        .setNumToReturn(mSearchSuggestionSpec.getMaximumResultCount());
+                        .setNumToReturn(mSearchSuggestionSpec.getMaximumResultCount())
+                        .addAllQueryParameterStrings(
+                                mSearchSuggestionSpec.getSearchStringParameters());
 
         // Convert type property filter map into type property mask proto.
         for (Map.Entry<String, List<String>> entry :
diff --git a/service/java/com/android/server/appsearch/external/localstorage/visibilitystore/VisibilityToDocumentConverter.java b/service/java/com/android/server/appsearch/external/localstorage/visibilitystore/VisibilityToDocumentConverter.java
index 5d27c0cd..b80c4d42 100644
--- a/service/java/com/android/server/appsearch/external/localstorage/visibilitystore/VisibilityToDocumentConverter.java
+++ b/service/java/com/android/server/appsearch/external/localstorage/visibilitystore/VisibilityToDocumentConverter.java
@@ -291,8 +291,9 @@ public class VisibilityToDocumentConverter {
         return builder.build();
     }
 
+    /** Convert {@link VisibilityConfigProto} into {@link SchemaVisibilityConfig}. */
     @NonNull
-    private static SchemaVisibilityConfig convertVisibilityConfigFromProto(
+    public static SchemaVisibilityConfig convertVisibilityConfigFromProto(
             @NonNull VisibilityConfigProto proto) {
         SchemaVisibilityConfig.Builder builder = new SchemaVisibilityConfig.Builder();
 
@@ -321,7 +322,9 @@ public class VisibilityToDocumentConverter {
         return builder.build();
     }
 
-    private static VisibilityConfigProto convertSchemaVisibilityConfigToProto(
+    /** Convert {@link SchemaVisibilityConfig} into {@link VisibilityConfigProto}. */
+    @NonNull
+    public static VisibilityConfigProto convertSchemaVisibilityConfigToProto(
             @NonNull SchemaVisibilityConfig schemaVisibilityConfig) {
         VisibilityConfigProto.Builder builder = VisibilityConfigProto.newBuilder();
 
diff --git a/service/java/com/android/server/appsearch/indexer/IndexerSettings.java b/service/java/com/android/server/appsearch/indexer/IndexerSettings.java
new file mode 100644
index 00000000..4bc889a5
--- /dev/null
+++ b/service/java/com/android/server/appsearch/indexer/IndexerSettings.java
@@ -0,0 +1,126 @@
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
+package com.android.server.appsearch.indexer;
+
+import android.annotation.CurrentTimeMillisLong;
+import android.annotation.NonNull;
+import android.annotation.WorkerThread;
+import android.os.PersistableBundle;
+import android.util.AtomicFile;
+
+import com.android.internal.annotations.VisibleForTesting;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.util.Objects;
+
+/**
+ * Settings backed by a PersistableBundle, providing common functionality for settings handling.
+ *
+ * <p>This class provides common functionality for settings handling, including:
+ *
+ * <ul>
+ *   <li>getting and setting the timestamp of the last update
+ *   <li>loading and persisting settings to/from a file
+ * </ul>
+ *
+ * <p>This class is NOT thread safe (similar to {@link PersistableBundle} which it wraps).
+ */
+public abstract class IndexerSettings {
+
+    public static final String LAST_UPDATE_TIMESTAMP_KEY = "last_update_timestamp_millis";
+
+    private final File mBaseDir;
+    private File mFile;
+    protected PersistableBundle mBundle = new PersistableBundle();
+
+    public IndexerSettings(@NonNull File baseDir) {
+        mBaseDir = Objects.requireNonNull(baseDir);
+    }
+
+    /** Allows for late initialization of the settings file. */
+    @WorkerThread
+    private void ensureFileCreated() {
+        if (mFile != null) {
+            return;
+        }
+        mFile = new File(mBaseDir, getSettingsFileName());
+    }
+
+    protected abstract String getSettingsFileName();
+
+    /** Loads the bundle from the file. */
+    @WorkerThread
+    public void load() throws IOException {
+        ensureFileCreated();
+        mBundle = readBundle(mFile);
+    }
+
+    /** Saves the bundle to the file. */
+    @WorkerThread
+    public void persist() throws IOException {
+        ensureFileCreated();
+        writeBundle(mFile, mBundle);
+    }
+
+    /** Returns the timestamp of when the last update occurred in milliseconds. */
+    public @CurrentTimeMillisLong long getLastUpdateTimestampMillis() {
+        return mBundle.getLong(LAST_UPDATE_TIMESTAMP_KEY);
+    }
+
+    /** Sets the timestamp of when the last update occurred in milliseconds. */
+    public void setLastUpdateTimestampMillis(@CurrentTimeMillisLong long timestampMillis) {
+        mBundle.putLong(LAST_UPDATE_TIMESTAMP_KEY, timestampMillis);
+    }
+
+    /** Resets all the settings to default values. */
+    public void reset() {
+        setLastUpdateTimestampMillis(0);
+    }
+
+    /** Static util method to read a bundle from a file. */
+    @VisibleForTesting
+    @NonNull
+    @WorkerThread
+    public static PersistableBundle readBundle(@NonNull File src) throws IOException {
+        AtomicFile atomicFile = new AtomicFile(src);
+        try (FileInputStream fis = atomicFile.openRead()) {
+            return PersistableBundle.readFromStream(fis);
+        }
+    }
+
+    /** Static util method to write a bundle to a file. */
+    @VisibleForTesting
+    @WorkerThread
+    public static void writeBundle(@NonNull File dest, @NonNull PersistableBundle bundle)
+            throws IOException {
+        AtomicFile atomicFile = new AtomicFile(dest);
+        FileOutputStream fos = null;
+        try {
+            fos = atomicFile.startWrite();
+            bundle.writeToStream(fos);
+            atomicFile.finishWrite(fos);
+        } catch (IOException e) {
+            if (fos != null) {
+                atomicFile.failWrite(fos);
+            }
+            throw e;
+        }
+    }
+}
diff --git a/service/java/com/android/server/appsearch/util/ExecutorManager.java b/service/java/com/android/server/appsearch/util/ExecutorManager.java
index 5503ff9c..1fd971a1 100644
--- a/service/java/com/android/server/appsearch/util/ExecutorManager.java
+++ b/service/java/com/android/server/appsearch/util/ExecutorManager.java
@@ -16,8 +16,20 @@
 
 package com.android.server.appsearch.util;
 
+import static android.app.appsearch.AppSearchResult.RESULT_RATE_LIMITED;
+import static android.app.appsearch.AppSearchResult.throwableToFailedResult;
+
+import static com.android.server.appsearch.util.ServiceImplHelper.invokeCallbackOnError;
+import static com.android.server.appsearch.util.ServiceImplHelper.invokeCallbackOnResult;
+
+import android.annotation.BinderThread;
 import android.annotation.NonNull;
 import android.app.appsearch.AppSearchEnvironmentFactory;
+import android.app.appsearch.AppSearchResult;
+import android.app.appsearch.aidl.AppSearchResultParcel;
+import android.app.appsearch.aidl.IAppSearchBatchResultCallback;
+import android.app.appsearch.aidl.IAppSearchResultCallback;
+import android.app.appsearch.annotation.CanIgnoreReturnValue;
 import android.os.UserHandle;
 import android.util.ArrayMap;
 
@@ -25,6 +37,7 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.server.appsearch.AppSearchRateLimitConfig;
 import com.android.server.appsearch.FrameworkServiceAppSearchConfig;
 import com.android.server.appsearch.ServiceAppSearchConfig;
+import com.android.server.appsearch.external.localstorage.stats.CallStats;
 
 import java.util.Map;
 import java.util.Objects;
@@ -41,15 +54,6 @@ import java.util.concurrent.TimeUnit;
  * @hide
  */
 public class ExecutorManager {
-    private final ServiceAppSearchConfig mAppSearchConfig;
-
-    /**
-     * A map of per-user executors for queued work. These can be started or shut down via this
-     * class's public API.
-     */
-    @GuardedBy("mPerUserExecutorsLocked")
-    private final Map<UserHandle, ExecutorService> mPerUserExecutorsLocked = new ArrayMap<>();
-
     /**
      * Creates a new {@link ExecutorService} with default settings for use in AppSearch.
      *
@@ -73,6 +77,15 @@ public class ExecutorManager {
                         /* priority= */ 0); // priority is unused.
     }
 
+    private final ServiceAppSearchConfig mAppSearchConfig;
+
+    /**
+     * A map of per-user executors for queued work. These can be started or shut down via this
+     * class's public API.
+     */
+    @GuardedBy("mPerUserExecutorsLocked")
+    private final Map<UserHandle, ExecutorService> mPerUserExecutorsLocked = new ArrayMap<>();
+
     public ExecutorManager(@NonNull ServiceAppSearchConfig appSearchConfig) {
         mAppSearchConfig = Objects.requireNonNull(appSearchConfig);
     }
@@ -99,6 +112,175 @@ public class ExecutorManager {
         }
     }
 
+    /**
+     * Gracefully shuts down the executor for the given user if there is one, waiting up to 30
+     * seconds for jobs to finish.
+     */
+    public void shutDownAndRemoveUserExecutor(@NonNull UserHandle userHandle)
+            throws InterruptedException {
+        Objects.requireNonNull(userHandle);
+        ExecutorService executor;
+        synchronized (mPerUserExecutorsLocked) {
+            executor = mPerUserExecutorsLocked.remove(userHandle);
+        }
+        if (executor != null) {
+            executor.shutdown();
+            // Wait a little bit to finish outstanding requests. It's important not to call
+            // shutdownNow because nothing would pass a final result to the caller, leading to
+            // hangs. If we are interrupted or the timeout elapses, just move on to closing the
+            // user instance, meaning pending tasks may crash when AppSearchImpl closes under
+            // them.
+            executor.awaitTermination(30, TimeUnit.SECONDS);
+        }
+    }
+
+    /**
+     * Helper to execute the implementation of some AppSearch functionality on the executor for that
+     * user.
+     *
+     * @param targetUser The verified user the call should run as.
+     * @param errorCallback Callback to complete with an error if starting the lambda fails.
+     *     Otherwise this callback is not triggered.
+     * @param callingPackageName Package making this lambda call.
+     * @param apiType Api type of this lambda call.
+     * @param lambda The lambda to execute on the user-provided executor.
+     * @return true if the call is accepted by the executor and false otherwise.
+     */
+    @BinderThread
+    @CanIgnoreReturnValue
+    public boolean executeLambdaForUserAsync(
+            @NonNull UserHandle targetUser,
+            @NonNull IAppSearchResultCallback errorCallback,
+            @NonNull String callingPackageName,
+            @CallStats.CallType int apiType,
+            @NonNull Runnable lambda) {
+        Objects.requireNonNull(targetUser);
+        Objects.requireNonNull(errorCallback);
+        Objects.requireNonNull(callingPackageName);
+        Objects.requireNonNull(lambda);
+        try {
+            synchronized (mPerUserExecutorsLocked) {
+                Executor executor = getOrCreateUserExecutor(targetUser);
+                if (executor instanceof RateLimitedExecutor) {
+                    boolean callAccepted =
+                            ((RateLimitedExecutor) executor)
+                                    .execute(lambda, callingPackageName, apiType);
+                    if (!callAccepted) {
+                        invokeCallbackOnResult(
+                                errorCallback,
+                                AppSearchResultParcel.fromFailedResult(
+                                        AppSearchResult.newFailedResult(
+                                                RESULT_RATE_LIMITED,
+                                                "AppSearch rate limit reached.")));
+                        return false;
+                    }
+                } else {
+                    executor.execute(lambda);
+                }
+            }
+        } catch (RuntimeException e) {
+            AppSearchResult failedResult = throwableToFailedResult(e);
+            invokeCallbackOnResult(
+                    errorCallback, AppSearchResultParcel.fromFailedResult(failedResult));
+        }
+        return true;
+    }
+
+    /**
+     * Helper to execute the implementation of some AppSearch functionality on the executor for that
+     * user.
+     *
+     * @param targetUser The verified user the call should run as.
+     * @param errorCallback Callback to complete with an error if starting the lambda fails.
+     *     Otherwise this callback is not triggered.
+     * @param callingPackageName Package making this lambda call.
+     * @param apiType Api type of this lambda call.
+     * @param lambda The lambda to execute on the user-provided executor.
+     * @return true if the call is accepted by the executor and false otherwise.
+     */
+    @BinderThread
+    public boolean executeLambdaForUserAsync(
+            @NonNull UserHandle targetUser,
+            @NonNull IAppSearchBatchResultCallback errorCallback,
+            @NonNull String callingPackageName,
+            @CallStats.CallType int apiType,
+            @NonNull Runnable lambda) {
+        Objects.requireNonNull(targetUser);
+        Objects.requireNonNull(errorCallback);
+        Objects.requireNonNull(callingPackageName);
+        Objects.requireNonNull(lambda);
+        try {
+            synchronized (mPerUserExecutorsLocked) {
+                Executor executor = getOrCreateUserExecutor(targetUser);
+                if (executor instanceof RateLimitedExecutor) {
+                    boolean callAccepted =
+                            ((RateLimitedExecutor) executor)
+                                    .execute(lambda, callingPackageName, apiType);
+                    if (!callAccepted) {
+                        invokeCallbackOnError(
+                                errorCallback,
+                                AppSearchResult.newFailedResult(
+                                        RESULT_RATE_LIMITED, "AppSearch rate limit reached."));
+                        return false;
+                    }
+                } else {
+                    executor.execute(lambda);
+                }
+            }
+        } catch (RuntimeException e) {
+            invokeCallbackOnError(errorCallback, e);
+        }
+        return true;
+    }
+
+    /**
+     * Helper to execute the implementation of some AppSearch functionality on the executor for that
+     * user, without invoking callback for the user.
+     *
+     * @param targetUser The verified user the call should run as.
+     * @param callingPackageName Package making this lambda call.
+     * @param apiType Api type of this lambda call.
+     * @param lambda The lambda to execute on the user-provided executor.
+     * @return true if the call is accepted by the executor and false otherwise.
+     */
+    @BinderThread
+    public boolean executeLambdaForUserNoCallbackAsync(
+            @NonNull UserHandle targetUser,
+            @NonNull String callingPackageName,
+            @CallStats.CallType int apiType,
+            @NonNull Runnable lambda) {
+        Objects.requireNonNull(targetUser);
+        Objects.requireNonNull(callingPackageName);
+        Objects.requireNonNull(lambda);
+        synchronized (mPerUserExecutorsLocked) {
+            Executor executor = getOrCreateUserExecutor(targetUser);
+            if (executor instanceof RateLimitedExecutor) {
+                return ((RateLimitedExecutor) executor)
+                        .execute(lambda, callingPackageName, apiType);
+            } else {
+                executor.execute(lambda);
+                return true;
+            }
+        }
+    }
+
+    /**
+     * Helper to execute the implementation of some AppSearch functionality on the executor for that
+     * user, without invoking callback for the user.
+     *
+     * @param targetUser The verified user the call should run as.
+     * @param lambda The lambda to execute on the user-provided executor.
+     */
+    public void executeLambdaForUserNoCallbackAsync(
+            @NonNull UserHandle targetUser, @NonNull Runnable lambda) {
+        Objects.requireNonNull(targetUser);
+        Objects.requireNonNull(lambda);
+
+        synchronized (mPerUserExecutorsLocked) {
+            getOrCreateUserExecutor(targetUser).execute(lambda);
+        }
+    }
+
     @GuardedBy("mPerUserExecutorsLocked")
     @NonNull
     private Executor getOrCreateUserExecutorLocked(@NonNull UserHandle userHandle) {
@@ -130,26 +312,4 @@ public class ExecutorManager {
         }
         return executor;
     }
-
-    /**
-     * Gracefully shuts down the executor for the given user if there is one, waiting up to 30
-     * seconds for jobs to finish.
-     */
-    public void shutDownAndRemoveUserExecutor(@NonNull UserHandle userHandle)
-            throws InterruptedException {
-        Objects.requireNonNull(userHandle);
-        ExecutorService executor;
-        synchronized (mPerUserExecutorsLocked) {
-            executor = mPerUserExecutorsLocked.remove(userHandle);
-        }
-        if (executor != null) {
-            executor.shutdown();
-            // Wait a little bit to finish outstanding requests. It's important not to call
-            // shutdownNow because nothing would pass a final result to the caller, leading to
-            // hangs. If we are interrupted or the timeout elapses, just move on to closing the
-            // user instance, meaning pending tasks may crash when AppSearchImpl closes under
-            // them.
-            executor.awaitTermination(30, TimeUnit.SECONDS);
-        }
-    }
 }
diff --git a/service/java/com/android/server/appsearch/util/ServiceImplHelper.java b/service/java/com/android/server/appsearch/util/ServiceImplHelper.java
index f3e0f00c..68eea811 100644
--- a/service/java/com/android/server/appsearch/util/ServiceImplHelper.java
+++ b/service/java/com/android/server/appsearch/util/ServiceImplHelper.java
@@ -15,7 +15,6 @@
  */
 package com.android.server.appsearch.util;
 
-import static android.app.appsearch.AppSearchResult.RESULT_RATE_LIMITED;
 import static android.app.appsearch.AppSearchResult.throwableToFailedResult;
 
 import android.Manifest;
@@ -42,11 +41,9 @@ import android.util.Log;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.server.appsearch.AppSearchUserInstanceManager;
-import com.android.server.appsearch.external.localstorage.stats.CallStats;
 
 import java.util.Objects;
 import java.util.Set;
-import java.util.concurrent.Executor;
 
 /**
  * Utilities to help with implementing AppSearch's services.
@@ -59,7 +56,6 @@ public class ServiceImplHelper {
     private final Context mContext;
     private final UserManager mUserManager;
     private final DevicePolicyManager mDevicePolicyManager;
-    private final ExecutorManager mExecutorManager;
     private final AppSearchUserInstanceManager mAppSearchUserInstanceManager;
 
     // Cache of unlocked users so we don't have to query UserManager service each time. The "locked"
@@ -78,10 +74,9 @@ public class ServiceImplHelper {
     @Nullable
     private UserHandle mEnterpriseUserLocked;
 
-    public ServiceImplHelper(@NonNull Context context, @NonNull ExecutorManager executorManager) {
+    public ServiceImplHelper(@NonNull Context context) {
         mContext = Objects.requireNonNull(context);
         mUserManager = context.getSystemService(UserManager.class);
-        mExecutorManager = Objects.requireNonNull(executorManager);
         mAppSearchUserInstanceManager = AppSearchUserInstanceManager.getInstance();
         mDevicePolicyManager = context.getSystemService(DevicePolicyManager.class);
     }
@@ -341,137 +336,6 @@ public class ServiceImplHelper {
                         + Manifest.permission.INTERACT_ACROSS_USERS_FULL);
     }
 
-    /**
-     * Helper to execute the implementation of some AppSearch functionality on the executor for that
-     * user.
-     *
-     * <p>You should first make sure the call is allowed to run using {@link #verifyCaller}.
-     *
-     * @param targetUser The verified user the call should run as, as determined by {@link
-     *     #verifyCaller}.
-     * @param errorCallback Callback to complete with an error if starting the lambda fails.
-     *     Otherwise this callback is not triggered.
-     * @param callingPackageName Package making this lambda call.
-     * @param apiType Api type of this lambda call.
-     * @param lambda The lambda to execute on the user-provided executor.
-     * @return true if the call is accepted by the executor and false otherwise.
-     */
-    @BinderThread
-    @CanIgnoreReturnValue
-    public boolean executeLambdaForUserAsync(
-            @NonNull UserHandle targetUser,
-            @NonNull IAppSearchResultCallback errorCallback,
-            @NonNull String callingPackageName,
-            @CallStats.CallType int apiType,
-            @NonNull Runnable lambda) {
-        Objects.requireNonNull(targetUser);
-        Objects.requireNonNull(errorCallback);
-        Objects.requireNonNull(callingPackageName);
-        Objects.requireNonNull(lambda);
-        try {
-            Executor executor = mExecutorManager.getOrCreateUserExecutor(targetUser);
-            if (executor instanceof RateLimitedExecutor) {
-                boolean callAccepted =
-                        ((RateLimitedExecutor) executor)
-                                .execute(lambda, callingPackageName, apiType);
-                if (!callAccepted) {
-                    invokeCallbackOnResult(
-                            errorCallback,
-                            AppSearchResultParcel.fromFailedResult(
-                                    AppSearchResult.newFailedResult(
-                                            RESULT_RATE_LIMITED, "AppSearch rate limit reached.")));
-                    return false;
-                }
-            } else {
-                executor.execute(lambda);
-            }
-        } catch (RuntimeException e) {
-            AppSearchResult failedResult = throwableToFailedResult(e);
-            invokeCallbackOnResult(
-                    errorCallback, AppSearchResultParcel.fromFailedResult(failedResult));
-        }
-        return true;
-    }
-
-    /**
-     * Helper to execute the implementation of some AppSearch functionality on the executor for that
-     * user.
-     *
-     * <p>You should first make sure the call is allowed to run using {@link #verifyCaller}.
-     *
-     * @param targetUser The verified user the call should run as, as determined by {@link
-     *     #verifyCaller}.
-     * @param errorCallback Callback to complete with an error if starting the lambda fails.
-     *     Otherwise this callback is not triggered.
-     * @param callingPackageName Package making this lambda call.
-     * @param apiType Api type of this lambda call.
-     * @param lambda The lambda to execute on the user-provided executor.
-     * @return true if the call is accepted by the executor and false otherwise.
-     */
-    @BinderThread
-    public boolean executeLambdaForUserAsync(
-            @NonNull UserHandle targetUser,
-            @NonNull IAppSearchBatchResultCallback errorCallback,
-            @NonNull String callingPackageName,
-            @CallStats.CallType int apiType,
-            @NonNull Runnable lambda) {
-        Objects.requireNonNull(targetUser);
-        Objects.requireNonNull(errorCallback);
-        Objects.requireNonNull(callingPackageName);
-        Objects.requireNonNull(lambda);
-        try {
-            Executor executor = mExecutorManager.getOrCreateUserExecutor(targetUser);
-            if (executor instanceof RateLimitedExecutor) {
-                boolean callAccepted =
-                        ((RateLimitedExecutor) executor)
-                                .execute(lambda, callingPackageName, apiType);
-                if (!callAccepted) {
-                    invokeCallbackOnError(
-                            errorCallback,
-                            AppSearchResult.newFailedResult(
-                                    RESULT_RATE_LIMITED, "AppSearch rate limit reached."));
-                    return false;
-                }
-            } else {
-                executor.execute(lambda);
-            }
-        } catch (RuntimeException e) {
-            invokeCallbackOnError(errorCallback, e);
-        }
-        return true;
-    }
-
-    /**
-     * Helper to execute the implementation of some AppSearch functionality on the executor for that
-     * user, without invoking callback for the user.
-     *
-     * <p>You should first make sure the call is allowed to run using {@link #verifyCaller}.
-     *
-     * @param targetUser The verified user the call should run as, as determined by {@link
-     *     #verifyCaller}.
-     * @param callingPackageName Package making this lambda call.
-     * @param apiType Api type of this lambda call.
-     * @param lambda The lambda to execute on the user-provided executor.
-     * @return true if the call is accepted by the executor and false otherwise.
-     */
-    @BinderThread
-    public boolean executeLambdaForUserNoCallbackAsync(
-            @NonNull UserHandle targetUser,
-            @NonNull String callingPackageName,
-            @CallStats.CallType int apiType,
-            @NonNull Runnable lambda) {
-        Objects.requireNonNull(targetUser);
-        Objects.requireNonNull(callingPackageName);
-        Objects.requireNonNull(lambda);
-        Executor executor = mExecutorManager.getOrCreateUserExecutor(targetUser);
-        if (executor instanceof RateLimitedExecutor) {
-            return ((RateLimitedExecutor) executor).execute(lambda, callingPackageName, apiType);
-        } else {
-            executor.execute(lambda);
-            return true;
-        }
-    }
-
     /**
      * Returns the target user of the query depending on whether the query is for enterprise access
      * or not. If the query is not enterprise, returns the original target user. If the query is
diff --git a/service/java/com/android/server/appsearch/visibilitystore/VisibilityCheckerImpl.java b/service/java/com/android/server/appsearch/visibilitystore/VisibilityCheckerImpl.java
index 093190b8..3e944900 100644
--- a/service/java/com/android/server/appsearch/visibilitystore/VisibilityCheckerImpl.java
+++ b/service/java/com/android/server/appsearch/visibilitystore/VisibilityCheckerImpl.java
@@ -15,6 +15,8 @@
  */
 package com.android.server.appsearch.visibilitystore;
 
+import static android.Manifest.permission.EXECUTE_APP_FUNCTIONS;
+import static android.Manifest.permission.EXECUTE_APP_FUNCTIONS_TRUSTED;
 import static android.Manifest.permission.READ_ASSISTANT_APP_SEARCH_DATA;
 import static android.Manifest.permission.READ_CALENDAR;
 import static android.Manifest.permission.READ_CONTACTS;
@@ -31,6 +33,7 @@ import android.app.appsearch.PackageIdentifier;
 import android.app.appsearch.SchemaVisibilityConfig;
 import android.app.appsearch.SetSchemaRequest;
 import android.app.appsearch.aidl.AppSearchAttributionSource;
+import android.content.AttributionSource;
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.os.UserHandle;
@@ -318,6 +321,8 @@ public class VisibilityCheckerImpl implements VisibilityChecker {
                 case SetSchemaRequest.READ_EXTERNAL_STORAGE:
                 case SetSchemaRequest.READ_HOME_APP_SEARCH_DATA:
                 case SetSchemaRequest.READ_ASSISTANT_APP_SEARCH_DATA:
+                case SetSchemaRequest.EXECUTE_APP_FUNCTIONS:
+                case SetSchemaRequest.EXECUTE_APP_FUNCTIONS_TRUSTED:
                     if (!doesCallerHavePermissionForDataDelivery(
                             requiredPermission, callerAttributionSource)) {
                         // The calling package doesn't have this required permission, return false.
@@ -354,6 +359,10 @@ public class VisibilityCheckerImpl implements VisibilityChecker {
      * Checks whether the calling package has the corresponding Android permission to the specified
      * {@code requiredPermission}.
      */
+    // Suppressing warning about not guarding by SDK level check since this method is manually
+    // tested to work on older devices that don't have permissions declared in higher SDKs
+    // (returning false by default if permission does not exist).
+    @SuppressWarnings("InlinedApi")
     private boolean doesCallerHavePermissionForDataDelivery(
             @SetSchemaRequest.AppSearchSupportedPermission int requiredPermission,
             @NonNull AppSearchAttributionSource callerAttributionSource) {
@@ -377,16 +386,36 @@ public class VisibilityCheckerImpl implements VisibilityChecker {
             case SetSchemaRequest.READ_ASSISTANT_APP_SEARCH_DATA:
                 permission = READ_ASSISTANT_APP_SEARCH_DATA;
                 break;
+            case SetSchemaRequest.EXECUTE_APP_FUNCTIONS:
+                permission = EXECUTE_APP_FUNCTIONS;
+                break;
+            case SetSchemaRequest.EXECUTE_APP_FUNCTIONS_TRUSTED:
+                permission = EXECUTE_APP_FUNCTIONS_TRUSTED;
+                break;
             default:
                 return false;
         }
         // getAttributionSource can be safely called and the returned value will only be
         // null on Android R-
+        return checkPermissionForDataDeliveryGranted(
+                permission,
+                callerAttributionSource.getAttributionSource(),
+                /* message= */ "appsearch");
+    }
+
+    /**
+     * Checks whether permission for data delivery with {@link PermissionManager} is granted.
+     *
+     * @hide
+     */
+    @VisibleForTesting
+    public boolean checkPermissionForDataDeliveryGranted(
+            @NonNull String permission,
+            @NonNull AttributionSource attributionSource,
+            @Nullable String message) {
         return PERMISSION_GRANTED
                 == mPermissionManager.checkPermissionForDataDelivery(
-                        permission,
-                        callerAttributionSource.getAttributionSource(),
-                        /* message= */ "appsearch");
+                        permission, attributionSource, message);
     }
 
     /**
diff --git a/synced_jetpack_sha.txt b/synced_jetpack_sha.txt
index dfdbf1ae..ead1ecfc 100644
--- a/synced_jetpack_sha.txt
+++ b/synced_jetpack_sha.txt
@@ -1 +1 @@
-f217c908e6d0a8529bf287a145b20ebd77403eb8
+7eae2382f01dc1565625aab36a5263541d6a0831
diff --git a/testing/appsindexertests/Android.bp b/testing/appsindexertests/Android.bp
index fb47c202..b1def6e7 100644
--- a/testing/appsindexertests/Android.bp
+++ b/testing/appsindexertests/Android.bp
@@ -25,15 +25,16 @@ android_test {
         "CtsAppSearchTestUtils",
         "androidx.test.ext.junit",
         "androidx.test.rules",
+        "appsearch_flags_java_exported_lib",
         "compatibility-device-util-axt",
         "service-appsearch-for-tests",
         "services.core",
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
         "framework-appsearch.impl",
     ],
     test_suites: [
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImplTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImplTest.java
new file mode 100644
index 00000000..8d2162ba
--- /dev/null
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppFunctionStaticMetadataParserImplTest.java
@@ -0,0 +1,193 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.Mockito.when;
+
+import android.content.pm.PackageManager;
+import android.content.res.AssetManager;
+import android.content.res.Resources;
+
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.junit.MockitoJUnitRunner;
+
+import java.io.ByteArrayInputStream;
+import java.io.IOException;
+import java.io.InputStream;
+import java.util.List;
+
+@RunWith(MockitoJUnitRunner.class)
+public class AppFunctionStaticMetadataParserImplTest {
+
+    private static final String TEST_PACKAGE_NAME = "com.example.app";
+    private static final String TEST_INDEXER_PACKAGE_NAME = "com.android.test.indexer";
+    private static final String TEST_XML_ASSET_FILE_PATH = "app_functions.xml";
+
+    @Mock private PackageManager mPackageManager;
+    @Mock private Resources mResources;
+    @Mock private AssetManager mAssetManager;
+
+    private AppFunctionStaticMetadataParser mParser;
+
+    @Before
+    public void setUp() throws Exception {
+        mParser =
+                new AppFunctionStaticMetadataParserImpl(
+                        TEST_INDEXER_PACKAGE_NAME, /* maxAppFunctions= */ 2);
+
+        when(mPackageManager.getResourcesForApplication(TEST_PACKAGE_NAME)).thenReturn(mResources);
+        when(mResources.getAssets()).thenReturn(mAssetManager);
+    }
+
+    private void setXmlInput(String xml) throws IOException {
+        InputStream inputStream = new ByteArrayInputStream(xml.getBytes());
+        when(mAssetManager.open(TEST_XML_ASSET_FILE_PATH)).thenReturn(inputStream);
+    }
+
+    @Test
+    public void parse_singleAppFunctionWithAllProperties() throws Exception {
+        setXmlInput(
+                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
+                        + "<version>1</version>\n"
+                        + "<appfunctions>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example.utils#print</function_id>\n"
+                        + "    <schema_name>insert_note</schema_name>\n"
+                        + "    <schema_version>1</schema_version>\n"
+                        + "    <schema_category>utils</schema_category>\n"
+                        + "    <enabled_by_default>false</enabled_by_default>\n"
+                        + "    <restrict_callers_with_execute_app_functions>true\n"
+                        + "</restrict_callers_with_execute_app_functions>\n"
+                        + "    <display_name_string_res>10</display_name_string_res>\n"
+                        + "  </appfunction>\n"
+                        + "</appfunctions>");
+
+        List<AppFunctionStaticMetadata> appFunctions =
+                mParser.parse(mPackageManager, TEST_PACKAGE_NAME, TEST_XML_ASSET_FILE_PATH);
+
+        assertThat(appFunctions).hasSize(1);
+
+        AppFunctionStaticMetadata appFunction1 = appFunctions.get(0);
+        assertThat(appFunction1.getFunctionId()).isEqualTo("com.example.utils#print");
+        assertThat(appFunction1.getPackageName()).isEqualTo(TEST_PACKAGE_NAME);
+        assertThat(appFunction1.getSchemaName()).isEqualTo("insert_note");
+        assertThat(appFunction1.getSchemaVersion()).isEqualTo(1);
+        assertThat(appFunction1.getSchemaCategory()).isEqualTo("utils");
+        assertThat(appFunction1.getEnabledByDefault()).isEqualTo(false);
+        assertThat(appFunction1.getRestrictCallersWithExecuteAppFunctions()).isEqualTo(true);
+        assertThat(appFunction1.getDisplayNameStringRes()).isEqualTo(10);
+    }
+
+    @Test
+    public void parse_singleAppFunctionWithDefaults() throws Exception {
+        setXmlInput(
+                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
+                        + "<version>1</version>\n"
+                        + "<appfunctions>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example.utils#print</function_id>\n"
+                        + "  </appfunction>\n"
+                        + "</appfunctions>");
+
+        List<AppFunctionStaticMetadata> appFunctions =
+                mParser.parse(mPackageManager, TEST_PACKAGE_NAME, TEST_XML_ASSET_FILE_PATH);
+
+        assertThat(appFunctions).hasSize(1);
+
+        AppFunctionStaticMetadata appFunction1 = appFunctions.get(0);
+        assertThat(appFunction1.getFunctionId()).isEqualTo("com.example.utils#print");
+        assertThat(appFunction1.getPackageName()).isEqualTo(TEST_PACKAGE_NAME);
+        assertThat(appFunction1.getSchemaName()).isNull();
+        assertThat(appFunction1.getSchemaVersion()).isEqualTo(0);
+        assertThat(appFunction1.getSchemaCategory()).isNull();
+        assertThat(appFunction1.getEnabledByDefault()).isEqualTo(true);
+        assertThat(appFunction1.getRestrictCallersWithExecuteAppFunctions()).isEqualTo(false);
+        assertThat(appFunction1.getDisplayNameStringRes()).isEqualTo(0);
+    }
+
+    @Test
+    public void parse_missingFunctionId() throws Exception {
+        setXmlInput(
+                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
+                        + "<version>1</version>\n"
+                        + "<appfunctions>\n"
+                        + "  <appfunction>\n"
+                        + "    <schema_name>insert_note</schema_name>\n"
+                        + "    <schema_version>1</schema_version>\n"
+                        + "    <schema_category>utils</schema_category>\n"
+                        + "  </appfunction>\n"
+                        + "</appfunctions>");
+
+        List<AppFunctionStaticMetadata> appFunctions =
+                mParser.parse(mPackageManager, TEST_PACKAGE_NAME, TEST_XML_ASSET_FILE_PATH);
+
+        assertThat(appFunctions).isEmpty();
+    }
+
+    @Test
+    public void parse_malformedXml() throws Exception {
+        // Missing </functionId>
+        setXmlInput(
+                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
+                        + "<version>1</version>\n"
+                        + "<appfunctions>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example.utils#print"
+                        + "    <schema_name>insert_note</schema_name>\n"
+                        + "    <schema_version>1</schema_version>\n"
+                        + "    <schema_category>utils</schema_category>\n"
+                        + "  </appfunction>\n"
+                        + "</appfunctions>");
+
+        List<AppFunctionStaticMetadata> appFunctions =
+                mParser.parse(mPackageManager, TEST_PACKAGE_NAME, TEST_XML_ASSET_FILE_PATH);
+
+        assertThat(appFunctions).isEmpty();
+    }
+
+    @Test
+    public void parse_exceedMaxNumAppFunctions() throws Exception {
+        // maxAppFunctions was set to be 2.
+        setXmlInput(
+                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
+                        + "<version>1</version>\n"
+                        + "<appfunctions>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example#send_message1</function_id>\n"
+                        + "  </appfunction>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example#send_message2</function_id>\n"
+                        + "  </appfunction>\n"
+                        + "  <appfunction>\n"
+                        + "    <function_id>com.example#send_message3</function_id>\n"
+                        + "  </appfunction>\n"
+                        + "</appfunctions>");
+
+        List<AppFunctionStaticMetadata> appFunctions =
+                mParser.parse(mPackageManager, TEST_PACKAGE_NAME, TEST_XML_ASSET_FILE_PATH);
+
+        assertThat(appFunctions).hasSize(2);
+        assertThat(appFunctions.get(0).getFunctionId()).isEqualTo("com.example#send_message1");
+        assertThat(appFunctions.get(1).getFunctionId()).isEqualTo("com.example#send_message2");
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettingsTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettingsTest.java
new file mode 100644
index 00000000..11db7851
--- /dev/null
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppOpenEventIndexerSettingsTest.java
@@ -0,0 +1,61 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+
+import java.io.File;
+import java.io.IOException;
+
+public class AppOpenEventIndexerSettingsTest {
+
+    @Rule public TemporaryFolder mTemporaryFolder = new TemporaryFolder();
+
+    private AppOpenEventIndexerSettings mAppOpenEventIndexerSettings;
+
+    @Before
+    public void setUp() throws IOException {
+        // Create a test folder for each test
+        File baseDirectory = mTemporaryFolder.newFolder("testAppOpenEventIndexerSettings");
+        mAppOpenEventIndexerSettings = new AppOpenEventIndexerSettings(baseDirectory);
+    }
+
+    @Test
+    public void testLoadAndPersist() throws IOException {
+        // Set some values, persist them, and then load them back
+        mAppOpenEventIndexerSettings.setLastUpdateTimestampMillis(123456789L);
+        mAppOpenEventIndexerSettings.persist();
+
+        // Reset the settings to ensure loading happens from the file
+        mAppOpenEventIndexerSettings.setLastUpdateTimestampMillis(0);
+
+        mAppOpenEventIndexerSettings.load();
+        Assert.assertEquals(
+                123456789L, mAppOpenEventIndexerSettings.getLastUpdateTimestampMillis());
+    }
+
+    @Test
+    public void testReset() {
+        mAppOpenEventIndexerSettings.setLastUpdateTimestampMillis(123456789L);
+        mAppOpenEventIndexerSettings.reset();
+        Assert.assertEquals(0, mAppOpenEventIndexerSettings.getLastUpdateTimestampMillis());
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppSearchHelperTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppSearchHelperTest.java
index 2db97300..16a043b2 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppSearchHelperTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppSearchHelperTest.java
@@ -20,6 +20,7 @@ import static com.android.server.appsearch.appsindexer.TestUtils.COMPATIBLE_APP_
 import static com.android.server.appsearch.appsindexer.TestUtils.FAKE_PACKAGE_PREFIX;
 import static com.android.server.appsearch.appsindexer.TestUtils.FAKE_SIGNATURE;
 import static com.android.server.appsearch.appsindexer.TestUtils.INCOMPATIBLE_APP_SCHEMA;
+import static com.android.server.appsearch.appsindexer.TestUtils.createFakeAppFunction;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakeAppIndexerSession;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakeMobileApplication;
 import static com.android.server.appsearch.appsindexer.TestUtils.createMobileApplications;
@@ -36,7 +37,9 @@ import static org.mockito.Mockito.when;
 
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchResult;
+import android.app.appsearch.AppSearchSchema;
 import android.app.appsearch.AppSearchSessionShim;
+import android.app.appsearch.GenericDocument;
 import android.app.appsearch.GetSchemaResponse;
 import android.app.appsearch.PackageIdentifier;
 import android.app.appsearch.PutDocumentsRequest;
@@ -47,6 +50,7 @@ import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
 import com.google.common.collect.ImmutableList;
@@ -74,7 +78,7 @@ public class AppSearchHelperTest {
     @Before
     public void setUp() throws Exception {
         mContext = ApplicationProvider.getApplicationContext();
-        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        mAppSearchHelper = new AppSearchHelper(mContext);
     }
 
     @After
@@ -85,8 +89,11 @@ public class AppSearchHelperTest {
 
     @Test
     public void testAppSearchHelper_permissionSetCorrectlyForMobileApplication() throws Exception {
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(1));
-        mAppSearchHelper.indexApps(createMobileApplications(1));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(1), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                createMobileApplications(1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
         AppSearchSessionShim session =
                 createFakeAppIndexerSession(mContext, mSingleThreadedExecutor);
@@ -106,10 +113,31 @@ public class AppSearchHelperTest {
         assertThat(actual.getPackageName()).isEqualTo(expected.getPackageName());
     }
 
+    @Test
+    public void testAppSearchHelper_onlyIndexMobileApp_appFunctionParentSchemaIsNotSet()
+            throws Exception {
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(1), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                createMobileApplications(1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
+
+        AppSearchSessionShim session =
+                createFakeAppIndexerSession(mContext, mSingleThreadedExecutor);
+        GetSchemaResponse response = session.getSchemaAsync().get();
+
+        assertThat(response.getSchemas().stream().map(AppSearchSchema::getSchemaType).toList())
+                .doesNotContain(AppFunctionStaticMetadata.SCHEMA_TYPE);
+    }
+
     @Test
     public void testIndexManyApps() throws Exception {
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(600));
-        mAppSearchHelper.indexApps(createMobileApplications(600));
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(600), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                createMobileApplications(600),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         Map<String, Long> appsearchIds = mAppSearchHelper.getAppsFromAppSearch();
         assertThat(appsearchIds.size()).isEqualTo(600);
         List<SearchResult> real = searchAppSearchForApps(600 + 1);
@@ -130,10 +158,13 @@ public class AppSearchHelperTest {
                 createFakeAppIndexerSession(mContext, mSingleThreadedExecutor);
         session.setSchemaAsync(setSchemaRequest).get();
 
-        AppSearchHelper appSearchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        AppSearchHelper appSearchHelper = new AppSearchHelper(mContext);
         appSearchHelper.setSchemasForPackages(
-                ImmutableList.of(createMockPackageIdentifier(variant)));
-        appSearchHelper.indexApps(ImmutableList.of(createFakeMobileApplication(variant)));
+                ImmutableList.of(createMockPackageIdentifier(variant)), new ArrayList<>());
+        appSearchHelper.indexApps(
+                ImmutableList.of(createFakeMobileApplication(variant)),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
         assertThat(appSearchHelper).isNotNull();
         List<SearchResult> results = searchAppSearchForApps(1 + 1);
@@ -154,8 +185,11 @@ public class AppSearchHelperTest {
                         .build();
         session.setSchemaAsync(setSchemaRequest).get();
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(50));
-        mAppSearchHelper.indexApps(createMobileApplications(50));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(50), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                createMobileApplications(50),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
         List<SearchResult> real = searchAppSearchForApps(50 + 1);
         assertThat(real).hasSize(50);
@@ -171,22 +205,30 @@ public class AppSearchHelperTest {
                                 .setFailure(
                                         "id", AppSearchResult.RESULT_OUT_OF_SPACE, "errorMessage")
                                 .build());
-        AppSearchHelper mocked = AppSearchHelper.createAppSearchHelper(mContext);
-        mocked.setAppSearchSession(fullSession);
+        AppSearchHelper mocked = new AppSearchHelper(mContext);
+        mocked.setAppSearchSessionForTest(fullSession);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(1));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(1), new ArrayList<>());
         // It should throw if it's out of space
         assertThrows(
                 AppSearchException.class,
-                () -> mocked.indexApps(ImmutableList.of(createFakeMobileApplication(0))));
+                () ->
+                        mocked.indexApps(
+                                ImmutableList.of(createFakeMobileApplication(0)),
+                                /* appFunctions= */ ImmutableList.of(),
+                                /* existingAppFunctions= */ ImmutableList.of()));
     }
 
     @Test
     public void testAppSearchHelper_removeApps() throws Exception {
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(100));
-        mAppSearchHelper.indexApps(createMobileApplications(100));
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(100), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                createMobileApplications(100),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(50));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(50), new ArrayList<>());
 
         List<String> deletedIds = new ArrayList<>();
         // Last 50 ids should be removed.
@@ -205,14 +247,20 @@ public class AppSearchHelperTest {
         MobileApplication app0 = createFakeMobileApplication(0);
         MobileApplication app1 = createFakeMobileApplication(1);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2));
-        mAppSearchHelper.indexApps(ImmutableList.of(app0, app1));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         Map<String, Long> timestampMapping = mAppSearchHelper.getAppsFromAppSearch();
         assertThat(timestampMapping)
                 .containsExactly("com.fake.package0", 0L, "com.fake.package1", 1L);
 
         // Try to add the same apps
-        mAppSearchHelper.indexApps(ImmutableList.of(app0, app1));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
         // Should still be two
         timestampMapping = mAppSearchHelper.getAppsFromAppSearch();
@@ -225,8 +273,11 @@ public class AppSearchHelperTest {
         MobileApplication app0 = createFakeMobileApplication(0);
         MobileApplication app1 = createFakeMobileApplication(1);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2));
-        mAppSearchHelper.indexApps(ImmutableList.of(app0, app1));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         Map<String, Long> timestampMapping = mAppSearchHelper.getAppsFromAppSearch();
         assertThat(timestampMapping)
                 .containsExactly("com.fake.package0", 0L, "com.fake.package1", 1L);
@@ -242,7 +293,10 @@ public class AppSearchHelperTest {
                         .build();
 
         // Should update the app, not add a new one
-        mAppSearchHelper.indexApps(ImmutableList.of(app1));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         timestampMapping = mAppSearchHelper.getAppsFromAppSearch();
         assertThat(timestampMapping)
                 .containsExactly("com.fake.package0", 0L, "com.fake.package1", 300L);
@@ -253,14 +307,20 @@ public class AppSearchHelperTest {
         MobileApplication app0 = createFakeMobileApplication(0);
         MobileApplication app1 = createFakeMobileApplication(1);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2));
-        mAppSearchHelper.indexApps(ImmutableList.of(app0, app1));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         assertThat(mAppSearchHelper.getAppsFromAppSearch()).hasSize(2);
 
         MobileApplication app2 = createFakeMobileApplication(2);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(3));
-        mAppSearchHelper.indexApps(ImmutableList.of(app0, app1, app2));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(3), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1, app2),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
 
         // Should be three
         Map<String, Long> timestampMapping = mAppSearchHelper.getAppsFromAppSearch();
@@ -268,4 +328,98 @@ public class AppSearchHelperTest {
                 .containsExactly(
                         "com.fake.package0", 0L, "com.fake.package1", 1L, "com.fake.package2", 2L);
     }
+
+    @Test
+    public void test_newAppFunction_indexed() throws Exception {
+        // Set up 2 MobileApplications.
+        MobileApplication app0 = createFakeMobileApplication(0);
+        MobileApplication app1 = createFakeMobileApplication(1);
+
+        // initially, no apps has app functions.
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(2), createMockPackageIdentifiers(0));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
+        assertThat(mAppSearchHelper.getAppFunctionsFromAppSearch()).isEmpty();
+
+        // Now app0 has an app function.
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(2), createMockPackageIdentifiers(1));
+        AppFunctionStaticMetadata app0Function0 = createFakeAppFunction(0, 0, mContext);
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(app0Function0),
+                /* existingAppFunctions= */ ImmutableList.of(app0Function0));
+
+        assertThat(mAppSearchHelper.getAppFunctionsFromAppSearch().get(0).getId())
+                .isEqualTo("com.fake.package0/function_id0");
+    }
+
+    @Test
+    public void test_newAppFunction_parentSchemaIsInserted() throws Exception {
+        // Set up 1 MobileApplications with an app function.
+        MobileApplication app0 = createFakeMobileApplication(0);
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(1), createMockPackageIdentifiers(1));
+        AppFunctionStaticMetadata app0Function0 = createFakeAppFunction(0, 0, mContext);
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0),
+                /* appFunctions= */ ImmutableList.of(app0Function0),
+                /* existingAppFunctions= */ ImmutableList.of());
+
+        AppSearchSessionShim session =
+                createFakeAppIndexerSession(mContext, mSingleThreadedExecutor);
+        GetSchemaResponse response = session.getSchemaAsync().get();
+        assertThat(response.getSchemas().stream().map(AppSearchSchema::getSchemaType).toList())
+                .contains(AppFunctionStaticMetadata.SCHEMA_TYPE);
+    }
+
+    @Test
+    public void test_appFunctionRemoved_indexed() throws Exception {
+        // Set up 2 MobileApplications.
+        MobileApplication app0 = createFakeMobileApplication(0);
+        MobileApplication app1 = createFakeMobileApplication(1);
+        // initially, app0 has two app functions.
+        AppFunctionStaticMetadata app0Function0 = createFakeAppFunction(0, 0, mContext);
+        AppFunctionStaticMetadata app0Function1 = createFakeAppFunction(0, 1, mContext);
+
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(2), createMockPackageIdentifiers(1));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(app0Function0, app0Function1),
+                /* existingAppFunctions= */ ImmutableList.of());
+        List<GenericDocument> appFunctionsInAppSearch =
+                mAppSearchHelper.getAppFunctionsFromAppSearch();
+        assertThat(appFunctionsInAppSearch).hasSize(2);
+        List<String> ids = new ArrayList<>();
+        ids.add(appFunctionsInAppSearch.get(0).getId());
+        ids.add(appFunctionsInAppSearch.get(1).getId());
+        assertThat(ids)
+                .containsExactly(
+                        "com.fake.package0/function_id0", "com.fake.package0/function_id1");
+
+        // Now we remove one app function from app0
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(2), createMockPackageIdentifiers(1));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(app0Function0),
+                /* existingAppFunctions= */ ImmutableList.of(app0Function0, app0Function1));
+        // app0 still have one app function. so app0 is being indexed.
+        assertThat(mAppSearchHelper.getAppFunctionsFromAppSearch().get(0).getId())
+                .isEqualTo("com.fake.package0/function_id0");
+
+        // We remove the last app function from app0.
+        mAppSearchHelper.setSchemasForPackages(
+                createMockPackageIdentifiers(2), createMockPackageIdentifiers(0));
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app0, app1),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of(app0Function0));
+        // App0 is no longer indexed for app functions cause it no longer has any of them.
+        assertThat(mAppSearchHelper.getAppFunctionsFromAppSearch()).isEmpty();
+    }
 }
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerImplTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerImplTest.java
index 20c4d05b..63ef8079 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerImplTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerImplTest.java
@@ -30,7 +30,9 @@ import static org.mockito.Mockito.when;
 
 import android.content.Context;
 import android.content.ContextWrapper;
+import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
+import android.content.pm.ResolveInfo;
 
 import androidx.test.core.app.ApplicationProvider;
 
@@ -56,11 +58,12 @@ public class AppsIndexerImplTest {
     private Context mContext;
     @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();
     private final ExecutorService mSingleThreadedExecutor = Executors.newSingleThreadExecutor();
+    private final AppsIndexerConfig mAppsIndexerConfig = new TestAppsIndexerConfig();
 
     @Before
     public void setUp() throws Exception {
         mContext = ApplicationProvider.getApplicationContext();
-        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        mAppSearchHelper = new AppSearchHelper(mContext);
     }
 
     @After
@@ -75,8 +78,11 @@ public class AppsIndexerImplTest {
         MobileApplication app1 = createFakeMobileApplication(0);
         MobileApplication app2 = createFakeMobileApplication(1);
 
-        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2));
-        mAppSearchHelper.indexApps(ImmutableList.of(app1, app2));
+        mAppSearchHelper.setSchemasForPackages(createMockPackageIdentifiers(2), new ArrayList<>());
+        mAppSearchHelper.indexApps(
+                ImmutableList.of(app1, app2),
+                /* appFunctions= */ ImmutableList.of(),
+                /* existingAppFunctions= */ ImmutableList.of());
         Map<String, Long> appTimestampMap = mAppSearchHelper.getAppsFromAppSearch();
 
         List<String> packageIds = new ArrayList<>(appTimestampMap.keySet());
@@ -84,7 +90,11 @@ public class AppsIndexerImplTest {
 
         // Set up mock so that just 1 document is returned, as if we deleted a doc
         PackageManager pm = Mockito.mock(PackageManager.class);
-        setupMockPackageManager(pm, createFakePackageInfos(1), createFakeResolveInfos(1));
+        setupMockPackageManager(
+                pm,
+                createFakePackageInfos(1),
+                createFakeResolveInfos(1),
+                /* appFunctionServices= */ ImmutableList.of());
         Context context =
                 new ContextWrapper(mContext) {
                     @Override
@@ -92,8 +102,10 @@ public class AppsIndexerImplTest {
                         return pm;
                     }
                 };
-        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context)) {
-            appsIndexerImpl.doUpdate(new AppsIndexerSettings(temporaryFolder.newFolder("temp")));
+        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context, mAppsIndexerConfig)) {
+            appsIndexerImpl.doUpdate(
+                    new AppsIndexerSettings(temporaryFolder.newFolder("temp")),
+                    new AppsUpdateStats());
 
             assertThat(mAppSearchHelper.getAppsFromAppSearch().keySet())
                     .containsExactly("com.fake.package0");
@@ -111,11 +123,86 @@ public class AppsIndexerImplTest {
                         return pm;
                     }
                 };
-        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context)) {
-            appsIndexerImpl.doUpdate(new AppsIndexerSettings(temporaryFolder.newFolder("tmp")));
+        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context, mAppsIndexerConfig)) {
+            appsIndexerImpl.doUpdate(
+                    new AppsIndexerSettings(temporaryFolder.newFolder("tmp")),
+                    new AppsUpdateStats());
 
             // Shouldn't throw, but no apps indexed
             assertThat(mAppSearchHelper.getAppsFromAppSearch()).isEmpty();
         }
     }
+
+    @Test
+    public void testAppsIndexerImpl_statsSet() throws Exception {
+        // Simulate the first update: no changes, just adding initial apps
+        PackageManager pm1 = Mockito.mock(PackageManager.class);
+        setupMockPackageManager(
+                pm1,
+                createFakePackageInfos(3),
+                createFakeResolveInfos(3),
+                /* appFunctionServices= */ ImmutableList.of());
+        Context context1 =
+                new ContextWrapper(mContext) {
+                    @Override
+                    public PackageManager getPackageManager() {
+                        return pm1;
+                    }
+                };
+
+        // Perform the first update
+        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context1, mAppsIndexerConfig)) {
+            AppsUpdateStats stats1 = new AppsUpdateStats();
+            appsIndexerImpl.doUpdate(
+                    new AppsIndexerSettings(temporaryFolder.newFolder("temp1")), stats1);
+
+            // Check the stats object after the first update
+            assertThat(stats1.mNumberOfAppsAdded).isEqualTo(3); // Three new apps added
+            assertThat(stats1.mNumberOfAppsRemoved).isEqualTo(0); // No apps deleted
+            assertThat(stats1.mNumberOfAppsUnchanged).isEqualTo(0); // No apps unchanged
+            assertThat(stats1.mNumberOfAppsUpdated).isEqualTo(0); // No apps updated
+
+            // Verify the state of the indexed apps after the first update
+            assertThat(mAppSearchHelper.getAppsFromAppSearch().keySet())
+                    .containsExactly("com.fake.package0", "com.fake.package1", "com.fake.package2");
+        }
+
+        PackageManager pm2 = Mockito.mock(PackageManager.class);
+        // Simulate the second update: one app updated, one unchanged, one deleted, and one new
+        // added. We'll remove package0, update package1, leave package2 unchanged, and add
+        // package3.
+        List<PackageInfo> fakePackages = new ArrayList<>(createFakePackageInfos(4));
+        List<ResolveInfo> fakeActivities = new ArrayList<>(createFakeResolveInfos(4));
+        int updateIndex = 1;
+        fakePackages.get(updateIndex).lastUpdateTime = 1000;
+        fakePackages.remove(0);
+        fakeActivities.remove(0);
+
+        setupMockPackageManager(
+                pm2, fakePackages, fakeActivities, /* appFunctionServices= */ ImmutableList.of());
+        Context context2 =
+                new ContextWrapper(mContext) {
+                    @Override
+                    public PackageManager getPackageManager() {
+                        return pm2;
+                    }
+                };
+
+        // Perform the second update
+        try (AppsIndexerImpl appsIndexerImpl = new AppsIndexerImpl(context2, mAppsIndexerConfig)) {
+            AppsUpdateStats stats2 = new AppsUpdateStats();
+            appsIndexerImpl.doUpdate(
+                    new AppsIndexerSettings(temporaryFolder.newFolder("temp2")), stats2);
+
+            // Check the stats object after the second update
+            assertThat(stats2.mNumberOfAppsAdded).isEqualTo(1); // One new app added
+            assertThat(stats2.mNumberOfAppsRemoved).isEqualTo(1); // One app deleted
+            assertThat(stats2.mNumberOfAppsUnchanged).isEqualTo(1); // One app unchanged
+            assertThat(stats2.mNumberOfAppsUpdated).isEqualTo(1); // One app updated
+
+            // Verify the state of the indexed apps after the second update
+            assertThat(mAppSearchHelper.getAppsFromAppSearch().keySet())
+                    .containsExactly("com.fake.package1", "com.fake.package2", "com.fake.package3");
+        }
+    }
 }
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerManagerServiceTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerManagerServiceTest.java
index cf3f2479..96cb92c2 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerManagerServiceTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerManagerServiceTest.java
@@ -20,9 +20,9 @@ import static android.Manifest.permission.INTERACT_ACROSS_USERS_FULL;
 import static android.Manifest.permission.RECEIVE_BOOT_COMPLETED;
 
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakeAppIndexerSession;
+import static com.android.server.appsearch.appsindexer.TestUtils.createFakeLaunchResolveInfo;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakePackageInfo;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakePackageInfos;
-import static com.android.server.appsearch.appsindexer.TestUtils.createFakeResolveInfo;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakeResolveInfos;
 import static com.android.server.appsearch.appsindexer.TestUtils.setupMockPackageManager;
 
@@ -61,6 +61,8 @@ import androidx.test.platform.app.InstrumentationRegistry;
 import com.android.server.SystemService;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
+import com.google.common.collect.ImmutableList;
+
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
@@ -163,7 +165,11 @@ public class AppsIndexerManagerServiceTest extends AppsIndexerTestBase {
         List<PackageInfo> fakePackages = new ArrayList<>(createFakePackageInfos(numFakePackages));
         List<ResolveInfo> fakeActivities = new ArrayList<>(createFakeResolveInfos(numFakePackages));
 
-        setupMockPackageManager(mPackageManager, fakePackages, fakeActivities);
+        setupMockPackageManager(
+                mPackageManager,
+                fakePackages,
+                fakeActivities,
+                /* appFunctionServices= */ ImmutableList.of());
 
         UserInfo userInfo =
                 new UserInfo(
@@ -214,7 +220,11 @@ public class AppsIndexerManagerServiceTest extends AppsIndexerTestBase {
         List<PackageInfo> fakePackages = new ArrayList<>(createFakePackageInfos(numFakePackages));
         List<ResolveInfo> fakeActivities = new ArrayList<>(createFakeResolveInfos(numFakePackages));
 
-        setupMockPackageManager(mPackageManager, fakePackages, fakeActivities);
+        setupMockPackageManager(
+                mPackageManager,
+                fakePackages,
+                fakeActivities,
+                /* appFunctionServices= */ ImmutableList.of());
 
         UserInfo userInfo =
                 new UserInfo(
@@ -240,7 +250,7 @@ public class AppsIndexerManagerServiceTest extends AppsIndexerTestBase {
 
         // Add a package at index numFakePackages
         fakePackages.add(createFakePackageInfo(numFakePackages));
-        fakeActivities.add(createFakeResolveInfo(numFakePackages));
+        fakeActivities.add(createFakeLaunchResolveInfo(numFakePackages));
         CountDownLatch latch = setupLatch(1, /* listenForSchemaChanges= */ false);
 
         mCapturedReceiver.onReceive(mContext, fakeIntent);
@@ -268,7 +278,11 @@ public class AppsIndexerManagerServiceTest extends AppsIndexerTestBase {
         List<PackageInfo> fakePackages = new ArrayList<>(createFakePackageInfos(numFakePackages));
         List<ResolveInfo> fakeActivities = new ArrayList<>(createFakeResolveInfos(numFakePackages));
 
-        setupMockPackageManager(mPackageManager, fakePackages, fakeActivities);
+        setupMockPackageManager(
+                mPackageManager,
+                fakePackages,
+                fakeActivities,
+                /* appFunctionServices= */ ImmutableList.of());
 
         UserInfo userInfo =
                 new UserInfo(
@@ -333,7 +347,11 @@ public class AppsIndexerManagerServiceTest extends AppsIndexerTestBase {
         List<PackageInfo> fakePackages = new ArrayList<>(createFakePackageInfos(numFakePackages));
         List<ResolveInfo> fakeActivities = new ArrayList<>(createFakeResolveInfos(numFakePackages));
 
-        setupMockPackageManager(mPackageManager, fakePackages, fakeActivities);
+        setupMockPackageManager(
+                mPackageManager,
+                fakePackages,
+                fakeActivities,
+                /* appFunctionServices= */ ImmutableList.of());
 
         UserInfo userInfo =
                 new UserInfo(
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerRealDocumentsTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerRealDocumentsTest.java
index 7f759a79..4f066351 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerRealDocumentsTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerRealDocumentsTest.java
@@ -46,6 +46,7 @@ import android.net.Uri;
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.platform.app.InstrumentationRegistry;
 
+import com.android.appsearch.flags.Flags;
 import com.android.server.SystemService;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
@@ -76,6 +77,7 @@ public class AppsIndexerRealDocumentsTest extends AppsIndexerTestBase {
         UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
         uiAutomation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG);
         assumeTrue(new FrameworkAppsIndexerConfig().isAppsIndexerEnabled());
+        assumeTrue(Flags.appsIndexerEnabled());
         // Ensure that all documents in the android package and with the "apps" namespace are
         // MobileApplication documents. Read-only test as we are dealing with real apps
         SearchSpec searchSpec =
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerSettingsTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerSettingsTest.java
index da1b8df0..e12d2841 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerSettingsTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerSettingsTest.java
@@ -27,8 +27,7 @@ import java.io.IOException;
 
 public class AppsIndexerSettingsTest {
 
-    @Rule
-    public TemporaryFolder mTemporaryFolder = new TemporaryFolder();
+    @Rule public TemporaryFolder mTemporaryFolder = new TemporaryFolder();
 
     private AppsIndexerSettings mIndexerSettings;
 
@@ -68,5 +67,3 @@ public class AppsIndexerSettingsTest {
         Assert.assertEquals(0, mIndexerSettings.getLastAppUpdateTimestampMillis());
     }
 }
-;
-
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerUserInstanceTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerUserInstanceTest.java
index cf0dd6de..f191c659 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerUserInstanceTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsIndexerUserInstanceTest.java
@@ -44,6 +44,9 @@ import android.os.UserHandle;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.server.appsearch.indexer.IndexerSettings;
+
+import com.google.common.collect.ImmutableList;
 
 import org.junit.After;
 import org.junit.Before;
@@ -63,7 +66,7 @@ import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 
 public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
-    private TestContext mContext;
+    private TestContext mTestContext;
     private final PackageManager mMockPackageManager = mock(PackageManager.class);
 
     @Rule public TemporaryFolder mTemporaryFolder = new TemporaryFolder();
@@ -79,7 +82,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     public void setUp() throws Exception {
         super.setUp();
         Context context = ApplicationProvider.getApplicationContext();
-        mContext = new TestContext(context);
+        mTestContext = new TestContext(context);
 
         mSingleThreadedExecutor =
                 new ThreadPoolExecutor(
@@ -94,13 +97,13 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         mSettingsFile = new File(mAppsDir, AppsIndexerSettings.SETTINGS_FILE_NAME);
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
     }
 
     @After
     @Override
     public void tearDown() throws Exception {
-        TestUtils.removeFakePackageDocuments(mContext, Executors.newSingleThreadExecutor());
+        TestUtils.removeFakePackageDocuments(mTestContext, Executors.newSingleThreadExecutor());
         mSingleThreadedExecutor.shutdownNow();
         mInstance.shutdown();
         super.tearDown();
@@ -126,11 +129,14 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 };
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
 
         // Pretend there's one package on device
         setupMockPackageManager(
-                mMockPackageManager, createFakePackageInfos(1), createFakeResolveInfos(1));
+                mMockPackageManager,
+                createFakePackageInfos(1),
+                createFakeResolveInfos(1),
+                /* appFunctionServices= */ ImmutableList.of());
 
         // Wait for file setup, as file setup uses the same ExecutorService.
         semaphore.acquire();
@@ -145,7 +151,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         }
 
         assertThat(mSingleThreadedExecutor.getCompletedTaskCount()).isEqualTo(beforeFirstRun + 1);
-        try (AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext)) {
+        try (AppSearchHelper searchHelper = new AppSearchHelper(mTestContext)) {
             Map<String, Long> appsTimestampMap = searchHelper.getAppsFromAppSearch();
             assertThat(appsTimestampMap).hasSize(1);
             assertThat(appsTimestampMap.keySet()).containsExactly("com.fake.package0");
@@ -156,6 +162,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     public void testFirstRun_updateAlreadyRan_doesNotUpdate() throws Exception {
         // Pretend we already ran
         AppsIndexerSettings settings = new AppsIndexerSettings(mAppsDir);
+        mAppsDir.mkdirs();
         settings.setLastUpdateTimestampMillis(1000);
         settings.persist();
 
@@ -177,11 +184,14 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 };
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
 
         // Pretend there's one package on device
         setupMockPackageManager(
-                mMockPackageManager, createFakePackageInfos(1), createFakeResolveInfos(1));
+                mMockPackageManager,
+                createFakePackageInfos(1),
+                createFakeResolveInfos(1),
+                /* appFunctionServices= */ ImmutableList.of());
 
         // Wait for file setup, as file setup uses the same ExecutorService.
         semaphore.acquire();
@@ -202,7 +212,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
 
         // Even though a task ran and we got 1 app ready, we requested a "firstRun" but the
         // timestamp was not 0, so nothing should've been indexed
-        try (AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext)) {
+        try (AppSearchHelper searchHelper = new AppSearchHelper(mTestContext)) {
             assertThat(searchHelper.getAppsFromAppSearch()).isEmpty();
         }
     }
@@ -262,7 +272,8 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(numOfNotifications / 10),
-                createFakeResolveInfos(numOfNotifications / 10));
+                createFakeResolveInfos(numOfNotifications / 10),
+                /* appFunctionServices= */ ImmutableList.of());
 
         // Schedule a bunch of tasks. However, only one will run, and one other will be scheduled
         for (int i = 0; i < numOfNotifications / 2; i++) {
@@ -286,7 +297,8 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(numOfNotifications),
-                createFakeResolveInfos(numOfNotifications));
+                createFakeResolveInfos(numOfNotifications),
+                /* appFunctionServices= */ ImmutableList.of());
         for (int i = numOfNotifications / 2; i < numOfNotifications; i++) {
             mInstance.updateAsync(/* firstRun= */ false);
         }
@@ -334,7 +346,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                                 () -> {
                                     AppsIndexerUserInstance unused =
                                             AppsIndexerUserInstance.createInstance(
-                                                    mContext,
+                                                    mTestContext,
                                                     dataDir,
                                                     mAppsIndexerConfig,
                                                     mSingleThreadedExecutor);
@@ -355,13 +367,14 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
         CountDownLatch latch = setupLatch(docCount);
 
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
         latch.await(10, TimeUnit.SECONDS);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        AppSearchHelper searchHelper = new AppSearchHelper(mTestContext);
         Map<String, Long> appIds = searchHelper.getAppsFromAppSearch();
         assertThat(appIds.size()).isEqualTo(docCount);
     }
@@ -372,8 +385,9 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
-        mInstance.doUpdate(/* firstRun= */ false);
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
         AppsIndexerSettings settings = new AppsIndexerSettings(mAppsDir);
         settings.load();
@@ -392,20 +406,26 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         // of them when we "remove" four apps.
 
         setupMockPackageManager(
-                mMockPackageManager, createFakePackageInfos(10), createFakeResolveInfos(10));
+                mMockPackageManager,
+                createFakePackageInfos(10),
+                createFakeResolveInfos(10),
+                /* appFunctionServices= */ ImmutableList.of());
 
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        AppSearchHelper searchHelper = new AppSearchHelper(mTestContext);
         Map<String, Long> appIds = searchHelper.getAppsFromAppSearch();
         assertThat(appIds.size()).isEqualTo(10);
 
         setupMockPackageManager(
-                mMockPackageManager, createFakePackageInfos(6), createFakeResolveInfos(6));
+                mMockPackageManager,
+                createFakePackageInfos(6),
+                createFakeResolveInfos(6),
+                /* appFunctionServices= */ ImmutableList.of());
 
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
-        searchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        searchHelper = new AppSearchHelper(mTestContext);
         appIds = searchHelper.getAppsFromAppSearch();
         assertThat(appIds.size()).isEqualTo(6);
         assertThat(appIds.keySet())
@@ -416,7 +436,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                         TestUtils.FAKE_PACKAGE_PREFIX + "9");
 
         PersistableBundle settingsBundle = AppsIndexerSettings.readBundle(mSettingsFile);
-        assertThat(settingsBundle.getLong(AppsIndexerSettings.LAST_UPDATE_TIMESTAMP_KEY))
+        assertThat(settingsBundle.getLong(IndexerSettings.LAST_UPDATE_TIMESTAMP_KEY))
                 .isAtLeast(timeBeforeChangeNotification);
 
         // The last updated app was still the "9" app
@@ -427,7 +447,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     @Test
     public void testStart_initialRun_schedulesUpdateJob() throws Exception {
         JobScheduler mockJobScheduler = mock(JobScheduler.class);
-        mContext.setJobScheduler(mockJobScheduler);
+        mTestContext.setJobScheduler(mockJobScheduler);
         // This semaphore allows us to make sure that a sync has finished running before performing
         // checks.
         final Semaphore afterSemaphore = new Semaphore(0);
@@ -446,7 +466,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 };
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
         // Wait for settings initialization
         afterSemaphore.acquire();
 
@@ -455,7 +475,8 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
 
         mInstance.updateAsync(/* firstRun= */ true);
 
@@ -474,7 +495,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     @Test
     public void testStart_subsequentRunWithNoScheduledJob_schedulesUpdateJob() throws Exception {
         // Trigger an initial update.
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
         // This semaphore allows us to pause test execution until we're sure the tasks in
         // AppsIndexerUserInstance (scheduling the maintenance job) are finished.
@@ -497,11 +518,11 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         // scenario where the scheduled update job after the initial run is cancelled
         // due to some reason.
         JobScheduler mockJobScheduler = mock(JobScheduler.class);
-        mContext.setJobScheduler(mockJobScheduler);
+        mTestContext.setJobScheduler(mockJobScheduler);
         // the update should be zero, and if not it's because of mAppsDir
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
 
         // Wait for file setup, as file setup uses the same ExecutorService.
         semaphore.acquire();
@@ -511,7 +532,8 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
 
         mInstance.updateAsync(/* firstRun= */ false);
 
@@ -544,7 +566,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
 
         // The current schema is compatible, and an update will be triggered
         JobScheduler mockJobScheduler = mock(JobScheduler.class);
-        mContext.setJobScheduler(mockJobScheduler);
+        mTestContext.setJobScheduler(mockJobScheduler);
         // This semaphore allows us to make sure that a sync has finished running before performing
         // checks.
         final Semaphore afterSemaphore = new Semaphore(0);
@@ -563,7 +585,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 };
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
         // Wait for settings initialization
         afterSemaphore.acquire();
 
@@ -615,17 +637,18 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
 
         // Since the current schema is incompatible, it will overwrite it
         JobScheduler mockJobScheduler = mock(JobScheduler.class);
-        mContext.setJobScheduler(mockJobScheduler);
+        mTestContext.setJobScheduler(mockJobScheduler);
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
         // Wait for file setup, as file setup uses the same ExecutorService.
         semaphore.acquire();
 
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
 
         mInstance.updateAsync(/* firstRun= */ true);
         // Wait for all async tasks to complete
@@ -644,7 +667,10 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     public void testConcurrentUpdates_updatesDoNotInterfereWithEachOther() throws Exception {
         long timeBeforeChangeNotification = System.currentTimeMillis();
         setupMockPackageManager(
-                mMockPackageManager, createFakePackageInfos(250), createFakeResolveInfos(250));
+                mMockPackageManager,
+                createFakePackageInfos(250),
+                createFakeResolveInfos(250),
+                /* appFunctionServices= */ ImmutableList.of());
         // This semaphore allows us to make sure that a sync has finished running before performing
         // checks.
         final Semaphore afterSemaphore = new Semaphore(0);
@@ -663,27 +689,28 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 };
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
         // Wait for settings initialization
         afterSemaphore.acquire();
 
         // As there is nothing else in the executor queue, it should run soon.
         Future<?> unused =
-                mSingleThreadedExecutor.submit(() -> mInstance.doUpdate(/* firstRun= */ false));
+                mSingleThreadedExecutor.submit(
+                        () -> mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats()));
 
         // On the current thread, this update will run at the same time as the task on the executor.
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
         // By waiting for the single threaded executor to finish after calling doUpdate, both
         // updates are guaranteed to be finished.
         afterSemaphore.acquire();
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext);
+        AppSearchHelper searchHelper = new AppSearchHelper(mTestContext);
         Map<String, Long> appIds = searchHelper.getAppsFromAppSearch();
         assertThat(appIds.size()).isEqualTo(250);
 
         PersistableBundle settingsBundle = AppsIndexerSettings.readBundle(mSettingsFile);
-        assertThat(settingsBundle.getLong(AppsIndexerSettings.LAST_UPDATE_TIMESTAMP_KEY))
+        assertThat(settingsBundle.getLong(IndexerSettings.LAST_UPDATE_TIMESTAMP_KEY))
                 .isAtLeast(timeBeforeChangeNotification);
     }
 
@@ -691,7 +718,7 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
     public void testStart_subsequentRunWithScheduledJob_doesNotScheduleUpdateJob()
             throws Exception {
         // Trigger an initial update.
-        mInstance.doUpdate(/* firstRun= */ false);
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
         JobScheduler mockJobScheduler = mock(JobScheduler.class);
         JobInfo mockJobInfo = mock(JobInfo.class);
@@ -701,19 +728,20 @@ public class AppsIndexerUserInstanceTest extends AppsIndexerTestBase {
                 .when(mockJobScheduler)
                 .getPendingJob(
                         AppsIndexerMaintenanceConfig.MIN_APPS_INDEXER_JOB_ID
-                                + mContext.getUser().getIdentifier());
-        mContext.setJobScheduler(mockJobScheduler);
+                                + mTestContext.getUser().getIdentifier());
+        mTestContext.setJobScheduler(mockJobScheduler);
         mInstance =
                 AppsIndexerUserInstance.createInstance(
-                        mContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
+                        mTestContext, mAppsDir, mAppsIndexerConfig, mSingleThreadedExecutor);
 
         int docCount = 10;
         CountDownLatch latch = setupLatch(docCount);
         setupMockPackageManager(
                 mMockPackageManager,
                 createFakePackageInfos(docCount),
-                createFakeResolveInfos(docCount));
-        mInstance.doUpdate(/* firstRun= */ false);
+                createFakeResolveInfos(docCount),
+                /* appFunctionServices= */ ImmutableList.of());
+        mInstance.doUpdate(/* firstRun= */ false, new AppsUpdateStats());
 
         mInstance.updateAsync(/* firstRun= */ false);
 
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsUtilTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsUtilTest.java
index 166a8150..34eca74c 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsUtilTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/AppsUtilTest.java
@@ -16,54 +16,75 @@
 
 package com.android.server.appsearch.appsindexer;
 
+import static com.android.server.appsearch.appsindexer.TestUtils.createFakeAppFunctionResolveInfo;
+import static com.android.server.appsearch.appsindexer.TestUtils.createFakeLaunchResolveInfo;
 import static com.android.server.appsearch.appsindexer.TestUtils.createFakePackageInfo;
-import static com.android.server.appsearch.appsindexer.TestUtils.createFakeResolveInfo;
+import static com.android.server.appsearch.appsindexer.TestUtils.createIndividualUsageEvent;
+import static com.android.server.appsearch.appsindexer.TestUtils.createUsageEvents;
 import static com.android.server.appsearch.appsindexer.TestUtils.setupMockPackageManager;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.when;
+
+import android.app.usage.UsageEvents;
+import android.app.usage.UsageStatsManager;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
+import android.content.res.AssetManager;
+import android.content.res.Resources;
 import android.util.ArrayMap;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
+import com.google.common.collect.ImmutableList;
+
 import org.junit.Test;
 import org.mockito.Mockito;
 
+import java.io.ByteArrayInputStream;
 import java.util.ArrayList;
+import java.util.Calendar;
 import java.util.List;
 import java.util.Map;
 
 /** This tests that we can convert what comes from PackageManager to a MobileApplication */
 public class AppsUtilTest {
+
     @Test
     public void testBuildAppsFromPackageInfos_ReturnsNonNullList() throws Exception {
         PackageManager pm = Mockito.mock(PackageManager.class);
         // Populate fake PackageManager with 10 Packages.
         List<PackageInfo> fakePackages = new ArrayList<>();
         List<ResolveInfo> fakeActivities = new ArrayList<>();
-        Map<PackageInfo, ResolveInfo> packageActivityMapping = new ArrayMap<>();
+        Map<PackageInfo, ResolveInfos> packageLaunchActivityMapping = new ArrayMap<>();
 
         for (int i = 0; i < 10; i++) {
             fakePackages.add(createFakePackageInfo(i));
-            fakeActivities.add(createFakeResolveInfo(i));
+            fakeActivities.add(createFakeLaunchResolveInfo(i));
         }
 
         // Package manager "has" 10 fake packages, but we're choosing just 5 of them to simulate the
         // case that not all the apps need to be synced. For example, 5 new apps were added and the
         // rest of the existing apps don't need to be re-indexed.
         for (int i = 0; i < 5; i++) {
-            packageActivityMapping.put(fakePackages.get(i), fakeActivities.get(i));
+            packageLaunchActivityMapping.put(
+                    fakePackages.get(i), new ResolveInfos(null, fakeActivities.get(i)));
         }
 
-        setupMockPackageManager(pm, fakePackages, fakeActivities);
+        setupMockPackageManager(
+                pm, fakePackages, fakeActivities, /* appFunctionServices= */ ImmutableList.of());
         List<MobileApplication> resultApps =
-                AppsUtil.buildAppsFromPackageInfos(pm, packageActivityMapping);
+                AppsUtil.buildAppsFromPackageInfos(pm, packageLaunchActivityMapping);
 
         assertThat(resultApps).hasSize(5);
         List<String> packageNames = new ArrayList<>();
@@ -80,17 +101,135 @@ public class AppsUtilTest {
     }
 
     @Test
-    public void testBuildRealApps() {
+    public void testBuildRealApps_returnsNonEmptyList() {
         // This shouldn't crash, and shouldn't be an empty list
         Context context = ApplicationProvider.getApplicationContext();
-        Map<PackageInfo, ResolveInfo> packageActivityMapping =
-                AppsUtil.getLaunchablePackages(context.getPackageManager());
+        Map<PackageInfo, ResolveInfos> packageActivityMapping =
+                AppsUtil.getPackagesToIndex(context.getPackageManager());
         List<MobileApplication> resultApps =
                 AppsUtil.buildAppsFromPackageInfos(
                         context.getPackageManager(), packageActivityMapping);
 
         assertThat(resultApps).isNotEmpty();
-        assertThat(resultApps.get(0).getDisplayName()).isNotEmpty();
     }
-}
 
+    // TODO(b/361879099): Add a test that checks that building apps from real PackageManager info
+    // results in non-empty documents
+
+    @Test
+    public void testRealUsageStatsManager() {
+        UsageStatsManager mockUsageStatsManager = Mockito.mock(UsageStatsManager.class);
+
+        UsageEvents.Event[] events =
+                new UsageEvents.Event[] {
+                    createIndividualUsageEvent(
+                            UsageEvents.Event.MOVE_TO_FOREGROUND, 1000L, "com.example.package"),
+                    createIndividualUsageEvent(
+                            UsageEvents.Event.ACTIVITY_RESUMED, 2000L, "com.example.package"),
+                    createIndividualUsageEvent(
+                            UsageEvents.Event.MOVE_TO_FOREGROUND, 3000L, "com.example.package2"),
+                    createIndividualUsageEvent(
+                            UsageEvents.Event.MOVE_TO_BACKGROUND, 4000L, "com.example.package2")
+                };
+
+        UsageEvents mockUsageEvents = createUsageEvents(events);
+        when(mockUsageStatsManager.queryEvents(anyLong(), anyLong())).thenReturn(mockUsageEvents);
+
+        Map<String, List<Long>> appOpenTimestamps =
+                AppsUtil.getAppOpenTimestamps(
+                        mockUsageStatsManager, 0, Calendar.getInstance().getTimeInMillis());
+
+        assertThat(appOpenTimestamps)
+                .containsExactly(
+                        "com.example.package", List.of(1000L, 2000L),
+                        "com.example.package2", List.of(3000L));
+    }
+
+    @Test
+    public void testRetrieveAppFunctionResolveInfo() throws Exception {
+        // Set up fake PackageManager with 10 Packages and 10 AppFunctions
+        PackageManager pm = Mockito.mock(PackageManager.class);
+        List<PackageInfo> fakePackages = new ArrayList<>();
+        List<ResolveInfo> fakeActivities = new ArrayList<>();
+        List<ResolveInfo> fakeAppFunctionServices = new ArrayList<>();
+
+        for (int i = 0; i < 10; i++) {
+            fakePackages.add(createFakePackageInfo(i));
+            fakeActivities.add(createFakeLaunchResolveInfo(i));
+            fakeAppFunctionServices.add(createFakeAppFunctionResolveInfo(i));
+        }
+
+        setupMockPackageManager(pm, fakePackages, fakeActivities, fakeAppFunctionServices);
+
+        Map<PackageInfo, ResolveInfos> packageActivityMapping = AppsUtil.getPackagesToIndex(pm);
+
+        // Make assertions
+        assertThat(packageActivityMapping).hasSize(10);
+        for (PackageInfo packageInfo : packageActivityMapping.keySet()) {
+            assertThat(packageInfo.packageName).startsWith("com.fake.package");
+        }
+        assertThat(packageActivityMapping.values()).hasSize(10);
+        for (ResolveInfos targetedResolveInfo : packageActivityMapping.values()) {
+            assertThat(targetedResolveInfo.getLaunchActivityResolveInfo().activityInfo.packageName)
+                    .isEqualTo(
+                            targetedResolveInfo.getAppFunctionServiceInfo()
+                                    .serviceInfo
+                                    .packageName);
+            assertThat(targetedResolveInfo.getAppFunctionServiceInfo().serviceInfo.packageName)
+                    .isEqualTo(
+                            targetedResolveInfo.getLaunchActivityResolveInfo()
+                                    .activityInfo
+                                    .packageName);
+        }
+    }
+
+    @Test
+    public void testBuildAppFunctionStaticMetadata() throws Exception {
+        PackageManager pm = Mockito.mock(PackageManager.class);
+        List<PackageInfo> fakePackages = new ArrayList<>();
+        List<ResolveInfo> fakeActivities = new ArrayList<>();
+        List<ResolveInfo> fakeAppFunctionServices = new ArrayList<>();
+
+        for (int i = 0; i < 10; i++) {
+            fakePackages.add(createFakePackageInfo(i));
+            fakeActivities.add(createFakeLaunchResolveInfo(i));
+            fakeAppFunctionServices.add(createFakeAppFunctionResolveInfo(i));
+        }
+
+        // Set up mocking
+        when(pm.getProperty(any(String.class), any(ComponentName.class)))
+                .thenReturn(new PackageManager.Property("", "", "", ""));
+        AssetManager assetManager = Mockito.mock(AssetManager.class);
+
+        when(assetManager.open(any())).thenReturn(new ByteArrayInputStream("".getBytes()));
+
+        Resources resources = Mockito.mock(Resources.class);
+        when(resources.getAssets()).thenReturn(assetManager);
+        when(pm.getResourcesForApplication(any(String.class))).thenReturn(resources);
+
+        setupMockPackageManager(pm, fakePackages, fakeActivities, fakeAppFunctionServices);
+
+        AppFunctionStaticMetadataParser parser =
+                Mockito.mock(AppFunctionStaticMetadataParser.class);
+        for (PackageInfo packageInfo : fakePackages) {
+            when(parser.parse(any(), eq(packageInfo.packageName), any()))
+                    .thenReturn(
+                            ImmutableList.of(
+                                    new AppFunctionStaticMetadata.Builder(
+                                                    packageInfo.packageName,
+                                                    /* functionId= */ "com.example.utils#print",
+                                                    /* indexerPackageName= */ "android")
+                                            .build()));
+        }
+
+        Map<PackageInfo, ResolveInfos> packageActivityMapping = AppsUtil.getPackagesToIndex(pm);
+
+        List<AppFunctionStaticMetadata> resultAppFunctions =
+                AppsUtil.buildAppFunctionStaticMetadata(pm, packageActivityMapping, parser);
+
+        assertThat(resultAppFunctions).hasSize(10);
+        for (AppFunctionStaticMetadata appFunction : resultAppFunctions) {
+            assertThat(appFunction.getFunctionId()).isEqualTo("com.example.utils#print");
+        }
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/ResolveInfosTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/ResolveInfosTest.java
new file mode 100644
index 00000000..c1dc9bc9
--- /dev/null
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/ResolveInfosTest.java
@@ -0,0 +1,49 @@
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
+package com.android.server.appsearch.appsindexer;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.content.pm.ActivityInfo;
+import android.content.pm.ResolveInfo;
+
+import org.junit.Test;
+
+public class ResolveInfosTest {
+    @Test
+    public void testBuilder() {
+        ResolveInfo appFunctionResolveInfo = new ResolveInfo();
+        appFunctionResolveInfo.activityInfo = new ActivityInfo();
+        appFunctionResolveInfo.activityInfo.packageName = "package1";
+        appFunctionResolveInfo.activityInfo.name = "activity1";
+
+        ResolveInfo launchActivityResolveInfo = new ResolveInfo();
+        launchActivityResolveInfo.activityInfo = new ActivityInfo();
+        launchActivityResolveInfo.activityInfo.packageName = "package1";
+        launchActivityResolveInfo.activityInfo.name = "activity2";
+
+        ResolveInfos resolveInfos =
+                new ResolveInfos.Builder()
+                        .setAppFunctionServiceResolveInfo(appFunctionResolveInfo)
+                        .setLaunchActivityResolveInfo(launchActivityResolveInfo)
+                        .build();
+
+        assertThat(resolveInfos.getAppFunctionServiceInfo()).isEqualTo(appFunctionResolveInfo);
+        assertThat(resolveInfos.getLaunchActivityResolveInfo())
+                .isEqualTo(launchActivityResolveInfo);
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/SyncAppSearchImplTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/SyncAppSearchImplTest.java
index eaed6e45..2f30467e 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/SyncAppSearchImplTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/SyncAppSearchImplTest.java
@@ -20,6 +20,9 @@ import static android.app.appsearch.SearchSpec.TERM_MATCH_PREFIX;
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.doThrow;
+import static org.mockito.Mockito.mock;
 
 import android.app.appsearch.AppSearchBatchResult;
 import android.app.appsearch.AppSearchManager;
@@ -32,6 +35,7 @@ import android.app.appsearch.SearchResult;
 import android.app.appsearch.SearchSpec;
 import android.app.appsearch.SetSchemaRequest;
 import android.app.appsearch.SetSchemaResponse;
+import android.app.appsearch.exceptions.AppSearchException;
 import android.content.Context;
 
 import androidx.test.core.app.ApplicationProvider;
@@ -47,7 +51,10 @@ import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.Executor;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
+import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.RejectedExecutionException;
+import java.util.concurrent.ThreadPoolExecutor;
+import java.util.concurrent.TimeUnit;
 
 /** Tests for {@link SyncAppSearchSessionImpl}. */
 public class SyncAppSearchImplTest {
@@ -63,7 +70,7 @@ public class SyncAppSearchImplTest {
 
     @After
     public void tearDown() throws Exception {
-       clean();
+        clean();
     }
 
     private void clean() throws Exception {
@@ -76,7 +83,9 @@ public class SyncAppSearchImplTest {
         CompletableFuture<AppSearchResult<SetSchemaResponse>> schemaFuture =
                 new CompletableFuture<>();
         searchSession.setSchema(
-                new SetSchemaRequest.Builder().setForceOverride(true).build(), mExecutor, mExecutor,
+                new SetSchemaRequest.Builder().setForceOverride(true).build(),
+                mExecutor,
+                mExecutor,
                 schemaFuture::complete);
         schemaFuture.get().getResultValue();
     }
@@ -90,20 +99,24 @@ public class SyncAppSearchImplTest {
                 new SyncAppSearchSessionImpl(mAppSearch, searchContext, mExecutor);
 
         // Set the schema.
-        syncWrapper.setSchema(new SetSchemaRequest.Builder()
-                .addSchemas(new AppSearchSchema.Builder("schema1").build())
-                .setForceOverride(true).build());
+        syncWrapper.setSchema(
+                new SetSchemaRequest.Builder()
+                        .addSchemas(new AppSearchSchema.Builder("schema1").build())
+                        .setForceOverride(true)
+                        .build());
 
         // Create a document and insert 3 package1 documents
-        GenericDocument document1 = new GenericDocument.Builder<>("namespace", "id1",
-                "schema1").build();
-        GenericDocument document2 = new GenericDocument.Builder<>("namespace", "id2",
-                "schema1").build();
-        GenericDocument document3 = new GenericDocument.Builder<>("namespace", "id3",
-                "schema1").build();
-
-        PutDocumentsRequest request = new PutDocumentsRequest.Builder()
-                .addGenericDocuments(document1, document2, document3).build();
+        GenericDocument document1 =
+                new GenericDocument.Builder<>("namespace", "id1", "schema1").build();
+        GenericDocument document2 =
+                new GenericDocument.Builder<>("namespace", "id2", "schema1").build();
+        GenericDocument document3 =
+                new GenericDocument.Builder<>("namespace", "id3", "schema1").build();
+
+        PutDocumentsRequest request =
+                new PutDocumentsRequest.Builder()
+                        .addGenericDocuments(document1, document2, document3)
+                        .build();
         // Test put operation with no futures
         AppSearchBatchResult<String, Void> result = syncWrapper.put(request);
 
@@ -113,11 +126,12 @@ public class SyncAppSearchImplTest {
         SyncGlobalSearchSession globalSession =
                 new SyncGlobalSearchSessionImpl(mAppSearch, mExecutor);
         // Search globally for only 2 result per page
-        SearchSpec searchSpec = new SearchSpec.Builder()
-                .setTermMatch(TERM_MATCH_PREFIX)
-                .addFilterPackageNames(mContext.getPackageName())
-                .setResultCountPerPage(2)
-                .build();
+        SearchSpec searchSpec =
+                new SearchSpec.Builder()
+                        .setTermMatch(TERM_MATCH_PREFIX)
+                        .addFilterPackageNames(mContext.getPackageName())
+                        .setResultCountPerPage(2)
+                        .build();
         SyncSearchResults searchResults = globalSession.search("", searchSpec);
 
         // Get the first page, it contains 2 results.
@@ -161,7 +175,127 @@ public class SyncAppSearchImplTest {
         callbackExecutor.shutdown();
         AppSearchManager.SearchContext searchContext =
                 new AppSearchManager.SearchContext.Builder("testDb").build();
-        assertThrows(RejectedExecutionException.class, () ->
-                new SyncAppSearchSessionImpl(mAppSearch, searchContext, callbackExecutor));
+        SyncAppSearchSession session =
+                new SyncAppSearchSessionImpl(mAppSearch, searchContext, callbackExecutor);
+
+        assertThrows(
+                RejectedExecutionException.class,
+                () -> session.search("", new SearchSpec.Builder().build()));
+    }
+
+    @Test
+    public void testSyncAppSearchSessionImpl_removesDocuments() throws AppSearchException {
+        AppSearchManager.SearchContext searchContext =
+                new AppSearchManager.SearchContext.Builder("testDb").build();
+        SyncAppSearchSession syncWrapper =
+                new SyncAppSearchSessionImpl(mAppSearch, searchContext, mExecutor);
+
+        // Set the schema
+        syncWrapper.setSchema(
+                new SetSchemaRequest.Builder()
+                        .addSchemas(new AppSearchSchema.Builder("schema1").build())
+                        .addSchemas(new AppSearchSchema.Builder("schema2").build())
+                        .setForceOverride(true)
+                        .build());
+        // Index 2 documents
+        GenericDocument document1 =
+                new GenericDocument.Builder<>("namespace", "id1", "schema1").build();
+        GenericDocument document2 =
+                new GenericDocument.Builder<>("namespace", "id2", "schema2").build();
+        syncWrapper.put(
+                new PutDocumentsRequest.Builder()
+                        .addGenericDocuments(document1, document2)
+                        .build());
+
+        // Delete 1 document by filtering on schema
+        syncWrapper.remove("", new SearchSpec.Builder().addFilterSchemas("schema1").build());
+
+        // Assert that only 1 document is left
+        SyncGlobalSearchSession globalSession =
+                new SyncGlobalSearchSessionImpl(mAppSearch, mExecutor);
+        // Search globally for only 2 result per page
+        SearchSpec searchSpec =
+                new SearchSpec.Builder()
+                        .setTermMatch(TERM_MATCH_PREFIX)
+                        .addFilterPackageNames(mContext.getPackageName())
+                        .setResultCountPerPage(2)
+                        .build();
+        SyncSearchResults searchResults = globalSession.search("", searchSpec);
+        // Check that only 1 document is left, document2
+        List<SearchResult> results = searchResults.getNextPage();
+        assertThat(results).hasSize(1);
+        assertThat(results.get(0).getGenericDocument()).isEqualTo(document2);
+    }
+
+    @Test
+    public void testSyncAppSearchImpl_lateInitialization() throws AppSearchException {
+        AppSearchManager.SearchContext searchContext =
+                new AppSearchManager.SearchContext.Builder("testDb").build();
+        ThreadPoolExecutor executor =
+                new ThreadPoolExecutor(
+                        /* corePoolSize= */ 1,
+                        /* maximumPoolSize= */ 1,
+                        /* KeepAliveTime= */ 0L,
+                        TimeUnit.MILLISECONDS,
+                        new LinkedBlockingQueue<>());
+        SyncAppSearchSession session =
+                new SyncAppSearchSessionImpl(mAppSearch, searchContext, executor);
+        assertThat(executor.getCompletedTaskCount()).isEqualTo(0);
+
+        // Searching will late initialize the underlying session
+        session.search("", new SearchSpec.Builder().build());
+        long completedTasks = executor.getCompletedTaskCount();
+        assertThat(completedTasks).isGreaterThan(0);
+
+        session.setSchema(new SetSchemaRequest.Builder().build());
+        assertThat(executor.getCompletedTaskCount()).isGreaterThan(completedTasks);
+    }
+
+    @Test
+    public void testSyncGlobalSearchImpl_lateInitialization() throws AppSearchException {
+        ThreadPoolExecutor executor =
+                new ThreadPoolExecutor(
+                        /* corePoolSize= */ 1,
+                        /* maximumPoolSize= */ 1,
+                        /* KeepAliveTime= */ 0L,
+                        TimeUnit.MILLISECONDS,
+                        new LinkedBlockingQueue<>());
+        SyncGlobalSearchSession session = new SyncGlobalSearchSessionImpl(mAppSearch, executor);
+        assertThat(executor.getCompletedTaskCount()).isEqualTo(0);
+
+        // Searching will late initialize the underlying session
+        session.search("", new SearchSpec.Builder().build());
+        assertThat(executor.getCompletedTaskCount()).isGreaterThan(0);
+    }
+
+    @Test
+    public void testAsyncOperationThrowsError() throws AppSearchException {
+        // This should throw an error, but not crash the device
+        AppSearchManager.SearchContext searchContext =
+                new AppSearchManager.SearchContext.Builder("testDb").build();
+        AppSearchManager appSearchManager = mock(AppSearchManager.class);
+        doThrow(new IllegalStateException("Innocuous exception"))
+                .when(appSearchManager)
+                .createSearchSession(any(), any(), any());
+
+        AppSearchException e;
+        try (SyncAppSearchSession syncWrapper =
+                new SyncAppSearchSessionImpl(appSearchManager, searchContext, mExecutor)) {
+            e =
+                    assertThrows(
+                            AppSearchException.class,
+                            () -> syncWrapper.setSchema(new SetSchemaRequest.Builder().build()));
+            assertThat(e.getCause().getMessage()).isEqualTo("Innocuous exception");
+        }
+
+        // The put command uses a separate method in SyncAppSearchBase
+        try (SyncAppSearchSession syncWrapper =
+                new SyncAppSearchSessionImpl(appSearchManager, searchContext, mExecutor)) {
+            e =
+                    assertThrows(
+                            AppSearchException.class,
+                            () -> syncWrapper.put(new PutDocumentsRequest.Builder().build()));
+            assertThat(e.getCause().getMessage()).isEqualTo("Innocuous exception");
+        }
     }
-}
\ No newline at end of file
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestAppsIndexerConfig.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestAppsIndexerConfig.java
index 89c7da22..e8f1ab3d 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestAppsIndexerConfig.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestAppsIndexerConfig.java
@@ -26,4 +26,9 @@ public class TestAppsIndexerConfig implements AppsIndexerConfig {
     public long getAppsMaintenanceUpdateIntervalMillis() {
         return 24 * 60 * 60 * 1000L;
     }
+
+    @Override
+    public int getMaxAppFunctionsPerPackage() {
+        return 500;
+    }
 }
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestUtils.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestUtils.java
index 9f01458f..fb1993d8 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestUtils.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/TestUtils.java
@@ -36,21 +36,25 @@ import android.app.appsearch.SetSchemaRequest;
 import android.app.appsearch.SetSchemaResponse;
 import android.app.appsearch.testutil.AppSearchSessionShimImpl;
 import android.app.appsearch.testutil.GlobalSearchSessionShimImpl;
+import android.app.usage.UsageEvents;
 import android.content.Context;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
+import android.content.pm.ServiceInfo;
 import android.content.pm.Signature;
 import android.content.pm.SigningInfo;
 import android.content.res.Resources;
 
+import com.android.server.appsearch.appsindexer.appsearchtypes.AppFunctionStaticMetadata;
 import com.android.server.appsearch.appsindexer.appsearchtypes.MobileApplication;
 
 import org.mockito.Mockito;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
 import java.util.Objects;
@@ -66,15 +70,18 @@ class TestUtils {
     // upgrades. It is compatible as changing to MobileApplication just adds properties.
     public static final AppSearchSchema COMPATIBLE_APP_SCHEMA =
             new AppSearchSchema.Builder(SCHEMA_TYPE)
-                    .addProperty(new AppSearchSchema.StringPropertyConfig.Builder(
-                            MobileApplication.APP_PROPERTY_PACKAGE_NAME)
-                            .setCardinality(
-                                    AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
-                            .setIndexingType(
-                                    AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_PREFIXES)
-                            .setTokenizerType(
-                                    AppSearchSchema.StringPropertyConfig.TOKENIZER_TYPE_VERBATIM)
-                            .build())
+                    .addProperty(
+                            new AppSearchSchema.StringPropertyConfig.Builder(
+                                            MobileApplication.APP_PROPERTY_PACKAGE_NAME)
+                                    .setCardinality(
+                                            AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                    .setIndexingType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .INDEXING_TYPE_PREFIXES)
+                                    .setTokenizerType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .TOKENIZER_TYPE_VERBATIM)
+                                    .build())
                     .build();
 
     // Represents a schema incompatible with MobileApplication. This is used to test incompatible
@@ -82,21 +89,24 @@ class TestUtils {
     // "NotPackageName" field.
     public static final AppSearchSchema INCOMPATIBLE_APP_SCHEMA =
             new AppSearchSchema.Builder(SCHEMA_TYPE)
-                    .addProperty(new AppSearchSchema.StringPropertyConfig.Builder("NotPackageName")
-                            .setCardinality(
-                                    AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
-                            .setIndexingType(
-                                    AppSearchSchema.StringPropertyConfig.INDEXING_TYPE_PREFIXES)
-                            .setTokenizerType(
-                                    AppSearchSchema.StringPropertyConfig.TOKENIZER_TYPE_PLAIN)
-                            .build())
+                    .addProperty(
+                            new AppSearchSchema.StringPropertyConfig.Builder("NotPackageName")
+                                    .setCardinality(
+                                            AppSearchSchema.PropertyConfig.CARDINALITY_OPTIONAL)
+                                    .setIndexingType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .INDEXING_TYPE_PREFIXES)
+                                    .setTokenizerType(
+                                            AppSearchSchema.StringPropertyConfig
+                                                    .TOKENIZER_TYPE_PLAIN)
+                                    .build())
                     .build();
 
     /**
      * Creates a fake {@link PackageInfo} object.
      *
      * @param variant provides variation in the mocked PackageInfo so we can index multiple fake
-     *                apps.
+     *     apps.
      */
     @NonNull
     public static PackageInfo createFakePackageInfo(int variant) {
@@ -136,13 +146,13 @@ class TestUtils {
     }
 
     /**
-     * Generates a mock resolve info corresponding to the same package created by
+     * Generates a mock launch activity resolve info corresponding to the same package created by
      * {@link #createFakePackageInfo} with the same variant.
      *
      * @param variant adds variation in the mocked ResolveInfo so we can index multiple fake apps.
      */
     @NonNull
-    public static ResolveInfo createFakeResolveInfo(int variant) {
+    public static ResolveInfo createFakeLaunchResolveInfo(int variant) {
         String pkgName = FAKE_PACKAGE_PREFIX + variant;
         ResolveInfo mockResolveInfo = new ResolveInfo();
         mockResolveInfo.activityInfo = new ActivityInfo();
@@ -156,28 +166,47 @@ class TestUtils {
         return mockResolveInfo;
     }
 
+    /**
+     * Generates a mock app function activity resolve info corresponding to the same package created
+     * by {@link #createFakePackageInfo} with the same variant.
+     *
+     * @param variant adds variation in the mocked ResolveInfo so we can index multiple fake apps.
+     */
+    @NonNull
+    public static ResolveInfo createFakeAppFunctionResolveInfo(int variant) {
+        String pkgName = FAKE_PACKAGE_PREFIX + variant;
+        ResolveInfo mockResolveInfo = new ResolveInfo();
+        mockResolveInfo.serviceInfo = new ServiceInfo();
+        mockResolveInfo.serviceInfo.packageName = pkgName;
+        mockResolveInfo.serviceInfo.name = pkgName + ".FakeActivity";
+
+        return mockResolveInfo;
+    }
+
     /**
      * Generates multiple mock ResolveInfos.
      *
-     * @see #createFakeResolveInfo
+     * @see #createFakeLaunchResolveInfo
      * @param numApps number of mock ResolveInfos to create
      */
     @NonNull
     public static List<ResolveInfo> createFakeResolveInfos(int numApps) {
         List<ResolveInfo> resolveInfoList = new ArrayList<>();
         for (int i = 0; i < numApps; i++) {
-            resolveInfoList.add(createFakeResolveInfo(i));
+            resolveInfoList.add(createFakeLaunchResolveInfo(i));
         }
         return resolveInfoList;
     }
 
     /**
-     * Configure a mock {@link PackageManager} to return certain {@link PackageInfo}s and
-     * {@link ResolveInfo}s when getInstalledPackages and queryIntentActivities are called,
-     * respectively.
+     * Configure a mock {@link PackageManager} to return certain {@link PackageInfo}s and {@link
+     * ResolveInfo}s when getInstalledPackages and queryIntentActivities are called, respectively.
      */
-    public static void setupMockPackageManager(@NonNull PackageManager pm,
-            @NonNull List<PackageInfo> packages, @NonNull List<ResolveInfo> activities)
+    public static void setupMockPackageManager(
+            @NonNull PackageManager pm,
+            @NonNull List<PackageInfo> packages,
+            @NonNull List<ResolveInfo> activities,
+            @NonNull List<ResolveInfo> appFunctionServices)
             throws Exception {
         Objects.requireNonNull(pm);
         Objects.requireNonNull(packages);
@@ -189,6 +218,7 @@ class TestUtils {
         when(pm.getResourcesForApplication((ApplicationInfo) any())).thenReturn(res);
         when(pm.getApplicationLabel(any())).thenReturn("label");
         when(pm.queryIntentActivities(any(), eq(0))).then(i -> activities);
+        when(pm.queryIntentServices(any(), eq(0))).then(i -> appFunctionServices);
     }
 
     /** Wipes out the apps database. */
@@ -213,9 +243,9 @@ class TestUtils {
     /**
      * Search for documents indexed by the Apps Indexer. The database, namespace, and schematype are
      * all configured.
+     *
      * @param pageSize The page size to use in the {@link SearchSpec}. By setting to a expected
-     *                 amount + 1, you can verify that the expected quantity of apps docs are
-     *                 present.
+     *     amount + 1, you can verify that the expected quantity of apps docs are present.
      */
     @NonNull
     public static List<SearchResult> searchAppSearchForApps(int pageSize)
@@ -236,7 +266,7 @@ class TestUtils {
                         .build();
         // Don't want to get this confused with real indexed apps.
         SearchResultsShim results =
-                globalSession.search(/*queryExpression=*/ "com.fake.package", allDocumentIdsSpec);
+                globalSession.search(/* queryExpression= */ "com.fake.package", allDocumentIdsSpec);
         return results.getNextPageAsync().get();
     }
 
@@ -290,6 +320,23 @@ class TestUtils {
         return appList;
     }
 
+    /**
+     * Generates a mock {@link AppFunctionStaticMetadata} corresponding to the same package created
+     * by {@link #createFakePackageInfo} with the same variant.
+     *
+     * @param packageVariant changes the package of the AppFunctionStaticMetadata document.
+     * @param functionVariant changes the function id of the AppFunctionStaticMetadata document.
+     */
+    @NonNull
+    public static AppFunctionStaticMetadata createFakeAppFunction(
+            int packageVariant, int functionVariant, Context context) {
+        return new AppFunctionStaticMetadata.Builder(
+                        FAKE_PACKAGE_PREFIX + packageVariant,
+                        "function_id" + functionVariant,
+                        context.getPackageName())
+                .build();
+    }
+
     /**
      * Returns a package identifier representing some mock package.
      *
@@ -310,5 +357,32 @@ class TestUtils {
         }
         return packageIdList;
     }
-}
 
+    /**
+     * Creates a mock {@link UsageEvents} object.
+     *
+     * @param events the events to add to the UsageEvents object.
+     * @return a {@link UsageEvents} object with the given events.
+     */
+    public static UsageEvents createUsageEvents(UsageEvents.Event... events) {
+        return new UsageEvents(Arrays.asList(events), new String[] {});
+    }
+
+    /**
+     * Creates a mock {@link UsageEvents.Event} object.
+     *
+     * @param eventType the event type of the UsageEvents.Event object.
+     * @param timestamp the timestamp of the UsageEvents.Event object.
+     * @param packageName the package name of the UsageEvents.Event object.
+     * @return a {@link UsageEvents.Event} object with the given event type, timestamp, and package
+     *     name.
+     */
+    public static UsageEvents.Event createIndividualUsageEvent(
+            int eventType, long timestamp, String packageName) {
+        UsageEvents.Event e = new UsageEvents.Event();
+        e.mEventType = eventType;
+        e.mTimeStamp = timestamp;
+        e.mPackage = packageName;
+        return e;
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadataTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadataTest.java
new file mode 100644
index 00000000..fbe8519c
--- /dev/null
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppFunctionStaticMetadataTest.java
@@ -0,0 +1,83 @@
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
+package com.android.server.appsearch.appsindexer.appsearchtypes;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.app.appsearch.AppSearchSchema;
+
+import org.junit.Test;
+
+public class AppFunctionStaticMetadataTest {
+    @Test
+    public void testAppFunction() {
+        String functionId = "com.example.message#send_message";
+        String schemaName = "send_message";
+        String schemaCategory = "messaging";
+        int stringResId = 3;
+        long schemaVersion = 2;
+        boolean enabledByDefault = false;
+        boolean restrictCallersWithExecuteAppFunctions = false;
+        String packageName = "com.example.message";
+
+        AppFunctionStaticMetadata appFunction =
+                new AppFunctionStaticMetadata.Builder(packageName, functionId, "android")
+                        .setSchemaName(schemaName)
+                        .setSchemaVersion(schemaVersion)
+                        .setSchemaCategory(schemaCategory)
+                        .setEnabledByDefault(enabledByDefault)
+                        .setRestrictCallersWithExecuteAppFunctions(
+                                restrictCallersWithExecuteAppFunctions)
+                        .setDisplayNameStringRes(stringResId)
+                        .build();
+        assertThat(appFunction.getFunctionId()).isEqualTo(functionId);
+        assertThat(appFunction.getPackageName()).isEqualTo(packageName);
+        assertThat(appFunction.getSchemaName()).isEqualTo(schemaName);
+        assertThat(appFunction.getSchemaVersion()).isEqualTo(schemaVersion);
+        assertThat(appFunction.getRestrictCallersWithExecuteAppFunctions())
+                .isEqualTo(restrictCallersWithExecuteAppFunctions);
+        assertThat(appFunction.getSchemaCategory()).isEqualTo(schemaCategory);
+        assertThat(appFunction.getEnabledByDefault()).isEqualTo(enabledByDefault);
+        assertThat(appFunction.getDisplayNameStringRes()).isEqualTo(stringResId);
+        assertThat(appFunction.getMobileApplicationQualifiedId())
+                .isEqualTo("android$apps-db/apps#com.example.message");
+    }
+
+    @Test
+    public void testSchemaName() {
+        String packageName = "com.example.message";
+        String schemaName = AppFunctionStaticMetadata.getSchemaNameForPackage(packageName);
+        assertThat(schemaName).isEqualTo("AppFunctionStaticMetadata-com.example.message");
+    }
+
+    @Test
+    public void testChildSchema() {
+        AppSearchSchema appSearchSchema =
+                AppFunctionStaticMetadata.createAppFunctionSchemaForPackage("com.xyz");
+
+        if (AppFunctionStaticMetadata.shouldSetParentType()) {
+            assertThat(appSearchSchema.getParentTypes())
+                    .containsExactly(AppFunctionStaticMetadata.SCHEMA_TYPE);
+        }
+    }
+
+    @Test
+    public void testParentSchema() {
+        assertThat(AppFunctionStaticMetadata.PARENT_TYPE_APPSEARCH_SCHEMA.getSchemaType())
+                .isEqualTo(AppFunctionStaticMetadata.SCHEMA_TYPE);
+    }
+}
diff --git a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/MobileApplicationTest.java b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppsIndexerSchemaTests.java
similarity index 71%
rename from testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/MobileApplicationTest.java
rename to testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppsIndexerSchemaTests.java
index 478fb866..8e0d610f 100644
--- a/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/MobileApplicationTest.java
+++ b/testing/appsindexertests/src/com/android/server/appsearch/appsindexer/appsearchtypes/AppsIndexerSchemaTests.java
@@ -22,7 +22,7 @@ import android.net.Uri;
 
 import org.junit.Test;
 
-public class MobileApplicationTest {
+public class AppsIndexerSchemaTests {
     @Test
     public void testMobileApplication() {
         String packageName = "com.android.apps.food";
@@ -50,4 +50,23 @@ public class MobileApplicationTest {
         assertThat(mobileApplication.getSha256Certificate()).isEqualTo(sha256Certificate);
         assertThat(mobileApplication.getUpdatedTimestamp()).isEqualTo(updatedTimestamp);
     }
+
+    @Test
+    public void testAppOpenEvent() {
+        String packageName = "com.android.apps.food";
+        String mobileApplicationQualifiedId = "appsearch$internal/db#food";
+        long appOpenEventTimestampMillis = System.currentTimeMillis();
+
+        AppOpenEvent appOpenEvent =
+                new AppOpenEvent.Builder(packageName, appOpenEventTimestampMillis)
+                        .setPackageName(packageName)
+                        .setMobileApplicationQualifiedId(mobileApplicationQualifiedId)
+                        .build();
+
+        assertThat(appOpenEvent.getPackageName()).isEqualTo(packageName);
+        assertThat(appOpenEvent.getMobileApplicationQualifiedId())
+                .isEqualTo(mobileApplicationQualifiedId);
+        assertThat(appOpenEvent.getAppOpenEventTimestampMillis())
+                .isEqualTo(appOpenEventTimestampMillis);
+    }
 }
diff --git a/testing/contactsindexertests/Android.bp b/testing/contactsindexertests/Android.bp
index 17b0303d..5bf8304f 100644
--- a/testing/contactsindexertests/Android.bp
+++ b/testing/contactsindexertests/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_appsearch",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -22,20 +23,21 @@ android_test {
     defaults: ["modules-utils-testable-device-config-defaults"],
     static_libs: [
         "CtsAppSearchTestUtils",
+        "Harrier",
+        "Nene",
+        "TestApp",
         "androidx.test.ext.junit",
         "androidx.test.rules",
+        "appsearch_flags_java_lib",
         "compatibility-device-util-axt",
         "service-appsearch-for-tests",
         "services.core",
         "truth",
-        "Nene",
-        "Harrier",
-        "TestApp",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
         "framework-appsearch.impl",
     ],
     test_suites: [
diff --git a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/AppSearchHelperTest.java b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/AppSearchHelperTest.java
index 9b0274cb..03e8aa3a 100644
--- a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/AppSearchHelperTest.java
+++ b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/AppSearchHelperTest.java
@@ -38,11 +38,15 @@ import android.app.appsearch.SearchSpec;
 import android.app.appsearch.SetSchemaRequest;
 import android.app.appsearch.exceptions.AppSearchException;
 import android.app.appsearch.testutil.AppSearchSessionShimImpl;
-import android.app.appsearch.testutil.TestContactsIndexerConfig;
 import android.content.Context;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.appsearch.flags.Flags;
 import com.android.server.appsearch.contactsindexer.appsearchtypes.ContactPoint;
 import com.android.server.appsearch.contactsindexer.appsearchtypes.Person;
 
@@ -50,6 +54,7 @@ import com.google.common.collect.ImmutableSet;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.mockito.Mockito;
 
@@ -73,7 +78,9 @@ public class AppSearchHelperTest {
     private ContactsUpdateStats mUpdateStats;
 
     private AppSearchSessionShim mDb;
-    private ContactsIndexerConfig mConfigForTest = new TestContactsIndexerConfig();
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
     @Before
     public void setUp() throws Exception {
@@ -100,8 +107,7 @@ public class AppSearchHelperTest {
         // We choose to do it in the setup to make sure it won't create such flakiness in the
         // future tests.
         //
-        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor,
-                mConfigForTest);
+        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         // TODO(b/237115318) we need to revisit this once the contact indexer is refactored.
         // getSession here will call get() on the future for AppSearchSession to make sure it has
         // been initialized.
@@ -266,8 +272,8 @@ public class AppSearchHelperTest {
 
     @Test
     public void testCreateAppSearchHelper_compatibleSchemaChange() throws Exception {
-        AppSearchHelper appSearchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper appSearchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
 
         assertThat(appSearchHelper).isNotNull();
         assertThat(appSearchHelper.isDataLikelyWipedDuringInitAsync().get()).isFalse();
@@ -282,8 +288,7 @@ public class AppSearchHelperTest {
 
         // APP_IDS changed from optional to repeated, which is a compatible change.
         AppSearchHelper appSearchHelper =
-                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor,
-                        mConfigForTest);
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
 
         assertThat(appSearchHelper).isNotNull();
         assertThat(appSearchHelper.isDataLikelyWipedDuringInitAsync().get()).isFalse();
@@ -298,8 +303,7 @@ public class AppSearchHelperTest {
 
         // LABEL changed from repeated to optional, which is an incompatible change.
         AppSearchHelper appSearchHelper =
-                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor,
-                        mConfigForTest);
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
 
         assertThat(appSearchHelper).isNotNull();
         assertThat(appSearchHelper.isDataLikelyWipedDuringInitAsync().get()).isTrue();
@@ -331,18 +335,14 @@ public class AppSearchHelperTest {
         return indexContactsInBatchesFuture;
     }
 
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES)
     @Test
     public void testPersonSchema_indexFirstMiddleAndLastNames() throws Exception {
-        // Override test config to index first, middle and last names.
-        ContactsIndexerConfig config = new TestContactsIndexerConfig() {
-            @Override
-            public boolean shouldIndexFirstMiddleAndLastNames() {
-                return true;
-            }
-        };
-        SetSchemaRequest setSchemaRequest = new SetSchemaRequest.Builder()
-                .addSchemas(ContactPoint.SCHEMA, Person.getSchema(config))
-                .setForceOverride(true).build();
+        SetSchemaRequest setSchemaRequest =
+                new SetSchemaRequest.Builder()
+                        .addSchemas(ContactPoint.SCHEMA, Person.getSchema())
+                        .setForceOverride(true)
+                        .build();
         mDb.setSchemaAsync(setSchemaRequest).get();
         // Index document
         GenericDocument doc1 =
@@ -388,11 +388,14 @@ public class AppSearchHelperTest {
     // a single token "新中野" currently), the third and fourth asserts in ths test will start
     // failing. This documents current behavior, but doesn't endorse it. Ideally, all of the below
     // queries would be considered matches even when only the full name is indexed.
+    @RequiresFlagsDisabled(Flags.FLAG_ENABLE_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES)
     @Test
     public void testPersonSchema_indexFullNameOnly() throws Exception {
-        SetSchemaRequest setSchemaRequest = new SetSchemaRequest.Builder()
-                .addSchemas(ContactPoint.SCHEMA, Person.getSchema(mConfigForTest))
-                .setForceOverride(true).build();
+        SetSchemaRequest setSchemaRequest =
+                new SetSchemaRequest.Builder()
+                        .addSchemas(ContactPoint.SCHEMA, Person.getSchema())
+                        .setForceOverride(true)
+                        .build();
         mDb.setSchemaAsync(setSchemaRequest).get();
         GenericDocument doc1 =
                 new GenericDocument.Builder<>("namespace", "id1", Person.SCHEMA_TYPE)
diff --git a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstanceTest.java b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstanceTest.java
index 129560f0..a57baf35 100644
--- a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstanceTest.java
+++ b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/ContactsIndexerUserInstanceTest.java
@@ -425,8 +425,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                 mInstance.doFullUpdateInternalAsync(new CancellationSignal(), mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(500);
     }
@@ -477,8 +477,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                         mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(250);
 
@@ -527,8 +527,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                         mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(100);
     }
@@ -561,8 +561,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                         mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(6);
         assertThat(contactIds).containsNoneOf("2", "3", "5", "7");
@@ -624,8 +624,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                         mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(6);
         assertThat(contactIds).containsNoneOf("2", "3", "5", "7");
@@ -699,8 +699,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                         mUpdateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(11);
         assertThat(contactIds).containsNoneOf("2", "3", "5", "7");
@@ -788,10 +788,13 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                 new AppSearchManager.SearchContext.Builder(AppSearchHelper.DATABASE_NAME).build();
         AppSearchSessionShim db = AppSearchSessionShimImpl.createSearchSessionAsync(
                 searchContext).get();
-        SetSchemaRequest setSchemaRequest = new SetSchemaRequest.Builder()
-                .addSchemas(TestUtils.CONTACT_POINT_SCHEMA_WITH_APP_IDS_OPTIONAL,
-                        Person.getSchema(mConfigForTest))
-                .setForceOverride(true).build();
+        SetSchemaRequest setSchemaRequest =
+                new SetSchemaRequest.Builder()
+                        .addSchemas(
+                                TestUtils.CONTACT_POINT_SCHEMA_WITH_APP_IDS_OPTIONAL,
+                                Person.getSchema())
+                        .setForceOverride(true)
+                        .build();
         db.setSchemaAsync(setSchemaRequest).get();
 
         // Since the current schema is compatible, this won't trigger any delta update and
@@ -835,10 +838,13 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                 new AppSearchManager.SearchContext.Builder(AppSearchHelper.DATABASE_NAME).build();
         AppSearchSessionShim db = AppSearchSessionShimImpl.createSearchSessionAsync(
                 searchContext).get();
-        SetSchemaRequest setSchemaRequest = new SetSchemaRequest.Builder()
-                .addSchemas(TestUtils.CONTACT_POINT_SCHEMA_WITH_LABEL_REPEATED,
-                        Person.getSchema(mConfigForTest))
-                .setForceOverride(true).build();
+        SetSchemaRequest setSchemaRequest =
+                new SetSchemaRequest.Builder()
+                        .addSchemas(
+                                TestUtils.CONTACT_POINT_SCHEMA_WITH_LABEL_REPEATED,
+                                Person.getSchema())
+                        .setForceOverride(true)
+                        .build();
         db.setSchemaAsync(setSchemaRequest).get();
         // Setup a latch
         CountDownLatch latch = new CountDownLatch(docCount);
@@ -943,8 +949,8 @@ public class ContactsIndexerUserInstanceTest extends FakeContactsProviderTestBas
                 mInstance.doFullUpdateInternalAsync(new CancellationSignal(), updateStats),
                 mSingleThreadedExecutor);
 
-        AppSearchHelper searchHelper = AppSearchHelper.createAppSearchHelper(mContext,
-                mSingleThreadedExecutor, mConfigForTest);
+        AppSearchHelper searchHelper =
+                AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         List<String> contactIds = searchHelper.getAllContactIdsAsync().get();
         assertThat(contactIds.size()).isEqualTo(250);
 
diff --git a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/EnterpriseContactsTest.java b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/EnterpriseContactsTest.java
index 0910da5c..1a327313 100644
--- a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/EnterpriseContactsTest.java
+++ b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/EnterpriseContactsTest.java
@@ -65,7 +65,6 @@ import android.app.appsearch.observer.SchemaChangeInfo;
 import android.app.appsearch.testutil.AppSearchSessionShimImpl;
 import android.app.appsearch.testutil.EnterpriseGlobalSearchSessionShimImpl;
 import android.app.appsearch.testutil.GlobalSearchSessionShimImpl;
-import android.app.appsearch.testutil.TestContactsIndexerConfig;
 import android.content.ContentProviderOperation;
 import android.content.ContentProviderResult;
 import android.content.ContentResolver;
@@ -79,11 +78,11 @@ import android.provider.ContactsContract;
 import androidx.annotation.NonNull;
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.bedstead.enterprise.annotations.EnsureHasWorkProfile;
 import com.android.bedstead.harrier.BedsteadJUnit4;
 import com.android.bedstead.harrier.DeviceState;
-import com.android.bedstead.permissions.annotations.EnsureHasPermission;
-import com.android.bedstead.enterprise.annotations.EnsureHasWorkProfile;
 import com.android.bedstead.nene.TestApis;
+import com.android.bedstead.permissions.annotations.EnsureHasPermission;
 import com.android.bedstead.remotedpc.RemoteDpc;
 import com.android.server.appsearch.contactsindexer.appsearchtypes.ContactPoint;
 import com.android.server.appsearch.contactsindexer.appsearchtypes.Person;
@@ -133,7 +132,6 @@ public class EnterpriseContactsTest {
     private Context mContext;
     private AppSearchHelper mAppSearchHelper;
     private AppSearchSessionShim mDb;
-    private ContactsIndexerConfig mConfigForTest = new TestContactsIndexerConfig();
 
     // Main profile
     private EnterpriseGlobalSearchSessionShim mEnterpriseSession;
@@ -154,8 +152,7 @@ public class EnterpriseContactsTest {
         mContext = TestApis.context().androidContextAsUser(sDeviceState.workProfile());
 
         // Set up AppSearch contacts in the managed profile
-        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor,
-                mConfigForTest);
+        mAppSearchHelper = AppSearchHelper.createAppSearchHelper(mContext, mSingleThreadedExecutor);
         // Call getSession() to ensure mAppSearchHelper has finished initializing
         AppSearchSession unused = mAppSearchHelper.getSession();
         AppSearchManager.SearchContext searchContext = new AppSearchManager.SearchContext.Builder(
diff --git a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/FakeAppSearchHelper.java b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/FakeAppSearchHelper.java
index 13b23664..a304b874 100644
--- a/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/FakeAppSearchHelper.java
+++ b/testing/contactsindexertests/src/com/android/server/appsearch/contactsindexer/FakeAppSearchHelper.java
@@ -20,7 +20,6 @@ import android.annotation.NonNull;
 import android.app.appsearch.AppSearchResult;
 import android.app.appsearch.GenericDocument;
 import android.app.appsearch.exceptions.AppSearchException;
-import android.app.appsearch.testutil.TestContactsIndexerConfig;
 import android.content.Context;
 import android.util.ArrayMap;
 
@@ -46,7 +45,7 @@ public final class FakeAppSearchHelper extends AppSearchHelper {
     }
 
     public FakeAppSearchHelper(@NonNull Context context, int docLimit, int deleteLimit) {
-        super(context, Runnable::run, new TestContactsIndexerConfig());
+        super(context, Runnable::run);
         mDocLimit = docLimit;
         mDeleteLimit = deleteLimit;
     }
diff --git a/testing/coretests/Android.bp b/testing/coretests/Android.bp
index adc4fe19..50e4320f 100644
--- a/testing/coretests/Android.bp
+++ b/testing/coretests/Android.bp
@@ -23,13 +23,14 @@ android_test {
         "CtsAppSearchTestUtils",
         "androidx.test.ext.junit",
         "androidx.test.rules",
-        "appsearch_flags_java_lib",
+        "appsearch_flags_java_exported_lib",
+        "flag-junit",
         "junit",
         "testng",
         "truth",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "framework-annotations-lib",
         "framework-appsearch.impl",
     ],
diff --git a/testing/coretests/src/android/app/appsearch/external/app/AppSearchBlobHandleInternalTest.java b/testing/coretests/src/android/app/appsearch/external/app/AppSearchBlobHandleInternalTest.java
new file mode 100644
index 00000000..faa16375
--- /dev/null
+++ b/testing/coretests/src/android/app/appsearch/external/app/AppSearchBlobHandleInternalTest.java
@@ -0,0 +1,79 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.app.appsearch;
+
+import static android.app.appsearch.testutil.AppSearchTestUtils.calculateDigest;
+import static android.app.appsearch.testutil.AppSearchTestUtils.generateRandomBytes;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+
+// TODO(b/273591938) move this to cts test once it's public.
+public class AppSearchBlobHandleInternalTest {
+
+    @Test
+    public void testCreateBlobHandle() throws Exception {
+        byte[] data = generateRandomBytes(10); // 10 Bytes
+        byte[] digest = calculateDigest(data);
+        AppSearchBlobHandle blobHandle = AppSearchBlobHandle.createWithSha256(digest, "label123");
+        assertThat(blobHandle.getLabel()).isEqualTo("label123");
+        assertThat(blobHandle.getSha256Digest()).isEqualTo(digest);
+    }
+
+    @Test
+    public void testBlobHandleIdentical() throws Exception {
+        byte[] data1 = {(byte) 1};
+        byte[] data2 = {(byte) 2};
+        byte[] digest1 = calculateDigest(data1);
+        byte[] digest2 = calculateDigest(data2);
+        AppSearchBlobHandle blobHandle1 = AppSearchBlobHandle.createWithSha256(digest1, "label123");
+        AppSearchBlobHandle blobHandle2 = AppSearchBlobHandle.createWithSha256(digest1, "label123");
+        AppSearchBlobHandle blobHandle3 = AppSearchBlobHandle.createWithSha256(digest1, "321lebal");
+        AppSearchBlobHandle blobHandle4 = AppSearchBlobHandle.createWithSha256(digest2, "label123");
+        assertThat(blobHandle1).isEqualTo(blobHandle2);
+        assertThat(blobHandle1).isNotEqualTo(blobHandle3);
+        assertThat(blobHandle1).isNotEqualTo(blobHandle4);
+        assertThat(blobHandle3).isNotEqualTo(blobHandle4);
+        assertThat(blobHandle1.hashCode()).isEqualTo(blobHandle2.hashCode());
+        assertThat(blobHandle1.hashCode()).isNotEqualTo(blobHandle3.hashCode());
+        assertThat(blobHandle1.hashCode()).isNotEqualTo(blobHandle4.hashCode());
+        assertThat(blobHandle3.hashCode()).isNotEqualTo(blobHandle4.hashCode());
+    }
+
+    @Test
+    public void testCreateBlobHandle_invalidDigest() throws Exception {
+        IllegalArgumentException exception =
+                assertThrows(
+                        IllegalArgumentException.class,
+                        () -> AppSearchBlobHandle.createWithSha256(new byte[10], "label123"));
+        assertThat(exception).hasMessageThat().contains("The digest is not a SHA-256 digest");
+    }
+
+    @Test
+    public void testCreateBlobHandle_emptyLabel() throws Exception {
+        byte[] data = {(byte) 1};
+        byte[] digest = calculateDigest(data);
+        AppSearchBlobHandle blobHandle1 = AppSearchBlobHandle.createWithSha256(digest);
+        AppSearchBlobHandle blobHandle2 =
+                AppSearchBlobHandle.createWithSha256(digest, /* label= */ "");
+        assertThat(blobHandle1).isEqualTo(blobHandle2);
+        assertThat(blobHandle1.hashCode()).isEqualTo(blobHandle2.hashCode());
+    }
+}
diff --git a/testing/coretests/src/android/app/appsearch/external/app/SearchSpecInternalTest.java b/testing/coretests/src/android/app/appsearch/external/app/SearchSpecInternalTest.java
index 28ac20fb..380dff8d 100644
--- a/testing/coretests/src/android/app/appsearch/external/app/SearchSpecInternalTest.java
+++ b/testing/coretests/src/android/app/appsearch/external/app/SearchSpecInternalTest.java
@@ -130,10 +130,9 @@ public class SearchSpecInternalTest {
         SearchSpec searchSpec =
                 new SearchSpec.Builder()
                         .setListFilterQueryLanguageEnabled(true)
-                        .setEmbeddingSearchEnabled(true)
                         .setDefaultEmbeddingSearchMetricType(
                                 SearchSpec.EMBEDDING_SEARCH_METRIC_TYPE_DOT_PRODUCT)
-                        .addSearchEmbeddings(embedding1, embedding2)
+                        .addEmbeddingParameters(embedding1, embedding2)
                         .build();
 
         // Check that copy constructor works.
@@ -142,8 +141,8 @@ public class SearchSpecInternalTest {
                 .containsExactlyElementsIn(searchSpec.getEnabledFeatures());
         assertThat(searchSpecCopy.getDefaultEmbeddingSearchMetricType())
                 .isEqualTo(searchSpec.getDefaultEmbeddingSearchMetricType());
-        assertThat(searchSpecCopy.getSearchEmbeddings())
-                .containsExactlyElementsIn(searchSpec.getSearchEmbeddings());
+        assertThat(searchSpecCopy.getEmbeddingParameters())
+                .containsExactlyElementsIn(searchSpec.getEmbeddingParameters());
     }
 
     @Test
@@ -199,59 +198,4 @@ public class SearchSpecInternalTest {
         assertThat(searchSpec3.getEnabledFeatures())
                 .containsExactly(Features.VERBATIM_SEARCH, Features.LIST_FILTER_QUERY_LANGUAGE);
     }
-
-    @Test
-    public void testGetEnabledFeatures_embeddingSearch() {
-        SearchSpec searchSpec =
-                new SearchSpec.Builder()
-                        .setNumericSearchEnabled(true)
-                        .setVerbatimSearchEnabled(true)
-                        .setListFilterQueryLanguageEnabled(true)
-                        .setListFilterHasPropertyFunctionEnabled(true)
-                        .setEmbeddingSearchEnabled(true)
-                        .build();
-        assertThat(searchSpec.getEnabledFeatures())
-                .containsExactly(
-                        Features.NUMERIC_SEARCH,
-                        Features.VERBATIM_SEARCH,
-                        Features.LIST_FILTER_QUERY_LANGUAGE,
-                        Features.LIST_FILTER_HAS_PROPERTY_FUNCTION,
-                        FeatureConstants.EMBEDDING_SEARCH);
-
-        // Check that copy constructor works.
-        SearchSpec searchSpecCopy = new SearchSpec.Builder(searchSpec).build();
-        assertThat(searchSpecCopy.getEnabledFeatures())
-                .containsExactly(
-                        Features.NUMERIC_SEARCH,
-                        Features.VERBATIM_SEARCH,
-                        Features.LIST_FILTER_QUERY_LANGUAGE,
-                        Features.LIST_FILTER_HAS_PROPERTY_FUNCTION,
-                        FeatureConstants.EMBEDDING_SEARCH);
-    }
-
-    @Test
-    public void testGetEnabledFeatures_tokenize() {
-        SearchSpec searchSpec =
-                new SearchSpec.Builder()
-                        .setNumericSearchEnabled(true)
-                        .setVerbatimSearchEnabled(true)
-                        .setListFilterQueryLanguageEnabled(true)
-                        .setListFilterTokenizeFunctionEnabled(true)
-                        .build();
-        assertThat(searchSpec.getEnabledFeatures())
-                .containsExactly(
-                        Features.NUMERIC_SEARCH,
-                        Features.VERBATIM_SEARCH,
-                        Features.LIST_FILTER_QUERY_LANGUAGE,
-                        FeatureConstants.LIST_FILTER_TOKENIZE_FUNCTION);
-
-        // Check that copy constructor works.
-        SearchSpec searchSpecCopy = new SearchSpec.Builder(searchSpec).build();
-        assertThat(searchSpecCopy.getEnabledFeatures())
-                .containsExactly(
-                        Features.NUMERIC_SEARCH,
-                        Features.VERBATIM_SEARCH,
-                        Features.LIST_FILTER_QUERY_LANGUAGE,
-                        FeatureConstants.LIST_FILTER_TOKENIZE_FUNCTION);
-    }
 }
diff --git a/testing/coretests/src/android/app/appsearch/external/flags/FlagsTest.java b/testing/coretests/src/android/app/appsearch/external/flags/FlagsTest.java
index 53bb33a0..4be2b278 100644
--- a/testing/coretests/src/android/app/appsearch/external/flags/FlagsTest.java
+++ b/testing/coretests/src/android/app/appsearch/external/flags/FlagsTest.java
@@ -116,9 +116,10 @@ public class FlagsTest {
     }
 
     @Test
-    public void testFlagValue_enableListFilterTokenizeFunction() {
-        assertThat(Flags.FLAG_ENABLE_LIST_FILTER_TOKENIZE_FUNCTION)
-                .isEqualTo("com.android.appsearch.flags.enable_list_filter_tokenize_function");
+    public void testFlagValue_enableSearchSpecSearchStringParameters() {
+        assertThat(Flags.FLAG_ENABLE_SEARCH_SPEC_SEARCH_STRING_PARAMETERS)
+                .isEqualTo(
+                        "com.android.appsearch.flags.enable_search_spec_search_string_parameters");
     }
 
     @Test
@@ -126,4 +127,22 @@ public class FlagsTest {
         assertThat(Flags.FLAG_ENABLE_INFORMATIONAL_RANKING_EXPRESSIONS)
                 .isEqualTo("com.android.appsearch.flags.enable_informational_ranking_expressions");
     }
+
+    @Test
+    public void testFlagValue_enableResultAlreadyExists() {
+        assertThat(Flags.FLAG_ENABLE_RESULT_ALREADY_EXISTS)
+                .isEqualTo("com.android.appsearch.flags.enable_result_already_exists");
+    }
+
+    @Test
+    public void testFlagValue_enableBlobStore() {
+        assertThat(Flags.FLAG_ENABLE_BLOB_STORE)
+                .isEqualTo("com.android.appsearch.flags.enable_blob_store");
+    }
+
+    @Test
+    public void testFlagValue_enableEnterpriseEmptyBatchResultFix() {
+        assertThat(Flags.FLAG_ENABLE_ENTERPRISE_EMPTY_BATCH_RESULT_FIX)
+                .isEqualTo("com.android.appsearch.flags.enable_enterprise_empty_batch_result_fix");
+    }
 }
diff --git a/testing/mockingservicestests/Android.bp b/testing/mockingservicestests/Android.bp
index 542d9e55..a7a078ed 100644
--- a/testing/mockingservicestests/Android.bp
+++ b/testing/mockingservicestests/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_appsearch",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -24,6 +25,8 @@ android_test {
         "CtsAppSearchTestUtils",
         "androidx.test.ext.junit",
         "androidx.test.rules",
+        "appsearch_flags_java_lib",
+        "flag-junit",
         "mockito-target-minus-junit4",
         "service-appsearch-for-tests",
         "services.core",
diff --git a/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchManagerServiceTest.java b/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchManagerServiceTest.java
index 47105378..9cdfe05b 100644
--- a/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchManagerServiceTest.java
+++ b/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchManagerServiceTest.java
@@ -17,6 +17,7 @@ package com.android.server.appsearch;
 
 import static android.Manifest.permission.READ_GLOBAL_APP_SEARCH_DATA;
 import static android.app.appsearch.AppSearchResult.RESULT_DENIED;
+import static android.app.appsearch.AppSearchResult.RESULT_NOT_FOUND;
 import static android.app.appsearch.AppSearchResult.RESULT_RATE_LIMITED;
 import static android.system.OsConstants.O_RDONLY;
 import static android.system.OsConstants.O_WRONLY;
@@ -95,7 +96,6 @@ import android.app.appsearch.aidl.SearchSuggestionAidlRequest;
 import android.app.appsearch.aidl.SetSchemaAidlRequest;
 import android.app.appsearch.aidl.UnregisterObserverCallbackAidlRequest;
 import android.app.appsearch.aidl.WriteSearchResultsToFileAidlRequest;
-import android.app.appsearch.functions.AppFunctionManager;
 import android.app.appsearch.functions.ExecuteAppFunctionRequest;
 import android.app.appsearch.functions.ExecuteAppFunctionResponse;
 import android.app.appsearch.functions.ServiceCallHelper;
@@ -119,11 +119,16 @@ import android.os.ServiceManager;
 import android.os.SystemClock;
 import android.os.UserHandle;
 import android.os.UserManager;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.DeviceConfig;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.platform.app.InstrumentationRegistry;
 
+import com.android.appsearch.flags.Flags;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.dx.mockito.inline.extended.StaticMockitoSessionBuilder;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
@@ -172,6 +177,9 @@ public class AppSearchManagerServiceTest {
     private final RoleManager mRoleManager = mock(RoleManager.class);
     private final DevicePolicyManager mDevicePolicyManager = mock(DevicePolicyManager.class);
 
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
     @Rule
     public ExtendedMockitoRule mExtendedMockitoRule = new ExtendedMockitoRule.Builder()
             .addStaticMockFixtures(() -> mMockServiceManager, TestableDeviceConfig::new)
@@ -1418,6 +1426,7 @@ public class AppSearchManagerServiceTest {
         verify(mLogger, timeout(1000).times(0)).logStats(any(CallStats.class));
     }
 
+    @RequiresFlagsDisabled(Flags.FLAG_ENABLE_ENTERPRISE_EMPTY_BATCH_RESULT_FIX)
     @Test
     public void testEnterpriseGetDocuments_noEnterpriseUser_emptyResult() throws Exception {
         // Even on devices with an enterprise user, this test will run properly, since we haven't
@@ -1427,11 +1436,12 @@ public class AppSearchManagerServiceTest {
                 new GetDocumentsAidlRequest(
                         AppSearchAttributionSource.createAttributionSource(mContext,
                                 mCallingPid),
-                mContext.getPackageName(), DATABASE_NAME, new GetByDocumentIdRequest.Builder(
-                        NAMESPACE)
-                        .addIds(/* ids= */ Collections.emptyList())
-                        .build(),
-                mUserHandle, BINDER_CALL_START_TIME, /* isForEnterprise= */ true),
+                        mContext.getPackageName(), DATABASE_NAME,
+                        new GetByDocumentIdRequest.Builder(
+                                NAMESPACE)
+                                .addIds(/* ids= */ Arrays.asList("123", "456", "789"))
+                                .build(),
+                        mUserHandle, BINDER_CALL_START_TIME, /* isForEnterprise= */ true),
                 callback);
         assertThat(callback.get()).isNull(); // null means there wasn't an error
         assertThat(callback.getBatchResult().getAll()).isEmpty();
@@ -1439,6 +1449,35 @@ public class AppSearchManagerServiceTest {
         verify(mLogger, timeout(1000).times(0)).logStats(any(CallStats.class));
     }
 
+    @RequiresFlagsEnabled(Flags.FLAG_ENABLE_ENTERPRISE_EMPTY_BATCH_RESULT_FIX)
+    @Test
+    public void testEnterpriseGetDocuments_noEnterpriseUser_notFoundResults() throws Exception {
+        // Even on devices with an enterprise user, this test will run properly, since we haven't
+        // unlocked the enterprise user for our local instance of AppSearchManagerService
+        TestBatchResultErrorCallback callback = new TestBatchResultErrorCallback();
+        mAppSearchManagerServiceStub.getDocuments(
+                new GetDocumentsAidlRequest(
+                        AppSearchAttributionSource.createAttributionSource(mContext,
+                                mCallingPid),
+                        mContext.getPackageName(), DATABASE_NAME,
+                        new GetByDocumentIdRequest.Builder(
+                                NAMESPACE)
+                                .addIds(/* ids= */ Arrays.asList("123", "456", "789"))
+                                .build(),
+                        mUserHandle, BINDER_CALL_START_TIME, /* isForEnterprise= */ true),
+                callback);
+        assertThat(callback.get()).isNull(); // null means there wasn't an error
+        assertThat(callback.getBatchResult().getFailures()).containsExactly("123",
+                AppSearchResult.newFailedResult(RESULT_NOT_FOUND,
+                        "Document (namespace, 123) not found."), "456",
+                AppSearchResult.newFailedResult(RESULT_NOT_FOUND,
+                        "Document (namespace, 456) not found."), "789",
+                AppSearchResult.newFailedResult(RESULT_NOT_FOUND,
+                        "Document (namespace, 789) not found."));
+        // No CallStats logged since we returned early
+        verify(mLogger, timeout(1000).times(0)).logStats(any(CallStats.class));
+    }
+
     @Test
     public void testEnterpriseGlobalSearch_noEnterpriseUser_emptyResult() throws Exception {
         // Even on devices with an enterprise user, this test will run properly, since we haven't
@@ -1508,19 +1547,6 @@ public class AppSearchManagerServiceTest {
         verifyExecuteAppFunctionCallbackResult(AppSearchResult.RESULT_NOT_FOUND);
     }
 
-    @Test
-    public void executeAppFunction_serviceNotPermissionProtected() throws Exception {
-        ServiceInfo serviceInfo = new ServiceInfo();
-        serviceInfo.packageName = FOO_PACKAGE_NAME;
-        serviceInfo.name = ".MyAppFunctionService";
-        ResolveInfo resolveInfo = new ResolveInfo();
-        resolveInfo.serviceInfo = serviceInfo;
-        PackageManager spyPackageManager = mContext.getPackageManager();
-        doReturn(resolveInfo).when(spyPackageManager).resolveService(any(Intent.class), eq(0));
-
-        verifyExecuteAppFunctionCallbackResult(AppSearchResult.RESULT_NOT_FOUND);
-    }
-
     @Test
     public void executeAppFunction_bindServiceReturnsFalse() throws Exception {
         mServiceCallHelper.setBindServiceResult(false);
@@ -2020,7 +2046,10 @@ public class AppSearchManagerServiceTest {
         ServiceInfo serviceInfo = new ServiceInfo();
         serviceInfo.packageName = FOO_PACKAGE_NAME;
         serviceInfo.name = ".MyAppFunctionService";
-        serviceInfo.permission = AppFunctionManager.PERMISSION_BIND_APP_FUNCTION_SERVICE;
+        // TODO(b/359911502): Commenting out this permission since the BIND_APP_FUNCTION_SERVICE
+        //   permission is deleted from app search. Th whole app function functionality should be
+        //   removed along with the tests here once the new app function manager is submitted.
+        //   serviceInfo.permission = AppFunctionManager.PERMISSION_BIND_APP_FUNCTION_SERVICE;
         ResolveInfo resolveInfo = new ResolveInfo();
         resolveInfo.serviceInfo = serviceInfo;
         PackageManager spyPackageManager = mContext.getPackageManager();
diff --git a/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchModuleTest.java b/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchModuleTest.java
index c0e36822..1fab22d1 100644
--- a/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchModuleTest.java
+++ b/testing/mockingservicestests/src/com/android/server/appsearch/AppSearchModuleTest.java
@@ -30,10 +30,14 @@ import static org.mockito.Mockito.verify;
 import android.annotation.NonNull;
 import android.content.Context;
 import android.content.pm.UserInfo;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.DeviceConfig;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.appsearch.flags.Flags;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.server.SystemService.TargetUser;
 import com.android.server.appsearch.AppSearchModule.Lifecycle;
@@ -44,15 +48,20 @@ import com.android.server.appsearch.contactsindexer.ContactsIndexerManagerServic
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+@RequiresFlagsEnabled(Flags.FLAG_APPS_INDEXER_ENABLED)
 public class AppSearchModuleTest {
     private static final String NAMESPACE_APPSEARCH = "appsearch";
     private static final String KEY_CONTACTS_INDEXER_ENABLED = "contacts_indexer_enabled";
     private static final String KEY_APPS_INDEXER_ENABLED = "apps_indexer_enabled";
 
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
     private final ContactsIndexerManagerService mContactsIndexerService =
             mock(ContactsIndexerManagerService.class);
     private final AppsIndexerManagerService mAppsIndexerService =
@@ -98,6 +107,7 @@ public class AppSearchModuleTest {
                     }
                 };
 
+        // Enable contacts indexer and apps indexer by default. Some tests will turn them off
         ExtendedMockito.doReturn(true)
                 .when(
                         () ->
@@ -217,7 +227,7 @@ public class AppSearchModuleTest {
         assertThat(mLifecycle.mAppsIndexerManagerService).isNull();
         assertThat(mLifecycle.mContactsIndexerManagerService).isNotNull();
 
-        //  Setup ContactsIndexerManagerService to throw an error on start
+        // Setup ContactsIndexerManagerService to throw an error on start
         doNothing().when(mAppsIndexerService).onStart();
         doThrow(new RuntimeException("Contacts indexer exception"))
                 .when(mContactsIndexerService)
diff --git a/testing/mockingservicestests/src/com/android/server/appsearch/ContactsIndexer/FrameworkContactsIndexerConfigTest.java b/testing/mockingservicestests/src/com/android/server/appsearch/ContactsIndexer/FrameworkContactsIndexerConfigTest.java
index 8e82c1c6..a7675104 100644
--- a/testing/mockingservicestests/src/com/android/server/appsearch/ContactsIndexer/FrameworkContactsIndexerConfigTest.java
+++ b/testing/mockingservicestests/src/com/android/server/appsearch/ContactsIndexer/FrameworkContactsIndexerConfigTest.java
@@ -43,7 +43,6 @@ public class FrameworkContactsIndexerConfigTest {
                 ContactsIndexerConfig.DEFAULT_CONTACTS_FULL_UPDATE_INDEXING_LIMIT);
         assertThat(contactsIndexerConfig.getContactsDeltaUpdateLimit()).isEqualTo(
                 ContactsIndexerConfig.DEFAULT_CONTACTS_DELTA_UPDATE_INDEXING_LIMIT);
-        assertThat(contactsIndexerConfig.shouldIndexFirstMiddleAndLastNames()).isFalse();
     }
 
     @Test
@@ -72,10 +71,6 @@ public class FrameworkContactsIndexerConfigTest {
                 Long.toString(
                         ContactsIndexerConfig.DEFAULT_CONTACTS_DELTA_UPDATE_INDEXING_LIMIT + 1),
                 false);
-        DeviceConfig.setProperty(DeviceConfig.NAMESPACE_APPSEARCH,
-                FrameworkContactsIndexerConfig.KEY_CONTACTS_INDEX_FIRST_MIDDLE_AND_LAST_NAMES,
-                Boolean.toString(false),
-                false);
 
         ContactsIndexerConfig contactsIndexerConfig = new FrameworkContactsIndexerConfig();
 
@@ -88,6 +83,5 @@ public class FrameworkContactsIndexerConfigTest {
                 ContactsIndexerConfig.DEFAULT_CONTACTS_FULL_UPDATE_INDEXING_LIMIT + 1);
         assertThat(contactsIndexerConfig.getContactsDeltaUpdateLimit()).isEqualTo(
                 ContactsIndexerConfig.DEFAULT_CONTACTS_DELTA_UPDATE_INDEXING_LIMIT + 1);
-        assertThat(contactsIndexerConfig.shouldIndexFirstMiddleAndLastNames()).isFalse();
     }
 }
diff --git a/testing/safeparceltests/Android.bp b/testing/safeparceltests/Android.bp
index 21423a43..48443ac3 100644
--- a/testing/safeparceltests/Android.bp
+++ b/testing/safeparceltests/Android.bp
@@ -35,7 +35,7 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "framework-annotations-lib",
         "framework-appsearch.impl",
     ],
diff --git a/testing/servicestests/Android.bp b/testing/servicestests/Android.bp
index 3a1c56d3..083ff4a3 100644
--- a/testing/servicestests/Android.bp
+++ b/testing/servicestests/Android.bp
@@ -21,17 +21,20 @@ android_test {
     srcs: ["src/**/*.java"],
     static_libs: [
         "CtsAppSearchTestUtils",
+        "android.app.appfunctions.flags-aconfig-java",
         "androidx.test.ext.junit",
         "androidx.test.rules",
         "compatibility-device-util-axt",
+        "flag-junit",
         "framework-appsearch.impl",
+        "platform-test-annotations",
         "service-appsearch-for-tests",
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
     ],
     // jni libs are not normally accessible from apps so they must be explicitly included.
     jni_libs: ["libicing"],
diff --git a/testing/servicestests/src/com/android/server/appsearch/visibilitystore/VisibilityCheckerImplTest.java b/testing/servicestests/src/com/android/server/appsearch/visibilitystore/VisibilityCheckerImplTest.java
index eb9c102c..23cf16fb 100644
--- a/testing/servicestests/src/com/android/server/appsearch/visibilitystore/VisibilityCheckerImplTest.java
+++ b/testing/servicestests/src/com/android/server/appsearch/visibilitystore/VisibilityCheckerImplTest.java
@@ -16,6 +16,8 @@
 
 package com.android.server.appsearch.visibilitystore;
 
+import static android.Manifest.permission.EXECUTE_APP_FUNCTIONS;
+import static android.Manifest.permission.EXECUTE_APP_FUNCTIONS_TRUSTED;
 import static android.Manifest.permission.READ_ASSISTANT_APP_SEARCH_DATA;
 import static android.Manifest.permission.READ_CALENDAR;
 import static android.Manifest.permission.READ_CONTACTS;
@@ -23,13 +25,16 @@ import static android.Manifest.permission.READ_EXTERNAL_STORAGE;
 import static android.Manifest.permission.READ_GLOBAL_APP_SEARCH_DATA;
 import static android.Manifest.permission.READ_HOME_APP_SEARCH_DATA;
 import static android.Manifest.permission.READ_SMS;
+import static android.app.appfunctions.flags.Flags.FLAG_ENABLE_APP_FUNCTION_MANAGER;
 import static android.content.pm.PackageManager.PERMISSION_DENIED;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.when;
 
 import android.annotation.NonNull;
@@ -43,6 +48,9 @@ import android.content.Context;
 import android.content.ContextWrapper;
 import android.content.pm.PackageManager;
 import android.os.UserHandle;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.util.ArrayMap;
 
 import androidx.test.core.app.ApplicationProvider;
@@ -74,6 +82,11 @@ public class VisibilityCheckerImplTest {
     // These constants are hidden in SetSchemaRequest
     private static final int ENTERPRISE_ACCESS = 7;
     private static final int MANAGED_PROFILE_CONTACTS_ACCESS = 8;
+    private static final int SET_SCHEMA_REQUEST_EXECUTE_APP_FUNCTIONS = 9;
+    private static final int SET_SCHEMA_REQUEST_EXECUTE_APP_FUNCTIONS_TRUSTED = 10;
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
     @Rule public TemporaryFolder mTemporaryFolder = new TemporaryFolder();
     private final Map<UserHandle, PackageManager> mMockPackageManagers = new ArrayMap<>();
@@ -105,7 +118,7 @@ public class VisibilityCheckerImplTest {
             }
         };
         mUiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
-        mVisibilityChecker = new VisibilityCheckerImpl(mContext);
+        mVisibilityChecker = Mockito.spy(new VisibilityCheckerImpl(mContext));
         // Give ourselves global query permissions
         AppSearchImpl appSearchImpl = AppSearchImpl.create(
                 mTemporaryFolder.newFolder(),
@@ -519,6 +532,84 @@ public class VisibilityCheckerImplTest {
                 .isFalse();
     }
 
+    @Test
+    @RequiresFlagsEnabled(FLAG_ENABLE_APP_FUNCTION_MANAGER)
+    public void testSetSchema_visibleToAppFunctionsPermissions() throws Exception {
+        String prefix = PrefixUtil.createPrefix("package", "database");
+
+        // Create a VDoc that require either EXECUTE_APP_FUNCTIONS or EXECUTE_APP_FUNCTIONS_TRUSTED
+        // permissions only.
+        InternalVisibilityConfig visibilityConfig =
+                new InternalVisibilityConfig.Builder(/* id= */ prefix + "Schema")
+                        .addVisibleToPermissions(
+                                ImmutableSet.of(SET_SCHEMA_REQUEST_EXECUTE_APP_FUNCTIONS))
+                        .addVisibleToPermissions(
+                                ImmutableSet.of(SET_SCHEMA_REQUEST_EXECUTE_APP_FUNCTIONS_TRUSTED))
+                        .build();
+        mVisibilityStore.setVisibility(ImmutableList.of(visibilityConfig));
+
+        // Grant the EXECUTE_APP_FUNCTIONS permission, we should able to access.
+        doReturn(true)
+                .when(mVisibilityChecker)
+                .checkPermissionForDataDeliveryGranted(eq(EXECUTE_APP_FUNCTIONS), any(), any());
+        assertThat(
+                        mVisibilityChecker.isSchemaSearchableByCaller(
+                                new FrameworkCallerAccess(
+                                        mAttributionSource,
+                                        /* callerHasSystemAccess= */ false,
+                                        /* isForEnterprise= */ false),
+                                "package",
+                                prefix + "Schema",
+                                mVisibilityStore))
+                .isTrue();
+        // Grant the EXECUTE_APP_FUNCTIONS_TRUSTED permission along with EXECUTE_APP_FUNCTIONS, we
+        // should still be able to access.
+        doReturn(true)
+                .when(mVisibilityChecker)
+                .checkPermissionForDataDeliveryGranted(
+                        eq(EXECUTE_APP_FUNCTIONS_TRUSTED), any(), any());
+        assertThat(
+                        mVisibilityChecker.isSchemaSearchableByCaller(
+                                new FrameworkCallerAccess(
+                                        mAttributionSource,
+                                        /* callerHasSystemAccess= */ false,
+                                        /* isForEnterprise= */ false),
+                                "package",
+                                prefix + "Schema",
+                                mVisibilityStore))
+                .isTrue();
+        // Drop the EXECUTE_APP_FUNCTIONS permission so only EXECUTE_APP_FUNCTIONS_TRUSTED is held,
+        // we should still be able to access.
+        doReturn(false)
+                .when(mVisibilityChecker)
+                .checkPermissionForDataDeliveryGranted(eq(EXECUTE_APP_FUNCTIONS), any(), any());
+        assertThat(
+                        mVisibilityChecker.isSchemaSearchableByCaller(
+                                new FrameworkCallerAccess(
+                                        mAttributionSource,
+                                        /* callerHasSystemAccess= */ false,
+                                        /* isForEnterprise= */ false),
+                                "package",
+                                prefix + "Schema",
+                                mVisibilityStore))
+                .isTrue();
+        // Drop both permissions, it becomes invisible.
+        doReturn(false)
+                .when(mVisibilityChecker)
+                .checkPermissionForDataDeliveryGranted(
+                        eq(EXECUTE_APP_FUNCTIONS_TRUSTED), any(), any());
+        assertThat(
+                        mVisibilityChecker.isSchemaSearchableByCaller(
+                                new FrameworkCallerAccess(
+                                        mAttributionSource,
+                                        /* callerHasSystemAccess= */ false,
+                                        /* isForEnterprise= */ false),
+                                "package",
+                                prefix + "Schema",
+                                mVisibilityStore))
+                .isFalse();
+    }
+
     @Test
     public void testSetSchema_enterpriseNotVisibleToPermissions_withoutEnterpriseAccessPermission()
             throws Exception {
```

