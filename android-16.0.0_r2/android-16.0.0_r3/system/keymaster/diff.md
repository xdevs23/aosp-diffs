```diff
diff --git a/contexts/keymaster1_passthrough_context.cpp b/contexts/keymaster1_passthrough_context.cpp
index 8dcd5cf..4c67f18 100644
--- a/contexts/keymaster1_passthrough_context.cpp
+++ b/contexts/keymaster1_passthrough_context.cpp
@@ -92,7 +92,7 @@ Keymaster1PassthroughContext::GetOperationFactory(keymaster_algorithm_t algorith
     auto keyfactory = GetKeyFactory(algorithm);
     return keyfactory->GetOperationFactory(purpose);
 }
-keymaster_algorithm_t*
+const keymaster_algorithm_t*
 Keymaster1PassthroughContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
     if (algorithms_count) *algorithms_count = 0;
     return nullptr;
diff --git a/contexts/keymaster2_passthrough_context.cpp b/contexts/keymaster2_passthrough_context.cpp
index 23fc145..8859f47 100644
--- a/contexts/keymaster2_passthrough_context.cpp
+++ b/contexts/keymaster2_passthrough_context.cpp
@@ -54,7 +54,7 @@ Keymaster2PassthroughContext::GetOperationFactory(keymaster_algorithm_t algorith
     auto keyfactory = GetKeyFactory(algorithm);
     return keyfactory->GetOperationFactory(purpose);
 }
-keymaster_algorithm_t*
+const keymaster_algorithm_t*
 Keymaster2PassthroughContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
     if (algorithms_count) *algorithms_count = 0;
     return nullptr;
diff --git a/include/keymaster/contexts/keymaster1_passthrough_context.h b/include/keymaster/contexts/keymaster1_passthrough_context.h
index e5bd16b..c657041 100644
--- a/include/keymaster/contexts/keymaster1_passthrough_context.h
+++ b/include/keymaster/contexts/keymaster1_passthrough_context.h
@@ -62,7 +62,7 @@ class Keymaster1PassthroughContext : public KeymasterContext,
     KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override;
     OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
                                           keymaster_purpose_t purpose) const override;
-    keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
+    const keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
 
     /**
      * UpgradeKeyBlob takes an existing blob, parses out key material and constructs a new blob with
diff --git a/include/keymaster/contexts/keymaster2_passthrough_context.h b/include/keymaster/contexts/keymaster2_passthrough_context.h
index 37592f8..96ac152 100644
--- a/include/keymaster/contexts/keymaster2_passthrough_context.h
+++ b/include/keymaster/contexts/keymaster2_passthrough_context.h
@@ -56,7 +56,7 @@ class Keymaster2PassthroughContext : public KeymasterContext {
     KeyFactory* GetKeyFactory(keymaster_algorithm_t algorithm) const override;
     OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
                                           keymaster_purpose_t purpose) const override;
-    keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
+    const keymaster_algorithm_t* GetSupportedAlgorithms(size_t* algorithms_count) const override;
 
     /**
      * UpgradeKeyBlob takes an existing blob, parses out key material and constructs a new blob with
```

