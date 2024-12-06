```diff
diff --git a/build/hidl_interface.go b/build/hidl_interface.go
index 1696282f..6250604b 100644
--- a/build/hidl_interface.go
+++ b/build/hidl_interface.go
@@ -627,6 +627,7 @@ This corresponds to the "-r%s:<some path>" option that would be passed into hidl
 			Libs:            []string{"hwbinder.stubs"},
 			Apex_available:  i.properties.Apex_available,
 			Min_sdk_version: getMinSdkVersion(name.string()),
+			Is_stubs_module: proptools.BoolPtr(true),
 		}
 
 		mctx.CreateModule(java.LibraryFactory, &javaProperties{
@@ -657,6 +658,7 @@ This corresponds to the "-r%s:<some path>" option that would be passed into hidl
 			Srcs:            []string{":" + name.javaConstantsSourcesName()},
 			Apex_available:  i.properties.Apex_available,
 			Min_sdk_version: getMinSdkVersion(name.string()),
+			Is_stubs_module: proptools.BoolPtr(true),
 		})
 	}
 
diff --git a/build/properties.go b/build/properties.go
index 6d67033b..d134b726 100644
--- a/build/properties.go
+++ b/build/properties.go
@@ -56,6 +56,7 @@ type javaProperties struct {
 	Static_libs     []string
 	Apex_available  []string
 	Min_sdk_version *string
+	Is_stubs_module *bool
 }
 
 type fuzzConfig struct {
diff --git a/hidl2aidl/AidlInterface.cpp b/hidl2aidl/AidlInterface.cpp
index 93317f2b..83f05e81 100644
--- a/hidl2aidl/AidlInterface.cpp
+++ b/hidl2aidl/AidlInterface.cpp
@@ -111,7 +111,7 @@ std::string getBaseName(const std::string& rawName) {
 template <class NODE>
 static void pushVersionedNodeOntoMap(const NODE& versionedNode,
                                      std::map<std::string, NODE>* latestNodeForBaseName,
-                                     std::vector<const NODE>* supersededNode) {
+                                     std::vector<NODE>* supersededNode) {
     // attempt to push name onto latestNodeForBaseName
     auto [it, inserted] =
             latestNodeForBaseName->emplace(std::move(versionedNode.baseName), versionedNode);
@@ -183,9 +183,9 @@ void AidlHelper::emitAidl(
     out << "interface " << getAidlName(interface.fqName()) << " ";
     out.block([&] {
         std::map<std::string, NodeWithVersion<NamedType>> latestTypeForBaseName;
-        std::vector<const NodeWithVersion<NamedType>> supersededNamedTypes;
+        std::vector<NodeWithVersion<NamedType>> supersededNamedTypes;
         std::map<std::string, NodeWithVersion<Method>> latestMethodForBaseName;
-        std::vector<const NodeWithVersion<Method>> supersededMethods;
+        std::vector<NodeWithVersion<Method>> supersededMethods;
         for (const Interface* iface : interface.typeChain()) {
             if (!AidlHelper::shouldBeExpanded(interface.fqName(), iface->fqName())) {
                 // Stop traversing extended interfaces once they leave this package
```

