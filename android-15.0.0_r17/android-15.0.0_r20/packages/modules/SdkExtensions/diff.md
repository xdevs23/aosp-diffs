```diff
diff --git a/OWNERS b/OWNERS
index 792e28d..36a5088 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,2 @@
 # Bug component: 1133050
-amhk@google.com
-michaelwr@google.com
-paulduffin@google.com
-
-include platform/packages/modules/common:/MODULES_OWNERS  # see go/mainline-owners-policy
\ No newline at end of file
+include platform/frameworks/base:/SDK_OWNERS
diff --git a/gen_sdk/extensions_db.textpb b/gen_sdk/extensions_db.textpb
index 17a2ebb..ce3bf2f 100644
--- a/gen_sdk/extensions_db.textpb
+++ b/gen_sdk/extensions_db.textpb
@@ -1327,3 +1327,102 @@ versions {
     }
   }
 }
+versions {
+  version: 16
+  requirements {
+    module: ART
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: CONSCRYPT
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: IPSEC
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: MEDIA
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: MEDIA_PROVIDER
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: PERMISSIONS
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: SCHEDULING
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: SDK_EXTENSIONS
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: STATSD
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: TETHERING
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: AD_SERVICES
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: APPSEARCH
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: ON_DEVICE_PERSONALIZATION
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: CONFIG_INFRASTRUCTURE
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: HEALTH_FITNESS
+    version {
+      version: 16
+    }
+  }
+  requirements {
+    module: EXT_SERVICES
+    version {
+      version: 16
+    }
+  }
+}
diff --git a/javatests/com/android/sdkext/extensions/Android.bp b/javatests/com/android/sdkext/extensions/Android.bp
index 217d2fb..448e9fa 100644
--- a/javatests/com/android/sdkext/extensions/Android.bp
+++ b/javatests/com/android/sdkext/extensions/Android.bp
@@ -27,7 +27,7 @@ java_test_host {
         "modules-utils-build-testing",
         "test_util_current_version",
     ],
-    data: [
+    device_common_data: [
         ":sdkextensions_e2e_test_app",
         ":sdkextensions_e2e_test_app_req_r12",
         ":sdkextensions_e2e_test_app_req_s12",
diff --git a/sdk-extensions-info-test/test.rs b/sdk-extensions-info-test/test.rs
index 02a624f..9f42f61 100644
--- a/sdk-extensions-info-test/test.rs
+++ b/sdk-extensions-info-test/test.rs
@@ -96,26 +96,29 @@ mod tests {
         }
 
         // verify all Sdk fields are unique across all Sdk items
+        let dupes = sdks.iter().duplicates_by(|sdk| &sdk.id).collect::<Vec<_>>();
+        ensure!(dupes.is_empty(), "{:?}: multiple sdk entries with identical id value", dupes);
+
+        let dupes = sdks.iter().duplicates_by(|sdk| &sdk.shortname).collect::<Vec<_>>();
         ensure!(
-            sdks.iter().duplicates_by(|sdk| &sdk.id).collect::<Vec<_>>().is_empty(),
-            "multiple sdk entries with identical id value"
-        );
-        ensure!(
-            sdks.iter().duplicates_by(|sdk| &sdk.shortname).collect::<Vec<_>>().is_empty(),
-            "multiple sdk entries with identical shortname value"
-        );
-        ensure!(
-            sdks.iter().duplicates_by(|sdk| &sdk.name).collect::<Vec<_>>().is_empty(),
-            "multiple sdk entries with identical name value"
+            dupes.is_empty(),
+            "{:?}: multiple sdk entries with identical shortname value",
+            dupes
         );
+
+        let dupes = sdks.iter().duplicates_by(|sdk| &sdk.name).collect::<Vec<_>>();
+        ensure!(dupes.is_empty(), "{:?}: multiple sdk entries with identical name value", dupes);
+
+        let dupes = sdks.iter().duplicates_by(|sdk| &sdk.reference).collect::<Vec<_>>();
         ensure!(
-            sdks.iter().duplicates_by(|sdk| &sdk.reference).collect::<Vec<_>>().is_empty(),
-            "multiple sdk entries with identical reference value"
+            dupes.is_empty(),
+            "{:?}: multiple sdk entries with identical reference value",
+            dupes
         );
 
         // verify Sdk id field has the expected format (positive integer)
-        for id in sdks.iter().map(|sdk| &sdk.id) {
-            ensure!(id.parse::<usize>().is_ok(), "sdk id {} not a positive int", id);
+        for sdk in sdks.iter() {
+            ensure!(sdk.id.parse::<usize>().is_ok(), "{:?}: id not a positive int", sdk);
         }
 
         // verify individual Symbol elements
@@ -123,10 +126,26 @@ mod tests {
         for symbol in symbols.iter() {
             ensure!(
                 symbol.sdks.iter().duplicates().collect::<Vec<_>>().is_empty(),
-                "symbol contains duplicate references to the same sdk"
+                "{:?}: symbol contains duplicate references to the same sdk",
+                symbol
+            );
+            ensure!(
+                !symbol.jar.contains(char::is_whitespace),
+                "{:?}: jar contains whitespace",
+                symbol
+            );
+            ensure!(
+                !symbol.pattern.contains(char::is_whitespace),
+                "{:?}: pattern contains whitespace",
+                symbol
             );
             for id in symbol.sdks.iter() {
-                ensure!(sdk_shortnames.contains(&id), "symbol refers to non-existent sdk {}", id);
+                ensure!(
+                    sdk_shortnames.contains(&id),
+                    "{:?}: symbol refers to non-existent sdk {}",
+                    symbol,
+                    id
+                );
             }
         }
 
@@ -166,28 +185,39 @@ mod tests {
         );
         assert_err!(
             "testdata/duplicate-sdk-id.xml",
-            "multiple sdk entries with identical id value"
+            r#"[Sdk { id: "1", shortname: "bar", name: "The bar extensions", reference: "android/os/Build$BAR" }]: multiple sdk entries with identical id value"#
         );
         assert_err!(
             "testdata/duplicate-sdk-shortname.xml",
-            "multiple sdk entries with identical shortname value"
+            r#"[Sdk { id: "2", shortname: "foo", name: "The bar extensions", reference: "android/os/Build$BAR" }]: multiple sdk entries with identical shortname value"#
         );
         assert_err!(
             "testdata/duplicate-sdk-name.xml",
-            "multiple sdk entries with identical name value"
+            r#"[Sdk { id: "2", shortname: "bar", name: "The foo extensions", reference: "android/os/Build$BAR" }]: multiple sdk entries with identical name value"#
         );
         assert_err!(
             "testdata/duplicate-sdk-reference.xml",
-            "multiple sdk entries with identical reference value"
+            r#"[Sdk { id: "2", shortname: "bar", name: "The bar extensions", reference: "android/os/Build$FOO" }]: multiple sdk entries with identical reference value"#
+        );
+        assert_err!(
+            "testdata/incorrect-sdk-id-format.xml",
+            r#"Sdk { id: "1.0", shortname: "foo", name: "The foo extensions", reference: "android/os/Build$FOO" }: id not a positive int"#
         );
-        assert_err!("testdata/incorrect-sdk-id-format.xml", "sdk id 1.0 not a positive int");
         assert_err!(
             "testdata/duplicate-symbol-sdks.xml",
-            "symbol contains duplicate references to the same sdk"
+            r#"Symbol { jar: "framework-something", pattern: "*", sdks: ["foo", "bar", "bar"] }: symbol contains duplicate references to the same sdk"#
         );
         assert_err!(
             "testdata/symbol-refers-to-non-existent-sdk.xml",
-            "symbol refers to non-existent sdk does-not-exist"
+            r#"Symbol { jar: "framework-something", pattern: "*", sdks: ["foo", "does-not-exist", "bar"] }: symbol refers to non-existent sdk does-not-exist"#
+        );
+        assert_err!(
+            "testdata/whitespace-in-jar.xml",
+            r#"Symbol { jar: "framework something", pattern: "*", sdks: ["foo", "bar"] }: jar contains whitespace"#
+        );
+        assert_err!(
+            "testdata/whitespace-in-pattern.xml",
+            r#"Symbol { jar: "framework-something-else", pattern: "android.app.appsearch.AppSearchSchema.DocumentPropertyConfig.Builder\n                .addIndexableNestedProperties ", sdks: ["bar"] }: pattern contains whitespace"#
         );
     }
 
diff --git a/sdk-extensions-info-test/testdata/whitespace-in-jar.xml b/sdk-extensions-info-test/testdata/whitespace-in-jar.xml
new file mode 100644
index 0000000..e479ca4
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/whitespace-in-jar.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<sdk-extensions-info>
+    <sdk
+        id="1"
+        shortname="foo"
+        name="The foo extensions"
+        reference="android/os/Build$FOO" />
+    <sdk
+        id="2"
+        shortname="bar"
+        name="The bar extensions"
+        reference="android/os/Build$BAR" />
+    <symbol
+        jar="framework something"
+        pattern="*"
+        sdks="foo,bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.a"
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info-test/testdata/whitespace-in-pattern.xml b/sdk-extensions-info-test/testdata/whitespace-in-pattern.xml
new file mode 100644
index 0000000..bf8c53a
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/whitespace-in-pattern.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<sdk-extensions-info>
+    <sdk
+        id="1"
+        shortname="foo"
+        name="The foo extensions"
+        reference="android/os/Build$FOO" />
+    <sdk
+        id="2"
+        shortname="bar"
+        name="The bar extensions"
+        reference="android/os/Build$BAR" />
+    <symbol
+        jar="framework-something"
+        pattern="*"
+        sdks="foo,bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="android.app.appsearch.AppSearchSchema.DocumentPropertyConfig.Builder
+                .addIndexableNestedProperties "
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info.xml b/sdk-extensions-info.xml
index d3d0637..3f1eb41 100644
--- a/sdk-extensions-info.xml
+++ b/sdk-extensions-info.xml
@@ -61,12 +61,7 @@
   <!-- APPSEARCH -->
   <symbol
     jar="framework-appsearch"
-    pattern="android.app.appsearch.AppSearchSchema.Builder.addParentType"
-    sdks="T-ext,U-ext,V-ext" />
-  <symbol
-    jar="framework-appsearch"
-    pattern="android.app.appsearch.AppSearchSchema.DocumentPropertyConfig.Builder
-            .addIndexableNestedProperties"
+    pattern="android.app.appsearch"
     sdks="T-ext,U-ext,V-ext" />
 
   <!-- MEDIA_PROVIDER -->
@@ -138,6 +133,10 @@
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.QUERY_ARG_MEDIA_STANDARD_SORT_ORDER"
     sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.markIsFavoriteStatus"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.VOLUME_EXTERNAL"
@@ -536,4 +535,229 @@
     pattern="android.health.connect.datatypes.MindfulnessSessionRecord.Builder"
     sdks="U-ext,V-ext" />
 
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.createMedicalDataSource"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.deleteMedicalDataSourceWithData"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.deleteMedicalResources"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.getMedicalDataSources"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.readMedicalResources"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthConnectManager.upsertMedicalResources"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.CreateMedicalDataSourceRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.CreateMedicalDataSourceRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.DeleteMedicalResourcesRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.DeleteMedicalResourcesRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.GetMedicalDataSourcesRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.GetMedicalDataSourcesRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.MedicalResourceId"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesInitialRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesInitialRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesPageRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesPageRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.ReadMedicalResourcesResponse"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.UpsertMedicalResourceRequest"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.UpsertMedicalResourceRequest.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.FhirResource"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.FhirResource.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.FhirVersion"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MedicalDataSource"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MedicalDataSource.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MedicalResource"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MedicalResource.Builder"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_ALLERGIES_INTOLERANCES"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_CONDITIONS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VACCINES"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_LABORATORY_RESULTS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_MEDICATIONS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PERSONAL_DETAILS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PRACTITIONER_DETAILS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PREGNANCY"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PROCEDURES"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_SOCIAL_HISTORY"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VISITS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VITAL_SIGNS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.WRITE_MEDICAL_DATA"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_ACTIVITY_INTENSITY"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.WRITE_ACTIVITY_INTENSITY"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.ActivityIntensityRecord"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.ActivityIntensityRecord.Builder"
+    sdks="U-ext,V-ext" />
+
 </sdk-extensions-info>
```

