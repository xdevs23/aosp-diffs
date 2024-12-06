```diff
diff --git a/OWNERS b/OWNERS
index ea61d9b..792e28d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,6 @@
 # Bug component: 1133050
 amhk@google.com
-gurpreetgs@google.com
-hansson@google.com
+michaelwr@google.com
 paulduffin@google.com
-robertogil@google.com
 
 include platform/packages/modules/common:/MODULES_OWNERS  # see go/mainline-owners-policy
\ No newline at end of file
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index ab1d052..700df2b 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -4,9 +4,11 @@ clang_format = true
 commit_msg_changeid_field = true
 commit_msg_test_field = true
 google_java_format = true
+rustfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
 
 [Hook Scripts]
 do_not_use_DO_NOT_MERGE = ${REPO_ROOT}/build/soong/scripts/check_do_not_merge.sh ${PREUPLOAD_COMMIT}
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 9f1e2f5..2f4e7b7 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -18,6 +18,9 @@
     },
     {
       "name": "gen_sdk_test"
+    },
+    {
+      "name": "sdk-extensions-info-test"
     }
   ],
   "presubmit-large": [
diff --git a/gen_sdk/extensions_db.textpb b/gen_sdk/extensions_db.textpb
index 83d2ee5..17a2ebb 100644
--- a/gen_sdk/extensions_db.textpb
+++ b/gen_sdk/extensions_db.textpb
@@ -1129,3 +1129,201 @@ versions {
     }
   }
 }
+versions {
+  version: 14
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
+      version: 13
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
+      version: 13
+    }
+  }
+  requirements {
+    module: AD_SERVICES
+    version {
+      version: 14
+    }
+  }
+  requirements {
+    module: APPSEARCH
+    version {
+      version: 13
+    }
+  }
+  requirements {
+    module: ON_DEVICE_PERSONALIZATION
+    version {
+      version: 13
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
+      version: 13
+    }
+  }
+  requirements {
+    module: EXT_SERVICES
+    version {
+      version: 14
+    }
+  }
+}
+versions {
+  version: 15
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
+      version: 15
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
+      version: 15
+    }
+  }
+  requirements {
+    module: AD_SERVICES
+    version {
+      version: 15
+    }
+  }
+  requirements {
+    module: APPSEARCH
+    version {
+      version: 15
+    }
+  }
+  requirements {
+    module: ON_DEVICE_PERSONALIZATION
+    version {
+      version: 15
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
+      version: 15
+    }
+  }
+  requirements {
+    module: EXT_SERVICES
+    version {
+      version: 15
+    }
+  }
+}
diff --git a/javatests/com/android/os/classpath/AndroidTest.xml b/javatests/com/android/os/classpath/AndroidTest.xml
index f4047f5..af8992b 100644
--- a/javatests/com/android/os/classpath/AndroidTest.xml
+++ b/javatests/com/android/os/classpath/AndroidTest.xml
@@ -20,6 +20,7 @@
     <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
     <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
     <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
     <test class="com.android.tradefed.testtype.HostTest" >
         <option name="jar" value="CtsClasspathsTestCases.jar" />
     </test>
diff --git a/javatests/com/android/os/ext/CtsSdkExtensionsTestCases.xml b/javatests/com/android/os/ext/CtsSdkExtensionsTestCases.xml
index a0b2055..aeb4643 100644
--- a/javatests/com/android/os/ext/CtsSdkExtensionsTestCases.xml
+++ b/javatests/com/android/os/ext/CtsSdkExtensionsTestCases.xml
@@ -19,6 +19,7 @@
     <option name="config-descriptor:metadata" key="parameter" value="instant_app" />
     <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
     <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="cleanup-apks" value="true" />
         <option name="test-file-name" value="CtsSdkExtensionsTestCases.apk" />
diff --git a/javatests/com/android/os/ext/SdkExtensionsTest.java b/javatests/com/android/os/ext/SdkExtensionsTest.java
index b744940..bb2172c 100644
--- a/javatests/com/android/os/ext/SdkExtensionsTest.java
+++ b/javatests/com/android/os/ext/SdkExtensionsTest.java
@@ -62,15 +62,19 @@ public class SdkExtensionsTest {
     private static final String TAG = "SdkExtensionsTest";
 
     private enum Expectation {
-        /** Expect an extension to be the current / latest defined version */
-        CURRENT,
+        /**
+         * Expect an extension to be the current / latest defined version, or later (which may be
+         * the case if the device under test comes from a more recent build that the tests come
+         * from).
+         */
+        AT_LEAST_CURRENT,
         /** Expect an extension to be missing / version 0 */
         MISSING,
         /** Expect an extension to be at least the base extension version of the device */
         AT_LEAST_BASE,
     }
 
-    private static final Expectation CURRENT = Expectation.CURRENT;
+    private static final Expectation AT_LEAST_CURRENT = Expectation.AT_LEAST_CURRENT;
     private static final Expectation MISSING = Expectation.MISSING;
     private static final Expectation AT_LEAST_BASE = Expectation.AT_LEAST_BASE;
 
@@ -89,8 +93,8 @@ public class SdkExtensionsTest {
 
     private static void assertVersion(Expectation expectation, int version) {
         switch (expectation) {
-            case CURRENT:
-                assertEquals(CURRENT_TRAIN_VERSION, version);
+            case AT_LEAST_CURRENT:
+                assertThat(version).isAtLeast(CURRENT_TRAIN_VERSION);
                 break;
             case AT_LEAST_BASE:
                 assertAtLeastBaseVersion(version);
@@ -226,7 +230,9 @@ public class SdkExtensionsTest {
         // Go trains don't include all modules, so even when all trains for a particular release
         // have been installed correctly on a Go device, we can't generally expect the extension
         // version to be the current train version.
-        return SdkLevel.isAtLeastT() && isGoWithSideloadedModules() ? AT_LEAST_BASE : CURRENT;
+        return SdkLevel.isAtLeastT() && isGoWithSideloadedModules()
+                ? AT_LEAST_BASE
+                : AT_LEAST_CURRENT;
     }
 
     private boolean isGoWithSideloadedModules() throws Exception {
diff --git a/javatests/com/android/sdkext/extensions/apps/Android.bp b/javatests/com/android/sdkext/extensions/apps/Android.bp
index 5b9e638..da05413 100644
--- a/javatests/com/android/sdkext/extensions/apps/Android.bp
+++ b/javatests/com/android/sdkext/extensions/apps/Android.bp
@@ -21,7 +21,7 @@ android_test_helper_app {
     name: "sdkextensions_e2e_test_app",
     srcs: ["Receiver.java"],
     libs: [
-        "framework-sdkextensions",
+        "framework-sdkextensions.stubs.module_lib",
         // Depend on the impl library directly so that its tests can try and
         // invoke methods which it is not allowed to use to verify that the
         // runtime correctly refuses access to them.
diff --git a/rustfmt.toml b/rustfmt.toml
new file mode 100644
index 0000000..cefaa42
--- /dev/null
+++ b/rustfmt.toml
@@ -0,0 +1,5 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
diff --git a/sdk-extensions-info-test/Android.bp b/sdk-extensions-info-test/Android.bp
new file mode 100644
index 0000000..ea605ed
--- /dev/null
+++ b/sdk-extensions-info-test/Android.bp
@@ -0,0 +1,19 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_test_host {
+    name: "sdk-extensions-info-test",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    srcs: [
+        "test.rs",
+    ],
+    rustlibs: [
+        "libanyhow",
+        "libitertools",
+        "libxml_rust",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/sdk-extensions-info-test/test.rs b/sdk-extensions-info-test/test.rs
new file mode 100644
index 0000000..02a624f
--- /dev/null
+++ b/sdk-extensions-info-test/test.rs
@@ -0,0 +1,198 @@
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
+#[cfg(test)]
+mod tests {
+    use anyhow::{anyhow, bail, ensure, Result};
+    use itertools::Itertools;
+    use std::fmt::Debug;
+    use std::io::Read;
+    use xml::attribute::OwnedAttribute;
+    use xml::reader::{ParserConfig, XmlEvent};
+
+    fn get_attribute(attributes: &[OwnedAttribute], tag: &str, key: &str) -> Result<String> {
+        attributes
+            .iter()
+            .find_map(
+                |attr| {
+                    if attr.name.local_name == key {
+                        Some(attr.value.clone())
+                    } else {
+                        None
+                    }
+                },
+            )
+            .ok_or_else(|| anyhow!("tag {}: missing attribute {}", tag, key))
+    }
+
+    fn verify_xml<R: Read>(mut source: R) -> Result<()> {
+        #[derive(Debug)]
+        struct Sdk {
+            id: String,
+            shortname: String,
+            name: String,
+            reference: String,
+        }
+
+        #[derive(Debug)]
+        struct Symbol {
+            #[allow(dead_code)]
+            jar: String,
+            #[allow(dead_code)]
+            pattern: String,
+            sdks: Vec<String>,
+        }
+
+        // this will error out on XML syntax errors
+        let reader = ParserConfig::new().create_reader(&mut source);
+        let events: Vec<_> = reader.into_iter().collect::<Result<Vec<_>, _>>()?;
+
+        // parse XML
+        let mut sdks = vec![];
+        let mut symbols = vec![];
+        for (name, attributes) in events.into_iter().filter_map(|e| match e {
+            XmlEvent::StartElement { name, attributes, namespace: _ } => {
+                Some((name.local_name, attributes))
+            }
+            _ => None,
+        }) {
+            match name.as_str() {
+                "sdk-extensions-info" => {}
+                "sdk" => {
+                    let sdk = Sdk {
+                        id: get_attribute(&attributes, "sdk", "id")?,
+                        shortname: get_attribute(&attributes, "sdk", "shortname")?,
+                        name: get_attribute(&attributes, "sdk", "name")?,
+                        reference: get_attribute(&attributes, "sdk", "reference")?,
+                    };
+                    sdks.push(sdk);
+                }
+                "symbol" => {
+                    let symbol = Symbol {
+                        jar: get_attribute(&attributes, "symbol", "jar")?,
+                        pattern: get_attribute(&attributes, "symbol", "pattern")?,
+                        sdks: get_attribute(&attributes, "symbol", "sdks")?
+                            .split(',')
+                            .map(|s| s.to_owned())
+                            .collect(),
+                    };
+                    symbols.push(symbol);
+                }
+                _ => bail!("unknown tag '{}'", name),
+            }
+        }
+
+        // verify all Sdk fields are unique across all Sdk items
+        ensure!(
+            sdks.iter().duplicates_by(|sdk| &sdk.id).collect::<Vec<_>>().is_empty(),
+            "multiple sdk entries with identical id value"
+        );
+        ensure!(
+            sdks.iter().duplicates_by(|sdk| &sdk.shortname).collect::<Vec<_>>().is_empty(),
+            "multiple sdk entries with identical shortname value"
+        );
+        ensure!(
+            sdks.iter().duplicates_by(|sdk| &sdk.name).collect::<Vec<_>>().is_empty(),
+            "multiple sdk entries with identical name value"
+        );
+        ensure!(
+            sdks.iter().duplicates_by(|sdk| &sdk.reference).collect::<Vec<_>>().is_empty(),
+            "multiple sdk entries with identical reference value"
+        );
+
+        // verify Sdk id field has the expected format (positive integer)
+        for id in sdks.iter().map(|sdk| &sdk.id) {
+            ensure!(id.parse::<usize>().is_ok(), "sdk id {} not a positive int", id);
+        }
+
+        // verify individual Symbol elements
+        let sdk_shortnames: Vec<_> = sdks.iter().map(|sdk| &sdk.shortname).collect();
+        for symbol in symbols.iter() {
+            ensure!(
+                symbol.sdks.iter().duplicates().collect::<Vec<_>>().is_empty(),
+                "symbol contains duplicate references to the same sdk"
+            );
+            for id in symbol.sdks.iter() {
+                ensure!(sdk_shortnames.contains(&id), "symbol refers to non-existent sdk {}", id);
+            }
+        }
+
+        Ok(())
+    }
+
+    #[test]
+    fn test_get_attribute() {
+        use xml::EventReader;
+
+        let mut iter = EventReader::from_str(r#"<tag a="A" b="B" c="C"/>"#).into_iter();
+        let _ = iter.next().unwrap(); // skip start of doc
+        let Ok(XmlEvent::StartElement { attributes, .. }) = iter.next().unwrap() else {
+            panic!();
+        };
+        assert_eq!(get_attribute(&attributes, "tag", "a").unwrap(), "A");
+        assert!(get_attribute(&attributes, "tag", "no-such-attribute").is_err());
+    }
+
+    #[test]
+    fn test_verify_xml_correct_input() {
+        verify_xml(&include_bytes!("testdata/correct.xml")[..]).unwrap();
+    }
+
+    #[test]
+    fn test_verify_xml_incorrect_input() {
+        macro_rules! assert_err {
+            ($input_path:expr, $expected_error:expr) => {
+                let error = verify_xml(&include_bytes!($input_path)[..]).unwrap_err().to_string();
+                assert_eq!(error, $expected_error);
+            };
+        }
+
+        assert_err!(
+            "testdata/corrupt-xml.xml",
+            "25:1 Unexpected end of stream: still inside the root element"
+        );
+        assert_err!(
+            "testdata/duplicate-sdk-id.xml",
+            "multiple sdk entries with identical id value"
+        );
+        assert_err!(
+            "testdata/duplicate-sdk-shortname.xml",
+            "multiple sdk entries with identical shortname value"
+        );
+        assert_err!(
+            "testdata/duplicate-sdk-name.xml",
+            "multiple sdk entries with identical name value"
+        );
+        assert_err!(
+            "testdata/duplicate-sdk-reference.xml",
+            "multiple sdk entries with identical reference value"
+        );
+        assert_err!("testdata/incorrect-sdk-id-format.xml", "sdk id 1.0 not a positive int");
+        assert_err!(
+            "testdata/duplicate-symbol-sdks.xml",
+            "symbol contains duplicate references to the same sdk"
+        );
+        assert_err!(
+            "testdata/symbol-refers-to-non-existent-sdk.xml",
+            "symbol refers to non-existent sdk does-not-exist"
+        );
+    }
+
+    #[test]
+    fn test_actual_sdk_extensions_info_contents() {
+        verify_xml(&include_bytes!("../sdk-extensions-info.xml")[..]).unwrap();
+    }
+}
diff --git a/sdk-extensions-info-test/testdata/correct.xml b/sdk-extensions-info-test/testdata/correct.xml
new file mode 100644
index 0000000..91d756c
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/correct.xml
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
+        jar="framework-something"
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
diff --git a/sdk-extensions-info-test/testdata/corrupt-xml.xml b/sdk-extensions-info-test/testdata/corrupt-xml.xml
new file mode 100644
index 0000000..26aa449
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/corrupt-xml.xml
@@ -0,0 +1,24 @@
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
+        pattern="pkg.a"
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
diff --git a/sdk-extensions-info-test/testdata/duplicate-sdk-id.xml b/sdk-extensions-info-test/testdata/duplicate-sdk-id.xml
new file mode 100644
index 0000000..e92a7dd
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/duplicate-sdk-id.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<sdk-extensions-info>
+    <sdk
+        id="1"
+        shortname="foo"
+        name="The foo extensions"
+        reference="android/os/Build$FOO" />
+    <sdk
+        id="1"
+        shortname="bar"
+        name="The bar extensions"
+        reference="android/os/Build$BAR" />
+    <symbol
+        jar="framework-something"
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
diff --git a/sdk-extensions-info-test/testdata/duplicate-sdk-name.xml b/sdk-extensions-info-test/testdata/duplicate-sdk-name.xml
new file mode 100644
index 0000000..d083c1f
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/duplicate-sdk-name.xml
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
+        name="The foo extensions"
+        reference="android/os/Build$BAR" />
+    <symbol
+        jar="framework-something"
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
diff --git a/sdk-extensions-info-test/testdata/duplicate-sdk-reference.xml b/sdk-extensions-info-test/testdata/duplicate-sdk-reference.xml
new file mode 100644
index 0000000..ef5fbdd
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/duplicate-sdk-reference.xml
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
+        reference="android/os/Build$FOO" />
+    <symbol
+        jar="framework-something"
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
diff --git a/sdk-extensions-info-test/testdata/duplicate-sdk-shortname.xml b/sdk-extensions-info-test/testdata/duplicate-sdk-shortname.xml
new file mode 100644
index 0000000..27380aa
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/duplicate-sdk-shortname.xml
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
+        shortname="foo"
+        name="The bar extensions"
+        reference="android/os/Build$BAR" />
+    <symbol
+        jar="framework-something"
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
diff --git a/sdk-extensions-info-test/testdata/duplicate-symbol-sdks.xml b/sdk-extensions-info-test/testdata/duplicate-symbol-sdks.xml
new file mode 100644
index 0000000..47ddb30
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/duplicate-symbol-sdks.xml
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
+        jar="framework-something"
+        pattern="*"
+        sdks="foo,bar,bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.a"
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info-test/testdata/incorrect-sdk-id-format.xml b/sdk-extensions-info-test/testdata/incorrect-sdk-id-format.xml
new file mode 100644
index 0000000..ddaa958
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/incorrect-sdk-id-format.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<sdk-extensions-info>
+    <sdk
+        id="1.0"
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
+        pattern="pkg.a"
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info-test/testdata/symbol-refers-to-non-existent-sdk.xml b/sdk-extensions-info-test/testdata/symbol-refers-to-non-existent-sdk.xml
new file mode 100644
index 0000000..96fb15f
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/symbol-refers-to-non-existent-sdk.xml
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
+        jar="framework-something"
+        pattern="*"
+        sdks="foo,does-not-exist,bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.a"
+        sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.b"
+        sdks="bar" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info.xml b/sdk-extensions-info.xml
index 974a05e..d3d0637 100644
--- a/sdk-extensions-info.xml
+++ b/sdk-extensions-info.xml
@@ -118,10 +118,50 @@
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.getVersion"
     sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.openFileDescriptor"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.openAssetFileDescriptor"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.openTypedAssetFileDescriptor"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.ACCESS_OEM_METADATA_PERMISSION"
+    sdks="T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.QUERY_ARG_MEDIA_STANDARD_SORT_ORDER"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.VOLUME_EXTERNAL"
     sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.MediaColumns.INFERRED_DATE"
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.MediaColumns.OEM_METADATA"
+    sdks="T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.Audio.AudioColumns.BITS_PER_SAMPLE"
+    sdks="T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.Audio.AudioColumns.SAMPLERATE"
+    sdks="T-ext,U-ext,V-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.OemMetadataService"
+    sdks="T-ext,U-ext,V-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.CloudMediaProvider"
@@ -143,6 +183,12 @@
     pattern="android.provider.MediaStore.notifyCloudMediaChangedEvent"
     sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
 
+   <!-- PHOTOPICKER -->
+   <symbol
+    jar="framework-photopicker"
+    pattern="android.widget.photopicker"
+    sdks="U-ext,V-ext" />
+
   <!-- CONNECTIVITY -->
   <symbol
     jar="framework-connectivity"
@@ -160,6 +206,10 @@
     jar="framework-connectivity"
     pattern="android.net"
     sdks="U-ext,V-ext" />
+  <symbol
+    jar="framework-connectivity-t"
+    pattern="android.net.NetworkStats"
+    sdks="T-ext,U-ext,V-ext" />
 
   <!-- PDF -->
   <symbol
@@ -466,4 +516,24 @@
     pattern="android.health.connect.datatypes.ExerciseSessionRecord.getPlannedExerciseSessionId"
     sdks="U-ext,V-ext" />
 
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.READ_MINDFULNESS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.HealthPermissions.WRITE_MINDFULNESS"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MindfulnessSessionRecord"
+    sdks="U-ext,V-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.datatypes.MindfulnessSessionRecord.Builder"
+    sdks="U-ext,V-ext" />
+
 </sdk-extensions-info>
```

