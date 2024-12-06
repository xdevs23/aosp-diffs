```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..1390cc2
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,37 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc {
+    name: "approved-ogki-builds.xml",
+    src: "approved-ogki-builds.xml",
+    sub_dir: "kernel",
+}
+
+prebuilt_etc {
+    name: "kernel-lifetimes.xml",
+    src: "kernel-lifetimes.xml",
+    sub_dir: "kernel",
+}
+
+filegroup {
+    name: "kernel_lifetimes_ref",
+    srcs: [
+        "kernel-lifetimes.xml",
+    ],
+}
diff --git a/OWNERS b/OWNERS
index ea62c47..8cafa08 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1 @@
-adelva@google.com
-elsk@google.com
-sspatil@google.com
-tkjos@google.com
+include kernel/common:android-mainline:/OWNERS
diff --git a/approved-ogki-builds.xml b/approved-ogki-builds.xml
new file mode 100644
index 0000000..41a3933
--- /dev/null
+++ b/approved-ogki-builds.xml
@@ -0,0 +1,13 @@
+<ogki-approved version="1">
+    <branch name="android14-6.1">
+        <build id="ac5884e09bd22ecd2375c7c2cfe578eebd2f943c00257c57daf3973d6dbef2d8" bug="352795077"/>
+    </branch>
+    <branch name="android15-6.6">
+        <build id="9541494216af24d2fffb20356a05ab797b7de641eef05b748dfe217dd9778e2a" bug="359105495"/>
+        <build id="fbde0e8f64bf18d9695ef2d77bc43f57097b5001a95b09802a887dacb20044de" bug="355127761"/>
+        <build id="0ae1f2faa245584c5e28f48a36137eab04bcf0d72f0839304145ecd8a289f759" bug="362162679"/>
+        <build id="33c3a0275689e4e1ec425168c518bb2a19067d15134b8a378d9f559e81a158a2" bug="365040462"/>
+        <build id="0141db8fab24fa166137f8ab0a22ab2f50e3cf7b582e1619713641e27604b42d" bug="365050796"/>
+        <build id="cef7d3cb5e807a1290e8ebfec13d82666e7e9fea3607b9b85a1c98ad660b5db2" bug="367569362"/>
+    </branch>
+</ogki-approved>
diff --git a/kernel-lifetimes.xml b/kernel-lifetimes.xml
new file mode 100644
index 0000000..acae814
--- /dev/null
+++ b/kernel-lifetimes.xml
@@ -0,0 +1,70 @@
+<kernels schema_version="0">
+	<branch name="android-4.14" version="4.14" launch="2017-10-22" eol="2024-01-01">
+		<no-releases reason="non-GKI kernel"/>
+	</branch>
+
+	<branch name="android-4.19" version="4.19" launch="2018-10-22" eol="2025-01-01">
+		<no-releases reason="non-GKI kernel"/>
+	</branch>
+	<branch name="android11-5.4" min_android_release="11" version="5.4" launch="2019-11-24" eol="2026-01-01">
+		<no-releases reason="non-GKI kernel"/>
+	</branch>
+	<branch name="android12-5.4" min_android_release="12" version="5.4" launch="2019-11-24" eol="2026-01-01">
+		<no-releases reason="non-GKI kernel"/>
+	</branch>
+
+	<branch name="android12-5.10" min_android_release="12" version="5.10" launch="2020-12-13" eol="2027-07-01">
+		<lts-versions>
+			<release version="5.10.198" launch="2023-11-14" eol="2024-11-01"/>
+			<release version="5.10.205" launch="2024-03-12" eol="2024-11-01"/>
+			<release version="5.10.209" launch="2024-05-09" eol="2025-06-01"/>
+		</lts-versions>
+	</branch>
+
+	<branch name="android13-5.10" min_android_release="13" version="5.10" launch="2020-12-13" eol="2027-07-01">
+		<lts-versions>
+			<release version="5.10.189" launch="2023-10-31" eol="2024-11-01"/>
+			<release version="5.10.198" launch="2023-12-13" eol="2024-11-01"/>
+			<release version="5.10.205" launch="2024-02-20" eol="2024-11-01"/>
+			<release version="5.10.209" launch="2024-04-27" eol="2025-06-01"/>
+			<release version="5.10.210" launch="2024-06-21" eol="2025-07-01"/>
+		</lts-versions>
+	</branch>
+
+	<branch name="android13-5.15" min_android_release="13" version="5.15" launch="2021-10-31" eol="2028-07-01">
+		<lts-versions>
+			<release version="5.15.123" launch="2023-10-27" eol="2024-11-01"/>
+			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
+			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
+			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
+			<release version="5.15.149" launch="2024-06-12" eol="2025-07-01"/>
+		</lts-versions>
+	</branch>
+
+	<branch name="android14-5.15" min_android_release="14" version="5.15" launch="2021-10-31" eol="2028-07-01">
+		<lts-versions>
+			<release version="5.15.123" launch="2023-10-27" eol="2024-11-01"/>
+			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
+			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
+			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
+			<release version="5.15.149" launch="2024-06-27" eol="2025-07-01"/>
+			<release version="5.15.153" launch="2024-07-09" eol="2025-08-01"/>
+		</lts-versions>
+	</branch>
+
+	<branch name="android14-6.1" min_android_release="14" version="6.1" launch="2022-12-11" eol="2029-07-01">
+		<lts-versions>
+			<release version="6.1.43" launch="2023-10-31" eol="2024-11-01"/>
+			<release version="6.1.57" launch="2023-12-15" eol="2024-11-01"/>
+			<release version="6.1.68" launch="2024-02-21" eol="2024-11-01"/>
+			<release version="6.1.75" launch="2024-04-24" eol="2025-05-01"/>
+			<release version="6.1.78" launch="2024-06-20" eol="2025-07-01"/>
+		</lts-versions>
+	</branch>
+
+	<branch name="android15-6.6" min_android_release="15" version="6.6" launch="2023-10-29" eol="2028-07-01">
+		<lts-versions>
+			<release version="6.6.30" launch="2024-07-12" eol="2025-08-01"/>
+		</lts-versions>
+	</branch>
+</kernels>
diff --git a/tools/bump.py b/tools/bump.py
index 8aed6bd..13fd4f8 100755
--- a/tools/bump.py
+++ b/tools/bump.py
@@ -30,7 +30,9 @@ def check_call(*args, **kwargs):
     subprocess.check_call(*args, **kwargs)
 
 def replace_configs_module_name(current_release, new_release, file_path):
-    check_call("sed -i'' -E 's/\"kernel_config_{}_([0-9.]*)\"/\"kernel_config_{}_\\1\"/g' {}"
+    # TODO(b/355580919): Remove the pattern '[0-9]+\\.next' by replacing the
+    # version placeholder with 'next'.
+    check_call("sed -i'' -E 's/\"kernel_config_{}_([0-9]+\\.[0-9]+|[0-9]+\\.next|next)\"/\"kernel_config_{}_\\1\"/g' {}"
                 .format(current_release, new_release, file_path), shell=True)
 
 class Bump(object):
diff --git a/xsd/approvedBuild/Android.bp b/xsd/approvedBuild/Android.bp
new file mode 100644
index 0000000..5a5e517
--- /dev/null
+++ b/xsd/approvedBuild/Android.bp
@@ -0,0 +1,29 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_android_kernel",
+
+    // http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+xsd_config {
+    name: "approved_build",
+    srcs: ["approved_build.xsd"],
+    package_name: "approved.build",
+    api_dir: "schema",
+}
diff --git a/xsd/approvedBuild/approved_build.xsd b/xsd/approvedBuild/approved_build.xsd
new file mode 100644
index 0000000..a2d06aa
--- /dev/null
+++ b/xsd/approvedBuild/approved_build.xsd
@@ -0,0 +1,39 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+         Licensed under the Apache License, Version 2.0 (the "License");
+         you may not use this file except in compliance with the License.
+         You may obtain a copy of the License at
+
+                    http://www.apache.org/licenses/LICENSE-2.0
+
+         Unless required by applicable law or agreed to in writing, software
+         distributed under the License is distributed on an "AS IS" BASIS,
+         WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+         See the License for the specific language governing permissions and
+         limitations under the License.
+-->
+
+<xs:schema version="2.0"
+           elementFormDefault="qualified"
+           attributeFormDefault="unqualified"
+           xmlns:xs="http://www.w3.org/2001/XMLSchema">
+    <xs:element name="ogki-approved">
+        <xs:complexType>
+            <xs:sequence>
+                <xs:element name="branch" type="branch" minOccurs="0" maxOccurs="unbounded"/>
+            </xs:sequence>
+            <xs:attribute name="version" type="xs:int" use="required"/>
+        </xs:complexType>
+    </xs:element>
+    <xs:complexType name="branch">
+        <xs:sequence>
+            <xs:element name="build" type="build" minOccurs="0" maxOccurs="unbounded"/>
+        </xs:sequence>
+        <xs:attribute name="name" type="xs:string" use="required"/>
+    </xs:complexType>
+    <xs:complexType name="build">
+        <xs:attribute name="id" type="xs:string" use="required"/>
+        <xs:attribute name="bug" type="xs:integer"/>
+    </xs:complexType>
+</xs:schema>
diff --git a/xsd/approvedBuild/schema/current.txt b/xsd/approvedBuild/schema/current.txt
new file mode 100644
index 0000000..329b837
--- /dev/null
+++ b/xsd/approvedBuild/schema/current.txt
@@ -0,0 +1,34 @@
+// Signature format: 2.0
+package approved.build {
+
+  public class Branch {
+    ctor public Branch();
+    method public java.util.List<approved.build.Build> getBuild();
+    method public String getName();
+    method public void setName(String);
+  }
+
+  public class Build {
+    ctor public Build();
+    method public java.math.BigInteger getBug();
+    method public String getId();
+    method public void setBug(java.math.BigInteger);
+    method public void setId(String);
+  }
+
+  public class OgkiApproved {
+    ctor public OgkiApproved();
+    method public java.util.List<approved.build.Branch> getBranch();
+    method public int getVersion();
+    method public void setVersion(int);
+  }
+
+  public class XmlParser {
+    ctor public XmlParser();
+    method public static approved.build.OgkiApproved read(java.io.InputStream) throws javax.xml.datatype.DatatypeConfigurationException, java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+    method public static String readText(org.xmlpull.v1.XmlPullParser) throws java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+    method public static void skip(org.xmlpull.v1.XmlPullParser) throws java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+  }
+
+}
+
diff --git a/xsd/approvedBuild/schema/last_current.txt b/xsd/approvedBuild/schema/last_current.txt
new file mode 100644
index 0000000..e69de29
diff --git a/xsd/approvedBuild/schema/last_removed.txt b/xsd/approvedBuild/schema/last_removed.txt
new file mode 100644
index 0000000..e69de29
diff --git a/xsd/approvedBuild/schema/removed.txt b/xsd/approvedBuild/schema/removed.txt
new file mode 100644
index 0000000..d802177
--- /dev/null
+++ b/xsd/approvedBuild/schema/removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/xsd/approvedBuild/vts/Android.bp b/xsd/approvedBuild/vts/Android.bp
new file mode 100644
index 0000000..1a02a0a
--- /dev/null
+++ b/xsd/approvedBuild/vts/Android.bp
@@ -0,0 +1,54 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_android_kernel",
+
+    // http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "vts_approvedBuild_validate_test",
+    srcs: [
+        "ValidateApprovedBuild.cpp",
+    ],
+    defaults: [
+        "libvintf_static_user_defaults",
+    ],
+    static_libs: [
+        "android.hardware.audio.common.test.utility",
+        "libkver",
+        "libvintf",
+        "libxml2",
+    ],
+    shared_libs: [
+        "liblog",
+        "libbase",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    data: [
+        ":approved_build",
+    ],
+    test_suites: [
+        "device-tests",
+        "vts",
+    ],
+    auto_gen_config: true,
+}
diff --git a/xsd/approvedBuild/vts/ValidateApprovedBuild.cpp b/xsd/approvedBuild/vts/ValidateApprovedBuild.cpp
new file mode 100644
index 0000000..4f790a3
--- /dev/null
+++ b/xsd/approvedBuild/vts/ValidateApprovedBuild.cpp
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
+#include <android-base/file.h>
+#include <kver/kernel_release.h>
+#include <unistd.h>
+#include <vintf/VintfObject.h>
+
+#include <string>
+
+#include "utility/ValidateXml.h"
+
+TEST(CheckConfig, approvedBuildValidation) {
+  const auto kernel_release = android::kver::KernelRelease::Parse(
+      android::vintf::VintfObject::GetRuntimeInfo()->osRelease(),
+      /* allow_suffix = */ true);
+  if (!kernel_release.has_value()) {
+    GTEST_FAIL() << "Failed to parse the kernel release string";
+  }
+  if (kernel_release->android_release() < 14) {
+    GTEST_SKIP() << "Kernel releases below android14 are exempt";
+  }
+
+  RecordProperty("description",
+                 "Verify that the approved OGKI builds file "
+                 "is valid according to the schema");
+
+  std::string xml_schema_path =
+      android::base::GetExecutableDirectory() + "/approved_build.xsd";
+  std::vector<const char*> locations = {"/system/etc/kernel"};
+  EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS("approved-ogki-builds.xml", locations,
+                                          xml_schema_path.c_str());
+}
diff --git a/xsd/kernelLifetimes/Android.bp b/xsd/kernelLifetimes/Android.bp
new file mode 100644
index 0000000..e42834f
--- /dev/null
+++ b/xsd/kernelLifetimes/Android.bp
@@ -0,0 +1,29 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_android_kernel",
+
+    // http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+xsd_config {
+    name: "kernel_lifetimes",
+    srcs: ["kernel_lifetimes.xsd"],
+    package_name: "kernel.lifetimes",
+    api_dir: "schema",
+}
diff --git a/xsd/kernelLifetimes/kernel_lifetimes.xsd b/xsd/kernelLifetimes/kernel_lifetimes.xsd
new file mode 100644
index 0000000..7f90d89
--- /dev/null
+++ b/xsd/kernelLifetimes/kernel_lifetimes.xsd
@@ -0,0 +1,53 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+         Licensed under the Apache License, Version 2.0 (the "License");
+         you may not use this file except in compliance with the License.
+         You may obtain a copy of the License at
+
+                    http://www.apache.org/licenses/LICENSE-2.0
+
+         Unless required by applicable law or agreed to in writing, software
+         distributed under the License is distributed on an "AS IS" BASIS,
+         WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+         See the License for the specific language governing permissions and
+         limitations under the License.
+-->
+
+<xs:schema version="2.0"
+           elementFormDefault="qualified"
+           attributeFormDefault="unqualified"
+           xmlns:xs="http://www.w3.org/2001/XMLSchema">
+    <xs:element name="kernels">
+        <xs:complexType>
+            <xs:sequence>
+                <xs:element name="branch" type="branch" minOccurs="0" maxOccurs="unbounded"/>
+            </xs:sequence>
+            <xs:attribute name="schema_version" type="xs:int" use="required"/>
+        </xs:complexType>
+    </xs:element>
+    <xs:complexType name="branch">
+        <xs:choice>
+            <xs:element name="no-releases" type="no-releases"/>
+            <xs:element name="lts-versions" type="lts-versions"/>
+        </xs:choice>
+        <xs:attribute name="name" type="xs:string" use="required"/>
+        <xs:attribute name="min_android_release" type="xs:int"/>
+        <xs:attribute name="version" type="xs:string" use="required"/>
+        <xs:attribute name="launch" type="xs:date" use="required"/>
+        <xs:attribute name="eol" type="xs:date" use="required"/>
+    </xs:complexType>
+    <xs:complexType name="no-releases">
+        <xs:attribute name="reason" type="xs:string" fixed="non-GKI kernel"/>
+    </xs:complexType>
+    <xs:complexType name="lts-versions">
+        <xs:sequence>
+            <xs:element name="release" type="release" minOccurs="0" maxOccurs="unbounded"/>
+        </xs:sequence>
+    </xs:complexType>
+    <xs:complexType name="release">
+        <xs:attribute name="version" type="xs:string" use="required"/>
+        <xs:attribute name="launch" type="xs:date" use="required"/>
+        <xs:attribute name="eol" type="xs:date" use="required"/>
+    </xs:complexType>
+</xs:schema>
diff --git a/xsd/kernelLifetimes/schema/current.txt b/xsd/kernelLifetimes/schema/current.txt
new file mode 100644
index 0000000..bd96b76
--- /dev/null
+++ b/xsd/kernelLifetimes/schema/current.txt
@@ -0,0 +1,58 @@
+// Signature format: 2.0
+package kernel.lifetimes {
+
+  public class Branch {
+    ctor public Branch();
+    method public javax.xml.datatype.XMLGregorianCalendar getEol();
+    method public javax.xml.datatype.XMLGregorianCalendar getLaunch();
+    method public kernel.lifetimes.LtsVersions getLtsVersions_optional();
+    method public int getMin_android_release();
+    method public String getName();
+    method public kernel.lifetimes.NoReleases getNoReleases_optional();
+    method public String getVersion();
+    method public void setEol(javax.xml.datatype.XMLGregorianCalendar);
+    method public void setLaunch(javax.xml.datatype.XMLGregorianCalendar);
+    method public void setLtsVersions_optional(kernel.lifetimes.LtsVersions);
+    method public void setMin_android_release(int);
+    method public void setName(String);
+    method public void setNoReleases_optional(kernel.lifetimes.NoReleases);
+    method public void setVersion(String);
+  }
+
+  public class Kernels {
+    ctor public Kernels();
+    method public java.util.List<kernel.lifetimes.Branch> getBranch();
+    method public int getSchema_version();
+    method public void setSchema_version(int);
+  }
+
+  public class LtsVersions {
+    ctor public LtsVersions();
+    method public java.util.List<kernel.lifetimes.Release> getRelease();
+  }
+
+  public class NoReleases {
+    ctor public NoReleases();
+    method public String getReason();
+    method public void setReason(String);
+  }
+
+  public class Release {
+    ctor public Release();
+    method public javax.xml.datatype.XMLGregorianCalendar getEol();
+    method public javax.xml.datatype.XMLGregorianCalendar getLaunch();
+    method public String getVersion();
+    method public void setEol(javax.xml.datatype.XMLGregorianCalendar);
+    method public void setLaunch(javax.xml.datatype.XMLGregorianCalendar);
+    method public void setVersion(String);
+  }
+
+  public class XmlParser {
+    ctor public XmlParser();
+    method public static kernel.lifetimes.Kernels read(java.io.InputStream) throws javax.xml.datatype.DatatypeConfigurationException, java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+    method public static String readText(org.xmlpull.v1.XmlPullParser) throws java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+    method public static void skip(org.xmlpull.v1.XmlPullParser) throws java.io.IOException, org.xmlpull.v1.XmlPullParserException;
+  }
+
+}
+
diff --git a/xsd/kernelLifetimes/schema/last_current.txt b/xsd/kernelLifetimes/schema/last_current.txt
new file mode 100644
index 0000000..e69de29
diff --git a/xsd/kernelLifetimes/schema/last_removed.txt b/xsd/kernelLifetimes/schema/last_removed.txt
new file mode 100644
index 0000000..e69de29
diff --git a/xsd/kernelLifetimes/schema/removed.txt b/xsd/kernelLifetimes/schema/removed.txt
new file mode 100644
index 0000000..d802177
--- /dev/null
+++ b/xsd/kernelLifetimes/schema/removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/xsd/kernelLifetimes/vts/Android.bp b/xsd/kernelLifetimes/vts/Android.bp
new file mode 100644
index 0000000..bcfbfab
--- /dev/null
+++ b/xsd/kernelLifetimes/vts/Android.bp
@@ -0,0 +1,53 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_android_kernel",
+
+    // http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "vts_kernelLifetimes_validate_test",
+    srcs: [
+        "ValidateKernelLifetimes.cpp",
+    ],
+    defaults: [
+        "libvintf_static_user_defaults",
+    ],
+    static_libs: [
+        "android.hardware.audio.common.test.utility",
+        "libvintf",
+        "libxml2",
+    ],
+    shared_libs: [
+        "liblog",
+        "libbase",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    data: [
+        ":kernel_lifetimes",
+    ],
+    test_suites: [
+        "device-tests",
+        "vts",
+    ],
+    auto_gen_config: true,
+}
diff --git a/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp b/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp
new file mode 100644
index 0000000..28d4dae
--- /dev/null
+++ b/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp
@@ -0,0 +1,39 @@
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
+#include <unistd.h>
+#include <string>
+
+#include <android-base/file.h>
+#include <vintf/Version.h>
+#include <vintf/VintfObject.h>
+#include "utility/ValidateXml.h"
+
+TEST(CheckConfig, approvedBuildValidation) {
+    if (android::vintf::VintfObject::GetRuntimeInfo()->kernelVersion().dropMinor() <
+        android::vintf::Version{4, 14}) {
+        GTEST_SKIP() << "Kernel versions below 4.14 are exempt";
+    }
+
+    RecordProperty("description",
+                   "Verify that the kernel EOL config file "
+                   "is valid according to the schema");
+
+    std::string xml_schema_path = android::base::GetExecutableDirectory() + "/kernel_lifetimes.xsd";
+    std::vector<const char*> locations = {"/system/etc/kernel"};
+    EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS("kernel-lifetimes.xml", locations,
+                                            xml_schema_path.c_str());
+}
```

