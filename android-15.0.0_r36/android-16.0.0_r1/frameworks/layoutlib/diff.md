```diff
diff --git a/.idea/libraries/environment_services_prebuilt.xml b/.idea/libraries/environment_services_prebuilt.xml
new file mode 100644
index 0000000000..4361bc2f56
--- /dev/null
+++ b/.idea/libraries/environment_services_prebuilt.xml
@@ -0,0 +1,9 @@
+<component name="libraryTable">
+  <library name="environment-services-prebuilt">
+    <CLASSES>
+      <root url="jar://$PROJECT_DIR$/../../prebuilts/misc/common/environment-services/environment-services-prebuilt.jar!/" />
+    </CLASSES>
+    <JAVADOC />
+    <SOURCES />
+  </library>
+</component>
\ No newline at end of file
diff --git a/.idea/libraries/resource_repository_prebuilt.xml b/.idea/libraries/resource_repository_prebuilt.xml
new file mode 100644
index 0000000000..c99f6c248e
--- /dev/null
+++ b/.idea/libraries/resource_repository_prebuilt.xml
@@ -0,0 +1,9 @@
+<component name="libraryTable">
+  <library name="resource-repository-prebuilt">
+    <CLASSES>
+      <root url="jar://$PROJECT_DIR$/../../prebuilts/misc/common/resource-repository/resource-repository-prebuilt.jar!/" />
+    </CLASSES>
+    <JAVADOC />
+    <SOURCES />
+  </library>
+</component>
\ No newline at end of file
diff --git a/.idea/runConfigurations/All_in_bridge.xml b/.idea/runConfigurations/All_in_bridge.xml
index 5353408242..67b2eead6e 100644
--- a/.idea/runConfigurations/All_in_bridge.xml
+++ b/.idea/runConfigurations/All_in_bridge.xml
@@ -1,8 +1,6 @@
 <component name="ProjectRunConfigurationManager">
   <configuration default="false" name="All in bridge" type="JUnit" factoryName="JUnit" singleton="true">
     <module name="bridge_tests" />
-    <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
-    <option name="ALTERNATIVE_JRE_PATH" value="jbr-17" />
     <option name="PACKAGE_NAME" value="" />
     <option name="MAIN_CLASS_NAME" value="" />
     <option name="METHOD_NAME" value="" />
diff --git a/.idea/runConfigurations/All_in_create.xml b/.idea/runConfigurations/All_in_create.xml
index ac2401627d..0275dadb3b 100644
--- a/.idea/runConfigurations/All_in_create.xml
+++ b/.idea/runConfigurations/All_in_create.xml
@@ -1,8 +1,7 @@
 <component name="ProjectRunConfigurationManager">
   <configuration default="false" name="All in create" type="JUnit" factoryName="JUnit" singleton="false" nameIsGenerated="true">
     <module name="create" />
-    <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
-    <option name="ALTERNATIVE_JRE_PATH" value="jbr-17" />
+    <option name="ALTERNATIVE_JRE_PATH" value="jbr-21" />
     <option name="PACKAGE_NAME" value="" />
     <option name="MAIN_CLASS_NAME" value="" />
     <option name="METHOD_NAME" value="" />
diff --git a/.idea/runConfigurations/Bridge_quick.xml b/.idea/runConfigurations/Bridge_quick.xml
index 3a598ab60d..921eacd870 100644
--- a/.idea/runConfigurations/Bridge_quick.xml
+++ b/.idea/runConfigurations/Bridge_quick.xml
@@ -1,8 +1,7 @@
 <component name="ProjectRunConfigurationManager">
   <configuration default="false" name="Bridge quick" type="JUnit" factoryName="JUnit">
     <module name="bridge_tests" />
-    <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
-    <option name="ALTERNATIVE_JRE_PATH" value="jbr-17" />
+    <option name="ALTERNATIVE_JRE_PATH" value="jbr-21" />
     <option name="MAIN_CLASS_NAME" value="" />
     <option name="METHOD_NAME" value="" />
     <option name="TEST_OBJECT" value="pattern" />
diff --git a/.idea/runConfigurations/Create.xml b/.idea/runConfigurations/Create.xml
index 150458d918..1addefdead 100644
--- a/.idea/runConfigurations/Create.xml
+++ b/.idea/runConfigurations/Create.xml
@@ -1,7 +1,6 @@
 <component name="ProjectRunConfigurationManager">
   <configuration default="false" name="Create" type="Application" factoryName="Application" singleton="true">
     <option name="ALTERNATIVE_JRE_PATH" value="jbr-21" />
-    <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
     <option name="MAIN_CLASS_NAME" value="com.android.tools.layoutlib.create.Main" />
     <module name="create" />
     <option name="PROGRAM_PARAMETERS" value="--create-stub out/soong/.temp/temp_layoutlib.jar out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/local-combined/atf-prebuilt-jars-557133692.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar out/soong/.intermediates/external/icu/android_icu4j/core-icu4j-for-host/android_common/withres/core-icu4j-for-host.jar out/soong/.intermediates/libcore/core-libart-for-host/android_common/combined/core-libart-for-host.jar out/soong/.intermediates/frameworks/base/framework-all/android_common/combined/framework-all.jar out/soong/.intermediates/frameworks/base/ext/android_common/withres/ext.jar out/soong/.intermediates/frameworks/libs/systemui/iconloaderlib/iconloader_base/android_common/withres/iconloader_base.jar out/soong/.intermediates/frameworks/libs/systemui/monet/monet/android_common/combined/monet.jar" />
diff --git a/Android.bp b/Android.bp
index 5e5fd7aa64..b1fe832e03 100644
--- a/Android.bp
+++ b/Android.bp
@@ -45,6 +45,12 @@ java_genrule_host {
     cmd: "rm -f $(out) && $(location layoutlib_create) --create-stub $(out) $(in)",
 }
 
+java_library_host {
+    name: "layoutlib-framework",
+    static_libs: ["temp_layoutlib"],
+    jarjar_rules: "jarjar-rules.txt",
+}
+
 java_device_for_host {
     name: "layoutlib_create-classpath",
     libs: [
@@ -63,7 +69,6 @@ java_device_for_host {
 cc_library_host_shared {
     name: "layoutlib_jni",
     srcs: [
-        "jni/android_view_LayoutlibRenderer.cpp",
         "jni/LayoutlibLoader.cpp",
     ],
     cflags: [
@@ -71,17 +76,17 @@ cc_library_host_shared {
     ],
     header_libs: [
         "libbase_headers",
-        "libhostgraphics_headers",
-        "libnativebase_headers",
-        "libnativedisplay_headers",
-        "libnativewindow_headers",
     ],
     shared_libs: [
         "libandroid_runtime",
     ],
     static_libs: [
-        "libhostgraphics",
+        "libbase",
+        "libbinder",
+        "libcutils",
         "libinput",
+        "libui-types",
+        "libutils",
     ],
     stl: "libc++_static",
     target: {
@@ -89,7 +94,7 @@ cc_library_host_shared {
             version_script: "jni/linux/layoutlib_jni_export.txt",
         },
         darwin: {
-            ldflags: ["-Wl,-exported_symbols_list,frameworks/layoutlib/jni/darwin/layoutlib_jni_export.exp"],
+            exported_symbols_list: "jni/darwin/layoutlib_jni_export.exp",
             dist: {
                 targets: ["layoutlib_jni"],
                 dir: "layoutlib_native/darwin",
diff --git a/bridge/Android.bp b/bridge/Android.bp
index a48f0d009a..4c720beed1 100644
--- a/bridge/Android.bp
+++ b/bridge/Android.bp
@@ -33,13 +33,11 @@ java_library_host {
     ],
 
     static_libs: [
-        "temp_layoutlib",
+        "layoutlib-framework",
         "layoutlib-common",
         "layoutlib-validator",
     ],
 
-    jarjar_rules: "jarjar-rules.txt",
-
     dist: {
         targets: ["layoutlib"],
     },
diff --git a/bridge/bridge_client/Android.bp b/bridge/bridge_client/Android.bp
index 02bd07f037..08d709ca5d 100644
--- a/bridge/bridge_client/Android.bp
+++ b/bridge/bridge_client/Android.bp
@@ -25,23 +25,17 @@ java_library_host {
     ],
 
     static_libs: [
-        "tools-common-prebuilt",
-        "sdk-common",
+        "guava",
+        "junit",
         "kxml2-2.3.0",
+        "layoutlib",
         "layoutlib_api-prebuilt",
+        "sdk-common",
+        "tools-common-prebuilt",
+        "tools-environment-services",
+        "tools-resource-repository",
         "trove-prebuilt",
-        "junit",
-        "guava",
-        "layoutlib",
     ],
-
-    // Copy the jar to DIST_DIR for sdk builds
-    dist: {
-        targets: [
-            "sdk",
-            "win_sdk",
-        ],
-    },
 }
 
 java_host_for_device {
diff --git a/bridge/bridge_client/bridge_client.iml b/bridge/bridge_client/bridge_client.iml
index 618c727706..f1f3e4310d 100644
--- a/bridge/bridge_client/bridge_client.iml
+++ b/bridge/bridge_client/bridge_client.iml
@@ -17,5 +17,7 @@
     <orderEntry type="library" name="framework.jar" level="project" />
     <orderEntry type="module" module-name="bridge" />
     <orderEntry type="module" module-name="common" />
+    <orderEntry type="library" name="resource-repository-prebuilt" level="project" />
+    <orderEntry type="library" name="environment-services-prebuilt" level="project" />
   </component>
 </module>
\ No newline at end of file
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java
deleted file mode 100644
index c1c32b6850..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java
+++ /dev/null
@@ -1,182 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-
-import com.android.SdkConstants;
-import com.android.io.IAbstractFile;
-import com.android.io.IAbstractFolder;
-import com.android.resources.ResourceType;
-import com.android.tools.layoutlib.annotations.NotNull;
-import com.android.tools.layoutlib.annotations.Nullable;
-import com.android.utils.ILogger;
-
-import org.kxml2.io.KXmlParser;
-import org.xmlpull.v1.XmlPullParser;
-
-import java.io.BufferedReader;
-import java.io.InputStreamReader;
-import java.io.Reader;
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.EnumMap;
-import java.util.List;
-import java.util.Map;
-
-import com.google.common.base.Charsets;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class FrameworkResources extends ResourceRepository {
-
-    /**
-     * Map of {@link ResourceType} to list of items. It is guaranteed to contain a list for all
-     * possible values of ResourceType.
-     */
-    private final Map<ResourceType, List<ResourceItem>> mPublicResourceMap =
-        new EnumMap<>(ResourceType.class);
-
-    public FrameworkResources(@NotNull TestFolderWrapper resFolder) {
-        super(resFolder, true /*isFrameworkRepository*/);
-    }
-
-    @Override
-    @NotNull
-    protected ResourceItem createResourceItem(@NotNull String name) {
-        return new ResourceItem(name);
-    }
-
-    /**
-     * Reads the public.xml file in data/res/values/ for a given resource folder and builds up
-     * a map of public resources.
-     *
-     * This map is a subset of the full resource map that only contains framework resources
-     * that are public.
-     *
-     * @param logger a logger to report issues to
-     */
-    public void loadPublicResources(@Nullable ILogger logger) {
-        IAbstractFolder valueFolder = getResFolder().getFolder(SdkConstants.FD_RES_VALUES);
-        if (!valueFolder.exists()) {
-            return;
-        }
-
-        IAbstractFile publicXmlFile = valueFolder.getFile("public.xml"); //$NON-NLS-1$
-        if (publicXmlFile.exists()) {
-            try (Reader reader = new BufferedReader(
-                    new InputStreamReader(publicXmlFile.getContents(), Charsets.UTF_8))) {
-                KXmlParser parser = new KXmlParser();
-                parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
-                parser.setInput(reader);
-
-                ResourceType lastType = null;
-                String lastTypeName = "";
-                while (true) {
-                    int event = parser.next();
-                    if (event == XmlPullParser.START_TAG) {
-                        // As of API 15 there are a number of "java-symbol" entries here
-                        if (!parser.getName().equals("public")) { //$NON-NLS-1$
-                            continue;
-                        }
-
-                        String name = null;
-                        String typeName = null;
-                        for (int i = 0, n = parser.getAttributeCount(); i < n; i++) {
-                            String attribute = parser.getAttributeName(i);
-
-                            if (attribute.equals("name")) { //$NON-NLS-1$
-                                name = parser.getAttributeValue(i);
-                                if (typeName != null) {
-                                    // Skip id attribute processing
-                                    break;
-                                }
-                            } else if (attribute.equals("type")) { //$NON-NLS-1$
-                                typeName = parser.getAttributeValue(i);
-                            }
-                        }
-
-                        if (name != null && typeName != null) {
-                            ResourceType type;
-                            if (typeName.equals(lastTypeName)) {
-                                type = lastType;
-                            } else {
-                                type = ResourceType.fromXmlValue(typeName);
-                                lastType = type;
-                                lastTypeName = typeName;
-                            }
-                            if (type != null) {
-                                ResourceItem match = null;
-                                Map<String, ResourceItem> map = mResourceMap.get(type);
-                                if (map != null) {
-                                    match = map.get(name);
-                                }
-
-                                if (match != null) {
-                                    List<ResourceItem> publicList = mPublicResourceMap.get(type);
-                                    if (publicList == null) {
-                                        // Pick initial size for the list to hold the public
-                                        // resources. We could just use map.size() here,
-                                        // but they're usually much bigger; for example,
-                                        // in one platform version, there are 1500 drawables
-                                        // and 1200 strings but only 175 and 25 public ones
-                                        // respectively.
-                                        int size = switch (type) {
-                                            case STYLE -> 500;
-                                            case ATTR -> 1050;
-                                            case DRAWABLE -> 200;
-                                            case ID -> 50;
-                                            case LAYOUT, COLOR, STRING, ANIM, INTERPOLATOR -> 30;
-                                            default -> 10;
-                                        };
-                                        publicList = new ArrayList<>(size);
-                                        mPublicResourceMap.put(type, publicList);
-                                    }
-
-                                    publicList.add(match);
-                                }
-                            }
-                        }
-                    } else if (event == XmlPullParser.END_DOCUMENT) {
-                        break;
-                    }
-                }
-            } catch (Exception e) {
-                if (logger != null) {
-                    logger.error(e, "Can't read and parse public attribute list");
-                }
-            }
-        }
-
-        // put unmodifiable list for all res type in the public resource map
-        // this will simplify access
-        for (ResourceType type : ResourceType.values()) {
-            List<ResourceItem> list = mPublicResourceMap.get(type);
-            if (list == null) {
-                list = Collections.emptyList();
-            } else {
-                list = Collections.unmodifiableList(list);
-            }
-
-            // put the new list in the map
-            mPublicResourceMap.put(type, list);
-        }
-    }
-}
-
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdGeneratingResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdGeneratingResourceFile.java
deleted file mode 100644
index 5434cadfb1..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdGeneratingResourceFile.java
+++ /dev/null
@@ -1,215 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.DensityBasedResourceValueImpl;
-import com.android.ide.common.rendering.api.ResourceNamespace;
-import com.android.ide.common.rendering.api.ResourceReference;
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.rendering.api.ResourceValueImpl;
-import com.android.ide.common.resources.ResourceValueMap;
-import com.android.ide.common.resources.configuration.DensityQualifier;
-import com.android.ide.common.resources.configuration.ResourceQualifier;
-import com.android.ide.common.resources.deprecated.ValueResourceParser.IValueResourceRepository;
-import com.android.io.IAbstractFile;
-import com.android.io.StreamException;
-import com.android.resources.ResourceType;
-
-import java.io.IOException;
-import java.util.Collection;
-import java.util.EnumSet;
-import java.util.HashSet;
-import java.util.Set;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public final class IdGeneratingResourceFile extends ResourceFile
-        implements IValueResourceRepository {
-
-    private final ResourceValueMap mIdResources = ResourceValueMap.create();
-
-    private final Collection<ResourceType> mResourceTypeList;
-
-    private final String mFileName;
-
-    private final ResourceType mFileType;
-
-    private final ResourceValue mFileValue;
-
-    public IdGeneratingResourceFile(TestFileWrapper file, ResourceFolder folder, ResourceType type) {
-        super(file, folder);
-
-        mFileType = type;
-
-        // Set up our resource types
-        mResourceTypeList = EnumSet.of(mFileType, ResourceType.ID);
-
-        // compute the resource name
-        mFileName = getFileName();
-
-        // Get the resource value of this file as a whole layout
-        mFileValue = getFileValue(file, folder);
-    }
-
-    @Override
-    protected void load(ScanningContext context) {
-        // Parse the file and look for @+id/ entries
-        parseFileForIds();
-
-        // create the resource items in the repository
-        updateResourceItems(context);
-    }
-
-    @Override
-    protected void update(ScanningContext context) {
-        // Copy the previous list of ID names
-        Set<String> oldIdNames = new HashSet<>(mIdResources.keySet());
-
-        // reset current content.
-        mIdResources.clear();
-
-        // need to parse the file and find the IDs.
-        if (!parseFileForIds()) {
-            context.requestFullAapt();
-            // Continue through to updating the resource item here since it
-            // will make for example layout rendering more accurate until
-            // aapt is re-run
-        }
-
-        // We only need to update the repository if our IDs have changed
-        Set<String> keySet = mIdResources.keySet();
-        assert keySet != oldIdNames;
-        if (!oldIdNames.equals(keySet)) {
-            updateResourceItems(context);
-        }
-    }
-
-    @Override
-    public ResourceValue getValue(ResourceType type, String name) {
-        // Check to see if they're asking for one of the right types:
-        if (type != mFileType && type != ResourceType.ID) {
-            return null;
-        }
-
-        // If they're looking for a resource of this type with this name give them the whole file
-        if (type == mFileType && name.equals(mFileName)) {
-            return mFileValue;
-        } else {
-            // Otherwise try to return them an ID
-            // the map will return null if it's not found
-            return mIdResources.get(name);
-        }
-    }
-
-    /**
-     * Looks through the file represented for Ids and adds them to
-     * our id repository
-     *
-     * @return true if parsing succeeds and false if it fails
-     */
-    private boolean parseFileForIds() {
-        IdResourceParser parser = new IdResourceParser(this, isFramework());
-        try {
-            IAbstractFile file = getFile();
-            return parser.parse(file.getContents());
-        } catch (IOException | StreamException ignore) {}
-
-        return false;
-    }
-
-    /**
-     * Add the resources represented by this file to the repository
-     */
-    private void updateResourceItems(ScanningContext context) {
-        ResourceRepository repository = getRepository();
-
-        // remove this file from all existing ResourceItem.
-        repository.removeFile(mResourceTypeList, this);
-
-        // First add this as a layout file
-        ResourceItem item = repository.getResourceItem(mFileType, mFileName);
-        item.add(this);
-
-        // Now iterate through our IDs and add
-        for (String idName : mIdResources.keySet()) {
-            item = repository.getResourceItem(ResourceType.ID, idName);
-            // add this file to the list of files generating ID resources.
-            item.add(this);
-        }
-
-        //  Ask the repository for an ID refresh
-        context.requestFullAapt();
-    }
-
-    /**
-     * Returns the resource value associated with this whole file as a layout resource
-     * @param file the file handler that represents this file
-     * @param folder the folder this file is under
-     * @return a resource value associated with this layout
-     */
-    private ResourceValue getFileValue(IAbstractFile file, ResourceFolder folder) {
-        // test if there's a density qualifier associated with the resource
-        DensityQualifier qualifier = folder.getConfiguration().getDensityQualifier();
-
-        ResourceValue value;
-        if (!ResourceQualifier.isValid(qualifier)) {
-            value =
-                    new ResourceValueImpl(
-                            new ResourceReference(
-                                    ResourceNamespace.fromBoolean(isFramework()),
-                                    mFileType,
-                                    mFileName),
-                            file.getOsLocation());
-        } else {
-            value =
-                    new DensityBasedResourceValueImpl(
-                            new ResourceReference(
-                                    ResourceNamespace.fromBoolean(isFramework()),
-                                    mFileType,
-                                    mFileName),
-                            file.getOsLocation(),
-                            qualifier.getValue());
-        }
-        return value;
-    }
-
-
-    /**
-     * Returns the name of this resource.
-     */
-    private String getFileName() {
-        // get the name from the filename.
-        String name = getFile().getName();
-
-        int pos = name.indexOf('.');
-        if (pos != -1) {
-            name = name.substring(0, pos);
-        }
-
-        return name;
-    }
-
-    @Override
-    public void addResourceValue(ResourceValue value) {
-        // Just overwrite collisions. We're only interested in the unique
-        // IDs declared
-        mIdResources.put(value.getName(), value);
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdResourceParser.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdResourceParser.java
deleted file mode 100644
index 090217ab54..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/IdResourceParser.java
+++ /dev/null
@@ -1,122 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.SdkConstants;
-import com.android.ide.common.rendering.api.ResourceNamespace;
-import com.android.ide.common.rendering.api.ResourceReference;
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.rendering.api.ResourceValueImpl;
-import com.android.ide.common.resources.deprecated.ValueResourceParser.IValueResourceRepository;
-import com.android.resources.ResourceType;
-import com.android.tools.layoutlib.annotations.NotNull;
-
-import org.kxml2.io.KXmlParser;
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.BufferedInputStream;
-import java.io.FileInputStream;
-import java.io.IOException;
-import java.io.InputStream;
-
-import com.google.common.io.Closeables;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class IdResourceParser {
-    private final IValueResourceRepository mRepository;
-    private final boolean mIsFramework;
-
-    /**
-     * Creates a new {@link com.android.ide.common.resources.deprecated.IdResourceParser}
-     *
-     * @param repository value repository for registering resource declaration
-     * @param isFramework true if scanning a framework resource
-     */
-    public IdResourceParser(
-            @NotNull ValueResourceParser.IValueResourceRepository repository,
-            boolean isFramework) {
-        mRepository = repository;
-        mIsFramework = isFramework;
-    }
-
-    /**
-     * Parse the given input and register ids with the given
-     * {@link IValueResourceRepository}.
-     *
-     * @param input the input stream of the XML to be parsed (will be closed by this method)
-     * @return true if parsing succeeds and false if it fails
-     * @throws IOException if reading the contents fails
-     */
-    public boolean parse(InputStream input)
-            throws IOException {
-        KXmlParser parser = new KXmlParser();
-        try {
-            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
-
-            if (input instanceof FileInputStream) {
-                input = new BufferedInputStream(input);
-            }
-            parser.setInput(input, SdkConstants.UTF_8);
-
-            return parse(parser);
-        } catch (XmlPullParserException | RuntimeException e) {
-            return false;
-        } finally {
-            try {
-                Closeables.close(input, true /* swallowIOException */);
-            } catch (IOException e) {
-                // cannot happen
-            }
-        }
-    }
-
-    private boolean parse(KXmlParser parser)
-            throws XmlPullParserException, IOException {
-        while (true) {
-            int event = parser.next();
-            if (event == XmlPullParser.START_TAG) {
-                for (int i = 0, n = parser.getAttributeCount(); i < n; i++) {
-                    String attribute = parser.getAttributeName(i);
-                    String value = parser.getAttributeValue(i);
-                    assert value != null : attribute;
-
-                    if (value.startsWith("@+")) {       //$NON-NLS-1$
-                        // Strip out the @+id/ or @+android:id/ section
-                        String id = value.substring(value.indexOf('/') + 1);
-                        ResourceValue newId =
-                                new ResourceValueImpl(
-                                        new ResourceReference(
-                                                ResourceNamespace.fromBoolean(mIsFramework),
-                                                ResourceType.ID,
-                                                id),
-                                        null);
-                        mRepository.addResourceValue(newId);
-                    }
-                }
-            } else if (event == XmlPullParser.END_DOCUMENT) {
-                break;
-            }
-        }
-
-        return true;
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java
deleted file mode 100644
index 64f23a65c4..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java
+++ /dev/null
@@ -1,189 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.rendering.api.ResourceValueImpl;
-import com.android.ide.common.resources.ResourceValueMap;
-import com.android.ide.common.resources.deprecated.ValueResourceParser.IValueResourceRepository;
-import com.android.io.StreamException;
-import com.android.resources.ResourceType;
-import com.android.utils.XmlUtils;
-
-import org.xml.sax.SAXException;
-
-import java.io.IOException;
-import java.util.Collection;
-import java.util.Collections;
-import java.util.EnumMap;
-import java.util.Map;
-
-import javax.xml.parsers.ParserConfigurationException;
-import javax.xml.parsers.SAXParser;
-import javax.xml.parsers.SAXParserFactory;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public final class MultiResourceFile extends ResourceFile implements IValueResourceRepository {
-
-    private static final SAXParserFactory sParserFactory = XmlUtils.configureSaxFactory(
-            SAXParserFactory.newInstance(), false, false);
-
-    private final Map<ResourceType, ResourceValueMap> mResourceItems =
-        new EnumMap<>(ResourceType.class);
-
-    private Collection<ResourceType> mResourceTypeList = null;
-
-    public MultiResourceFile(TestFileWrapper file, ResourceFolder folder) {
-        super(file, folder);
-    }
-
-    // Boolean flag to track whether a named element has been added or removed, thus requiring
-    // a new ID table to be generated
-    private boolean mNeedIdRefresh;
-
-    @Override
-    protected void load(ScanningContext context) {
-        // need to parse the file and find the content.
-        parseFile();
-
-        // create new ResourceItems for the new content.
-        mResourceTypeList = Collections.unmodifiableCollection(mResourceItems.keySet());
-
-        // We need an ID generation step
-        mNeedIdRefresh = true;
-
-        // create/update the resource items.
-        updateResourceItems(context);
-    }
-
-    @Override
-    protected void update(ScanningContext context) {
-        // Reset the ID generation flag
-        mNeedIdRefresh = false;
-
-        // Copy the previous version of our list of ResourceItems and types
-        Map<ResourceType, ResourceValueMap> oldResourceItems
-                        = new EnumMap<>(mResourceItems);
-
-        // reset current content.
-        mResourceItems.clear();
-
-        // need to parse the file and find the content.
-        parseFile();
-
-        // create new ResourceItems for the new content.
-        mResourceTypeList = Collections.unmodifiableCollection(mResourceItems.keySet());
-
-        // Check to see if any names have changed. If so, mark the flag so updateResourceItems
-        // can notify the ResourceRepository that an ID refresh is needed
-        if (oldResourceItems.keySet().equals(mResourceItems.keySet())) {
-            for (ResourceType type : mResourceTypeList) {
-                // We just need to check the names of the items.
-                // If there are new or removed names then we'll have to regenerate IDs
-                if (!mResourceItems.get(type).keySet().equals(oldResourceItems.get(type).keySet())) {
-                    mNeedIdRefresh = true;
-                }
-            }
-        } else {
-            // If our type list is different, obviously the names will be different
-            mNeedIdRefresh = true;
-        }
-        // create/update the resource items.
-        updateResourceItems(context);
-    }
-
-    private void updateResourceItems(ScanningContext context) {
-        ResourceRepository repository = getRepository();
-
-        // remove this file from all existing ResourceItem.
-        repository.removeFile(mResourceTypeList, this);
-
-        for (ResourceType type : mResourceTypeList) {
-            ResourceValueMap list = mResourceItems.get(type);
-
-            if (list != null) {
-                Collection<ResourceValue> values = list.values();
-                for (ResourceValue res : values) {
-                    ResourceItem item = repository.getResourceItem(type, res.getName());
-
-                    // add this file to the list of files generating this resource item.
-                    item.add(this);
-                }
-            }
-        }
-
-        // If we need an ID refresh, ask the repository for that now
-        if (mNeedIdRefresh) {
-            context.requestFullAapt();
-        }
-    }
-
-    /**
-     * Parses the file and creates a list of {@link ResourceType}.
-     */
-    private void parseFile() {
-        try {
-            SAXParser parser = XmlUtils.createSaxParser(sParserFactory);
-            parser.parse(getFile().getContents(), new ValueResourceParser(this, isFramework(), null));
-        } catch (ParserConfigurationException | IOException | StreamException | SAXException ignore) {
-        }
-    }
-
-    /**
-     * Adds a resource item to the list
-     * @param value The value of the resource.
-     */
-    @Override
-    public void addResourceValue(ResourceValue value) {
-        ResourceType resType = value.getResourceType();
-
-        ResourceValueMap list = mResourceItems.get(resType);
-
-        // if the list does not exist, create it.
-        if (list == null) {
-            list = ResourceValueMap.create();
-            mResourceItems.put(resType, list);
-        } else {
-            // look for a possible value already existing.
-            ResourceValue oldValue = list.get(value.getName());
-
-            if (oldValue instanceof ResourceValueImpl) {
-                ((ResourceValueImpl) oldValue).replaceWith(value);
-                return;
-            }
-        }
-
-        // empty list or no match found? add the given resource
-        list.put(value.getName(), value);
-    }
-
-    @Override
-    public ResourceValue getValue(ResourceType type, String name) {
-        // get the list for the given type
-        ResourceValueMap list = mResourceItems.get(type);
-
-        if (list != null) {
-            return list.get(name);
-        }
-
-        return null;
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java
deleted file mode 100644
index 050f7cc949..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java
+++ /dev/null
@@ -1,78 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.resources.configuration.Configurable;
-import com.android.ide.common.resources.configuration.FolderConfiguration;
-import com.android.resources.ResourceType;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public abstract class ResourceFile implements Configurable {
-
-    private final TestFileWrapper mFile;
-    private final ResourceFolder mFolder;
-
-    protected ResourceFile(TestFileWrapper file, ResourceFolder folder) {
-        mFile = file;
-        mFolder = folder;
-    }
-
-    protected abstract void load(ScanningContext context);
-    protected abstract void update(ScanningContext context);
-
-    @Override
-    public FolderConfiguration getConfiguration() {
-        return mFolder.getConfiguration();
-    }
-
-    /**
-     * Returns the IFile associated with the ResourceFile.
-     */
-    protected final TestFileWrapper getFile() {
-        return mFile;
-    }
-
-    protected final ResourceRepository getRepository() {
-        return mFolder.getRepository();
-    }
-
-    /**
-     * Returns whether the resource is a framework resource.
-     */
-    protected final boolean isFramework() {
-        return mFolder.getRepository().isFrameworkRepository();
-    }
-
-    /**
-     * Returns the value of a resource generated by this file by {@link ResourceType} and name.
-     * <p>If no resource match, <code>null</code> is returned.
-     * @param type the type of the resource.
-     * @param name the name of the resource.
-     */
-    public abstract ResourceValue getValue(ResourceType type, String name);
-
-    @Override
-    public String toString() {
-        return mFile.toString();
-    }
-}
-
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFolder.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFolder.java
deleted file mode 100644
index 5fc2c195ec..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFolder.java
+++ /dev/null
@@ -1,151 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.SdkConstants;
-import com.android.ide.common.resources.configuration.Configurable;
-import com.android.ide.common.resources.configuration.FolderConfiguration;
-import com.android.io.IAbstractFile;
-import com.android.io.IAbstractFolder;
-import com.android.resources.FolderTypeRelationship;
-import com.android.resources.ResourceFolderType;
-import com.android.resources.ResourceType;
-import com.android.utils.SdkUtils;
-
-import java.util.List;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public final class ResourceFolder implements Configurable {
-    private final ResourceFolderType mType;
-    final FolderConfiguration mConfiguration;
-    IAbstractFolder mFolder;
-    private final ResourceRepository mRepository;
-
-    /**
-     * Creates a new {@link com.android.ide.common.resources.deprecated.ResourceFolder}
-     * @param type The type of the folder
-     * @param config The configuration of the folder
-     * @param folder The associated {@link IAbstractFolder} object.
-     * @param repository The associated {@link ResourceRepository}
-     */
-    protected ResourceFolder(ResourceFolderType type, FolderConfiguration config,
-            IAbstractFolder folder, ResourceRepository repository) {
-        mType = type;
-        mConfiguration = config;
-        mFolder = folder;
-        mRepository = repository;
-    }
-
-    /**
-     * Processes a file and adds it to its parent folder resource.
-     *
-     * @param file the underlying resource file.
-     * @param kind the file change kind.
-     * @param context a context object with state for the current update, such
-     *            as a place to stash errors encountered
-     * @return the {@link ResourceFile} that was created.
-     */
-    public ResourceFile processFile(TestFileWrapper file, ResourceDeltaKind kind,
-            ScanningContext context) {
-        // look for this file if it's already been created
-        ResourceFile resFile = getFile(file, context);
-
-        if (resFile == null) {
-            if (kind != ResourceDeltaKind.REMOVED) {
-                // create a ResourceFile for it.
-
-                resFile = createResourceFile(file);
-                resFile.load(context);
-            }
-        } else {
-            if (kind != ResourceDeltaKind.REMOVED) {
-                resFile.update(context);
-            }
-        }
-
-        return resFile;
-    }
-
-    private ResourceFile createResourceFile(TestFileWrapper file) {
-        // check if that's a single or multi resource type folder. We have a special case
-        // for ID generating resource types (layout/menu, and XML drawables, etc.).
-        // MultiResourceFile handles the case when several resource types come from a single file
-        // (values files).
-
-        ResourceFile resFile;
-        if (mType != ResourceFolderType.VALUES) {
-            if (FolderTypeRelationship.isIdGeneratingFolderType(mType) &&
-                SdkUtils.endsWithIgnoreCase(file.getName(), SdkConstants.DOT_XML)) {
-                List<ResourceType> types = FolderTypeRelationship.getRelatedResourceTypes(mType);
-                ResourceType primaryType = types.get(0);
-                resFile = new IdGeneratingResourceFile(file, this, primaryType);
-            } else {
-                resFile = new SingleResourceFile(file, this);
-            }
-        } else {
-            resFile = new MultiResourceFile(file, this);
-        }
-        return resFile;
-    }
-
-    /**
-     * Returns the {@link ResourceFolderType} of this object.
-     */
-    public ResourceFolderType getType() {
-        return mType;
-    }
-
-    public ResourceRepository getRepository() {
-        return mRepository;
-    }
-
-    @Override
-    public FolderConfiguration getConfiguration() {
-        return mConfiguration;
-    }
-
-    /**
-     * Returns the {@link ResourceFile} matching a {@link IAbstractFile} object.
-     *
-     * @param file The {@link IAbstractFile} object.
-     * @param context a context object with state for the current update, such
-     *            as a place to stash errors encountered
-     * @return the {@link ResourceFile} or null if no match was found.
-     */
-    private ResourceFile getFile(TestFileWrapper file, ScanningContext context) {
-        assert mFolder.equals(file.getParentFolder());
-
-        // If the file actually exists, the resource folder  may not have been
-        // scanned yet; add it lazily
-        if (file.exists()) {
-            ResourceFile resFile = createResourceFile(file);
-            resFile.load(context);
-            return resFile;
-        }
-
-        return null;
-    }
-
-    @Override
-    public String toString() {
-        return mFolder.toString();
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceItem.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceItem.java
deleted file mode 100644
index 8aaefde789..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceItem.java
+++ /dev/null
@@ -1,107 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.resources.configuration.FolderConfiguration;
-import com.android.resources.ResourceType;
-
-import java.util.ArrayList;
-import java.util.List;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class ResourceItem implements Comparable<ResourceItem> {
-    private final String mName;
-
-    /**
-     * List of files generating this ResourceItem.
-     */
-    private final List<ResourceFile> mFiles = new ArrayList<>();
-
-    /**
-     * Constructs a new ResourceItem.
-     * @param name the name of the resource as it appears in the XML and R.java files.
-     */
-    public ResourceItem(String name) {
-        mName = name;
-    }
-
-    /**
-     * Returns the name of the resource.
-     */
-    public final String getName() {
-        return mName;
-    }
-
-    /**
-     * Compares the {@link com.android.ide.common.resources.deprecated.ResourceItem} to another.
-     * @param other the ResourceItem to be compared to.
-     */
-    @Override
-    public int compareTo(com.android.ide.common.resources.deprecated.ResourceItem other) {
-        return mName.compareTo(other.mName);
-    }
-
-    /**
-     * Returns a {@link ResourceValue} for this item based on the given configuration.
-     * If the ResourceItem has several source files, one will be selected based on the config.
-     * @param type the type of the resource. This is necessary because ResourceItem doesn't embed
-     *     its type, but ResourceValue does.
-     * @param referenceConfig the config of the resource item.
-     * @return a ResourceValue or null if none match the config.
-     */
-    public ResourceValue getResourceValue(ResourceType type, FolderConfiguration referenceConfig) {
-        // look for the best match for the given configuration
-        // the match has to be of type ResourceFile since that's what the input list contains
-        ResourceFile match = referenceConfig.findMatchingConfigurable(mFiles);
-
-        if (match != null) {
-            // get the value of this configured resource.
-            return match.getValue(type, mName);
-        }
-
-        return null;
-    }
-
-    /**
-     * Adds a new source file.
-     * @param file the source file.
-     */
-    protected void add(ResourceFile file) {
-        mFiles.add(file);
-    }
-
-    /**
-     * Removes a file from the list of source files.
-     * @param file the file to remove
-     */
-    protected void removeFile(ResourceFile file) {
-        mFiles.remove(file);
-    }
-
-    /**
-     * Returns {@code true} if the item has no source file.
-     * @return true if the item has no source file.
-     */
-    protected boolean hasNoSourceFile() {
-        return mFiles.isEmpty();
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java
deleted file mode 100644
index 6707144ca9..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java
+++ /dev/null
@@ -1,387 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.SdkConstants;
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.resources.ResourceValueMap;
-import com.android.ide.common.resources.configuration.FolderConfiguration;
-import com.android.io.IAbstractFolder;
-import com.android.io.IAbstractResource;
-import com.android.resources.ResourceFolderType;
-import com.android.resources.ResourceType;
-import com.android.tools.layoutlib.annotations.NotNull;
-import com.android.tools.layoutlib.annotations.Nullable;
-
-import java.util.ArrayList;
-import java.util.Collection;
-import java.util.EnumMap;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public abstract class ResourceRepository {
-    private final TestFolderWrapper mResourceFolder;
-
-    private Map<ResourceFolderType, List<ResourceFolder>> mFolderMap =
-            new EnumMap<>(ResourceFolderType.class);
-
-    protected Map<ResourceType, Map<String, ResourceItem>> mResourceMap =
-            new EnumMap<>(ResourceType.class);
-
-    private final boolean mFrameworkRepository;
-    private boolean mCleared = true;
-    private boolean mInitializing;
-
-    /**
-     * Makes a resource repository.
-     *
-     * @param resFolder the resource folder of the repository.
-     * @param isFrameworkRepository whether the repository is for framework resources.
-     */
-    protected ResourceRepository(@NotNull TestFolderWrapper resFolder,
-            boolean isFrameworkRepository) {
-        mResourceFolder = resFolder;
-        mFrameworkRepository = isFrameworkRepository;
-    }
-
-    protected TestFolderWrapper getResFolder() {
-        return mResourceFolder;
-    }
-
-    public boolean isFrameworkRepository() {
-        return mFrameworkRepository;
-    }
-
-    private synchronized void clear() {
-        mCleared = true;
-        mFolderMap = new EnumMap<>(ResourceFolderType.class);
-        mResourceMap = new EnumMap<>(ResourceType.class);
-    }
-
-    /**
-     * Ensures that the repository has been initialized again after a call to
-     * {@link com.android.ide.common.resources.deprecated.ResourceRepository#clear()}.
-     *
-     * @return true if the repository was just re-initialized.
-     */
-    private synchronized boolean ensureInitialized() {
-        if (mCleared && !mInitializing) {
-            ScanningContext context = new ScanningContext();
-            mInitializing = true;
-
-            IAbstractResource[] resources = mResourceFolder.listMembers();
-
-            for (IAbstractResource res : resources) {
-                if (res instanceof TestFolderWrapper folder) {
-                    ResourceFolder resFolder = processFolder(folder);
-
-                    if (resFolder != null) {
-                        // now we process the content of the folder
-                        IAbstractResource[] files = folder.listMembers();
-
-                        for (IAbstractResource fileRes : files) {
-                            if (fileRes instanceof TestFileWrapper file) {
-
-                                resFolder.processFile(file, ResourceDeltaKind.ADDED, context);
-                            }
-                        }
-                    }
-                }
-            }
-
-            mInitializing = false;
-            mCleared = false;
-            return true;
-        }
-
-        return false;
-    }
-
-    /**
-     * Adds a Folder Configuration to the project.
-     *
-     * @param type The resource type.
-     * @param config The resource configuration.
-     * @param folder The workspace folder object.
-     * @return the {@link ResourceFolder} object associated to this folder.
-     */
-    private ResourceFolder add(
-            @NotNull ResourceFolderType type,
-            @NotNull FolderConfiguration config,
-            @NotNull IAbstractFolder folder) {
-        // get the list for the resource type
-        List<ResourceFolder> list = mFolderMap.get(type);
-
-        if (list == null) {
-            list = new ArrayList<>();
-
-            ResourceFolder cf = new ResourceFolder(type, config, folder, this);
-            list.add(cf);
-
-            mFolderMap.put(type, list);
-
-            return cf;
-        }
-
-        // look for an already existing folder configuration.
-        for (ResourceFolder cFolder : list) {
-            if (cFolder.mConfiguration.equals(config)) {
-                // config already exist. Nothing to be done really, besides making sure
-                // the IAbstractFolder object is up to date.
-                cFolder.mFolder = folder;
-                return cFolder;
-            }
-        }
-
-        // If we arrive here, this means we didn't find a matching configuration.
-        // So we add one.
-        ResourceFolder cf = new ResourceFolder(type, config, folder, this);
-        list.add(cf);
-
-        return cf;
-    }
-
-    /**
-     * Returns a {@link ResourceItem} matching the given {@link ResourceType} and name. If none
-     * exist, it creates one.
-     *
-     * @param type the resource type
-     * @param name the name of the resource.
-     * @return A resource item matching the type and name.
-     */
-    @NotNull
-    public ResourceItem getResourceItem(@NotNull ResourceType type, @NotNull String name) {
-        ensureInitialized();
-
-        // looking for an existing ResourceItem with this type and name
-        ResourceItem item = findDeclaredResourceItem(type, name);
-
-        // create one if there isn't one already, or if the existing one is inlined, since
-        // clearly we need a non inlined one (the inline one is removed too)
-        if (item == null) {
-            item = createResourceItem(name);
-
-            Map<String, ResourceItem> map = mResourceMap.get(type);
-
-            if (map == null) {
-                if (isFrameworkRepository()) {
-                    // Pick initial size for the maps. Also change the load factor to 1.0
-                    // to avoid rehashing the whole table when we (as expected) get near
-                    // the known rough size of each resource type map.
-                    int size = switch (type) {
-                        // Based on counts in API 16. Going back to API 10, the counts
-                        // are roughly 25-50% smaller (e.g. compared to the top 5 types below
-                        // the fractions are 1107 vs 1734, 831 vs 1508, 895 vs 1255,
-                        // 733 vs 1064 and 171 vs 783.
-                        case PUBLIC -> 1734;
-                        case DRAWABLE -> 1508;
-                        case STRING -> 1255;
-                        case ATTR -> 1064;
-                        case STYLE -> 783;
-                        case ID -> 347;
-                        case STYLEABLE -> 210;
-                        case LAYOUT -> 187;
-                        case COLOR -> 120;
-                        case ANIM -> 95;
-                        case DIMEN -> 81;
-                        case BOOL -> 54;
-                        case INTEGER -> 52;
-                        case ARRAY -> 51;
-                        case PLURALS -> 20;
-                        case XML -> 14;
-                        case INTERPOLATOR -> 13;
-                        case ANIMATOR -> 8;
-                        case RAW -> 4;
-                        case MENU -> 2;
-                        case MIPMAP -> 2;
-                        case FRACTION -> 1;
-                        default -> 2;
-                    };
-                    map = new HashMap<>(size, 1.0f);
-                } else {
-                    map = new HashMap<>();
-                }
-                mResourceMap.put(type, map);
-            }
-
-            map.put(item.getName(), item);
-        }
-
-        return item;
-    }
-
-    /**
-     * Creates a resource item with the given name.
-     * @param name the name of the resource
-     * @return a new ResourceItem (or child class) instance.
-     */
-    @NotNull
-    protected abstract ResourceItem createResourceItem(@NotNull String name);
-
-    /**
-     * Processes a folder and adds it to the list of existing folders.
-     * @param folder the folder to process
-     * @return the ResourceFolder created from this folder, or null if the process failed.
-     */
-    @Nullable
-    private ResourceFolder processFolder(@NotNull TestFolderWrapper folder) {
-        ensureInitialized();
-
-        // split the name of the folder in segments.
-        String[] folderSegments = folder.getName().split(SdkConstants.RES_QUALIFIER_SEP);
-
-        // get the enum for the resource type.
-        ResourceFolderType type = ResourceFolderType.getTypeByName(folderSegments[0]);
-
-        if (type != null) {
-            // get the folder configuration.
-            FolderConfiguration config = FolderConfiguration.getConfig(folderSegments);
-
-            if (config != null) {
-                return add(type, config, folder);
-            }
-        }
-
-        return null;
-    }
-
-    /**
-     * Returns the resources values matching a given {@link FolderConfiguration}.
-     *
-     * @param referenceConfig the configuration that each value must match.
-     * @return a map with guaranteed to contain an entry for each {@link ResourceType}
-     */
-    @NotNull
-    public Map<ResourceType, ResourceValueMap> getConfiguredResources(
-            @NotNull FolderConfiguration referenceConfig) {
-        ensureInitialized();
-
-        return doGetConfiguredResources(referenceConfig);
-    }
-
-    /**
-     * Returns the resources values matching a given {@link FolderConfiguration} for the current
-     * project.
-     *
-     * @param referenceConfig the configuration that each value must match.
-     * @return a map with guaranteed to contain an entry for each {@link ResourceType}
-     */
-    @NotNull
-    private Map<ResourceType, ResourceValueMap> doGetConfiguredResources(
-            @NotNull FolderConfiguration referenceConfig) {
-        ensureInitialized();
-
-        Map<ResourceType, ResourceValueMap> map =
-            new EnumMap<>(ResourceType.class);
-
-        for (ResourceType key : ResourceType.values()) {
-            // get the local results and put them in the map
-            map.put(key, getConfiguredResource(key, referenceConfig));
-        }
-
-        return map;
-    }
-
-    /**
-     * Loads the resources.
-     */
-    public void loadResources() {
-        clear();
-        ensureInitialized();
-    }
-
-    protected void removeFile(@NotNull Collection<ResourceType> types,
-            @NotNull ResourceFile file) {
-        ensureInitialized();
-
-        for (ResourceType type : types) {
-            removeFile(type, file);
-        }
-    }
-
-    private void removeFile(@NotNull ResourceType type, @NotNull ResourceFile file) {
-        Map<String, ResourceItem> map = mResourceMap.get(type);
-        if (map != null) {
-            Collection<ResourceItem> values = map.values();
-            List<ResourceItem> toDelete = null;
-            for (ResourceItem item : values) {
-                item.removeFile(file);
-                if (item.hasNoSourceFile()) {
-                    if (toDelete == null) {
-                        toDelete = new ArrayList<>(values.size());
-                    }
-                    toDelete.add(item);
-                }
-            }
-            if (toDelete != null) {
-                for (ResourceItem item : toDelete) {
-                    map.remove(item.getName());
-                }
-            }
-        }
-    }
-
-    /**
-     * Returns a map of (resource name, resource value) for the given {@link ResourceType}.
-     * <p>The values returned are taken from the resource files best matching a given
-     * {@link FolderConfiguration}.
-     *
-     * @param type the type of the resources.
-     * @param referenceConfig the configuration to best match.
-     */
-    @NotNull
-    private ResourceValueMap getConfiguredResource(@NotNull ResourceType type,
-            @NotNull FolderConfiguration referenceConfig) {
-        // get the resource item for the given type
-        Map<String, ResourceItem> items = mResourceMap.get(type);
-        if (items == null) {
-            return ResourceValueMap.create();
-        }
-
-        // create the map
-        ResourceValueMap map = ResourceValueMap.createWithExpectedSize(items.size());
-
-        for (ResourceItem item : items.values()) {
-            ResourceValue value = item.getResourceValue(type, referenceConfig);
-            if (value != null) {
-                map.put(item.getName(), value);
-            }
-        }
-
-        return map;
-    }
-
-    /**
-     * Looks up an existing {@link ResourceItem} by {@link ResourceType} and name.
-     *
-     * @param type the resource type.
-     * @param name the resource name.
-     * @return the existing ResourceItem or null if no match was found.
-     */
-    @Nullable
-    private ResourceItem findDeclaredResourceItem(
-            @NotNull ResourceType type, @NotNull String name) {
-        Map<String, ResourceItem> map = mResourceMap.get(type);
-        return map != null ? map.get(name) : null;
-    }
-}
-
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ScanningContext.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ScanningContext.java
deleted file mode 100644
index dadf18d42d..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ScanningContext.java
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class ScanningContext {
-    private boolean mNeedsFullAapt;
-
-    /**
-     * Marks that a full aapt compilation of the resources is necessary because it has
-     * detected a change that cannot be incrementally handled.
-     */
-    protected void requestFullAapt() {
-        mNeedsFullAapt = true;
-    }
-
-    /**
-     * Returns whether this repository has been marked as "dirty"; if one or
-     * more of the constituent files have declared that the resource item names
-     * that they provide have changed.
-     *
-     * @return true if a full aapt compilation is required
-     */
-    public boolean needsFullAapt() {
-        return mNeedsFullAapt;
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/SingleResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/SingleResourceFile.java
deleted file mode 100644
index 38d975dab4..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/SingleResourceFile.java
+++ /dev/null
@@ -1,150 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.DensityBasedResourceValueImpl;
-import com.android.ide.common.rendering.api.ResourceNamespace;
-import com.android.ide.common.rendering.api.ResourceReference;
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.rendering.api.ResourceValueImpl;
-import com.android.ide.common.resources.configuration.DensityQualifier;
-import com.android.ide.common.resources.configuration.ResourceQualifier;
-import com.android.io.IAbstractFile;
-import com.android.resources.FolderTypeRelationship;
-import com.android.resources.ResourceType;
-import com.android.utils.SdkUtils;
-
-import java.util.List;
-
-
-import static com.android.SdkConstants.DOT_XML;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class SingleResourceFile extends ResourceFile {
-    private final String mResourceName;
-    private final ResourceType mType;
-    private final ResourceValue mValue;
-
-    public SingleResourceFile(TestFileWrapper file, ResourceFolder folder) {
-        super(file, folder);
-
-        // we need to infer the type of the resource from the folder type.
-        // This is easy since this is a single Resource file.
-        List<ResourceType> types = FolderTypeRelationship.getRelatedResourceTypes(folder.getType());
-        mType = types.get(0);
-
-        // compute the resource name
-        mResourceName = getResourceName();
-
-        // test if there's a density qualifier associated with the resource
-        DensityQualifier qualifier = folder.getConfiguration().getDensityQualifier();
-
-        if (!ResourceQualifier.isValid(qualifier)) {
-            mValue =
-                    new ResourceValueImpl(
-                            new ResourceReference(
-                                    ResourceNamespace.fromBoolean(isFramework()),
-                                    mType,
-                                    getResourceName()),
-                            file.getOsLocation());
-        } else {
-            mValue =
-                    new DensityBasedResourceValueImpl(
-                            new ResourceReference(
-                                    ResourceNamespace.fromBoolean(isFramework()),
-                                    mType,
-                                    getResourceName()),
-                            file.getOsLocation(),
-                            qualifier.getValue());
-        }
-    }
-
-    @Override
-    protected void load(ScanningContext context) {
-        // get a resource item matching the given type and name
-        ResourceItem item = getRepository().getResourceItem(mType, mResourceName);
-
-        // add this file to the list of files generating this resource item.
-        item.add(this);
-
-        // Ask for an ID refresh since we're adding an item that will generate an ID
-        context.requestFullAapt();
-    }
-
-    @Override
-    protected void update(ScanningContext context) {
-        // when this happens, nothing needs to be done since the file only generates
-        // a single resources that doesn't actually change (its content is the file path)
-
-        // However, we should check for newly introduced errors
-        // Parse the file and look for @+id/ entries
-        validateAttributes(context);
-    }
-
-    /*
-     * (non-Javadoc)
-     * @see com.android.ide.eclipse.editors.resources.manager.ResourceFile#getValue(com.android.ide.eclipse.common.resources.ResourceType, java.lang.String)
-     *
-     * This particular implementation does not care about the type or name since a
-     * SingleResourceFile represents a file generating only one resource.
-     * The value returned is the full absolute path of the file in OS form.
-     */
-    @Override
-    public ResourceValue getValue(ResourceType type, String name) {
-        return mValue;
-    }
-
-    /**
-     * Returns the name of the resources.
-     */
-    private String getResourceName() {
-        // get the name from the filename.
-        String name = getFile().getName();
-
-        int pos = name.indexOf('.');
-        if (pos != -1) {
-            name = name.substring(0, pos);
-        }
-
-        return name;
-    }
-
-    /**
-     * Validates the associated resource file to make sure the attribute references are valid
-     *
-     * @return true if parsing succeeds and false if it fails
-     */
-    private boolean validateAttributes(ScanningContext context) {
-        // We only need to check if it's a non-framework file (and an XML file; skip .png's)
-        if (!isFramework() && SdkUtils.endsWith(getFile().getName(), DOT_XML)) {
-            ValidatingResourceParser parser = new ValidatingResourceParser(context, false);
-            try {
-                IAbstractFile file = getFile();
-                return parser.parse(file.getContents());
-            } catch (Exception e) {
-                context.needsFullAapt();
-            }
-
-            return false;
-        }
-
-        return true;
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFolderWrapper.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFolderWrapper.java
deleted file mode 100644
index f945d3c650..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFolderWrapper.java
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.io.FolderWrapper;
-import com.android.io.IAbstractResource;
-
-import java.io.File;
-
-public class TestFolderWrapper extends FolderWrapper {
-
-    public TestFolderWrapper(String pathname) {
-        super(pathname);
-    }
-
-    public TestFolderWrapper(File file) {
-        super(file.getAbsolutePath());
-    }
-
-    public IAbstractResource[] listMembers() {
-        File[] files = listFiles();
-        final int count = files == null ? 0 : files.length;
-        IAbstractResource[] afiles = new IAbstractResource[count];
-
-        if (files != null) {
-            for (int i = 0 ; i < count ; i++) {
-                File f = files[i];
-                if (f.isFile()) {
-                    afiles[i] = new TestFileWrapper(f);
-                } else if (f.isDirectory()) {
-                    afiles[i] = new TestFolderWrapper(f);
-                }
-            }
-        }
-
-        return afiles;
-    }
-
-    public TestFolderWrapper getFolder(String name) {
-        return new TestFolderWrapper(new File(this, name));
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValidatingResourceParser.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValidatingResourceParser.java
deleted file mode 100644
index 58af88d9d6..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValidatingResourceParser.java
+++ /dev/null
@@ -1,121 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.SdkConstants;
-import com.android.tools.layoutlib.annotations.NotNull;
-
-import org.kxml2.io.KXmlParser;
-import org.xmlpull.v1.XmlPullParser;
-import org.xmlpull.v1.XmlPullParserException;
-
-import java.io.BufferedInputStream;
-import java.io.FileInputStream;
-import java.io.IOException;
-import java.io.InputStream;
-
-import com.google.common.io.Closeables;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public class ValidatingResourceParser {
-    private final boolean mIsFramework;
-    private final ScanningContext mContext;
-
-    /**
-     * Creates a new {@link com.android.ide.common.resources.deprecated.ValidatingResourceParser}
-     *
-     * @param context a context object with state for the current update, such
-     *            as a place to stash errors encountered
-     * @param isFramework true if scanning a framework resource
-     */
-    public ValidatingResourceParser(
-            @NotNull ScanningContext context,
-            boolean isFramework) {
-        mContext = context;
-        mIsFramework = isFramework;
-    }
-
-    /**
-     * Parse the given input and return false if it contains errors, <b>or</b> if
-     * the context is already tagged as needing a full aapt run.
-     *
-     * @param input the input stream of the XML to be parsed (will be closed by this method)
-     * @return true if parsing succeeds and false if it fails
-     * @throws IOException if reading the contents fails
-     */
-    public boolean parse(InputStream input)
-            throws IOException {
-        // No need to validate framework files
-        if (mIsFramework) {
-            try {
-                Closeables.close(input, true /* swallowIOException */);
-            } catch (IOException e) {
-                // cannot happen
-            }
-            return true;
-        }
-        if (mContext.needsFullAapt()) {
-            try {
-                Closeables.close(input, true /* swallowIOException */);
-            } catch (IOException ignore) {
-                // cannot happen
-            }
-            return false;
-        }
-
-        KXmlParser parser = new KXmlParser();
-        try {
-            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
-
-            if (input instanceof FileInputStream) {
-                input = new BufferedInputStream(input);
-            }
-            parser.setInput(input, SdkConstants.UTF_8);
-
-            return parse(parser);
-        } catch (XmlPullParserException | RuntimeException e) {
-            return false;
-        } finally {
-            try {
-                Closeables.close(input, true /* swallowIOException */);
-            } catch (IOException e) {
-                // cannot happen
-            }
-        }
-    }
-
-    private boolean parse(KXmlParser parser)
-            throws XmlPullParserException, IOException {
-        while (true) {
-            int event = parser.next();
-            if (event == XmlPullParser.START_TAG) {
-                for (int i = 0, n = parser.getAttributeCount(); i < n; i++) {
-                    String attribute = parser.getAttributeName(i);
-                    String value = parser.getAttributeValue(i);
-                    assert value != null : attribute;
-                }
-            } else if (event == XmlPullParser.END_DOCUMENT) {
-                break;
-            }
-        }
-
-        return true;
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValueResourceParser.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValueResourceParser.java
deleted file mode 100644
index 53bb5c0fcc..0000000000
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ValueResourceParser.java
+++ /dev/null
@@ -1,227 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-package com.android.ide.common.resources.deprecated;
-
-import com.android.ide.common.rendering.api.ArrayResourceValueImpl;
-import com.android.ide.common.rendering.api.AttrResourceValueImpl;
-import com.android.ide.common.rendering.api.ResourceNamespace;
-import com.android.ide.common.rendering.api.ResourceReference;
-import com.android.ide.common.rendering.api.ResourceValue;
-import com.android.ide.common.rendering.api.ResourceValueImpl;
-import com.android.ide.common.rendering.api.StyleItemResourceValue;
-import com.android.ide.common.rendering.api.StyleItemResourceValueImpl;
-import com.android.ide.common.rendering.api.StyleResourceValueImpl;
-import com.android.ide.common.rendering.api.StyleableResourceValueImpl;
-import com.android.ide.common.resources.ValueXmlHelper;
-import com.android.resources.ResourceType;
-
-import org.xml.sax.Attributes;
-import org.xml.sax.SAXException;
-import org.xml.sax.helpers.DefaultHandler;
-
-import com.google.common.base.Strings;
-
-import static com.android.SdkConstants.ANDROID_NS_NAME_PREFIX;
-import static com.android.SdkConstants.ANDROID_NS_NAME_PREFIX_LEN;
-import static com.android.SdkConstants.ATTR_NAME;
-import static com.android.SdkConstants.ATTR_PARENT;
-import static com.android.SdkConstants.ATTR_VALUE;
-import static com.android.SdkConstants.TAG_RESOURCES;
-
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public final class ValueResourceParser extends DefaultHandler {
-
-    private static final ResourceReference TMP_REF =
-            new ResourceReference(ResourceNamespace.RES_AUTO, ResourceType.STRING, "_tmp");
-
-    public interface IValueResourceRepository {
-        void addResourceValue(ResourceValue value);
-    }
-
-    private boolean inResources;
-    private int mDepth;
-    private ResourceValueImpl mCurrentValue;
-    private ArrayResourceValueImpl mArrayResourceValue;
-    private StyleResourceValueImpl mCurrentStyle;
-    private StyleableResourceValueImpl mCurrentDeclareStyleable;
-    private AttrResourceValueImpl mCurrentAttr;
-    private final IValueResourceRepository mRepository;
-    private final boolean mIsFramework;
-    private final String mLibraryName;
-
-    public ValueResourceParser(IValueResourceRepository repository, boolean isFramework, String libraryName) {
-        mRepository = repository;
-        mIsFramework = isFramework;
-        mLibraryName = libraryName;
-    }
-
-    @Override
-    public void endElement(String uri, String localName, String qName) throws SAXException {
-        if (mCurrentValue != null) {
-            String value = mCurrentValue.getValue();
-            value = value == null ? "" : ValueXmlHelper.unescapeResourceString(value, false, true);
-            mCurrentValue.setValue(value);
-        }
-
-        if (inResources && qName.equals(TAG_RESOURCES)) {
-            inResources = false;
-        } else if (mDepth == 2) {
-            mCurrentValue = null;
-            mCurrentStyle = null;
-            mCurrentDeclareStyleable = null;
-            mCurrentAttr = null;
-            mArrayResourceValue = null;
-        } else if (mDepth == 3) {
-            if (mArrayResourceValue != null && mCurrentValue != null) {
-                mArrayResourceValue.addElement(mCurrentValue.getValue());
-            }
-            mCurrentValue = null;
-            //noinspection VariableNotUsedInsideIf
-            if (mCurrentDeclareStyleable != null) {
-                mCurrentAttr = null;
-            }
-        }
-
-        mDepth--;
-        super.endElement(uri, localName, qName);
-    }
-
-    @Override
-    public void startElement(String uri, String localName, String qName, Attributes attributes)
-            throws SAXException {
-        try {
-            ResourceNamespace namespace = ResourceNamespace.fromBoolean(mIsFramework);
-            mDepth++;
-            if (!inResources && mDepth == 1) {
-                if (qName.equals(TAG_RESOURCES)) {
-                    inResources = true;
-                }
-            } else if (mDepth == 2 && inResources) {
-                ResourceType type =
-                        ResourceType.fromXmlTag(
-                                new Object(), (t) -> qName, (t, name) -> attributes.getValue(name));
-
-                if (type != null) {
-                    // get the resource name
-                    String name = attributes.getValue(ATTR_NAME);
-                    if (name != null) {
-                        switch (type) {
-                            case STYLE:
-                                String parent = attributes.getValue(ATTR_PARENT);
-                                mCurrentStyle =
-                                        new StyleResourceValueImpl(
-                                                namespace, name, parent, mLibraryName);
-                                mRepository.addResourceValue(mCurrentStyle);
-                                break;
-                            case STYLEABLE:
-                                mCurrentDeclareStyleable =
-                                        new StyleableResourceValueImpl(
-                                                namespace, name, null, mLibraryName);
-                                mRepository.addResourceValue(mCurrentDeclareStyleable);
-                                break;
-                            case ATTR:
-                                mCurrentAttr =
-                                        new AttrResourceValueImpl(namespace, name, mLibraryName);
-                                mRepository.addResourceValue(mCurrentAttr);
-                                break;
-                            case ARRAY:
-                                mArrayResourceValue =
-                                        new ArrayResourceValueImpl(namespace, name, mLibraryName);
-                                mRepository.addResourceValue(mArrayResourceValue);
-                                break;
-                            default:
-                                mCurrentValue =
-                                        new ResourceValueImpl(
-                                                namespace, type, name, null, mLibraryName);
-                                mRepository.addResourceValue(mCurrentValue);
-                                break;
-                        }
-                    }
-                }
-            } else if (mDepth == 3) {
-                // get the resource name
-                String name = attributes.getValue(ATTR_NAME);
-                if (!Strings.isNullOrEmpty(name)) {
-                    if (mCurrentStyle != null) {
-                        mCurrentValue =
-                                new StyleItemResourceValueImpl(
-                                        mCurrentStyle.getNamespace(), name, null, mLibraryName);
-                        mCurrentStyle.addItem((StyleItemResourceValue) mCurrentValue);
-                    } else if (mCurrentDeclareStyleable != null) {
-                        if (name.startsWith(ANDROID_NS_NAME_PREFIX)) {
-                            name = name.substring(ANDROID_NS_NAME_PREFIX_LEN);
-                        }
-
-                        mCurrentAttr = new AttrResourceValueImpl(namespace, name, mLibraryName);
-                        mCurrentDeclareStyleable.addValue(mCurrentAttr);
-
-                        // also add it to the repository.
-                        mRepository.addResourceValue(mCurrentAttr);
-
-                    } else if (mCurrentAttr != null) {
-                        // get the enum/flag value
-                        String value = attributes.getValue(ATTR_VALUE);
-
-                        try {
-                            // Integer.decode/parseInt can't deal with hex value > 0x7FFFFFFF so we
-                            // use Long.decode instead.
-                            mCurrentAttr.addValue(name, Long.decode(value).intValue(), null);
-                        } catch (NumberFormatException e) {
-                            // pass, we'll just ignore this value
-                        }
-                    }
-                } else //noinspection VariableNotUsedInsideIf
-                    if (mArrayResourceValue != null) {
-                    // Create a temporary resource value to hold the item's value. The value is
-                    // not added to the repository, since it's just a holder. The value will be set
-                    // in the `characters` method and then added to mArrayResourceValue in `endElement`.
-                    mCurrentValue = new ResourceValueImpl(TMP_REF, null);
-                    }
-            } else if (mDepth == 4 && mCurrentAttr != null) {
-                // get the enum/flag name
-                String name = attributes.getValue(ATTR_NAME);
-                String value = attributes.getValue(ATTR_VALUE);
-
-                try {
-                    // Integer.decode/parseInt can't deal with hex value > 0x7FFFFFFF so we
-                    // use Long.decode instead.
-                    mCurrentAttr.addValue(name, Long.decode(value).intValue(), null);
-                } catch (NumberFormatException e) {
-                    // pass, we'll just ignore this value
-                }
-            }
-        } finally {
-            super.startElement(uri, localName, qName, attributes);
-        }
-    }
-
-    @Override
-    public void characters(char[] ch, int start, int length) {
-        if (mCurrentValue != null) {
-            String value = mCurrentValue.getValue();
-            if (value == null) {
-                mCurrentValue.setValue(new String(ch, start, length));
-            } else {
-                mCurrentValue.setValue(value + new String(ch, start, length));
-            }
-        }
-    }
-}
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
index 8801cd4465..614b1267c3 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
@@ -21,10 +21,7 @@ import com.android.ide.common.rendering.api.RenderSession;
 import com.android.ide.common.rendering.api.Result;
 import com.android.ide.common.rendering.api.SessionParams;
 import com.android.ide.common.rendering.api.SessionParams.RenderingMode;
-import com.android.ide.common.resources.deprecated.FrameworkResources;
-import com.android.ide.common.resources.deprecated.ResourceItem;
-import com.android.ide.common.resources.deprecated.ResourceRepository;
-import com.android.ide.common.resources.deprecated.TestFolderWrapper;
+import com.android.ide.common.resources.ResourceRepository;
 import com.android.internal.lang.System_Delegate;
 import com.android.layoutlib.bridge.Bridge;
 import com.android.layoutlib.bridge.android.RenderParamsFlags;
@@ -35,6 +32,8 @@ import com.android.layoutlib.bridge.intensive.util.ImageUtils;
 import com.android.layoutlib.bridge.intensive.util.ModuleClassLoader;
 import com.android.layoutlib.bridge.intensive.util.SessionParamsBuilder;
 import com.android.layoutlib.bridge.intensive.util.TestAssetRepository;
+import com.android.resources.aar.AarSourceResourceRepository;
+import com.android.resources.aar.FrameworkResourceRepository;
 import com.android.utils.ILogger;
 
 import org.junit.AfterClass;
@@ -54,6 +53,7 @@ import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.Collections;
 import java.util.concurrent.TimeUnit;
 
 import com.google.android.collect.Lists;
@@ -109,7 +109,7 @@ public abstract class BridgeClient {
     /** List of log messages generated by a render call. It can be used to find specific errors */
     protected static final ArrayList<String> sRenderMessages = Lists.newArrayList();
     private static ILayoutLog sLayoutLibLog;
-    private static FrameworkResources sFrameworkRepo;
+    private static FrameworkResourceRepository sFrameworkRepo;
     private static ResourceRepository sProjectResources;
     private static ILogger sLogger;
 
@@ -193,7 +193,7 @@ public abstract class BridgeClient {
     private static String getIcuDataPath() {
         String icuDataPath = System.getProperty(ICU_DATA_PATH_PROPERTY);
         if (icuDataPath == null) {
-            icuDataPath = PLATFORM_DIR + "/../../../../../com.android.i18n/etc/icu/icudt75l.dat";
+            icuDataPath = PLATFORM_DIR + "/../../../../../com.android.i18n/etc/icu/icudt76l.dat";
         }
         return icuDataPath;
     }
@@ -375,9 +375,8 @@ public abstract class BridgeClient {
     public static void beforeClass() {
         File data_dir = new File(PLATFORM_DIR, "data");
         File res = new File(data_dir, "res");
-        sFrameworkRepo = new FrameworkResources(new TestFolderWrapper(res));
-        sFrameworkRepo.loadResources();
-        sFrameworkRepo.loadPublicResources(getLogger());
+        sFrameworkRepo = FrameworkResourceRepository.create(res.getAbsoluteFile().toPath(),
+                Collections.emptySet(), null, false);
 
         File fontLocation = new File(FONT_DIR);
         File buildProp = new File(PLATFORM_DIR, "build.prop");
@@ -534,16 +533,9 @@ public abstract class BridgeClient {
 
     private void initProjectResources() {
         String TEST_RESOURCE_FOLDER = getAppTestRes();
-        sProjectResources =
-                new ResourceRepository(new TestFolderWrapper(TEST_RESOURCE_FOLDER), false) {
-                    @NonNull
-                    @Override
-                    protected ResourceItem createResourceItem(@NonNull String name) {
-                        return new ResourceItem(name);
-                    }
-                };
-        sProjectResources.loadResources();
-
+        File res = new File(TEST_RESOURCE_FOLDER);
+        sProjectResources = AarSourceResourceRepository.create(res.getAbsoluteFile().toPath(),
+                "Application");
     }
 
     @NonNull
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
index e90a61a144..6f555d53ae 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
@@ -25,11 +25,11 @@ import com.android.ide.common.rendering.api.ResourceNamespace;
 import com.android.ide.common.rendering.api.ResourceReference;
 import com.android.ide.common.rendering.api.SessionParams;
 import com.android.ide.common.rendering.api.SessionParams.RenderingMode;
+import com.android.ide.common.resources.ResourceRepository;
+import com.android.ide.common.resources.ResourceRepositoryUtil;
 import com.android.ide.common.resources.ResourceResolver;
 import com.android.ide.common.resources.ResourceValueMap;
 import com.android.ide.common.resources.configuration.FolderConfiguration;
-import com.android.ide.common.resources.deprecated.ResourceRepository;
-import com.android.layoutlib.bridge.android.RenderParamsFlags;
 import com.android.layoutlib.bridge.intensive.setup.ConfigGenerator;
 import com.android.layoutlib.bridge.intensive.setup.LayoutPullParser;
 import com.android.resources.ResourceType;
@@ -39,7 +39,7 @@ import android.annotation.NonNull;
 import java.util.HashMap;
 import java.util.Map;
 
-import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.Table;
 
 /**
  * Builder to help setting up {@link SessionParams} objects.
@@ -63,7 +63,6 @@ public class SessionParamsBuilder {
     private boolean mDecor = true;
     private IImageFactory mImageFactory = null;
     private boolean enableLayoutValidator = false;
-    private boolean enableLayoutValidatorImageCheck = false;
     private boolean transparentBackground = false;
     private Map<ResourceType, ResourceValueMap> mFrameworkOverlayResources;
 
@@ -178,12 +177,6 @@ public class SessionParamsBuilder {
         return this;
     }
 
-    @NonNull
-    public SessionParamsBuilder enableLayoutValidationImageCheck() {
-        this.enableLayoutValidatorImageCheck = true;
-        return this;
-    }
-
     @NonNull
     public SessionParamsBuilder setTransparentBackground() {
         this.transparentBackground = true;
@@ -207,15 +200,24 @@ public class SessionParamsBuilder {
 
         FolderConfiguration config = mConfigGenerator.getFolderConfig();
         Map<ResourceType, ResourceValueMap> frameworkConfigResources =
-                mFrameworkResources.getConfiguredResources(config);
+                ResourceRepositoryUtil.getConfiguredResources(mFrameworkResources, config).row(
+                        ResourceNamespace.ANDROID);
+        Table<ResourceNamespace, ResourceType, ResourceValueMap> projectConfigResources =
+                ResourceRepositoryUtil.getConfiguredResources(mProjectResources, config);
         if (mFrameworkOverlayResources != null) {
-            mFrameworkOverlayResources.keySet().forEach(type ->
-                    frameworkConfigResources.get(type).putAll(mFrameworkOverlayResources.get(type)));
+            mFrameworkOverlayResources.keySet().forEach(
+                    type -> mFrameworkOverlayResources.get(type).values().forEach(
+                            resourceValue -> frameworkConfigResources.get(type).put(
+                                    resourceValue)));
+        }
+        Map<ResourceNamespace, Map<ResourceType, ResourceValueMap>> allResourcesMap =
+                new HashMap<>();
+        allResourcesMap.put(ResourceNamespace.ANDROID, frameworkConfigResources);
+        for (ResourceNamespace namespace : projectConfigResources.rowKeySet()) {
+            allResourcesMap.put(namespace, projectConfigResources.row(namespace));
         }
         ResourceResolver resourceResolver = ResourceResolver.create(
-                ImmutableMap.of(
-                        ResourceNamespace.ANDROID, frameworkConfigResources,
-                        ResourceNamespace.TODO(), mProjectResources.getConfiguredResources(config)),
+                allResourcesMap,
                 new ResourceReference(
                         ResourceNamespace.fromBoolean(!isProjectTheme),
                         ResourceType.STYLE,
@@ -224,10 +226,7 @@ public class SessionParamsBuilder {
         SessionParams params = new SessionParams(mLayoutParser, mRenderingMode, null /* for
         caching */, mConfigGenerator.getHardwareConfig(), resourceResolver, mLayoutlibCallback,
                 mMinSdk, mTargetSdk, mLayoutLog, mSimulatedSdk);
-        params.setFlag(RenderParamsFlags.FLAG_ENABLE_LAYOUT_VALIDATOR, enableLayoutValidator);
-        params.setFlag(
-                RenderParamsFlags.FLAG_ENABLE_LAYOUT_VALIDATOR_IMAGE_CHECK,
-                enableLayoutValidatorImageCheck);
+        params.setLayoutValidationChecker(() -> enableLayoutValidator);
         if (mImageFactory != null) {
             params.setImageFactory(mImageFactory);
         }
diff --git a/bridge/src/android/content/res/BridgeTypedArray.java b/bridge/src/android/content/res/BridgeTypedArray.java
index bba31ad126..863106620f 100644
--- a/bridge/src/android/content/res/BridgeTypedArray.java
+++ b/bridge/src/android/content/res/BridgeTypedArray.java
@@ -207,16 +207,7 @@ public final class BridgeTypedArray extends TypedArray {
             return String.valueOf((int) v);
         }
         ResourceValue resourceValue = mResourceData[index];
-        String value = resourceValue.getValue();
-        if (resourceValue instanceof TextResourceValue) {
-            String rawValue =
-                    ValueXmlHelper.unescapeResourceString(resourceValue.getRawXmlValue(),
-                            true, true);
-            if (rawValue != null && !rawValue.equals(value)) {
-                return ResourceHelper.parseHtml(rawValue);
-            }
-        }
-        return value;
+        return ResourceHelper.getText(resourceValue);
     }
 
     /**
diff --git a/bridge/src/android/content/res/Resources_Delegate.java b/bridge/src/android/content/res/Resources_Delegate.java
index fd6381c893..e45c81bfb0 100644
--- a/bridge/src/android/content/res/Resources_Delegate.java
+++ b/bridge/src/android/content/res/Resources_Delegate.java
@@ -27,6 +27,8 @@ import com.android.ide.common.rendering.api.ResourceNamespace;
 import com.android.ide.common.rendering.api.ResourceReference;
 import com.android.ide.common.rendering.api.ResourceValue;
 import com.android.ide.common.rendering.api.ResourceValueImpl;
+import com.android.ide.common.rendering.api.TextResourceValue;
+import com.android.ide.common.resources.ValueXmlHelper;
 import com.android.layoutlib.bridge.Bridge;
 import com.android.layoutlib.bridge.BridgeConstants;
 import com.android.layoutlib.bridge.android.BridgeContext;
@@ -264,16 +266,9 @@ public class Resources_Delegate {
 
     @LayoutlibDelegate
     static CharSequence getText(Resources resources, int id, CharSequence def) {
-        Pair<String, ResourceValue> value = getResourceValue(resources, id);
-
-        if (value != null) {
-            ResourceValue resValue = value.second;
-
-            assert resValue != null;
-            String v = resValue.getValue();
-            if (v != null) {
-                return v;
-            }
+        CharSequence text = getTextInternal(resources, id);
+        if (text != null) {
+            return text;
         }
 
         return def;
@@ -281,16 +276,9 @@ public class Resources_Delegate {
 
     @LayoutlibDelegate
     static CharSequence getText(Resources resources, int id) throws NotFoundException {
-        Pair<String, ResourceValue> value = getResourceValue(resources, id);
-
-        if (value != null) {
-            ResourceValue resValue = value.second;
-
-            assert resValue != null;
-            String v = resValue.getValue();
-            if (v != null) {
-                return v;
-            }
+        CharSequence text = getTextInternal(resources, id);
+        if (text != null) {
+            return text;
         }
 
         // id was not found or not resolved. Throw a NotFoundException.
@@ -300,6 +288,18 @@ public class Resources_Delegate {
         return null;
     }
 
+    @Nullable
+    private static CharSequence getTextInternal(Resources resources, int id) {
+        Pair<String, ResourceValue> value = getResourceValue(resources, id);
+
+        if (value != null) {
+            ResourceValue resValue = value.second;
+            assert resValue != null;
+            return ResourceHelper.getText(resValue);
+        }
+        return null;
+    }
+
     @LayoutlibDelegate
     static CharSequence[] getTextArray(Resources resources, int id) throws NotFoundException {
         ResourceValue resValue = getArrayResourceValue(resources, id);
@@ -956,6 +956,12 @@ public class Resources_Delegate {
     @LayoutlibDelegate
     static XmlResourceParser loadXmlResourceParser(Resources resources, String file, int id,
             int assetCookie, String type) throws NotFoundException {
+        return resources.loadXmlResourceParser_Original(file, id, assetCookie, type);
+    }
+
+    @LayoutlibDelegate
+    public static XmlResourceParser loadXmlResourceParser(Resources resources, String file, int id,
+            int assetCookie, String type, boolean usesFeatureFlags) throws NotFoundException {
         // even though we know the XML file to load directly, we still need to resolve the
         // id so that we can know if it's a platform or project resource.
         // (mPlatformResourceFlag will get the result and will be used later).
diff --git a/bridge/src/android/hardware/display/DisplayManagerGlobal.java b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
index a91c3b1916..5816b11bd4 100644
--- a/bridge/src/android/hardware/display/DisplayManagerGlobal.java
+++ b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
@@ -29,6 +29,8 @@ import android.hardware.OverlayProperties;
 import android.hardware.display.DisplayManager.DisplayListener;
 import android.media.projection.MediaProjection;
 import android.os.Handler;
+import android.os.HandlerExecutor;
+import android.os.Looper;
 import android.util.Pair;
 import android.view.Display;
 import android.view.DisplayAdjustments;
@@ -87,11 +89,16 @@ public final class DisplayManagerGlobal {
         return null;
     }
 
+    public void registerDisplayListener(@NonNull DisplayListener listener,
+            @Nullable Handler handler, long internalEventFlagsMask, String packageName,
+            boolean isEventFilterExplicit) {}
+
     public void registerDisplayListener(@NonNull DisplayListener listener,
             @Nullable Handler handler, long internalEventFlagsMask, String packageName) {}
 
     public void registerDisplayListener(@NonNull DisplayListener listener,
-            @NonNull Executor executor, long internalEventFlagsMask, String packageName) {}
+            @NonNull Executor executor, long internalEventFlagsMask, String packageName,
+            boolean isEventFilterExplicit) {}
 
     public void unregisterDisplayListener(DisplayListener listener) {}
 
diff --git a/bridge/src/android/os/PerfettoTrace_Category_Delegate.java b/bridge/src/android/os/PerfettoTrace_Category_Delegate.java
new file mode 100644
index 0000000000..494948a1df
--- /dev/null
+++ b/bridge/src/android/os/PerfettoTrace_Category_Delegate.java
@@ -0,0 +1,43 @@
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
+package android.os;
+
+import com.android.layoutlib.bridge.impl.DelegateManager;
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+import libcore.util.NativeAllocationRegistry_Delegate;
+
+public class PerfettoTrace_Category_Delegate {
+    // ---- delegate manager ----
+    private static final DelegateManager<PerfettoTrace_Category_Delegate> sManager =
+            new DelegateManager<>(PerfettoTrace_Category_Delegate.class);
+    private static long sFinalizer = -1;
+
+    @LayoutlibDelegate
+    /*package*/ static long native_init(String name, String tag, String severity) {
+        return sManager.addNewDelegate(new PerfettoTrace_Category_Delegate());
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static long native_delete() {
+        synchronized (PerfettoTrace_Category_Delegate.class) {
+            if (sFinalizer == -1) {
+                sFinalizer = NativeAllocationRegistry_Delegate.createFinalizer(sManager::removeJavaReferenceFor);
+            }
+        }
+        return sFinalizer;
+    }
+}
diff --git a/bridge/src/android/os/PerfettoTrackEventExtra_Delegate.java b/bridge/src/android/os/PerfettoTrackEventExtra_Delegate.java
new file mode 100644
index 0000000000..67887eac75
--- /dev/null
+++ b/bridge/src/android/os/PerfettoTrackEventExtra_Delegate.java
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
+package android.os;
+
+import android.os.PerfettoTrackEventExtra.CounterDouble;
+import android.os.PerfettoTrackEventExtra.CounterInt64;
+import android.os.PerfettoTrackEventExtra.Flow;
+import android.os.PerfettoTrackEventExtra.Proto;
+
+import com.android.layoutlib.bridge.impl.DelegateManager;
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+import libcore.util.NativeAllocationRegistry_Delegate;
+
+public class PerfettoTrackEventExtra_Delegate {
+    // ---- delegate manager ----
+    private static final DelegateManager<PerfettoTrackEventExtra_Delegate> sManager =
+            new DelegateManager<>(PerfettoTrackEventExtra_Delegate.class);
+    private static long sFinalizer = -1;
+
+    @LayoutlibDelegate
+    /*package*/ static long native_init() {
+        return sManager.addNewDelegate(new PerfettoTrackEventExtra_Delegate());
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static long native_delete() {
+        synchronized (PerfettoTrackEventExtra_Delegate.class) {
+            if (sFinalizer == -1) {
+                sFinalizer = NativeAllocationRegistry_Delegate.createFinalizer(sManager::removeJavaReferenceFor);
+            }
+        }
+        return sFinalizer;
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static CounterInt64 getCounterInt64(PerfettoTrackEventExtra thiz) {
+        return null;
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static CounterDouble getCounterDouble(PerfettoTrackEventExtra thiz) {
+        return null;
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static Proto getProto(PerfettoTrackEventExtra thiz) {
+        return null;
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static Flow getFlow(PerfettoTrackEventExtra thiz) {
+        return null;
+    }
+
+    @LayoutlibDelegate
+    /*package*/ static Flow getTerminatingFlow(PerfettoTrackEventExtra thiz) {
+        return null;
+    }
+}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceDeltaKind.java b/bridge/src/android/tracing/Flags_Delegate.java
similarity index 60%
rename from bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceDeltaKind.java
rename to bridge/src/android/tracing/Flags_Delegate.java
index 67c48f3940..805328f44a 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceDeltaKind.java
+++ b/bridge/src/android/tracing/Flags_Delegate.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,13 +14,13 @@
  * limitations under the License.
  */
 
-package com.android.ide.common.resources.deprecated;
+package android.tracing;
 
-/**
- * @deprecated This class is part of an obsolete resource repository system that is no longer used
- *     in production code. The class is preserved temporarily for LayoutLib tests.
- */
-@Deprecated
-public enum ResourceDeltaKind {
-    CHANGED, ADDED, REMOVED
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+public class Flags_Delegate {
+    @LayoutlibDelegate
+    public static boolean perfettoProtologTracing() {
+        return false;
+    }
 }
diff --git a/bridge/src/android/util/Pools_SimplePool_Delegate.java b/bridge/src/android/util/Pools_SimplePool_Delegate.java
new file mode 100644
index 0000000000..5d302a1ac5
--- /dev/null
+++ b/bridge/src/android/util/Pools_SimplePool_Delegate.java
@@ -0,0 +1,47 @@
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
+package android.util;
+
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.util.Pools.SimplePool;
+
+import java.lang.ref.WeakReference;
+
+public class Pools_SimplePool_Delegate {
+    @LayoutlibDelegate
+    public static <T> T acquire(SimplePool<T> thiz) {
+        if (thiz.mPoolSize > 0) {
+            final int lastPooledIndex = thiz.mPoolSize - 1;
+            WeakReference<T> instance = (WeakReference<T>) thiz.mPool[lastPooledIndex];
+            thiz.mPool[lastPooledIndex] = null;
+            thiz.mPoolSize--;
+            return instance.get();
+        }
+        return null;
+    }
+
+    @LayoutlibDelegate
+    public static <T> boolean release(SimplePool<T> thiz, T instance) {
+        if (thiz.mPoolSize < thiz.mPool.length) {
+            thiz.mPool[thiz.mPoolSize] = new WeakReference<T>(instance);
+            thiz.mPoolSize++;
+            return true;
+        }
+        return false;
+    }
+}
diff --git a/bridge/src/android/view/AttachInfo_Accessor.java b/bridge/src/android/view/AttachInfo_Accessor.java
index 8042f32817..8aa7292baa 100644
--- a/bridge/src/android/view/AttachInfo_Accessor.java
+++ b/bridge/src/android/view/AttachInfo_Accessor.java
@@ -52,7 +52,7 @@ public class AttachInfo_Accessor {
         root.setOnContentApplyWindowInsetsListener(sDefaultContentInsetsApplier);
         LayoutlibRenderer renderer = new LayoutlibRenderer(context, false, "layoutlib-renderer");
         AttachInfo info = root.mAttachInfo;
-        info.mThreadedRenderer = renderer;
+        info.mThreadedRenderer = renderer.getThreadedRenderer();
         info.mHasWindowFocus = true;
         info.mWindowVisibility = View.VISIBLE;
         info.mInTouchMode = false; // this is so that we can display selections.
diff --git a/bridge/src/android/view/LayoutlibRenderer.java b/bridge/src/android/view/LayoutlibRenderer.java
index fa8894ae44..8c532885b9 100644
--- a/bridge/src/android/view/LayoutlibRenderer.java
+++ b/bridge/src/android/view/LayoutlibRenderer.java
@@ -20,22 +20,25 @@ import com.android.internal.lang.System_Delegate;
 
 import android.content.Context;
 import android.graphics.BlendMode;
+import android.graphics.PixelFormat;
 import android.graphics.RecordingCanvas;
+import android.media.Image;
+import android.media.Image.Plane;
+import android.media.ImageReader;
+import android.view.ThreadedRenderer.DrawCallbacks;
 
 import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
 
-public class LayoutlibRenderer extends ThreadedRenderer {
+public class LayoutlibRenderer {
 
+    private final ThreadedRenderer mDelegateRenderer;
     private float scaleX = 1.0f;
     private float scaleY = 1.0f;
-    @SuppressWarnings("unused") // Used by native code
-    private long mNativeContext;
-    /** Buffer in which the rendering will be drawn */
-    private ByteBuffer mBuffer;
+    private ImageReader mImageReader;
+    private Image mNativeImage;
 
     LayoutlibRenderer(Context context, boolean translucent, String name) {
-        super(context, translucent, name);
+        mDelegateRenderer = new ThreadedRenderer(context, translucent, name);
     }
 
     public void draw(ViewGroup viewGroup) {
@@ -45,7 +48,7 @@ public class LayoutlibRenderer extends ThreadedRenderer {
         }
         // Animations require mDrawingTime to be set to animate
         rootView.mAttachInfo.mDrawingTime = System_Delegate.currentTimeMillis();
-        this.draw(viewGroup, rootView.mAttachInfo,
+        mDelegateRenderer.draw(viewGroup, rootView.mAttachInfo,
                 new DrawCallbacks() {
                     @Override
                     public void onPreDraw(RecordingCanvas canvas) {
@@ -60,12 +63,14 @@ public class LayoutlibRenderer extends ThreadedRenderer {
 
                     }
                 });
+        // Wait for render thread to finish rendering
+        mDelegateRenderer.fence();
     }
 
     public void setScale(float scaleX, float scaleY) {
         this.scaleX = scaleX;
         this.scaleY = scaleY;
-        invalidateRoot();
+        mDelegateRenderer.invalidateRoot();
     }
 
     /**
@@ -77,31 +82,33 @@ public class LayoutlibRenderer extends ThreadedRenderer {
             return;
         }
 
-        // If the surface associated with the ViewRootImpl is not valid,
-        // create a new one.
-        if (!viewRoot.mSurface.isValid()) {
-            Surface surface = nativeCreateSurface();
-            viewRoot.mSurface.transferFrom(surface);
+        if (mImageReader == null) {
+            mImageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 1);
+            mDelegateRenderer.setSurface(mImageReader.getSurface());
         }
+        mNativeImage = mImageReader.acquireLatestImage();
 
-        // Create a new buffer to draw the image in, making sure that it is following the native
-        // ordering to work on all platforms.
-        mBuffer = nativeCreateBuffer(width, height);
-        mBuffer.order(ByteOrder.nativeOrder());
-
-        setup(width, height, rootView.mAttachInfo, viewRoot.mWindowAttributes.surfaceInsets);
-        setSurface(viewRoot.mSurface);
+        mDelegateRenderer.setup(width, height, rootView.mAttachInfo,
+                viewRoot.mWindowAttributes.surfaceInsets);
     }
 
     public ByteBuffer getBuffer() {
-        return mBuffer;
+        Plane[] planes = mNativeImage.getPlanes();
+        return planes[0].getBuffer();
     }
 
     public void reset() {
-        mBuffer = null;
+        if (mImageReader != null) {
+            mImageReader.close();
+            mImageReader = null;
+        }
     }
 
-    private native Surface nativeCreateSurface();
+    public ThreadedRenderer getThreadedRenderer() {
+        return mDelegateRenderer;
+    }
 
-    private native ByteBuffer nativeCreateBuffer(int width, int height);
+    public void destroy() {
+        mDelegateRenderer.destroy();
+    }
 }
diff --git a/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
index 8e6311409f..8427a780e4 100644
--- a/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
+++ b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
@@ -30,7 +30,7 @@ public class MonochromeIconFactory_Accessor {
             int foregroundColor) {
         MonochromeIconFactory monoFactory = new MonochromeIconFactory(adaptiveIcon.getBounds().width());
         monoFactory.setColorFilter(new BlendModeColorFilter(foregroundColor, BlendMode.SRC_IN));
-        Drawable mono = monoFactory.wrap(adaptiveIcon);
+        Drawable mono = monoFactory.wrap(adaptiveIcon, adaptiveIcon.getIconMask(), 1f);
         float inset = getExtraInsetFraction() / (1 + 2 * getExtraInsetFraction());
         return new InsetDrawable(mono, inset);
     }
diff --git a/bridge/src/com/android/layoutlib/bridge/Bridge.java b/bridge/src/com/android/layoutlib/bridge/Bridge.java
index d4af5dc837..d38342548d 100644
--- a/bridge/src/com/android/layoutlib/bridge/Bridge.java
+++ b/bridge/src/com/android/layoutlib/bridge/Bridge.java
@@ -806,6 +806,7 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
             // This is needed on Windows to avoid creating HostRuntime when loading
             // libandroid_runtime.dll.
             System.setProperty("use_base_native_hostruntime", "false");
+            System.setProperty("icu.locale.default", "en-US");
             for (String library : getNativeLibraries()) {
                 String path = new File(nativeLibDir, library).getAbsolutePath();
                 System.load(path);
@@ -847,4 +848,18 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
         mockView.setGravity(Gravity.CENTER);
         return mockView;
     }
+
+    public static void clearBitmapCaches(Object projectKey) {
+        sFrameworkBitmapCache.clear();
+        sFrameworkBitmapPaddingCache.clear();
+        Map<String, SoftReference<Bitmap>> bitmapCache = sProjectBitmapCache.get(projectKey);
+        if (bitmapCache != null) {
+            bitmapCache.clear();
+        }
+        Map<String, SoftReference<Rect>> paddingCache =
+                sProjectBitmapPaddingCache.get(projectKey);
+        if (paddingCache != null) {
+            paddingCache.clear();
+        }
+    }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java b/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
index 94c3b9246c..73a70a3d11 100644
--- a/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
+++ b/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
@@ -16,6 +16,7 @@
 
 package com.android.layoutlib.bridge;
 
+import com.android.ide.common.rendering.api.HardwareConfig;
 import com.android.ide.common.rendering.api.ILayoutLog;
 import com.android.ide.common.rendering.api.RenderParams;
 import com.android.ide.common.rendering.api.RenderSession;
@@ -232,4 +233,11 @@ public class BridgeRenderSession extends RenderSession {
         }
         return null;
     }
+
+    @Override
+    public void updateHardwareConfiguration(HardwareConfig hardwareConfig) {
+        if (mSession != null) {
+            mSession.updateHardwareConfiguration(hardwareConfig);
+        }
+    }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
index ed96282932..ccd8b947f3 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
@@ -20,6 +20,7 @@ import android.os.BatterySaverPolicyConfig;
 import android.os.ParcelDuration;
 import android.os.IBinder;
 import android.os.IPowerManager;
+import android.os.IScreenTimeoutPolicyListener;
 import android.os.IWakeLockCallback;
 import android.os.PowerManager;
 import android.os.PowerManager.WakeReason;
@@ -245,6 +246,17 @@ public class BridgePowerManager implements IPowerManager {
         return true;
     }
 
+    public void addScreenTimeoutPolicyListener(int displayId,
+            IScreenTimeoutPolicyListener listener) {
+        // pass for now.
+    }
+
+    public void removeScreenTimeoutPolicyListener(int displayId,
+            IScreenTimeoutPolicyListener listener) {
+        // pass for now.
+    }
+
+
     @Override
     public boolean isWakeLockLevelSupportedWithDisplayId(int level, int displayId)
             throws RemoteException {
diff --git a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
index 733ea2c753..eae61aa902 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
@@ -56,19 +56,6 @@ public final class RenderParamsFlags {
     public static final Key<Boolean> FLAG_KEY_RESULT_IMAGE_AUTO_SCALE =
             new Key<>("enableResultImageAutoScale", Boolean.class);
 
-    /**
-     * Enables layout validation calls within rendering.
-     */
-    public static final Key<Boolean> FLAG_ENABLE_LAYOUT_VALIDATOR =
-            new Key<>("enableLayoutValidator", Boolean.class);
-
-    /**
-     * Enables image-related validation checks within layout validation.
-     * {@link #FLAG_ENABLE_LAYOUT_VALIDATOR} must be enabled before this can be effective.
-     */
-    public static final Key<Boolean> FLAG_ENABLE_LAYOUT_VALIDATOR_IMAGE_CHECK =
-            new Key<>("enableLayoutValidatorImageCheck", Boolean.class);
-
     /**
      * To tell Layoutlib the path of the image resource of the wallpaper to use for dynamic theming.
      * If null, use default system colors.
@@ -107,6 +94,12 @@ public final class RenderParamsFlags {
     public static final Key<Boolean> FLAG_KEY_SHOW_CUTOUT =
             new Key<>("showCutout", Boolean.class);
 
+    /**
+     * To tell Layoutlib whether to cache bitmaps.
+     */
+    public static final Key<Boolean> FLAG_KEY_CACHE_BITMAPS =
+            new Key<>("cacheBitmaps", Boolean.class);
+
     // Disallow instances.
     private RenderParamsFlags() {}
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
index 1a3279f417..e4b73b8801 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
@@ -36,6 +36,7 @@ import android.animation.AnimationHandler;
 import android.animation.PropertyValuesHolder_Accessor;
 import android.content.Context;
 import android.content.res.Configuration;
+import android.graphics.Bitmap;
 import android.graphics.Rect;
 import android.graphics.drawable.AdaptiveIconDrawable_Delegate;
 import android.os.HandlerThread_Delegate;
@@ -43,7 +44,6 @@ import android.os.SystemProperties;
 import android.util.DisplayMetrics;
 import android.view.IWindowManager;
 import android.view.IWindowManagerImpl;
-import android.view.Surface;
 import android.view.ViewConfiguration_Accessor;
 import android.view.WindowManagerGlobal_Delegate;
 import android.view.WindowManagerImpl;
@@ -63,6 +63,7 @@ import static android.view.Surface.ROTATION_90;
 import static com.android.ide.common.rendering.api.Result.Status.ERROR_LOCK_INTERRUPTED;
 import static com.android.ide.common.rendering.api.Result.Status.ERROR_TIMEOUT;
 import static com.android.ide.common.rendering.api.Result.Status.SUCCESS;
+import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_CACHE_BITMAPS;
 import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_SHOW_CUTOUT;
 
 /**
@@ -181,6 +182,10 @@ public abstract class RenderAction<T extends RenderParams> {
         return SUCCESS.createResult();
     }
 
+    public void updateHardwareConfiguration(HardwareConfig hardwareConfig) {
+        mParams.setHardwareConfig(hardwareConfig);
+    }
+
     /**
      * Prepares the scene for action.
      * <p>
@@ -335,6 +340,11 @@ public abstract class RenderAction<T extends RenderParams> {
 
         PropertyValuesHolder_Accessor.clearClassCaches();
         AccessibilityInteractionClient_Accessor.clearCaches();
+        if (!Boolean.TRUE.equals(mParams.getFlag(FLAG_KEY_CACHE_BITMAPS))) {
+            // Clear caches except if the flag is explicitly set to true.
+            Bitmap.sAllBitmaps.clear();
+            Bridge.clearBitmapCaches(mParams.getProjectKey());
+        }
     }
 
     public static BridgeContext getCurrentContext() {
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
index 94920ec8c4..1cb50ec565 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
@@ -551,8 +551,6 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                 }
 
                 mRenderer.draw(mViewRoot);
-                // Wait for render thread to finish rendering
-                mRenderer.fence();
 
                 int[] imageData = ((DataBufferInt) mImage.getRaster().getDataBuffer()).getData();
                 IntBuffer buff = mRenderer.getBuffer().asIntBuffer();
@@ -568,21 +566,14 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                 imageTransformation.accept(mImage);
             }
 
-            boolean enableLayoutValidation = Boolean.TRUE.equals(params.getFlag(RenderParamsFlags.FLAG_ENABLE_LAYOUT_VALIDATOR));
-            boolean enableLayoutValidationImageCheck = Boolean.TRUE.equals(
-                    params.getFlag(RenderParamsFlags.FLAG_ENABLE_LAYOUT_VALIDATOR_IMAGE_CHECK));
-
             try {
-                if (enableLayoutValidation && !getViewInfos().isEmpty()) {
+                if (params.isLayoutValidationEnabled() && !getViewInfos().isEmpty()) {
                     CustomHierarchyHelper.sLayoutlibCallback =
                             getContext().getLayoutlibCallback();
 
-                    BufferedImage imageToPass =
-                            enableLayoutValidationImageCheck ? getImage() : null;
-
                     ValidatorHierarchy hierarchy = LayoutValidator.buildHierarchy(
                             ((View) getViewInfos().get(0).getViewObject()),
-                            imageToPass,
+                            getImage(),
                             scaleX,
                             scaleY);
                     setValidatorHierarchy(hierarchy);
@@ -1205,10 +1196,10 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     @Override
     public void dispose() {
         try {
+            releaseRender();
             if (mRenderer != null) {
                 mRenderer.destroy();
             }
-            releaseRender();
             // detachFromWindow might create Handler callbacks, thus before Handler_Delegate.dispose
             AttachInfo_Accessor.detachFromWindow(mViewRoot);
             getContext().getSessionInteractiveData().dispose();
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java b/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
index 4f51f35b1b..1defb1c025 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
@@ -25,6 +25,8 @@ import com.android.ide.common.rendering.api.RenderResources;
 import com.android.ide.common.rendering.api.ResourceNamespace;
 import com.android.ide.common.rendering.api.ResourceReference;
 import com.android.ide.common.rendering.api.ResourceValue;
+import com.android.ide.common.rendering.api.TextResourceValue;
+import com.android.ide.common.resources.ValueXmlHelper;
 import com.android.internal.util.XmlUtils;
 import com.android.layoutlib.bridge.Bridge;
 import com.android.layoutlib.bridge.android.BridgeContext;
@@ -539,6 +541,23 @@ public final class ResourceHelper {
         return getBooleanThemeValue(resources, attrRef, defaultValue);
     }
 
+    /**
+     * Extracts text from a {@link ResourceValue} in the correct format, including handling
+     * HTML tags.
+     */
+    public static CharSequence getText(@NonNull ResourceValue resourceValue) {
+        String value = resourceValue.getValue();
+        if (resourceValue instanceof TextResourceValue) {
+            String rawValue =
+                    ValueXmlHelper.unescapeResourceString(resourceValue.getRawXmlValue(),
+                            true, true);
+            if (rawValue != null && !rawValue.equals(value)) {
+                return ResourceHelper.parseHtml(rawValue);
+            }
+        }
+        return value;
+    }
+
     /**
      * This takes a resource string containing HTML tags for styling,
      * and returns it correctly formatted to be displayed.
@@ -552,12 +571,13 @@ public final class ResourceHelper {
         if (firstTagIndex == -1) {
             return string;
         }
-        int lastTagIndex = str.lastIndexOf('>');
-        StringBuilder stringBuilder = new StringBuilder(str.substring(0, firstTagIndex));
+        StringBuilder stringBuilder = new StringBuilder();
         List<Tag> tagList = new ArrayList<>();
         Map<String, Deque<Tag>> startStacks = new HashMap<>();
         Parser parser = new Parser();
         parser.setContentHandler(new DefaultHandler() {
+            private int numberStartTags = 0;
+
             @Override
             public void startElement(String uri, String localName, String qName,
                     Attributes attributes) {
@@ -566,6 +586,7 @@ public final class ResourceHelper {
                     tag.mStart = stringBuilder.length();
                     tag.mAttributes = attributes;
                     startStacks.computeIfAbsent(localName, key -> new ArrayDeque<>()).addFirst(tag);
+                    numberStartTags++;
                 }
             }
 
@@ -580,19 +601,44 @@ public final class ResourceHelper {
 
             @Override
             public void characters(char[] ch, int start, int length) {
-                stringBuilder.append(ch, start, length);
+                // The Android framework keeps whitespaces before the first tag, but collapses them
+                // after.
+                if (numberStartTags <= 2) {
+                    // We have only seen the outer <html><body> tags but we are still before the
+                    // first tag from the user string. In this case, we keep all the whitespaces.
+                    stringBuilder.append(ch, start, length);
+                } else {
+                    boolean prevSpace = false;
+                    for (int i = 0; i < length; i++) {
+                        char current = ch[start + i];
+                        if (Character.isWhitespace(current)) {
+                            if (!prevSpace) {
+                                stringBuilder.append(' ');
+                                prevSpace = true;
+                            }
+                        } else {
+                            stringBuilder.append(current);
+                            prevSpace = false;
+                        }
+                    }
+                }
             }
         });
         try {
             parser.setProperty(Parser.schemaProperty, new HTMLSchema());
-            parser.parse(new InputSource(
-                    new StringReader(str.substring(firstTagIndex, lastTagIndex + 1))));
+            // String resources in Android do not need to specify the <html> tag. But if it is
+            // not the first tag encountered by the parser, the parser will automatically add it.
+            // To avoid the issue of not knowing if the first html tag encountered by the parser
+            // was present in the string or not, we wrap the string in <html><body> tags, and we
+            // can then be sure that exactly the first two tags encountered were not in the
+            // original string.
+            String htmlString = "<html><body>" + str + "</html></body>";
+            parser.parse(new InputSource(new StringReader(htmlString)));
         } catch (SAXException | IOException e) {
             Bridge.getLog().warning(ILayoutLog.TAG_RESOURCES_FORMAT,
                     "The string " + str + " is not valid HTML", null, null);
             return str;
         }
-        stringBuilder.append(str.substring(lastTagIndex + 1));
         return applyStyles(stringBuilder, tagList);
     }
 
diff --git a/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java b/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
index d1ca9a796e..76f6588695 100644
--- a/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
+++ b/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
@@ -97,12 +97,12 @@ public class SysUiResources {
                 density = iconLoader.getDensity();
                 String path = iconLoader.getPath();
                 // look for a cached bitmap
-                Bitmap bitmap = Bridge.getCachedBitmap(path, Boolean.TRUE /*isFramework*/);
+                Bitmap bitmap = Bridge.getCachedBitmap(path, null);
                 if (bitmap == null) {
                     Options options = new Options();
                     options.inDensity = density.getDpiValue();
                     bitmap = BitmapFactory.decodeStream(stream, null, options);
-                    Bridge.setCachedBitmap(path, bitmap, Boolean.TRUE /*isFramework*/);
+                    Bridge.setCachedBitmap(path, bitmap, null);
                 }
 
                 if (bitmap != null) {
diff --git a/bridge/tests/Android.bp b/bridge/tests/Android.bp
index c80bdca789..58b79c12e0 100644
--- a/bridge/tests/Android.bp
+++ b/bridge/tests/Android.bp
@@ -35,13 +35,9 @@ java_test_host {
         "objenesis",
     ],
 
-    required: ["libandroid_runtime"],
+    required: ["layoutlib_jni"],
 
-    // Copy the jar to DIST_DIR for sdk builds
     dist: {
-        targets: [
-            "sdk",
-            "win_sdk",
-        ],
+        targets: ["layoutlib-tests"],
     },
 }
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png
new file mode 100644
index 0000000000..617b05ce37
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/src/main/res/values/strings.xml b/bridge/tests/res/testApp/MyApplication/src/main/res/values/strings.xml
index f4ff361ae4..37483a9c0a 100644
--- a/bridge/tests/res/testApp/MyApplication/src/main/res/values/strings.xml
+++ b/bridge/tests/res/testApp/MyApplication/src/main/res/values/strings.xml
@@ -93,5 +93,4 @@
         "For example, position the FAB to one side of stream of a cards so the FAB won’t interfere "
         "when a user tries to pick up one of cards.\n\n"
     </string>
-
 </resources>
diff --git a/bridge/tests/run_tests.sh b/bridge/tests/run_tests.sh
index 12b8ff6367..a2ee108be4 100755
--- a/bridge/tests/run_tests.sh
+++ b/bridge/tests/run_tests.sh
@@ -24,7 +24,7 @@ SDK_REPO="${BASE_DIR}/out/host/linux-x86/sdk-repo"
 FONT_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/fonts_intermediates"
 HYPHEN_DATA_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/hyphen_intermediates"
 KEYBOARD_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/keyboards_intermediates"
-ICU_DATA_PATH="${BASE_DIR}/out/host/linux-x86/com.android.i18n/etc/icu/icudt75l.dat"
+ICU_DATA_PATH="${BASE_DIR}/out/host/linux-x86/com.android.i18n/etc/icu/icudt76l.dat"
 TMP_DIR=${OUT_DIR}"/layoutlib_tmp"
 
 PLATFORM=${TMP_DIR}/"android"
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/impl/ResourceHelperTest.java b/bridge/tests/src/com/android/layoutlib/bridge/impl/ResourceHelperTest.java
index d88f77a0ee..d13ee84af4 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/impl/ResourceHelperTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/impl/ResourceHelperTest.java
@@ -16,6 +16,10 @@
 
 package com.android.layoutlib.bridge.impl;
 
+import com.android.ide.common.rendering.api.ResourceNamespace;
+import com.android.ide.common.rendering.api.ResourceValue;
+import com.android.ide.common.rendering.api.TextResourceValueImpl;
+
 import org.junit.Test;
 
 import android.content.res.StringBlock;
@@ -105,4 +109,52 @@ public class ResourceHelperTest {
         String plainText = "This text has no html tags";
         assertEquals(plainText, ResourceHelper.parseHtml(plainText));
     }
+
+    @Test
+    public void testParseHtmlFromResource() {
+        ResourceValue resourceValue =
+                new TextResourceValueImpl(ResourceNamespace.RES_AUTO, "html_string",
+                        "           Normal   Bold      Italic     Normal   This                  " +
+                                "       is bold html    More normal\n         ",
+                        "\"           Normal<b>   Bold   </b>  <i>   Italic</i>     Normal   " +
+                                "<html><body>This                         is <b>bold</b> " +
+                                "html</body></html>    More normal\n         \"",
+                        "");
+        CharSequence text = ResourceHelper.getText(resourceValue);
+        assertTrue(text instanceof SpannedString);
+        assertEquals("           Normal Bold   Italic Normal This is bold html More normal ",
+                text.toString());
+        SpannedString spannedString = (SpannedString)text;
+        Object[] spans = spannedString.getSpans(0, spannedString.length(), Object.class);
+        Class<?>[] classes = {StyleSpan.class, StyleSpan.class, StyleSpan.class};
+        int[] starts = {17, 24, 47};
+        int[] ends = {23, 31, 51};
+        for (int i =0; i < spans.length; i++) {
+            assertEquals(classes[i], spans[i].getClass());
+            assertEquals(starts[i], spannedString.getSpanStart(spans[i]));
+            assertEquals(ends[i], spannedString.getSpanEnd(spans[i]));
+        }
+
+        resourceValue =
+                new TextResourceValueImpl(ResourceNamespace.RES_AUTO, "html_string",
+                        "       This    is bold html    Normal   Bold      Italic     Normal\n   " +
+                                "      ",
+                        "\"       <html><body>This    is <b>bold</b> html</body></html>    " +
+                                "Normal<b>   Bold   </b><i>   Italic</i>     Normal\n         \"",
+                        "");
+        text = ResourceHelper.getText(resourceValue);
+        assertTrue(text instanceof SpannedString);
+        assertEquals("       This is bold html Normal Bold  Italic Normal ",
+                text.toString());
+        spannedString = (SpannedString)text;
+        spans = spannedString.getSpans(0, spannedString.length(), Object.class);
+        classes = new Class[]{StyleSpan.class, StyleSpan.class, StyleSpan.class};
+        starts = new int[]{15, 31, 37};
+        ends = new int[]{19, 37, 44};
+        for (int i =0; i < spans.length; i++) {
+            assertEquals(classes[i], spans[i].getClass());
+            assertEquals(starts[i], spannedString.getSpanStart(spans[i]));
+            assertEquals(ends[i], spannedString.getSpanEnd(spans[i]));
+        }
+    }
 }
\ No newline at end of file
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
index 7cc00e5e87..e9e43e2cce 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
@@ -2437,4 +2437,43 @@ public class RenderTests extends RenderTestBase {
 
         renderAndVerify(params, "hyphenation.png", TimeUnit.SECONDS.toNanos(2));
     }
+
+    /** Test expand_layout.xml */
+    @Test
+    public void testUpdateHardwareConfig() throws ClassNotFoundException {
+        LayoutPullParser parser = createParserFromPath("allwidgets.xml");
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        layoutLibCallback.initResources();
+        SessionParams params = getSessionParamsBuilder()
+                .setParser(parser)
+                .setConfigGenerator(ConfigGenerator.NEXUS_5)
+                .setCallback(layoutLibCallback)
+                .build();
+
+        System_Delegate.setBootTimeNanos(TimeUnit.MILLISECONDS.toNanos(871732800000L));
+        System_Delegate.setNanosTime(TimeUnit.MILLISECONDS.toNanos(871732800000L));
+        RenderSession session = sBridge.createSession(params);
+        session.setElapsedFrameTimeNanos(TimeUnit.SECONDS.toNanos(2));
+
+        try {
+            // Render the session with a timeout of 50s.
+            session.render(50000);
+            RenderResult result = RenderResult.getFromSession(session);
+            verify("allwidgets.png", result.getImage());
+
+            ConfigGenerator enlargedConfig = new ConfigGenerator()
+                    .setScreenHeight(2200)
+                    .setScreenWidth(2000)
+                    .setXdpi(445)
+                    .setYdpi(445)
+                    .setDensity(Density.XXHIGH);
+            session.updateHardwareConfiguration(enlargedConfig.getHardwareConfig());
+            session.render(50000, true);
+            result = RenderResult.getFromSession(session);
+            verify("allwidgets_resized.png", result.getImage());
+        } finally {
+            session.dispose();
+        }
+    }
 }
diff --git a/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java b/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
index 221c1c687d..d9f3ecca73 100644
--- a/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
+++ b/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
@@ -207,26 +207,6 @@ public class AccessibilityValidatorTests extends RenderTestBase {
         });
     }
 
-    @Test
-    public void testTextContrastCheckNoImage() throws Exception {
-        render("a11y_test_text_contrast.xml", session -> {
-            ValidatorResult result = getRenderResult(session);
-            List<Issue> textContrast = filter(result.getIssues(), "TextContrastCheck");
-
-            // ATF doesn't count alpha values unless image is passed.
-            ExpectedLevels expectedLevels = new ExpectedLevels();
-            expectedLevels.expectedErrors = 4;
-            expectedLevels.expectedVerboses = 1;
-            expectedLevels.expectedFixes = 4;
-            expectedLevels.check(textContrast);
-
-            // Make sure no other errors in the system.
-            textContrast = filter(textContrast, EnumSet.of(Level.ERROR));
-            List<Issue> filtered = filter(result.getIssues(), EnumSet.of(Level.ERROR));
-            checkEquals(filtered, textContrast);
-        }, false);
-    }
-
     @Test
     public void testImageContrastCheck() throws Exception {
         render("a11y_test_image_contrast.xml", session -> {
@@ -282,29 +262,12 @@ public class AccessibilityValidatorTests extends RenderTestBase {
 
                 // Ensure that the check went thru the overridden class loader.
                 assertTrue(overriddenClassLoaderCalled[0]);
-            }, true, testCallback);
+            }, testCallback);
         } finally {
             ValidatorUtil.sDefaultCustomViewBuilderAndroid = new DefaultCustomViewBuilderAndroid();
         }
     }
 
-    @Test
-    public void testImageContrastCheckNoImage() throws Exception {
-        render("a11y_test_image_contrast.xml", session -> {
-            ValidatorResult result = getRenderResult(session);
-            List<Issue> imageContrast = filter(result.getIssues(), "ImageContrastCheck");
-
-            ExpectedLevels expectedLevels = new ExpectedLevels();
-            expectedLevels.expectedVerboses = 3;
-            expectedLevels.check(imageContrast);
-
-            // Make sure no other errors in the system.
-            imageContrast = filter(imageContrast, EnumSet.of(Level.ERROR, Level.WARNING));
-            List<Issue> filtered = filter(result.getIssues(), EnumSet.of(Level.ERROR, Level.WARNING));
-            checkEquals(filtered, imageContrast);
-        }, false);
-    }
-
     @Test
     public void testTouchTargetSizeCheck() throws Exception {
         render("a11y_test_touch_target_size.xml", session -> {
@@ -357,25 +320,17 @@ public class AccessibilityValidatorTests extends RenderTestBase {
         return ValidatorUtil.generateResults(LayoutValidator.DEFAULT_POLICY,
                 (ValidatorHierarchy) validationData);
     }
-    private void render(String fileName, RenderSessionListener verifier) throws Exception {
-        render(fileName, verifier, true);
-    }
 
-    private void render(
-            String fileName,
-            RenderSessionListener verifier,
-            boolean enableImageCheck) throws Exception {
+    private void render(String fileName, RenderSessionListener verifier) throws Exception {
         render(
                 fileName,
                 verifier,
-                enableImageCheck,
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader));
     }
 
     private void render(
             String fileName,
             RenderSessionListener verifier,
-            boolean enableImageCheck,
             LayoutLibTestCallback layoutLibCallback) throws Exception {
         LayoutValidator.updatePolicy(new Policy(
                 EnumSet.of(Type.ACCESSIBILITY, Type.RENDER),
@@ -391,10 +346,6 @@ public class AccessibilityValidatorTests extends RenderTestBase {
                 .disableDecoration()
                 .enableLayoutValidation();
 
-        if (enableImageCheck) {
-            params.enableLayoutValidationImageCheck();
-        }
-
         render(sBridge, params.build(), -1, verifier);
     }
 
diff --git a/common/src/com/android/tools/layoutlib/create/NativeConfig.java b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
index 9b3d34c9ae..aaf27253a7 100644
--- a/common/src/com/android/tools/layoutlib/create/NativeConfig.java
+++ b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
@@ -27,6 +27,7 @@ public class NativeConfig {
     public final static String[] DEFERRED_STATIC_INITIALIZER_CLASSES = new String [] {
             "android.graphics.PathIterator",
             "android.graphics.Typeface",
+            "android.media.ImageReader",
     };
 
     public static final String[] DELEGATE_METHODS = new String[] {
@@ -93,6 +94,15 @@ public class NativeConfig {
             "android.os.Handler#sendMessageAtFrontOfQueue",
             "android.os.Handler#sendMessageAtTime",
             "android.os.HandlerThread#run",
+            "android.os.PerfettoTrace$Category#native_delete",
+            "android.os.PerfettoTrace$Category#native_init",
+            "android.os.PerfettoTrackEventExtra#getCounterDouble",
+            "android.os.PerfettoTrackEventExtra#getCounterInt64",
+            "android.os.PerfettoTrackEventExtra#getFlow",
+            "android.os.PerfettoTrackEventExtra#getProto",
+            "android.os.PerfettoTrackEventExtra#getTerminatingFlow",
+            "android.os.PerfettoTrackEventExtra#native_delete",
+            "android.os.PerfettoTrackEventExtra#native_init",
             "android.os.SystemProperties#find",
             "android.permission.PermissionManager#checkPermission",
             "android.preference.Preference#getView",
@@ -104,6 +114,9 @@ public class NativeConfig {
             "android.provider.DeviceConfig#getString",
             "android.provider.Settings$Config#getContentResolver",
             "android.text.format.DateFormat#is24HourFormat",
+            "android.tracing.Flags#perfettoProtologTracing",
+            "android.util.Pools$SimplePool#acquire",
+            "android.util.Pools$SimplePool#release",
             "android.util.Xml#newPullParser",
             "android.view.Choreographer#doCallbacks",
             "android.view.Choreographer#getRefreshRate",
@@ -163,6 +176,8 @@ public class NativeConfig {
             "android.animation.PropertyValuesHolder",
             "android.content.res.StringBlock",
             "android.content.res.XmlBlock",
+            "android.media.ImageReader",
+            "android.media.PublicFormatUtils",
             "android.os.SystemProperties",
             "android.text.AndroidCharacter",
             "android.text.Hyphenator",
diff --git a/create/src/com/android/tools/layoutlib/create/CreateInfo.java b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
index 75c53c000e..0a62671005 100644
--- a/create/src/com/android/tools/layoutlib/create/CreateInfo.java
+++ b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
@@ -18,6 +18,7 @@ package com.android.tools.layoutlib.create;
 
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 import com.android.tools.layoutlib.java.LinkedHashMap_Delegate;
+import com.android.tools.layoutlib.java.NioUtils_Delegate;
 import com.android.tools.layoutlib.java.Reference_Delegate;
 
 import org.objectweb.asm.Opcodes;
@@ -152,6 +153,7 @@ public final class CreateInfo implements ICreateInfo {
         new HtmlApplicationResourceReplacer(),
         new NativeAllocationRegistryApplyFreeFunctionReplacer(),
         new LineBreakConfigApplicationInfoReplacer(),
+        new NioUtilsFreeBufferReplacer(),
     };
 
     /**
@@ -168,6 +170,7 @@ public final class CreateInfo implements ICreateInfo {
             InjectMethodRunnables.class,
             /* Java package classes */
             LinkedHashMap_Delegate.class,
+            NioUtils_Delegate.class,
             Reference_Delegate.class,
         };
 
@@ -268,6 +271,9 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.text.MeasuredText",
         "android.graphics.text.MeasuredText$Builder",
         "android.graphics.text.TextRunShaper",
+        "android.media.ImageReader",
+        "android.media.ImageReader$SurfaceImage",
+        "android.media.PublicFormatUtils",
         "android.os.SystemProperties",
         "android.text.AndroidCharacter",
         "android.text.Hyphenator",
@@ -341,6 +347,7 @@ public final class CreateInfo implements ICreateInfo {
         "android.animation.PropertyValuesHolder$FloatPropertyValuesHolder#sJNISetterPropertyMap",
         "android.animation.PropertyValuesHolder$MultiFloatValuesHolder#sJNISetterPropertyMap",
         "android.animation.PropertyValuesHolder$MultiIntValuesHolder#sJNISetterPropertyMap",
+        "android.graphics.Bitmap#sAllBitmaps",
         "android.graphics.ImageDecoder$InputStreamSource#mInputStream",
         "android.graphics.Typeface#DEFAULT_FAMILY",
         "android.graphics.Typeface#sDynamicTypefaceCache",
@@ -349,10 +356,13 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.drawable.AnimatedVectorDrawable#mAnimatorSet",
         "android.graphics.drawable.DrawableInflater#mRes",
         "android.hardware.input.InputManagerGlobal#sInstance",
+        "android.util.Pools$SimplePool#mPool",
+        "android.util.Pools$SimplePool#mPoolSize",
         "android.view.Choreographer#mCallbackQueues", // required for tests only
         "android.view.Choreographer#mCallbacksRunning",
         "android.view.Choreographer#mFrameScheduled",
         "android.view.Choreographer$CallbackQueue#mHead", // required for tests only
+        "android.view.View#sAlwaysRemeasureExactly",
         "android.view.ViewRootImpl#mTmpFrames",
         "android.view.accessibility.AccessibilityInteractionClient#sCaches",
         "android.view.accessibility.AccessibilityInteractionClient#sClients",
@@ -386,6 +396,10 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.ImageDecoder$ResourceSource",
         "android.graphics.drawable.AnimatedVectorDrawable$VectorDrawableAnimatorUI",
         "android.graphics.drawable.AnimatedVectorDrawable$VectorDrawableAnimator",
+        "android.os.PerfettoTrackEventExtra$CounterInt64",
+        "android.os.PerfettoTrackEventExtra$CounterDouble",
+        "android.os.PerfettoTrackEventExtra$Flow",
+        "android.os.PerfettoTrackEventExtra$Proto",
         "android.view.Choreographer$CallbackQueue", // required for tests only
     };
 
@@ -665,4 +679,16 @@ public final class CreateInfo implements ICreateInfo {
             mi.desc = "(Landroid/app/Application;)Landroid/content/pm/ApplicationInfo;";
         }
     }
+
+    public static class NioUtilsFreeBufferReplacer implements MethodReplacer {
+        @Override
+        public boolean isNeeded(String owner, String name, String desc, String sourceClass) {
+            return "java/nio/NioUtils".equals(owner) && name.equals("freeDirectBuffer");
+        }
+
+        @Override
+        public void replace(MethodInformation mi) {
+            mi.owner = Type.getInternalName(NioUtils_Delegate.class);
+        }
+    }
 }
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFileWrapper.java b/create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java
similarity index 53%
rename from bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFileWrapper.java
rename to create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java
index f1f3f1743a..72c09aafc3 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/TestFileWrapper.java
+++ b/create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2020 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,23 +14,12 @@
  * limitations under the License.
  */
 
-package com.android.ide.common.resources.deprecated;
+package com.android.tools.layoutlib.java;
 
-import com.android.io.FileWrapper;
-import com.android.io.IAbstractFolder;
+import java.nio.ByteBuffer;
 
-import java.io.File;
-
-public class TestFileWrapper extends FileWrapper {
-    public TestFileWrapper(File file) {
-        super(file);
-    }
-
-    public IAbstractFolder getParentFolder() {
-        String p = this.getParent();
-        if (p == null) {
-            return null;
-        }
-        return new TestFolderWrapper(p);
+public final class NioUtils_Delegate {
+    public static void freeDirectBuffer(ByteBuffer buffer) {
+        // This is a no-op for the layoutlib use case.
     }
 }
diff --git a/bridge/jarjar-rules.txt b/jarjar-rules.txt
similarity index 82%
rename from bridge/jarjar-rules.txt
rename to jarjar-rules.txt
index f4206d7fe9..9c80c65402 100644
--- a/bridge/jarjar-rules.txt
+++ b/jarjar-rules.txt
@@ -2,4 +2,4 @@ rule androidx.** com.android.layoutlib.androidx.@1
 rule com.google.protobuf.** com.android.layoutlib.protobuf.@1
 rule org.hamcrest.** com.android.layoutlib.hamcrest.@1
 rule org.jetbrains.** com.android.layoutlib.jetbrains.@1
-rule org.jsoup.** com.android.layoutlib.jsoup.@1
+rule org.jsoup.** com.android.layoutlib.jsoup.@1
\ No newline at end of file
diff --git a/jni/LayoutlibLoader.cpp b/jni/LayoutlibLoader.cpp
index 8993ef0c1b..3bb24f1c84 100644
--- a/jni/LayoutlibLoader.cpp
+++ b/jni/LayoutlibLoader.cpp
@@ -34,28 +34,6 @@ static jmethodID logMethodId;
 
 namespace android {
 
-extern int register_android_view_LayoutlibRenderer(JNIEnv* env);
-
-#define REG_JNI(name) \
-    { name }
-struct RegJNIRec {
-    int (*mProc)(JNIEnv*);
-};
-
-static const RegJNIRec gRegJNI[] = {
-        REG_JNI(register_android_view_LayoutlibRenderer),
-};
-
-int register_jni_procs(JNIEnv* env) {
-    for (size_t i = 0; i < NELEM(android::gRegJNI); i++) {
-        if (android::gRegJNI[i].mProc(env) < 0) {
-            return -1;
-        }
-    }
-
-    return 0;
-}
-
 static vector<string> parseCsv(const string& csvString) {
     vector<string> result;
     istringstream stream(csvString);
@@ -138,7 +116,6 @@ public:
 
     void onStarted() override {
         JNIEnv* env = AndroidRuntime::getJNIEnv();
-        register_jni_procs(env);
 
         jmethodID setSystemPropertiesMethod =
                 GetStaticMethodIDOrDie(env, bridge, "setSystemProperties", "()V");
diff --git a/jni/android_view_LayoutlibRenderer.cpp b/jni/android_view_LayoutlibRenderer.cpp
deleted file mode 100644
index 50ddb26107..0000000000
--- a/jni/android_view_LayoutlibRenderer.cpp
+++ /dev/null
@@ -1,116 +0,0 @@
-/*
- * Copyright 2024 The Android Open Source Project
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
-#include <gui/BufferQueue.h>
-#include <gui/IGraphicBufferConsumer.h>
-#include <gui/IGraphicBufferProducer.h>
-#include <ui/GraphicBuffer.h>
-
-#include "android_runtime/android_view_Surface.h"
-#include "core_jni_helpers.h"
-#include "jni.h"
-
-namespace android {
-
-jfieldID gNativeContextFieldId;
-
-/**
- * Class to store information needed by the Layoutlib renderer
- */
-class JNILayoutlibRendererContext : public RefBase {
-public:
-    ~JNILayoutlibRendererContext() override {
-        if (mBufferConsumer != nullptr) {
-            mBufferConsumer.clear();
-        }
-    }
-
-    void setBufferConsumer(const sp<IGraphicBufferConsumer>& consumer) {
-        mBufferConsumer = consumer;
-    }
-
-    IGraphicBufferConsumer* getBufferConsumer() {
-        return mBufferConsumer.get();
-    }
-
-private:
-    sp<IGraphicBufferConsumer> mBufferConsumer;
-};
-
-static jobject android_view_LayoutlibRenderer_createSurface(JNIEnv* env, jobject thiz) {
-    sp<IGraphicBufferProducer> gbProducer;
-    sp<IGraphicBufferConsumer> gbConsumer;
-    BufferQueue::createBufferQueue(&gbProducer, &gbConsumer);
-
-    // Save the IGraphicBufferConsumer in the context so that it can be reused for buffer creation
-    sp<JNILayoutlibRendererContext> newCtx = sp<JNILayoutlibRendererContext>::make();
-    newCtx->setBufferConsumer(gbConsumer);
-    auto* const currentCtx = reinterpret_cast<JNILayoutlibRendererContext*>(
-            env->GetLongField(thiz, gNativeContextFieldId));
-    if (newCtx != nullptr) {
-        // Create a strong reference to the new context to avoid it being destroyed
-        newCtx->incStrong((void*)android_view_LayoutlibRenderer_createSurface);
-    }
-    if (currentCtx != nullptr) {
-        // Delete the reference to the previous context as it is not needed and can be destroyed
-        currentCtx->decStrong((void*)android_view_LayoutlibRenderer_createSurface);
-    }
-    env->SetLongField(thiz, gNativeContextFieldId, reinterpret_cast<jlong>(newCtx.get()));
-
-    return android_view_Surface_createFromIGraphicBufferProducer(env, gbProducer);
-}
-
-static jobject android_view_LayoutlibRenderer_createBuffer(JNIEnv* env, jobject thiz, jint width,
-                                                           jint height) {
-    auto* ctx = reinterpret_cast<JNILayoutlibRendererContext*>(
-            env->GetLongField(thiz, gNativeContextFieldId));
-    if (ctx == nullptr) {
-        jniThrowException(env, "java/lang/IllegalStateException", "No surface has been created");
-        return nullptr;
-    }
-
-    IGraphicBufferConsumer* bufferConsumer = ctx->getBufferConsumer();
-    bufferConsumer->setDefaultBufferSize(width, height);
-    auto* bufferItem = new BufferItem();
-    bufferConsumer->acquireBuffer(bufferItem, 0);
-    sp<GraphicBuffer> buffer = bufferItem->mGraphicBuffer;
-    delete bufferItem;
-
-    int bytesPerPixel = 4;
-    uint32_t dataSize = buffer->getStride() * buffer->getHeight() * bytesPerPixel;
-
-    void* pData = nullptr;
-    buffer->lockAsync(0, Rect::EMPTY_RECT, &pData, 0);
-
-    jobject byteBuffer = env->NewDirectByteBuffer(pData, dataSize);
-    return byteBuffer;
-}
-
-static const JNINativeMethod gMethods[] = {
-        {"nativeCreateSurface", "()Landroid/view/Surface;",
-         (void*)android_view_LayoutlibRenderer_createSurface},
-        {"nativeCreateBuffer", "(II)Ljava/nio/ByteBuffer;",
-         (void*)android_view_LayoutlibRenderer_createBuffer},
-};
-
-int register_android_view_LayoutlibRenderer(JNIEnv* env) {
-    jclass layoutlibRendererClass = FindClassOrDie(env, "android/view/LayoutlibRenderer");
-    gNativeContextFieldId = GetFieldIDOrDie(env, layoutlibRendererClass, "mNativeContext", "J");
-
-    return RegisterMethodsOrDie(env, "android/view/LayoutlibRenderer", gMethods, NELEM(gMethods));
-}
-
-} // namespace android
\ No newline at end of file
diff --git a/overlay_codenames.txt b/overlay_codenames.txt
new file mode 100644
index 0000000000..3a6c871d6f
--- /dev/null
+++ b/overlay_codenames.txt
@@ -0,0 +1,15 @@
+oriole:pixel_6
+raven:pixel_6_pro
+bluejay:pixel_6a
+panther:pixel_7
+cheetah:pixel_7_pro
+lynx:pixel_7a
+felix:pixel_fold
+shiba:pixel_8
+husky:pixel_8_pro
+akita:pixel_8a
+tokay:pixel_9
+caiman:pixel_9_pro
+komodo:pixel_9_pro_xl
+comet:pixel_9_pro_fold
+tangorpro:pixel_tablet
\ No newline at end of file
diff --git a/validator/Android.bp b/validator/Android.bp
index 1581c96515..e924d379f7 100644
--- a/validator/Android.bp
+++ b/validator/Android.bp
@@ -25,7 +25,7 @@ java_library_host {
     java_resource_dirs: ["resources"],
 
     libs: [
-        "temp_layoutlib",
+        "layoutlib-framework",
         "layoutlib_api-prebuilt",
         "layoutlib-common",
         "guava",
@@ -36,4 +36,6 @@ java_library_host {
         "jsoup-1.6.3",
         "libprotobuf-java-lite",
     ],
+
+    jarjar_rules: "jarjar-rules.txt",
 }
diff --git a/validator/jarjar-rules.txt b/validator/jarjar-rules.txt
new file mode 100644
index 0000000000..b30190708f
--- /dev/null
+++ b/validator/jarjar-rules.txt
@@ -0,0 +1,3 @@
+rule com.google.protobuf.** com.android.layoutlib.protobuf.@1
+rule org.hamcrest.** com.android.layoutlib.hamcrest.@1
+rule org.jsoup.** com.android.layoutlib.jsoup.@1
```

