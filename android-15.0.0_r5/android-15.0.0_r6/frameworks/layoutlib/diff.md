```diff
diff --git a/.clang-format b/.clang-format
new file mode 100644
index 0000000000..0f6b166ecd
--- /dev/null
+++ b/.clang-format
@@ -0,0 +1,25 @@
+BasedOnStyle: Google
+
+AccessModifierOffset: -4
+AlignOperands: false
+AllowShortFunctionsOnASingleLine: Empty
+AlwaysBreakBeforeMultilineStrings: false
+ColumnLimit: 100
+CommentPragmas: NOLINT:.*
+ConstructorInitializerIndentWidth: 6
+ContinuationIndentWidth: 8
+IndentWidth: 4
+JavaImportGroups:
+- android
+- androidx
+- com.android
+- dalvik
+- libcore
+- com
+- junit
+- net
+- org
+- java
+- javax
+PenaltyBreakBeforeFirstCallParameter: 100000
+SpacesBeforeTrailingComments: 1
diff --git a/.idea/libraries/framework_jar.xml b/.idea/libraries/framework_jar.xml
index 82af4c51f7..37e4754f38 100644
--- a/.idea/libraries/framework_jar.xml
+++ b/.idea/libraries/framework_jar.xml
@@ -1,7 +1,7 @@
 <component name="libraryTable">
   <library name="framework.jar">
     <CLASSES>
-      <root url="jar://$PROJECT_DIR$/../../out/soong/.intermediates/frameworks/layoutlib/temp_layoutlib/linux_glibc_common/gen/temp_layoutlib.jar!/" />
+      <root url="file://$PROJECT_DIR$/../../out/soong/.intermediates/frameworks/layoutlib/temp_layoutlib/linux_glibc_common" />
     </CLASSES>
     <JAVADOC />
     <SOURCES>
@@ -10,5 +10,7 @@
       <root url="file://$PROJECT_DIR$/../../libcore/luni/src/main/java" />
       <root url="file://$PROJECT_DIR$/../../libcore/dalvik/src/main/java" />
     </SOURCES>
+    <jarDirectory
+        url="file://$PROJECT_DIR$/../../out/soong/.intermediates/frameworks/layoutlib/temp_layoutlib/linux_glibc_common" recursive="true" />
   </library>
 </component>
\ No newline at end of file
diff --git a/.idea/libraries/ow2_asm.xml b/.idea/libraries/ow2_asm.xml
new file mode 100644
index 0000000000..b4dee6bb6b
--- /dev/null
+++ b/.idea/libraries/ow2_asm.xml
@@ -0,0 +1,11 @@
+<component name="libraryTable">
+  <library name="ow2-asm">
+    <CLASSES>
+      <root url="jar://$PROJECT_DIR$/../../out/soong/.intermediates/external/ow2-asm/ow2-asm/linux_glibc_common/javac/ow2-asm.jar!/" />
+    </CLASSES>
+    <JAVADOC />
+    <SOURCES>
+      <root url="file://$PROJECT_DIR$/../../external/ow2-asm/asm/src/main/java" />
+    </SOURCES>
+  </library>
+</component>
\ No newline at end of file
diff --git a/.idea/libraries/ow2_asm_commons.xml b/.idea/libraries/ow2_asm_commons.xml
new file mode 100644
index 0000000000..a487c52033
--- /dev/null
+++ b/.idea/libraries/ow2_asm_commons.xml
@@ -0,0 +1,12 @@
+<component name="libraryTable">
+  <library name="ow2-asm-commons">
+    <CLASSES>
+      <root url="jar://$PROJECT_DIR$/../../out/soong/.intermediates/external/ow2-asm/ow2-asm-commons/linux_glibc_common/javac/ow2-asm-commons.jar!/" />
+    </CLASSES>
+    <JAVADOC />
+    <SOURCES>
+      <root url="file://$PROJECT_DIR$/../../external/ow2-asm/asm-commons/src/main/java" />
+      <root url="file://$PROJECT_DIR$/../../external/ow2-asm/asm-commons/src/resources/java" />
+    </SOURCES>
+  </library>
+</component>
\ No newline at end of file
diff --git a/.idea/misc.xml b/.idea/misc.xml
index d47ec03f54..e4f8290c2e 100644
--- a/.idea/misc.xml
+++ b/.idea/misc.xml
@@ -53,7 +53,7 @@
       </value>
     </option>
   </component>
-  <component name="ProjectRootManager" version="2" languageLevel="JDK_11" project-jdk-name="jbr-17" project-jdk-type="JavaSDK">
+  <component name="ProjectRootManager" version="2" languageLevel="JDK_17" default="true" project-jdk-name="jbr-17" project-jdk-type="JavaSDK">
     <output url="file://$PROJECT_DIR$/out" />
   </component>
 </project>
\ No newline at end of file
diff --git a/.idea/runConfigurations/Create.xml b/.idea/runConfigurations/Create.xml
index 68f4a033f8..af69537b09 100644
--- a/.idea/runConfigurations/Create.xml
+++ b/.idea/runConfigurations/Create.xml
@@ -1,9 +1,10 @@
 <component name="ProjectRunConfigurationManager">
   <configuration default="false" name="Create" type="Application" factoryName="Application" singleton="true">
-    <option name="ALTERNATIVE_JRE_PATH" value="$PROJECT_DIR$/../../prebuilts/jdk/jdk9/linux-x86" />
+    <option name="ALTERNATIVE_JRE_PATH" value="jbr-21" />
+    <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
     <option name="MAIN_CLASS_NAME" value="com.android.tools.layoutlib.create.Main" />
     <module name="create" />
-    <option name="PROGRAM_PARAMETERS" value="--create-stub out/soong/.temp/temp_layoutlib.jar out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-502584086/linux_glibc_common/combined/atf-prebuilt-jars-502584086.jar out/soong/.intermediates/external/icu/android_icu4j/core-icu4j-for-host/android_common/withres/core-icu4j-for-host.jar out/soong/.intermediates/libcore/core-libart/android_common/javac/core-libart.jar out/soong/.intermediates/frameworks/base/framework-all/android_common/combined/framework-all.jar out/soong/.intermediates/frameworks/base/ext/android_common/withres/ext.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar out/soong/.intermediates/frameworks/base/packages/SystemUI/monet/monet/android_common/combined/monet.jar" />
+    <option name="PROGRAM_PARAMETERS" value="--create-stub out/soong/.temp/temp_layoutlib.jar out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/combined/atf-prebuilt-jars-557133692.jar out/soong/.intermediates/external/icu/android_icu4j/core-icu4j-for-host/android_common/withres/core-icu4j-for-host.jar out/soong/.intermediates/libcore/core-libart/android_common/combined/core-libart.jar out/soong/.intermediates/frameworks/base/framework-all/android_common/combined/framework-all.jar out/soong/.intermediates/frameworks/base/ext/android_common/withres/ext.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar out/soong/.intermediates/frameworks/libs/systemui/monet/monet/android_common/combined/monet.jar" />
     <option name="VM_PARAMETERS" value="-ea" />
     <option name="WORKING_DIRECTORY" value="$PROJECT_DIR$/../.." />
     <RunnerSettings RunnerId="Debug">
diff --git a/Android.bp b/Android.bp
index 5fd342d124..3320e227fe 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,3 +55,44 @@ java_device_for_host {
         "monet",
     ],
 }
+
+cc_library_host_shared {
+    name: "layoutlib_jni",
+    srcs: [
+        "jni/android_view_LayoutlibRenderer.cpp",
+        "jni/LayoutlibLoader.cpp",
+    ],
+    cflags: [
+        "-Wno-unused-parameter",
+    ],
+    header_libs: [
+        "libnativebase_headers",
+        "libnativedisplay_headers",
+        "libnativewindow_headers",
+    ],
+    shared_libs: [
+        "libandroid_runtime",
+    ],
+    static_libs: [
+        "libbase",
+        "libbinder",
+        "libcutils",
+        "libharfbuzz_ng",
+        "libhostgraphics",
+        "libhwui",
+        "libicui18n",
+        "libicuuc",
+        "libicuuc_stubdata",
+        "libimage_io",
+        "libinput",
+        "liblog",
+        "libjpegdecoder",
+        "libjpegencoder",
+        "libminikin",
+        "libnativehelper_jvm",
+        "libui-types",
+        "libultrahdr",
+        "libutils",
+    ],
+    stl: "libc++_static",
+}
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java
index 2624df0e1b..c1c32b6850 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java
+++ b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/FrameworkResources.java
@@ -137,31 +137,14 @@ public class FrameworkResources extends ResourceRepository {
                                         // in one platform version, there are 1500 drawables
                                         // and 1200 strings but only 175 and 25 public ones
                                         // respectively.
-                                        int size;
-                                        switch (type) {
-                                            case STYLE:
-                                                size = 500;
-                                                break;
-                                            case ATTR:
-                                                size = 1050;
-                                                break;
-                                            case DRAWABLE:
-                                                size = 200;
-                                                break;
-                                            case ID:
-                                                size = 50;
-                                                break;
-                                            case LAYOUT:
-                                            case COLOR:
-                                            case STRING:
-                                            case ANIM:
-                                            case INTERPOLATOR:
-                                                size = 30;
-                                                break;
-                                            default:
-                                                size = 10;
-                                                break;
-                                        }
+                                        int size = switch (type) {
+                                            case STYLE -> 500;
+                                            case ATTR -> 1050;
+                                            case DRAWABLE -> 200;
+                                            case ID -> 50;
+                                            case LAYOUT, COLOR, STRING, ANIM, INTERPOLATOR -> 30;
+                                            default -> 10;
+                                        };
                                         publicList = new ArrayList<>(size);
                                         mPublicResourceMap.put(type, publicList);
                                     }
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java
index 016c6b4088..64f23a65c4 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java
+++ b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/MultiResourceFile.java
@@ -20,7 +20,6 @@ import com.android.ide.common.rendering.api.ResourceValue;
 import com.android.ide.common.rendering.api.ResourceValueImpl;
 import com.android.ide.common.resources.ResourceValueMap;
 import com.android.ide.common.resources.deprecated.ValueResourceParser.IValueResourceRepository;
-import com.android.io.IAbstractFile;
 import com.android.io.StreamException;
 import com.android.resources.ResourceType;
 import com.android.utils.XmlUtils;
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java
index 30fbd0b153..050f7cc949 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java
+++ b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceFile.java
@@ -47,18 +47,18 @@ public abstract class ResourceFile implements Configurable {
     /**
      * Returns the IFile associated with the ResourceFile.
      */
-    public final TestFileWrapper getFile() {
+    protected final TestFileWrapper getFile() {
         return mFile;
     }
 
-    public final ResourceRepository getRepository() {
+    protected final ResourceRepository getRepository() {
         return mFolder.getRepository();
     }
 
     /**
      * Returns whether the resource is a framework resource.
      */
-    public final boolean isFramework() {
+    protected final boolean isFramework() {
         return mFolder.getRepository().isFrameworkRepository();
     }
 
diff --git a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java
index fca0862922..6707144ca9 100644
--- a/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java
+++ b/bridge/bridge_client/src/com/android/ide/common/resources/deprecated/ResourceRepository.java
@@ -63,7 +63,7 @@ public abstract class ResourceRepository {
         mFrameworkRepository = isFrameworkRepository;
     }
 
-    public TestFolderWrapper getResFolder() {
+    protected TestFolderWrapper getResFolder() {
         return mResourceFolder;
     }
 
@@ -91,8 +91,7 @@ public abstract class ResourceRepository {
             IAbstractResource[] resources = mResourceFolder.listMembers();
 
             for (IAbstractResource res : resources) {
-                if (res instanceof TestFolderWrapper) {
-                    TestFolderWrapper folder = (TestFolderWrapper)res;
+                if (res instanceof TestFolderWrapper folder) {
                     ResourceFolder resFolder = processFolder(folder);
 
                     if (resFolder != null) {
@@ -100,8 +99,7 @@ public abstract class ResourceRepository {
                         IAbstractResource[] files = folder.listMembers();
 
                         for (IAbstractResource fileRes : files) {
-                            if (fileRes instanceof TestFileWrapper) {
-                                TestFileWrapper file = (TestFileWrapper) fileRes;
+                            if (fileRes instanceof TestFileWrapper file) {
 
                                 resFolder.processFile(file, ResourceDeltaKind.ADDED, context);
                             }
@@ -189,39 +187,35 @@ public abstract class ResourceRepository {
                     // Pick initial size for the maps. Also change the load factor to 1.0
                     // to avoid rehashing the whole table when we (as expected) get near
                     // the known rough size of each resource type map.
-                    int size;
-                    switch (type) {
+                    int size = switch (type) {
                         // Based on counts in API 16. Going back to API 10, the counts
                         // are roughly 25-50% smaller (e.g. compared to the top 5 types below
                         // the fractions are 1107 vs 1734, 831 vs 1508, 895 vs 1255,
                         // 733 vs 1064 and 171 vs 783.
-                        case PUBLIC:           size = 1734; break;
-                        case DRAWABLE:         size = 1508; break;
-                        case STRING:           size = 1255; break;
-                        case ATTR:             size = 1064; break;
-                        case STYLE:             size = 783; break;
-                        case ID:                size = 347; break;
-                        case STYLEABLE:
-                            size = 210;
-                            break;
-                        case LAYOUT:            size = 187; break;
-                        case COLOR:             size = 120; break;
-                        case ANIM:               size = 95; break;
-                        case DIMEN:              size = 81; break;
-                        case BOOL:               size = 54; break;
-                        case INTEGER:            size = 52; break;
-                        case ARRAY:              size = 51; break;
-                        case PLURALS:            size = 20; break;
-                        case XML:                size = 14; break;
-                        case INTERPOLATOR :      size = 13; break;
-                        case ANIMATOR:            size = 8; break;
-                        case RAW:                 size = 4; break;
-                        case MENU:                size = 2; break;
-                        case MIPMAP:              size = 2; break;
-                        case FRACTION:            size = 1; break;
-                        default:
-                            size = 2;
-                    }
+                        case PUBLIC -> 1734;
+                        case DRAWABLE -> 1508;
+                        case STRING -> 1255;
+                        case ATTR -> 1064;
+                        case STYLE -> 783;
+                        case ID -> 347;
+                        case STYLEABLE -> 210;
+                        case LAYOUT -> 187;
+                        case COLOR -> 120;
+                        case ANIM -> 95;
+                        case DIMEN -> 81;
+                        case BOOL -> 54;
+                        case INTEGER -> 52;
+                        case ARRAY -> 51;
+                        case PLURALS -> 20;
+                        case XML -> 14;
+                        case INTERPOLATOR -> 13;
+                        case ANIMATOR -> 8;
+                        case RAW -> 4;
+                        case MENU -> 2;
+                        case MIPMAP -> 2;
+                        case FRACTION -> 1;
+                        default -> 2;
+                    };
                     map = new HashMap<>(size, 1.0f);
                 } else {
                     map = new HashMap<>();
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
index c510306259..b0689da390 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
@@ -86,7 +86,7 @@ import static org.junit.Assert.fail;
  */
 public abstract class BridgeClient {
 
-    protected static final String PLATFORM_DIR;
+    private static final String PLATFORM_DIR;
     private static final String ANDROID_HOST_OUT_DIR_PROPERTY = "android_host_out.dir";
     private static final String NATIVE_LIB_PATH_PROPERTY = "native.lib.path";
     private static final String FONT_DIR_PROPERTY = "font.dir";
@@ -105,7 +105,7 @@ public abstract class BridgeClient {
                     + "android:layout_height=\"match_parent\"> </FrameLayout>";
     protected static Bridge sBridge;
     /** List of log messages generated by a render call. It can be used to find specific errors */
-    protected static ArrayList<String> sRenderMessages = Lists.newArrayList();
+    protected static final ArrayList<String> sRenderMessages = Lists.newArrayList();
     private static ILayoutLog sLayoutLibLog;
     private static FrameworkResources sFrameworkRepo;
     private static ResourceRepository sProjectResources;
@@ -155,7 +155,7 @@ public abstract class BridgeClient {
         init(themeName);
     }
 
-    public BridgeClient() {
+    protected BridgeClient() {
         init("AppTheme");
     }
 
@@ -391,7 +391,7 @@ public abstract class BridgeClient {
         sBridge = null;
     }
 
-    protected static ILayoutLog getLayoutLog() {
+    private static ILayoutLog getLayoutLog() {
         if (sLayoutLibLog == null) {
             sLayoutLibLog = new ILayoutLog() {
                 @Override
@@ -499,27 +499,27 @@ public abstract class BridgeClient {
 
     public abstract String getAppTestDir();
 
-    public abstract String getAppTestRes();
+    protected abstract String getAppTestRes();
 
-    public abstract String getAppResources();
+    protected abstract String getAppResources();
 
-    public abstract String getAppGoldenDir();
+    protected abstract String getAppGoldenDir();
 
-    public abstract String getAppTestAsset();
+    protected abstract String getAppTestAsset();
 
-    public abstract String getAppClassesLocation();
+    protected abstract String getAppClassesLocation();
 
-    protected void init(String themeName) {
+    private void init(String themeName) {
         mPackageName = "NOT_INITIALIZED";
         mThemeName = themeName;
         initProjectResources();
     }
 
-    public void setPackageName(String packageName) {
+    protected void setPackageName(String packageName) {
         mPackageName = packageName;
     }
 
-    public void initProjectResources() {
+    private void initProjectResources() {
         String TEST_RESOURCE_FOLDER = getAppTestRes();
         sProjectResources =
                 new ResourceRepository(new TestFolderWrapper(TEST_RESOURCE_FOLDER), false) {
@@ -599,7 +599,7 @@ public abstract class BridgeClient {
      */
     @Nullable
     protected RenderResult renderAndVerify(SessionParams params, String goldenFileName,
-            long frameTimeNanos) throws ClassNotFoundException {
+            long frameTimeNanos) {
         RenderResult result = render(sBridge, params, frameTimeNanos);
         assertNotNull(result.getImage());
         verify(goldenFileName, result.getImage());
@@ -612,8 +612,7 @@ public abstract class BridgeClient {
      * exceptions and matches the provided image.
      */
     @Nullable
-    protected RenderResult renderAndVerify(SessionParams params, String goldenFileName)
-            throws ClassNotFoundException {
+    protected RenderResult renderAndVerify(SessionParams params, String goldenFileName) {
         return renderAndVerify(params, goldenFileName, TimeUnit.SECONDS.toNanos(2));
     }
 
@@ -626,14 +625,12 @@ public abstract class BridgeClient {
     }
 
     @NonNull
-    protected LayoutPullParser createParserFromPath(String layoutPath)
-            throws FileNotFoundException {
+    protected LayoutPullParser createParserFromPath(String layoutPath) {
         return LayoutPullParser.createFromPath(getAppResources() + "/layout/" + layoutPath);
     }
 
     @NonNull
-    protected LayoutPullParser createParserFromString(String layoutStr)
-            throws FileNotFoundException {
+    private LayoutPullParser createParserFromString(String layoutStr) {
         return LayoutPullParser.createFromString(layoutStr);
     }
 
@@ -653,7 +650,7 @@ public abstract class BridgeClient {
      * doesn't throw any exceptions and matches the provided image.
      */
     @Nullable
-    protected RenderResult renderAndVerify(String layoutFileName, String goldenFileName,
+    private RenderResult renderAndVerify(String layoutFileName, String goldenFileName,
             ConfigGenerator deviceConfig, boolean decoration) throws ClassNotFoundException,
             FileNotFoundException {
         SessionParams params = createSessionParams(layoutFileName, deviceConfig);
@@ -664,10 +661,10 @@ public abstract class BridgeClient {
     }
 
     protected SessionParams createSessionParams(String layoutFileName, ConfigGenerator deviceConfig)
-            throws ClassNotFoundException, FileNotFoundException {
+            throws ClassNotFoundException {
         // Create the layout pull parser.
 
-        LayoutPullParser parser = null;
+        LayoutPullParser parser;
         if (layoutFileName != null) {
             parser = createParserFromPath(layoutFileName);
         } else {
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/RenderResult.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/RenderResult.java
index 989d146bc1..35c9383118 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/RenderResult.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/RenderResult.java
@@ -32,7 +32,7 @@ public class RenderResult {
     private final List<ViewInfo> mRootViews;
     private final List<ViewInfo> mSystemViews;
     private final Result mRenderResult;
-    private BufferedImage mImage;
+    private final BufferedImage mImage;
 
     private RenderResult(@Nullable Result result, @Nullable List<ViewInfo> systemViewInfoList,
             @Nullable List<ViewInfo> rootViewInfoList, @Nullable BufferedImage image) {
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/ConfigGenerator.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/ConfigGenerator.java
index 684cf12c4e..76ddd29caf 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/ConfigGenerator.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/ConfigGenerator.java
@@ -230,11 +230,8 @@ public class ConfigGenerator {
                         // Integer.decode cannot handle "ffffffff", see JDK issue 6624867
                         int i = (int) (long) Long.decode(value);
                         assert attr != null;
-                        Map<String, Integer> attributeMap = map.get(attr);
-                        if (attributeMap == null) {
-                            attributeMap = Maps.newHashMap();
-                            map.put(attr, attributeMap);
-                        }
+                        Map<String, Integer> attributeMap =
+                                map.computeIfAbsent(attr, k -> Maps.newHashMap());
                         attributeMap.put(name, i);
                     }
                 } else if (eventType == XmlPullParser.END_TAG) {
@@ -244,9 +241,7 @@ public class ConfigGenerator {
                 }
                 eventType = xmlPullParser.next();
             }
-        } catch (XmlPullParserException e) {
-            e.printStackTrace();
-        } catch (IOException e) {
+        } catch (XmlPullParserException | IOException e) {
             e.printStackTrace();
         }
         return map;
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/LayoutlibBridgeClientCallback.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/LayoutlibBridgeClientCallback.java
index b6663a170c..f190e71b79 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/LayoutlibBridgeClientCallback.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/setup/LayoutlibBridgeClientCallback.java
@@ -55,7 +55,7 @@ public class LayoutlibBridgeClientCallback extends LayoutlibCallback {
     private final ActionBarCallback mActionBarCallback = new ActionBarCallback();
     private final ClassLoader mModuleClassLoader;
     private String mAdaptiveIconMaskPath;
-    private String mPackageName;
+    private final String mPackageName;
 
     public LayoutlibBridgeClientCallback(ILogger logger, ClassLoader classLoader,
             String packageName) {
@@ -124,14 +124,6 @@ public class LayoutlibBridgeClientCallback extends LayoutlibCallback {
         }
     }
 
-    @Override
-    public Object getAdapterItemValue(ResourceReference adapterView, Object adapterCookie,
-            ResourceReference itemRef, int fullPosition, int positionPerType,
-            int fullParentPosition, int parentPositionPerType, ResourceReference viewRef,
-            ViewAttribute viewAttribute, Object defaultValue) {
-        return null;
-    }
-
     @Override
     public AdapterBinding getAdapterBinding(Object viewObject, Map<String, String> attributes) {
         return null;
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ImageUtils.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ImageUtils.java
index a8adf95d1a..471a3aa480 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ImageUtils.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ImageUtils.java
@@ -75,7 +75,7 @@ public class ImageUtils {
         }
     }
 
-    public static void assertImageSimilar(String relativePath, BufferedImage goldenImage,
+    private static void assertImageSimilar(String relativePath, BufferedImage goldenImage,
             BufferedImage image, double maxPercentDifferent) throws IOException {
         if (goldenImage.getType() != TYPE_INT_ARGB) {
             BufferedImage temp = new BufferedImage(goldenImage.getWidth(), goldenImage.getHeight(),
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ModuleClassLoader.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ModuleClassLoader.java
index d52fdcf9d4..0415e7f0ad 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ModuleClassLoader.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/ModuleClassLoader.java
@@ -28,7 +28,7 @@ import libcore.io.Streams;
  */
 public class ModuleClassLoader extends ClassLoader {
     private final Map<String, Class<?>> mClasses = new HashMap<>();
-    private String myModuleRoot;
+    private final String myModuleRoot;
 
     /**
      * @param moduleRoot The path to the module root
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
index c0e22d3619..e90a61a144 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/SessionParamsBuilder.java
@@ -26,6 +26,7 @@ import com.android.ide.common.rendering.api.ResourceReference;
 import com.android.ide.common.rendering.api.SessionParams;
 import com.android.ide.common.rendering.api.SessionParams.RenderingMode;
 import com.android.ide.common.resources.ResourceResolver;
+import com.android.ide.common.resources.ResourceValueMap;
 import com.android.ide.common.resources.configuration.FolderConfiguration;
 import com.android.ide.common.resources.deprecated.ResourceRepository;
 import com.android.layoutlib.bridge.android.RenderParamsFlags;
@@ -47,7 +48,6 @@ public class SessionParamsBuilder {
 
     private LayoutPullParser mLayoutParser;
     private RenderingMode mRenderingMode = RenderingMode.NORMAL;
-    private Object mProjectKey = null;
     private ConfigGenerator mConfigGenerator = ConfigGenerator.NEXUS_5;
     private ResourceRepository mFrameworkResources;
     private ResourceRepository mProjectResources;
@@ -58,13 +58,14 @@ public class SessionParamsBuilder {
     private int mMinSdk = 0;
     private int mSimulatedSdk = 0;
     private ILayoutLog mLayoutLog;
-    private Map<SessionParams.Key, Object> mFlags = new HashMap<>();
+    private final Map<SessionParams.Key, Object> mFlags = new HashMap<>();
     private AssetRepository mAssetRepository = null;
     private boolean mDecor = true;
     private IImageFactory mImageFactory = null;
     private boolean enableLayoutValidator = false;
     private boolean enableLayoutValidatorImageCheck = false;
     private boolean transparentBackground = false;
+    private Map<ResourceType, ResourceValueMap> mFrameworkOverlayResources;
 
     @NonNull
     public SessionParamsBuilder setParser(@NonNull LayoutPullParser layoutParser) {
@@ -148,7 +149,7 @@ public class SessionParamsBuilder {
     }
 
     @NonNull
-    public SessionParamsBuilder setFlag(@NonNull SessionParams.Key flag, Object value) {
+    public SessionParamsBuilder setFlag(@NonNull SessionParams.Key<?> flag, Object value) {
         mFlags.put(flag, value);
         return this;
     }
@@ -182,13 +183,20 @@ public class SessionParamsBuilder {
         this.enableLayoutValidatorImageCheck = true;
         return this;
     }
-    
+
     @NonNull
     public SessionParamsBuilder setTransparentBackground() {
         this.transparentBackground = true;
         return this;
     }
 
+    @NonNull
+    public SessionParamsBuilder setFrameworkOverlayResources(
+            Map<ResourceType, ResourceValueMap> resources) {
+        this.mFrameworkOverlayResources = resources;
+        return this;
+    }
+
     @NonNull
     public SessionParams build() {
         assert mFrameworkResources != null;
@@ -198,16 +206,22 @@ public class SessionParamsBuilder {
         assert mLayoutlibCallback != null;
 
         FolderConfiguration config = mConfigGenerator.getFolderConfig();
+        Map<ResourceType, ResourceValueMap> frameworkConfigResources =
+                mFrameworkResources.getConfiguredResources(config);
+        if (mFrameworkOverlayResources != null) {
+            mFrameworkOverlayResources.keySet().forEach(type ->
+                    frameworkConfigResources.get(type).putAll(mFrameworkOverlayResources.get(type)));
+        }
         ResourceResolver resourceResolver = ResourceResolver.create(
                 ImmutableMap.of(
-                        ResourceNamespace.ANDROID, mFrameworkResources.getConfiguredResources(config),
+                        ResourceNamespace.ANDROID, frameworkConfigResources,
                         ResourceNamespace.TODO(), mProjectResources.getConfiguredResources(config)),
                 new ResourceReference(
                         ResourceNamespace.fromBoolean(!isProjectTheme),
                         ResourceType.STYLE,
                         mThemeName));
 
-        SessionParams params = new SessionParams(mLayoutParser, mRenderingMode, mProjectKey /* for
+        SessionParams params = new SessionParams(mLayoutParser, mRenderingMode, null /* for
         caching */, mConfigGenerator.getHardwareConfig(), resourceResolver, mLayoutlibCallback,
                 mMinSdk, mTargetSdk, mLayoutLog, mSimulatedSdk);
         params.setFlag(RenderParamsFlags.FLAG_ENABLE_LAYOUT_VALIDATOR, enableLayoutValidator);
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/TestUtils.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/TestUtils.java
index 1df8e7978b..a3d6cb252c 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/TestUtils.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/TestUtils.java
@@ -22,7 +22,7 @@ public class TestUtils {
     public static void gc() {
         // See RuntimeUtil#gc in jlibs (http://jlibs.in/)
         Object obj = new Object();
-        WeakReference ref = new WeakReference<>(obj);
+        WeakReference<Object> ref = new WeakReference<>(obj);
         //noinspection UnusedAssignment
         obj = null;
         while (ref.get() != null) {
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/LongStatsCollector.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/LongStatsCollector.java
index ee98b4ba3b..aa1f229ef9 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/LongStatsCollector.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/LongStatsCollector.java
@@ -53,7 +53,7 @@ public class LongStatsCollector implements LongConsumer {
         Arrays.sort(buffer);
 
         int midPoint = size / 2;
-        median = (size % 2 == 0) ? (buffer[midPoint - 1] + buffer[midPoint]) / 2 : buffer[midPoint];
+        median = (size % 2 == 0) ? (buffer[midPoint - 1] + buffer[midPoint]) / 2. : buffer[midPoint];
 
         return new Stats(mAllValues.size(), mMin, mMax, median);
     }
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/TimedStatementResult.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/TimedStatementResult.java
index 59f90d2954..7b346a701f 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/TimedStatementResult.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/util/perf/TimedStatementResult.java
@@ -45,12 +45,15 @@ public class TimedStatementResult {
 
     @Override
     public String toString() {
-        return String.format(
-                "Warm up %d. Runs %d\n" + "Time:             %s ms (min: %s, max %s)\n" +
-                        "Calibration Time: %f ms\n" +
-                        "Calibrated Time:  %s units (min: %s, max %s)\n" +
-                        "Sampled %d times\n" +
-                        "   Memory used:  %d bytes (max %d)\n\n",
+        return String.format("""
+                        Warm up %d. Runs %d
+                        Time:             %s ms (min: %s, max %s)
+                        Calibration Time: %f ms
+                        Calibrated Time:  %s units (min: %s, max %s)
+                        Sampled %d times
+                           Memory used:  %d bytes (max %d)
+
+                        """,
                 mWarmUpIterations, mRuns,
                 mTimeStats.getMedian(), mTimeStats.getMin(), mTimeStats.getMax(),
                 mCalibrationTimeMs,
diff --git a/bridge/jarjar-rules.txt b/bridge/jarjar-rules.txt
index 3318faad1d..b30190708f 100644
--- a/bridge/jarjar-rules.txt
+++ b/bridge/jarjar-rules.txt
@@ -1 +1,3 @@
 rule com.google.protobuf.** com.android.layoutlib.protobuf.@1
+rule org.hamcrest.** com.android.layoutlib.hamcrest.@1
+rule org.jsoup.** com.android.layoutlib.jsoup.@1
diff --git a/bridge/resources/bars/v21/xhdpi/stat_sys_wifi_signal_4_fully.xml b/bridge/resources/bars/v21/anydpi/stat_sys_wifi_signal_4_fully.xml
similarity index 100%
rename from bridge/resources/bars/v21/xhdpi/stat_sys_wifi_signal_4_fully.xml
rename to bridge/resources/bars/v21/anydpi/stat_sys_wifi_signal_4_fully.xml
diff --git a/bridge/resources/bars/v28/xhdpi/stat_sys_wifi_signal_4_fully.xml b/bridge/resources/bars/v28/anydpi/stat_sys_wifi_signal_4_fully.xml
similarity index 100%
rename from bridge/resources/bars/v28/xhdpi/stat_sys_wifi_signal_4_fully.xml
rename to bridge/resources/bars/v28/anydpi/stat_sys_wifi_signal_4_fully.xml
diff --git a/bridge/resources/bars/v29/anydpi/ic_sysbar_back.xml b/bridge/resources/bars/v29/anydpi/ic_sysbar_back.xml
new file mode 100644
index 0000000000..4eb532f9b1
--- /dev/null
+++ b/bridge/resources/bars/v29/anydpi/ic_sysbar_back.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2018 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="20dp"
+    android:height="20dp"
+    android:autoMirrored="true"
+    android:viewportWidth="20"
+    android:viewportHeight="20">
+
+    <path
+        android:fillColor="#FFFFFFFF"
+        android:pathData="M15.5417 1.66669C15.1833 1.66669 14.8417 1.76669 14.5333 1.94169L3.21667 8.74169C2.775 9.00002 2.5 9.48335 2.5 10C2.5 10.5167 2.775 11 3.21667 11.2584L14.5333 18.05C14.8417 18.2334 15.1833 18.325 15.5417 18.325C16.625 18.325 17.5 17.45 17.5 16.3667V3.62502C17.5 2.54169 16.625 1.66669 15.5417 1.66669Z" />
+</vector>
\ No newline at end of file
diff --git a/bridge/resources/bars/v29/anydpi/ic_sysbar_back_quick_step.xml b/bridge/resources/bars/v29/anydpi/ic_sysbar_back_quick_step.xml
new file mode 100644
index 0000000000..4eb532f9b1
--- /dev/null
+++ b/bridge/resources/bars/v29/anydpi/ic_sysbar_back_quick_step.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2018 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="20dp"
+    android:height="20dp"
+    android:autoMirrored="true"
+    android:viewportWidth="20"
+    android:viewportHeight="20">
+
+    <path
+        android:fillColor="#FFFFFFFF"
+        android:pathData="M15.5417 1.66669C15.1833 1.66669 14.8417 1.76669 14.5333 1.94169L3.21667 8.74169C2.775 9.00002 2.5 9.48335 2.5 10C2.5 10.5167 2.775 11 3.21667 11.2584L14.5333 18.05C14.8417 18.2334 15.1833 18.325 15.5417 18.325C16.625 18.325 17.5 17.45 17.5 16.3667V3.62502C17.5 2.54169 16.625 1.66669 15.5417 1.66669Z" />
+</vector>
\ No newline at end of file
diff --git a/bridge/resources/bars/v29/anydpi/ic_sysbar_home.xml b/bridge/resources/bars/v29/anydpi/ic_sysbar_home.xml
new file mode 100644
index 0000000000..8cc20456dc
--- /dev/null
+++ b/bridge/resources/bars/v29/anydpi/ic_sysbar_home.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2018 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="20dp"
+    android:height="20dp"
+    android:viewportWidth="20"
+    android:viewportHeight="20">
+
+    <path
+        android:fillColor="#FFFFFFFF"
+        android:pathData="M10.0001 18.3334C5.40008 18.3334 1.66675 14.6 1.66675 10C1.66675 5.40002 5.40008 1.66669 10.0001 1.66669C14.6001 1.66669 18.3334 5.40002 18.3334 10C18.3334 14.6 14.6001 18.3334 10.0001 18.3334Z" />
+</vector>
\ No newline at end of file
diff --git a/bridge/resources/bars/v29/anydpi/ic_sysbar_home_quick_step.xml b/bridge/resources/bars/v29/anydpi/ic_sysbar_home_quick_step.xml
new file mode 100644
index 0000000000..629fe0bb1f
--- /dev/null
+++ b/bridge/resources/bars/v29/anydpi/ic_sysbar_home_quick_step.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2018 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+     android:width="28dp"
+     android:height="28dp"
+     android:viewportWidth="28"
+     android:viewportHeight="28">
+
+     <path
+         android:fillColor="#FFFFFFFF"
+          android:pathData="M23,19H5c-2.76,0-5-2.24-5-5l0,0c0-2.76,2.24-5,5-5h18c2.76,0,5,2.24,5,5l0,0C28,16.76,25.76,19,23,19z" />
+</vector>
\ No newline at end of file
diff --git a/bridge/resources/bars/v29/anydpi/ic_sysbar_recent.xml b/bridge/resources/bars/v29/anydpi/ic_sysbar_recent.xml
new file mode 100644
index 0000000000..5bf357ddad
--- /dev/null
+++ b/bridge/resources/bars/v29/anydpi/ic_sysbar_recent.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2018 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="20dp"
+    android:height="20dp"
+    android:viewportWidth="20"
+    android:viewportHeight="20">
+
+    <path
+        android:fillColor="#FFFFFFFF"
+        android:pathData="M4.47634 2.5H15.5241C16.6164 2.5 17.5002 3.38382 17.5002 4.4761V15.5239C17.5002 16.6162 16.6164 17.5 15.5241 17.5H4.47634C3.38407 17.5 2.50024 16.6162 2.50024 15.5239V4.4761C2.50024 3.38382 3.38407 2.5 4.47634 2.5Z" />
+</vector>
\ No newline at end of file
diff --git a/bridge/src/android/app/ActivityManager_Delegate.java b/bridge/src/android/app/ActivityManager_Delegate.java
index 72004a2b95..4b112a31f1 100644
--- a/bridge/src/android/app/ActivityManager_Delegate.java
+++ b/bridge/src/android/app/ActivityManager_Delegate.java
@@ -16,41 +16,8 @@
 
 package android.app;
 
-import com.android.internal.os.IResultReceiver;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
-import android.app.ActivityManager.MemoryInfo;
-import android.app.ActivityManager.PendingIntentInfo;
-import android.app.ActivityManager.ProcessErrorStateInfo;
-import android.app.ActivityManager.RunningAppProcessInfo;
-import android.app.ActivityManager.RunningServiceInfo;
-import android.app.ActivityManager.RunningTaskInfo;
-import android.app.ActivityTaskManager.RootTaskInfo;
-import android.content.ComponentName;
-import android.content.IIntentReceiver;
-import android.content.IIntentSender;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.content.LocusId;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.IPackageDataObserver;
-import android.content.pm.ParceledListSlice;
-import android.content.pm.UserInfo;
-import android.content.res.Configuration;
-import android.graphics.Rect;
-import android.net.Uri;
-import android.os.Bundle;
-import android.os.Debug;
-import android.os.IBinder;
-import android.os.IProgressListener;
-import android.os.ParcelFileDescriptor;
-import android.os.RemoteCallback;
-import android.os.RemoteException;
-import android.os.StrictMode.ViolationInfo;
-import android.os.WorkSource;
-
-import java.util.List;
-
 public class ActivityManager_Delegate {
     private static final IActivityManager sStubManager = new IActivityManager.Default();
 
diff --git a/bridge/src/android/app/Application_Delegate.java b/bridge/src/android/app/Application_Delegate.java
index 1f1d90adde..5ce089e8b1 100644
--- a/bridge/src/android/app/Application_Delegate.java
+++ b/bridge/src/android/app/Application_Delegate.java
@@ -16,10 +16,17 @@
 
 package android.app;
 
+import android.content.pm.ApplicationInfo;
 import android.content.res.Resources;
 
+import static com.android.layoutlib.bridge.impl.RenderAction.getCurrentContext;
+
 public class Application_Delegate {
     public static Resources getResources(Application app) {
         return Resources.getSystem();
     }
+
+    public static ApplicationInfo getApplicationInfo(Application app) {
+        return getCurrentContext().getApplicationInfo();
+    }
 }
diff --git a/bridge/src/android/app/Fragment_Delegate.java b/bridge/src/android/app/Fragment_Delegate.java
index 8b216f05c3..bc21b7d2c2 100644
--- a/bridge/src/android/app/Fragment_Delegate.java
+++ b/bridge/src/android/app/Fragment_Delegate.java
@@ -59,8 +59,7 @@ public class Fragment_Delegate {
     @LayoutlibDelegate
     /*package*/ static Fragment instantiate(Context context, String fname, Bundle args) {
         try {
-            if (context instanceof BridgeContext) {
-                BridgeContext bc = (BridgeContext) context;
+            if (context instanceof BridgeContext bc) {
                 Fragment f = (Fragment) bc.getLayoutlibCallback().loadView(fname,
                         new Class[0], new Object[0]);
 
diff --git a/bridge/src/android/content/res/BridgeAssetManager.java b/bridge/src/android/content/res/BridgeAssetManager.java
index c9b7095ee8..f370fc2074 100644
--- a/bridge/src/android/content/res/BridgeAssetManager.java
+++ b/bridge/src/android/content/res/BridgeAssetManager.java
@@ -81,6 +81,6 @@ public class BridgeAssetManager extends AssetManager {
         return getAssetRepository().openNonAsset(cookie, fileName, accessMode);
     }
 
-    public BridgeAssetManager() {
+    private BridgeAssetManager() {
     }
 }
diff --git a/bridge/src/android/content/res/BridgeTypedArray.java b/bridge/src/android/content/res/BridgeTypedArray.java
index ae6f538178..bba31ad126 100644
--- a/bridge/src/android/content/res/BridgeTypedArray.java
+++ b/bridge/src/android/content/res/BridgeTypedArray.java
@@ -739,8 +739,7 @@ public final class BridgeTypedArray extends TypedArray {
             return null;
         }
         ResourceValue resVal = mResourceData[index];
-        if (resVal instanceof ArrayResourceValue) {
-            ArrayResourceValue array = (ArrayResourceValue) resVal;
+        if (resVal instanceof ArrayResourceValue array) {
             int count = array.getElementCount();
             return count >= 0 ?
                     Resources_Delegate.resolveValues(mBridgeResources, array) :
diff --git a/bridge/src/android/content/res/Resources_Delegate.java b/bridge/src/android/content/res/Resources_Delegate.java
index 4eb6bddeed..fd6381c893 100644
--- a/bridge/src/android/content/res/Resources_Delegate.java
+++ b/bridge/src/android/content/res/Resources_Delegate.java
@@ -70,13 +70,13 @@ import static com.android.ide.common.rendering.api.AndroidConstants.APP_PREFIX;
 import static com.android.ide.common.rendering.api.AndroidConstants.PREFIX_RESOURCE_REF;
 
 public class Resources_Delegate {
-    private static WeakHashMap<Resources, LayoutlibCallback> sLayoutlibCallbacks =
+    private static final WeakHashMap<Resources, LayoutlibCallback> sLayoutlibCallbacks =
             new WeakHashMap<>();
-    private static WeakHashMap<Resources, BridgeContext> sContexts = new WeakHashMap<>();
+    private static final WeakHashMap<Resources, BridgeContext> sContexts = new WeakHashMap<>();
 
     // TODO: This cache is cleared every time a render session is disposed. Look into making this
     // more long lived.
-    private static LruCache<String, Drawable.ConstantState> sDrawableCache = new LruCache<>(50);
+    private static final LruCache<String, Drawable.ConstantState> sDrawableCache = new LruCache<>(50);
 
     public static Resources initSystem(@NonNull BridgeContext context,
             @NonNull AssetManager assets,
@@ -270,11 +270,9 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    return v;
-                }
+            String v = resValue.getValue();
+            if (v != null) {
+                return v;
             }
         }
 
@@ -289,11 +287,9 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    return v;
-                }
+            String v = resValue.getValue();
+            if (v != null) {
+                return v;
             }
         }
 
@@ -311,8 +307,7 @@ public class Resources_Delegate {
             // Error already logged by getArrayResourceValue.
             return new CharSequence[0];
         }
-        if (resValue instanceof ArrayResourceValue) {
-            ArrayResourceValue arrayValue = (ArrayResourceValue) resValue;
+        if (resValue instanceof ArrayResourceValue arrayValue) {
             return resolveValues(resources, arrayValue);
         }
         RenderResources renderResources = getContext(resources).getRenderResources();
@@ -326,8 +321,7 @@ public class Resources_Delegate {
             // Error already logged by getArrayResourceValue.
             return new String[0];
         }
-        if (resValue instanceof ArrayResourceValue) {
-            ArrayResourceValue arv = (ArrayResourceValue) resValue;
+        if (resValue instanceof ArrayResourceValue arv) {
             return resolveValues(resources, arv);
         }
         return new String[] { resolveReference(resources, resValue) };
@@ -356,8 +350,7 @@ public class Resources_Delegate {
             // Error already logged by getArrayResourceValue.
             return new int[0];
         }
-        if (rv instanceof ArrayResourceValue) {
-            ArrayResourceValue resValue = (ArrayResourceValue) rv;
+        if (rv instanceof ArrayResourceValue resValue) {
             int n = resValue.getElementCount();
             int[] values = new int[n];
             for (int i = 0; i < n; i++) {
@@ -429,23 +422,21 @@ public class Resources_Delegate {
             ResourceValue resValue = v.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                final ResourceType type = resValue.getResourceType();
-                if (type != ResourceType.ARRAY) {
-                    Bridge.getLog().error(ILayoutLog.TAG_RESOURCES_RESOLVE,
-                            String.format(
-                                    "Resource with id 0x%1$X is not an array resource, but %2$s",
-                                    id, type == null ? "null" : type.getDisplayName()),
-                            null, null);
-                    return null;
-                }
-                if (!(resValue instanceof ArrayResourceValue)) {
-                    Bridge.getLog().warning(ILayoutLog.TAG_UNSUPPORTED,
-                            "Obtaining resource arrays via getTextArray, getStringArray or getIntArray is not fully supported in this version of the IDE.",
-                            null, null);
-                }
-                return resValue;
+            final ResourceType type = resValue.getResourceType();
+            if (type != ResourceType.ARRAY) {
+                Bridge.getLog().error(ILayoutLog.TAG_RESOURCES_RESOLVE,
+                        String.format(
+                                "Resource with id 0x%1$X is not an array resource, but %2$s",
+                                id, type == null ? "null" : type.getDisplayName()),
+                        null, null);
+                return null;
+            }
+            if (!(resValue instanceof ArrayResourceValue)) {
+                Bridge.getLog().warning(ILayoutLog.TAG_UNSUPPORTED,
+                        "Obtaining resource arrays via getTextArray, getStringArray or getIntArray is not fully supported in this version of the IDE.",
+                        null, null);
             }
+            return resValue;
         }
 
         // id was not found or not resolved. Throw a NotFoundException.
@@ -549,11 +540,10 @@ public class Resources_Delegate {
         RenderResources renderResources = context.getRenderResources();
         ResourceValue value = renderResources.getResolvedResource(reference);
 
-        if (!(value instanceof ArrayResourceValue)) {
+        if (!(value instanceof ArrayResourceValue arrayValue)) {
             throw new NotFoundException("Array resource ID #0x" + Integer.toHexString(id));
         }
 
-        ArrayResourceValue arrayValue = (ArrayResourceValue) value;
         int length = arrayValue.getElementCount();
         ResourceNamespace namespace = arrayValue.getNamespace();
         BridgeTypedArray typedArray = newTypeArray(resources, length);
@@ -584,21 +574,19 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    if (v.equals(BridgeConstants.MATCH_PARENT) ||
-                            v.equals(BridgeConstants.FILL_PARENT)) {
-                        return LayoutParams.MATCH_PARENT;
-                    } else if (v.equals(BridgeConstants.WRAP_CONTENT)) {
-                        return LayoutParams.WRAP_CONTENT;
-                    }
-                    TypedValue tmpValue = new TypedValue();
-                    if (ResourceHelper.parseFloatAttribute(
-                            value.first, v, tmpValue, true /*requireUnit*/) &&
-                            tmpValue.type == TypedValue.TYPE_DIMENSION) {
-                        return tmpValue.getDimension(resources.getDisplayMetrics());
-                    }
+            String v = resValue.getValue();
+            if (v != null) {
+                if (v.equals(BridgeConstants.MATCH_PARENT) ||
+                        v.equals(BridgeConstants.FILL_PARENT)) {
+                    return LayoutParams.MATCH_PARENT;
+                } else if (v.equals(BridgeConstants.WRAP_CONTENT)) {
+                    return LayoutParams.WRAP_CONTENT;
+                }
+                TypedValue tmpValue = new TypedValue();
+                if (ResourceHelper.parseFloatAttribute(
+                        value.first, v, tmpValue, true /*requireUnit*/) &&
+                        tmpValue.type == TypedValue.TYPE_DIMENSION) {
+                    return tmpValue.getDimension(resources.getDisplayMetrics());
                 }
             }
         }
@@ -618,16 +606,14 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    TypedValue tmpValue = new TypedValue();
-                    if (ResourceHelper.parseFloatAttribute(
-                            value.first, v, tmpValue, true /*requireUnit*/) &&
-                            tmpValue.type == TypedValue.TYPE_DIMENSION) {
-                        return TypedValue.complexToDimensionPixelOffset(tmpValue.data,
-                                resources.getDisplayMetrics());
-                    }
+            String v = resValue.getValue();
+            if (v != null) {
+                TypedValue tmpValue = new TypedValue();
+                if (ResourceHelper.parseFloatAttribute(
+                        value.first, v, tmpValue, true /*requireUnit*/) &&
+                        tmpValue.type == TypedValue.TYPE_DIMENSION) {
+                    return TypedValue.complexToDimensionPixelOffset(tmpValue.data,
+                            resources.getDisplayMetrics());
                 }
             }
         }
@@ -647,16 +633,14 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    TypedValue tmpValue = new TypedValue();
-                    if (ResourceHelper.parseFloatAttribute(
-                            value.first, v, tmpValue, true /*requireUnit*/) &&
-                            tmpValue.type == TypedValue.TYPE_DIMENSION) {
-                        return TypedValue.complexToDimensionPixelSize(tmpValue.data,
-                                resources.getDisplayMetrics());
-                    }
+            String v = resValue.getValue();
+            if (v != null) {
+                TypedValue tmpValue = new TypedValue();
+                if (ResourceHelper.parseFloatAttribute(
+                        value.first, v, tmpValue, true /*requireUnit*/) &&
+                        tmpValue.type == TypedValue.TYPE_DIMENSION) {
+                    return TypedValue.complexToDimensionPixelSize(tmpValue.data,
+                            resources.getDisplayMetrics());
                 }
             }
         }
@@ -676,14 +660,12 @@ public class Resources_Delegate {
             ResourceValue resValue = value.second;
 
             assert resValue != null;
-            if (resValue != null) {
-                String v = resValue.getValue();
-                if (v != null) {
-                    try {
-                        return getInt(v);
-                    } catch (NumberFormatException e) {
-                        // return exception below
-                    }
+            String v = resValue.getValue();
+            if (v != null) {
+                try {
+                    return getInt(v);
+                } catch (NumberFormatException e) {
+                    // return exception below
                 }
             }
         }
@@ -827,8 +809,7 @@ public class Resources_Delegate {
         Pair<String, ResourceValue> value = getResourceValue(resources, id);
 
         if (value != null) {
-            if (value.second instanceof PluralsResourceValue) {
-                PluralsResourceValue pluralsResourceValue = (PluralsResourceValue) value.second;
+            if (value.second instanceof PluralsResourceValue pluralsResourceValue) {
                 PluralRules pluralRules = PluralRules.forLocale(resources.getConfiguration().getLocales()
                         .get(0));
                 String strValue = pluralsResourceValue.getValue(pluralRules.select(quantity));
@@ -977,7 +958,7 @@ public class Resources_Delegate {
             int assetCookie, String type) throws NotFoundException {
         // even though we know the XML file to load directly, we still need to resolve the
         // id so that we can know if it's a platform or project resource.
-        // (mPlatformResouceFlag will get the result and will be used later).
+        // (mPlatformResourceFlag will get the result and will be used later).
         Pair<String, ResourceValue> result = getResourceValue(resources, id);
 
         ResourceNamespace layoutNamespace;
diff --git a/bridge/src/android/content/res/Resources_Theme_Delegate.java b/bridge/src/android/content/res/Resources_Theme_Delegate.java
index 4740fac3c2..3459df94d2 100644
--- a/bridge/src/android/content/res/Resources_Theme_Delegate.java
+++ b/bridge/src/android/content/res/Resources_Theme_Delegate.java
@@ -21,7 +21,6 @@ import com.android.ide.common.rendering.api.StyleResourceValue;
 import com.android.layoutlib.bridge.android.BridgeContext;
 import com.android.layoutlib.bridge.impl.DelegateManager;
 import com.android.layoutlib.bridge.impl.RenderSessionImpl;
-import com.android.resources.ResourceType;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
 import android.annotation.Nullable;
@@ -43,7 +42,7 @@ public class Resources_Theme_Delegate {
     // ---- delegate manager ----
 
     private static final DelegateManager<Resources_Theme_Delegate> sManager =
-            new DelegateManager<Resources_Theme_Delegate>(Resources_Theme_Delegate.class);
+            new DelegateManager<>(Resources_Theme_Delegate.class);
 
     public static DelegateManager<Resources_Theme_Delegate> getDelegateManager() {
         return sManager;
diff --git a/bridge/src/android/graphics/ImageDecoder_Delegate.java b/bridge/src/android/graphics/ImageDecoder_Delegate.java
index b97803bf60..94a84f0125 100644
--- a/bridge/src/android/graphics/ImageDecoder_Delegate.java
+++ b/bridge/src/android/graphics/ImageDecoder_Delegate.java
@@ -38,10 +38,9 @@ public class ImageDecoder_Delegate {
     @LayoutlibDelegate
     /*package*/ static Bitmap decodeBitmapImpl(@NonNull Source src,
             @NonNull OnHeaderDecodedListener listener) throws IOException {
-        if (src instanceof ResourceSource) {
+        if (src instanceof ResourceSource source) {
             // Bypass ImageDecoder for ResourceSource as it goes through the native AssetManager
             // which is not supported in layoutlib.
-            ResourceSource source = (ResourceSource) src;
             return BitmapFactory.decodeResource(source.mResources, source.mResId);
         }
         InputStream stream = src instanceof InputStreamSource ?
diff --git a/bridge/src/android/graphics/LayoutlibRenderer.java b/bridge/src/android/graphics/LayoutlibRenderer.java
deleted file mode 100644
index e96c790261..0000000000
--- a/bridge/src/android/graphics/LayoutlibRenderer.java
+++ /dev/null
@@ -1,48 +0,0 @@
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
-package android.graphics;
-
-import android.annotation.Nullable;
-
-public class LayoutlibRenderer extends HardwareRenderer {
-
-    private float scaleX = 1.0f;
-    private float scaleY = 1.0f;
-
-    /**
-     * We are overriding this method in order to call {@link Canvas#enableZ} (for shadows) and set
-     * the scale
-     */
-    @Override
-    public void setContentRoot(@Nullable RenderNode content) {
-        RecordingCanvas canvas = mRootNode.beginRecording();
-        canvas.scale(scaleX, scaleY);
-        canvas.enableZ();
-        // This way we clear the native image buffer before drawing
-        canvas.drawColor(0, BlendMode.CLEAR);
-        if (content != null) {
-            canvas.drawRenderNode(content);
-        }
-        canvas.disableZ();
-        mRootNode.endRecording();
-    }
-
-    public void setScale(float scaleX, float scaleY) {
-        this.scaleX = scaleX;
-        this.scaleY = scaleY;
-    }
-}
diff --git a/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java b/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
index 3c090e0e5a..faf35321cb 100644
--- a/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
+++ b/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
@@ -18,10 +18,10 @@ package android.graphics.drawable;
 
 import com.android.internal.R;
 import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.layoutlib.bridge.impl.RenderAction;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
 import android.content.res.Resources;
-import android.content.res.Resources_Delegate;
 import android.graphics.Canvas;
 
 public class AdaptiveIconDrawable_Delegate {
@@ -43,7 +43,7 @@ public class AdaptiveIconDrawable_Delegate {
     @LayoutlibDelegate
     public static void draw(AdaptiveIconDrawable thisDrawable, Canvas canvas) {
         Resources res = Resources.getSystem();
-        BridgeContext context = Resources_Delegate.getContext(res);
+        BridgeContext context = RenderAction.getCurrentContext();
         if (context.useThemedIcon() && thisDrawable.getMonochrome() != null) {
             AdaptiveIconDrawable themedIcon =
                     createThemedVersionFromMonochrome(thisDrawable.getMonochrome(), res);
diff --git a/bridge/src/android/graphics/drawable/DrawableInflater_Delegate.java b/bridge/src/android/graphics/drawable/DrawableInflater_Delegate.java
index 5d2d03bae1..e9fec803d1 100644
--- a/bridge/src/android/graphics/drawable/DrawableInflater_Delegate.java
+++ b/bridge/src/android/graphics/drawable/DrawableInflater_Delegate.java
@@ -16,9 +16,9 @@
 
 package android.graphics.drawable;
 
+import com.android.layoutlib.bridge.impl.RenderAction;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
-import android.content.res.Resources_Delegate;
 import android.util.LruCache;
 import android.view.InflateException;
 
@@ -41,32 +41,21 @@ public class DrawableInflater_Delegate {
                 constructor = CONSTRUCTOR_MAP.get(className);
                 if (constructor == null) {
                     final Class<? extends Drawable> clazz =
-                            Resources_Delegate.getLayoutlibCallback(thisInflater.mRes)
+                            RenderAction.getCurrentContext().getLayoutlibCallback()
                                     .findClass(className).asSubclass(Drawable.class);
                     constructor = clazz.getConstructor();
                     CONSTRUCTOR_MAP.put(className, constructor);
                 }
             }
             return constructor.newInstance();
-        } catch (NoSuchMethodException e) {
-            final InflateException ie = new InflateException("Error inflating class " + className);
-            ie.initCause(e);
-            throw ie;
         } catch (ClassCastException e) {
             // If loaded class is not a Drawable subclass.
-            final InflateException ie =
-                    new InflateException("Class is not a Drawable " + className);
-            ie.initCause(e);
-            throw ie;
+            throw new InflateException("Class is not a Drawable " + className, e);
         } catch (ClassNotFoundException e) {
             // If loadClass fails, we should propagate the exception.
-            final InflateException ie = new InflateException("Class not found " + className);
-            ie.initCause(e);
-            throw ie;
+            throw new InflateException("Class not found " + className, e);
         } catch (Exception e) {
-            final InflateException ie = new InflateException("Error inflating class " + className);
-            ie.initCause(e);
-            throw ie;
+            throw new InflateException("Error inflating class " + className, e);
         }
     }
 
diff --git a/bridge/src/android/graphics/fonts/SystemFonts_Delegate.java b/bridge/src/android/graphics/fonts/SystemFonts_Delegate.java
index ff2d64c708..167356b8bd 100644
--- a/bridge/src/android/graphics/fonts/SystemFonts_Delegate.java
+++ b/bridge/src/android/graphics/fonts/SystemFonts_Delegate.java
@@ -19,7 +19,6 @@ package android.graphics.fonts;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
 import android.annotation.NonNull;
-import android.annotation.Nullable;
 import android.text.FontConfig;
 import android.util.Log;
 
@@ -62,8 +61,10 @@ public class SystemFonts_Delegate {
             long lastModifiedDate,
             int configVersion) {
         sIsTypefaceInitialized = true;
+        int lastSeparator = fontsXml.lastIndexOf('/');
+        String fileName = fontsXml.substring(lastSeparator + 1);
         return SystemFonts.getSystemFontConfigInternal_Original(
-            sFontLocation + "fonts.xml", sFontLocation, null, null, updatableFontMap,
+            sFontLocation + fileName, sFontLocation, null, null, updatableFontMap,
             lastModifiedDate, configVersion);
     }
 
diff --git a/bridge/src/android/os/HandlerThread_Delegate.java b/bridge/src/android/os/HandlerThread_Delegate.java
index 18faa5de4f..20ef57dcac 100644
--- a/bridge/src/android/os/HandlerThread_Delegate.java
+++ b/bridge/src/android/os/HandlerThread_Delegate.java
@@ -35,8 +35,7 @@ import java.util.Map;
  */
 public class HandlerThread_Delegate {
 
-    private static final Map<BridgeContext, List<HandlerThread>> sThreads =
-            new HashMap<BridgeContext, List<HandlerThread>>();
+    private static final Map<BridgeContext, List<HandlerThread>> sThreads = new HashMap<>();
 
     public static void cleanUp(BridgeContext context) {
         List<HandlerThread> list = sThreads.get(context);
@@ -56,12 +55,7 @@ public class HandlerThread_Delegate {
     /*package*/ static void run(HandlerThread theThread) {
         // record the thread so that it can be quit() on clean up.
         BridgeContext context = RenderAction.getCurrentContext();
-        List<HandlerThread> list = sThreads.get(context);
-        if (list == null) {
-            list = new ArrayList<HandlerThread>();
-            sThreads.put(context, list);
-        }
-
+        List<HandlerThread> list = sThreads.computeIfAbsent(context, k -> new ArrayList<>());
         list.add(theThread);
 
         // ---- START DEFAULT IMPLEMENTATION.
diff --git a/bridge/src/android/os/Handler_Delegate.java b/bridge/src/android/os/Handler_Delegate.java
index d8688afa9d..82dfc5c302 100644
--- a/bridge/src/android/os/Handler_Delegate.java
+++ b/bridge/src/android/os/Handler_Delegate.java
@@ -23,6 +23,8 @@ import com.android.layoutlib.bridge.util.HandlerMessageQueue;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 import com.android.tools.layoutlib.annotations.NotNull;
 
+import android.util.TimeUtils;
+
 import static com.android.layoutlib.bridge.impl.RenderAction.getCurrentContext;
 
 /**
@@ -84,15 +86,15 @@ public class Handler_Delegate {
      *
      * @return if there are more callbacks to execute
      */
-    public static boolean executeCallbacks() {
+    public static boolean executeCallbacks(long frameTimeNanos) {
         BridgeContext context = getCurrentContext();
         if (context == null) {
             return false;
         }
+        long frameTimeMs = frameTimeNanos / TimeUtils.NANOS_PER_MS;
         HandlerMessageQueue queue = context.getSessionInteractiveData().getHandlerMessageQueue();
-        long uptimeMillis = SystemClock_Delegate.uptimeMillis();
         Runnable r;
-        while ((r = queue.extractFirst(uptimeMillis)) != null) {
+        while ((r = queue.extractFirst(frameTimeMs)) != null) {
             executeSafely(r);
         }
         return queue.isNotEmpty();
@@ -102,8 +104,7 @@ public class Handler_Delegate {
         void sendMessageAtTime(Handler handler, Message msg, long uptimeMillis);
     }
 
-    private final static ThreadLocal<IHandlerCallback> sCallbacks =
-        new ThreadLocal<IHandlerCallback>();
+    private final static ThreadLocal<IHandlerCallback> sCallbacks = new ThreadLocal<>();
 
     public static void setCallback(IHandlerCallback callback) {
         sCallbacks.set(callback);
diff --git a/bridge/src/android/os/Looper_Accessor.java b/bridge/src/android/os/Looper_Accessor.java
index 09f3e47d7a..fdbaa03991 100644
--- a/bridge/src/android/os/Looper_Accessor.java
+++ b/bridge/src/android/os/Looper_Accessor.java
@@ -29,13 +29,8 @@ public class Looper_Accessor {
             Field sMainLooper = Looper.class.getDeclaredField("sMainLooper");
             sMainLooper.setAccessible(true);
             sMainLooper.set(null, null);
-        } catch (SecurityException e) {
-            catchReflectionException();
-        } catch (IllegalArgumentException e) {
-            catchReflectionException();
-        } catch (NoSuchFieldException e) {
-            catchReflectionException();
-        } catch (IllegalAccessException e) {
+        } catch (SecurityException | IllegalAccessException | NoSuchFieldException |
+                 IllegalArgumentException e) {
             catchReflectionException();
         }
 
diff --git a/bridge/src/android/permission/PermissionManager_Delegate.java b/bridge/src/android/permission/PermissionManager_Delegate.java
index 642b015a2b..65b0b9322a 100644
--- a/bridge/src/android/permission/PermissionManager_Delegate.java
+++ b/bridge/src/android/permission/PermissionManager_Delegate.java
@@ -26,4 +26,10 @@ public class PermissionManager_Delegate {
     public static int checkPermission(String permission, int pid, int uid, int deviceId) {
         return PackageManager.PERMISSION_GRANTED;
     }
+
+    @LayoutlibDelegate
+    public static int checkPermission(PermissionManager thisManager, String permissionName,
+            String packageName, String persistentDeviceId) {
+        return PackageManager.PERMISSION_GRANTED;
+    }
 }
diff --git a/bridge/src/android/preference/BridgePreferenceInflater.java b/bridge/src/android/preference/BridgePreferenceInflater.java
index c17313bcdf..683016c355 100644
--- a/bridge/src/android/preference/BridgePreferenceInflater.java
+++ b/bridge/src/android/preference/BridgePreferenceInflater.java
@@ -47,7 +47,7 @@ public class BridgePreferenceInflater extends PreferenceInflater {
             viewKey = ((BridgeXmlBlockParser) attrs).getViewCookie();
         }
 
-        Preference preference = null;
+        Preference preference;
         try {
             preference = super.createItem(name, prefix, attrs);
         } catch (ClassNotFoundException | InflateException exception) {
diff --git a/bridge/src/android/preference/Preference_Delegate.java b/bridge/src/android/preference/Preference_Delegate.java
index 2e44a7770a..724daae204 100644
--- a/bridge/src/android/preference/Preference_Delegate.java
+++ b/bridge/src/android/preference/Preference_Delegate.java
@@ -75,6 +75,6 @@ public class Preference_Delegate {
                 (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
         inflater.inflate(mLayoutResId, root, true);
 
-        return (ListView) root.findViewById(android.R.id.list);
+        return root.findViewById(android.R.id.list);
     }
 }
diff --git a/bridge/src/android/view/AttachInfo_Accessor.java b/bridge/src/android/view/AttachInfo_Accessor.java
index a406ba6580..645e6a1182 100644
--- a/bridge/src/android/view/AttachInfo_Accessor.java
+++ b/bridge/src/android/view/AttachInfo_Accessor.java
@@ -16,30 +16,58 @@
 
 package android.view;
 
+import com.android.layoutlib.bridge.impl.Layout;
+import com.android.layoutlib.bridge.util.InsetUtil;
+
 import android.content.Context;
+import android.graphics.Insets;
+import android.util.Pair;
 import android.view.View.AttachInfo;
+import android.view.Window.OnContentApplyWindowInsetsListener;
+
+import static android.view.View.SYSTEM_UI_LAYOUT_FLAGS;
 
 /**
  * Class allowing access to package-protected methods/fields.
  */
 public class AttachInfo_Accessor {
+    // Copied from PhoneWindow.java
+    private static final OnContentApplyWindowInsetsListener sDefaultContentInsetsApplier =
+            (view, insets) -> {
+                if ((view.getWindowSystemUiVisibility() & SYSTEM_UI_LAYOUT_FLAGS) != 0) {
+                    return new Pair<>(Insets.NONE, insets);
+                }
+                Insets insetsToApply = insets.getSystemWindowInsets();
+                return new Pair<>(insetsToApply,
+                        insets.inset(insetsToApply).consumeSystemWindowInsets());
+            };
 
-    public static void setAttachInfo(ViewGroup view) {
+    public static LayoutlibRenderer setAttachInfo(ViewGroup view) {
         Context context = view.getContext();
         WindowManagerImpl wm = (WindowManagerImpl)context.getSystemService(Context.WINDOW_SERVICE);
         wm.setBaseRootView(view);
         Display display = wm.getDefaultDisplay();
         ViewRootImpl root = new ViewRootImpl(context, display, new IWindowSession.Default(),
                 new WindowLayout());
+        root.setOnContentApplyWindowInsetsListener(sDefaultContentInsetsApplier);
+        LayoutlibRenderer renderer = new LayoutlibRenderer(context, false, "layoutlib-renderer");
         AttachInfo info = root.mAttachInfo;
+        info.mThreadedRenderer = renderer;
         info.mHasWindowFocus = true;
         info.mWindowVisibility = View.VISIBLE;
         info.mInTouchMode = false; // this is so that we can display selections.
-        info.mHardwareAccelerated = false;
+        info.mHardwareAccelerated = true;
         info.mApplicationScale = 1.0f;
         ViewRootImpl_Accessor.setChild(root, view);
         view.assignParent(root);
+        if (view instanceof Layout) {
+            InsetsController insetsController = root.getInsetsController();
+            wm.createOrUpdateDisplayFrames(insetsController.getState());
+            InsetUtil.setupSysUiInsets(context, insetsController,
+                    ((Layout)view).getInsetsFrameProviders());
+        }
         view.dispatchAttachedToWindow(info, 0);
+        return renderer;
     }
 
     public static void dispatchOnPreDraw(View view) {
@@ -56,6 +84,15 @@ public class AttachInfo_Accessor {
             view.dispatchDetachedFromWindow();
             if (attachInfo != null) {
                 ViewRootImpl_Accessor.detachFromWindow(attachInfo.mViewRootImpl);
+                final ThreadedRenderer threadedRenderer = attachInfo.mThreadedRenderer;
+                if(threadedRenderer != null) {
+                    threadedRenderer.destroy();
+                }
+                ThreadedRenderer rootRenderer =
+                        attachInfo.mViewRootImpl.mAttachInfo.mThreadedRenderer;
+                if (rootRenderer != null) {
+                    rootRenderer.destroy();
+                }
             }
         }
     }
diff --git a/bridge/src/android/view/BridgeInflater.java b/bridge/src/android/view/BridgeInflater.java
index ad9a442da7..e23ad2ea37 100644
--- a/bridge/src/android/view/BridgeInflater.java
+++ b/bridge/src/android/view/BridgeInflater.java
@@ -256,8 +256,7 @@ public final class BridgeInflater extends LayoutInflater {
         if (mCustomInflater == null) {
             Context context = getContext();
             context = getBaseContext(context);
-            if (context instanceof BridgeContext) {
-                BridgeContext bc = (BridgeContext) context;
+            if (context instanceof BridgeContext bc) {
                 Class<?> inflaterClass = findCustomInflater(bc, mLayoutlibCallback);
 
                 if (inflaterClass != null) {
@@ -324,12 +323,12 @@ public final class BridgeInflater extends LayoutInflater {
             // Creation of ContextThemeWrapper code is same as in the super method.
             // Apply a theme wrapper, if allowed and one is specified.
             if (!ignoreThemeAttr) {
-                final TypedArray ta = context.obtainStyledAttributes(attrs, ATTRS_THEME);
-                final int themeResId = ta.getResourceId(0, 0);
-                if (themeResId != 0) {
-                    context = new ContextThemeWrapper(context, themeResId);
+                try (final TypedArray ta = context.obtainStyledAttributes(attrs, ATTRS_THEME)) {
+                    final int themeResId = ta.getResourceId(0, 0);
+                    if (themeResId != 0) {
+                        context = new ContextThemeWrapper(context, themeResId);
+                    }
                 }
-                ta.recycle();
             }
             if (!(e.getCause() instanceof ClassNotFoundException)) {
                 // There is some unknown inflation exception in inflating a View that was found.
@@ -367,8 +366,7 @@ public final class BridgeInflater extends LayoutInflater {
     public View inflate(int resource, ViewGroup root) {
         Context context = getContext();
         context = getBaseContext(context);
-        if (context instanceof BridgeContext) {
-            BridgeContext bridgeContext = (BridgeContext)context;
+        if (context instanceof BridgeContext bridgeContext) {
 
             ResourceValue value = null;
 
@@ -443,11 +441,10 @@ public final class BridgeInflater extends LayoutInflater {
     private void setupViewInContext(View view, AttributeSet attrs) {
         Context context = getContext();
         context = getBaseContext(context);
-        if (!(context instanceof BridgeContext)) {
+        if (!(context instanceof BridgeContext bc)) {
             return;
         }
 
-        BridgeContext bc = (BridgeContext) context;
         // get the view key
         Object viewKey = getViewKeyFromParser(attrs, bc, mResourceReference, mIsInMerge);
         if (viewKey != null) {
@@ -483,8 +480,7 @@ public final class BridgeInflater extends LayoutInflater {
                 getDrawerLayoutMap().put(view, attrVal);
             }
         }
-        else if (view instanceof NumberPicker) {
-            NumberPicker numberPicker = (NumberPicker) view;
+        else if (view instanceof NumberPicker numberPicker) {
             String minValue = attrs.getAttributeValue(BridgeConstants.NS_TOOLS_URI, "minValue");
             if (minValue != null) {
                 numberPicker.setMinValue(Integer.parseInt(minValue));
@@ -494,8 +490,7 @@ public final class BridgeInflater extends LayoutInflater {
                 numberPicker.setMaxValue(Integer.parseInt(maxValue));
             }
         }
-        else if (view instanceof ImageView) {
-            ImageView img = (ImageView) view;
+        else if (view instanceof ImageView img) {
             Drawable drawable = img.getDrawable();
             if (drawable instanceof Animatable) {
                 if (!((Animatable) drawable).isRunning()) {
@@ -572,8 +567,7 @@ public final class BridgeInflater extends LayoutInflater {
             AdapterBinding binding) {
         if (view instanceof AbsListView) {
             if ((binding.getFooterCount() > 0 || binding.getHeaderCount() > 0) &&
-                    view instanceof ListView) {
-                ListView list = (ListView) view;
+                    view instanceof ListView list) {
 
                 boolean skipCallbackParser = false;
 
@@ -655,10 +649,9 @@ public final class BridgeInflater extends LayoutInflater {
     /*package*/ static Object getViewKeyFromParser(AttributeSet attrs, BridgeContext bc,
             ResourceReference resourceReference, boolean isInMerge) {
 
-        if (!(attrs instanceof BridgeXmlBlockParser)) {
+        if (!(attrs instanceof BridgeXmlBlockParser parser)) {
             return null;
         }
-        BridgeXmlBlockParser parser = ((BridgeXmlBlockParser) attrs);
 
         // get the view key
         Object viewKey = parser.getViewCookie();
diff --git a/bridge/src/android/view/Choreographer_Delegate.java b/bridge/src/android/view/Choreographer_Delegate.java
index d6f3936a72..c78763209b 100644
--- a/bridge/src/android/view/Choreographer_Delegate.java
+++ b/bridge/src/android/view/Choreographer_Delegate.java
@@ -23,6 +23,8 @@ import com.android.layoutlib.bridge.impl.RenderAction;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 import com.android.tools.layoutlib.annotations.Nullable;
 
+import android.view.DisplayEventReceiver.VsyncEventData;
+
 import java.lang.StackWalker.StackFrame;
 import java.util.Optional;
 
@@ -36,6 +38,9 @@ import static com.android.layoutlib.bridge.impl.RenderAction.getCurrentContext;
  *
  */
 public class Choreographer_Delegate {
+    private static VsyncEventData sVsyncEventData;
+    public static long sChoreographerTime = 0;
+
     @LayoutlibDelegate
     public static float getRefreshRate() {
         return 60.f;
@@ -64,7 +69,7 @@ public class Choreographer_Delegate {
         }
         if (action == null) {
             Bridge.getLog().error(ILayoutLog.TAG_BROKEN,
-                    "Callback with null action", (Object) null, null);
+                    "Callback with null action", null, null);
         }
         context.getSessionInteractiveData().getChoreographerCallbacks().add(action,
                 token, delayMillis);
@@ -84,9 +89,25 @@ public class Choreographer_Delegate {
         context.getSessionInteractiveData().getChoreographerCallbacks().remove(action, token);
     }
 
+    /**
+     * This method is called from {@link Choreographer#doFrame} and is responsible for figuring
+     * out which callbacks have to be executed based on the callbackType and frameData.
+     * In layoutlib, we are only interested in animation callbacks.
+     */
     @LayoutlibDelegate
-    public static long getFrameTimeNanos(Choreographer thiz) {
-        return System.nanoTime();
+    public static void doCallbacks(Choreographer thiz, int callbackType, long frameIntervalNanos) {
+        BridgeContext context = getCurrentContext();
+        if (context == null) {
+            return;
+        }
+        if (callbackType != Choreographer.CALLBACK_ANIMATION) {
+            // Ignore non-animation callbacks
+            return;
+        }
+        thiz.mCallbacksRunning = true;
+        context.getSessionInteractiveData().getChoreographerCallbacks().execute(
+                System_Delegate.nanoTime(), Bridge.getLog());
+        thiz.mCallbacksRunning = false;
     }
 
     /**
@@ -109,4 +130,24 @@ public class Choreographer_Delegate {
             return null;
         }
     }
+
+    /**
+     * This is a way to call the {@link Choreographer#doFrame} method bypassing the
+     * scheduling system of the Choreographer. That system relies on callbacks being
+     * stored in queues inside the Choreographer class, but Layoutlib has its own way
+     * of storing callbacks that is incompatible.
+     * The doFrame method is responsible for updating the Choreographer FrameInfo object
+     * which is used by the ThreadedRenderer to know which frame to draw. It also triggers
+     * the execution of the relevant callbacks through calls to the doCallback method.
+     */
+    public static void doFrame(long frameTimeNanos) {
+        if (sVsyncEventData == null) {
+            sVsyncEventData = new VsyncEventData();
+            sVsyncEventData.frameTimelinesLength = 1;
+        }
+        Choreographer choreographer = Choreographer.getInstance();
+        choreographer.mFrameScheduled = true;
+        choreographer.doFrame(frameTimeNanos, 0, sVsyncEventData);
+        sChoreographerTime = frameTimeNanos;
+    }
 }
diff --git a/bridge/src/android/view/DisplayEventReceiver_VsyncEventData_Accessor.java b/bridge/src/android/view/DisplayEventReceiver_VsyncEventData_Accessor.java
deleted file mode 100644
index a72ea7954f..0000000000
--- a/bridge/src/android/view/DisplayEventReceiver_VsyncEventData_Accessor.java
+++ /dev/null
@@ -1,33 +0,0 @@
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
-package android.view;
-
-import com.android.tools.layoutlib.annotations.NotNull;
-
-import android.view.DisplayEventReceiver.VsyncEventData;
-
-public class DisplayEventReceiver_VsyncEventData_Accessor {
-    private static VsyncEventData sVsyncEventData;
-
-    @NotNull
-    public static VsyncEventData getVsyncEventDataInstance() {
-        if (sVsyncEventData == null) {
-            sVsyncEventData = new VsyncEventData();
-        }
-        return sVsyncEventData;
-    }
-}
diff --git a/bridge/src/android/view/IWindowManagerImpl.java b/bridge/src/android/view/IWindowManagerImpl.java
index efa8a9a70d..6dbab73119 100644
--- a/bridge/src/android/view/IWindowManagerImpl.java
+++ b/bridge/src/android/view/IWindowManagerImpl.java
@@ -26,14 +26,12 @@ import android.util.DisplayMetrics;
  */
 public class IWindowManagerImpl extends IWindowManager.Default {
 
-    private final Configuration mConfig;
     private final DisplayMetrics mMetrics;
     private final int mRotation;
     private final boolean mHasNavigationBar;
 
     public IWindowManagerImpl(Configuration config, DisplayMetrics metrics, int rotation,
             boolean hasNavigationBar) {
-        mConfig = config;
         mMetrics = metrics;
         mRotation = rotation;
         mHasNavigationBar = hasNavigationBar;
diff --git a/bridge/src/android/view/LayoutInflater_Delegate.java b/bridge/src/android/view/LayoutInflater_Delegate.java
index 51c413d47d..4cc8dcf949 100644
--- a/bridge/src/android/view/LayoutInflater_Delegate.java
+++ b/bridge/src/android/view/LayoutInflater_Delegate.java
@@ -60,7 +60,7 @@ public class LayoutInflater_Delegate {
             View parent, Context context, AttributeSet attrs, boolean finishInflate)
             throws XmlPullParserException, IOException {
 
-        if (finishInflate == false) {
+        if (!finishInflate) {
             // this is a merge rInflate!
             if (thisInflater instanceof BridgeInflater) {
                 ((BridgeInflater) thisInflater).setIsInMerge(true);
@@ -73,7 +73,7 @@ public class LayoutInflater_Delegate {
 
         // ---- END DEFAULT IMPLEMENTATION.
 
-        if (finishInflate == false) {
+        if (!finishInflate) {
             // this is a merge rInflate!
             if (thisInflater instanceof BridgeInflater) {
                 ((BridgeInflater) thisInflater).setIsInMerge(false);
@@ -105,7 +105,7 @@ public class LayoutInflater_Delegate {
             int layout = attrs.getAttributeResourceValue(null, ATTR_LAYOUT, 0);
             if (layout == 0) {
                 final String value = attrs.getAttributeValue(null, ATTR_LAYOUT);
-                if (value == null || value.length() <= 0) {
+                if (value == null || value.isEmpty()) {
                     Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "You must specify a layout in the"
                             + " include tag: <include layout=\"@layout/layoutID\" />", null, null);
                     LayoutInflater.consumeChildElements(parser);
@@ -136,10 +136,8 @@ public class LayoutInflater_Delegate {
                             + "reference. The layout ID " + value + " is not valid.", null, null);
                 }
             } else {
-                final XmlResourceParser childParser =
-                    thisInflater.getContext().getResources().getLayout(layout);
-
-                try {
+                try (XmlResourceParser childParser = thisInflater.getContext().getResources()
+                        .getLayout(layout)) {
                     final AttributeSet childAttrs = Xml.asAttributeSet(childParser);
 
                     while ((type = childParser.next()) != XmlPullParser.START_TAG &&
@@ -221,8 +219,6 @@ public class LayoutInflater_Delegate {
 
                         group.addView(view);
                     }
-                } finally {
-                    childParser.close();
                 }
             }
         } else {
diff --git a/bridge/src/android/view/LayoutlibRenderer.java b/bridge/src/android/view/LayoutlibRenderer.java
new file mode 100644
index 0000000000..fa8894ae44
--- /dev/null
+++ b/bridge/src/android/view/LayoutlibRenderer.java
@@ -0,0 +1,107 @@
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
+package android.view;
+
+import com.android.internal.lang.System_Delegate;
+
+import android.content.Context;
+import android.graphics.BlendMode;
+import android.graphics.RecordingCanvas;
+
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+
+public class LayoutlibRenderer extends ThreadedRenderer {
+
+    private float scaleX = 1.0f;
+    private float scaleY = 1.0f;
+    @SuppressWarnings("unused") // Used by native code
+    private long mNativeContext;
+    /** Buffer in which the rendering will be drawn */
+    private ByteBuffer mBuffer;
+
+    LayoutlibRenderer(Context context, boolean translucent, String name) {
+        super(context, translucent, name);
+    }
+
+    public void draw(ViewGroup viewGroup) {
+        ViewRootImpl rootView = AttachInfo_Accessor.getRootView(viewGroup);
+        if (rootView == null) {
+            return;
+        }
+        // Animations require mDrawingTime to be set to animate
+        rootView.mAttachInfo.mDrawingTime = System_Delegate.currentTimeMillis();
+        this.draw(viewGroup, rootView.mAttachInfo,
+                new DrawCallbacks() {
+                    @Override
+                    public void onPreDraw(RecordingCanvas canvas) {
+                        AttachInfo_Accessor.dispatchOnPreDraw(viewGroup);
+                        canvas.scale(scaleX, scaleY);
+                        // This way we clear the native image buffer before drawing
+                        canvas.drawColor(0, BlendMode.CLEAR);
+                    }
+
+                    @Override
+                    public void onPostDraw(RecordingCanvas canvas) {
+
+                    }
+                });
+    }
+
+    public void setScale(float scaleX, float scaleY) {
+        this.scaleX = scaleX;
+        this.scaleY = scaleY;
+        invalidateRoot();
+    }
+
+    /**
+     * Prepares the renderer for drawing
+     */
+    public void setup(int width, int height, View rootView) {
+        ViewRootImpl viewRoot =  rootView.mAttachInfo.mViewRootImpl;
+        if (viewRoot == null) {
+            return;
+        }
+
+        // If the surface associated with the ViewRootImpl is not valid,
+        // create a new one.
+        if (!viewRoot.mSurface.isValid()) {
+            Surface surface = nativeCreateSurface();
+            viewRoot.mSurface.transferFrom(surface);
+        }
+
+        // Create a new buffer to draw the image in, making sure that it is following the native
+        // ordering to work on all platforms.
+        mBuffer = nativeCreateBuffer(width, height);
+        mBuffer.order(ByteOrder.nativeOrder());
+
+        setup(width, height, rootView.mAttachInfo, viewRoot.mWindowAttributes.surfaceInsets);
+        setSurface(viewRoot.mSurface);
+    }
+
+    public ByteBuffer getBuffer() {
+        return mBuffer;
+    }
+
+    public void reset() {
+        mBuffer = null;
+    }
+
+    private native Surface nativeCreateSurface();
+
+    private native ByteBuffer nativeCreateBuffer(int width, int height);
+}
diff --git a/bridge/src/android/view/PointerIcon_Delegate.java b/bridge/src/android/view/PointerIcon_Delegate.java
index 84c75f72eb..43df7ece8d 100644
--- a/bridge/src/android/view/PointerIcon_Delegate.java
+++ b/bridge/src/android/view/PointerIcon_Delegate.java
@@ -18,21 +18,15 @@ package android.view;
 
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
-import android.content.Context;
 import android.content.res.Resources;
 
 public class PointerIcon_Delegate {
 
     @LayoutlibDelegate
-    /*package*/ static void loadResource(PointerIcon icon, Context context, Resources resources,
-            int resourceId) {
+    /*package*/ static void loadResource(PointerIcon icon, Resources resources, int resourceId,
+            Resources.Theme theme, float pointerScale) {
         // HACK: This bypasses the problem of having an enum resolved as a resourceId.
         // PointerIcon would not be displayed by layoutlib anyway, so we always return the null
         // icon.
     }
-
-    @LayoutlibDelegate
-    /*package*/ static void registerDisplayListener(Context context) {
-        // Ignore this as we do not have a DisplayManager
-    }
 }
diff --git a/bridge/src/android/view/SurfaceView.java b/bridge/src/android/view/SurfaceView.java
index 2c1d6747e7..02e02aa86d 100644
--- a/bridge/src/android/view/SurfaceView.java
+++ b/bridge/src/android/view/SurfaceView.java
@@ -140,7 +140,7 @@ public class SurfaceView extends MockView {
     public void applyTransactionToFrame(@NonNull SurfaceControl.Transaction transaction) {
     }
 
-    private SurfaceHolder mSurfaceHolder = new SurfaceHolder() {
+    private final SurfaceHolder mSurfaceHolder = new SurfaceHolder() {
 
         @Override
         public boolean isCreating() {
diff --git a/bridge/src/android/graphics/HardwareRenderer_ProcessInitializer_Delegate.java b/bridge/src/android/view/TextureView_Delegate.java
similarity index 64%
rename from bridge/src/android/graphics/HardwareRenderer_ProcessInitializer_Delegate.java
rename to bridge/src/android/view/TextureView_Delegate.java
index 88c034ba2a..0a2abe10cb 100644
--- a/bridge/src/android/graphics/HardwareRenderer_ProcessInitializer_Delegate.java
+++ b/bridge/src/android/view/TextureView_Delegate.java
@@ -14,13 +14,18 @@
  * limitations under the License.
  */
 
-package android.graphics;
+package android.view;
 
-public class HardwareRenderer_ProcessInitializer_Delegate {
-    public static void initSched(long renderProxy) {
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.graphics.TextureLayer;
+
+public class TextureView_Delegate {
+    @LayoutlibDelegate
+    static TextureLayer getTextureLayer(TextureView thisTextureView) {
         /*
-         * This is done in order to prevent NullPointerException when creating HardwareRenderer in
-         * layoutlib
+         * Currently layoutlib does not support TextureLayers (no OpenGL)
          */
+        return null;
     }
 }
diff --git a/bridge/src/android/view/ViewRootImpl_Delegate.java b/bridge/src/android/view/ViewRootImpl_Delegate.java
index 660ce47057..d9e18dde83 100644
--- a/bridge/src/android/view/ViewRootImpl_Delegate.java
+++ b/bridge/src/android/view/ViewRootImpl_Delegate.java
@@ -29,7 +29,7 @@ public class ViewRootImpl_Delegate {
 
     @LayoutlibDelegate
     /*package*/ static boolean performHapticFeedback(ViewRootImpl thisViewRoot, int effectId,
-            boolean always) {
+            int flags, int privFlags) {
         return false;
     }
 }
diff --git a/bridge/src/android/view/WindowCallback.java b/bridge/src/android/view/WindowCallback.java
index 1ea8a9f229..d691c8ea71 100644
--- a/bridge/src/android/view/WindowCallback.java
+++ b/bridge/src/android/view/WindowCallback.java
@@ -16,13 +16,10 @@
 
 package android.view;
 
-import android.annotation.Nullable;
 import android.view.ActionMode.Callback;
 import android.view.WindowManager.LayoutParams;
 import android.view.accessibility.AccessibilityEvent;
 
-import java.util.List;
-
 /**
  * An empty implementation of {@link Window.Callback} that always returns null/false.
  */
diff --git a/bridge/src/android/view/WindowManagerImpl.java b/bridge/src/android/view/WindowManagerImpl.java
index 285ca9e5e4..ffca71f294 100644
--- a/bridge/src/android/view/WindowManagerImpl.java
+++ b/bridge/src/android/view/WindowManagerImpl.java
@@ -15,15 +15,11 @@
  */
 package android.view;
 
-import static android.view.View.SYSTEM_UI_FLAG_VISIBLE;
 import static android.view.ViewGroup.LayoutParams.MATCH_PARENT;
 import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
-import static android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING;
-import static android.view.WindowManager.LayoutParams.TYPE_APPLICATION;
+import static com.android.layoutlib.bridge.util.InsetUtil.getCurrentBounds;
 
-import android.app.ResourcesManager;
 import android.content.Context;
-import android.content.res.Configuration;
 import android.graphics.Color;
 import android.graphics.Point;
 import android.graphics.Rect;
@@ -31,7 +27,6 @@ import android.graphics.Region;
 import android.graphics.drawable.ColorDrawable;
 import android.graphics.drawable.Drawable;
 import android.os.IBinder;
-import android.os.RemoteException;
 import android.util.DisplayMetrics;
 import android.view.Display.Mode;
 import android.widget.FrameLayout;
@@ -40,14 +35,18 @@ import com.android.ide.common.rendering.api.ILayoutLog;
 import com.android.internal.R;
 import com.android.internal.policy.DecorView;
 import com.android.layoutlib.bridge.Bridge;
+import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.server.wm.DisplayFrames;
 
 import java.util.ArrayList;
 
 public class WindowManagerImpl implements WindowManager {
-
+    private static final PrivacyIndicatorBounds sPrivacyIndicatorBounds =
+            new PrivacyIndicatorBounds();
     private final Context mContext;
     private final DisplayMetrics mMetrics;
-    private final Display mDisplay;
+    private final DisplayInfo mDisplayInfo;
+    private Display mDisplay;
     /**
      * Root view of the base window, new windows will be added on top of this.
      */
@@ -57,20 +56,20 @@ public class WindowManagerImpl implements WindowManager {
      * null if there is only the base window present.
      */
     private ViewGroup mCurrentRootView;
+    private DisplayFrames mDisplayFrames;
 
-    public WindowManagerImpl(Context context, DisplayMetrics metrics) {
+    public WindowManagerImpl(BridgeContext context, DisplayMetrics metrics) {
         mContext = context;
         mMetrics = metrics;
 
-        DisplayInfo info = new DisplayInfo();
-        info.logicalHeight = mMetrics.heightPixels;
-        info.logicalWidth = mMetrics.widthPixels;
-        info.supportedModes = new Mode[] {
+        mDisplayInfo = new DisplayInfo();
+        mDisplayInfo.logicalHeight = mMetrics.heightPixels;
+        mDisplayInfo.logicalWidth = mMetrics.widthPixels;
+        mDisplayInfo.supportedModes = new Mode[] {
                 new Mode(0, mMetrics.widthPixels, mMetrics.heightPixels, 60f)
         };
-        info.logicalDensityDpi = mMetrics.densityDpi;
-        mDisplay = new Display(null, Display.DEFAULT_DISPLAY, info,
-                DisplayAdjustments.DEFAULT_DISPLAY_ADJUSTMENTS);
+        mDisplayInfo.logicalDensityDpi = mMetrics.densityDpi;
+        mDisplayInfo.displayCutout = DisplayCutout.NO_CUTOUT;
     }
 
     public WindowManagerImpl createLocalWindowManager(Window parentWindow) {
@@ -96,6 +95,10 @@ public class WindowManagerImpl implements WindowManager {
 
     @Override
     public Display getDefaultDisplay() {
+        if (mDisplay == null) {
+            mDisplay = new Display(null, Display.DEFAULT_DISPLAY, mDisplayInfo,
+                    mContext.getResources());
+        }
         return mDisplay;
     }
 
@@ -163,8 +166,7 @@ public class WindowManagerImpl implements WindowManager {
         }
 
         FrameLayout.LayoutParams frameLayoutParams = new FrameLayout.LayoutParams(arg1);
-        if (arg1 instanceof WindowManager.LayoutParams) {
-            LayoutParams params = (LayoutParams) arg1;
+        if (arg1 instanceof LayoutParams params) {
             frameLayoutParams.gravity = params.gravity;
             if ((params.flags & LayoutParams.FLAG_DIM_BEHIND) != 0) {
                 mCurrentRootView.setBackgroundColor(Color.argb(params.dimAmount, 0, 0, 0));
@@ -215,11 +217,10 @@ public class WindowManagerImpl implements WindowManager {
         if (view == null) {
             throw new IllegalArgumentException("view must not be null");
         }
-        if (!(params instanceof WindowManager.LayoutParams)) {
+        if (!(params instanceof LayoutParams wparams)) {
             throw new IllegalArgumentException("Params must be WindowManager.LayoutParams");
         }
 
-        WindowManager.LayoutParams wparams = (WindowManager.LayoutParams)params;
         FrameLayout.LayoutParams lparams = new FrameLayout.LayoutParams(params);
         lparams.gravity = wparams.gravity;
         view.setLayoutParams(lparams);
@@ -238,6 +239,11 @@ public class WindowManagerImpl implements WindowManager {
         removeView(arg0);
     }
 
+    @Override
+    public KeyboardShortcutGroup getApplicationLaunchKeyboardShortcuts(int deviceId) {
+        return new KeyboardShortcutGroup("", new ArrayList<>());
+    }
+
     @Override
     public void requestAppKeyboardShortcuts(
             KeyboardShortcutsReceiver receiver, int deviceId) {
@@ -270,12 +276,6 @@ public class WindowManagerImpl implements WindowManager {
         return new WindowMetrics(bound, computeWindowInsets());
     }
 
-    private static Rect getCurrentBounds(Context context) {
-        synchronized (ResourcesManager.getInstance()) {
-            return context.getResources().getConfiguration().windowConfiguration.getBounds();
-        }
-    }
-
     @Override
     public WindowMetrics getMaximumWindowMetrics() {
         return new WindowMetrics(getMaximumBounds(), computeWindowInsets());
@@ -283,25 +283,15 @@ public class WindowManagerImpl implements WindowManager {
 
     private Rect getMaximumBounds() {
         final Point displaySize = new Point();
-        mDisplay.getRealSize(displaySize);
+        getDefaultDisplay().getRealSize(displaySize);
         return new Rect(0, 0, displaySize.x, displaySize.y);
     }
 
     private WindowInsets computeWindowInsets() {
-        try {
-            final InsetsState insetsState = new InsetsState();
-            WindowManagerGlobal.getWindowManagerService().getWindowInsets(mContext.getDisplayId(),
-                    null /* token */, insetsState);
-            final Configuration config = mContext.getResources().getConfiguration();
-            final boolean isScreenRound = config.isScreenRound();
-            final int activityType = config.windowConfiguration.getActivityType();
-            return insetsState.calculateInsets(getCurrentBounds(mContext),
-                    null /* ignoringVisibilityState */, isScreenRound, SOFT_INPUT_ADJUST_NOTHING,
-                    0 /* legacySystemUiFlags */, SYSTEM_UI_FLAG_VISIBLE, TYPE_APPLICATION,
-                    activityType, null /* typeSideMap */);
-        } catch (RemoteException ignore) {
+        if (mBaseRootView == null) {
+            return null;
         }
-        return null;
+        return mBaseRootView.getViewRootImpl().getWindowInsets(true);
     }
 
     // ---- Extra methods for layoutlib ----
@@ -332,4 +322,28 @@ public class WindowManagerImpl implements WindowManager {
     public ViewGroup getCurrentRootView() {
         return mCurrentRootView;
     }
+
+    public void createOrUpdateDisplayFrames(InsetsState insetsState) {
+        if (mDisplayFrames == null) {
+            mDisplayFrames = new DisplayFrames(insetsState, mDisplayInfo,
+                    mDisplayInfo.displayCutout, RoundedCorners.NO_ROUNDED_CORNERS,
+                    sPrivacyIndicatorBounds, DisplayShape.NONE);
+        } else {
+            mDisplayFrames.update(mDisplayInfo.rotation, mDisplayInfo.logicalWidth,
+                    mDisplayInfo.logicalHeight, mDisplayInfo.displayCutout,
+                    RoundedCorners.NO_ROUNDED_CORNERS, sPrivacyIndicatorBounds, DisplayShape.NONE);
+        }
+    }
+
+    public void setupDisplayCutout() {
+        DisplayCutout displayCutout =
+                DisplayCutout.fromResourcesRectApproximation(mContext.getResources(), null,
+                        mMetrics.widthPixels, mMetrics.heightPixels, mMetrics.widthPixels,
+                        mMetrics.heightPixels);
+        if (displayCutout != null) {
+            mDisplayInfo.displayCutout = displayCutout.getRotated(mDisplayInfo.logicalWidth,
+                    mDisplayInfo.logicalHeight, mDisplayInfo.rotation,
+                    getDefaultDisplay().getRotation());
+        }
+    }
 }
diff --git a/bridge/src/android/media/ImageReader_Delegate.java b/bridge/src/android/view/flags/Flags_Delegate.java
similarity index 67%
rename from bridge/src/android/media/ImageReader_Delegate.java
rename to bridge/src/android/view/flags/Flags_Delegate.java
index 0ff1ce7303..2e2ed053a3 100644
--- a/bridge/src/android/media/ImageReader_Delegate.java
+++ b/bridge/src/android/view/flags/Flags_Delegate.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,11 +14,13 @@
  * limitations under the License.
  */
 
-package android.media;
+package android.view.flags;
 
-public class ImageReader_Delegate {
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
-    static void nativeClassInit() {
-        // Call ImageReader.nativeClassInit(); in layoutlib implicitly before using ImageReader
+public class Flags_Delegate {
+    @LayoutlibDelegate
+    public static boolean sensitiveContentAppProtection() {
+        return false;
     }
 }
diff --git a/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java b/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
index 61d90702f8..e97813f17d 100644
--- a/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
+++ b/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
@@ -51,6 +51,12 @@ public class InputMethodManager_Delegate {
         return false;
     }
 
+    @LayoutlibDelegate
+    /*package*/ static boolean showSoftInput(InputMethodManager thisManager, View view,
+            int flags, ResultReceiver resultReceiver, int reason) {
+        return false;
+    }
+
     @LayoutlibDelegate
     /*package*/static boolean showSoftInput(InputMethodManager thisManager, View view,
             ImeTracker.Token statsToken, int flags, ResultReceiver resultReceiver, int reason) {
diff --git a/bridge/src/android/webkit/WebView.java b/bridge/src/android/webkit/WebView.java
index 202f2046a3..ffb034b863 100644
--- a/bridge/src/android/webkit/WebView.java
+++ b/bridge/src/android/webkit/WebView.java
@@ -21,7 +21,6 @@ import com.android.layoutlib.bridge.MockView;
 import android.content.Context;
 import android.graphics.Bitmap;
 import android.graphics.Picture;
-import android.os.Bundle;
 import android.os.Message;
 import android.util.AttributeSet;
 import android.view.View;
diff --git a/bridge/src/com/android/internal/lang/System_Delegate.java b/bridge/src/com/android/internal/lang/System_Delegate.java
index 2558989a6e..d4ce93d48a 100644
--- a/bridge/src/com/android/internal/lang/System_Delegate.java
+++ b/bridge/src/com/android/internal/lang/System_Delegate.java
@@ -17,7 +17,6 @@ package com.android.internal.lang;
 
 import com.android.layoutlib.bridge.android.BridgeContext;
 
-import java.util.WeakHashMap;
 import java.util.concurrent.TimeUnit;
 
 import static com.android.layoutlib.bridge.impl.RenderAction.getCurrentContext;
diff --git a/bridge/src/com/android/layoutlib/bridge/Bridge.java b/bridge/src/com/android/layoutlib/bridge/Bridge.java
index ce0fb2ddd8..90d8a28348 100644
--- a/bridge/src/com/android/layoutlib/bridge/Bridge.java
+++ b/bridge/src/com/android/layoutlib/bridge/Bridge.java
@@ -47,7 +47,6 @@ import android.graphics.Rect;
 import android.graphics.Typeface;
 import android.graphics.fonts.SystemFonts_Delegate;
 import android.hardware.input.IInputManager;
-import android.hardware.input.InputManager;
 import android.hardware.input.InputManagerGlobal;
 import android.icu.util.ULocale;
 import android.os.Looper;
@@ -73,6 +72,7 @@ import java.util.HashMap;
 import java.util.Locale;
 import java.util.Map;
 import java.util.Map.Entry;
+import java.util.Objects;
 import java.util.WeakHashMap;
 import java.util.concurrent.locks.ReentrantLock;
 
@@ -92,10 +92,10 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
 
     private static final String ICU_LOCALE_DIRECTION_RTL = "right-to-left";
 
-    public static class StaticMethodNotImplementedException extends RuntimeException {
+    protected static class StaticMethodNotImplementedException extends RuntimeException {
         private static final long serialVersionUID = 1L;
 
-        public StaticMethodNotImplementedException(String msg) {
+        protected StaticMethodNotImplementedException(String msg) {
             super(msg);
         }
     }
@@ -172,10 +172,11 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
     private static String sIcuDataPath;
     private static String[] sKeyboardPaths;
 
-    private static final String[] LINUX_NATIVE_LIBRARIES = {"libandroid_runtime.so"};
-    private static final String[] MAC_NATIVE_LIBRARIES = {"libandroid_runtime.dylib"};
+    private static final String[] LINUX_NATIVE_LIBRARIES = {"layoutlib_jni.so"};
+    private static final String[] MAC_NATIVE_LIBRARIES = {"layoutlib_jni.dylib"};
     private static final String[] WINDOWS_NATIVE_LIBRARIES =
-            {"libicuuc_stubdata.dll", "libicuuc-host.dll", "libandroid_runtime.dll"};
+            {"libicuuc_stubdata.dll", "libicuuc-host.dll", "libandroid_runtime.dll",
+                    "layoutlib_jni.dll"};
 
     @Override
     public boolean init(Map<String, String> platformProperties,
@@ -334,6 +335,8 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
         for (Entry<String, String> property : sPlatformProperties.entrySet()) {
             SystemProperties.set(property.getKey(), property.getValue());
         }
+        SystemProperties.set("ro.icu.data.path", Bridge.getIcuDataPath());
+        SystemProperties.set("ro.keyboard.paths", String.join(",", sKeyboardPaths));
     }
 
     /**
@@ -527,8 +530,7 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
 
     @Override
     public Result getViewIndex(Object viewObject) {
-        if (viewObject instanceof View) {
-            View view = (View) viewObject;
+        if (viewObject instanceof View view) {
             ViewParent parentView = view.getParent();
 
             if (parentView instanceof ViewGroup) {
@@ -601,11 +603,7 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
             throw new IllegalStateException("scene must be acquired first. see #acquire(long)");
         }
 
-        if (log != null) {
-            sCurrentLog = log;
-        } else {
-            sCurrentLog = sDefaultLog;
-        }
+        sCurrentLog = Objects.requireNonNullElse(log, sDefaultLog);
     }
 
     /**
@@ -800,10 +798,8 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
                     NativeConfig.CORE_CLASS_NATIVES));
             System.setProperty("graphics_native_classes", String.join(",",
                     NativeConfig.GRAPHICS_CLASS_NATIVES));
-            System.setProperty("icu.data.path", Bridge.getIcuDataPath());
             System.setProperty("use_bridge_for_logging", "true");
             System.setProperty("register_properties_during_load", "true");
-            System.setProperty("keyboard_paths", String.join(",", sKeyboardPaths));
             for (String library : getNativeLibraries()) {
                 String path = new File(nativeLibDir, library).getAbsolutePath();
                 System.load(path);
diff --git a/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java b/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
index 8316430b91..94c3b9246c 100644
--- a/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
+++ b/bridge/src/com/android/layoutlib/bridge/BridgeRenderSession.java
@@ -31,7 +31,7 @@ import com.android.layoutlib.bridge.impl.RenderSessionImpl;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.os.Handler_Delegate;
-import android.os.SystemClock_Delegate;
+import android.view.Choreographer_Delegate;
 import android.view.MotionEvent;
 
 import java.awt.image.BufferedImage;
@@ -39,8 +39,6 @@ import java.util.Collections;
 import java.util.List;
 import java.util.Map;
 
-import static com.android.layoutlib.bridge.impl.RenderAction.getCurrentContext;
-
 /**
  * An implementation of {@link RenderSession}.
  *
@@ -157,12 +155,9 @@ public class BridgeRenderSession extends RenderSession {
         try {
             Bridge.prepareThread();
             mLastResult = mSession.acquire(RenderParams.DEFAULT_TIMEOUT);
-            boolean hasMoreCallbacks = Handler_Delegate.executeCallbacks();
-            long currentTimeMs = SystemClock_Delegate.uptimeMillis();
-            getCurrentContext()
-                    .getSessionInteractiveData()
-                    .getChoreographerCallbacks()
-                    .execute(currentTimeMs, Bridge.getLog());
+            long currentTimeNanos = System_Delegate.nanoTime();
+            boolean hasMoreCallbacks = Handler_Delegate.executeCallbacks(currentTimeNanos);
+            Choreographer_Delegate.doFrame(currentTimeNanos);
             return hasMoreCallbacks;
         } catch (Throwable t) {
             Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Failed executing Choreographer#doFrame "
@@ -175,15 +170,11 @@ public class BridgeRenderSession extends RenderSession {
     }
 
     private static int toMotionEventType(TouchEventType eventType) {
-        switch (eventType) {
-            case PRESS:
-                return MotionEvent.ACTION_DOWN;
-            case RELEASE:
-                return MotionEvent.ACTION_UP;
-            case DRAG:
-                return MotionEvent.ACTION_MOVE;
-        }
-        throw new IllegalStateException("Unexpected touch event type: " + eventType);
+        return switch (eventType) {
+            case PRESS -> MotionEvent.ACTION_DOWN;
+            case RELEASE -> MotionEvent.ACTION_UP;
+            case DRAG -> MotionEvent.ACTION_MOVE;
+        };
     }
 
     @Override
diff --git a/bridge/src/com/android/layoutlib/bridge/SessionInteractiveData.java b/bridge/src/com/android/layoutlib/bridge/SessionInteractiveData.java
index 39b8b082f3..9ba104288b 100644
--- a/bridge/src/com/android/layoutlib/bridge/SessionInteractiveData.java
+++ b/bridge/src/com/android/layoutlib/bridge/SessionInteractiveData.java
@@ -4,6 +4,8 @@ import com.android.layoutlib.bridge.util.ChoreographerCallbacks;
 import com.android.layoutlib.bridge.util.HandlerMessageQueue;
 import com.android.tools.layoutlib.annotations.NotNull;
 
+import android.view.Choreographer_Delegate;
+
 import java.util.concurrent.atomic.AtomicLong;
 
 public class SessionInteractiveData {
@@ -11,6 +13,7 @@ public class SessionInteractiveData {
     private final ChoreographerCallbacks mChoreographerCallbacks = new ChoreographerCallbacks();
     // Current system time
     private final AtomicLong mNanosTime = new AtomicLong(System.nanoTime());
+    private final AtomicLong mPreviousNanosTime = new AtomicLong(System.nanoTime());
     // Time that the system booted up in nanos
     private final AtomicLong mBootNanosTime = new AtomicLong(System.nanoTime());
 
@@ -23,11 +26,13 @@ public class SessionInteractiveData {
     public ChoreographerCallbacks getChoreographerCallbacks() { return mChoreographerCallbacks; }
 
     public void setNanosTime(long nanos) {
+        mPreviousNanosTime.set(mNanosTime.get());
         mNanosTime.set(nanos);
     }
 
     public long getNanosTime() {
-        return mNanosTime.get();
+        return mNanosTime.get() - mPreviousNanosTime.get()
+                + Choreographer_Delegate.sChoreographerTime;
     }
 
     public void setBootNanosTime(long nanos) {
diff --git a/bridge/src/com/android/layoutlib/bridge/android/ApplicationContext.java b/bridge/src/com/android/layoutlib/bridge/android/ApplicationContext.java
index 8e14030d6f..2017f327c8 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/ApplicationContext.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/ApplicationContext.java
@@ -718,6 +718,17 @@ public class ApplicationContext extends Context {
         }
     }
 
+    @Override
+    public void sendOrderedBroadcastAsUserMultiplePermissions(Intent intent, UserHandle user,
+            String[] receiverPermissions, int appOp, Bundle options,
+            BroadcastReceiver resultReceiver, Handler scheduler, int initialCode,
+            String initialData, Bundle initialExtras) {
+        Context context = mContextRef.get();
+        if (context != null) {
+            context.sendOrderedBroadcastAsUserMultiplePermissions(intent, user, receiverPermissions, appOp, options, resultReceiver, scheduler, initialCode, initialData, initialExtras);
+        }
+    }
+
     @Override
     public void sendStickyBroadcast(Intent intent) {
         Context context = mContextRef.get();
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeContentProvider.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeContentProvider.java
index a194dc5b1b..9847f88e96 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeContentProvider.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeContentProvider.java
@@ -35,7 +35,6 @@ import android.os.ParcelFileDescriptor;
 import android.os.RemoteCallback;
 import android.os.RemoteException;
 
-import java.io.FileNotFoundException;
 import java.util.ArrayList;
 
 /**
@@ -96,7 +95,7 @@ public final class BridgeContentProvider implements IContentProvider {
     }
 
     
-    public String getTypeAnonymous(Uri arg0) throws RemoteException {
+    private String getTypeAnonymous(Uri arg0) throws RemoteException {
         // TODO Auto-generated method stub
         return null;
     }
@@ -125,7 +124,7 @@ public final class BridgeContentProvider implements IContentProvider {
     @Override
     public AssetFileDescriptor openAssetFile(AttributionSource attributionSource,
             Uri arg0, String arg1, ICancellationSignal signal)
-            throws RemoteException, FileNotFoundException {
+            throws RemoteException {
         // TODO Auto-generated method stub
         return null;
     }
@@ -133,7 +132,7 @@ public final class BridgeContentProvider implements IContentProvider {
     @Override
     public ParcelFileDescriptor openFile(AttributionSource attributionSource, Uri arg0,
             String arg1, ICancellationSignal signal)
-            throws RemoteException, FileNotFoundException {
+            throws RemoteException {
         // TODO Auto-generated method stub
         return null;
     }
@@ -168,7 +167,7 @@ public final class BridgeContentProvider implements IContentProvider {
     @Override
     public AssetFileDescriptor openTypedAssetFile(AttributionSource attributionSource,
             Uri arg0, String arg1, Bundle arg2, ICancellationSignal signal)
-            throws RemoteException, FileNotFoundException {
+            throws RemoteException {
         // TODO Auto-generated method stub
         return null;
     }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
index c1daac2465..f85fae8c8e 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
@@ -115,9 +115,7 @@ import android.view.textservice.TextServicesManager;
 import java.io.File;
 import java.io.FileDescriptor;
 import java.io.FileInputStream;
-import java.io.FileNotFoundException;
 import java.io.FileOutputStream;
-import java.io.IOException;
 import java.io.InputStream;
 import java.util.ArrayList;
 import java.util.HashMap;
@@ -215,6 +213,7 @@ public class BridgeContext extends Context {
 
     private final SessionInteractiveData mSessionInteractiveData;
     private final ThreadLocal<AnimationHandler> mAnimationHandlerThreadLocal = new ThreadLocal<>();
+    private Display mDisplay;
 
     /**
      * Some applications that target both pre API 17 and post API 17, set the newer attrs to
@@ -223,7 +222,7 @@ public class BridgeContext extends Context {
      * This a map from value to attribute name. Warning for missing references shouldn't be logged
      * if value and attr name pair is the same as an entry in this map.
      */
-    private static Map<String, String> RTL_ATTRS = new HashMap<>(10);
+    private static final Map<String, String> RTL_ATTRS = new HashMap<>(10);
 
     static {
         RTL_ATTRS.put("?android:attr/paddingLeft", "paddingStart");
@@ -394,9 +393,10 @@ public class BridgeContext extends Context {
      * Removes the parser at the top of the stack
      */
     public void popParser() {
-        BridgeXmlBlockParser parser = mParserStack.pop();
-        if (ParserFactory.LOG_PARSER) {
-            System.out.println("POPD " + parser.getParser().toString());
+        try (BridgeXmlBlockParser parser = mParserStack.pop()) {
+            if (ParserFactory.LOG_PARSER) {
+                System.out.println("POPD " + parser.getParser().toString());
+            }
         }
     }
 
@@ -508,11 +508,7 @@ public class BridgeContext extends Context {
 
         // didn't find a match in the framework? look in the project.
         if (mLayoutlibCallback != null) {
-            resourceInfo = mLayoutlibCallback.resolveResourceId(id);
-
-            if (resourceInfo != null) {
-                return resourceInfo;
-            }
+            return mLayoutlibCallback.resolveResourceId(id);
         }
 
         return null;
@@ -944,124 +940,111 @@ public class BridgeContext extends Context {
             }
         }
 
-        if (attributeList != null) {
-            for (int index = 0 ; index < attributeList.size() ; index++) {
-                AttributeHolder attributeHolder = attributeList.get(index);
+        for (int index = 0; index < attributeList.size(); index++) {
+            AttributeHolder attributeHolder = attributeList.get(index);
 
-                if (attributeHolder == null) {
-                    continue;
-                }
+            if (attributeHolder == null) {
+                continue;
+            }
 
-                String attrName = attributeHolder.getName();
-                String value = null;
-                if (set != null) {
-                    value = set.getAttributeValue(
-                            attributeHolder.getNamespace().getXmlNamespaceUri(), attrName);
+            String attrName = attributeHolder.getName();
+            String value = null;
+            if (set != null) {
+                value = set.getAttributeValue(attributeHolder.getNamespace().getXmlNamespaceUri(),
+                        attrName);
 
-                    // if this is an app attribute, and the first get fails, try with the
-                    // new res-auto namespace as well
-                    if (attributeHolder.getNamespace() != ResourceNamespace.ANDROID && value == null) {
-                        value = set.getAttributeValue(BridgeConstants.NS_APP_RES_AUTO, attrName);
-                    }
+                // if this is an app attribute, and the first get fails, try with the
+                // new res-auto namespace as well
+                if (attributeHolder.getNamespace() != ResourceNamespace.ANDROID && value == null) {
+                    value = set.getAttributeValue(BridgeConstants.NS_APP_RES_AUTO, attrName);
                 }
+            }
 
-                // Calculate the default value from the Theme in two cases:
-                //   - If defaultPropMap is not null, get the default value to add it to the list
-                //   of default values of properties.
-                //   - If value is null, it means that the attribute is not directly set as an
-                //   attribute in the XML so try to get the default value.
-                ResourceValue defaultValue = null;
-                if (defaultPropMap != null || value == null) {
-                    // look for the value in the custom style first (and its parent if needed)
-                    ResourceReference attrRef = attributeHolder.asReference();
-                    if (customStyleValues != null) {
-                        defaultValue =
-                                mRenderResources.findItemInStyle(customStyleValues, attrRef);
-                    }
-
-                    // then look for the value in the default Style (and its parent if needed)
-                    if (defaultValue == null && defStyleValues != null) {
-                        defaultValue =
-                                mRenderResources.findItemInStyle(defStyleValues, attrRef);
-                    }
+            // Calculate the default value from the Theme in two cases:
+            //   - If defaultPropMap is not null, get the default value to add it to the list
+            //   of default values of properties.
+            //   - If value is null, it means that the attribute is not directly set as an
+            //   attribute in the XML so try to get the default value.
+            ResourceValue defaultValue = null;
+            if (defaultPropMap != null || value == null) {
+                // look for the value in the custom style first (and its parent if needed)
+                ResourceReference attrRef = attributeHolder.asReference();
+                if (customStyleValues != null) {
+                    defaultValue = mRenderResources.findItemInStyle(customStyleValues, attrRef);
+                }
 
-                    // if the item is not present in the defStyle, we look in the main theme (and
-                    // its parent themes)
-                    if (defaultValue == null) {
-                        defaultValue =
-                                mRenderResources.findItemInTheme(attrRef);
-                    }
+                // then look for the value in the default Style (and its parent if needed)
+                if (defaultValue == null && defStyleValues != null) {
+                    defaultValue = mRenderResources.findItemInStyle(defStyleValues, attrRef);
+                }
 
-                    // if we found a value, we make sure this doesn't reference another value.
-                    // So we resolve it.
-                    if (defaultValue != null) {
-                        if (defaultPropMap != null) {
-                            defaultPropMap.put(attrRef, defaultValue);
-                        }
+                // if the item is not present in the defStyle, we look in the main theme (and
+                // its parent themes)
+                if (defaultValue == null) {
+                    defaultValue = mRenderResources.findItemInTheme(attrRef);
+                }
 
-                        defaultValue = mRenderResources.resolveResValue(defaultValue);
+                // if we found a value, we make sure this doesn't reference another value.
+                // So we resolve it.
+                if (defaultValue != null) {
+                    if (defaultPropMap != null) {
+                        defaultPropMap.put(attrRef, defaultValue);
                     }
-                }
-                // Done calculating the defaultValue.
 
-                // If there's no direct value for this attribute in the XML, we look for default
-                // values in the widget defStyle, and then in the theme.
-                if (value == null) {
-                    if (attributeHolder.getNamespace() == ResourceNamespace.ANDROID) {
-                        // For some framework values, layoutlib patches the actual value in the
-                        // theme when it helps to improve the final preview. In most cases
-                        // we just disable animations.
-                        ResourceValue patchedValue = FRAMEWORK_PATCHED_VALUES.get(attrName);
-                        if (patchedValue != null) {
-                            defaultValue = patchedValue;
-                        }
+                    defaultValue = mRenderResources.resolveResValue(defaultValue);
+                }
+            }
+            // Done calculating the defaultValue.
+
+            // If there's no direct value for this attribute in the XML, we look for default
+            // values in the widget defStyle, and then in the theme.
+            if (value == null) {
+                if (attributeHolder.getNamespace() == ResourceNamespace.ANDROID) {
+                    // For some framework values, layoutlib patches the actual value in the
+                    // theme when it helps to improve the final preview. In most cases
+                    // we just disable animations.
+                    ResourceValue patchedValue = FRAMEWORK_PATCHED_VALUES.get(attrName);
+                    if (patchedValue != null) {
+                        defaultValue = patchedValue;
                     }
+                }
 
-                    // If we found a value, we make sure this doesn't reference another value.
-                    // So we resolve it.
-                    if (defaultValue != null) {
-                        // If the value is a reference to another theme attribute that doesn't
-                        // exist, we should log a warning and omit it.
-                        String val = defaultValue.getValue();
-                        if (val != null && val.startsWith(AndroidConstants.PREFIX_THEME_REF)) {
-                            // Because we always use the latest framework code, some resources might
-                            // fail to resolve when using old themes (they haven't been backported).
-                            // Since this is an artifact caused by us using always the latest
-                            // code, we check for some of those values and replace them here.
-                            ResourceReference reference = defaultValue.getReference();
-                            defaultValue = FRAMEWORK_REPLACE_VALUES.get(attrName);
-
-                            // Only log a warning if the referenced value isn't one of the RTL
-                            // attributes, or the app targets old API.
-                            if (defaultValue == null &&
-                                    (getApplicationInfo().targetSdkVersion < JELLY_BEAN_MR1 ||
-                                    !attrName.equals(RTL_ATTRS.get(val)))) {
-                                if (reference != null) {
-                                    val = reference.getResourceUrl().toString();
-                                }
-                                Bridge.getLog().warning(ILayoutLog.TAG_RESOURCES_RESOLVE_THEME_ATTR,
-                                        String.format("Failed to find '%s' in current theme.", val),
-                                        null, val);
+                // If we found a value, we make sure this doesn't reference another value.
+                // So we resolve it.
+                if (defaultValue != null) {
+                    // If the value is a reference to another theme attribute that doesn't
+                    // exist, we should log a warning and omit it.
+                    String val = defaultValue.getValue();
+                    if (val != null && val.startsWith(AndroidConstants.PREFIX_THEME_REF)) {
+                        // Because we always use the latest framework code, some resources might
+                        // fail to resolve when using old themes (they haven't been backported).
+                        // Since this is an artifact caused by us using always the latest
+                        // code, we check for some of those values and replace them here.
+                        ResourceReference reference = defaultValue.getReference();
+                        defaultValue = FRAMEWORK_REPLACE_VALUES.get(attrName);
+
+                        // Only log a warning if the referenced value isn't one of the RTL
+                        // attributes, or the app targets old API.
+                        if (defaultValue == null &&
+                                (getApplicationInfo().targetSdkVersion < JELLY_BEAN_MR1 || !attrName.equals(RTL_ATTRS.get(val)))) {
+                            if (reference != null) {
+                                val = reference.getResourceUrl().toString();
                             }
+                            Bridge.getLog().warning(ILayoutLog.TAG_RESOURCES_RESOLVE_THEME_ATTR,
+                                    String.format("Failed to find '%s' in current theme.", val),
+                                    null, val);
                         }
                     }
-
-                    ta.bridgeSetValue(
-                            index,
-                            attrName, attributeHolder.getNamespace(),
-                            attributeHolder.getResourceId(),
-                            defaultValue);
-                } else {
-                    // There is a value in the XML, but we need to resolve it in case it's
-                    // referencing another resource or a theme value.
-                    ta.bridgeSetValue(
-                            index,
-                            attrName, attributeHolder.getNamespace(),
-                            attributeHolder.getResourceId(),
-                            mRenderResources.resolveResValue(
-                                    new UnresolvedResourceValue(
-                                            value, currentFileNamespace, resolver)));
                 }
+
+                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(), attributeHolder.getResourceId(),
+                        defaultValue);
+            } else {
+                // There is a value in the XML, but we need to resolve it in case it's
+                // referencing another resource or a theme value.
+                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(), attributeHolder.getResourceId(),
+                        mRenderResources.resolveResValue(
+                                new UnresolvedResourceValue(value, currentFileNamespace, resolver)));
             }
         }
 
@@ -1153,6 +1136,7 @@ public class BridgeContext extends Context {
      * @param attributeIds An attribute array reference given to obtainStyledAttributes.
      * @return List of attribute information.
      */
+    @NotNull
     private List<AttributeHolder> searchAttrs(int[] attributeIds) {
         List<AttributeHolder> results = new ArrayList<>(attributeIds.length);
 
@@ -1255,7 +1239,7 @@ public class BridgeContext extends Context {
      * Returns the Framework resource reference with the given type and name.
      */
     @NonNull
-    public static ResourceReference createFrameworkResourceReference(@NonNull ResourceType type,
+    private static ResourceReference createFrameworkResourceReference(@NonNull ResourceType type,
             @NonNull String name) {
         return new ResourceReference(ResourceNamespace.ANDROID, type, name);
     }
@@ -1704,13 +1688,13 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public FileInputStream openFileInput(String arg0) throws FileNotFoundException {
+    public FileInputStream openFileInput(String arg0) {
         // pass
         return null;
     }
 
     @Override
-    public FileOutputStream openFileOutput(String arg0, int arg1) throws FileNotFoundException {
+    public FileOutputStream openFileOutput(String arg0, int arg1) {
         // pass
         return null;
     }
@@ -1902,6 +1886,13 @@ public class BridgeContext extends Context {
         // pass
     }
 
+    public void sendOrderedBroadcastAsUserMultiplePermissions(Intent intent, UserHandle user,
+            String[] receiverPermissions, int appOp, Bundle options,
+            BroadcastReceiver resultReceiver, Handler scheduler, int initialCode,
+            String initialData, Bundle initialExtras) {
+        // pass
+    }
+
     @Override
     public void sendStickyBroadcast(Intent arg0) {
         // pass
@@ -1945,13 +1936,13 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void setWallpaper(Bitmap arg0) throws IOException {
+    public void setWallpaper(Bitmap arg0) {
         // pass
 
     }
 
     @Override
-    public void setWallpaper(InputStream arg0) throws IOException {
+    public void setWallpaper(InputStream arg0) {
         // pass
 
     }
@@ -2061,11 +2052,6 @@ public class BridgeContext extends Context {
 
     }
 
-    @Override
-    public boolean isRestricted() {
-        return false;
-    }
-
     @Override
     public File getObbDir() {
         Bridge.getLog().error(ILayoutLog.TAG_UNSUPPORTED, "OBB not supported", null, null);
@@ -2080,8 +2066,10 @@ public class BridgeContext extends Context {
 
     @Override
     public Display getDisplay() {
-        // pass
-        return null;
+        if (mDisplay == null) {
+            mDisplay = mWindowManager.getDefaultDisplay();
+        }
+        return mDisplay;
     }
 
     @Override
@@ -2219,7 +2207,7 @@ public class BridgeContext extends Context {
 
         @NonNull
         public static <T> Key<T> create(@NonNull String name) {
-            return new Key<T>(name);
+            return new Key<>(name);
         }
 
         private Key(@NonNull String name) {
@@ -2233,7 +2221,7 @@ public class BridgeContext extends Context {
         }
     }
 
-    private class AttributeHolder {
+    private static class AttributeHolder {
         private final int resourceId;
         @NonNull private final ResourceReference reference;
 
@@ -2278,7 +2266,7 @@ public class BridgeContext extends Context {
      */
     private static class TypedArrayCache {
 
-        private Map<int[],
+        private final Map<int[],
                 Map<List<StyleResourceValue>,
                         Map<Integer, Pair<BridgeTypedArray,
                                 Map<ResourceReference, ResourceValue>>>>> mCache;
@@ -2287,7 +2275,7 @@ public class BridgeContext extends Context {
             mCache = new IdentityHashMap<>();
         }
 
-        public Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>> get(int[] attrs,
+        private Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>> get(int[] attrs,
                 List<StyleResourceValue> themes, int resId) {
             Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference,
                     ResourceValue>>>>
@@ -2302,7 +2290,7 @@ public class BridgeContext extends Context {
             return null;
         }
 
-        public void put(int[] attrs, List<StyleResourceValue> themes, int resId,
+        private void put(int[] attrs, List<StyleResourceValue> themes, int resId,
                 Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>> value) {
             Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference,
                     ResourceValue>>>>
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgePackageManager.java b/bridge/src/com/android/layoutlib/bridge/android/BridgePackageManager.java
index 92acec09fa..66d15e5d7a 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgePackageManager.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgePackageManager.java
@@ -392,7 +392,7 @@ public class BridgePackageManager extends PackageManager {
     }
 
     @Override
-    public void clearInstantAppCookie() {;
+    public void clearInstantAppCookie() {
 
     }
 
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
index 0122da1818..53b9228d1b 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
@@ -23,9 +23,6 @@ import android.os.IThermalStatusListener;
 import android.os.IThermalService;
 import android.os.Temperature;
 
-import java.util.ArrayList;
-import java.util.List;
-
 /**
  * Fake implementation of IThermalService
  */
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeXmlBlockParser.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeXmlBlockParser.java
index 460dd43f7a..5dfecd37a2 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeXmlBlockParser.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeXmlBlockParser.java
@@ -61,7 +61,7 @@ public class BridgeXmlBlockParser implements XmlResourceParser, ResolvingAttribu
             @Nullable BridgeContext context,
             @NonNull ResourceNamespace fileNamespace) {
         if (ParserFactory.LOG_PARSER) {
-            System.out.println("CRTE " + parser.toString());
+            System.out.println("CRTE " + parser);
         }
 
         mParser = parser;
@@ -296,7 +296,7 @@ public class BridgeXmlBlockParser implements XmlResourceParser, ResolvingAttribu
             mStarted = true;
 
             if (ParserFactory.LOG_PARSER) {
-                System.out.println("STRT " + mParser.toString());
+                System.out.println("STRT " + mParser);
             }
 
             return START_DOCUMENT;
@@ -312,7 +312,7 @@ public class BridgeXmlBlockParser implements XmlResourceParser, ResolvingAttribu
         }
 
         if (ParserFactory.LOG_PARSER) {
-            System.out.println("NEXT " + mParser.toString() + " " +
+            System.out.println("NEXT " + mParser + " " +
                     eventTypeToString(mEventType) + " -> " + eventTypeToString(ev));
         }
 
@@ -326,32 +326,21 @@ public class BridgeXmlBlockParser implements XmlResourceParser, ResolvingAttribu
     }
 
     private static String eventTypeToString(int eventType) {
-        switch (eventType) {
-            case START_DOCUMENT:
-                return "START_DOC";
-            case END_DOCUMENT:
-                return "END_DOC";
-            case START_TAG:
-                return "START_TAG";
-            case END_TAG:
-                return "END_TAG";
-            case TEXT:
-                return "TEXT";
-            case CDSECT:
-                return "CDSECT";
-            case ENTITY_REF:
-                return "ENTITY_REF";
-            case IGNORABLE_WHITESPACE:
-                return "IGNORABLE_WHITESPACE";
-            case PROCESSING_INSTRUCTION:
-                return "PROCESSING_INSTRUCTION";
-            case COMMENT:
-                return "COMMENT";
-            case DOCDECL:
-                return "DOCDECL";
-        }
+        return switch (eventType) {
+            case START_DOCUMENT -> "START_DOC";
+            case END_DOCUMENT -> "END_DOC";
+            case START_TAG -> "START_TAG";
+            case END_TAG -> "END_TAG";
+            case TEXT -> "TEXT";
+            case CDSECT -> "CDSECT";
+            case ENTITY_REF -> "ENTITY_REF";
+            case IGNORABLE_WHITESPACE -> "IGNORABLE_WHITESPACE";
+            case PROCESSING_INSTRUCTION -> "PROCESSING_INSTRUCTION";
+            case COMMENT -> "COMMENT";
+            case DOCDECL -> "DOCDECL";
+            default -> "????";
+        };
 
-        return "????";
     }
 
     @Override
diff --git a/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java b/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
index b9c8e7f2e4..e356b6570b 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
@@ -25,6 +25,7 @@ import com.android.ide.common.rendering.api.StyleResourceValue;
 import com.android.internal.graphics.ColorUtils;
 import com.android.resources.ResourceType;
 import com.android.systemui.monet.ColorScheme;
+import com.android.systemui.monet.DynamicColors;
 import com.android.systemui.monet.Style;
 import com.android.systemui.monet.TonalPalette;
 import com.android.tools.layoutlib.annotations.VisibleForTesting;
@@ -33,6 +34,7 @@ import android.app.WallpaperColors;
 import android.graphics.Bitmap;
 import android.graphics.BitmapFactory;
 import android.graphics.Color;
+import android.util.Pair;
 
 import java.io.IOException;
 import java.io.InputStream;
@@ -40,6 +42,8 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 
+import com.google.ux.material.libmonet.dynamiccolor.DynamicColor;
+
 /**
  * Wrapper for RenderResources that allows overriding default system colors
  * when using dynamic theming.
@@ -165,13 +169,25 @@ public class DynamicRenderResources extends RenderResources {
             }
             WallpaperColors wallpaperColors = WallpaperColors.fromBitmap(wallpaper);
             int seed = ColorScheme.getSeedColor(wallpaperColors);
-            ColorScheme scheme = new ColorScheme(seed, isNightMode);
+            ColorScheme lightScheme = new ColorScheme(seed, false);
+            ColorScheme darkScheme = new ColorScheme(seed, true);
+            ColorScheme currentScheme = isNightMode ? darkScheme : lightScheme;
             Map<String, Integer> dynamicColorMap = new HashMap<>();
-            extractPalette("accent1", dynamicColorMap, scheme.getAccent1());
-            extractPalette("accent2", dynamicColorMap, scheme.getAccent2());
-            extractPalette("accent3", dynamicColorMap, scheme.getAccent3());
-            extractPalette("neutral1", dynamicColorMap, scheme.getNeutral1());
-            extractPalette("neutral2", dynamicColorMap, scheme.getNeutral2());
+            extractPalette("accent1", dynamicColorMap, currentScheme.getAccent1());
+            extractPalette("accent2", dynamicColorMap, currentScheme.getAccent2());
+            extractPalette("accent3", dynamicColorMap, currentScheme.getAccent3());
+            extractPalette("neutral1", dynamicColorMap, currentScheme.getNeutral1());
+            extractPalette("neutral2", dynamicColorMap, currentScheme.getNeutral2());
+
+            //Themed Colors
+            extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
+                    DynamicColors.getAllDynamicColorsMapped(false), false);
+            // Fixed Colors
+            extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
+                    DynamicColors.getFixedColorsMapped(false), true);
+            //Custom Colors
+            extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
+                    DynamicColors.getCustomColorsMapped(false), false);
             return dynamicColorMap;
         } catch (IllegalArgumentException | IOException ignore) {
             return null;
@@ -193,12 +209,26 @@ public class DynamicRenderResources extends RenderResources {
         colorMap.put(resourcePrefix + "_0", Color.WHITE);
     }
 
-    private static boolean isDynamicColor(ResourceValue resourceValue) {
+    private static void extractDynamicColors(Map<String, Integer> colorMap, ColorScheme lightScheme,
+            ColorScheme darkScheme, List<Pair<String, DynamicColor>> colors, Boolean isFixed) {
+        colors.forEach(p -> {
+            String prefix = "system_" + p.first;
+
+            if (isFixed) {
+                colorMap.put(prefix, p.second.getArgb(lightScheme.getMaterialScheme()));
+                return;
+            }
+
+            colorMap.put(prefix + "_light", p.second.getArgb(lightScheme.getMaterialScheme()));
+            colorMap.put(prefix + "_dark", p.second.getArgb(darkScheme.getMaterialScheme()));
+        });
+    }
+
+    private boolean isDynamicColor(ResourceValue resourceValue) {
         if (!resourceValue.isFramework() || resourceValue.getResourceType() != ResourceType.COLOR) {
             return false;
         }
-        return resourceValue.getName().startsWith("system_accent")
-                || resourceValue.getName().startsWith("system_neutral");
+        return mDynamicColorMap.containsKey(resourceValue.getName());
     }
 
     public boolean hasDynamicColors() {
diff --git a/bridge/src/com/android/layoutlib/bridge/android/NopAttributeSet.java b/bridge/src/com/android/layoutlib/bridge/android/NopAttributeSet.java
index 86ec79809b..6e38bcf7cb 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/NopAttributeSet.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/NopAttributeSet.java
@@ -31,11 +31,6 @@ class NopAttributeSet implements ResolvingAttributeSet {
         return 0;
     }
 
-    @Override
-    public String getAttributeNamespace(int index) {
-        return null;
-    }
-
     @Override
     public String getAttributeName(int index) {
         return null;
diff --git a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
index 2cba415750..73d8728b67 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
@@ -29,19 +29,18 @@ import com.android.ide.common.rendering.api.SessionParams.Key;
  */
 public final class RenderParamsFlags {
 
-    public static final Key<String> FLAG_KEY_ROOT_TAG =
-            new Key<String>("rootTag", String.class);
+    public static final Key<String> FLAG_KEY_ROOT_TAG = new Key<>("rootTag", String.class);
     public static final Key<Boolean> FLAG_KEY_DISABLE_BITMAP_CACHING =
-            new Key<Boolean>("disableBitmapCaching", Boolean.class);
+            new Key<>("disableBitmapCaching", Boolean.class);
     public static final Key<Boolean> FLAG_KEY_RENDER_ALL_DRAWABLE_STATES =
-            new Key<Boolean>("renderAllDrawableStates", Boolean.class);
+            new Key<>("renderAllDrawableStates", Boolean.class);
 
     /**
      * To tell LayoutLib to not render when creating a new session. This allows controlling when the first
      * layout rendering will happen.
      */
     public static final Key<Boolean> FLAG_DO_NOT_RENDER_ON_CREATE =
-            new Key<Boolean>("doNotRenderOnCreate", Boolean.class);
+            new Key<>("doNotRenderOnCreate", Boolean.class);
     /**
      * To tell Layoutlib which path to use for the adaptive icon mask.
      */
@@ -55,7 +54,7 @@ public final class RenderParamsFlags {
      * returned by {@link IImageFactory#getImage(int, int)}.
      */
     public static final Key<Boolean> FLAG_KEY_RESULT_IMAGE_AUTO_SCALE =
-            new Key<Boolean>("enableResultImageAutoScale", Boolean.class);
+            new Key<>("enableResultImageAutoScale", Boolean.class);
 
     /**
      * Enables layout validation calls within rendering.
@@ -84,11 +83,23 @@ public final class RenderParamsFlags {
             new Key<>("useThemedIcon", Boolean.class);
 
     /**
-     * To tell Layoutlib to the gesture navigation, instead of a button navigation bar.
+     * To tell Layoutlib to use the gesture navigation, instead of a button navigation bar.
      */
     public static final Key<Boolean> FLAG_KEY_USE_GESTURE_NAV =
             new Key<>("useGestureNav", Boolean.class);
 
+    /**
+     * To tell Layoutlib to display the app edge to edge.
+     */
+    public static final Key<Boolean> FLAG_KEY_EDGE_TO_EDGE =
+            new Key<>("edgeToEdge", Boolean.class);
+
+    /**
+     * To tell Layoutlib to display the device cutout if there is one.
+     */
+    public static final Key<Boolean> FLAG_KEY_SHOW_CUTOUT =
+            new Key<>("showCutout", Boolean.class);
+
     // Disallow instances.
     private RenderParamsFlags() {}
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/graphics/NopCanvas.java b/bridge/src/com/android/layoutlib/bridge/android/graphics/NopCanvas.java
index 55512ec914..6e9d77bb43 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/graphics/NopCanvas.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/graphics/NopCanvas.java
@@ -35,11 +35,9 @@ import android.graphics.text.MeasuredText;
  * Canvas implementation that does not do any rendering
  */
 public class NopCanvas extends Canvas {
-    private boolean mIsInitialized = false;
 
     public NopCanvas() {
         super();
-        mIsInitialized = true;
     }
 
     @Override
diff --git a/bridge/src/com/android/layoutlib/bridge/android/support/SupportPreferencesUtil.java b/bridge/src/com/android/layoutlib/bridge/android/support/SupportPreferencesUtil.java
index 6876312f40..81f477662d 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/support/SupportPreferencesUtil.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/support/SupportPreferencesUtil.java
@@ -66,7 +66,7 @@ public class SupportPreferencesUtil {
 
     @NonNull
     private static Object instantiateClass(@NonNull LayoutlibCallback callback,
-            @NonNull String className, @Nullable Class[] constructorSignature,
+            @NonNull String className, @Nullable Class<?>[] constructorSignature,
             @Nullable Object[] constructorArgs) throws ReflectionException {
         try {
             Object instance = callback.loadClass(className, constructorSignature, constructorArgs);
@@ -229,7 +229,6 @@ public class SupportPreferencesUtil {
             }
         }
 
-        assert preferencePackageName != null;
         String preferenceGroupClassName = preferencePackageName + ".PreferenceGroup";
         String preferenceGroupAdapterClassName = preferencePackageName + ".PreferenceGroupAdapter";
         String preferenceInflaterClassName = preferencePackageName + ".PreferenceInflater";
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/AppCompatActionBar.java b/bridge/src/com/android/layoutlib/bridge/bars/AppCompatActionBar.java
index 8ca809e516..e38318f20f 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/AppCompatActionBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/AppCompatActionBar.java
@@ -95,7 +95,7 @@ public class AppCompatActionBar extends BridgeActionBar {
             setContentRoot(contentRoot);
         }
         try {
-            Class[] constructorParams = {View.class};
+            Class<?>[] constructorParams = {View.class};
             Object[] constructorArgs = {getDecorContent()};
             LayoutlibCallback callback = params.getLayoutlibCallback();
 
@@ -272,14 +272,14 @@ public class AppCompatActionBar extends BridgeActionBar {
         Class<?> instanceClass = instance.getClass();
         try {
             Field field = instanceClass.getDeclaredField(name);
-            boolean accesible = field.isAccessible();
-            if (!accesible) {
+            boolean accessible = field.isAccessible();
+            if (!accessible) {
                 field.setAccessible(true);
             }
             try {
                 return field.get(instance);
             } finally {
-                field.setAccessible(accesible);
+                field.setAccessible(accessible);
             }
         } catch (NoSuchFieldException | IllegalAccessException e) {
             e.printStackTrace();
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/BridgeActionBar.java b/bridge/src/com/android/layoutlib/bridge/bars/BridgeActionBar.java
index 1f7b187ec7..a91054da90 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/BridgeActionBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/BridgeActionBar.java
@@ -38,7 +38,8 @@ import android.widget.RelativeLayout;
 public abstract class BridgeActionBar {
     // Store a reference to the context so that we don't have to cast it repeatedly.
     @NonNull protected final BridgeContext mBridgeContext;
-    @NonNull protected final SessionParams mParams;
+    @NonNull
+    private final SessionParams mParams;
     // A Layout that contains the inflated action bar. The menu popup is added to this layout.
     @Nullable protected final ViewGroup mEnclosingLayout;
 
@@ -48,7 +49,7 @@ public abstract class BridgeActionBar {
     @SuppressWarnings("NotNullFieldNotInitialized") // Should be initialized by subclasses.
     @NonNull private FrameLayout mContentRoot;
 
-    public BridgeActionBar(@NonNull BridgeContext context, @NonNull SessionParams params) {
+    protected BridgeActionBar(@NonNull BridgeContext context, @NonNull SessionParams params) {
         mBridgeContext = context;
         mParams = params;
         mCallback = params.getLayoutlibCallback().getActionBarCallback();
@@ -151,7 +152,7 @@ public abstract class BridgeActionBar {
         return mEnclosingLayout == null ? mDecorContent : mEnclosingLayout;
     }
 
-    public ActionBarCallback getCallBack() {
+    protected ActionBarCallback getCallBack() {
         return mCallback;
     }
 
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/Config.java b/bridge/src/com/android/layoutlib/bridge/bars/Config.java
index 794990852a..739745b2ff 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/Config.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/Config.java
@@ -34,7 +34,8 @@ public class Config {
     private static final String JELLYBEAN_DIR        = "/bars/v18/";
     private static final String KITKAT_DIR           = "/bars/v19/";
     private static final String LOLLIPOP_DIR         = "/bars/v21/";
-    private static final String PI_DIR = "/bars/v28/";
+    private static final String PI_DIR               = "/bars/v28/";
+    private static final String QT_DIR               = "/bars/v29/";
 
 
     private static final List<String> sDefaultResourceDir;
@@ -44,6 +45,7 @@ public class Config {
 
     static {
         sDefaultResourceDir = new ArrayList<>(6);
+        sDefaultResourceDir.add(QT_DIR);
         sDefaultResourceDir.add(PI_DIR);
         sDefaultResourceDir.add("/bars/");
         // If something is not found in the default directories, we fall back to search in the
@@ -68,7 +70,7 @@ public class Config {
         if (platformVersion == 0) {
             return sDefaultResourceDir;
         }
-        List<String> list = new ArrayList<String>(10);
+        List<String> list = new ArrayList<>(10);
         // Gingerbread - uses custom battery and wifi icons.
         if (platformVersion <= GINGERBREAD) {
             list.add(GINGERBREAD_DIR);
@@ -92,8 +94,8 @@ public class Config {
     }
 
     public static String getTime(int platformVersion) {
-        if (isGreaterOrEqual(platformVersion, UPSIDE_DOWN_CAKE)) {
-            return "14:00";
+        if (isGreaterOrEqual(platformVersion, VANILLA_ICE_CREAM)) {
+            return "15:00";
         }
         if (platformVersion < GINGERBREAD) {
             return "2:20";
@@ -146,6 +148,9 @@ public class Config {
         if (platformVersion < UPSIDE_DOWN_CAKE) {
             return "13:00";
         }
+        if (platformVersion < VANILLA_ICE_CREAM) {
+            return "14:00";
+        }
         // Should never happen.
         return "4:04";
     }
@@ -171,6 +176,10 @@ public class Config {
         return isGreaterOrEqual(platformVersion, LOLLIPOP) ? "xml" : "png";
     }
 
+    public static String getNavIconType(int platformVersion) {
+        return isGreaterOrEqual(platformVersion, Q) ? "xml" : "png";
+    }
+
     /**
      * Compare simulated platform version and code from {@link VERSION_CODES} to check if
      * the simulated platform is greater than or equal to the version code.
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/CustomBar.java b/bridge/src/com/android/layoutlib/bridge/bars/CustomBar.java
index 98378e63e1..25a91cfd5f 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/CustomBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/CustomBar.java
@@ -30,7 +30,6 @@ import com.android.resources.ResourceType;
 
 import android.annotation.NonNull;
 import android.content.res.ColorStateList;
-import android.graphics.Color;
 import android.graphics.drawable.Drawable;
 import android.util.TypedValue;
 import android.view.Gravity;
@@ -52,6 +51,16 @@ import static android.os._Original_Build.VERSION_CODES.LOLLIPOP;
  * It also provides a few utility methods to configure the content of the layout.
  */
 abstract class CustomBar extends LinearLayout {
+    /**
+     * Color corresponding to light_mode_icon_color_single_tone
+     * from frameworks/base/packages/SettingsLib/res/values/colors.xml
+     */
+    protected static final int LIGHT_ICON_COLOR = 0xffffffff;
+    /**
+     * Color corresponding to dark_mode_icon_color_single_tone
+     * from frameworks/base/packages/SettingsLib/res/values/colors.xml
+     */
+    protected static final int DARK_ICON_COLOR = 0x99000000;
     private final int mSimulatedPlatformVersion;
 
     protected CustomBar(BridgeContext context, int orientation, String layoutName,
@@ -76,7 +85,7 @@ abstract class CustomBar extends LinearLayout {
 
     protected abstract TextView getStyleableTextView();
 
-    protected BridgeXmlBlockParser loadXml(String layoutName) {
+    private BridgeXmlBlockParser loadXml(String layoutName) {
         return SysUiResources.loadXml((BridgeContext) mContext, mSimulatedPlatformVersion,
                 layoutName);
     }
@@ -86,12 +95,12 @@ abstract class CustomBar extends LinearLayout {
                 density, false, color);
     }
 
-    protected ImageView loadIcon(int index, String iconName, Density density, boolean isRtl) {
+    protected ImageView loadIcon(int index, String iconName, Density density, boolean isRtl,
+            int color) {
         View child = getChildAt(index);
-        if (child instanceof ImageView) {
-            ImageView imageView = (ImageView) child;
+        if (child instanceof ImageView imageView) {
             return SysUiResources.loadIcon(mContext, mSimulatedPlatformVersion, imageView, iconName,
-                    density, isRtl, Color.WHITE);
+                    density, isRtl, color);
         }
 
         return null;
@@ -99,8 +108,7 @@ abstract class CustomBar extends LinearLayout {
 
     protected TextView setText(int index, String string) {
         View child = getChildAt(index);
-        if (child instanceof TextView) {
-            TextView textView = (TextView) child;
+        if (child instanceof TextView textView) {
             textView.setText(string);
             return textView;
         }
@@ -116,12 +124,10 @@ abstract class CustomBar extends LinearLayout {
                 res.findItemInTheme(BridgeContext.createFrameworkAttrReference(themeEntryName));
         value = res.resolveResValue(value);
 
-        if (!(value instanceof StyleResourceValue)) {
+        if (!(value instanceof StyleResourceValue style)) {
             return;
         }
 
-        StyleResourceValue style = (StyleResourceValue) value;
-
         // get the background
         ResourceValue backgroundValue = res.findItemInStyle(style,
                 BridgeContext.createFrameworkAttrReference("background"));
@@ -139,8 +145,7 @@ abstract class CustomBar extends LinearLayout {
             ResourceValue textStyleValue = res.findItemInStyle(style,
                     BridgeContext.createFrameworkAttrReference("titleTextStyle"));
             textStyleValue = res.resolveResValue(textStyleValue);
-            if (textStyleValue instanceof StyleResourceValue) {
-                StyleResourceValue textStyle = (StyleResourceValue) textStyleValue;
+            if (textStyleValue instanceof StyleResourceValue textStyle) {
 
                 ResourceValue textSize = res.findItemInStyle(textStyle,
                         BridgeContext.createFrameworkAttrReference("textSize"));
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBar.java b/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBar.java
index e08f5238ea..86afb2072e 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBar.java
@@ -50,7 +50,7 @@ public class FrameworkActionBar extends BridgeActionBar {
     private static final String LAYOUT_ATTR_NAME = "windowActionBarFullscreenDecorLayout";
 
     // The Action Bar
-    @NonNull private FrameworkActionBarWrapper mActionBar;
+    @NonNull private final FrameworkActionBarWrapper mActionBar;
 
     // A fake parent for measuring views.
     @Nullable private ViewGroup mMeasureParent;
@@ -66,7 +66,7 @@ public class FrameworkActionBar extends BridgeActionBar {
         mActionBar = FrameworkActionBarWrapper.getActionBarWrapper(context, getCallBack(),
                 decorContent);
 
-        FrameLayout contentRoot = (FrameLayout) decorContent.findViewById(android.R.id.content);
+        FrameLayout contentRoot = decorContent.findViewById(android.R.id.content);
 
         // If something went wrong and we were not able to initialize the content root,
         // just add a frame layout inside this and return.
@@ -155,11 +155,11 @@ public class FrameworkActionBar extends BridgeActionBar {
         layoutParams.setMarginEnd(getPixelValue("5dp", metrics));
         listView.setLayoutParams(layoutParams);
         listView.setAdapter(adapter);
-        final TypedArray a = mActionBar.getPopupContext().obtainStyledAttributes(null,
-                R.styleable.PopupWindow, R.attr.popupMenuStyle, 0);
-        listView.setBackground(a.getDrawable(R.styleable.PopupWindow_popupBackground));
-        listView.setDivider(a.getDrawable(R.attr.actionBarDivider));
-        a.recycle();
+        try (final TypedArray a = mActionBar.getPopupContext().obtainStyledAttributes(null,
+                R.styleable.PopupWindow, R.attr.popupMenuStyle, 0)) {
+            listView.setBackground(a.getDrawable(R.styleable.PopupWindow_popupBackground));
+            listView.setDivider(a.getDrawable(R.attr.actionBarDivider));
+        }
         listView.setElevation(mActionBar.getMenuPopupElevation());
         assert mEnclosingLayout != null : "Unable to find view to attach ActionMenuPopup.";
         mEnclosingLayout.addView(listView);
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBarWrapper.java b/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBarWrapper.java
index 9811af4ec1..bcf7fa120b 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBarWrapper.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/FrameworkActionBarWrapper.java
@@ -178,7 +178,7 @@ public abstract class FrameworkActionBarWrapper {
         @NonNull
         private final Toolbar mToolbar;  // This is the view.
 
-        ToolbarWrapper(@NonNull BridgeContext context, @NonNull ActionBarCallback callback,
+        private ToolbarWrapper(@NonNull BridgeContext context, @NonNull ActionBarCallback callback,
                 @NonNull Toolbar toolbar) {
             super(context, callback, new ToolbarActionBar(toolbar, "", new WindowCallback()));
             mToolbar = toolbar;
@@ -246,7 +246,7 @@ public abstract class FrameworkActionBarWrapper {
         @NonNull private final View mDecorContentRoot;
         private MenuBuilder mMenuBuilder;
 
-        public WindowActionBarWrapper(@NonNull BridgeContext context,
+        private WindowActionBarWrapper(@NonNull BridgeContext context,
                 @NonNull ActionBarCallback callback, @NonNull View decorContentRoot,
                 @NonNull ActionBarView actionBarView) {
             super(context, callback, new WindowDecorActionBar(decorContentRoot));
@@ -267,7 +267,7 @@ public abstract class FrameworkActionBarWrapper {
             }
 
             // Set action bar to be split, if needed.
-            ViewGroup splitView = (ViewGroup) mDecorContentRoot.findViewById(R.id.split_action_bar);
+            ViewGroup splitView = mDecorContentRoot.findViewById(R.id.split_action_bar);
             if (splitView != null) {
                 mActionBarView.setSplitView(splitView);
                 Resources res = mContext.getResources();
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/NavigationBar.java b/bridge/src/com/android/layoutlib/bridge/bars/NavigationBar.java
index a244e2b535..6bc148cc05 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/NavigationBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/NavigationBar.java
@@ -17,6 +17,7 @@
 package com.android.layoutlib.bridge.bars;
 
 import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.layoutlib.bridge.impl.ResourceHelper;
 import com.android.resources.Density;
 
 import android.util.DisplayMetrics;
@@ -24,6 +25,8 @@ import android.view.View;
 import android.widget.LinearLayout;
 import android.widget.TextView;
 
+import static com.android.layoutlib.bridge.bars.Config.getNavIconType;
+
 public class NavigationBar extends CustomBar {
 
     /** Navigation bar background color attribute name. */
@@ -38,21 +41,31 @@ public class NavigationBar extends CustomBar {
     private static final int WIDTH_DEFAULT = 36;
     private static final int WIDTH_SW360 = 40;
     private static final int WIDTH_SW600 = 48;
-    protected static final String LAYOUT_XML = "navigation_bar.xml";
+    private static final String LAYOUT_XML = "navigation_bar.xml";
     private static final String LAYOUT_600DP_XML = "navigation_bar600dp.xml";
 
     public NavigationBar(BridgeContext context, Density density, int orientation, boolean isRtl,
-      boolean rtlEnabled, int simulatedPlatformVersion, boolean quickStepEnabled) {
-        this(context, density, orientation, isRtl, rtlEnabled, simulatedPlatformVersion,
-          getShortestWidth(context)>= 600 ? LAYOUT_600DP_XML : LAYOUT_XML, quickStepEnabled);
+            boolean rtlEnabled, boolean isEdgeToEdge, int simulatedPlatformVersion,
+            boolean quickStepEnabled) {
+        this(context, density, orientation, isRtl, rtlEnabled, isEdgeToEdge,
+                simulatedPlatformVersion,
+                getShortestWidth(context) >= 600 ? LAYOUT_600DP_XML : LAYOUT_XML, quickStepEnabled);
     }
 
-    protected NavigationBar(BridgeContext context, Density density, int orientation, boolean isRtl,
-      boolean rtlEnabled, int simulatedPlatformVersion, String layoutPath, boolean quickStepEnabled) {
+    private NavigationBar(BridgeContext context, Density density, int orientation, boolean isRtl,
+            boolean rtlEnabled, boolean isEdgeToEdge, int simulatedPlatformVersion,
+            String layoutPath, boolean quickStepEnabled) {
         super(context, orientation, layoutPath, simulatedPlatformVersion);
 
-        int color = getBarColor(ATTR_COLOR, ATTR_TRANSLUCENT);
-        setBackgroundColor(color == 0 ? 0xFF000000 : color);
+        boolean isLightTheme =
+                ResourceHelper.getBooleanThemeFrameworkAttrValue(context.getRenderResources(),
+                        "isLightTheme", false);
+        if (isEdgeToEdge) {
+            setBackgroundColor(isLightTheme ? 0xe6ffffff : 0x66000000);
+        } else {
+            int color = getBarColor(ATTR_COLOR, ATTR_TRANSLUCENT);
+            setBackgroundColor(color == 0 ? 0xFF000000 : color);
+        }
 
         // Cannot access the inside items through id because no R.id values have been
         // created for them.
@@ -66,17 +79,17 @@ public class NavigationBar extends CustomBar {
             recent = 1;
         }
 
+        int iconColor = isLightTheme ? DARK_ICON_COLOR : LIGHT_ICON_COLOR;
+        String ext = getNavIconType(simulatedPlatformVersion);
         //noinspection SpellCheckingInspection
-        loadIcon(back,
-                quickStepEnabled ? "ic_sysbar_back_quick_step.png" : "ic_sysbar_back.png",
-                density, isRtl);
+        loadIcon(back, (quickStepEnabled ? "ic_sysbar_back_quick_step." : "ic_sysbar_back.") + ext,
+                density, isRtl, iconColor);
         //noinspection SpellCheckingInspection
-        loadIcon(3, quickStepEnabled ? "ic_sysbar_home_quick_step.png" : "ic_sysbar_home.png",
-                density,
-                isRtl);
+        loadIcon(3, (quickStepEnabled ? "ic_sysbar_home_quick_step." : "ic_sysbar_home.") + ext,
+                density, isRtl, iconColor);
         if (!quickStepEnabled) {
             //noinspection SpellCheckingInspection
-            loadIcon(recent, "ic_sysbar_recent.png", density, isRtl);
+            loadIcon(recent, "ic_sysbar_recent." + ext, density, isRtl, iconColor);
         }
         setupNavBar(context, orientation);
     }
@@ -99,7 +112,7 @@ public class NavigationBar extends CustomBar {
     }
 
     private static void setSize(BridgeContext context, View view, int orientation, int size) {
-        size *= context.getMetrics().density;
+        size = (int) (size * context.getMetrics().density);
         LayoutParams layoutParams = (LayoutParams) view.getLayoutParams();
         if (orientation == HORIZONTAL) {
             layoutParams.width = size;
@@ -109,7 +122,7 @@ public class NavigationBar extends CustomBar {
         view.setLayoutParams(layoutParams);
     }
 
-    protected int getSidePadding(float sw) {
+    private int getSidePadding(float sw) {
         if (sw >= 400) {
             return PADDING_WIDTH_SW400;
         }
@@ -131,8 +144,7 @@ public class NavigationBar extends CustomBar {
 
     private static float getShortestWidth(BridgeContext context) {
         DisplayMetrics metrics = context.getMetrics();
-        float sw = metrics.widthPixels < metrics.heightPixels ?
-                metrics.widthPixels : metrics.heightPixels;
+        float sw = Math.min(metrics.widthPixels, metrics.heightPixels);
         sw /= metrics.density;
         return sw;
     }
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
index 68423337a0..0b3caebe57 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
@@ -18,81 +18,72 @@ package com.android.layoutlib.bridge.bars;
 
 import com.android.ide.common.rendering.api.ILayoutLog;
 import com.android.ide.common.rendering.api.RenderResources;
-import com.android.ide.common.rendering.api.ResourceNamespace;
+import com.android.internal.R;
 import com.android.layoutlib.bridge.Bridge;
 import com.android.layoutlib.bridge.android.BridgeContext;
-import com.android.layoutlib.bridge.android.BridgeXmlBlockParser;
-import com.android.layoutlib.bridge.impl.ParserFactory;
 import com.android.layoutlib.bridge.impl.ResourceHelper;
-import com.android.layoutlib.bridge.resources.IconLoader;
 import com.android.resources.Density;
 
-import org.xmlpull.v1.XmlPullParserException;
-
 import android.content.Context;
-import android.content.pm.ApplicationInfo;
-import android.graphics.drawable.Drawable;
-import android.util.AttributeSet;
+import android.graphics.Color;
+import android.graphics.Insets;
+import android.graphics.PixelFormat;
+import android.graphics.Rect;
+import android.view.Display;
+import android.view.DisplayCutout;
+import android.view.DisplayInfo;
 import android.view.Gravity;
+import android.view.InsetsFrameProvider;
+import android.view.Surface;
 import android.view.View;
+import android.view.ViewGroup;
+import android.view.WindowManager;
 import android.widget.ImageView;
 import android.widget.LinearLayout;
 import android.widget.TextView;
 
-import java.io.IOException;
-import java.io.InputStream;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.stream.Stream;
 
 import static android.graphics.Color.WHITE;
 import static android.os._Original_Build.VERSION_CODES.M;
+import static android.view.Surface.ROTATION_0;
+import static android.view.WindowInsets.Type.mandatorySystemGestures;
+import static android.view.WindowInsets.Type.statusBars;
+import static android.view.WindowInsets.Type.tappableElement;
+import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+import static android.view.WindowManager.LayoutParams.PRIVATE_FLAG_COLOR_SPACE_AGNOSTIC;
 import static com.android.layoutlib.bridge.bars.Config.getTimeColor;
 import static com.android.layoutlib.bridge.bars.Config.isGreaterOrEqual;
 
 public class StatusBar extends CustomBar {
 
-    private final int mSimulatedPlatformVersion;
-    /**
-     * Color corresponding to light_mode_icon_color_single_tone
-     * from frameworks/base/packages/SettingsLib/res/values/colors.xml
-     */
-    private static final int LIGHT_ICON_COLOR = 0xffffffff;
-    /**
-     * Color corresponding to dark_mode_icon_color_single_tone
-     * from frameworks/base/packages/SettingsLib/res/values/colors.xml
-     */
-    private static final int DARK_ICON_COLOR = 0x99000000;
     /** Status bar background color attribute name. */
     private static final String ATTR_COLOR = "statusBarColor";
     /** Attribute for translucency property. */
     public static final String ATTR_TRANSLUCENT = "windowTranslucentStatus";
 
-    /**
-     * Constructor to be used when creating the {@link StatusBar} as a regular control. This
-     * is currently used by the theme editor.
-     */
-    @SuppressWarnings("UnusedParameters")
-    public StatusBar(Context context, AttributeSet attrs) {
-        this((BridgeContext) context,
-                Density.create(((BridgeContext) context).getMetrics().densityDpi),
-                ((BridgeContext) context).getConfiguration().getLayoutDirection() ==
-                        View.LAYOUT_DIRECTION_RTL,
-                (context.getApplicationInfo().flags & ApplicationInfo.FLAG_SUPPORTS_RTL) != 0,
-                context.getApplicationInfo().targetSdkVersion);
-    }
+    private DisplayCutout mDisplayCutout;
+    private int mStatusBarHeight;
 
     @SuppressWarnings("UnusedParameters")
     public StatusBar(BridgeContext context, Density density, boolean isRtl, boolean rtlEnabled,
-            int simulatedPlatformVersion) {
+            boolean isEdgeToEdge, int simulatedPlatformVersion) {
         // FIXME: if direction is RTL but it's not enabled in application manifest, mirror this bar.
         super(context, LinearLayout.HORIZONTAL, "status_bar.xml", simulatedPlatformVersion);
-        mSimulatedPlatformVersion = simulatedPlatformVersion;
 
         // FIXME: use FILL_H?
         setGravity(Gravity.START | Gravity.TOP | Gravity.RIGHT);
 
-        int color = getBarColor(ATTR_COLOR, ATTR_TRANSLUCENT);
-        setBackgroundColor(color == 0 ? Config.getStatusBarColor(simulatedPlatformVersion) : color);
+        int backgroundColor;
+        if (isEdgeToEdge) {
+            backgroundColor = Color.TRANSPARENT;
+        } else {
+            int color = getBarColor(ATTR_COLOR, ATTR_TRANSLUCENT);
+            backgroundColor = color == 0 ? Config.getStatusBarColor(simulatedPlatformVersion) : color;
+        }
+        setBackgroundColor(backgroundColor);
 
         List<ImageView> icons = new ArrayList<>(2);
         TextView clockView = null;
@@ -112,7 +103,8 @@ public class StatusBar extends CustomBar {
             return;
         }
 
-        int foregroundColor = getForegroundColor(simulatedPlatformVersion);
+        int foregroundColor =
+                isEdgeToEdge ? DARK_ICON_COLOR : getForegroundColor(simulatedPlatformVersion);
         // Cannot access the inside items through id because no R.id values have been
         // created for them.
         // We do know the order though.
@@ -148,40 +140,144 @@ public class StatusBar extends CustomBar {
     }
 
     @Override
-    protected ImageView loadIcon(ImageView imageView, String iconName, Density density, int color) {
-        if (!iconName.endsWith(".xml")) {
-            return super.loadIcon(imageView, iconName, density, color);
+    protected TextView getStyleableTextView() {
+        return null;
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/statusbar/window/StatusBarWindowController.java
+    public WindowManager.LayoutParams getBarLayoutParams() {
+        return getBarLayoutParamsForRotation(mContext.getDisplay().getRotation());
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/statusbar/window/StatusBarWindowController.java
+    private WindowManager.LayoutParams getBarLayoutParamsForRotation(int rotation) {
+        int height = getStatusBarHeightForRotation(mContext, rotation);
+        WindowManager.LayoutParams lp = createWindowParams(height);
+        final InsetsFrameProvider gestureInsetsProvider =
+                new InsetsFrameProvider(this, 0, mandatorySystemGestures());
+        final int safeTouchRegionHeight = mContext.getResources().getDimensionPixelSize(
+                com.android.internal.R.dimen.display_cutout_touchable_region_size);
+        if (safeTouchRegionHeight > 0) {
+            gestureInsetsProvider.setMinimalInsetsSizeInDisplayCutoutSafe(
+                    Insets.of(0, safeTouchRegionHeight, 0, 0));
         }
+        lp.providedInsets = new InsetsFrameProvider[]{
+                new InsetsFrameProvider(this, 0, statusBars()).setInsetsSize(getInsets(height)),
+                new InsetsFrameProvider(this, 0, tappableElement()).setInsetsSize(
+                        getInsets(height)), gestureInsetsProvider};
+        return lp;
 
-        // The xml is stored only in xhdpi.
-        IconLoader iconLoader = new IconLoader(iconName, Density.XHIGH,
-                mSimulatedPlatformVersion, null);
-        InputStream stream = iconLoader.getIcon();
-
-        if (stream != null) {
-            try {
-                BridgeXmlBlockParser parser =
-                        new BridgeXmlBlockParser(
-                                ParserFactory.create(stream, iconName),
-                                (BridgeContext) mContext,
-                                ResourceNamespace.ANDROID);
-                Drawable drawable = Drawable.createFromXml(mContext.getResources(), parser);
-                drawable.setTint(color);
-                imageView.setImageDrawable(drawable);
-            } catch (XmlPullParserException e) {
-                Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Unable to draw wifi icon", e,
-                        null, null);
-            } catch (IOException e) {
-                Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Unable to draw wifi icon", e,
-                        null, null);
-            }
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/statusbar/window/StatusBarWindowController.java
+    private static int getStatusBarHeightForRotation(Context context,
+            @Surface.Rotation int targetRot) {
+        final Display display = context.getDisplay();
+        final DisplayCutout cutout = display.getCutout();
+        DisplayInfo info = new DisplayInfo();
+        display.getDisplayInfo(info);
+        Insets insets;
+        Insets waterfallInsets;
+        if (cutout == null) {
+            insets = Insets.NONE;
+            waterfallInsets = Insets.NONE;
+        } else {
+            DisplayCutout rotated =
+                    cutout.getRotated(info.logicalWidth, info.logicalHeight, ROTATION_0, targetRot);
+            insets = Insets.of(rotated.getSafeInsets());
+            waterfallInsets = rotated.getWaterfallInsets();
         }
+        final int defaultSize =
+                context.getResources().getDimensionPixelSize(R.dimen.status_bar_height_default);
+        // The status bar height should be:
+        // Max(top cutout size, (status bar default height + waterfall top size))
+        return Math.max(insets.top, defaultSize + waterfallInsets.top);
+    }
+
+    private static WindowManager.LayoutParams createWindowParams(int height) {
+        WindowManager.LayoutParams lp =
+                new WindowManager.LayoutParams(WindowManager.LayoutParams.MATCH_PARENT, height,
+                        WindowManager.LayoutParams.TYPE_STATUS_BAR,
+                        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
+                                WindowManager.LayoutParams.FLAG_SPLIT_TOUCH |
+                                WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS,
+                        PixelFormat.TRANSLUCENT);
+        lp.privateFlags |= PRIVATE_FLAG_COLOR_SPACE_AGNOSTIC;
+        lp.gravity = Gravity.TOP;
+        lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+        return lp;
+    }
 
-        return imageView;
+    private static Insets getInsets(int height) {
+        return Insets.of(0, height, 0, 0);
     }
 
+    // ----------------------------------------------------------------------------------------
+    // All the methods that follow deal with taking care of the cutout when laying
+    // out the Status Bar.
+    // Copied/adapted from
+    // packages/SystemUI/src/com/android/systemui/statusbar/phone/PhoneStatusBarView.java
     @Override
-    protected TextView getStyleableTextView() {
-        return null;
+    protected void onAttachedToWindow() {
+        super.onAttachedToWindow();
+        final Display display = getDisplay();
+        DisplayInfo info = new DisplayInfo();
+        display.getDisplayInfo(info);
+        mDisplayCutout = info.displayCutout;
+        if (mDisplayCutout != null) {
+            updateStatusBarHeight();
+            updateSafeInsets();
+        }
+    }
+
+    @Override
+    protected void onDetachedFromWindow() {
+        super.onDetachedFromWindow();
+        mDisplayCutout = null;
+    }
+
+    private void updateStatusBarHeight() {
+        final int waterfallTopInset =
+                mDisplayCutout == null ? 0 : mDisplayCutout.getWaterfallInsets().top;
+        ViewGroup.LayoutParams layoutParams = getLayoutParams();
+        mStatusBarHeight = getStatusBarHeightForRotation(mContext, mContext.getDisplay().getRotation());
+        layoutParams.height = mStatusBarHeight - waterfallTopInset;
+        setLayoutParams(layoutParams);
+    }
+
+    private void updateSafeInsets() {
+        Insets insets = getStatusBarContentInsets();
+        setPadding(
+                insets.left,
+                insets.top,
+                insets.right,
+                getPaddingBottom());
+    }
+
+    private Insets getStatusBarContentInsets() {
+        Rect screenBounds =
+                getContext().getResources().getConfiguration().windowConfiguration.getMaxBounds();
+        int width = screenBounds.width();
+        List<Rect> cutoutRects = Stream.of(mDisplayCutout.getBoundingRectLeft(),
+                mDisplayCutout.getBoundingRectRight(),
+                mDisplayCutout.getBoundingRectTop()).filter(rect -> !rect.isEmpty()).toList();
+        if (cutoutRects.isEmpty()) {
+            return Insets.NONE;
+        }
+
+        int leftMargin = 0;
+        int rightMargin = 0;
+        Rect sbRect = new Rect(0, 0, width, mStatusBarHeight);
+        for (Rect cutoutRect : cutoutRects) {
+            if (!sbRect.intersects(0, cutoutRect.top, width, cutoutRect.bottom)) {
+                continue;
+            }
+            if (cutoutRect.left == 0) {
+                leftMargin = Math.max(leftMargin, cutoutRect.width());
+            } else if (cutoutRect.right == width) {
+                rightMargin = Math.max(rightMargin, cutoutRect.width());
+            }
+        }
+        return Insets.of(leftMargin, 0, rightMargin, 0);
     }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/TitleBar.java b/bridge/src/com/android/layoutlib/bridge/bars/TitleBar.java
index 16578fbbf9..9c5c7b1623 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/TitleBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/TitleBar.java
@@ -18,14 +18,12 @@ package com.android.layoutlib.bridge.bars;
 
 import com.android.layoutlib.bridge.android.BridgeContext;
 
-import org.xmlpull.v1.XmlPullParserException;
-
 import android.widget.LinearLayout;
 import android.widget.TextView;
 
 public class TitleBar extends CustomBar {
 
-    private TextView mTextView;
+    private final TextView mTextView;
 
     public TitleBar(BridgeContext context, String label, int simulatedPlatformVersion) {
         super(context, LinearLayout.HORIZONTAL, "title_bar.xml", simulatedPlatformVersion);
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/DelegateManager.java b/bridge/src/com/android/layoutlib/bridge/impl/DelegateManager.java
index 398c260b70..279c856630 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/DelegateManager.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/DelegateManager.java
@@ -32,7 +32,7 @@ import java.util.concurrent.atomic.AtomicLong;
 /**
  * Manages native delegates.
  *
- * This is used in conjunction with layoublib_create: certain Android java classes are mere
+ * This is used in conjunction with layoutlib_create: certain Android java classes are mere
  * wrappers around a heavily native based implementation, and we need a way to run these classes
  * in our Android Studio rendering framework without bringing all the native code from the Android
  * platform.
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/DisplayCutoutView.java b/bridge/src/com/android/layoutlib/bridge/impl/DisplayCutoutView.java
index 48a8425371..dc7a94c360 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/DisplayCutoutView.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/DisplayCutoutView.java
@@ -22,61 +22,76 @@ import android.graphics.Color;
 import android.graphics.Paint;
 import android.graphics.Path;
 import android.graphics.Rect;
-import android.graphics.Region;
 import android.view.DisplayCutout;
+import android.view.DisplayCutout.BoundsPosition;
 import android.view.DisplayInfo;
 import android.view.Gravity;
 import android.view.View;
+import android.view.ViewGroup.LayoutParams;
+import android.widget.FrameLayout;
 
-class DisplayCutoutView extends View {
+import java.util.ArrayList;
+import java.util.List;
+
+import static android.view.DisplayCutout.BOUNDS_POSITION_BOTTOM;
+import static android.view.DisplayCutout.BOUNDS_POSITION_LEFT;
+import static android.view.DisplayCutout.BOUNDS_POSITION_RIGHT;
+import static android.view.DisplayCutout.BOUNDS_POSITION_TOP;
 
+class DisplayCutoutView extends View {
     private final DisplayInfo mInfo = new DisplayInfo();
     private final Paint mPaint = new Paint();
-    private final Region mBounds = new Region();
+    private final List<Rect> mBounds = new ArrayList<>();
     private final Rect mBoundingRect = new Rect();
-    private final Path mBoundingPath = new Path();
+    private final Path cutoutPath = new Path();
     private final int[] mLocation = new int[2];
-    private final boolean mStart;
+    private final int mRotation;
 
-    public DisplayCutoutView(Context context, boolean start) {
+    private int mColor = Color.BLACK;
+    @BoundsPosition
+    private final int mInitialPosition;
+    private int mPosition;
+
+    public DisplayCutoutView(Context context, @BoundsPosition int pos) {
         super(context);
-        mStart = start;
+        mInitialPosition = pos;
+        mPaint.setColor(mColor);
+        mPaint.setStyle(Paint.Style.FILL);
+        mRotation = mInfo.rotation;
     }
 
-    @Override
-    protected void onAttachedToWindow() {
-        super.onAttachedToWindow();
-        update();
+    public void setColor(int color) {
+        if (color == mColor) {
+            return;
+        }
+        mColor = color;
+        mPaint.setColor(mColor);
+        invalidate();
     }
 
     @Override
-    protected void onDetachedFromWindow() {
-        super.onDetachedFromWindow();
+    protected void onAttachedToWindow() {
+        super.onAttachedToWindow();
+        updateCutout();
     }
 
-    @Override
-    protected void onDraw(Canvas canvas) {
-        super.onDraw(canvas);
-        getLocationOnScreen(mLocation);
-        canvas.translate(-mLocation[0], -mLocation[1]);
-        if (!mBoundingPath.isEmpty()) {
-            mPaint.setColor(Color.BLACK);
-            mPaint.setStyle(Paint.Style.FILL);
-            canvas.drawPath(mBoundingPath, mPaint);
+    private void updateCutout() {
+        if (!isAttachedToWindow()) {
+            return;
         }
-    }
-
-    private void update() {
+        mPosition = getBoundPositionFromRotation(mInitialPosition, mRotation);
         requestLayout();
         getDisplay().getDisplayInfo(mInfo);
-        mBounds.setEmpty();
+        mBounds.clear();
         mBoundingRect.setEmpty();
-        mBoundingPath.reset();
+        cutoutPath.reset();
         int newVisible;
         if (hasCutout()) {
-            mBounds.set(mInfo.displayCutout.getBoundingRectTop());
+            mBounds.addAll(mInfo.displayCutout.getBoundingRects());
             localBounds(mBoundingRect);
-            mBounds.getBoundaryPath(mBoundingPath);
+            updateGravity();
+            updateBoundingPath();
+            invalidate();
             newVisible = VISIBLE;
         } else {
             newVisible = GONE;
@@ -86,18 +101,49 @@ class DisplayCutoutView extends View {
         }
     }
 
+    private static int getBoundPositionFromRotation(@BoundsPosition int pos, int rotation) {
+        return (pos - rotation) < 0
+                ? pos - rotation + DisplayCutout.BOUNDS_POSITION_LENGTH
+                : pos - rotation;
+    }
+
+    private void updateBoundingPath() {
+        final Path path = mInfo.displayCutout.getCutoutPath();
+        if (path != null) {
+            cutoutPath.set(path);
+        } else {
+            cutoutPath.reset();
+        }
+    }
+
+    private void updateGravity() {
+        LayoutParams lp = getLayoutParams();
+        if (lp instanceof FrameLayout.LayoutParams) {
+            FrameLayout.LayoutParams flp = (FrameLayout.LayoutParams) lp;
+            int newGravity = getGravity(mInfo.displayCutout);
+            if (flp.gravity != newGravity) {
+                flp.gravity = newGravity;
+                setLayoutParams(flp);
+            }
+        }
+    }
+
     private boolean hasCutout() {
         final DisplayCutout displayCutout = mInfo.displayCutout;
         if (displayCutout == null) {
             return false;
         }
-        if (mStart) {
-            return displayCutout.getSafeInsetLeft() > 0
-                    || displayCutout.getSafeInsetTop() > 0;
-        } else {
-            return displayCutout.getSafeInsetRight() > 0
-                    || displayCutout.getSafeInsetBottom() > 0;
+
+        if (mPosition == BOUNDS_POSITION_LEFT) {
+            return !displayCutout.getBoundingRectLeft().isEmpty();
+        } else if (mPosition == BOUNDS_POSITION_TOP) {
+            return !displayCutout.getBoundingRectTop().isEmpty();
+        } else if (mPosition == BOUNDS_POSITION_BOTTOM) {
+            return !displayCutout.getBoundingRectBottom().isEmpty();
+        } else if (mPosition == BOUNDS_POSITION_RIGHT) {
+            return !displayCutout.getBoundingRectRight().isEmpty();
         }
+        return false;
     }
 
     @Override
@@ -111,48 +157,57 @@ class DisplayCutoutView extends View {
                 resolveSizeAndState(mBoundingRect.height(), heightMeasureSpec, 0));
     }
 
-    public static void boundsFromDirection(DisplayCutout displayCutout, int gravity, Rect out) {
-        Region bounds = new Region(displayCutout.getBoundingRectTop());
+    private static void boundsFromDirection(DisplayCutout displayCutout, int gravity, Rect out) {
         switch (gravity) {
             case Gravity.TOP:
-                bounds.op(0, 0, Integer.MAX_VALUE, displayCutout.getSafeInsetTop(),
-                        Region.Op.INTERSECT);
-                out.set(bounds.getBounds());
+                out.set(displayCutout.getBoundingRectTop());
                 break;
             case Gravity.LEFT:
-                bounds.op(0, 0, displayCutout.getSafeInsetLeft(), Integer.MAX_VALUE,
-                        Region.Op.INTERSECT);
-                out.set(bounds.getBounds());
+                out.set(displayCutout.getBoundingRectLeft());
                 break;
             case Gravity.BOTTOM:
-                bounds.op(0, displayCutout.getSafeInsetTop() + 1, Integer.MAX_VALUE,
-                        Integer.MAX_VALUE, Region.Op.INTERSECT);
-                out.set(bounds.getBounds());
+                out.set(displayCutout.getBoundingRectBottom());
                 break;
             case Gravity.RIGHT:
-                bounds.op(displayCutout.getSafeInsetLeft() + 1, 0, Integer.MAX_VALUE,
-                        Integer.MAX_VALUE, Region.Op.INTERSECT);
-                out.set(bounds.getBounds());
+                out.set(displayCutout.getBoundingRectRight());
                 break;
+            default:
+                out.setEmpty();
         }
-        bounds.recycle();
     }
 
     private void localBounds(Rect out) {
-        final DisplayCutout displayCutout = mInfo.displayCutout;
+        DisplayCutout displayCutout = mInfo.displayCutout;
+        boundsFromDirection(displayCutout, getGravity(displayCutout), out);
+    }
 
-        if (mStart) {
-            if (displayCutout.getSafeInsetLeft() > 0) {
-                boundsFromDirection(displayCutout, Gravity.LEFT, out);
-            } else if (displayCutout.getSafeInsetTop() > 0) {
-                boundsFromDirection(displayCutout, Gravity.TOP, out);
+    private int getGravity(DisplayCutout displayCutout) {
+        if (mPosition == BOUNDS_POSITION_LEFT) {
+            if (!displayCutout.getBoundingRectLeft().isEmpty()) {
+                return Gravity.LEFT;
             }
-        } else {
-            if (displayCutout.getSafeInsetRight() > 0) {
-                boundsFromDirection(displayCutout, Gravity.RIGHT, out);
-            } else if (displayCutout.getSafeInsetBottom() > 0) {
-                boundsFromDirection(displayCutout, Gravity.BOTTOM, out);
+        } else if (mPosition == BOUNDS_POSITION_TOP) {
+            if (!displayCutout.getBoundingRectTop().isEmpty()) {
+                return Gravity.TOP;
+            }
+        } else if (mPosition == BOUNDS_POSITION_BOTTOM) {
+            if (!displayCutout.getBoundingRectBottom().isEmpty()) {
+                return Gravity.BOTTOM;
+            }
+        } else if (mPosition == BOUNDS_POSITION_RIGHT) {
+            if (!displayCutout.getBoundingRectRight().isEmpty()) {
+                return Gravity.RIGHT;
             }
         }
+        return Gravity.NO_GRAVITY;
+    }
+
+    public void onDraw(Canvas canvas) {
+        super.onDraw(canvas);
+        canvas.save();
+        getLocationOnScreen(mLocation);
+        canvas.translate(-mLocation[0], -mLocation[1]);
+        canvas.drawPath(cutoutPath, mPaint);
+        canvas.restore();
     }
 }
\ No newline at end of file
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/Layout.java b/bridge/src/com/android/layoutlib/bridge/impl/Layout.java
index 63b99cf8af..4f0bf8f064 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/Layout.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/Layout.java
@@ -38,26 +38,43 @@ import com.android.resources.ScreenOrientation;
 
 import android.R.id;
 import android.annotation.NonNull;
-import android.graphics.Color;
+import android.annotation.Nullable;
 import android.graphics.Point;
 import android.graphics.Rect;
 import android.graphics.drawable.Drawable;
 import android.util.DisplayMetrics;
 import android.util.TypedValue;
 import android.view.AttachInfo_Accessor;
+import android.view.DisplayCutout.BoundsPosition;
+import android.view.InsetsFrameProvider;
+import android.view.Surface;
 import android.view.View;
+import android.view.ViewGroup;
 import android.view.ViewRootImpl;
 import android.view.ViewRootImpl_Accessor;
+import android.view.WindowManager;
 import android.widget.FrameLayout;
 import android.widget.LinearLayout;
 import android.widget.RelativeLayout;
 
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+
+import static android.os._Original_Build.VERSION_CODES.VANILLA_ICE_CREAM;
+import static android.view.DisplayCutout.BOUNDS_POSITION_LEFT;
+import static android.view.DisplayCutout.BOUNDS_POSITION_TOP;
 import static android.view.ViewGroup.LayoutParams.MATCH_PARENT;
 import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
+import static android.widget.LinearLayout.HORIZONTAL;
 import static android.widget.LinearLayout.VERTICAL;
+import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_EDGE_TO_EDGE;
 import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_USE_GESTURE_NAV;
+import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_SHOW_CUTOUT;
+import static com.android.layoutlib.bridge.bars.Config.isGreaterOrEqual;
 import static com.android.layoutlib.bridge.impl.ResourceHelper.getBooleanThemeFrameworkAttrValue;
 import static com.android.layoutlib.bridge.impl.ResourceHelper.getBooleanThemeValue;
+import static com.android.layoutlib.bridge.util.InsetUtil.getNavBarLayoutParamsForRotation;
 
 /**
  * The Layout used to create the system decor.
@@ -93,7 +110,7 @@ import static com.android.layoutlib.bridge.impl.ResourceHelper.getBooleanThemeVa
  *  +--------------------------------------+
  * </pre>
  */
-class Layout extends FrameLayout {
+public class Layout extends FrameLayout {
 
     // Theme attributes used for configuring appearance of the system decor.
     private static final String ATTR_WINDOW_FLOATING = "windowIsFloating";
@@ -123,6 +140,8 @@ class Layout extends FrameLayout {
     // Prefix used with the above ids in order to make them unique in framework namespace.
     private static final String ID_PREFIX = "android_layoutlib_";
 
+    private final List<InsetsFrameProvider> mInsetsFrameProviders = new ArrayList<>();
+
     /**
      * Temporarily store the builder so that it doesn't have to be passed to all methods used
      * during inflation.
@@ -130,9 +149,9 @@ class Layout extends FrameLayout {
     private Builder mBuilder;
 
     /**
-     * SysUI layout
+     * App UI layout
      */
-    private RelativeLayout mSysUiRoot;
+    private final RelativeLayout mAppUiRoot;
 
     /**
      * This holds user's layout.
@@ -163,16 +182,18 @@ class Layout extends FrameLayout {
 
         if (mBuilder.hasNavBar()) {
             navBar = createNavBar(getContext(), mBuilder.useGestureNav(), density, isRtl,
-                    getParams().isRtlSupported(), simulatedPlatformVersion, false);
+                    getParams().isRtlSupported(), mBuilder.mIsEdgeToEdge, simulatedPlatformVersion,
+                    false);
         }
 
         if (builder.hasStatusBar()) {
             statusBar = createStatusBar(getContext(), density, isRtl, getParams().isRtlSupported(),
-                    simulatedPlatformVersion);
+                    mBuilder.mIsEdgeToEdge, simulatedPlatformVersion);
         }
 
         if (mBuilder.hasAppCompatActionBar()) {
-            BridgeActionBar bar = createActionBar(getContext(), getParams(), true);
+            BridgeActionBar bar =
+                    createActionBar(getContext(), getParams(), true, navBar, statusBar);
             mContentRoot = bar.getContentRoot();
             appCompatActionBar = bar.getRootView();
         }
@@ -180,10 +201,11 @@ class Layout extends FrameLayout {
         // Title bar must appear on top of the Action bar
         if (mBuilder.hasTitleBar()) {
             titleBar = createTitleBar(getContext(), getParams().getAppLabel(),
-                    simulatedPlatformVersion);
+                    simulatedPlatformVersion, navBar, statusBar);
         } else if (mBuilder.hasFrameworkActionBar()) {
-            BridgeActionBar bar = createActionBar(getContext(), getParams(), false);
-            if(mContentRoot == null) {
+            BridgeActionBar bar =
+                    createActionBar(getContext(), getParams(), false, navBar, statusBar);
+            if (mContentRoot == null) {
                 // We only set the content root if the AppCompat action bar did not already
                 // provide it
                 mContentRoot = bar.getContentRoot();
@@ -191,15 +213,57 @@ class Layout extends FrameLayout {
             frameworkActionBar = bar.getRootView();
         }
 
-        mSysUiRoot = new RelativeLayout(builder.mContext);
-        addSystemUiViews(titleBar, mContentRoot == null ? (mContentRoot = createContentFrame()) : frameworkActionBar,
-                statusBar, navBar, appCompatActionBar);
-        addView(mSysUiRoot);
-        //addView(createSysUiOverlay(mBuilder.mContext));
+        mAppUiRoot = new RelativeLayout(builder.mContext);
+        addAppUiViews(titleBar,
+                mContentRoot == null ? (mContentRoot = createContentFrame(navBar, statusBar)) :
+                        frameworkActionBar, appCompatActionBar);
+        addView(mAppUiRoot);
+
+        ViewGroup sysUiRoot = buildSysUi(statusBar, navBar,
+                hwConfig.getOrientation() == ScreenOrientation.LANDSCAPE);
+        if (sysUiRoot != null) {
+            addView(sysUiRoot, MATCH_PARENT, MATCH_PARENT);
+        }
         // Done with the builder. Don't hold a reference to it.
         mBuilder = null;
     }
 
+    @Nullable
+    private ViewGroup buildSysUi(@Nullable StatusBar statusBar, @Nullable View navBar,
+            boolean rotated) {
+        if (statusBar == null && navBar == null && !mBuilder.mShowCutout) {
+            return null;
+        }
+
+        FrameLayout sysUiRoot = new FrameLayout(mContext);
+        if (navBar != null && statusBar != null) {
+            if (!mBuilder.useGestureNav() && mBuilder.mNavBarOrientation == VERTICAL) {
+                LinearLayout insideLayout = new LinearLayout(mContext);
+                insideLayout.setOrientation(HORIZONTAL);
+                ViewGroup statusBarContainer = new FrameLayout(mContext);
+                statusBarContainer.addView(statusBar);
+                insideLayout.addView(statusBarContainer,
+                        new LinearLayout.LayoutParams(WRAP_CONTENT, MATCH_PARENT, 1.0f));
+                insideLayout.addView(navBar);
+                sysUiRoot.addView(insideLayout, MATCH_PARENT, MATCH_PARENT);
+            } else {
+                sysUiRoot.addView(statusBar);
+                sysUiRoot.addView(navBar);
+            }
+        } else if (navBar == null) {
+            sysUiRoot.addView(statusBar);
+        } else {
+            sysUiRoot.addView(navBar);
+        }
+
+        if (mBuilder.mShowCutout) {
+            sysUiRoot.addView(
+                    new DisplayCutoutView(mBuilder.mContext, rotated? BOUNDS_POSITION_LEFT : BOUNDS_POSITION_TOP),
+                    MATCH_PARENT, MATCH_PARENT);
+        }
+        return sysUiRoot;
+    }
+
     @Override
     public boolean getChildVisibleRect(View child, Rect r, Point offset, boolean forceParentCheck) {
         return r.intersect(0, 0, getWidth(), getHeight());
@@ -220,31 +284,28 @@ class Layout extends FrameLayout {
     }
 
     @NonNull
-    private static View createSysUiOverlay(@NonNull BridgeContext context) {
-        SysUiOverlay overlay =  new SysUiOverlay(context, 20, 10, 50, 40, 60);
-        overlay.setNotchColor(Color.BLACK);
-        overlay.setLayoutParams(new FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT));
-        return overlay;
-    }
-
-    @NonNull
-    private FrameLayout createContentFrame() {
+    private FrameLayout createContentFrame(@Nullable View navBar, @Nullable StatusBar statusBar) {
         FrameLayout contentRoot = new FrameLayout(getContext());
-        RelativeLayout.LayoutParams params = createSysUiLayoutParams(MATCH_PARENT, MATCH_PARENT);
-        int rule = mBuilder.isNavBarVertical() ? RelativeLayout.START_OF : RelativeLayout.ABOVE;
-        if (mBuilder.hasSolidNavBar()) {
-            params.addRule(rule, getId(ID_NAV_BAR));
-        }
-        int below = -1;
-        if (mBuilder.mAppCompatActionBarSize > 0) {
-            below = getId(ID_APP_COMPAT_ACTION_BAR);
-        } else if (mBuilder.hasFrameworkActionBar() || mBuilder.hasTitleBar()) {
-            below = getId(ID_FRAMEWORK_BAR);
-        } else if (mBuilder.hasSolidStatusBar()) {
-            below = getId(ID_STATUS_BAR);
-        }
-        if (below != -1) {
-            params.addRule(RelativeLayout.BELOW, below);
+        RelativeLayout.LayoutParams params = createAppUiLayoutParams(MATCH_PARENT, MATCH_PARENT);
+        if (navBar != null && mBuilder.hasSolidNavBar()) {
+            if (mBuilder.isNavBarVertical()) {
+                params.bottomMargin = navBar.getLayoutParams().height;
+            } else {
+                params.rightMargin = navBar.getLayoutParams().width;
+            }
+        }
+        if (!mBuilder.mIsEdgeToEdge) {
+            int below = -1;
+            if (mBuilder.mAppCompatActionBarSize > 0) {
+                below = getId(ID_APP_COMPAT_ACTION_BAR);
+            } else if (mBuilder.hasFrameworkActionBar() || mBuilder.hasTitleBar()) {
+                below = getId(ID_FRAMEWORK_BAR);
+            } else if (statusBar != null && mBuilder.hasSolidStatusBar()) {
+                params.topMargin = statusBar.getLayoutParams().height;
+            }
+            if (below != -1) {
+                params.addRule(RelativeLayout.BELOW, below);
+            }
         }
         contentRoot.setLayoutParams(params);
         contentRoot.setId(id.content);
@@ -252,7 +313,7 @@ class Layout extends FrameLayout {
     }
 
     @NonNull
-    private RelativeLayout.LayoutParams createSysUiLayoutParams(int width, int height) {
+    private RelativeLayout.LayoutParams createAppUiLayoutParams(int width, int height) {
         DisplayMetrics metrics = getContext().getResources().getDisplayMetrics();
         if (width > 0) {
             width = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, width, metrics);
@@ -279,6 +340,11 @@ class Layout extends FrameLayout {
         return (BridgeContext) super.getContext();
     }
 
+    @NonNull
+    public List<InsetsFrameProvider> getInsetsFrameProviders() {
+        return mInsetsFrameProviders;
+    }
+
     /**
      * @param isRtl whether the current locale is an RTL locale.
      * @param isRtlSupported whether the applications supports RTL (i.e. has supportsRtl=true in the
@@ -286,34 +352,36 @@ class Layout extends FrameLayout {
      */
     @NonNull
     private StatusBar createStatusBar(BridgeContext context, Density density, boolean isRtl,
-            boolean isRtlSupported, int simulatedPlatformVersion) {
-        StatusBar statusBar =
-                new StatusBar(context, density, isRtl, isRtlSupported, simulatedPlatformVersion);
-        RelativeLayout.LayoutParams params = createSysUiLayoutParams(MATCH_PARENT, mBuilder
-                .mStatusBarSize);
-        if (mBuilder.isNavBarVertical()) {
-            params.addRule(RelativeLayout.START_OF, getId(ID_NAV_BAR));
-        }
-        statusBar.setLayoutParams(params);
+            boolean isRtlSupported, boolean isEdgeToEdge, int simulatedPlatformVersion) {
+        StatusBar statusBar = new StatusBar(context, density, isRtl, isRtlSupported, isEdgeToEdge,
+                simulatedPlatformVersion);
         statusBar.setId(getId(ID_STATUS_BAR));
+        WindowManager.LayoutParams layoutParams = statusBar.getBarLayoutParams();
+        mInsetsFrameProviders.addAll(Arrays.asList(layoutParams.providedInsets));
+        FrameLayout.LayoutParams lparams = new FrameLayout.LayoutParams(layoutParams);
+        lparams.gravity = layoutParams.gravity;
+        statusBar.setLayoutParams(lparams);
         return statusBar;
     }
 
     private BridgeActionBar createActionBar(@NonNull BridgeContext context,
-            @NonNull SessionParams params, boolean appCompatActionBar) {
+            @NonNull SessionParams params, boolean appCompatActionBar, @Nullable View navBar,
+            @Nullable StatusBar statusBar) {
         boolean isMenu = "menu".equals(params.getFlag(RenderParamsFlags.FLAG_KEY_ROOT_TAG));
         String id;
 
         // For the framework action bar, we set the height to MATCH_PARENT only if there is no
         // AppCompat ActionBar below it
         int heightRule = appCompatActionBar || !mBuilder.hasAppCompatActionBar() ? MATCH_PARENT :
-          WRAP_CONTENT;
-        RelativeLayout.LayoutParams layoutParams = createSysUiLayoutParams(MATCH_PARENT, heightRule);
-        int rule = mBuilder.isNavBarVertical() ? RelativeLayout.START_OF : RelativeLayout.ABOVE;
-        if (mBuilder.hasSolidNavBar()) {
+                WRAP_CONTENT;
+        RelativeLayout.LayoutParams layoutParams =
+                createAppUiLayoutParams(MATCH_PARENT, heightRule);
+        if (navBar != null && mBuilder.hasSolidNavBar()) {
             // If there
-            if(rule == RelativeLayout.START_OF || appCompatActionBar || !mBuilder.hasAppCompatActionBar()) {
-                layoutParams.addRule(rule, getId(ID_NAV_BAR));
+            if (mBuilder.isNavBarVertical()) {
+                layoutParams.rightMargin = navBar.getLayoutParams().width;
+            } else if (appCompatActionBar || !mBuilder.hasAppCompatActionBar()) {
+                layoutParams.bottomMargin = navBar.getLayoutParams().height;
             }
         }
 
@@ -325,14 +393,14 @@ class Layout extends FrameLayout {
 
             if (mBuilder.hasTitleBar() || mBuilder.hasFrameworkActionBar()) {
                 layoutParams.addRule(RelativeLayout.BELOW, getId(ID_FRAMEWORK_BAR));
-            } else if (mBuilder.hasSolidStatusBar()) {
-                layoutParams.addRule(RelativeLayout.BELOW, getId(ID_STATUS_BAR));
+            } else if (statusBar != null && mBuilder.hasSolidStatusBar()) {
+                layoutParams.topMargin = statusBar.getLayoutParams().height;
             }
         } else {
             actionBar = new FrameworkActionBar(context, params);
             id = ID_FRAMEWORK_BAR;
-            if (mBuilder.hasSolidStatusBar()) {
-                layoutParams.addRule(RelativeLayout.BELOW, getId(ID_STATUS_BAR));
+            if (statusBar != null && mBuilder.hasSolidStatusBar()) {
+                layoutParams.topMargin = statusBar.getLayoutParams().height;
             }
         }
 
@@ -344,14 +412,15 @@ class Layout extends FrameLayout {
 
     @NonNull
     private TitleBar createTitleBar(BridgeContext context, String title,
-            int simulatedPlatformVersion) {
+            int simulatedPlatformVersion, @Nullable View navBar, @Nullable StatusBar statusBar) {
         TitleBar titleBar = new TitleBar(context, title, simulatedPlatformVersion);
-        RelativeLayout.LayoutParams params = createSysUiLayoutParams(MATCH_PARENT, mBuilder.mTitleBarSize);
-        if (mBuilder.hasSolidStatusBar()) {
-            params.addRule(RelativeLayout.BELOW, getId(ID_STATUS_BAR));
+        RelativeLayout.LayoutParams params =
+                createAppUiLayoutParams(MATCH_PARENT, mBuilder.mTitleBarSize);
+        if (statusBar != null && mBuilder.hasSolidStatusBar()) {
+            params.topMargin = statusBar.getLayoutParams().height;
         }
-        if (mBuilder.isNavBarVertical() && mBuilder.hasSolidNavBar()) {
-            params.addRule(RelativeLayout.START_OF, getId(ID_NAV_BAR));
+        if (navBar != null && mBuilder.isNavBarVertical() && mBuilder.hasSolidNavBar()) {
+            params.rightMargin = navBar.getLayoutParams().width;
         }
         titleBar.setLayoutParams(params);
         titleBar.setId(getId(ID_FRAMEWORK_BAR));
@@ -365,11 +434,10 @@ class Layout extends FrameLayout {
      * manifest and targetSdkVersion >= 17.
      */
     @NonNull
-    private View createNavBar(BridgeContext context, boolean useGestureNav,
-            Density density, boolean isRtl, boolean isRtlSupported, int simulatedPlatformVersion,
-            boolean isQuickStepEnabled) {
-        int orientation = mBuilder.mNavBarOrientation;
-        int size = mBuilder.mNavBarSize;
+    private View createNavBar(BridgeContext context, boolean useGestureNav, Density density,
+            boolean isRtl, boolean isRtlSupported, boolean isEdgeToEdge,
+            int simulatedPlatformVersion, boolean isQuickStepEnabled) {
+        int rotation = Surface.ROTATION_0;
         // Only allow quickstep in the latest version or >= 28
         isQuickStepEnabled = isQuickStepEnabled &&
                 (simulatedPlatformVersion == 0 || simulatedPlatformVersion >= 28);
@@ -377,23 +445,26 @@ class Layout extends FrameLayout {
         if (useGestureNav) {
             navBar = new NavigationHandle(context);
         } else {
-            navBar = new NavigationBar(context, density, orientation, isRtl, isRtlSupported,
-                            simulatedPlatformVersion, isQuickStepEnabled);
-        }
-        boolean isVertical = mBuilder.isNavBarVertical();
-        int w = isVertical ? size : MATCH_PARENT;
-        int h = isVertical ? MATCH_PARENT : size;
-        RelativeLayout.LayoutParams params = createSysUiLayoutParams(w, h);
-        params.addRule(isVertical ? RelativeLayout.ALIGN_PARENT_END : RelativeLayout.ALIGN_PARENT_BOTTOM);
-        navBar.setLayoutParams(params);
+            navBar = new NavigationBar(context, density, mBuilder.mNavBarOrientation, isRtl,
+                    isRtlSupported, isEdgeToEdge, simulatedPlatformVersion, isQuickStepEnabled);
+            if (mBuilder.mNavBarOrientation == VERTICAL) {
+                rotation = Surface.ROTATION_90;
+            }
+        }
+        WindowManager.LayoutParams layoutParams =
+                getNavBarLayoutParamsForRotation(mBuilder.mContext, navBar, rotation);
+        mInsetsFrameProviders.addAll(Arrays.asList(layoutParams.providedInsets));
+        FrameLayout.LayoutParams lparams = new FrameLayout.LayoutParams(layoutParams);
+        lparams.gravity = layoutParams.gravity;
+        navBar.setLayoutParams(lparams);
         navBar.setId(getId(ID_NAV_BAR));
         return navBar;
     }
 
-    private void addSystemUiViews(@NonNull View... views) {
+    private void addAppUiViews(@NonNull View... views) {
         for (View view : views) {
             if (view != null) {
-                mSysUiRoot.addView(view);
+                mAppUiRoot.addView(view);
             }
         }
     }
@@ -435,6 +506,8 @@ class Layout extends FrameLayout {
         private boolean mTranslucentStatus;
         private boolean mTranslucentNav;
         private boolean mUseGestureNav;
+        private boolean mIsEdgeToEdge;
+        private boolean mShowCutout;
 
         public Builder(@NonNull SessionParams params, @NonNull BridgeContext context) {
             mParams = params;
@@ -446,6 +519,10 @@ class Layout extends FrameLayout {
             findBackground();
 
             if (!mParams.isForceNoDecor()) {
+                mIsEdgeToEdge = isGreaterOrEqual(mParams.getSimulatedPlatformVersion(),
+                        VANILLA_ICE_CREAM) ||
+                        Boolean.TRUE.equals(mParams.getFlag(FLAG_KEY_EDGE_TO_EDGE));
+                mShowCutout = Boolean.TRUE.equals(mParams.getFlag(FLAG_KEY_SHOW_CUTOUT));
                 findStatusBar();
                 findFrameworkBar();
                 findAppCompatActionBar();
@@ -598,14 +675,14 @@ class Layout extends FrameLayout {
          * Returns true if the nav bar is present and not translucent.
          */
         private boolean hasSolidNavBar() {
-            return hasNavBar() && !mTranslucentNav;
+            return hasNavBar() && !mTranslucentNav && !mIsEdgeToEdge;
         }
 
         /**
          * Returns true if the status bar is present and not translucent.
          */
         private boolean hasSolidStatusBar() {
-            return hasStatusBar() && !mTranslucentStatus;
+            return hasStatusBar() && !mTranslucentStatus && !mIsEdgeToEdge;
         }
 
         private boolean hasNavBar() {
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/LayoutParserWrapper.java b/bridge/src/com/android/layoutlib/bridge/impl/LayoutParserWrapper.java
index 8c3b128c4b..5352ecefaa 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/LayoutParserWrapper.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/LayoutParserWrapper.java
@@ -27,6 +27,7 @@ import java.io.Reader;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+import java.util.Objects;
 
 /**
  * A wrapper around XmlPullParser that can peek forward to inspect if the file is a data-binding
@@ -110,8 +111,7 @@ public class LayoutParserWrapper implements XmlPullParser {
         mNext = mDelegate.next();
         if (mEventType == START_TAG) {
             int count = mDelegate.getAttributeCount();
-            mAttributes = count > 0 ? new ArrayList<Attribute>(count) :
-                    Collections.<Attribute>emptyList();
+            mAttributes = count > 0 ? new ArrayList<>(count) : Collections.emptyList();
             for (int i = 0; i < count; i++) {
                 mAttributes.add(new Attribute(mDelegate.getAttributeNamespace(i),
                         mDelegate.getAttributeName(i), mDelegate.getAttributeValue(i)));
@@ -184,9 +184,7 @@ public class LayoutParserWrapper implements XmlPullParser {
                 }
             } else {
                 for (Attribute attribute : mAttributes) {
-                    //noinspection StringEquality for nullness check.
-                    if (attribute.name.equals(name) && (attribute.namespace == namespace ||
-                            attribute.namespace != null && attribute.namespace.equals(namespace))) {
+                    if (attribute.name.equals(name) && Objects.equals(attribute.namespace, namespace)) {
                         returnValue = attribute.value;
                         break;
                     }
@@ -212,11 +210,11 @@ public class LayoutParserWrapper implements XmlPullParser {
 
     private static class Attribute {
         @Nullable
-        public final String namespace;
-        public final String name;
-        public final String value;
+        private final String namespace;
+        private final String name;
+        private final String value;
 
-        public Attribute(@Nullable String namespace, String name, String value) {
+        private Attribute(@Nullable String namespace, String name, String value) {
             this.namespace = namespace;
             this.name = name;
             this.value = value;
@@ -278,7 +276,7 @@ public class LayoutParserWrapper implements XmlPullParser {
     // -- We don't care much about the methods that follow.
 
     @Override
-    public void require(int i, String s, String s1) throws XmlPullParserException, IOException {
+    public void require(int i, String s, String s1) {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
@@ -288,7 +286,7 @@ public class LayoutParserWrapper implements XmlPullParser {
     }
 
     @Override
-    public void defineEntityReplacementText(String s, String s1) throws XmlPullParserException {
+    public void defineEntityReplacementText(String s, String s1) {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
@@ -298,22 +296,22 @@ public class LayoutParserWrapper implements XmlPullParser {
     }
 
     @Override
-    public int nextToken() throws XmlPullParserException, IOException {
+    public int nextToken() {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
     @Override
-    public int getNamespaceCount(int i) throws XmlPullParserException {
+    public int getNamespaceCount(int i) {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
     @Override
-    public String getNamespacePrefix(int i) throws XmlPullParserException {
+    public String getNamespacePrefix(int i) {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
     @Override
-    public String getNamespaceUri(int i) throws XmlPullParserException {
+    public String getNamespaceUri(int i) {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
@@ -328,7 +326,7 @@ public class LayoutParserWrapper implements XmlPullParser {
     }
 
     @Override
-    public boolean isEmptyElementTag() throws XmlPullParserException {
+    public boolean isEmptyElementTag() {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
@@ -368,12 +366,12 @@ public class LayoutParserWrapper implements XmlPullParser {
     }
 
     @Override
-    public String nextText() throws XmlPullParserException, IOException {
+    public String nextText() {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 
     @Override
-    public int nextTag() throws XmlPullParserException, IOException {
+    public int nextTag() {
         throw new UnsupportedOperationException("Only few parser methods are supported.");
     }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
index 1ad05ef245..9bc6dbf603 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
@@ -34,16 +34,19 @@ import com.android.tools.layoutlib.annotations.VisibleForTesting;
 
 import android.animation.AnimationHandler;
 import android.animation.PropertyValuesHolder_Accessor;
+import android.content.Context;
 import android.content.res.Configuration;
 import android.graphics.Rect;
 import android.graphics.drawable.AdaptiveIconDrawable_Delegate;
 import android.os.HandlerThread_Delegate;
+import android.os.SystemProperties;
 import android.util.DisplayMetrics;
 import android.view.IWindowManager;
 import android.view.IWindowManagerImpl;
 import android.view.Surface;
 import android.view.ViewConfiguration_Accessor;
 import android.view.WindowManagerGlobal_Delegate;
+import android.view.WindowManagerImpl;
 import android.view.accessibility.AccessibilityInteractionClient_Accessor;
 import android.view.inputmethod.InputMethodManager_Accessor;
 
@@ -55,9 +58,12 @@ import java.util.concurrent.TimeUnit;
 import java.util.concurrent.locks.ReentrantLock;
 
 import static android.os._Original_Build.VERSION.SDK_INT;
+import static android.view.Surface.ROTATION_0;
+import static android.view.Surface.ROTATION_90;
 import static com.android.ide.common.rendering.api.Result.Status.ERROR_LOCK_INTERRUPTED;
 import static com.android.ide.common.rendering.api.Result.Status.ERROR_TIMEOUT;
 import static com.android.ide.common.rendering.api.Result.Status.SUCCESS;
+import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_SHOW_CUTOUT;
 
 /**
  * Base class for rendering action.
@@ -77,6 +83,7 @@ public abstract class RenderAction<T extends RenderParams> {
      * This is to be accessed when wanting to know the simulated SDK version instead
      * of Build.VERSION.SDK_INT.
      */
+    @SuppressWarnings("WeakerAccess") // Field accessed from Studio
     public static int sSimulatedSdk;
 
     private static final Set<String> COMPOSE_CLASS_FQNS =
@@ -134,6 +141,8 @@ public abstract class RenderAction<T extends RenderParams> {
         HardwareConfig hardwareConfig = mParams.getHardwareConfig();
 
         // setup the display Metrics.
+        SystemProperties.set("qemu.sf.lcd_density",
+                Integer.toString(hardwareConfig.getDensity().getDpiValue()));
         DisplayMetrics metrics = new DisplayMetrics();
         metrics.densityDpi = metrics.noncompatDensityDpi =
                 hardwareConfig.getDensity().getDpiValue();
@@ -143,8 +152,13 @@ public abstract class RenderAction<T extends RenderParams> {
 
         metrics.scaledDensity = metrics.noncompatScaledDensity = metrics.density;
 
-        metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenWidth();
-        metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenHeight();
+        if (hardwareConfig.getOrientation() == ScreenOrientation.PORTRAIT) {
+            metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenWidth();
+            metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenHeight();
+        } else {
+            metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenHeight();
+            metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenWidth();
+        }
         metrics.xdpi = metrics.noncompatXdpi = hardwareConfig.getXdpi();
         metrics.ydpi = metrics.noncompatYdpi = hardwareConfig.getYdpi();
 
@@ -279,10 +293,13 @@ public abstract class RenderAction<T extends RenderParams> {
         // Set-up WindowManager
         // FIXME: find those out, and possibly add them to the render params
         boolean hasNavigationBar = true;
-        //noinspection ConstantConditions
         IWindowManager iwm = new IWindowManagerImpl(getContext().getConfiguration(),
-                getContext().getMetrics(), Surface.ROTATION_0, hasNavigationBar);
+                getContext().getMetrics(), ROTATION_0, hasNavigationBar);
         WindowManagerGlobal_Delegate.setWindowManagerService(iwm);
+        if (Boolean.TRUE.equals(mParams.getFlag(FLAG_KEY_SHOW_CUTOUT))) {
+            ((WindowManagerImpl) mContext.getSystemService(Context.WINDOW_SERVICE))
+                    .setupDisplayCutout();
+        }
 
         ILayoutLog currentLog = mParams.getLog();
         Bridge.setLog(currentLog);
@@ -390,12 +407,7 @@ public abstract class RenderAction<T extends RenderParams> {
 
         config.screenWidthDp = hardwareConfig.getScreenWidth() * 160 / density.getDpiValue();
         config.screenHeightDp = hardwareConfig.getScreenHeight() * 160 / density.getDpiValue();
-        if (config.screenHeightDp < config.screenWidthDp) {
-            //noinspection SuspiciousNameCombination
-            config.smallestScreenWidthDp = config.screenHeightDp;
-        } else {
-            config.smallestScreenWidthDp = config.screenWidthDp;
-        }
+        config.smallestScreenWidthDp = Math.min(config.screenHeightDp, config.screenWidthDp);
         config.densityDpi = density.getDpiValue();
 
         // never run in compat mode:
@@ -407,13 +419,16 @@ public abstract class RenderAction<T extends RenderParams> {
             switch (orientation) {
             case PORTRAIT:
                 config.orientation = Configuration.ORIENTATION_PORTRAIT;
+                config.windowConfiguration.setDisplayRotation(ROTATION_0);
                 break;
             case LANDSCAPE:
                 config.orientation = Configuration.ORIENTATION_LANDSCAPE;
+                config.windowConfiguration.setDisplayRotation(ROTATION_90);
                 break;
             case SQUARE:
                 //noinspection deprecation
                 config.orientation = Configuration.ORIENTATION_SQUARE;
+                config.windowConfiguration.setDisplayRotation(ROTATION_0);
                 break;
             }
         } else {
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
index 0dd35ce055..371ccbf8d6 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
@@ -35,9 +35,6 @@ import android.view.AttachInfo_Accessor;
 import android.view.View.MeasureSpec;
 import android.widget.FrameLayout;
 
-import java.awt.AlphaComposite;
-import java.awt.Color;
-import java.awt.Graphics2D;
 import java.awt.image.BufferedImage;
 import java.awt.image.DataBufferInt;
 import java.util.ArrayList;
@@ -88,9 +85,8 @@ public class RenderDrawable extends RenderAction<DrawableParams> {
         if (allStates == Boolean.TRUE) {
             List<BufferedImage> result;
 
-            if (d instanceof StateListDrawable) {
-                result = new ArrayList<BufferedImage>();
-                StateListDrawable stateList = (StateListDrawable) d;
+            if (d instanceof StateListDrawable stateList) {
+                result = new ArrayList<>();
                 for (int i = 0; i < stateList.getStateCount(); i++) {
                     Drawable stateDrawable = stateList.getStateDrawable(i);
                     result.add(renderImage(hardwareConfig, stateDrawable, context));
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
index 199ce5b4f4..71657abfd6 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
@@ -29,7 +29,6 @@ import com.android.ide.common.rendering.api.SessionParams.RenderingMode;
 import com.android.ide.common.rendering.api.SessionParams.RenderingMode.SizeAction;
 import com.android.ide.common.rendering.api.ViewInfo;
 import com.android.ide.common.rendering.api.ViewType;
-import com.android.internal.R;
 import com.android.internal.view.menu.ActionMenuItemView;
 import com.android.internal.view.menu.BridgeMenuItemImpl;
 import com.android.internal.view.menu.IconMenuItemView;
@@ -53,9 +52,7 @@ import com.android.tools.layoutlib.annotations.NotNull;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.Context;
-import android.content.res.TypedArray;
 import android.graphics.Bitmap;
-import android.graphics.Bitmap.Config;
 import android.graphics.Canvas;
 import android.graphics.drawable.AnimatedVectorDrawable_VectorDrawableAnimatorUI_Delegate;
 import android.preference.Preference_Delegate;
@@ -65,6 +62,7 @@ import android.view.AttachInfo_Accessor;
 import android.view.BridgeInflater;
 import android.view.InputDevice;
 import android.view.KeyEvent;
+import android.view.LayoutlibRenderer;
 import android.view.MotionEvent;
 import android.view.View;
 import android.view.View.MeasureSpec;
@@ -87,9 +85,11 @@ import java.awt.image.BufferedImage;
 import java.awt.image.DataBufferInt;
 import java.io.PrintWriter;
 import java.io.StringWriter;
+import java.nio.IntBuffer;
 import java.util.ArrayList;
 import java.util.IdentityHashMap;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 import java.util.function.Consumer;
 import java.util.function.Function;
@@ -111,10 +111,10 @@ import static com.android.layoutlib.common.util.ReflectionUtils.isInstanceOf;
 public class RenderSessionImpl extends RenderAction<SessionParams> {
 
     private static final Canvas NOP_CANVAS = new NopCanvas();
-    private static final String SIMULATED_SDK_TOO_HIGH =
-            String.format("The current rendering only supports APIs up to %d. You may encounter " +
-                    "crashes if using with higher APIs. To avoid, you can set a lower API for " +
-                    "your previews.", SDK_INT);
+    private static final String SIMULATED_SDK_TOO_HIGH = String.format(Locale.ENGLISH,
+            "The current rendering only supports APIs up to %d. You may encounter crashes if " +
+                    "using with higher APIs. To avoid, you can set a lower API for your previews.",
+            SDK_INT);
 
     // scene state
     private RenderSession mScene;
@@ -135,8 +135,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     private List<ViewInfo> mSystemViewInfoList;
     private Layout.Builder mLayoutBuilder;
     private boolean mNewRenderSize;
-    private Canvas mCanvas;
-    private Bitmap mBitmap;
+    private LayoutlibRenderer mRenderer;
 
     // Passed in MotionEvent initialization when dispatching a touch event.
     private final MotionEvent.PointerProperties[] mPointerProperties =
@@ -359,7 +358,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
             context.popParser();
 
             // set the AttachInfo on the root view.
-            AttachInfo_Accessor.setAttachInfo(mViewRoot);
+            mRenderer = AttachInfo_Accessor.setAttachInfo(mViewRoot);
 
             // post-inflate process. For now this supports TabHost/TabWidget
             postInflateProcess(view, params.getLayoutlibCallback(), isPreference ? view : null);
@@ -417,23 +416,6 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         handleScrolling(context, viewRoot);
     }
 
-    /**
-     * Creates a display list for the root view and draws that display list with a "hardware"
-     * renderer. In layoutlib the renderer is not actually hardware (in contrast to the actual
-     * android) but pretends to be so in order to draw all the advanced android features (e.g.
-     * shadows).
-     */
-    private static Result renderAndBuildResult(@NonNull ViewGroup viewRoot,
-            @Nullable Canvas canvas) {
-        if (canvas == null) {
-            return SUCCESS.createResult();
-        }
-        AttachInfo_Accessor.dispatchOnPreDraw(viewRoot);
-        viewRoot.draw(canvas);
-
-        return SUCCESS.createResult();
-    }
-
     /**
      * Renders the scene.
      * <p>
@@ -496,14 +478,12 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         }
 
         try {
-            if (mViewRoot == null) {
+            if (mViewRoot == null || mRenderer == null) {
                 return ERROR_NOT_INFLATED.createResult();
             }
 
             measureLayout(params);
 
-            HardwareConfig hardwareConfig = params.getHardwareConfig();
-            Result renderResult = SUCCESS.createResult();
             float scaleX = 1.0f;
             float scaleY = 1.0f;
             if (onlyMeasure) {
@@ -518,7 +498,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                 boolean disableBitmapCaching = Boolean.TRUE.equals(params.getFlag(
                     RenderParamsFlags.FLAG_KEY_DISABLE_BITMAP_CACHING));
 
-                if (mNewRenderSize || mCanvas == null || disableBitmapCaching) {
+                if (mNewRenderSize || mImage == null || disableBitmapCaching) {
                     if (params.getImageFactory() != null) {
                         mImage = params.getImageFactory().getImage(
                                 mMeasuredScreenWidth,
@@ -527,21 +507,10 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                         mImage = new BufferedImage(
                                 mMeasuredScreenWidth,
                                 mMeasuredScreenHeight,
-                                BufferedImage.TYPE_INT_ARGB);
+                                BufferedImage.TYPE_INT_ARGB_PRE);
                     }
 
-                    // create an Android bitmap around the BufferedImage
-                    mBitmap = Bitmap.createBitmap(mImage.getWidth(), mImage.getHeight(),
-                            Config.ARGB_8888);
-                    int[] imageData = ((DataBufferInt) mImage.getRaster().getDataBuffer()).getData();
-                    mBitmap.setPixels(imageData, 0, mImage.getWidth(), 0, 0, mImage.getWidth(), mImage.getHeight());
-
-                    if (mCanvas == null) {
-                        // create a Canvas around the Android bitmap
-                        mCanvas = new Canvas(mBitmap);
-                    } else {
-                        mCanvas.setBitmap(mBitmap);
-                    }
+                    assert mImage.getType() == BufferedImage.TYPE_INT_ARGB_PRE;
 
                     boolean enableImageResizing =
                             mImage.getWidth() != mMeasuredScreenWidth &&
@@ -549,14 +518,19 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                                     Boolean.TRUE.equals(params.getFlag(
                                             RenderParamsFlags.FLAG_KEY_RESULT_IMAGE_AUTO_SCALE));
 
+                    if (enableImageResizing || mNewRenderSize) {
+                        disposeImageSurface();
+                    }
+
                     if (enableImageResizing) {
                         scaleX = mImage.getWidth() * 1.0f / mMeasuredScreenWidth;
                         scaleY = mImage.getHeight() * 1.0f / mMeasuredScreenHeight;
-                        mCanvas.scale(scaleX, scaleY);
+                        mRenderer.setScale(scaleX, scaleY);
                     } else {
-                        mCanvas.scale(1.0f, 1.0f);
+                        mRenderer.setScale(1.0f, 1.0f);
                     }
 
+                    mRenderer.setup(mImage.getWidth(), mImage.getHeight(), mViewRoot);
                     mNewRenderSize = false;
                 }
 
@@ -576,11 +550,14 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                             mElapsedFrameTimeNanos / 1000000;
                 }
 
-                renderResult = renderAndBuildResult(mViewRoot, mCanvas);
+                mRenderer.draw(mViewRoot);
+                // Wait for render thread to finish rendering
+                mRenderer.fence();
 
                 int[] imageData = ((DataBufferInt) mImage.getRaster().getDataBuffer()).getData();
-                mBitmap.getPixels(imageData, 0, mImage.getWidth(), 0, 0, mImage.getWidth(),
-                        mImage.getHeight());
+                IntBuffer buff = mRenderer.getBuffer().asIntBuffer();
+                int len = buff.remaining();
+                buff.get(imageData, 0, len);
             }
 
             mSystemViewInfoList =
@@ -623,7 +600,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
             }
 
             // success!
-            return renderResult;
+            return SUCCESS.createResult();
         } catch (Throwable e) {
             // get the real cause of the exception.
             Throwable t = e;
@@ -680,12 +657,10 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         }
         if (view instanceof TabHost) {
             setupTabHost((TabHost) view, layoutlibCallback);
-        } else if (view instanceof QuickContactBadge) {
-            QuickContactBadge badge = (QuickContactBadge) view;
+        } else if (view instanceof QuickContactBadge badge) {
             badge.setImageToDefault();
-        } else if (view instanceof ViewGroup) {
+        } else if (view instanceof ViewGroup group) {
             mInflater.postInflateProcess(view);
-            ViewGroup group = (ViewGroup) view;
             final int count = group.getChildCount();
             for (int c = 0; c < count; c++) {
                 View child = group.getChildAt(c);
@@ -720,10 +695,9 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     }
 
     private View findChildView(View view, String[] className) {
-        if (!(view instanceof ViewGroup)) {
+        if (!(view instanceof ViewGroup group)) {
             return null;
         }
-        ViewGroup group = (ViewGroup) view;
         for (int i = 0; i < group.getChildCount(); i++) {
             if (isInstanceOf(group.getChildAt(i), className)) {
                 return group.getChildAt(i);
@@ -733,10 +707,9 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     }
 
     private boolean hasToolbar(View collapsingToolbar) {
-        if (!(collapsingToolbar instanceof ViewGroup)) {
+        if (!(collapsingToolbar instanceof ViewGroup group)) {
             return false;
         }
-        ViewGroup group = (ViewGroup) collapsingToolbar;
         for (int i = 0; i < group.getChildCount(); i++) {
             if (isInstanceOf(group.getChildAt(i), DesignLibUtil.CN_TOOLBAR)) {
                 return true;
@@ -772,10 +745,9 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
             }
         }
 
-        if (!(view instanceof ViewGroup)) {
+        if (!(view instanceof ViewGroup group)) {
             return;
         }
-        ViewGroup group = (ViewGroup) view;
         for (int i = 0; i < group.getChildCount(); i++) {
             View child = group.getChildAt(i);
             handleScrolling(context, child);
@@ -813,15 +785,13 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                     "TabHost requires a FrameLayout with id \"android:id/tabcontent\".");
         }
 
-        if (!(v instanceof FrameLayout)) {
+        if (!(v instanceof FrameLayout content)) {
             //noinspection SpellCheckingInspection
             throw new PostInflateException(String.format(
                     "TabHost requires a FrameLayout with id \"android:id/tabcontent\".\n" +
                     "View found with id 'tabcontent' is '%s'", v.getClass().getCanonicalName()));
         }
 
-        FrameLayout content = (FrameLayout)v;
-
         // now process the content of the frameLayout and dynamically create tabs for it.
         final int count = content.getChildCount();
 
@@ -876,8 +846,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         ViewInfo result = createViewInfo(view, hOffset, vOffset, params.getExtendedViewInfoMode(),
                 isContentFrame);
 
-        if (view instanceof ViewGroup) {
-            ViewGroup group = ((ViewGroup) view);
+        if (view instanceof ViewGroup group) {
             result.setChildren(visitAllChildren(group, isContentFrame ? 0 : hOffset,
                     isContentFrame ? 0 : vOffset,
                     params, isContentFrame));
@@ -973,7 +942,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
      * set.
      * @param hOffset horizontal offset for the view bounds. Used only if view is part of the
      * content frame.
-     * @param vOffset vertial an offset for the view bounds. Used only if view is part of the
+     * @param vOffset vertical an offset for the view bounds. Used only if view is part of the
      * content frame.
      */
     private ViewInfo createViewInfo(View view, int hOffset, int vOffset, boolean setExtendedInfo,
@@ -1131,7 +1100,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         return mValidatorHierarchy;
     }
 
-    public void setValidatorHierarchy(@NotNull ValidatorHierarchy validatorHierarchy) {
+    private void setValidatorHierarchy(@NotNull ValidatorHierarchy validatorHierarchy) {
         mValidatorHierarchy = validatorHierarchy;
     }
 
@@ -1222,9 +1191,8 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     }
 
     private void disposeImageSurface() {
-        if (mCanvas != null) {
-            mCanvas.release();
-            mCanvas = null;
+        if (mRenderer != null) {
+            mRenderer.reset();
         }
     }
 
@@ -1237,6 +1205,9 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
     @Override
     public void dispose() {
         try {
+            if (mRenderer != null) {
+                mRenderer.destroy();
+            }
             releaseRender();
             // detachFromWindow might create Handler callbacks, thus before Handler_Delegate.dispose
             AttachInfo_Accessor.detachFromWindow(mViewRoot);
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java b/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
index 358795f256..4f51f35b1b 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/ResourceHelper.java
@@ -715,12 +715,12 @@ public final class ResourceHelper {
     // This is taken from //device/libs/utils/ResourceTypes.cpp
 
     private static final class UnitEntry {
-        String name;
-        int type;
-        int unit;
-        float scale;
+        private final String name;
+        private final int type;
+        private final int unit;
+        private final float scale;
 
-        UnitEntry(String name, int type, int unit, float scale) {
+        private UnitEntry(String name, int type, int unit, float scale) {
             this.name = name;
             this.type = type;
             this.unit = unit;
@@ -768,7 +768,7 @@ public final class ResourceHelper {
         value = value.trim();
         int len = value.length();
 
-        if (len <= 0) {
+        if (len == 0) {
             return false;
         }
 
@@ -799,7 +799,7 @@ public final class ResourceHelper {
                 return false;
             }
 
-            if (end.length() > 0 && end.charAt(0) != ' ') {
+            if (!end.isEmpty() && end.charAt(0) != ' ') {
                 // Might be a unit...
                 if (parseUnit(end, outValue, sFloatOut)) {
                     computeTypedValue(outValue, f, sFloatOut[0]);
@@ -811,7 +811,7 @@ public final class ResourceHelper {
             // make sure it's only spaces at the end.
             end = end.trim();
 
-            if (end.length() == 0) {
+            if (end.isEmpty()) {
                 if (outValue != null) {
                     if (!requireUnit) {
                         outValue.type = TypedValue.TYPE_FLOAT;
@@ -892,13 +892,12 @@ public final class ResourceHelper {
     private static void applyUnit(UnitEntry unit, TypedValue outValue, float[] outScale) {
         outValue.type = unit.type;
         // COMPLEX_UNIT_SHIFT is 0 and hence intelliJ complains about it. Suppress the warning.
-        //noinspection PointlessBitwiseExpression
         outValue.data = unit.unit << TypedValue.COMPLEX_UNIT_SHIFT;
         outScale[0] = unit.scale;
     }
 
     private static class Tag {
-        private String mLabel;
+        private final String mLabel;
         private int mStart;
         private int mEnd;
         private Attributes mAttributes;
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/SysUiOverlay.java b/bridge/src/com/android/layoutlib/bridge/impl/SysUiOverlay.java
index 8900c06185..f9ff7618c1 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/SysUiOverlay.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/SysUiOverlay.java
@@ -120,7 +120,7 @@ class SysUiOverlay extends View {
     }
 
     private void paintNotch(Canvas canvas) {
-        canvas.translate(getWidth() / 2 - mNotchTopWidth / 2, 0);
+        canvas.translate(getWidth() / 2f - mNotchTopWidth / 2f, 0);
         canvas.drawPath(mNotchPath, mNotchPaint);
     }
 
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterHelper.java b/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterHelper.java
index 640b5635cd..adba9c1506 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterHelper.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterHelper.java
@@ -65,8 +65,7 @@ public class AdapterHelper {
 
     private static void fillView(BridgeContext context, View view, AdapterItem item,
             AdapterItem parentItem, LayoutlibCallback callback, ResourceReference adapterRef) {
-        if (view instanceof ViewGroup) {
-            ViewGroup group = (ViewGroup) view;
+        if (view instanceof ViewGroup group) {
             final int count = group.getChildCount();
             for (int i = 0 ; i < count ; i++) {
                 fillView(context, group.getChildAt(i), item, parentItem, callback, adapterRef);
@@ -82,8 +81,7 @@ public class AdapterHelper {
                     int parentPositionPerType = parentItem != null ?
                             parentItem.getPositionPerType() : 0;
 
-                    if (view instanceof TextView) {
-                        TextView tv = (TextView) view;
+                    if (view instanceof TextView tv) {
                         Object value = callback.getAdapterItemValue(
                                 adapterRef, context.getViewKey(view),
                                 item.getDataBindingItem().getViewReference(),
@@ -101,8 +99,7 @@ public class AdapterHelper {
                         }
                     }
 
-                    if (view instanceof Checkable) {
-                        Checkable cb = (Checkable) view;
+                    if (view instanceof Checkable cb) {
 
                         Object value = callback.getAdapterItemValue(
                                 adapterRef, context.getViewKey(view),
@@ -121,8 +118,7 @@ public class AdapterHelper {
                         }
                     }
 
-                    if (view instanceof ImageView) {
-                        ImageView iv = (ImageView) view;
+                    if (view instanceof ImageView iv) {
 
                         Object value = callback.getAdapterItemValue(
                                 adapterRef, context.getViewKey(view),
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterItem.java b/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterItem.java
index 8e28dbaf1a..8df968b76f 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterItem.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/binding/AdapterItem.java
@@ -42,7 +42,7 @@ final class AdapterItem {
 
     void addChild(AdapterItem child) {
         if (mChildren == null) {
-            mChildren = new ArrayList<AdapterItem>();
+            mChildren = new ArrayList<>();
         }
 
         mChildren.add(child);
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeAdapter.java b/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeAdapter.java
index 1c5c6a6226..b8032b8f4a 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeAdapter.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeAdapter.java
@@ -40,10 +40,10 @@ import java.util.List;
 public class FakeAdapter extends BaseAdapter {
 
     // don't use a set because the order is important.
-    private final List<ResourceReference> mTypes = new ArrayList<ResourceReference>();
+    private final List<ResourceReference> mTypes = new ArrayList<>();
     private final LayoutlibCallback mCallback;
     private final ResourceReference mAdapterRef;
-    private final List<AdapterItem> mItems = new ArrayList<AdapterItem>();
+    private final List<AdapterItem> mItems = new ArrayList<>();
     private boolean mSkipCallbackParser = false;
 
     public FakeAdapter(ResourceReference adapterRef, AdapterBinding binding,
@@ -81,11 +81,6 @@ public class FakeAdapter extends BaseAdapter {
         }
     }
 
-    @Override
-    public boolean isEnabled(int position) {
-        return true;
-    }
-
     @Override
     public int getCount() {
         return mItems.size();
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeExpandableAdapter.java b/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeExpandableAdapter.java
index 1f72978aeb..22871e20c4 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeExpandableAdapter.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/binding/FakeExpandableAdapter.java
@@ -37,11 +37,11 @@ public class FakeExpandableAdapter implements ExpandableListAdapter, Heterogeneo
     private final ResourceReference mAdapterRef;
     private boolean mSkipCallbackParser = false;
 
-    protected final List<AdapterItem> mItems = new ArrayList<AdapterItem>();
+    private final List<AdapterItem> mItems = new ArrayList<>();
 
     // don't use a set because the order is important.
-    private final List<ResourceReference> mGroupTypes = new ArrayList<ResourceReference>();
-    private final List<ResourceReference> mChildrenTypes = new ArrayList<ResourceReference>();
+    private final List<ResourceReference> mGroupTypes = new ArrayList<>();
+    private final List<ResourceReference> mChildrenTypes = new ArrayList<>();
 
     public FakeExpandableAdapter(ResourceReference adapterRef, AdapterBinding binding,
             LayoutlibCallback callback) {
@@ -72,7 +72,7 @@ public class FakeExpandableAdapter implements ExpandableListAdapter, Heterogeneo
                 int count = dataBindingItem.getCount();
 
                 // if there are children, we use the count as a repeat count for the children.
-                if (children.size() > 0) {
+                if (!children.isEmpty()) {
                     count = 1;
                 }
 
@@ -84,7 +84,7 @@ public class FakeExpandableAdapter implements ExpandableListAdapter, Heterogeneo
                             index++);
                     mItems.add(item);
 
-                    if (children.size() > 0) {
+                    if (!children.isEmpty()) {
                         createItems(dataBindingItem, depth + 1);
                     }
                 }
diff --git a/bridge/src/com/android/layoutlib/bridge/resources/IconLoader.java b/bridge/src/com/android/layoutlib/bridge/resources/IconLoader.java
index df4f252c30..aef60259f6 100644
--- a/bridge/src/com/android/layoutlib/bridge/resources/IconLoader.java
+++ b/bridge/src/com/android/layoutlib/bridge/resources/IconLoader.java
@@ -30,7 +30,7 @@ public class IconLoader {
     private final LayoutDirection mDirection;
 
     private Density mCurrentDensity;
-    private StringBuilder mCurrentPath;
+    private final StringBuilder mCurrentPath;
 
     public IconLoader(String iconName, Density density, int platformVersion, LayoutDirection
             direction) {
diff --git a/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java b/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
index f8884d4b2e..d1ca9a796e 100644
--- a/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
+++ b/bridge/src/com/android/layoutlib/bridge/resources/SysUiResources.java
@@ -16,6 +16,7 @@
 
 package com.android.layoutlib.bridge.resources;
 
+import com.android.ide.common.rendering.api.ILayoutLog;
 import com.android.ide.common.rendering.api.ResourceNamespace;
 import com.android.layoutlib.bridge.Bridge;
 import com.android.layoutlib.bridge.android.BridgeContext;
@@ -34,8 +35,10 @@ import android.graphics.Bitmap;
 import android.graphics.BitmapFactory;
 import android.graphics.BitmapFactory.Options;
 import android.graphics.drawable.BitmapDrawable;
+import android.graphics.drawable.Drawable;
 import android.widget.ImageView;
 
+import java.io.IOException;
 import java.io.InputStream;
 
 public class SysUiResources {
@@ -69,29 +72,49 @@ public class SysUiResources {
     public static ImageView loadIcon(Context context, int api, ImageView imageView,
             String iconName, Density density, boolean isRtl, int color) {
         LayoutDirection dir = isRtl ? LayoutDirection.RTL : null;
-        IconLoader iconLoader = new IconLoader(iconName, density, api,
-                dir);
-        InputStream stream = iconLoader.getIcon();
-
-        if (stream != null) {
-            density = iconLoader.getDensity();
-            String path = iconLoader.getPath();
-            // look for a cached bitmap
-            Bitmap bitmap = Bridge.getCachedBitmap(path, Boolean.TRUE /*isFramework*/);
-            if (bitmap == null) {
-                Options options = new Options();
-                options.inDensity = density.getDpiValue();
-                bitmap = BitmapFactory.decodeStream(stream, null, options);
-                Bridge.setCachedBitmap(path, bitmap, Boolean.TRUE /*isFramework*/);
+        Drawable drawable = null;
+        if (iconName.endsWith("xml")) {
+            IconLoader iconLoader = new IconLoader(iconName, Density.ANYDPI, api, dir);
+            InputStream stream = iconLoader.getIcon();
+            if (stream != null) {
+                try {
+                    BridgeXmlBlockParser parser =
+                            new BridgeXmlBlockParser(
+                                    ParserFactory.create(stream, iconName),
+                                    (BridgeContext) context,
+                                    ResourceNamespace.ANDROID);
+                    drawable = Drawable.createFromXml(context.getResources(), parser);
+                } catch (XmlPullParserException | IOException e) {
+                    Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Unable to load icon " + iconName, e,
+                            null, null);
+                }
             }
+        } else {
+            IconLoader iconLoader = new IconLoader(iconName, density, api, dir);
+            InputStream stream = iconLoader.getIcon();
 
-            if (bitmap != null) {
-                BitmapDrawable drawable = new BitmapDrawable(context.getResources(), bitmap);
-                drawable.setTint(color);
-                imageView.setImageDrawable(drawable);
+            if (stream != null) {
+                density = iconLoader.getDensity();
+                String path = iconLoader.getPath();
+                // look for a cached bitmap
+                Bitmap bitmap = Bridge.getCachedBitmap(path, Boolean.TRUE /*isFramework*/);
+                if (bitmap == null) {
+                    Options options = new Options();
+                    options.inDensity = density.getDpiValue();
+                    bitmap = BitmapFactory.decodeStream(stream, null, options);
+                    Bridge.setCachedBitmap(path, bitmap, Boolean.TRUE /*isFramework*/);
+                }
+
+                if (bitmap != null) {
+                    drawable = new BitmapDrawable(context.getResources(), bitmap);
+                }
             }
         }
 
+        if (drawable != null) {
+            drawable.setTint(color);
+            imageView.setImageDrawable(drawable);
+        }
         return imageView;
     }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/util/ChoreographerCallbacks.java b/bridge/src/com/android/layoutlib/bridge/util/ChoreographerCallbacks.java
index 8862f7c89e..890034d91e 100644
--- a/bridge/src/com/android/layoutlib/bridge/util/ChoreographerCallbacks.java
+++ b/bridge/src/com/android/layoutlib/bridge/util/ChoreographerCallbacks.java
@@ -75,11 +75,11 @@ public class ChoreographerCallbacks {
         }
     }
 
-    public void execute(long currentTimeMs, @NotNull ILayoutLog logger) {
-        final long currentTimeNanos = currentTimeMs * TimeUtils.NANOS_PER_MS;
+    public void execute(long currentTimeNanos, @NotNull ILayoutLog logger) {
         List<Callback> toExecute;
         synchronized (mCallbacks) {
             int idx = 0;
+            long currentTimeMs = currentTimeNanos / TimeUtils.NANOS_PER_MS;
             while (idx < mCallbacks.size()) {
                 if (mCallbacks.get(idx).mDueTime > currentTimeMs) {
                     break;
@@ -105,15 +105,13 @@ public class ChoreographerCallbacks {
     private static void executeSafely(@NotNull Object action, long frameTimeNanos,
             @NotNull ILayoutLog logger) {
         try {
-            if (action instanceof FrameCallback) {
-                FrameCallback callback = (FrameCallback) action;
+            if (action instanceof FrameCallback callback) {
                 callback.doFrame(frameTimeNanos);
-            } else if (action instanceof Runnable) {
-                Runnable runnable = (Runnable) action;
+            } else if (action instanceof Runnable runnable) {
                 runnable.run();
             } else {
                 logger.error(ILayoutLog.TAG_BROKEN,
-                        "Unexpected action as Choreographer callback", (Object) null, null);
+                        "Unexpected action as Choreographer callback", null, null);
             }
         } catch (Throwable t) {
             logger.error(ILayoutLog.TAG_BROKEN, "Failed executing Choreographer callback", t,
diff --git a/bridge/src/com/android/layoutlib/bridge/util/HandlerMessageQueue.java b/bridge/src/com/android/layoutlib/bridge/util/HandlerMessageQueue.java
index 595b57556c..8493778447 100644
--- a/bridge/src/com/android/layoutlib/bridge/util/HandlerMessageQueue.java
+++ b/bridge/src/com/android/layoutlib/bridge/util/HandlerMessageQueue.java
@@ -60,7 +60,7 @@ public class HandlerMessageQueue {
     }
 
     private static class HandlerWrapper {
-        public Handler handler;
+        private Handler handler;
     }
 
     /**
diff --git a/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
new file mode 100644
index 0000000000..19d582defb
--- /dev/null
+++ b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
@@ -0,0 +1,229 @@
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
+package com.android.layoutlib.bridge.util;
+
+import com.android.layoutlib.bridge.bars.NavigationHandle;
+
+import android.app.ResourcesManager;
+import android.content.Context;
+import android.content.res.Resources;
+import android.graphics.Insets;
+import android.graphics.PixelFormat;
+import android.graphics.Rect;
+import android.util.DisplayMetrics;
+import android.util.TypedValue;
+import android.view.Gravity;
+import android.view.InsetsController;
+import android.view.InsetsFrameProvider;
+import android.view.InsetsSource;
+import android.view.InsetsState;
+import android.view.Surface;
+import android.view.View;
+import android.view.WindowInsets;
+import android.view.WindowManager;
+
+import java.util.List;
+
+import static android.app.WindowConfiguration.ROTATION_UNDEFINED;
+import static android.inputmethodservice.InputMethodService.ENABLE_HIDE_IME_CAPTION_BAR;
+import static android.view.InsetsSource.FLAG_SUPPRESS_SCRIM;
+import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+import static android.view.WindowManager.LayoutParams.TYPE_INPUT_METHOD;
+
+public class InsetUtil {
+    public static Rect getCurrentBounds(Context context) {
+        synchronized (ResourcesManager.getInstance()) {
+            return context.getResources().getConfiguration().windowConfiguration.getBounds();
+        }
+    }
+
+    /**
+     * This applies all insets provided by the System UI.
+     * This is a simplified version of what happens in
+     * services/core/java/com/android/server/wm/DisplayPolicy.java.
+     */
+    public static void setupSysUiInsets(Context context, InsetsController insetsController,
+            List<InsetsFrameProvider> insetsFrameProviders) {
+        Rect currentBounds = getCurrentBounds(context);
+        insetsController.onFrameChanged(currentBounds);
+        InsetsState insetsState = insetsController.getState();
+        Rect tmpRect = new Rect();
+        // First set the window frame to all inset sources
+        for (InsetsFrameProvider provider : insetsFrameProviders) {
+            InsetsSource source =
+                    insetsState.getOrCreateSource(provider.getId(), provider.getType());
+            source.getFrame().set(currentBounds);
+        }
+        // Then apply the insets
+        for (InsetsFrameProvider provider : insetsFrameProviders) {
+            Insets insets = provider.getInsetsSize();
+            InsetsSource source =
+                    insetsState.getOrCreateSource(provider.getId(), provider.getType());
+            Rect sourceFrame = source.getFrame();
+            if (provider.getMinimalInsetsSizeInDisplayCutoutSafe() != null) {
+                tmpRect.set(sourceFrame);
+            }
+            source.updateSideHint(currentBounds);
+            calculateInsetsFrame(sourceFrame, insets);
+
+            if (provider.getMinimalInsetsSizeInDisplayCutoutSafe() != null) {
+                // The insets is at least with the given size within the display cutout safe area.
+                // Calculate the smallest size.
+                calculateInsetsFrame(tmpRect, provider.getMinimalInsetsSizeInDisplayCutoutSafe());
+                // If it's larger than previous calculation, use it.
+                if (tmpRect.contains(sourceFrame)) {
+                    sourceFrame.set(tmpRect);
+                }
+            }
+        }
+    }
+
+    // Copied from services/core/java/com/android/server/wm/DisplayPolicy.java
+    private static void calculateInsetsFrame(Rect inOutFrame, Insets insetsSize) {
+        if (insetsSize == null) {
+            inOutFrame.setEmpty();
+            return;
+        }
+        // Only one side of the provider shall be applied. Check in the order of left - top -
+        // right - bottom, only the first non-zero value will be applied.
+        if (insetsSize.left != 0) {
+            inOutFrame.right = inOutFrame.left + insetsSize.left;
+        } else if (insetsSize.top != 0) {
+            inOutFrame.bottom = inOutFrame.top + insetsSize.top;
+        } else if (insetsSize.right != 0) {
+            inOutFrame.left = inOutFrame.right - insetsSize.right;
+        } else if (insetsSize.bottom != 0) {
+            inOutFrame.top = inOutFrame.bottom - insetsSize.bottom;
+        } else {
+            inOutFrame.setEmpty();
+        }
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/navigationbar/NavigationBar.java
+    public static WindowManager.LayoutParams getNavBarLayoutParamsForRotation(Context context,
+            View navBar, int rotation) {
+        int width = WindowManager.LayoutParams.MATCH_PARENT;
+        int height = WindowManager.LayoutParams.MATCH_PARENT;
+        int insetsHeight = -1;
+        int gravity = Gravity.BOTTOM;
+        boolean navBarCanMove = true;
+        WindowManager windowManager = context.getSystemService(WindowManager.class);
+        if (windowManager != null) {
+            Rect displaySize = windowManager.getCurrentWindowMetrics().getBounds();
+            navBarCanMove = displaySize.width() != displaySize.height() &&
+                    context.getResources().getBoolean(
+                            com.android.internal.R.bool.config_navBarCanMove);
+        }
+        if (!navBarCanMove) {
+            height = context.getResources().getDimensionPixelSize(
+                    com.android.internal.R.dimen.navigation_bar_frame_height);
+            insetsHeight = context.getResources().getDimensionPixelSize(
+                    com.android.internal.R.dimen.navigation_bar_height);
+        } else {
+            switch (rotation) {
+                case ROTATION_UNDEFINED:
+                case Surface.ROTATION_0:
+                case Surface.ROTATION_180:
+                    height = context.getResources().getDimensionPixelSize(
+                            com.android.internal.R.dimen.navigation_bar_frame_height);
+                    insetsHeight = context.getResources().getDimensionPixelSize(
+                            com.android.internal.R.dimen.navigation_bar_height);
+                    break;
+                case Surface.ROTATION_90:
+                    gravity = Gravity.RIGHT;
+                    width = context.getResources().getDimensionPixelSize(
+                            com.android.internal.R.dimen.navigation_bar_width);
+                    break;
+                case Surface.ROTATION_270:
+                    gravity = Gravity.LEFT;
+                    width = context.getResources().getDimensionPixelSize(
+                            com.android.internal.R.dimen.navigation_bar_width);
+                    break;
+            }
+        }
+        WindowManager.LayoutParams lp = new WindowManager.LayoutParams(width, height,
+                WindowManager.LayoutParams.TYPE_NAVIGATION_BAR,
+                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
+                        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL |
+                        WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH |
+                        WindowManager.LayoutParams.FLAG_SPLIT_TOUCH |
+                        WindowManager.LayoutParams.FLAG_SLIPPERY, PixelFormat.TRANSLUCENT);
+        lp.gravity = gravity;
+        lp.providedInsets = getInsetsFrameProvider(navBar, insetsHeight, context);
+
+        lp.privateFlags |= WindowManager.LayoutParams.PRIVATE_FLAG_COLOR_SPACE_AGNOSTIC |
+                WindowManager.LayoutParams.PRIVATE_FLAG_LAYOUT_SIZE_EXTENDED_BY_CUTOUT;
+        lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
+        return lp;
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/navigationbar/NavigationBar.java
+    private static InsetsFrameProvider[] getInsetsFrameProvider(View navBar, int insetsHeight,
+            Context userContext) {
+        final InsetsFrameProvider navBarProvider =
+                new InsetsFrameProvider(navBar, 0, WindowInsets.Type.navigationBars());
+        if (!ENABLE_HIDE_IME_CAPTION_BAR) {
+            navBarProvider.setInsetsSizeOverrides(new InsetsFrameProvider.InsetsSizeOverride[]{
+                    new InsetsFrameProvider.InsetsSizeOverride(TYPE_INPUT_METHOD, null)});
+        }
+        if (insetsHeight != -1) {
+            navBarProvider.setInsetsSize(Insets.of(0, 0, 0, insetsHeight));
+        }
+        final boolean needsScrim = userContext.getResources().getBoolean(
+                com.android.internal.R.bool.config_navBarNeedsScrim);
+        navBarProvider.setFlags(needsScrim ? 0 : FLAG_SUPPRESS_SCRIM, FLAG_SUPPRESS_SCRIM);
+
+        final InsetsFrameProvider tappableElementProvider =
+                new InsetsFrameProvider(navBar, 0, WindowInsets.Type.tappableElement());
+        final boolean tapThrough = userContext.getResources().getBoolean(
+                com.android.internal.R.bool.config_navBarTapThrough);
+        if (tapThrough) {
+            tappableElementProvider.setInsetsSize(Insets.NONE);
+        }
+
+        final int gestureHeight = userContext.getResources().getDimensionPixelSize(
+                com.android.internal.R.dimen.navigation_bar_gesture_height);
+        final boolean handlingGesture = navBar instanceof NavigationHandle;
+        final InsetsFrameProvider mandatoryGestureProvider =
+                new InsetsFrameProvider(navBar, 0, WindowInsets.Type.mandatorySystemGestures());
+        if (handlingGesture) {
+            mandatoryGestureProvider.setInsetsSize(Insets.of(0, 0, 0, gestureHeight));
+        }
+        final int gestureInset = handlingGesture ? getUnscaledInset(userContext.getResources()) : 0;
+        return new InsetsFrameProvider[]{navBarProvider, tappableElementProvider,
+                mandatoryGestureProvider,
+                new InsetsFrameProvider(navBar, 0, WindowInsets.Type.systemGestures()).setSource(
+                        InsetsFrameProvider.SOURCE_DISPLAY).setInsetsSize(
+                        Insets.of(gestureInset, 0, 0, 0)).setMinimalInsetsSizeInDisplayCutoutSafe(
+                        Insets.of(gestureInset, 0, 0, 0)),
+                new InsetsFrameProvider(navBar, 1, WindowInsets.Type.systemGestures()).setSource(
+                        InsetsFrameProvider.SOURCE_DISPLAY).setInsetsSize(
+                        Insets.of(0, 0, gestureInset, 0)).setMinimalInsetsSizeInDisplayCutoutSafe(
+                        Insets.of(0, 0, gestureInset, 0))};
+    }
+
+    // Copied/adapted from packages/SystemUI/src/com/android/systemui/navigationbar/NavigationBar.java
+    private static int getUnscaledInset(Resources userRes) {
+        final DisplayMetrics dm = userRes.getDisplayMetrics();
+        final float defaultInset =
+                userRes.getDimension(com.android.internal.R.dimen.config_backGestureInset) /
+                        dm.density;
+        final float inset =
+                TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, defaultInset, dm);
+        return (int) inset;
+    }
+}
diff --git a/bridge/src/com/android/layoutlib/bridge/util/SparseWeakArray.java b/bridge/src/com/android/layoutlib/bridge/util/SparseWeakArray.java
index dd06e80e60..9eb2febc0b 100644
--- a/bridge/src/com/android/layoutlib/bridge/util/SparseWeakArray.java
+++ b/bridge/src/com/android/layoutlib/bridge/util/SparseWeakArray.java
@@ -44,7 +44,7 @@ import java.lang.ref.WeakReference;
 public class SparseWeakArray<E> {
 
     private static final Object DELETED_REF = new Object();
-    private static final WeakReference<?> DELETED = new WeakReference(DELETED_REF);
+    private static final WeakReference<?> DELETED = new WeakReference<>(DELETED_REF);
     private boolean mGarbage = false;
 
     /**
@@ -153,13 +153,13 @@ public class SparseWeakArray<E> {
         int i = binarySearch(mKeys, 0, mSize, key);
 
         if (i >= 0) {
-            mValues[i] = new WeakReference(value);
+            mValues[i] = new WeakReference<>(value);
         } else {
             i = ~i;
 
             if (i < mSize && (mValues[i] == DELETED || mValues[i].get() == null)) {
                 mKeys[i] = key;
-                mValues[i] = new WeakReference(value);
+                mValues[i] = new WeakReference<>(value);
                 return;
             }
 
@@ -171,7 +171,7 @@ public class SparseWeakArray<E> {
             }
 
             mKeys = GrowingArrayUtils.insert(mKeys, mSize, i, key);
-            mValues = GrowingArrayUtils.insert(mValues, mSize, i, new WeakReference(value));
+            mValues = GrowingArrayUtils.insert(mValues, mSize, i, new WeakReference<>(value));
             mSize++;
         }
     }
@@ -224,7 +224,7 @@ public class SparseWeakArray<E> {
             gc();
         }
 
-        mValues[index] = new WeakReference(value);
+        mValues[index] = new WeakReference<>(value);
     }
 
     /**
@@ -290,7 +290,7 @@ public class SparseWeakArray<E> {
         }
 
         mKeys = GrowingArrayUtils.append(mKeys, mSize, key);
-        mValues = GrowingArrayUtils.append(mValues, mSize, new WeakReference(value));
+        mValues = GrowingArrayUtils.append(mValues, mSize, new WeakReference<>(value));
         mSize++;
     }
 
diff --git a/bridge/src/com/android/server/wm/DisplayFrames.java b/bridge/src/com/android/server/wm/DisplayFrames.java
new file mode 100644
index 0000000000..ef95e641ef
--- /dev/null
+++ b/bridge/src/com/android/server/wm/DisplayFrames.java
@@ -0,0 +1,107 @@
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
+package com.android.server.wm;
+
+import static android.view.InsetsSource.createId;
+import static android.view.WindowInsets.Type.displayCutout;
+
+import android.annotation.NonNull;
+import android.graphics.Rect;
+import android.view.DisplayCutout;
+import android.view.DisplayInfo;
+import android.view.DisplayShape;
+import android.view.InsetsState;
+import android.view.PrivacyIndicatorBounds;
+import android.view.RoundedCorners;
+
+// Copied/adapted from frameworks/base/services/core/java/com/android/server/wm/DisplayFrames.java
+public class DisplayFrames {
+
+    private static final int ID_DISPLAY_CUTOUT_LEFT = createId(null, 0, displayCutout());
+    private static final int ID_DISPLAY_CUTOUT_TOP = createId(null, 1, displayCutout());
+    private static final int ID_DISPLAY_CUTOUT_RIGHT = createId(null, 2, displayCutout());
+    private static final int ID_DISPLAY_CUTOUT_BOTTOM = createId(null, 3, displayCutout());
+
+    private final InsetsState mInsetsState;
+    private final Rect mUnrestricted = new Rect();
+    private final Rect mDisplayCutoutSafe = new Rect();
+    private int mWidth;
+    private int mHeight;
+    private int mRotation;
+
+    public DisplayFrames(InsetsState insetsState, DisplayInfo info, DisplayCutout cutout,
+            RoundedCorners roundedCorners, PrivacyIndicatorBounds indicatorBounds,
+            DisplayShape displayShape) {
+        mInsetsState = insetsState;
+        update(info.rotation, info.logicalWidth, info.logicalHeight, cutout, roundedCorners,
+                indicatorBounds, displayShape);
+    }
+
+    public boolean update(int rotation, int w, int h, @NonNull DisplayCutout displayCutout,
+            @NonNull RoundedCorners roundedCorners,
+            @NonNull PrivacyIndicatorBounds indicatorBounds,
+            @NonNull DisplayShape displayShape) {
+        final InsetsState state = mInsetsState;
+        final Rect safe = mDisplayCutoutSafe;
+        if (mRotation == rotation && mWidth == w && mHeight == h
+                && mInsetsState.getDisplayCutout().equals(displayCutout)
+                && state.getRoundedCorners().equals(roundedCorners)
+                && state.getPrivacyIndicatorBounds().equals(indicatorBounds)) {
+            return false;
+        }
+        mRotation = rotation;
+        mWidth = w;
+        mHeight = h;
+        final Rect u = mUnrestricted;
+        u.set(0, 0, w, h);
+        state.setDisplayFrame(u);
+        state.setDisplayCutout(displayCutout);
+        state.setRoundedCorners(roundedCorners);
+        state.setPrivacyIndicatorBounds(indicatorBounds);
+        state.setDisplayShape(displayShape);
+        state.getDisplayCutoutSafe(safe);
+        if (safe.left > u.left) {
+            state.getOrCreateSource(ID_DISPLAY_CUTOUT_LEFT, displayCutout())
+                    .setFrame(u.left, u.top, safe.left, u.bottom)
+                    .updateSideHint(u);
+        } else {
+            state.removeSource(ID_DISPLAY_CUTOUT_LEFT);
+        }
+        if (safe.top > u.top) {
+            state.getOrCreateSource(ID_DISPLAY_CUTOUT_TOP, displayCutout())
+                    .setFrame(u.left, u.top, u.right, safe.top)
+                    .updateSideHint(u);
+        } else {
+            state.removeSource(ID_DISPLAY_CUTOUT_TOP);
+        }
+        if (safe.right < u.right) {
+            state.getOrCreateSource(ID_DISPLAY_CUTOUT_RIGHT, displayCutout())
+                    .setFrame(safe.right, u.top, u.right, u.bottom)
+                    .updateSideHint(u);
+        } else {
+            state.removeSource(ID_DISPLAY_CUTOUT_RIGHT);
+        }
+        if (safe.bottom < u.bottom) {
+            state.getOrCreateSource(ID_DISPLAY_CUTOUT_BOTTOM, displayCutout())
+                    .setFrame(u.left, safe.bottom, u.right, u.bottom)
+                    .updateSideHint(u);
+        } else {
+            state.removeSource(ID_DISPLAY_CUTOUT_BOTTOM);
+        }
+        return true;
+    }
+}
\ No newline at end of file
diff --git a/bridge/src/com/android/tools/layoutlib/java/nio/Buffer_Delegate.java b/bridge/src/com/android/tools/layoutlib/java/nio/Buffer_Delegate.java
deleted file mode 100644
index 351d9b4e15..0000000000
--- a/bridge/src/com/android/tools/layoutlib/java/nio/Buffer_Delegate.java
+++ /dev/null
@@ -1,52 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-package com.android.tools.layoutlib.java.nio;
-
-import java.nio.Buffer;
-import java.nio.ByteBuffer;
-import java.nio.CharBuffer;
-import java.nio.DoubleBuffer;
-import java.nio.FloatBuffer;
-import java.nio.IntBuffer;
-import java.nio.LongBuffer;
-import java.nio.ShortBuffer;
-
-/**
- * Delegate to fix differences between the Android and the JVM versions of java.nio.Buffer
- */
-public class Buffer_Delegate {
-    /**
-     * The Android version of java.nio.Buffer has an extra final field called _elementSizeShift
-     * that only depend on the implementation of the buffer. This method can be called instead
-     * when wanting to access the value of that field on the JVM.
-     */
-    public static int elementSizeShift(Buffer buffer) {
-        if (buffer instanceof ByteBuffer) {
-            return 0;
-        }
-        if (buffer instanceof ShortBuffer || buffer instanceof CharBuffer) {
-            return 1;
-        }
-        if (buffer instanceof IntBuffer || buffer instanceof FloatBuffer) {
-            return 2;
-        }
-        if (buffer instanceof LongBuffer || buffer instanceof DoubleBuffer) {
-            return 3;
-        }
-        return 0;
-    }
-}
diff --git a/bridge/src/com/android/tools/layoutlib/java/nio/NIOAccess_Delegate.java b/bridge/src/com/android/tools/layoutlib/java/nio/NIOAccess_Delegate.java
deleted file mode 100644
index addcc0bd35..0000000000
--- a/bridge/src/com/android/tools/layoutlib/java/nio/NIOAccess_Delegate.java
+++ /dev/null
@@ -1,73 +0,0 @@
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
-package com.android.tools.layoutlib.java.nio;
-
-import com.android.layoutlib.common.util.ReflectionUtils;
-import com.android.layoutlib.common.util.ReflectionUtils.ReflectionException;
-
-import java.nio.Buffer;
-
-/**
- * A fork of libcore's java.nio.NIOAccess which does not exist in the JVM
- *
- * This class is used via JNI by code in frameworks/base/.
- * @hide
- */
-// @VisibleForTesting : was default
-public final class NIOAccess_Delegate {
-
-    /**
-     * Returns the underlying native pointer to the data of the given
-     * Buffer starting at the Buffer's current position, or 0 if the
-     * Buffer is not backed by native heap storage.
-     * @hide
-     */
-    // @VisibleForTesting : was default
-    public static long getBasePointer(Buffer b) {
-        try {
-            long address = (long)ReflectionUtils.getFieldValue(Buffer.class, b, "address");
-            if (address == 0L || !b.isDirect()) {
-                return 0L;
-            }
-            return address + ((long)b.position() << Buffer_Delegate.elementSizeShift(b));
-        } catch (ReflectionException e) {
-            return 0L;
-        }
-    }
-
-    /**
-     * Returns the underlying Java array containing the data of the
-     * given Buffer, or null if the Buffer is not backed by a Java array.
-     */
-    static Object getBaseArray(Buffer b) {
-        return b.hasArray() ? b.array() : null;
-    }
-
-    /**
-     * Returns the offset in bytes from the start of the underlying
-     * Java array object containing the data of the given Buffer to
-     * the actual start of the data. The start of the data takes into
-     * account the Buffer's current position. This method is only
-     * meaningful if getBaseArray() returns non-null.
-     */
-    static int getBaseArrayOffset(Buffer b) {
-        return b.hasArray() ?
-                ((b.arrayOffset() + b.position()) << Buffer_Delegate.elementSizeShift(b)) : 0;
-    }
-
-
-}
diff --git a/bridge/src/dalvik/system/VMRuntimeCommonHelper.java b/bridge/src/dalvik/system/VMRuntimeCommonHelper.java
index ae63625e16..be83482eb4 100644
--- a/bridge/src/dalvik/system/VMRuntimeCommonHelper.java
+++ b/bridge/src/dalvik/system/VMRuntimeCommonHelper.java
@@ -22,6 +22,7 @@ package dalvik.system;
 class VMRuntimeCommonHelper {
 
     // Copied from libcore/libdvm/src/main/java/dalvik/system/VMRuntime
+    @SuppressWarnings("UnnecessaryLocalVariable")
     /*package*/ static Object newUnpaddedArray(VMRuntime runtime, Class<?> componentType,
             int minLength) {
         // Dalvik has 32bit pointers, the array header is 16bytes plus 4bytes for dlmalloc,
diff --git a/bridge/src/libcore/io/MemoryMappedFile_Delegate.java b/bridge/src/libcore/io/MemoryMappedFile_Delegate.java
index 723d5c4b0d..f53ea0d83f 100644
--- a/bridge/src/libcore/io/MemoryMappedFile_Delegate.java
+++ b/bridge/src/libcore/io/MemoryMappedFile_Delegate.java
@@ -36,11 +36,10 @@ import java.util.Map;
  */
 public class MemoryMappedFile_Delegate {
 
-    private static final DelegateManager<MemoryMappedFile_Delegate> sManager = new
-            DelegateManager<MemoryMappedFile_Delegate>(MemoryMappedFile_Delegate.class);
+    private static final DelegateManager<MemoryMappedFile_Delegate> sManager =
+            new DelegateManager<>(MemoryMappedFile_Delegate.class);
 
-    private static final Map<MemoryMappedFile, Long> sMemoryMappedFileMap =
-            new HashMap<MemoryMappedFile, Long>();
+    private static final Map<MemoryMappedFile, Long> sMemoryMappedFileMap = new HashMap<>();
 
     private final MappedByteBuffer mMappedByteBuffer;
     private final long mSize;
@@ -64,8 +63,7 @@ public class MemoryMappedFile_Delegate {
             if (!f.exists()) {
                 throw new ErrnoException("File not found: " + f.getPath(), 1);
             }
-            RandomAccessFile file = new RandomAccessFile(f, "r");
-            try {
+            try (RandomAccessFile file = new RandomAccessFile(f, "r")) {
                 long size = file.length();
                 MemoryMappedFile_Delegate newDelegate = new MemoryMappedFile_Delegate(file);
                 long filePointer = file.getFilePointer();
@@ -73,8 +71,6 @@ public class MemoryMappedFile_Delegate {
                 long delegateIndex = sManager.addNewDelegate(newDelegate);
                 sMemoryMappedFileMap.put(mmFile, delegateIndex);
                 return mmFile;
-            } finally {
-                file.close();
             }
         } catch (IOException e) {
             throw new ErrnoException("mmapRO", 1, e);
@@ -98,7 +94,7 @@ public class MemoryMappedFile_Delegate {
 
     // TODO: implement littleEndianIterator()
 
-    public MemoryMappedFile_Delegate(RandomAccessFile file) throws IOException {
+    private MemoryMappedFile_Delegate(RandomAccessFile file) throws IOException {
         mSize = file.length();
         // It's weird that map() takes size as long, but returns MappedByteBuffer which uses an int
         // to store the marker to the position.
diff --git a/bridge/src/libcore/util/NativeAllocationRegistry_Delegate.java b/bridge/src/libcore/util/NativeAllocationRegistry_Delegate.java
index 857b4fec6f..0383b51dcd 100644
--- a/bridge/src/libcore/util/NativeAllocationRegistry_Delegate.java
+++ b/bridge/src/libcore/util/NativeAllocationRegistry_Delegate.java
@@ -51,6 +51,34 @@ public class NativeAllocationRegistry_Delegate {
     }
 
     @LayoutlibDelegate
+    public static NativeAllocationRegistry createMalloced(ClassLoader classLoader,
+            long freeFunction, long size) {
+        if (classLoader == null) {
+            classLoader = NativeAllocationRegistry_Delegate.class.getClassLoader();
+        }
+        return NativeAllocationRegistry.createMalloced_Original(classLoader, freeFunction, size);
+    }
+
+    @LayoutlibDelegate
+    public static NativeAllocationRegistry createMalloced(ClassLoader classLoader,
+            long freeFunction) {
+        if (classLoader == null) {
+            classLoader = NativeAllocationRegistry_Delegate.class.getClassLoader();
+        }
+        return NativeAllocationRegistry.createMalloced_Original(classLoader, freeFunction);
+    }
+
+    @LayoutlibDelegate
+    public static NativeAllocationRegistry createMalloced(Class clazz, long freeFunction,
+            long size) {
+        return NativeAllocationRegistry.createMalloced_Original(clazz, freeFunction, size);
+    }
+
+    @LayoutlibDelegate
+    public static NativeAllocationRegistry createMalloced(Class clazz, long freeFunction) {
+        return NativeAllocationRegistry.createMalloced_Original(clazz, freeFunction);
+    }
+
     /*package*/ static void applyFreeFunction(long freeFunction, long nativePtr) {
         // This method MIGHT run in the context of the finalizer thread. If the delegate method
         // crashes, it could bring down the VM. That's why we catch all the exceptions and ignore
@@ -60,7 +88,8 @@ public class NativeAllocationRegistry_Delegate {
             if (delegate != null) {
                 delegate.mFinalizer.free(nativePtr);
             } else if (freeFunction != 0) {
-                nativeApplyFreeFunction(freeFunction, nativePtr);
+               // Call the real method
+                NativeAllocationRegistry.applyFreeFunction(freeFunction, nativePtr);
             }
         } catch (Throwable ignore) {
         }
@@ -69,6 +98,4 @@ public class NativeAllocationRegistry_Delegate {
     public interface FreeFunction {
         void free(long nativePtr);
     }
-
-    private static native void nativeApplyFreeFunction(long freeFunction, long nativePtr);
 }
diff --git a/bridge/tests/bridge_tests.iml b/bridge/tests/bridge_tests.iml
index 8494210f69..fff1e6bb40 100644
--- a/bridge/tests/bridge_tests.iml
+++ b/bridge/tests/bridge_tests.iml
@@ -25,5 +25,7 @@
     <orderEntry type="library" name="tools-common-prebuilt" level="project" />
     <orderEntry type="module" module-name="common" />
     <orderEntry type="module" module-name="validator" />
+    <orderEntry type="library" name="sdk-common" level="project" />
+    <orderEntry type="library" name="trove4j" level="project" />
   </component>
 </module>
\ No newline at end of file
diff --git a/bridge/tests/res/testApp/MyApplication/golden/a11y_test1.png b/bridge/tests/res/testApp/MyApplication/golden/a11y_test1.png
index 7108915e9d..067a19363e 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/a11y_test1.png and b/bridge/tests/res/testApp/MyApplication/golden/a11y_test1.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/activity.png b/bridge/tests/res/testApp/MyApplication/golden/activity.png
index 4546682d06..c0d57856ed 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/activity.png and b/bridge/tests/res/testApp/MyApplication/golden/activity.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon.png
index b438464c6c..34d3088dbc 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_circle.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_circle.png
index e939a572ec..e8e1401abe 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_circle.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_circle.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png
index b70c65d05e..1348f00de2 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png
index 31647c615d..8bee0a8544 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_rounded_corners.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_rounded_corners.png
index 67deb6e4d4..7eb6605c5c 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_rounded_corners.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_rounded_corners.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_squircle.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_squircle.png
index 6e63ef2286..e636003535 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_squircle.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_squircle.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png
index 7ac28b683a..d22ba99053 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png
index 50b5f26443..4a1ec67a11 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/animated_vector.png b/bridge/tests/res/testApp/MyApplication/golden/animated_vector.png
index 3887e292e3..fb91dd4154 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/animated_vector.png and b/bridge/tests/res/testApp/MyApplication/golden/animated_vector.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/animated_vector_1.png b/bridge/tests/res/testApp/MyApplication/golden/animated_vector_1.png
index 9588148737..4d6864c9f7 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/animated_vector_1.png and b/bridge/tests/res/testApp/MyApplication/golden/animated_vector_1.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/array_check.png b/bridge/tests/res/testApp/MyApplication/golden/array_check.png
index ccdd9c180d..db6e934548 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/array_check.png and b/bridge/tests/res/testApp/MyApplication/golden/array_check.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/asset.png b/bridge/tests/res/testApp/MyApplication/golden/asset.png
index f4467d6c1d..831175ac6b 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/asset.png and b/bridge/tests/res/testApp/MyApplication/golden/asset.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/auto-scale-image.png b/bridge/tests/res/testApp/MyApplication/golden/auto-scale-image.png
index 7cabc39941..9da8534151 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/auto-scale-image.png and b/bridge/tests/res/testApp/MyApplication/golden/auto-scale-image.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/button_resize.png b/bridge/tests/res/testApp/MyApplication/golden/button_resize.png
index d1ed37b386..5c3df0d1b7 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/button_resize.png and b/bridge/tests/res/testApp/MyApplication/golden/button_resize.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png b/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png
index 28aa155f9b..c806502d58 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png and b/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/canvas.png b/bridge/tests/res/testApp/MyApplication/golden/canvas.png
index ff23e2c1f8..55f84c0073 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/canvas.png and b/bridge/tests/res/testApp/MyApplication/golden/canvas.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/color_interpolation.png b/bridge/tests/res/testApp/MyApplication/golden/color_interpolation.png
index 09efad4f6f..c816e57273 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/color_interpolation.png and b/bridge/tests/res/testApp/MyApplication/golden/color_interpolation.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/context_theme_wrapper.png b/bridge/tests/res/testApp/MyApplication/golden/context_theme_wrapper.png
index 9e08e22488..cf0e06d1bb 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/context_theme_wrapper.png and b/bridge/tests/res/testApp/MyApplication/golden/context_theme_wrapper.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png
index 445797f10d..02e5c26bfa 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png b/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png
index 34ff1adccf..871188c397 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png and b/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dialog.png b/bridge/tests/res/testApp/MyApplication/golden/dialog.png
index 55250f2860..2f029e5a52 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dialog.png and b/bridge/tests/res/testApp/MyApplication/golden/dialog.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/expand_horz_layout.png b/bridge/tests/res/testApp/MyApplication/golden/expand_horz_layout.png
index 7b1f1f1e02..21568fcff7 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/expand_horz_layout.png and b/bridge/tests/res/testApp/MyApplication/golden/expand_horz_layout.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/expand_vert_layout.png b/bridge/tests/res/testApp/MyApplication/golden/expand_vert_layout.png
index d6a4c5c586..d0f71278b2 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/expand_vert_layout.png and b/bridge/tests/res/testApp/MyApplication/golden/expand_vert_layout.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/font_test.png b/bridge/tests/res/testApp/MyApplication/golden/font_test.png
index 22da766330..e036c162ad 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/font_test.png and b/bridge/tests/res/testApp/MyApplication/golden/font_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners.png
index 4e7feb443f..dc41617323 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png
index 39a1e758d7..dc41617323 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png
index 7f6663f375..783d52f874 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/gradient_alpha_drawable.png b/bridge/tests/res/testApp/MyApplication/golden/gradient_alpha_drawable.png
index 8892bcf6e1..ff79e74396 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/gradient_alpha_drawable.png and b/bridge/tests/res/testApp/MyApplication/golden/gradient_alpha_drawable.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/gradient_colors.png b/bridge/tests/res/testApp/MyApplication/golden/gradient_colors.png
index f478afe0dd..d5b7c101a2 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/gradient_colors.png and b/bridge/tests/res/testApp/MyApplication/golden/gradient_colors.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png
new file mode 100644
index 0000000000..9ca7777be0
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png
new file mode 100644
index 0000000000..fd0eba67d9
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/html.png b/bridge/tests/res/testApp/MyApplication/golden/html.png
index 9d37ec87b5..0327975e7d 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/html.png and b/bridge/tests/res/testApp/MyApplication/golden/html.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png b/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png
index dbf22b1c39..48078217cb 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png and b/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/justified_none.png b/bridge/tests/res/testApp/MyApplication/golden/justified_none.png
index e2d44056a0..e083346b66 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/justified_none.png and b/bridge/tests/res/testApp/MyApplication/golden/justified_none.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png
index 3e85a227b5..71d38e0219 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/large_shadows_test.png b/bridge/tests/res/testApp/MyApplication/golden/large_shadows_test.png
index 045b5235c2..3b959812b8 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/large_shadows_test.png and b/bridge/tests/res/testApp/MyApplication/golden/large_shadows_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png
index b77b48d472..db0b4ea0e6 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png b/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png
index a37d8dee26..871188c397 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png and b/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png b/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png
index 318ced9328..ea5750c79c 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png and b/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/ninepatch_background.png b/bridge/tests/res/testApp/MyApplication/golden/ninepatch_background.png
index 6403637078..0b71897ced 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/ninepatch_background.png and b/bridge/tests/res/testApp/MyApplication/golden/ninepatch_background.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/ninepatch_drawable.png b/bridge/tests/res/testApp/MyApplication/golden/ninepatch_drawable.png
index de69d8d2c5..211594dfe3 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/ninepatch_drawable.png and b/bridge/tests/res/testApp/MyApplication/golden/ninepatch_drawable.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/ondraw_crash.png b/bridge/tests/res/testApp/MyApplication/golden/ondraw_crash.png
index 4051b05ca2..bab5b53aa6 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/ondraw_crash.png and b/bridge/tests/res/testApp/MyApplication/golden/ondraw_crash.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/onmeasure_crash.png b/bridge/tests/res/testApp/MyApplication/golden/onmeasure_crash.png
index e27ae9eb39..d8b3c964d8 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/onmeasure_crash.png and b/bridge/tests/res/testApp/MyApplication/golden/onmeasure_crash.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/render_effect.png b/bridge/tests/res/testApp/MyApplication/golden/render_effect.png
index 792f2bd85f..7a909981e9 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/render_effect.png and b/bridge/tests/res/testApp/MyApplication/golden/render_effect.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/shadow_scrollview_test.png b/bridge/tests/res/testApp/MyApplication/golden/shadow_scrollview_test.png
index 55a9982b5d..04b56b9e89 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/shadow_scrollview_test.png and b/bridge/tests/res/testApp/MyApplication/golden/shadow_scrollview_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/shadow_sizes_test.png b/bridge/tests/res/testApp/MyApplication/golden/shadow_sizes_test.png
index 6093824921..ded2457d03 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/shadow_sizes_test.png and b/bridge/tests/res/testApp/MyApplication/golden/shadow_sizes_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/shadows_test.png b/bridge/tests/res/testApp/MyApplication/golden/shadows_test.png
index 0ef304ec4e..470f34e314 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/shadows_test.png and b/bridge/tests/res/testApp/MyApplication/golden/shadows_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/shadows_test_rounded_edge.png b/bridge/tests/res/testApp/MyApplication/golden/shadows_test_rounded_edge.png
index f1437af29a..29cb244d90 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/shadows_test_rounded_edge.png and b/bridge/tests/res/testApp/MyApplication/golden/shadows_test_rounded_edge.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png b/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png
index 460c199da7..afa2082eff 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png and b/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/simple_activity.png b/bridge/tests/res/testApp/MyApplication/golden/simple_activity.png
index 1300dd0cca..d1d943bb00 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/simple_activity.png and b/bridge/tests/res/testApp/MyApplication/golden/simple_activity.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/simple_activity_noactionbar.png b/bridge/tests/res/testApp/MyApplication/golden/simple_activity_noactionbar.png
index 7852c9e323..127ce819c3 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/simple_activity_noactionbar.png and b/bridge/tests/res/testApp/MyApplication/golden/simple_activity_noactionbar.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/software_layer.png b/bridge/tests/res/testApp/MyApplication/golden/software_layer.png
index 70465cf27b..2d4dff9fc0 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/software_layer.png and b/bridge/tests/res/testApp/MyApplication/golden/software_layer.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/textclock.png b/bridge/tests/res/testApp/MyApplication/golden/textclock.png
index 7f1ccc6aff..108380c4d3 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/textclock.png and b/bridge/tests/res/testApp/MyApplication/golden/textclock.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/translate_test.png b/bridge/tests/res/testApp/MyApplication/golden/translate_test.png
index 741c5e05e6..032089f012 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/translate_test.png and b/bridge/tests/res/testApp/MyApplication/golden/translate_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/transparent_drawable.png b/bridge/tests/res/testApp/MyApplication/golden/transparent_drawable.png
index 3df5385e7d..68ccf2f91d 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/transparent_drawable.png and b/bridge/tests/res/testApp/MyApplication/golden/transparent_drawable.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png b/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png
index dd58a0b56d..e3f4df7c20 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png and b/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable.png
index b7905fc5bd..1d4a6781b9 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_91383.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_91383.png
index 03da31efc0..88c09b59a5 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_91383.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_91383.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_gradient.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_gradient.png
index 67e502fccd..7dc966a6d4 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_gradient.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_gradient.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_radial_gradient.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_radial_gradient.png
index 4b1425ac89..41c8e22acf 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_radial_gradient.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_radial_gradient.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_in_image_view.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_in_image_view.png
index 055af89473..13275d331b 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_in_image_view.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_in_image_view.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_itself.png b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_itself.png
index 99e37aed57..02a8085fab 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_itself.png and b/bridge/tests/res/testApp/MyApplication/golden/vector_drawable_with_tint_itself.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/view_boundaries.png b/bridge/tests/res/testApp/MyApplication/golden/view_boundaries.png
index b1e4a7c505..50d2a888c6 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/view_boundaries.png and b/bridge/tests/res/testApp/MyApplication/golden/view_boundaries.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/view_stub.png b/bridge/tests/res/testApp/MyApplication/golden/view_stub.png
index 14566c8f69..b66ff2d524 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/view_stub.png and b/bridge/tests/res/testApp/MyApplication/golden/view_stub.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/window_background.png b/bridge/tests/res/testApp/MyApplication/golden/window_background.png
index a43d4dfc04..1d25725e4e 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/window_background.png and b/bridge/tests/res/testApp/MyApplication/golden/window_background.png differ
diff --git a/bridge/tests/run_tests.sh b/bridge/tests/run_tests.sh
index fd5c817efe..376e948f17 100755
--- a/bridge/tests/run_tests.sh
+++ b/bridge/tests/run_tests.sh
@@ -15,12 +15,10 @@ readonly USE_SOONG=1
 readonly APP_NAME="regression"
 #readonly APP_NAME="test_HelloActivity"
 
-STUDIO_JDK="${BASE_DIR}/prebuilts/jdk/jdk17/linux-x86"
-MISC_COMMON="${BASE_DIR}/prebuilts/misc/common"
-OUT_INTERMEDIATES="${BASE_DIR}/out/soong/.intermediates"
+STUDIO_JDK="${BASE_DIR}/prebuilts/jdk/jdk21/linux-x86"
 NATIVE_LIBRARIES="${BASE_DIR}/out/host/linux-x86/lib64/"
 JAVA_LIBRARIES="${BASE_DIR}/out/host/common/obj/JAVA_LIBRARIES/"
-HOST_LIBRARIES="${BASE_DIR}/out/host/linux-x86/"
+HOST_LIBRARIES="${BASE_DIR}/out/host/linux-x86"
 SDK="${BASE_DIR}/out/host/linux-x86/sdk/sdk*/android-sdk*"
 SDK_REPO="${BASE_DIR}/out/host/linux-x86/sdk-repo"
 FONT_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/fonts_intermediates"
@@ -52,7 +50,7 @@ if [ ! -d $TMP_DIR ]; then
 fi
 
 
-TEST_JARS="${OUT_INTERMEDIATES}/frameworks/layoutlib/bridge/tests/layoutlib-tests/linux_glibc_common/withres/layoutlib-tests.jar"
+TEST_JARS="${HOST_LIBRARIES}/framework/layoutlib-tests.jar"
 GRADLE_RES="-Dtest_res.dir=${SCRIPT_DIR}/res"
 
 # Run layoutlib tests
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/BridgeRenderSessionTest.java b/bridge/tests/src/com/android/layoutlib/bridge/BridgeRenderSessionTest.java
index 5ef42e66a8..5615e21113 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/BridgeRenderSessionTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/BridgeRenderSessionTest.java
@@ -16,7 +16,6 @@
 
 package com.android.layoutlib.bridge;
 
-import com.android.ide.common.rendering.api.Result;
 import com.android.ide.common.rendering.api.Result.Status;
 
 import org.junit.Test;
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/TestDelegates.java b/bridge/tests/src/com/android/layoutlib/bridge/TestDelegates.java
index 60db306f62..db41c60386 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/TestDelegates.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/TestDelegates.java
@@ -42,7 +42,7 @@ import junit.framework.TestCase;
  */
 public class TestDelegates extends TestCase {
 
-    private List<String> mErrors = new ArrayList<String>();
+    private final List<String> mErrors = new ArrayList<>();
 
     public void testNativeDelegates() {
 
@@ -76,15 +76,13 @@ public class TestDelegates extends TestCase {
             Class<?> delegateClass = classLoader.loadClass(delegateClassName);
 
             compare(originalClass, delegateClass);
-        } catch (ClassNotFoundException e) {
-            mErrors.add("Failed to load class: " + e.getMessage());
-        } catch (SecurityException e) {
+        } catch (ClassNotFoundException | SecurityException e) {
             mErrors.add("Failed to load class: " + e.getMessage());
         }
     }
 
     private void compare(Class<?> originalClass, Class<?> delegateClass) throws SecurityException {
-        List<Method> checkedDelegateMethods = new ArrayList<Method>();
+        List<Method> checkedDelegateMethods = new ArrayList<>();
 
         // loop on the methods of the original class, and for the ones that are annotated
         // with @LayoutlibDelegate, look for a matching method in the delegate class.
@@ -205,9 +203,7 @@ public class TestDelegates extends TestCase {
                 theClass = theClass.getComponentType();
             }
             sb.append(theClass.getName());
-            for (int i = 0; i < dimensions; i++) {
-                sb.append("[]");
-            }
+            sb.append("[]".repeat(Math.max(0, dimensions)));
             if (j < (parameters.length - 1)) {
                 sb.append(",");
             }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/AccessibilityTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/AccessibilityTest.java
index e1cad4ee2d..2925c2f9d6 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/AccessibilityTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/AccessibilityTest.java
@@ -34,7 +34,6 @@ import android.view.ViewGroup;
 import android.view.accessibility.AccessibilityInteractionClient;
 import android.view.accessibility.AccessibilityNodeInfo;
 
-import java.io.FileNotFoundException;
 import java.util.ArrayList;
 import java.util.List;
 
@@ -49,8 +48,7 @@ public class AccessibilityTest extends RenderTestBase {
     }
 
     @Test
-    public void accessibilityNodeInfoCreation() throws FileNotFoundException,
-            ClassNotFoundException {
+    public void accessibilityNodeInfoCreation() throws ClassNotFoundException {
         LayoutPullParser parser = createParserFromPath("allwidgets.xml");
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -61,27 +59,29 @@ public class AccessibilityTest extends RenderTestBase {
                 .setCallback(layoutLibCallback)
                 .build();
         RenderSession session = sBridge.createSession(params);
+        session.setElapsedFrameTimeNanos(1);
         try {
             Result renderResult = session.render(50000);
             assertTrue(renderResult.isSuccess());
             assertEquals(0, AccessibilityInteractionClient.sConnectionCache.size());
-            View rootView = (View)session.getSystemRootViews().get(0).getViewObject();
-            AccessibilityNodeInfo rootNode = rootView.createAccessibilityNodeInfo();
-            assertNotNull(rootNode);
-            rootNode.setQueryFromAppProcessEnabled(rootView, true);
-            assertEquals(38, rootNode.getChildCount());
-            AccessibilityNodeInfo child = rootNode.getChild(0);
-            assertNotNull(child);
-            assertEquals(136, child.getBoundsInScreen().right);
-            assertEquals(75, child.getBoundsInScreen().bottom);
+            session.execute(() -> {
+                View rootView = (View) session.getSystemRootViews().get(0).getViewObject();
+                AccessibilityNodeInfo rootNode = rootView.createAccessibilityNodeInfo();
+                assertNotNull(rootNode);
+                rootNode.setQueryFromAppProcessEnabled(rootView, true);
+                assertEquals(37, rootNode.getChildCount());
+                AccessibilityNodeInfo child = rootNode.getChild(0);
+                assertNotNull(child);
+                assertEquals(147, child.getBoundsInScreen().right);
+                assertEquals(274, child.getBoundsInScreen().bottom);
+            });
         } finally {
             session.dispose();
         }
     }
 
     @Test
-    public void customHierarchyParserTest() throws FileNotFoundException,
-            ClassNotFoundException {
+    public void customHierarchyParserTest() throws ClassNotFoundException {
         LayoutPullParser parser = createParserFromPath("allwidgets.xml");
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -93,8 +93,7 @@ public class AccessibilityTest extends RenderTestBase {
                 .build();
         params.setCustomContentHierarchyParser(viewObject -> {
             List<ViewInfo> result = new ArrayList<>();
-            if (viewObject instanceof ViewGroup) {
-                ViewGroup view = (ViewGroup)viewObject;
+            if (viewObject instanceof ViewGroup view) {
                 for (int i = 0; i < view.getChildCount(); i++) {
                     View child = view.getChildAt(i);
                     ViewInfo childInfo =
@@ -108,6 +107,7 @@ public class AccessibilityTest extends RenderTestBase {
             return result;
         });
         RenderSession session = sBridge.createSession(params);
+        session.setElapsedFrameTimeNanos(1);
         try {
             Result renderResult = session.render(50000);
             assertTrue(renderResult.isSuccess());
@@ -123,16 +123,17 @@ public class AccessibilityTest extends RenderTestBase {
 
     @Test
     public void testDialogAccessibility() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.DialogView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <com.android.layoutlib.test.myapplication.widgets.DialogView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/BitmapTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/BitmapTest.java
index 4c0ac4ce30..4add0edf38 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/BitmapTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/BitmapTest.java
@@ -64,17 +64,17 @@ public class BitmapTest extends RenderTestBase {
         Assert.assertArrayEquals(compiledBitmap.getNinePatchChunk(), ninePatch.getChunk().getSerializedChunk());
     }
 
-//    @Test
-//    public void testNativeBitmap() {
-//        InputStream compiled =
-//                getClass().getResourceAsStream("/com/android/layoutlib/testdata/compiled.9.png");
-//        Bitmap compiledBitmap = BitmapFactory.decodeStream(compiled, null, null);
-//        assertNotNull(compiledBitmap);
-//        Buffer buffer = ByteBuffer.allocate(compiledBitmap.getByteCount());
-//        compiledBitmap.copyPixelsToBuffer(buffer);
-//        buffer.rewind();
-//        compiledBitmap.copyPixelsFromBuffer(buffer);
-//    }
+    @Test
+    public void testNativeBitmap() {
+        InputStream compiled =
+                getClass().getResourceAsStream("/com/android/layoutlib/testdata/compiled.9.png");
+        Bitmap compiledBitmap = BitmapFactory.decodeStream(compiled, null, null);
+        assertNotNull(compiledBitmap);
+        Buffer buffer = ByteBuffer.allocate(compiledBitmap.getByteCount());
+        compiledBitmap.copyPixelsToBuffer(buffer);
+        buffer.rewind();
+        compiledBitmap.copyPixelsFromBuffer(buffer);
+    }
 
     @Test
     public void testImageDecoder() throws Exception {
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
index 98125001eb..215da97471 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
@@ -179,7 +179,7 @@ public class BridgeContextTest extends RenderTestBase {
                 params.getTargetSdkVersion(), params.isRtlSupported());
         context.initResources(params.getAssets());
         try {
-            assertEquals(-13749965, context.getResources().getColor(android.R.color.system_neutral1_800, null));
+            assertEquals(-13684682, context.getResources().getColor(android.R.color.system_neutral1_800, null));
 
             ((DynamicRenderResources) context.getRenderResources()).setWallpaper(
                     "/com/android/layoutlib/testdata/wallpaper1.webp",
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
index ec7aa768fd..509c38f493 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
@@ -57,5 +57,9 @@ public class DynamicRenderResourcesTest extends RenderTestBase {
         assertEquals(-4632, (int)dynamicColorMap.get("system_neutral2_50"));
         assertEquals(-4413535, (int)dynamicColorMap.get("system_neutral2_300"));
         assertEquals(-12899031, (int)dynamicColorMap.get("system_neutral2_800"));
+
+        assertEquals(-8956083, (int)dynamicColorMap.get("system_secondary_light"));
+        assertEquals(-1589839, (int)dynamicColorMap.get("system_secondary_dark"));
+        assertEquals(-12973312, (int)dynamicColorMap.get("system_on_primary_fixed"));
     }
 }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/RenderTestBase.java b/bridge/tests/src/com/android/layoutlib/bridge/android/RenderTestBase.java
index ee41c6cd41..a5d0b9f187 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/RenderTestBase.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/RenderTestBase.java
@@ -26,7 +26,7 @@ import com.android.layoutlib.bridge.intensive.BridgeClient;
 
 public class RenderTestBase extends BridgeClient {
     private static final String RESOURCE_DIR_PROPERTY = "test_res.dir";
-    public static final String S_PACKAGE_NAME = "com.android.layoutlib.test.myapplication";
+    private static final String S_PACKAGE_NAME = "com.android.layoutlib.test.myapplication";
 
     public String getAppTestDir() {
         return "testApp/MyApplication";
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/impl/LayoutParserWrapperTest.java b/bridge/tests/src/com/android/layoutlib/bridge/impl/LayoutParserWrapperTest.java
index 2c33862230..04a7a905ca 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/impl/LayoutParserWrapperTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/impl/LayoutParserWrapperTest.java
@@ -92,92 +92,94 @@ public class LayoutParserWrapperTest {
 
     private static final String sDataBindingLayout =
             //language=XML
-            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
-                    "<layout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                    "        xmlns:app=\"http://schemas.android.com/apk/res-auto\"\n" +
-                    "        xmlns:tools=\"http://schemas.android.com/tools\"\n" +
-                    "        tools:context=\".MainActivity\"\n" +
-                    "        tools:showIn=\"@layout/activity_main\">\n" +
-                    "\n" +
-                    "    <data>\n" +
-                    "\n" +
-                    "        <variable\n" +
-                    "            name=\"user\"\n" +
-                    "            type=\"com.example.User\" />\n" +
-                    "        <variable\n" +
-                    "            name=\"activity\"\n" +
-                    "            type=\"com.example.MainActivity\" />\n" +
-                    "    </data>\n" +
-                    "\n" +
-                    "    <RelativeLayout\n" +
-                    "        android:layout_width=\"match_parent\"\n" +
-                    "        android:layout_height=\"match_parent\"\n" +
-                    "        android:paddingBottom=\"@dimen/activity_vertical_margin\"\n" +
-                    "        android:paddingLeft=\"@dimen/activity_horizontal_margin\"\n" +
-                    "        android:paddingRight=\"@dimen/activity_horizontal_margin\"\n" +
-                    "        android:paddingTop=\"@dimen/activity_vertical_margin\"\n" +
-                    "        app:layout_behavior=\"@string/appbar_scrolling_view_behavior\"\n" +
-                    "    >\n" +
-                    "\n" +
-                    "        <TextView\n" +
-                    "            android:id=\"@+id/first\"\n" +
-                    "            android:layout_width=\"wrap_content\"\n" +
-                    "            android:layout_alignParentStart=\"true\"\n" +
-                    "            android:layout_alignParentLeft=\"true\"\n" +
-                    "            android:layout_height=\"wrap_content\"\n" +
-                    "            android:text=\"@{user.firstName,default=World}\" />\n" +
-                    "\n" +
-                    "        <TextView\n" +
-                    "            android:id=\"@+id/last\"\n" +
-                    "            android:layout_width=\"wrap_content\"\n" +
-                    "            android:layout_height=\"wrap_content\"\n" +
-                    "            android:layout_toEndOf=\"@id/first\"\n" +
-                    "            android:layout_toRightOf=\"@id/first\"\n" +
-                    "            android:text=\"@{user.lastName,default=Hello}\" />\n" +
-                    "\n" +
-                    "        <Button\n" +
-                    "            android:layout_width=\"wrap_content\"\n" +
-                    "            android:layout_height=\"wrap_content\"\n" +
-                    "            android:layout_below=\"@id/last\"\n" +
-                    "            android:text=\"Submit\"\n" +
-                    "            android:onClick=\"@{activity.onClick}\"/>\n" +
-                    "    </RelativeLayout>\n" +
-                    "</layout>";
+            """
+                    <?xml version="1.0" encoding="utf-8"?>
+                    <layout xmlns:android="http://schemas.android.com/apk/res/android"
+                            xmlns:app="http://schemas.android.com/apk/res-auto"
+                            xmlns:tools="http://schemas.android.com/tools"
+                            tools:context=".MainActivity"
+                            tools:showIn="@layout/activity_main">
+
+                        <data>
+
+                            <variable
+                                name="user"
+                                type="com.example.User" />
+                            <variable
+                                name="activity"
+                                type="com.example.MainActivity" />
+                        </data>
+
+                        <RelativeLayout
+                            android:layout_width="match_parent"
+                            android:layout_height="match_parent"
+                            android:paddingBottom="@dimen/activity_vertical_margin"
+                            android:paddingLeft="@dimen/activity_horizontal_margin"
+                            android:paddingRight="@dimen/activity_horizontal_margin"
+                            android:paddingTop="@dimen/activity_vertical_margin"
+                            app:layout_behavior="@string/appbar_scrolling_view_behavior"
+                        >
+
+                            <TextView
+                                android:id="@+id/first"
+                                android:layout_width="wrap_content"
+                                android:layout_alignParentStart="true"
+                                android:layout_alignParentLeft="true"
+                                android:layout_height="wrap_content"
+                                android:text="@{user.firstName,default=World}" />
+
+                            <TextView
+                                android:id="@+id/last"
+                                android:layout_width="wrap_content"
+                                android:layout_height="wrap_content"
+                                android:layout_toEndOf="@id/first"
+                                android:layout_toRightOf="@id/first"
+                                android:text="@{user.lastName,default=Hello}" />
+
+                            <Button
+                                android:layout_width="wrap_content"
+                                android:layout_height="wrap_content"
+                                android:layout_below="@id/last"
+                                android:text="Submit"
+                                android:onClick="@{activity.onClick}"/>
+                        </RelativeLayout>
+                    </layout>""";
 
     private static final String sNonDataBindingLayout =
             //language=XML
-            "<RelativeLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                    "    xmlns:app=\"http://schemas.android.com/apk/res-auto\"\n" +
-                    "    android:layout_width=\"match_parent\"\n" +
-                    "    android:layout_height=\"match_parent\"\n" +
-                    "    android:paddingBottom=\"@dimen/activity_vertical_margin\"\n" +
-                    "    android:paddingLeft=\"@dimen/activity_horizontal_margin\"\n" +
-                    "    android:paddingRight=\"@dimen/activity_horizontal_margin\"\n" +
-                    "    android:paddingTop=\"@dimen/activity_vertical_margin\"\n" +
-                    "    app:layout_behavior=\"@string/appbar_scrolling_view_behavior\"\n" +
-                    ">\n" +
-                    "\n" +
-                    "    <TextView\n" +
-                    "        android:id=\"@+id/first\"\n" +
-                    "        android:layout_width=\"wrap_content\"\n" +
-                    "        android:layout_alignParentStart=\"true\"\n" +
-                    "        android:layout_alignParentLeft=\"true\"\n" +
-                    "        android:layout_height=\"wrap_content\"\n" +
-                    "        android:text=\"@{user.firstName,default=World}\" />\n" +
-                    "\n" +
-                    "    <TextView\n" +
-                    "        android:id=\"@+id/last\"\n" +
-                    "        android:layout_width=\"wrap_content\"\n" +
-                    "        android:layout_height=\"wrap_content\"\n" +
-                    "        android:layout_toEndOf=\"@id/first\"\n" +
-                    "        android:layout_toRightOf=\"@id/first\"\n" +
-                    "        android:text=\"@{user.lastName,default=Hello}\" />\n" +
-                    "\n" +
-                    "    <Button\n" +
-                    "        android:layout_width=\"wrap_content\"\n" +
-                    "        android:layout_height=\"wrap_content\"\n" +
-                    "        android:layout_below=\"@id/last\"\n" +
-                    "        android:text=\"Submit\"\n" +
-                    "        android:onClick=\"@{activity.onClick}\"/>\n" +
-                    "</RelativeLayout>";
+            """
+                    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                        xmlns:app="http://schemas.android.com/apk/res-auto"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent"
+                        android:paddingBottom="@dimen/activity_vertical_margin"
+                        android:paddingLeft="@dimen/activity_horizontal_margin"
+                        android:paddingRight="@dimen/activity_horizontal_margin"
+                        android:paddingTop="@dimen/activity_vertical_margin"
+                        app:layout_behavior="@string/appbar_scrolling_view_behavior"
+                    >
+
+                        <TextView
+                            android:id="@+id/first"
+                            android:layout_width="wrap_content"
+                            android:layout_alignParentStart="true"
+                            android:layout_alignParentLeft="true"
+                            android:layout_height="wrap_content"
+                            android:text="@{user.firstName,default=World}" />
+
+                        <TextView
+                            android:id="@+id/last"
+                            android:layout_width="wrap_content"
+                            android:layout_height="wrap_content"
+                            android:layout_toEndOf="@id/first"
+                            android:layout_toRightOf="@id/first"
+                            android:text="@{user.lastName,default=Hello}" />
+
+                        <Button
+                            android:layout_width="wrap_content"
+                            android:layout_height="wrap_content"
+                            android:layout_below="@id/last"
+                            android:text="Submit"
+                            android:onClick="@{activity.onClick}"/>
+                    </RelativeLayout>""";
 }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java b/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
index 95ec97de36..062a27413e 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
@@ -25,6 +25,8 @@ import com.android.layoutlib.bridge.android.BridgeXmlBlockParserTest;
 import com.android.layoutlib.bridge.android.DynamicRenderResourcesTest;
 import com.android.layoutlib.bridge.impl.LayoutParserWrapperTest;
 import com.android.layoutlib.bridge.impl.ResourceHelperTest;
+import com.android.layoutlib.bridge.util.ChoreographerCallbacksTest;
+import com.android.layoutlib.bridge.util.HandlerMessageQueueTest;
 import com.android.tools.idea.validator.LayoutValidatorTests;
 import com.android.tools.idea.validator.ValidatorResultTests;
 import com.android.tools.idea.validator.AccessibilityValidatorTests;
@@ -48,7 +50,7 @@ import android.util.BridgeXmlPullAttributesTest;
         BridgeContextTest.class, Resources_DelegateTest.class, ShadowsRenderTests.class,
         LayoutValidatorTests.class, AccessibilityValidatorTests.class, BridgeTypedArrayTest.class,
         ValidatorResultTests.class, BitmapTest.class, DynamicRenderResourcesTest.class,
-        AccessibilityTest.class
+        AccessibilityTest.class, ChoreographerCallbacksTest.class, HandlerMessageQueueTest.class
 })
 public class Main {
 }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
index b47b829721..23fe8434ab 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
@@ -25,6 +25,7 @@ import com.android.ide.common.rendering.api.SessionParams;
 import com.android.ide.common.rendering.api.SessionParams.RenderingMode;
 import com.android.ide.common.rendering.api.ViewInfo;
 import com.android.ide.common.rendering.api.XmlParserFactory;
+import com.android.ide.common.resources.ResourceValueMap;
 import com.android.internal.R;
 import com.android.internal.lang.System_Delegate;
 import com.android.layoutlib.bridge.android.BridgeContext;
@@ -65,12 +66,13 @@ import java.awt.image.BufferedImage;
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.FileOutputStream;
-import java.io.IOException;
 import java.io.PrintWriter;
 import java.lang.reflect.Field;
+import java.util.Map;
 import java.util.concurrent.TimeUnit;
 
 import static android.os._Original_Build.VERSION.SDK_INT;
+import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_SHOW_CUTOUT;
 import static com.android.layoutlib.bridge.android.RenderParamsFlags.FLAG_KEY_USE_GESTURE_NAV;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
@@ -94,33 +96,26 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testActivityOnOldTheme() throws ClassNotFoundException, FileNotFoundException {
+    public void testActivityOnOldTheme() throws ClassNotFoundException {
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
         layoutLibCallback.initResources();
 
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<RelativeLayout xmlns:android=\"http://schemas" +
-                        ".android.com/apk/res/android\"\n" +
-                        "                android:layout_width=\"match_parent\"\n" +
-                        "                android:layout_height=\"match_parent\"\n" +
-                        "                android:paddingLeft=\"@dimen/activity_horizontal_margin"
-                        + "\"\n"
-                        +
-                        "                android:paddingRight=\"@dimen/activity_horizontal_margin"
-                        + "\"\n"
-                        +
-                        "                android:paddingTop=\"@dimen/activity_vertical_margin\"\n" +
-                        "                android:paddingBottom=\"@dimen/activity_vertical_margin"
-                        + "\">\n"
-                        +
-                        "    <TextView\n" +
-                        "        android:text=\"@string/hello_world\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"200dp\"\n" +
-                        "        android:background=\"#FF0000\"\n" +
-                        "        android:id=\"@+id/text1\"/>\n" +
-                        "</RelativeLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                                android:layout_width="match_parent"
+                                android:layout_height="match_parent"
+                                android:paddingLeft="@dimen/activity_horizontal_margin"
+                                android:paddingRight="@dimen/activity_horizontal_margin"
+                                android:paddingTop="@dimen/activity_vertical_margin"
+                                android:paddingBottom="@dimen/activity_vertical_margin">
+                    <TextView
+                        android:text="@string/hello_world"
+                        android:layout_width="wrap_content"
+                        android:layout_height="200dp"
+                        android:background="#FF0000"
+                        android:id="@+id/text1"/>
+                </RelativeLayout>""");
         SessionParams params = getSessionParamsBuilder()
                 .setParser(parser)
                 .setCallback(layoutLibCallback)
@@ -131,7 +126,7 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testTranslucentBars() throws ClassNotFoundException, FileNotFoundException {
+    public void testTranslucentBars() throws ClassNotFoundException {
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
         layoutLibCallback.initResources();
@@ -163,7 +158,7 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testAllWidgets() throws ClassNotFoundException, FileNotFoundException {
+    public void testAllWidgets() throws ClassNotFoundException {
         LayoutPullParser parser = createParserFromPath("allwidgets.xml");
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -183,7 +178,7 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testAllWidgetsTablet() throws ClassNotFoundException, FileNotFoundException {
+    public void testAllWidgetsTablet() throws ClassNotFoundException {
         LayoutPullParser parser = createParserFromPath("allwidgets.xml");
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -198,27 +193,21 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testActivityActionBar() throws ClassNotFoundException {
-        String simpleActivity =
-                "<RelativeLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "                android:layout_width=\"match_parent\"\n" +
-                        "                android:layout_height=\"match_parent\"\n" +
-                        "                android:paddingLeft=\"@dimen/activity_horizontal_margin"
-                        + "\"\n"
-                        +
-                        "                android:paddingRight=\"@dimen/activity_horizontal_margin"
-                        + "\"\n"
-                        +
-                        "                android:paddingTop=\"@dimen/activity_vertical_margin\"\n" +
-                        "                android:paddingBottom=\"@dimen/activity_vertical_margin"
-                        + "\">\n"
-                        +
-                        "    <TextView\n" +
-                        "        android:text=\"@string/hello_world\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"200dp\"\n" +
-                        "        android:background=\"#FF0000\"\n" +
-                        "        android:id=\"@+id/text1\"/>\n" +
-                        "</RelativeLayout>";
+        String simpleActivity = """
+                <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                                android:layout_width="match_parent"
+                                android:layout_height="match_parent"
+                                android:paddingLeft="@dimen/activity_horizontal_margin"
+                                android:paddingRight="@dimen/activity_horizontal_margin"
+                                android:paddingTop="@dimen/activity_vertical_margin"
+                                android:paddingBottom="@dimen/activity_vertical_margin">
+                    <TextView
+                        android:text="@string/hello_world"
+                        android:layout_width="wrap_content"
+                        android:layout_height="200dp"
+                        android:background="#FF0000"
+                        android:id="@+id/text1"/>
+                </RelativeLayout>""";
 
         LayoutPullParser parser = LayoutPullParser.createFromString(simpleActivity);
         LayoutLibTestCallback layoutLibCallback =
@@ -262,22 +251,25 @@ public class RenderTests extends RenderTestBase {
             throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
         // We get the widget via reflection to avoid IntelliJ complaining about the class being
         // located in the wrong package. (From the Bridge tests point of view, it is)
-        Class insetsWidgetClass = Class.forName("com.android.layoutlib.test.myapplication.widgets" +
-                ".InsetsWidget");
+        Class<?> insetsWidgetClass = Class.forName(
+                "com.android.layoutlib.test.myapplication.widgets.InsetsWidget");
         Field field = insetsWidgetClass.getDeclaredField("sApplyInsetsCalled");
         assertFalse((Boolean) field.get(null));
 
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"wrap_content\"\n" +
-                        "              android:layout_height=\"wrap_content\">\n" + "\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.InsetsWidget\n" +
-                        "        android:text=\"Hello world\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:id=\"@+id/text1\"/>\n" + "</LinearLayout>\n");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="wrap_content"
+                              android:layout_height="wrap_content">
+
+                    <com.android.layoutlib.test.myapplication.widgets.InsetsWidget
+                        android:text="Hello world"
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:id="@+id/text1"/>
+                </LinearLayout>
+                """);
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
         layoutLibCallback.initResources();
@@ -295,7 +287,7 @@ public class RenderTests extends RenderTestBase {
 
     /** Test expand_layout.xml */
     @Test
-    public void testExpand() throws ClassNotFoundException, FileNotFoundException {
+    public void testExpand() throws ClassNotFoundException {
         // Create the layout pull parser.
         LayoutPullParser parser = createParserFromPath("expand_vert_layout.xml");
         // Create LayoutLibCallback.
@@ -337,7 +329,7 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testShrink() throws ClassNotFoundException, FileNotFoundException {
+    public void testShrink() throws ClassNotFoundException {
         // Create the layout pull parser.
         LayoutPullParser parser = createParserFromPath("expand_vert_layout.xml");
         // Create LayoutLibCallback.
@@ -383,15 +375,19 @@ public class RenderTests extends RenderTestBase {
     /** Test indeterminate_progressbar.xml */
     @Test
     public void testVectorAnimation() throws ClassNotFoundException {
-        String layout = "\n" +
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                "              android:padding=\"16dp\"\n" +
-                "              android:orientation=\"horizontal\"\n" +
-                "              android:layout_width=\"fill_parent\"\n" +
-                "              android:layout_height=\"fill_parent\">\n" + "\n" +
-                "    <ProgressBar\n" + "             android:layout_height=\"fill_parent\"\n" +
-                "             android:layout_width=\"fill_parent\" />\n" + "\n" +
-                "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+
+                    <ProgressBar
+                             android:layout_height="fill_parent"
+                             android:layout_width="fill_parent" />
+
+                </LinearLayout>
+                """;
 
         // Create the layout pull parser.
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
@@ -426,17 +422,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawable() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"fill_parent\"\n" +
-                        "             android:layout_width=\"fill_parent\"\n" +
-                        "             android:src=\"@drawable/multi_path\" />\n" + "\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                             android:layout_height="fill_parent"
+                             android:layout_width="fill_parent"
+                             android:src="@drawable/multi_path" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -459,25 +456,25 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawable91383() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"vertical\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <ImageView\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:src=\"@drawable/android\"/>\n" +
-                        "    <ImageView\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:src=\"@drawable/headset\"/>\n" +
-                        "    <ImageView\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:src=\"@drawable/clipped_even_odd\"/>\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="vertical"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:src="@drawable/android"/>
+                    <ImageView
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:src="@drawable/headset"/>
+                    <ImageView
+                        android:layout_height="wrap_content"
+                        android:layout_width="wrap_content"
+                        android:src="@drawable/clipped_even_odd"/>
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -499,12 +496,12 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawableWithTintInImageView() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<ImageView xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_height=\"match_parent\"\n" +
-                        "    android:layout_width=\"match_parent\"\n" +
-                        "    android:src=\"@drawable/vector_drawable_without_tint\"\n" +
-                        "    android:tint=\"#FF00FF00\" />");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <ImageView xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_height="match_parent"
+                    android:layout_width="match_parent"
+                    android:src="@drawable/vector_drawable_without_tint"
+                    android:tint="#FF00FF00" />""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -527,11 +524,11 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawableWithTintInItself() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<ImageView xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_height=\"match_parent\"\n" +
-                        "    android:layout_width=\"match_parent\"\n" +
-                        "    android:src=\"@drawable/vector_drawable_with_tint\" />");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <ImageView xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_height="match_parent"
+                    android:layout_width="match_parent"
+                    android:src="@drawable/vector_drawable_with_tint" />""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -554,11 +551,11 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testTransparentDrawable() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<ImageView xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_height=\"fill_parent\"\n" +
-                        "    android:layout_width=\"fill_parent\"\n" +
-                        "    android:src=\"@drawable/transparent_drawable\" />");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <ImageView xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_height="fill_parent"
+                    android:layout_width="fill_parent"
+                    android:src="@drawable/transparent_drawable" />""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -585,17 +582,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawableHasMultipleLineInPathData() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/multi_line_of_path_data\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/multi_line_of_path_data" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -623,17 +621,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawableGradient() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/shadow\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/shadow" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -659,17 +658,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testVectorDrawableRadialGradient() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/radial_gradient\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/radial_gradient" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -695,17 +695,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testGradientColors() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/gradient\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/gradient" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -731,17 +732,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testGradientAlphaDrawable() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/vector_gradient_alpha\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/vector_gradient_alpha" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -761,7 +763,7 @@ public class RenderTests extends RenderTestBase {
 
     /** Test activity.xml */
     @Test
-    public void testScrollingAndMeasure() throws ClassNotFoundException, FileNotFoundException {
+    public void testScrollingAndMeasure() throws ClassNotFoundException {
         // Create the layout pull parser.
         LayoutPullParser parser = createParserFromPath("scrolled.xml");
         // Create LayoutLibCallback.
@@ -848,9 +850,8 @@ public class RenderTests extends RenderTestBase {
         assertEquals("android", resources.getResourcePackageName(android.R.style.ButtonBar));
         assertEquals("ButtonBar", resources.getResourceEntryName(android.R.style.ButtonBar));
         assertEquals("style", resources.getResourceTypeName(android.R.style.ButtonBar));
-        Integer id = Resources_Delegate.getLayoutlibCallback(resources).getOrGenerateResourceId(
+        int id = Resources_Delegate.getLayoutlibCallback(resources).getOrGenerateResourceId(
                 new ResourceReference(ResourceNamespace.RES_AUTO, ResourceType.STRING, "app_name"));
-        assertNotNull(id);
         assertEquals("com.android.layoutlib.test.myapplication:string/app_name",
                 resources.getResourceName(id));
         assertEquals("com.android.layoutlib.test.myapplication",
@@ -886,14 +887,9 @@ public class RenderTests extends RenderTestBase {
         Resources resources = Resources_Delegate.initSystem(context, assetManager, metrics,
                 configuration, params.getLayoutlibCallback());
 
-        Integer id =
-                Resources_Delegate.getLayoutlibCallback(resources)
-                        .getOrGenerateResourceId(
-                                new ResourceReference(
-                                        ResourceNamespace.RES_AUTO,
-                                        ResourceType.ARRAY,
-                                        "string_array"));
-        assertNotNull(id);
+        int id = Resources_Delegate.getLayoutlibCallback(resources).getOrGenerateResourceId(
+                new ResourceReference(ResourceNamespace.RES_AUTO, ResourceType.ARRAY,
+                        "string_array"));
         String[] strings = resources.getStringArray(id);
         assertArrayEquals(
                 new String[]{"mystring", "Hello world!", "candidates", "Unknown", "?EC"},
@@ -910,19 +906,20 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testAdaptiveIcon() throws ClassNotFoundException, FileNotFoundException {
+    public void testAdaptiveIcon() throws ClassNotFoundException {
         // Create the layout pull parser.
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\"\n" +
-                        "             android:src=\"@drawable/adaptive\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:src="@drawable/adaptive" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -974,13 +971,14 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testColorStateList() throws Exception {
-        final String STATE_LIST =
-                "<selector xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
-                        "    <item android:state_pressed=\"true\"\n" +
-                        "          android:color=\"?android:attr/colorForeground\"/> \n" +
-                        "    <item android:state_focused=\"true\"\n" +
-                        "          android:color=\"?android:attr/colorBackground\"/> \n" +
-                        "    <item android:color=\"#a000\"/> <!-- default -->\n" + "</selector>";
+        final String STATE_LIST = """
+                <selector xmlns:android="http://schemas.android.com/apk/res/android">
+                    <item android:state_pressed="true"
+                          android:color="?android:attr/colorForeground"/>\s
+                    <item android:state_focused="true"
+                          android:color="?android:attr/colorBackground"/>\s
+                    <item android:color="#a000"/> <!-- default -->
+                </selector>""";
 
         File tmpColorList = File.createTempFile("statelist", "xml");
         try (PrintWriter output = new PrintWriter(new FileOutputStream(tmpColorList))) {
@@ -1145,22 +1143,24 @@ public class RenderTests extends RenderTestBase {
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
         layoutLibCallback.initResources();
 
-        String layoutCompiled =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_width=\"match_parent\"\n" +
-                        "    android:layout_height=\"match_parent\"\n" +
-                        "    android:background=\"@drawable/ninepatch\"\n" +
-                        "    android:layout_margin=\"20dp\"\n" +
-                        "    android:orientation=\"vertical\">\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n"
-                        + "</LinearLayout>";
+        String layoutCompiled = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:background="@drawable/ninepatch"
+                    android:layout_margin="20dp"
+                    android:orientation="vertical">
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+                </LinearLayout>""";
 
         LayoutPullParser parser = LayoutPullParser.createFromString(layoutCompiled);
         SessionParams params = getSessionParamsBuilder()
@@ -1172,22 +1172,24 @@ public class RenderTests extends RenderTestBase {
 
         renderAndVerify(params, "ninepatch_background.png");
 
-        String layoutNonCompiled =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_width=\"match_parent\"\n" +
-                        "    android:layout_height=\"match_parent\"\n" +
-                        "    android:background=\"@drawable/uncompiled_ninepatch\"\n" +
-                        "    android:layout_margin=\"20dp\"\n" +
-                        "    android:orientation=\"vertical\">\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n"
-                        + "</LinearLayout>";
+        String layoutNonCompiled = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:background="@drawable/uncompiled_ninepatch"
+                    android:layout_margin="20dp"
+                    android:orientation="vertical">
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+                </LinearLayout>""";
 
         parser = LayoutPullParser.createFromString(layoutNonCompiled);
         params = getSessionParamsBuilder()
@@ -1202,16 +1204,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testAssetManager() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.AssetView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <com.android.layoutlib.test.myapplication.widgets.AssetView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -1236,11 +1239,12 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testContextThemeWrapper() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<com.android.layoutlib.test.myapplication.ThemableWidget " +
-                        "xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"wrap_content\"\n" +
-                        "              android:layout_height=\"wrap_content\" />\n");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <com.android.layoutlib.test.myapplication.ThemableWidget
+                     xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="wrap_content"
+                              android:layout_height="wrap_content" />
+                """);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -1263,19 +1267,18 @@ public class RenderTests extends RenderTestBase {
      */
     @Test
     public void testCrashes() throws ClassNotFoundException {
-        final String layout =
-                "<LinearLayout " +
-                        "xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "<com.android.layoutlib.bridge.test.widgets.HookWidget " +
-                        "              android:layout_width=\"100dp\"\n" +
-                        "              android:layout_height=\"200dp\" />\n" +
-                        "<LinearLayout " +
-                        "              android:background=\"#CBBAF0\"\n" +
-                        "              android:layout_width=\"100dp\"\n" +
-                        "              android:layout_height=\"200dp\" />\n" +
-                        "</LinearLayout>";
+        final String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                <com.android.layoutlib.bridge.test.widgets.HookWidget
+                              android:layout_width="100dp"
+                              android:layout_height="200dp" />
+                <LinearLayout
+                              android:background="#CBBAF0"
+                              android:layout_width="100dp"
+                              android:layout_height="200dp" />
+                </LinearLayout>""";
         {
             com.android.layoutlib.bridge.test.widgets.HookWidget.setOnPreDrawHook(() -> {
                 throw new NullPointerException();
@@ -1350,41 +1353,42 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testViewBoundariesReporting() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\"\n" +
-                        "              android:background=\"@drawable/ninepatch\"\n" +
-                        "              android:layout_margin=\"20dp\"\n" +
-                        "              android:orientation=\"vertical\">\n" + "\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"150dp\"\n" +
-                        "        android:layout_height=\"50dp\"\n" +
-                        "        android:background=\"#FF0\"/>\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"150dp\"\n" +
-                        "        android:layout_height=\"50dp\"\n" +
-                        "        android:background=\"#F00\"/>\n" +
-                        "    <LinearLayout\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:paddingLeft=\"10dp\">\n" +
-                        "        <TextView\n" +
-                        "            android:layout_width=\"150dp\"\n" +
-                        "            android:layout_height=\"50dp\"\n" +
-                        "            android:background=\"#00F\"/>\n" +
-                        "    </LinearLayout>\n" +
-                        "    <LinearLayout\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:layout_marginLeft=\"30dp\"\n" +
-                        "        android:layout_marginTop=\"15dp\">\n" +
-                        "        <TextView\n" +
-                        "            android:layout_width=\"150dp\"\n" +
-                        "            android:layout_height=\"50dp\"\n" +
-                        "            android:background=\"#F0F\"/>\n" +
-                        "    </LinearLayout>\n" +
-                        "</LinearLayout>";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent"
+                              android:background="@drawable/ninepatch"
+                              android:layout_margin="20dp"
+                              android:orientation="vertical">
+
+                    <TextView
+                        android:layout_width="150dp"
+                        android:layout_height="50dp"
+                        android:background="#FF0"/>
+                    <TextView
+                        android:layout_width="150dp"
+                        android:layout_height="50dp"
+                        android:background="#F00"/>
+                    <LinearLayout
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:paddingLeft="10dp">
+                        <TextView
+                            android:layout_width="150dp"
+                            android:layout_height="50dp"
+                            android:background="#00F"/>
+                    </LinearLayout>
+                    <LinearLayout
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:layout_marginLeft="30dp"
+                        android:layout_marginTop="15dp">
+                        <TextView
+                            android:layout_width="150dp"
+                            android:layout_height="50dp"
+                            android:background="#F0F"/>
+                    </LinearLayout>
+                </LinearLayout>""";
 
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
@@ -1420,30 +1424,31 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testMixedRtlLtrRendering() throws Exception {
         //
-        final String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\"\n" +
-                        "              android:orientation=\"vertical\">\n" + "\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:textSize=\"30sp\"\n" +
-                        "        android:background=\"#55FF0000\"\n" +
-                        "        android:text=\"این یک رشته ایرانی است\"/>\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:textSize=\"30sp\"\n" +
-                        "        android:background=\"#55FF00FF\"\n" +
-                        "        android:text=\"این یک رشته ایرانی است(\"/>\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:textSize=\"30sp\"\n" +
-                        "        android:background=\"#55FAF012\"\n" +
-                        "        android:text=\")(این یک رشته ایرانی است(\"/>\n" +
-                        "</LinearLayout>";
+        final String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent"
+                              android:orientation="vertical">
+
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:textSize="30sp"
+                        android:background="#55FF0000"
+                        android:text="این یک رشته ایرانی است"/>
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:textSize="30sp"
+                        android:background="#55FF00FF"
+                        android:text="این یک رشته ایرانی است("/>
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:textSize="30sp"
+                        android:background="#55FAF012"
+                        android:text=")(این یک رشته ایرانی است("/>
+                </LinearLayout>""";
 
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
@@ -1465,18 +1470,19 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testViewStub() throws Exception {
         //
-        final String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\"\n" +
-                        "              android:orientation=\"vertical\">\n" + "\n" +
-                        "      <ViewStub\n" +
-                        "        xmlns:tools=\"http://schemas.android.com/tools\"\n" +
-                        "        android:layout_width=\"match_parent\"\n" +
-                        "        android:layout_height=\"match_parent\"\n" +
-                        "        android:layout=\"@layout/four_corners\"\n" +
-                        "        tools:visibility=\"visible\" />" +
-                        "</LinearLayout>";
+        final String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent"
+                              android:orientation="vertical">
+
+                      <ViewStub
+                        xmlns:tools="http://schemas.android.com/tools"
+                        android:layout_width="match_parent"
+                        android:layout_height="match_parent"
+                        android:layout="@layout/four_corners"
+                        tools:visibility="visible" />
+                </LinearLayout>""";
 
         // Create the layout pull parser.
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
@@ -1503,22 +1509,24 @@ public class RenderTests extends RenderTestBase {
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
         layoutLibCallback.initResources();
 
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "    android:layout_width=\"match_parent\"\n" +
-                        "    android:layout_height=\"match_parent\"\n" +
-                        "    android:background=\"@drawable/ninepatch\"\n" +
-                        "    android:layout_margin=\"20dp\"\n" +
-                        "    android:orientation=\"vertical\">\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n\n" +
-                        "    <Button\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Button\" />\n"
-                        + "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                    android:layout_width="match_parent"
+                    android:layout_height="match_parent"
+                    android:background="@drawable/ninepatch"
+                    android:layout_margin="20dp"
+                    android:orientation="vertical">
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+
+                    <Button
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Button" />
+                </LinearLayout>""");
 
         // Ask for an image that it's 1/10th the size of the actual device image
         SessionParams params = getSessionParamsBuilder()
@@ -1526,7 +1534,7 @@ public class RenderTests extends RenderTestBase {
                 .setCallback(layoutLibCallback)
                 .setImageFactory((width, height) ->
                         new BufferedImage(width / 10, height / 10,
-                                BufferedImage.TYPE_INT_ARGB))
+                                BufferedImage.TYPE_INT_ARGB_PRE))
                 .setFlag(RenderParamsFlags.FLAG_KEY_RESULT_IMAGE_AUTO_SCALE, true)
                 .build();
 
@@ -1548,17 +1556,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testCanvas() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.CanvasTestView\n" +
-                        "             android:layout_height=\"fill_parent\"\n" +
-                        "             android:layout_width=\"fill_parent\"\n" +
-                        "             android:src=\"@drawable/android\" />\n" + "\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <com.android.layoutlib.test.myapplication.widgets.CanvasTestView
+                             android:layout_height="fill_parent"
+                             android:layout_width="fill_parent"
+                             android:src="@drawable/android" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -1589,17 +1598,18 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testAnimatedVectorDrawableWithColorInterpolator() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"match_parent\"\n" +
-                        "             android:layout_width=\"match_parent\"\n" +
-                        "             android:src=\"@drawable/avd_color_interpolator\" />\n\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <ImageView
+                             android:layout_height="match_parent"
+                             android:layout_width="match_parent"
+                             android:src="@drawable/avd_color_interpolator" />
+
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -1625,28 +1635,29 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testManyLineBreaks() throws Exception {
-        String layout =
-                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" + "\n" +
-                        "    <EditText\n" +
-                        "        android:layout_width=\"match_parent\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:fallbackLineSpacing=\"true\"\n" +
-                        "        android:text=\"A very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very very very very very very very very " +
-                        "very very very very very very very long text\"/>\n" +
-                        "</FrameLayout>";
+        String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <EditText
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:fallbackLineSpacing="true"
+                        android:text="A very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very very very very very very very very \
+                very very very very very very very long text"/>
+                </FrameLayout>""";
 
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
@@ -1668,17 +1679,18 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testNinePatchDrawable() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"fill_parent\"\n" +
-                        "             android:layout_width=\"fill_parent\"\n" +
-                        "             android:src=\"@drawable/ninepatch_drawable\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                             android:layout_height="fill_parent"
+                             android:layout_width="fill_parent"
+                             android:src="@drawable/ninepatch_drawable" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -1695,14 +1707,15 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testContentId() throws ClassNotFoundException {
-        final String layout =
-                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" + "\n" +
-                        "    <com.android.layoutlib.bridge.test.widgets.ContentWidget\n" +
-                        "        android:layout_width=\"match_parent\"\n" +
-                        "        android:layout_height=\"wrap_content\"/>\n" +
-                        "</FrameLayout>";
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <com.android.layoutlib.bridge.test.widgets.ContentWidget
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"/>
+                </FrameLayout>""";
 
         {
             // Create the layout pull parser.
@@ -1749,18 +1762,19 @@ public class RenderTests extends RenderTestBase {
      */
     @Test
     public void testTextClock() throws ClassNotFoundException {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <TextClock\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\"\n" +
-                        "             android:text=\"12:34\"" +
-                        "             android:textSize=\"18sp\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <TextClock
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:text="12:34"\
+                             android:textSize="18sp" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -1777,16 +1791,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testChangeSize() throws ClassNotFoundException {
-        final String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:orientation=\"vertical\"\n" +
-                        "              android:layout_width=\"wrap_content\"\n" +
-                        "              android:layout_height=\"wrap_content\">\n" +
-                        "    <Button\n" +
-                        "             android:layout_height=\"50dp\"\n" +
-                        "             android:layout_width=\"100dp\"\n" +
-                        "             android:text=\"Hello\" />\n" +
-                        "</LinearLayout>\n";
+        final String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:orientation="vertical"
+                              android:layout_width="wrap_content"
+                              android:layout_height="wrap_content">
+                    <Button
+                             android:layout_height="50dp"
+                             android:layout_width="100dp"
+                             android:text="Hello" />
+                </LinearLayout>
+                """;
 
         // Create the layout pull parser.
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
@@ -1855,17 +1870,17 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testNonStyledResources() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:background=\"#999\"" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <com.android.layoutlib.bridge.test.widgets.CustomImageView\n" +
-                        "        android:layout_width=\"100dp\"\n" +
-                        "        android:layout_height=\"100dp\"/>\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:background="#999"\
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <com.android.layoutlib.bridge.test.widgets.CustomImageView
+                        android:layout_width="100dp"
+                        android:layout_height="100dp"/>
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -1886,17 +1901,17 @@ public class RenderTests extends RenderTestBase {
     @Test
     public void testRenderEffect() throws ClassNotFoundException {
         // Create the layout pull parser.
-        LayoutPullParser parser = LayoutPullParser.createFromString(
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:background=\"#999\"" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" +
-                        "    <com.android.layoutlib.bridge.test.widgets.BlurryImageView\n" +
-                        "        android:layout_width=\"100dp\"\n" +
-                        "        android:layout_height=\"100dp\"/>\n" +
-                        "</LinearLayout>");
+        LayoutPullParser parser = LayoutPullParser.createFromString("""
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:background="#999"\
+                              android:orientation="horizontal"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+                    <com.android.layoutlib.bridge.test.widgets.BlurryImageView
+                        android:layout_width="100dp"
+                        android:layout_height="100dp"/>
+                </LinearLayout>""");
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -1916,16 +1931,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testDialog() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.DialogView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <com.android.layoutlib.test.myapplication.widgets.DialogView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -1946,17 +1962,18 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testWindowBackgroundWithThemeAttribute() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <TextView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\"\n" +
-                        "             android:text=\"Hello World!\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <TextView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:text="Hello World!" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -1976,19 +1993,20 @@ public class RenderTests extends RenderTestBase {
     }
 
     @Test
-    public void testThemedAdaptiveIcon() throws ClassNotFoundException, IOException {
+    public void testThemedAdaptiveIcon() throws ClassNotFoundException {
         // Create the layout pull parser.
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <ImageView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\"\n" +
-                        "             android:src=\"@drawable/adaptive\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:src="@drawable/adaptive" />
+                </LinearLayout>
+                """;
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -2049,15 +2067,16 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testHtmlText() throws ClassNotFoundException {
-        final String layout =
-                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" + "\n" +
-                        "    <com.android.layoutlib.bridge.test.widgets.HtmlTextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:textSize=\"30sp\"/>\n" +
-                        "</FrameLayout>";
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <com.android.layoutlib.bridge.test.widgets.HtmlTextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:textSize="30sp"/>
+                </FrameLayout>""";
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -2077,16 +2096,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testStatusBar() throws ClassNotFoundException {
-        final String layout =
-                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" + "\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Test status bar colour\"\n" +
-                        "        android:textSize=\"30sp\"/>\n" +
-                        "</FrameLayout>";
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Test status bar colour"
+                        android:textSize="30sp"/>
+                </FrameLayout>""";
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -2113,16 +2133,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testSoftwareLayer() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <com.android.layoutlib.test.myapplication.widgets.SoftwareTextView\n" +
-                        "             android:layout_height=\"200dp\"\n" +
-                        "             android:layout_width=\"wrap_content\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <com.android.layoutlib.test.myapplication.widgets.SoftwareTextView
+                             android:layout_height="200dp"
+                             android:layout_width="wrap_content" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -2143,17 +2164,18 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testHighSimulatedSdk() throws Exception {
-        String layout =
-                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:padding=\"16dp\"\n" +
-                        "              android:orientation=\"horizontal\"\n" +
-                        "              android:layout_width=\"fill_parent\"\n" +
-                        "              android:layout_height=\"fill_parent\">\n" +
-                        "    <TextView\n" +
-                        "             android:layout_height=\"wrap_content\"\n" +
-                        "             android:layout_width=\"wrap_content\"\n" +
-                        "             android:text=\"This is a TextView\" />\n" +
-                        "</LinearLayout>\n";
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <TextView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:text="This is a TextView" />
+                </LinearLayout>
+                """;
         LayoutPullParser parser = LayoutPullParser.createFromString(layout);
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
@@ -2179,16 +2201,17 @@ public class RenderTests extends RenderTestBase {
 
     @Test
     public void testGestureNavBar() throws ClassNotFoundException {
-        final String layout =
-                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
-                        "              android:layout_width=\"match_parent\"\n" +
-                        "              android:layout_height=\"match_parent\">\n" + "\n" +
-                        "    <TextView\n" +
-                        "        android:layout_width=\"wrap_content\"\n" +
-                        "        android:layout_height=\"wrap_content\"\n" +
-                        "        android:text=\"Test gesture nav bar\"\n" +
-                        "        android:textSize=\"30sp\"/>\n" +
-                        "</FrameLayout>";
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Test gesture nav bar"
+                        android:textSize="30sp"/>
+                </FrameLayout>""";
         // Create LayoutLibCallback.
         LayoutLibTestCallback layoutLibCallback =
                 new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
@@ -2225,4 +2248,69 @@ public class RenderTests extends RenderTestBase {
 
         renderAndVerify(params, "land_gesture_nav.png", TimeUnit.SECONDS.toNanos(2));
     }
+
+    @Test
+    public void testCutouts() throws ClassNotFoundException {
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <TextView
+                        android:layout_width="wrap_content"
+                        android:layout_height="wrap_content"
+                        android:text="Test cutouts"
+                        android:textSize="30sp"/>
+                </FrameLayout>""";
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        layoutLibCallback.initResources();
+
+        ResourceValueMap stringOverlay = ResourceValueMap.create();
+        stringOverlay.put(new ResourceValueImpl(ResourceNamespace.ANDROID, ResourceType.STRING,
+                "config_mainBuiltInDisplayCutout",
+                "M 128,83 A 44,44 0 0 1 84,127 44,44 0 0 1 40,83 44,44 0 0 1 84,39 44,44 0 0 1 128,83 Z @left"));
+        stringOverlay.put(new ResourceValueImpl(ResourceNamespace.ANDROID, ResourceType.STRING,
+                "config_mainBuiltInDisplayCutoutRectApproximation",
+                "M 0.0,0.0 h 136 v 136 h -136 Z @left"));
+
+        ResourceValueMap booleanOverlay = ResourceValueMap.create();
+        booleanOverlay.put(new ResourceValueImpl(ResourceNamespace.ANDROID, ResourceType.BOOL,
+                "config_fillMainBuiltInDisplayCutout", "true"));
+
+        ResourceValueMap dimenOverlay = ResourceValueMap.create();
+        dimenOverlay.put(new ResourceValueImpl(ResourceNamespace.ANDROID, ResourceType.DIMEN,
+                "status_bar_height_portrait", "136px"));
+        dimenOverlay.put(new ResourceValueImpl(ResourceNamespace.ANDROID, ResourceType.DIMEN,
+                "status_bar_height_landscape", "28dp"));
+
+        Map<ResourceType, ResourceValueMap> frameworkOverlay = Map.of(
+                ResourceType.STRING, stringOverlay,
+                ResourceType.BOOL, booleanOverlay,
+                ResourceType.DIMEN, dimenOverlay);
+
+        SessionParams params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.Light", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .setFrameworkOverlayResources(frameworkOverlay)
+                .build();
+        params.setFlag(FLAG_KEY_SHOW_CUTOUT, true);
+
+        renderAndVerify(params, "hole_cutout.png", TimeUnit.SECONDS.toNanos(2));
+
+        params = getSessionParamsBuilder()
+                .setConfigGenerator(ConfigGenerator.NEXUS_5_LAND)
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.Light", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .setFrameworkOverlayResources(frameworkOverlay)
+                .build();
+        params.setFlag(FLAG_KEY_SHOW_CUTOUT, true);
+
+        renderAndVerify(params, "hole_cutout_landscape.png", TimeUnit.SECONDS.toNanos(2));
+    }
 }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/util/ChoreographerCallbacksTest.java b/bridge/tests/src/com/android/layoutlib/bridge/util/ChoreographerCallbacksTest.java
index c0c7ec23eb..8ee5c31a8a 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/util/ChoreographerCallbacksTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/util/ChoreographerCallbacksTest.java
@@ -24,6 +24,7 @@ import org.junit.Test;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.util.TimeUtils;
 import android.view.Choreographer.FrameCallback;
 
 import java.util.ArrayList;
@@ -60,7 +61,7 @@ public class ChoreographerCallbacksTest {
 
         callbacks.add((Runnable) () -> order.add(2), null, 200);
         callbacks.add((FrameCallback) frameTimeNanos -> order.add(1), null, 100);
-        callbacks.execute(200, logger);
+        callbacks.execute(200 * TimeUtils.NANOS_PER_MS, logger);
 
         Assert.assertArrayEquals(order.toArray(), new Object[] { 1, 2 });
         Assert.assertTrue(logger.errorMessages.isEmpty());
@@ -73,7 +74,7 @@ public class ChoreographerCallbacksTest {
 
         callbacks.add((Runnable) () -> order.add(2), null, 200);
         callbacks.add((FrameCallback) frameTimeNanos -> order.add(1), null, 100);
-        callbacks.execute(100, logger);
+        callbacks.execute(100 * TimeUtils.NANOS_PER_MS, logger);
 
         Assert.assertArrayEquals(order.toArray(), new Object[] { 1 });
         Assert.assertTrue(logger.errorMessages.isEmpty());
@@ -88,7 +89,7 @@ public class ChoreographerCallbacksTest {
         callbacks.add(runnable, null, 200);
         callbacks.add((FrameCallback) frameTimeNanos -> order.add(1), null, 100);
         callbacks.remove(runnable, null);
-        callbacks.execute(200, logger);
+        callbacks.execute(200 * TimeUtils.NANOS_PER_MS, logger);
 
         Assert.assertArrayEquals(order.toArray(), new Object[] { 1 });
         Assert.assertTrue(logger.errorMessages.isEmpty());
@@ -99,7 +100,7 @@ public class ChoreographerCallbacksTest {
         ChoreographerCallbacks callbacks = new ChoreographerCallbacks();
 
         callbacks.add(new Object(), null, 100);
-        callbacks.execute(200, logger);
+        callbacks.execute(200 * TimeUtils.NANOS_PER_MS, logger);
 
         Assert.assertFalse(logger.errorMessages.isEmpty());
         Assert.assertEquals(logger.errorMessages.get(0), "Unexpected action as Choreographer callback");
@@ -117,7 +118,7 @@ public class ChoreographerCallbacksTest {
         callbacks.add((Runnable) () -> order.add(3), token2, 100);
         callbacks.add((Runnable) () -> order.add(4), null, 200);
         callbacks.remove(null, token1);
-        callbacks.execute(200, logger);
+        callbacks.execute(200 * TimeUtils.NANOS_PER_MS, logger);
 
         Assert.assertArrayEquals(order.toArray(), new Object[] { 3, 4 });
         Assert.assertTrue(logger.errorMessages.isEmpty());
diff --git a/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java b/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
index 2dfefaca99..221c1c687d 100644
--- a/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
+++ b/bridge/tests/src/com/android/tools/idea/validator/AccessibilityValidatorTests.java
@@ -31,7 +31,6 @@ import org.junit.Test;
 
 import java.util.EnumSet;
 import java.util.List;
-import java.util.stream.Collectors;
 
 import com.google.android.apps.common.testing.accessibility.framework.uielement.DefaultCustomViewBuilderAndroid;
 import com.google.android.apps.common.testing.accessibility.framework.uielement.ViewHierarchyElementAndroid;
@@ -63,9 +62,9 @@ public class AccessibilityValidatorTests extends RenderTestBase {
                 ValidatorResult result = getRenderResult(session);
                 List<Issue> dupBounds = filter(result.getIssues(), "DuplicateClickableBoundsCheck");
 
-                /**
-                 * Expects no errors since disabled. When enabled it should print
-                 * the same result as {@link #testDuplicateClickableBoundsCheck}
+                /*
+                  Expects no errors since disabled. When enabled it should print
+                  the same result as {@link #testDuplicateClickableBoundsCheck}
                  */
                 ExpectedLevels expectedLevels = new ExpectedLevels();
                 expectedLevels.check(dupBounds);
@@ -333,8 +332,7 @@ public class AccessibilityValidatorTests extends RenderTestBase {
             List<ViewHierarchyElementAndroid> textViews =
                     hierarchy.mView.getActiveWindow().getAllViews().stream().filter(view->
                             (view.getClassName() != null &&
-                                    view.getClassName().toString().contains("TextView"))).collect(
-                            Collectors.toList());
+                                    view.getClassName().toString().contains("TextView"))).toList();
 
             // The text of the only TextView is very long (more than 1000 characters), but
             // only 100 text character locations are retrieved because
@@ -356,9 +354,8 @@ public class AccessibilityValidatorTests extends RenderTestBase {
         Object validationData = session.getValidationData();
         assertTrue(validationData instanceof ValidatorHierarchy);
 
-        ValidatorResult result = ValidatorUtil.generateResults(LayoutValidator.DEFAULT_POLICY,
+        return ValidatorUtil.generateResults(LayoutValidator.DEFAULT_POLICY,
                 (ValidatorHierarchy) validationData);
-        return result;
     }
     private void render(String fileName, RenderSessionListener verifier) throws Exception {
         render(fileName, verifier, true);
@@ -406,17 +403,17 @@ public class AccessibilityValidatorTests extends RenderTestBase {
      */
     private static class ExpectedLevels {
         // Number of errors expected
-        public int expectedErrors = 0;
+        private int expectedErrors = 0;
         // Number of warnings expected
-        public int expectedWarnings = 0;
+        private int expectedWarnings = 0;
         // Number of infos expected
-        public int expectedInfos = 0;
+        private int expectedInfos = 0;
         // Number of verboses expected
-        public int expectedVerboses = 0;
+        private int expectedVerboses = 0;
         // Number of fixes expected
-        public int expectedFixes = 0;
+        private int expectedFixes = 0;
 
-        public void check(List<Issue> issues) {
+        private void check(List<Issue> issues) {
             int errors = 0;
             int warnings = 0;
             int infos = 0;
@@ -453,5 +450,5 @@ public class AccessibilityValidatorTests extends RenderTestBase {
             int size = expectedErrors + expectedWarnings + expectedInfos + expectedVerboses;
             assertEquals("expected size", size, issues.size());
         }
-    };
+    }
 }
diff --git a/bridge/tests/src/com/android/tools/idea/validator/LayoutValidatorTests.java b/bridge/tests/src/com/android/tools/idea/validator/LayoutValidatorTests.java
index 44b42aef4c..5aa85ebb43 100644
--- a/bridge/tests/src/com/android/tools/idea/validator/LayoutValidatorTests.java
+++ b/bridge/tests/src/com/android/tools/idea/validator/LayoutValidatorTests.java
@@ -77,13 +77,13 @@ public class LayoutValidatorTests extends RenderTestBase {
 
         renderAndVerify(params, "a11y_test1.png");
         Object connectionCache = ReflectionUtils.getFieldValue(AccessibilityInteractionClient.class,
-                AccessibilityInteractionClient.getInstance(), "sConnectionCache");
-        assertEquals(0, ((SparseArray)connectionCache).size());
+                null, "sConnectionCache");
+        assertEquals(0, ((SparseArray<?>)connectionCache).size());
     }
 
     @Test
     public void testValidation() throws Exception {
-        render(sBridge, generateParams(), -1, session -> {
+        render(sBridge, generateParams(), -1, session -> session.execute(() -> {
             ValidatorResult result = LayoutValidator.validate(
                     ((View) session.getRootViews().get(0).getViewObject()),
                     null,
@@ -119,7 +119,7 @@ public class LayoutValidatorTests extends RenderTestBase {
             assertEquals("https://support.google.com/accessibility/android/answer/7101858",
                          second.mHelpfulUrl);
             assertEquals("TouchTargetSizeCheck", second.mSourceClass);
-            assertTrue(compoundFix.mFixes.size() == 2);
+            assertEquals(2, compoundFix.mFixes.size());
             assertEquals(
                     "Set this item's android:layout_width to 48dp.",
                     compoundFix.mFixes.get(0).getDescription());
@@ -138,7 +138,7 @@ public class LayoutValidatorTests extends RenderTestBase {
             assertTrue(third.mFix instanceof SetViewAttributeFix);
             assertEquals("Set this item's android:textColor to #757575.",
                     third.mFix.getDescription());
-        });
+        }));
     }
 
     @Test
@@ -173,7 +173,7 @@ public class LayoutValidatorTests extends RenderTestBase {
                     EnumSet.of(Level.VERBOSE));
             LayoutValidator.updatePolicy(newPolicy);
 
-            render(sBridge, generateParams(), -1, session -> {
+            render(sBridge, generateParams(), -1, session -> session.execute(() -> {
                 ValidatorResult result = LayoutValidator.validate(
                         ((View) session.getRootViews().get(0).getViewObject()),
                         null,
@@ -181,7 +181,7 @@ public class LayoutValidatorTests extends RenderTestBase {
                         SCALE_Y_FOR_NEXUS_5);
                 assertEquals(26, result.getIssues().size());
                 result.getIssues().forEach(issue ->assertEquals(Level.VERBOSE, issue.mLevel));
-            });
+            }));
         } finally {
             LayoutValidator.updatePolicy(LayoutValidator.DEFAULT_POLICY);
         }
@@ -203,7 +203,7 @@ public class LayoutValidatorTests extends RenderTestBase {
             newPolicy.mChecks.addAll(filtered);
             LayoutValidator.updatePolicy(newPolicy);
 
-            render(sBridge, generateParams(), -1, session -> {
+            render(sBridge, generateParams(), -1, session -> session.execute(() -> {
                 ValidatorResult result = LayoutValidator.validate(
                         ((View) session.getRootViews().get(0).getViewObject()),
                         null,
@@ -218,7 +218,7 @@ public class LayoutValidatorTests extends RenderTestBase {
                 assertEquals("https://support.google.com/accessibility/android/answer/7158390",
                         textCheck.mHelpfulUrl);
                 assertEquals("TextContrastCheck", textCheck.mSourceClass);
-            });
+            }));
         } finally {
             LayoutValidator.updatePolicy(LayoutValidator.DEFAULT_POLICY);
         }
diff --git a/bridge/tests/src/com/android/tools/idea/validator/ValidatorResultTests.java b/bridge/tests/src/com/android/tools/idea/validator/ValidatorResultTests.java
index b7e0e135f4..bcf62049c1 100644
--- a/bridge/tests/src/com/android/tools/idea/validator/ValidatorResultTests.java
+++ b/bridge/tests/src/com/android/tools/idea/validator/ValidatorResultTests.java
@@ -50,11 +50,12 @@ public class ValidatorResultTests {
         for (int i = 0; i < 3; i++) {
             builder.mIssues.add(createIssueBuilder().setMsg("issue " + i).build());
         }
-        assertEquals(
-                "Result containing 3 issues:\n" +
-                        " - [ERROR] issue 0\n" +
-                        " - [ERROR] issue 1\n" +
-                        " - [ERROR] issue 2\n",
+        assertEquals("""
+                        Result containing 3 issues:
+                         - [ERROR] issue 0
+                         - [ERROR] issue 1
+                         - [ERROR] issue 2
+                        """,
                 builder.build().toString());
     }
 
diff --git a/common/src/com/android/layoutlib/common/util/ReflectionUtils.java b/common/src/com/android/layoutlib/common/util/ReflectionUtils.java
index 7c2bff0ca9..733aedb326 100644
--- a/common/src/com/android/layoutlib/common/util/ReflectionUtils.java
+++ b/common/src/com/android/layoutlib/common/util/ReflectionUtils.java
@@ -20,10 +20,8 @@ import com.android.tools.layoutlib.annotations.NonNull;
 import com.android.tools.layoutlib.annotations.Nullable;
 
 import java.lang.reflect.Field;
-import java.lang.reflect.InvocationHandler;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
-import java.lang.reflect.Proxy;
 
 /**
  * Utility to convert checked Reflection exceptions to unchecked exceptions.
@@ -65,9 +63,7 @@ public class ReflectionUtils {
             Field field = clazz.getDeclaredField(name);
             field.setAccessible(true);
             return field.get(object);
-        } catch (NoSuchFieldException e) {
-            throw new ReflectionException(e);
-        } catch (IllegalAccessException e) {
+        } catch (NoSuchFieldException | IllegalAccessException e) {
             throw new ReflectionException(e);
         }
     }
@@ -100,7 +96,7 @@ public class ReflectionUtils {
      * for interfaces.
      */
     public static boolean isInstanceOf(Object object, String className) {
-        Class superClass = object.getClass();
+        Class<?> superClass = object.getClass();
         while (superClass != null) {
             String name = superClass.getName();
             if (name.equals(className)) {
@@ -173,34 +169,6 @@ public class ReflectionUtils {
         throw new RuntimeException("invalid object/classname combination.");
     }
 
-    public static <T> T createProxy(Class<T> interfaze) {
-        ClassLoader loader = interfaze.getClassLoader();
-        return (T) Proxy.newProxyInstance(loader, new Class[]{interfaze}, new InvocationHandler() {
-            public Object invoke(Object proxy, Method m, Object[] args) {
-                final Class<?> returnType = m.getReturnType();
-                if (returnType == boolean.class) {
-                    return false;
-                } else if (returnType == int.class) {
-                    return 0;
-                } else if (returnType == long.class) {
-                    return 0L;
-                } else if (returnType == short.class) {
-                    return 0;
-                } else if (returnType == char.class) {
-                    return 0;
-                } else if (returnType == byte.class) {
-                    return 0;
-                } else if (returnType == float.class) {
-                    return 0f;
-                } else if (returnType == double.class) {
-                    return 0.0;
-                } else {
-                    return null;
-                }
-            }
-        });
-    }
-
     /**
      * Wraps all reflection related exceptions. Created since ReflectiveOperationException was
      * introduced in 1.7 and we are still on 1.6
diff --git a/common/src/com/android/tools/layoutlib/create/NativeConfig.java b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
index d8947653dc..099adbaaf1 100644
--- a/common/src/com/android/tools/layoutlib/create/NativeConfig.java
+++ b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
@@ -25,16 +25,8 @@ public class NativeConfig {
     private NativeConfig() {}
 
     public final static String[] DEFERRED_STATIC_INITIALIZER_CLASSES = new String [] {
-            "android.graphics.ColorSpace",
-            "android.graphics.FontFamily",
-            "android.graphics.Matrix",
-            "android.graphics.Path",
-            // Order is important! Fonts and FontFamily have to be initialized before Typeface
-            "android.graphics.fonts.Font",
-            "android.graphics.fonts.FontFamily$Builder",
+            "android.graphics.PathIterator",
             "android.graphics.Typeface",
-            "android.graphics.text.PositionedGlyphs",
-            "android.graphics.text.LineBreaker",
     };
 
     public static final String[] DELEGATE_METHODS = new String[] {
@@ -113,7 +105,7 @@ public class NativeConfig {
             "android.provider.Settings$Config#getContentResolver",
             "android.text.format.DateFormat#is24HourFormat",
             "android.util.Xml#newPullParser",
-            "android.view.Choreographer#getFrameTimeNanos",
+            "android.view.Choreographer#doCallbacks",
             "android.view.Choreographer#getRefreshRate",
             "android.view.Choreographer#postCallbackDelayedInternal",
             "android.view.Choreographer#removeCallbacksInternal",
@@ -126,9 +118,9 @@ public class NativeConfig {
             "android.view.LayoutInflater#rInflate",
             "android.view.MenuInflater#registerMenu",
             "android.view.PointerIcon#loadResource",
-            "android.view.PointerIcon#registerDisplayListener",
             "android.view.SurfaceControl#nativeCreateTransaction",
             "android.view.SurfaceControl#nativeGetNativeTransactionFinalizer",
+            "android.view.TextureView#getTextureLayer",
             "android.view.VelocityTracker#obtain",
             "android.view.View#dispatchDetachedFromWindow",
             "android.view.View#draw",
@@ -140,6 +132,7 @@ public class NativeConfig {
             "android.view.WindowManagerGlobal#getWindowManagerService",
             "android.view.accessibility.AccessibilityManager#getInstance",
             "android.view.accessibility.AccessibilityManager#getWindowTransformationSpec",
+            "android.view.flags.Flags#sensitiveContentAppProtection",
             "android.view.inputmethod.InputMethodManager#hideSoftInputFromWindow",
             "android.view.inputmethod.InputMethodManager#isInEditMode",
             "android.view.inputmethod.InputMethodManager#showSoftInput",
@@ -154,7 +147,7 @@ public class NativeConfig {
             "libcore.io.MemoryMappedFile#bigEndianIterator",
             "libcore.io.MemoryMappedFile#close",
             "libcore.io.MemoryMappedFile#mmapRO",
-            "libcore.util.NativeAllocationRegistry#applyFreeFunction",
+            "libcore.util.NativeAllocationRegistry#createMalloced",
     };
 
     public final static String[] DELEGATE_CLASS_NATIVES = new String[] {
@@ -173,10 +166,13 @@ public class NativeConfig {
             "android.os.SystemProperties",
             "android.os.Trace",
             "android.text.AndroidCharacter",
+            "android.util.EventLog",
             "android.util.Log",
             "android.view.MotionEvent",
+            "android.view.Surface",
+            "android.view.VelocityTracker",
             "com.android.internal.util.VirtualRefBasePtr",
-            "libcore.util.NativeAllocationRegistry_Delegate",
+            "libcore.util.NativeAllocationRegistry",
     };
 
     /**
@@ -185,24 +181,33 @@ public class NativeConfig {
     public final static String[] GRAPHICS_CLASS_NATIVES = new String[] {
             "android.graphics.Bitmap",
             "android.graphics.BitmapFactory",
+            "android.graphics.BitmapRegionDecoder",
             "android.graphics.ByteBufferStreamAdaptor",
             "android.graphics.Camera",
             "android.graphics.Canvas",
             "android.graphics.CanvasProperty",
+            "android.graphics.Color",
             "android.graphics.ColorFilter",
             "android.graphics.ColorSpace",
             "android.graphics.CreateJavaOutputStreamAdaptor",
             "android.graphics.DrawFilter",
             "android.graphics.FontFamily",
+            "android.graphics.Gainmap",
             "android.graphics.Graphics",
+            "android.graphics.HardwareBufferRenderer",
+            "android.graphics.HardwareRenderer",
+            "android.graphics.HardwareRendererObserver",
             "android.graphics.ImageDecoder",
             "android.graphics.Interpolator",
             "android.graphics.MaskFilter",
             "android.graphics.Matrix",
+            "android.graphics.Mesh",
+            "android.graphics.MeshSpecification",
             "android.graphics.NinePatch",
             "android.graphics.Paint",
             "android.graphics.Path",
             "android.graphics.PathEffect",
+            "android.graphics.PathIterator",
             "android.graphics.PathMeasure",
             "android.graphics.Picture",
             "android.graphics.RecordingCanvas",
@@ -214,10 +219,12 @@ public class NativeConfig {
             "android.graphics.YuvImage",
             "android.graphics.animation.NativeInterpolatorFactory",
             "android.graphics.animation.RenderNodeAnimator",
+            "android.graphics.drawable.AnimatedImageDrawable",
             "android.graphics.drawable.AnimatedVectorDrawable",
             "android.graphics.drawable.VectorDrawable",
             "android.graphics.fonts.Font",
             "android.graphics.fonts.FontFamily",
+            "android.graphics.text.GraphemeBreak",
             "android.graphics.text.LineBreaker",
             "android.graphics.text.MeasuredText",
             "android.graphics.text.TextRunShaper",
diff --git a/create/README.txt b/create/README.txt
index 5625675c6a..be4b1f9013 100644
--- a/create/README.txt
+++ b/create/README.txt
@@ -171,7 +171,7 @@ This is the easiest: we currently inject the following classes:
   (platform/libcore/luni/src/main/java/java/...).
 - Charsets, IntegralToString and UnsafeByteSequence are not part of the Desktop VM. They are
   added to the Dalvik VM for performance reasons. An implementation that is very close to the
-  original (which is at platform/libcore/luni/src/main/java/...) is injected. Since these classees
+  original (which is at platform/libcore/luni/src/main/java/...) is injected. Since these classes
   were in part of the java package, where we can't inject classes, all references to these have been
   updated (See strategy 4- Refactoring Classes).
 
@@ -179,7 +179,7 @@ This is the easiest: we currently inject the following classes:
 2- Overriding methods
 
 As explained earlier, the creator doesn't have any replacement code for methods to override. Instead
-it removes the original code and replaces it by a call to a specific OveriddeMethod.invokeX(). The
+it removes the original code and replaces it by a call to a specific OverrideMethod.invokeX(). The
 bridge then registers a listener on the method signature and can provide an implementation.
 
 This strategy is now obsolete and replaced by the method delegates (See strategy 6- Method
diff --git a/create/create.iml b/create/create.iml
index bbf099f891..5c7d27ade6 100644
--- a/create/create.iml
+++ b/create/create.iml
@@ -10,27 +10,11 @@
     </content>
     <orderEntry type="inheritedJdk" />
     <orderEntry type="sourceFolder" forTests="false" />
-    <orderEntry type="module-library">
-      <library name="asm-9.6">
-        <CLASSES>
-          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/asm/asm-9.6/linux_glibc_common/combined/asm-9.6.jar!/" />
-        </CLASSES>
-        <JAVADOC />
-        <SOURCES />
-      </library>
-    </orderEntry>
-    <orderEntry type="module-library">
-      <library name="asm-commons-9.6">
-        <CLASSES>
-          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/asm/asm-commons-9.6/linux_glibc_common/combined/asm-commons-9.6.jar!/" />
-        </CLASSES>
-        <JAVADOC />
-        <SOURCES />
-      </library>
-    </orderEntry>
     <orderEntry type="library" scope="TEST" name="junit" level="project" />
     <orderEntry type="module" module-name="common" />
     <orderEntry type="library" name="guava" level="project" />
+    <orderEntry type="library" name="ow2-asm" level="project" />
+    <orderEntry type="library" name="ow2-asm-commons" level="project" />
     <orderEntry type="library" scope="TEST" name="hamcrest" level="project" />
     <orderEntry type="module-library" scope="RUNTIME">
       <library>
@@ -80,12 +64,21 @@
     <orderEntry type="module-library" scope="RUNTIME">
       <library>
         <CLASSES>
-          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-502584086/linux_glibc_common/combined/atf-prebuilt-jars-502584086.jar!/" />
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/combined/atf-prebuilt-jars-557133692.jar!/" />
         </CLASSES>
         <JAVADOC />
         <SOURCES />
       </library>
     </orderEntry>
     <orderEntry type="library" scope="RUNTIME" name="libprotobuf-java-lite" level="project" />
+    <orderEntry type="module-library" scope="RUNTIME">
+      <library>
+        <CLASSES>
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/frameworks/libs/systemui/monet/monet/android_common/combined/monet.jar!/" />
+        </CLASSES>
+        <JAVADOC />
+        <SOURCES />
+      </library>
+    </orderEntry>
   </component>
 </module>
diff --git a/create/src/com/android/tools/layoutlib/create/AbstractClassAdapter.java b/create/src/com/android/tools/layoutlib/create/AbstractClassAdapter.java
index 01c940ad66..d3aa236513 100644
--- a/create/src/com/android/tools/layoutlib/create/AbstractClassAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/AbstractClassAdapter.java
@@ -42,7 +42,7 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
      */
     abstract String renameInternalType(String name);
 
-    public AbstractClassAdapter(ClassVisitor cv) {
+    protected AbstractClassAdapter(ClassVisitor cv) {
         super(Main.ASM_VERSION, cv);
     }
 
@@ -63,7 +63,7 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
      * object element, e.g. "[Lcom.package.MyClass;"
      * If the type doesn't need to be renamed, returns the internal name of the input type.
      */
-    String renameType(Type type) {
+    private String renameType(Type type) {
         if (type == null) {
             return null;
         }
@@ -72,12 +72,8 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
             String in = type.getInternalName();
             return "L" + renameInternalType(in) + ";";
         } else if (type.getSort() == Type.ARRAY) {
-            StringBuilder sb = new StringBuilder();
-            for (int n = type.getDimensions(); n > 0; n--) {
-                sb.append('[');
-            }
-            sb.append(renameType(type.getElementType()));
-            return sb.toString();
+            return "[".repeat(Math.max(0, type.getDimensions())) +
+                    renameType(type.getElementType());
         }
         return type.getDescriptor();
     }
@@ -88,7 +84,7 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
      * This is like renameType() except that it returns a Type object.
      * If the type doesn't need to be renamed, returns the input type object.
      */
-    Type renameTypeAsType(Type type) {
+    private Type renameTypeAsType(Type type) {
         if (type == null) {
             return null;
         }
@@ -100,12 +96,9 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
                 return Type.getType("L" + newIn + ";");
             }
         } else if (type.getSort() == Type.ARRAY) {
-            StringBuilder sb = new StringBuilder();
-            for (int n = type.getDimensions(); n > 0; n--) {
-                sb.append('[');
-            }
-            sb.append(renameType(type.getElementType()));
-            return Type.getType(sb.toString());
+            String sb = "[".repeat(Math.max(0, type.getDimensions())) +
+                    renameType(type.getElementType());
+            return Type.getType(sb);
         }
         return type;
     }
@@ -140,7 +133,7 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
      * Renames the ClassSignature handled by ClassVisitor.visit
      * or the MethodTypeSignature handled by ClassVisitor.visitMethod.
      */
-    String renameTypeSignature(String sig) {
+    private String renameTypeSignature(String sig) {
         if (sig == null) {
             return null;
         }
@@ -156,7 +149,7 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
      * Renames the FieldTypeSignature handled by ClassVisitor.visitField
      * or MethodVisitor.visitLocalVariable.
      */
-    String renameFieldSignature(String sig) {
+    private String renameFieldSignature(String sig) {
         return renameTypeSignature(sig);
     }
 
@@ -219,14 +212,14 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
     /**
      * A method visitor that renames all references from an old class name to a new class name.
      */
-    public class RenameMethodAdapter extends MethodVisitor {
+    private class RenameMethodAdapter extends MethodVisitor {
 
         /**
          * Creates a method visitor that renames all references from a given old name to a given new
          * name. The method visitor will also rename all inner classes.
          * The names must be full qualified internal ASM names (e.g. com/blah/MyClass$InnerClass).
          */
-        public RenameMethodAdapter(MethodVisitor mv) {
+        private RenameMethodAdapter(MethodVisitor mv) {
             super(Main.ASM_VERSION, mv);
         }
 
@@ -314,11 +307,11 @@ public abstract class AbstractClassAdapter extends ClassVisitor {
 
     //----------------------------------
 
-    public class RenameSignatureAdapter extends SignatureVisitor {
+    private class RenameSignatureAdapter extends SignatureVisitor {
 
         private final SignatureVisitor mSv;
 
-        public RenameSignatureAdapter(SignatureVisitor sv) {
+        private RenameSignatureAdapter(SignatureVisitor sv) {
             super(Main.ASM_VERSION);
             mSv = sv;
         }
diff --git a/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java b/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
index e5d1088b31..258fec70c2 100644
--- a/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
+++ b/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
@@ -182,7 +182,7 @@ public class AsmAnalyzer {
      *                  in the form "android/data/dataFile".
      */
     void parseZip(List<String> jarPathList, Map<String, ClassReader> classes,
-            Map<String, InputStream> filesFound) throws IOException {
+            Map<String, InputStream> filesFound) {
         if (classes == null || filesFound == null) {
             return;
         }
@@ -252,8 +252,8 @@ public class AsmAnalyzer {
     }
 
     private static boolean matchesAny(@Nullable String className, @NotNull Pattern[] patterns) {
-        for (int i = 0; i < patterns.length; i++) {
-            if (patterns[i].matcher(className).matches()) {
+        for (Pattern pattern : patterns) {
+            if (pattern.matcher(className).matches()) {
                 return true;
             }
         }
@@ -308,7 +308,7 @@ public class AsmAnalyzer {
     }
 
 
-    static Pattern getPatternFromGlob(String globPattern) {
+    private static Pattern getPatternFromGlob(String globPattern) {
      // transforms the glob pattern in a regexp:
         // - escape "." with "\."
         // - replace "*" by "[^.]*"
@@ -371,10 +371,8 @@ public class AsmAnalyzer {
      * Finds all dependencies for all classes in keepClasses which are also
      * listed in zipClasses. Returns a map of all the dependencies found.
      */
-    void findDeps(Log log,
-            Map<String, ClassReader> zipClasses,
-            Map<String, ClassReader> inOutKeepClasses,
-            Consumer<Entry<String, ClassReader>> newKeep,
+    private void findDeps(Log log, Map<String, ClassReader> zipClasses,
+            Map<String, ClassReader> inOutKeepClasses, Consumer<Entry<String, ClassReader>> newKeep,
             Consumer<Entry<String, ClassReader>> newDep) {
 
         TreeMap<String, ClassReader> keep = new TreeMap<>(inOutKeepClasses);
@@ -392,7 +390,7 @@ public class AsmAnalyzer {
             cr.accept(visitor, 0 /* flags */);
         }
 
-        while (new_deps.size() > 0 || new_keep.size() > 0) {
+        while (!new_deps.isEmpty() || !new_keep.isEmpty()) {
             new_deps.entrySet().forEach(newDep);
             new_keep.entrySet().forEach(newKeep);
             keep.putAll(new_keep);
@@ -443,11 +441,9 @@ public class AsmAnalyzer {
          * @param inDeps Dependencies already known.
          * @param outDeps New dependencies found by this visitor.
          */
-        public DependencyVisitor(Map<String, ClassReader> zipClasses,
-                Map<String, ClassReader> inKeep,
-                Map<String, ClassReader> outKeep,
-                Map<String,ClassReader> inDeps,
-                Map<String,ClassReader> outDeps) {
+        private DependencyVisitor(Map<String, ClassReader> zipClasses,
+                Map<String, ClassReader> inKeep, Map<String, ClassReader> outKeep,
+                Map<String, ClassReader> inDeps, Map<String, ClassReader> outDeps) {
             super(Main.ASM_VERSION);
             mZipClasses = zipClasses;
             mInKeep = inKeep;
@@ -464,7 +460,7 @@ public class AsmAnalyzer {
          * Considers the given class name as a dependency.
          * If it does, add to the mOutDeps map.
          */
-        public void considerName(String className) {
+        private void considerName(String className) {
             if (className == null) {
                 return;
             }
@@ -509,7 +505,7 @@ public class AsmAnalyzer {
         /**
          * Considers this array of names using considerName().
          */
-        public void considerNames(String[] classNames) {
+        private void considerNames(String[] classNames) {
             if (classNames != null) {
                 for (String className : classNames) {
                     considerName(className);
@@ -521,7 +517,7 @@ public class AsmAnalyzer {
          * Considers this signature or type signature by invoking the {@link SignatureVisitor}
          * on it.
          */
-        public void considerSignature(String signature) {
+        private void considerSignature(String signature) {
             if (signature != null) {
                 SignatureReader sr = new SignatureReader(signature);
                 // SignatureReader.accept will call accessType so we don't really have
@@ -535,7 +531,7 @@ public class AsmAnalyzer {
          * If the type is an object, its internal name is considered. If it is a method type,
          * iterate through the argument and return types.
          */
-        public void considerType(Type t) {
+        private void considerType(Type t) {
             if (t != null) {
                 if (t.getSort() == Type.ARRAY) {
                     t = t.getElementType();
@@ -556,7 +552,7 @@ public class AsmAnalyzer {
          * Considers a descriptor string. The descriptor is converted to a {@link Type}
          * and then considerType() is invoked.
          */
-        public void considerDesc(String desc) {
+        private void considerDesc(String desc) {
             if (desc != null) {
                 try {
                     Type t = Type.getType(desc);
@@ -612,7 +608,7 @@ public class AsmAnalyzer {
 
         private class MyFieldVisitor extends FieldVisitor {
 
-            public MyFieldVisitor() {
+            private MyFieldVisitor() {
                 super(Main.ASM_VERSION);
             }
 
@@ -683,9 +679,9 @@ public class AsmAnalyzer {
 
         private class MyMethodVisitor extends MethodVisitor {
 
-            private String mOwnerClass;
+            private final String mOwnerClass;
 
-            public MyMethodVisitor(String ownerClass) {
+            private MyMethodVisitor(String ownerClass) {
                 super(Main.ASM_VERSION);
                 mOwnerClass = ownerClass;
             }
@@ -853,7 +849,7 @@ public class AsmAnalyzer {
 
         private class MySignatureVisitor extends SignatureVisitor {
 
-            public MySignatureVisitor() {
+            private MySignatureVisitor() {
                 super(Main.ASM_VERSION);
             }
 
@@ -952,7 +948,7 @@ public class AsmAnalyzer {
 
         private class MyAnnotationVisitor extends AnnotationVisitor {
 
-            public MyAnnotationVisitor() {
+            protected MyAnnotationVisitor() {
                 super(Main.ASM_VERSION);
             }
 
diff --git a/create/src/com/android/tools/layoutlib/create/AsmGenerator.java b/create/src/com/android/tools/layoutlib/create/AsmGenerator.java
index 55de0afe0f..5aa72d4694 100644
--- a/create/src/com/android/tools/layoutlib/create/AsmGenerator.java
+++ b/create/src/com/android/tools/layoutlib/create/AsmGenerator.java
@@ -53,7 +53,7 @@ public class AsmGenerator {
     private Map<String, ClassReader> mKeep;
     /** All dependencies that must be completely stubbed. */
     private Map<String, ClassReader> mDeps;
-    private Map<String, ClassWriter> mDelegates = new HashMap<>();
+    private final Map<String, ClassWriter> mDelegates = new HashMap<>();
     /** All files that are to be copied as-is. */
     private Map<String, InputStream> mCopyFiles;
     /** All classes where certain method calls need to be rewritten. */
@@ -65,9 +65,9 @@ public class AsmGenerator {
     /** FQCN Names of "old" classes that were NOT renamed. This starts with the full list of
      *  old-FQCN to rename and they get erased as they get renamed. At the end, classes still
      *  left here are not in the code base anymore and thus were not renamed. */
-    private HashSet<String> mClassesNotRenamed;
+    private final HashSet<String> mClassesNotRenamed;
     /** A map { FQCN => set { list of return types to delete from the FQCN } }. */
-    private HashMap<String, Set<String>> mDeleteReturns;
+    private final HashMap<String, Set<String>> mDeleteReturns;
     /** A map { FQCN => set { method names } } of methods to rewrite as delegates.
      *  The special name {@link DelegateClassAdapter#ALL_NATIVES} can be used as in internal set. */
     private final HashMap<String, Set<String>> mDelegateMethods;
@@ -88,11 +88,11 @@ public class AsmGenerator {
 
     private final Set<String> mDelegateAllNative;
     /** A set of classes for which to rename static initializers */
-    private Set<String> mRenameStaticInitializerClasses;
+    private final Set<String> mRenameStaticInitializerClasses;
 
     /** A Set of methods that should be intercepted and replaced **/
     private final Set<MethodReplacer> mMethodReplacers;
-    private boolean mKeepAllNativeClasses;
+    private final boolean mKeepAllNativeClasses;
 
     /** A map { FQCN => set { field names } } which should have their final modifier removed */
     private final Map<String, Set<String>> mRemoveFinalModifierFields;
@@ -129,11 +129,7 @@ public class AsmGenerator {
 
         for (String className : createInfo.getDelegateClassNatives()) {
             className = binaryToInternalClassName(className);
-            Set<String> methods = mDelegateMethods.get(className);
-            if (methods == null) {
-                methods = new HashSet<>();
-                mDelegateMethods.put(className, methods);
-            }
+            Set<String> methods = mDelegateMethods.computeIfAbsent(className, k -> new HashSet<>());
             methods.add(DelegateClassAdapter.ALL_NATIVES);
         }
 
@@ -237,11 +233,7 @@ public class AsmGenerator {
             }
             String className = binaryToInternalClassName(entry.substring(0, pos));
             String methodOrFieldName = entry.substring(pos + 1);
-            Set<String> set = map.get(className);
-            if (set == null) {
-                set = new HashSet<>();
-                map.put(className, set);
-            }
+            Set<String> set = map.computeIfAbsent(className, k -> new HashSet<>());
             set.add(methodOrFieldName);
         }
     }
@@ -322,7 +314,7 @@ public class AsmGenerator {
      * Utility method that converts a fully qualified java name into a JAR entry path
      * e.g. for the input "android.view.View" it returns "android/view/View.class"
      */
-    String classNameToEntryPath(String className) {
+    private String classNameToEntryPath(String className) {
         return className.replace('.', '/').concat(".class");
     }
 
@@ -350,7 +342,7 @@ public class AsmGenerator {
      * Note that unfortunately static methods cannot be changed to non-static (since static and
      * non-static are invoked differently.)
      */
-    byte[] transform(ClassReader cr, boolean stubNativesOnly) {
+    private byte[] transform(ClassReader cr, boolean stubNativesOnly) {
 
         boolean hasNativeMethods = hasNativeMethods(cr);
 
@@ -386,7 +378,7 @@ public class AsmGenerator {
         }
 
         String binaryNewName = newName.replace('/', '.');
-        if (mInjectedMethodsMap.keySet().contains(binaryNewName)) {
+        if (mInjectedMethodsMap.containsKey(binaryNewName)) {
             cv = new InjectMethodsAdapter(cv, mInjectedMethodsMap.get(binaryNewName));
         }
 
@@ -453,7 +445,7 @@ public class AsmGenerator {
      * @param className The internal ASM name of the class that may have to be renamed
      * @return A new transformed name or the original input argument.
      */
-    String transformName(String className) {
+    private String transformName(String className) {
         String newName = mRenameClasses.get(className);
         if (newName != null) {
             return newName;
@@ -474,7 +466,7 @@ public class AsmGenerator {
     /**
      * Returns true if a class has any native methods.
      */
-    boolean hasNativeMethods(ClassReader cr) {
+    private boolean hasNativeMethods(ClassReader cr) {
         ClassHasNativeVisitor cv = new ClassHasNativeVisitor();
         cr.accept(cv, 0);
         return cv.hasNativeMethods();
diff --git a/create/src/com/android/tools/layoutlib/create/CreateInfo.java b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
index fbfd66895f..fcb4ac8371 100644
--- a/create/src/com/android/tools/layoutlib/create/CreateInfo.java
+++ b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
@@ -145,12 +145,13 @@ public final class CreateInfo implements ICreateInfo {
         new SystemCurrentTimeMillisReplacer(),
         new LinkedHashMapEldestReplacer(),
         new ContextGetClassLoaderReplacer(),
-        new ImageReaderNativeInitReplacer(),
         new NativeInitPathReplacer(),
         new AdaptiveIconMaskReplacer(),
         new ActivityThreadInAnimationReplacer(),
         new ReferenceRefersToReplacer(),
         new HtmlApplicationResourceReplacer(),
+        new NativeAllocationRegistryApplyFreeFunctionReplacer(),
+        new LineBreakConfigApplicationInfoReplacer(),
     };
 
     /**
@@ -173,25 +174,26 @@ public final class CreateInfo implements ICreateInfo {
     /**
      * The list of methods to rewrite as delegates.
      */
-    public final static String[] DELEGATE_METHODS = NativeConfig.DELEGATE_METHODS;
+    private final static String[] DELEGATE_METHODS = NativeConfig.DELEGATE_METHODS;
 
     /**
      * The list of classes on which to delegate all native methods.
      */
-    public final static String[] DELEGATE_CLASS_NATIVES = NativeConfig.DELEGATE_CLASS_NATIVES;
+    private final static String[] DELEGATE_CLASS_NATIVES = NativeConfig.DELEGATE_CLASS_NATIVES;
 
-    public final static String[] DELEGATE_CLASS_NATIVES_TO_NATIVES = new String[] {};
+    private final static String[] DELEGATE_CLASS_NATIVES_TO_NATIVES = new String[] {};
 
     /**
      * The list of classes on which NOT to delegate any native method.
      */
-    public final static String[] KEEP_CLASS_NATIVES = new String[] {
+    private final static String[] KEEP_CLASS_NATIVES = new String[] {
         "android.animation.PropertyValuesHolder",
         "android.content.res.StringBlock",
         "android.content.res.XmlBlock",
         "android.graphics.BaseCanvas",
         "android.graphics.BaseRecordingCanvas",
         "android.graphics.Bitmap",
+        "android.graphics.BitmapRegionDecoder",
         "android.graphics.BitmapFactory",
         "android.graphics.BitmapShader",
         "android.graphics.BlendModeColorFilter",
@@ -203,7 +205,7 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.Color",
         "android.graphics.ColorFilter",
         "android.graphics.ColorMatrixColorFilter",
-        "android.graphics.ColorSpace$Rgb",
+        "android.graphics.ColorSpace$Rgb$Native",
         "android.graphics.ComposePathEffect",
         "android.graphics.ComposeShader",
         "android.graphics.CornerPathEffect",
@@ -212,18 +214,26 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.DrawFilter",
         "android.graphics.EmbossMaskFilter",
         "android.graphics.FontFamily",
+        "android.graphics.Gainmap",
+        "android.graphics.HardwareBufferRenderer",
+        "android.graphics.HardwareRenderer",
+        "android.graphics.HardwareRendererObserver",
         "android.graphics.ImageDecoder",
         "android.graphics.Interpolator",
         "android.graphics.LightingColorFilter",
         "android.graphics.LinearGradient",
         "android.graphics.MaskFilter",
         "android.graphics.Matrix",
+        "android.graphics.Matrix$ExtraNatives",
+        "android.graphics.Mesh",
+        "android.graphics.MeshSpecification",
         "android.graphics.NinePatch",
         "android.graphics.Paint",
         "android.graphics.PaintFlagsDrawFilter",
         "android.graphics.Path",
         "android.graphics.PathDashPathEffect",
         "android.graphics.PathEffect",
+        "android.graphics.PathIterator",
         "android.graphics.PathMeasure",
         "android.graphics.Picture",
         "android.graphics.PorterDuffColorFilter",
@@ -242,6 +252,7 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.YuvImage",
         "android.graphics.animation.NativeInterpolatorFactory",
         "android.graphics.animation.RenderNodeAnimator",
+        "android.graphics.drawable.AnimatedImageDrawable",
         "android.graphics.drawable.AnimatedVectorDrawable",
         "android.graphics.drawable.VectorDrawable",
         "android.graphics.fonts.Font",
@@ -251,6 +262,7 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.fonts.FontFileUtil",
         "android.graphics.fonts.SystemFonts",
         "android.graphics.text.PositionedGlyphs",
+        "android.graphics.text.GraphemeBreak",
         "android.graphics.text.LineBreaker",
         "android.graphics.text.MeasuredText",
         "android.graphics.text.MeasuredText$Builder",
@@ -258,11 +270,14 @@ public final class CreateInfo implements ICreateInfo {
         "android.os.SystemProperties",
         "android.os.Trace",
         "android.text.AndroidCharacter",
+        "android.util.EventLog",
         "android.util.Log",
         "android.util.PathParser",
         "android.view.MotionEvent",
         "android.view.Surface",
+        "android.view.VelocityTracker",
         "com.android.internal.util.VirtualRefBasePtr",
+        "libcore.util.NativeAllocationRegistry",
     };
 
     /**
@@ -334,6 +349,8 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.drawable.DrawableInflater#mRes",
         "android.hardware.input.InputManagerGlobal#sInstance",
         "android.view.Choreographer#mCallbackQueues", // required for tests only
+        "android.view.Choreographer#mCallbacksRunning",
+        "android.view.Choreographer#mFrameScheduled",
         "android.view.Choreographer$CallbackQueue#mHead", // required for tests only
         "android.view.ViewRootImpl#mTmpFrames",
         "android.view.accessibility.AccessibilityInteractionClient#sCaches",
@@ -355,10 +372,6 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.Path#nInit",
         "android.graphics.Typeface$Builder#createAssetUid",
         "android.hardware.input.InputManagerGlobal#<init>",
-        "android.media.ImageReader#nativeClassInit",
-        "android.view.Choreographer#doFrame",
-        "android.view.Choreographer#postCallbackDelayedInternal",
-        "android.view.Choreographer#removeCallbacksInternal",
         "android.view.ViewRootImpl#getRootMeasureSpec",
     };
 
@@ -503,23 +516,6 @@ public final class CreateInfo implements ICreateInfo {
         }
     }
 
-    /**
-     * This is to replace a static call to a dummy, so that ImageReader can be loaded and accessed
-     * during JNI loading
-     */
-    public static class ImageReaderNativeInitReplacer implements MethodReplacer {
-        @Override
-        public boolean isNeeded(String owner, String name, String desc, String sourceClass) {
-            return "android/media/ImageReader".equals(owner) && name.equals("nativeClassInit");
-        }
-
-        @Override
-        public void replace(MethodInformation mi) {
-            mi.owner = "android/media/ImageReader_Delegate";
-            mi.opcode = Opcodes.INVOKESTATIC;
-        }
-    }
-
     private static class LocaleGetDefaultReplacer implements MethodReplacer {
 
         @Override
@@ -540,7 +536,7 @@ public final class CreateInfo implements ICreateInfo {
          * Descriptors for specialized versions {@link System#arraycopy} that are not present on the
          * Desktop VM.
          */
-        private static Set<String> ARRAYCOPY_DESCRIPTORS = new HashSet<>(Arrays.asList(
+        private static final Set<String> ARRAYCOPY_DESCRIPTORS = new HashSet<>(Arrays.asList(
                 "([CI[CII)V", "([BI[BII)V", "([SI[SII)V", "([II[III)V",
                 "([JI[JII)V", "([FI[FII)V", "([DI[DII)V", "([ZI[ZII)V"));
 
@@ -636,4 +632,36 @@ public final class CreateInfo implements ICreateInfo {
             mi.desc = "(Landroid/app/Application;)Landroid/content/res/Resources;";
         }
     }
+
+    public static class NativeAllocationRegistryApplyFreeFunctionReplacer
+        implements MethodReplacer {
+        @Override
+        public boolean isNeeded(String owner, String name, String desc, String sourceClass) {
+            return "libcore/util/NativeAllocationRegistry".equals(owner) &&
+                    "applyFreeFunction".equals(name) && "(JJ)V".equals(desc);
+        }
+
+        @Override
+        public void replace(MethodInformation mi) {
+            mi.owner = "libcore/util/NativeAllocationRegistry_Delegate";
+            mi.opcode = Opcodes.INVOKESTATIC;
+        }
+    }
+
+    public static class LineBreakConfigApplicationInfoReplacer implements MethodReplacer {
+        @Override
+        public boolean isNeeded(String owner, String name, String desc, String sourceClass) {
+            return "android/graphics/text/LineBreakConfig".equals(sourceClass) &&
+                    "android/app/Application".equals(owner) &&
+                    name.equals("getApplicationInfo");
+        }
+
+        @Override
+        public void replace(MethodInformation mi) {
+            mi.owner = "android/app/Application_Delegate";
+            mi.name = "getApplicationInfo";
+            mi.opcode = Opcodes.INVOKESTATIC;
+            mi.desc = "(Landroid/app/Application;)Landroid/content/pm/ApplicationInfo;";
+        }
+    }
 }
diff --git a/create/src/com/android/tools/layoutlib/create/DelegateMethodAdapter.java b/create/src/com/android/tools/layoutlib/create/DelegateMethodAdapter.java
index 859578e601..3ec5a2966f 100644
--- a/create/src/com/android/tools/layoutlib/create/DelegateMethodAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/DelegateMethodAdapter.java
@@ -41,7 +41,7 @@ import java.util.ArrayList;
  *   This step is omitted if the method is native, since it has no Java implementation.
  * <li> A brand new implementation of {@code SomeClass.MethodName()} which calls to a
  *   non-existing method named {@code SomeClass_Delegate.MethodName()}.
- *   The implementation of this 'delegate' method is done in layoutlib_brigde.
+ *   The implementation of this 'delegate' method is done in layoutlib_bridge.
  * </ul>
  * A method visitor is generally constructed to generate a single method; however
  * here we might want to generate one or two depending on the context. To achieve
@@ -80,11 +80,11 @@ class DelegateMethodAdapter extends MethodVisitor {
 
     /** The parent method writer to copy of the original method.
      *  Null when dealing with a native original method. */
-    private MethodVisitor mOrgWriter;
+    private final MethodVisitor mOrgWriter;
     /** The parent method writer to generate the delegating method. Never null. */
-    private MethodVisitor mDelWriter;
+    private final MethodVisitor mDelWriter;
     /** The original method descriptor (return type + argument types.) */
-    private String mDesc;
+    private final String mDesc;
     /** True if the original method is static. */
     private final boolean mIsStatic;
     /** True if the method is contained in a static inner class */
@@ -266,7 +266,7 @@ class DelegateMethodAdapter extends MethodVisitor {
         // we pushed on the call stack. The return type remains unchanged.
         String desc = Type.getMethodDescriptor(
                 Type.getReturnType(mDesc),
-                paramTypes.toArray(new Type[paramTypes.size()]));
+                paramTypes.toArray(new Type[0]));
 
         // Invoke the static delegate
         mDelWriter.visitMethodInsn(Opcodes.INVOKESTATIC,
diff --git a/create/src/com/android/tools/layoutlib/create/DelegateToNativeAdapter.java b/create/src/com/android/tools/layoutlib/create/DelegateToNativeAdapter.java
index d063e15f71..3d534d711d 100644
--- a/create/src/com/android/tools/layoutlib/create/DelegateToNativeAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/DelegateToNativeAdapter.java
@@ -9,7 +9,6 @@ import org.objectweb.asm.MethodVisitor;
 import org.objectweb.asm.Opcodes;
 import org.objectweb.asm.Type;
 
-import java.util.ArrayList;
 import java.util.Map;
 import java.util.Set;
 
diff --git a/create/src/com/android/tools/layoutlib/create/DependencyFinder.java b/create/src/com/android/tools/layoutlib/create/DependencyFinder.java
index aa68ea0998..f0650356b1 100644
--- a/create/src/com/android/tools/layoutlib/create/DependencyFinder.java
+++ b/create/src/com/android/tools/layoutlib/create/DependencyFinder.java
@@ -16,9 +16,6 @@
 
 package com.android.tools.layoutlib.create;
 
-import com.android.tools.layoutlib.annotations.VisibleForTesting;
-import com.android.tools.layoutlib.annotations.VisibleForTesting.Visibility;
-
 import org.objectweb.asm.AnnotationVisitor;
 import org.objectweb.asm.Attribute;
 import org.objectweb.asm.ClassReader;
@@ -95,7 +92,7 @@ public class DependencyFinder {
         Map<String, Set<String>> deps = result.get(0);
         Map<String, Set<String>> missing = result.get(1);
 
-        // Print all dependences found in the format:
+        // Print all dependencies found in the format:
         // +Found: <FQCN from zip>
         //     uses: FQCN
 
@@ -112,7 +109,7 @@ public class DependencyFinder {
         }
 
 
-        // Now print all missing dependences in the format:
+        // Now print all missing dependencies in the format:
         // -Missing <FQCN>:
         //     used by: <FQCN>
 
@@ -149,19 +146,20 @@ public class DependencyFinder {
      * Parses a JAR file and returns a list of all classes founds using a map
      * class name => ASM ClassReader. Class names are in the form "android.view.View".
      */
-    Map<String,ClassReader> parseZip(List<String> jarPathList) throws IOException {
+    private Map<String,ClassReader> parseZip(List<String> jarPathList) throws IOException {
         TreeMap<String, ClassReader> classes = new TreeMap<>();
 
         for (String jarPath : jarPathList) {
-            ZipFile zip = new ZipFile(jarPath);
-            Enumeration<? extends ZipEntry> entries = zip.entries();
-            ZipEntry entry;
-            while (entries.hasMoreElements()) {
-                entry = entries.nextElement();
-                if (entry.getName().endsWith(".class")) {
-                    ClassReader cr = new ClassReader(zip.getInputStream(entry));
-                    String className = classReaderToClassName(cr);
-                    classes.put(className, cr);
+            try (ZipFile zip = new ZipFile(jarPath)) {
+                Enumeration<? extends ZipEntry> entries = zip.entries();
+                ZipEntry entry;
+                while (entries.hasMoreElements()) {
+                    entry = entries.nextElement();
+                    if (entry.getName().endsWith(".class")) {
+                        ClassReader cr = new ClassReader(zip.getInputStream(entry));
+                        String className = classReaderToClassName(cr);
+                        classes.put(className, cr);
+                    }
                 }
             }
         }
@@ -173,7 +171,7 @@ public class DependencyFinder {
      * Utility that returns the fully qualified binary class name for a ClassReader.
      * E.g. it returns something like android.view.View.
      */
-    static String classReaderToClassName(ClassReader classReader) {
+    private static String classReaderToClassName(ClassReader classReader) {
         if (classReader == null) {
             return null;
         } else {
@@ -185,7 +183,7 @@ public class DependencyFinder {
      * Utility that returns the fully qualified binary class name from a path-like FQCN.
      * E.g. it returns android.view.View from android/view/View.
      */
-    static String internalToBinaryClassName(String className) {
+    private static String internalToBinaryClassName(String className) {
         if (className == null) {
             return null;
         } else {
@@ -197,13 +195,13 @@ public class DependencyFinder {
      * Finds all dependencies for all classes in keepClasses which are also
      * listed in zipClasses. Returns a map of all the dependencies found.
      */
-    Map<String, Set<String>> findClassesDeps(Map<String, ClassReader> zipClasses) {
+    private Map<String, Set<String>> findClassesDeps(Map<String, ClassReader> zipClasses) {
 
         // The dependencies that we'll collect.
         // It's a map Class name => uses class names.
         Map<String, Set<String>> dependencyMap = new TreeMap<>();
 
-        DependencyVisitor visitor = getVisitor();
+        DependencyVisitor visitor = new DependencyVisitor();
 
         int count = 0;
         try {
@@ -247,11 +245,7 @@ public class DependencyFinder {
             for (String dep : entry.getValue()) {
                 if (!zipClasses.contains(dep)) {
                     // This dependency doesn't exist in the zip classes.
-                    Set<String> set = missing.get(dep);
-                    if (set == null) {
-                        set = new TreeSet<>();
-                        missing.put(dep, set);
-                    }
+                    Set<String> set = missing.computeIfAbsent(dep, k -> new TreeSet<>());
                     set.add(name);
                 }
             }
@@ -264,25 +258,17 @@ public class DependencyFinder {
 
     // ----------------------------------
 
-    /**
-     * Instantiates a new DependencyVisitor. Useful for unit tests.
-     */
-    @VisibleForTesting(visibility=Visibility.PRIVATE)
-    DependencyVisitor getVisitor() {
-        return new DependencyVisitor();
-    }
-
     /**
      * Visitor to collect all the type dependencies from a class.
      */
-    public class DependencyVisitor extends ClassVisitor {
+    protected static class DependencyVisitor extends ClassVisitor {
 
         private Set<String> mCurrentDepSet;
 
         /**
          * Creates a new visitor that will find all the dependencies for the visited class.
          */
-        public DependencyVisitor() {
+        private DependencyVisitor() {
             super(Main.ASM_VERSION);
         }
 
@@ -290,14 +276,14 @@ public class DependencyFinder {
          * Sets the {@link Set} where to record direct dependencies for this class.
          * This will change before each {@link ClassReader#accept(ClassVisitor, int)} call.
          */
-        public void setDependencySet(Set<String> set) {
+        private void setDependencySet(Set<String> set) {
             mCurrentDepSet = set;
         }
 
         /**
          * Considers the given class name as a dependency.
          */
-        public void considerName(String className) {
+        private void considerName(String className) {
             if (className == null) {
                 return;
             }
@@ -323,7 +309,7 @@ public class DependencyFinder {
         /**
          * Considers this array of names using considerName().
          */
-        public void considerNames(String[] classNames) {
+        private void considerNames(String[] classNames) {
             if (classNames != null) {
                 for (String className : classNames) {
                     considerName(className);
@@ -335,7 +321,7 @@ public class DependencyFinder {
          * Considers this signature or type signature by invoking the {@link SignatureVisitor}
          * on it.
          */
-        public void considerSignature(String signature) {
+        private void considerSignature(String signature) {
             if (signature != null) {
                 SignatureReader sr = new SignatureReader(signature);
                 // SignatureReader.accept will call accessType so we don't really have
@@ -348,7 +334,7 @@ public class DependencyFinder {
          * Considers this {@link Type}. For arrays, the element type is considered.
          * If the type is an object, it's internal name is considered.
          */
-        public void considerType(Type t) {
+        private void considerType(Type t) {
             if (t != null) {
                 if (t.getSort() == Type.ARRAY) {
                     t = t.getElementType();
@@ -363,10 +349,10 @@ public class DependencyFinder {
          * Considers a descriptor string. The descriptor is converted to a {@link Type}
          * and then considerType() is invoked.
          */
-        public boolean considerDesc(String desc) {
+        private boolean considerDesc(String desc) {
             if (desc != null) {
                 try {
-                    if (desc.length() > 0 && desc.charAt(0) == '(') {
+                    if (!desc.isEmpty() && desc.charAt(0) == '(') {
                         // This is a method descriptor with arguments and a return type.
                         Type t = Type.getReturnType(desc);
                         considerType(t);
@@ -433,7 +419,7 @@ public class DependencyFinder {
 
         private class MyFieldVisitor extends FieldVisitor {
 
-            public MyFieldVisitor() {
+            private MyFieldVisitor() {
                 super(Main.ASM_VERSION);
             }
 
@@ -508,7 +494,7 @@ public class DependencyFinder {
 
         private class MyMethodVisitor extends MethodVisitor {
 
-            public MyMethodVisitor() {
+            private MyMethodVisitor() {
                 super(Main.ASM_VERSION);
             }
 
@@ -653,7 +639,7 @@ public class DependencyFinder {
 
         private class MySignatureVisitor extends SignatureVisitor {
 
-            public MySignatureVisitor() {
+            private MySignatureVisitor() {
                 super(Main.ASM_VERSION);
             }
 
@@ -752,7 +738,7 @@ public class DependencyFinder {
 
         private class MyAnnotationVisitor extends AnnotationVisitor {
 
-            public MyAnnotationVisitor() {
+            protected MyAnnotationVisitor() {
                 super(Main.ASM_VERSION);
             }
 
diff --git a/create/src/com/android/tools/layoutlib/create/Log.java b/create/src/com/android/tools/layoutlib/create/Log.java
index c3ba591513..2ee06e58a0 100644
--- a/create/src/com/android/tools/layoutlib/create/Log.java
+++ b/create/src/com/android/tools/layoutlib/create/Log.java
@@ -56,7 +56,7 @@ public class Log {
         PrintWriter pw = new PrintWriter(sw);
         t.printStackTrace(pw);
         pw.flush();
-        error(format + "\n" + sw.toString(), args);
+        error(format + "\n" + sw, args);
     }
 
     /** for unit testing */
diff --git a/create/src/com/android/tools/layoutlib/create/Main.java b/create/src/com/android/tools/layoutlib/create/Main.java
index 2da8ea6b11..5f67ff44d3 100644
--- a/create/src/com/android/tools/layoutlib/create/Main.java
+++ b/create/src/com/android/tools/layoutlib/create/Main.java
@@ -133,7 +133,7 @@ public class Main {
                         "com.android.internal.util.*",
                         "com.android.internal.view.menu.ActionMenu",
                         "com.android.internal.widget.*",
-                        "com.android.systemui.monet.*",     // needed for dynamic theming
+                        "com.android.systemui.monet.**",     // needed for dynamic theming
                         "com.google.android.apps.common.testing.accessibility.**",
                         "com.google.android.libraries.accessibility.**",
                         "libcore.icu.ICU",                  // needed by ICU_Delegate in LayoutLib
@@ -173,13 +173,13 @@ public class Main {
             // it means the renameClasses[] array in AsmGenerator needs to be updated: some
             // class should have been renamed but it was not found in the input JAR files.
             Set<String> notRenamed = agen.getClassesNotRenamed();
-            if (notRenamed.size() > 0) {
+            if (!notRenamed.isEmpty()) {
                 // (80-column guide below for error formatting)
                 // 01234567890123456789012345678901234567890123456789012345678901234567890123456789
-                log.error(
-                  "ERROR when running layoutlib_create: the following classes are referenced\n" +
-                  "by tools/layoutlib/create but were not actually found in the input JAR files.\n" +
-                  "This may be due to some platform classes having been renamed.");
+                log.error("""
+                        ERROR when running layoutlib_create: the following classes are referenced
+                        by tools/layoutlib/create but were not actually found in the input JAR files.
+                        This may be due to some platform classes having been renamed.""");
                 for (String fqcn : notRenamed) {
                     log.error("- Class not found: %s", fqcn.replace('/', '.'));
                 }
diff --git a/create/src/com/android/tools/layoutlib/create/OverrideMethod.java b/create/src/com/android/tools/layoutlib/create/OverrideMethod.java
index 7ccafc3867..25a246e998 100644
--- a/create/src/com/android/tools/layoutlib/create/OverrideMethod.java
+++ b/create/src/com/android/tools/layoutlib/create/OverrideMethod.java
@@ -19,7 +19,7 @@ package com.android.tools.layoutlib.create;
 import java.util.HashMap;
 
 /**
- * Allows stub methods from LayoutLib to be overriden at runtime.
+ * Allows stub methods from LayoutLib to be overridden at runtime.
  * <p/>
  * Implementation note: all types required by this class(inner/outer classes & interfaces)
  * must be referenced by the injectClass argument to {@link AsmGenerator} in Main.java;
@@ -28,7 +28,7 @@ import java.util.HashMap;
 public final class OverrideMethod {
 
     /** Map of method overridden. */
-    private static HashMap<String, MethodListener> sMethods = new HashMap<>();
+    private static final HashMap<String, MethodListener> sMethods = new HashMap<>();
     /** Default listener for all method not listed in sMethods. Nothing if null. */
     private static MethodListener sDefaultListener = null;
     
diff --git a/create/src/com/android/tools/layoutlib/create/RenameClassAdapter.java b/create/src/com/android/tools/layoutlib/create/RenameClassAdapter.java
index 40bd1262f5..613dbfc95a 100644
--- a/create/src/com/android/tools/layoutlib/create/RenameClassAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/RenameClassAdapter.java
@@ -52,8 +52,6 @@ public class RenameClassAdapter extends AbstractClassAdapter {
         if (pos > 0) {
             mNewBase = mNewName.substring(0, pos);
         }
-
-        assert (mOldBase == null && mNewBase == null) || (mOldBase != null && mNewBase != null);
     }
 
     /**
diff --git a/create/src/com/android/tools/layoutlib/create/ReplaceMethodCallsAdapter.java b/create/src/com/android/tools/layoutlib/create/ReplaceMethodCallsAdapter.java
index a9bcd224e1..2660b61b62 100644
--- a/create/src/com/android/tools/layoutlib/create/ReplaceMethodCallsAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/ReplaceMethodCallsAdapter.java
@@ -30,7 +30,7 @@ import java.util.Set;
  */
 public class ReplaceMethodCallsAdapter extends ClassVisitor {
 
-    private Set<MethodReplacer> mMethodReplacers;
+    private final Set<MethodReplacer> mMethodReplacers;
     private final String mOriginalClassName;
 
     public ReplaceMethodCallsAdapter(Set<MethodReplacer> methodReplacers, ClassVisitor cv, String originalClassName) {
@@ -47,7 +47,7 @@ public class ReplaceMethodCallsAdapter extends ClassVisitor {
 
     private class MyMethodVisitor extends MethodVisitor {
 
-        public MyMethodVisitor(MethodVisitor mv) {
+        private MyMethodVisitor(MethodVisitor mv) {
             super(Main.ASM_VERSION, mv);
         }
 
diff --git a/create/src/com/android/tools/layoutlib/create/StubCallMethodAdapter.java b/create/src/com/android/tools/layoutlib/create/StubCallMethodAdapter.java
index f4cfc1d0c0..556188c7ce 100644
--- a/create/src/com/android/tools/layoutlib/create/StubCallMethodAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/StubCallMethodAdapter.java
@@ -33,11 +33,11 @@ class StubCallMethodAdapter extends MethodVisitor {
     private static final String CLASS_INIT = "<clinit>";
 
     /** The parent method writer */
-    private MethodVisitor mParentVisitor;
+    private final MethodVisitor mParentVisitor;
     /** The method return type. Can be null. */
-    private Type mReturnType;
+    private final Type mReturnType;
     /** Message to be printed by stub methods. */
-    private String mInvokeSignature;
+    private final String mInvokeSignature;
     /** Flag to output the first line number. */
     private boolean mOutputFirstLineNumber = true;
     /** Flag that is true when implementing a constructor, to accept all original
diff --git a/create/src/com/android/tools/layoutlib/create/StubClassAdapter.java b/create/src/com/android/tools/layoutlib/create/StubClassAdapter.java
index 5202ce49bd..7671a5703e 100644
--- a/create/src/com/android/tools/layoutlib/create/StubClassAdapter.java
+++ b/create/src/com/android/tools/layoutlib/create/StubClassAdapter.java
@@ -45,10 +45,10 @@ public class StubClassAdapter extends ClassVisitor {
     }
 
     public static class Builder {
-        private Log mLogger;
+        private final Log mLogger;
         private Set<String> mDeleteReturns;
         private String mClassName;
-        private ClassVisitor mCv;
+        private final ClassVisitor mCv;
         private boolean mStubNativesOnly;
         private boolean mRemoveStaticInitializers;
         private boolean mRemovePrivates;
@@ -77,19 +77,19 @@ public class StubClassAdapter extends ClassVisitor {
         }
 
         @NotNull
-        public Builder withMethodVisitorFactory(@Nullable MethodVisitorFactory factory) {
+        private Builder withMethodVisitorFactory(@Nullable MethodVisitorFactory factory) {
             mMethodVisitorFactory = factory;
             return this;
         }
 
         @NotNull
-        public Builder removePrivates() {
+        private Builder removePrivates() {
             mRemovePrivates = true;
             return this;
         }
 
         @NotNull
-        public Builder removeStaticInitializers() {
+        private Builder removeStaticInitializers() {
             mRemoveStaticInitializers = true;
             return this;
         }
@@ -115,7 +115,7 @@ public class StubClassAdapter extends ClassVisitor {
     private final Set<String> mDeleteReturns;
     private final MethodVisitorFactory mMethodVisitorFactory;
     private final boolean mRemovePrivates;
-    private final boolean mRemoveStaticInitalizers;
+    private final boolean mRemoveStaticInitializers;
 
 
     @NotNull
@@ -144,7 +144,7 @@ public class StubClassAdapter extends ClassVisitor {
         mDeleteReturns = deleteReturns;
         mMethodVisitorFactory = methodVisitorFactory;
         mRemovePrivates = removePrivates;
-        mRemoveStaticInitalizers = removeStaticInitializers;
+        mRemoveStaticInitializers = removeStaticInitializers;
     }
 
     /**
@@ -217,7 +217,7 @@ public class StubClassAdapter extends ClassVisitor {
             return null;
         }
 
-        if (mRemoveStaticInitalizers && "<clinit>".equals(name)) {
+        if (mRemoveStaticInitializers && "<clinit>".equals(name)) {
             return null;
         }
 
@@ -225,10 +225,8 @@ public class StubClassAdapter extends ClassVisitor {
             Type t = Type.getReturnType(desc);
             if (t.getSort() == Type.OBJECT) {
                 String returnType = t.getInternalName();
-                if (returnType != null) {
-                    if (mDeleteReturns.contains(returnType)) {
-                        return null;
-                    }
+                if (mDeleteReturns.contains(returnType)) {
+                    return null;
                 }
             }
         }
diff --git a/create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java b/create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java
deleted file mode 100644
index 33039b5fe9..0000000000
--- a/create/src/com/android/tools/layoutlib/java/NioUtils_Delegate.java
+++ /dev/null
@@ -1,15 +0,0 @@
-
-package com.android.tools.layoutlib.java;
-
-import java.nio.ByteBuffer;
-
-public final class NioUtils_Delegate {
-  public static void freeDirectBuffer(ByteBuffer buffer) {
-    /*
-     * NioUtils is not included in layoutlib classpath. Thus, calling NioUtils.freeDirectBuffer in
-     * {@link android.graphics.ImageReader} produces ClassNotFound exception. Moreover, it does not
-     * seem we have to do anything in here as we are only referencing the existing native buffer
-     * and do not perform any allocation on creation.
-     */
-  }
-}
\ No newline at end of file
diff --git a/create/tests/Android.bp b/create/tests/Android.bp
index 9153b8f87d..cb60ad8208 100644
--- a/create/tests/Android.bp
+++ b/create/tests/Android.bp
@@ -33,14 +33,12 @@ java_test_host {
     // Only compile source java files in this lib.
     srcs: ["src/**/*.java"],
 
-    java_resource_dirs: ["res"],
-
-    libs: [
+    static_libs: [
         "layoutlib_create",
         "junit",
         "hamcrest",
+        "ow2-asm",
     ],
-    static_libs: ["ow2-asm"],
 
     // Copy the jar to DIST_DIR for sdk builds
     dist: {
diff --git a/create/tests/run_tests.sh b/create/tests/run_tests.sh
index d0de029ecf..dee5f36ceb 100755
--- a/create/tests/run_tests.sh
+++ b/create/tests/run_tests.sh
@@ -3,11 +3,11 @@
 SCRIPT_DIR="$(dirname $0)"
 DIST_DIR="$1"
 
-STUDIO_JDK=${SCRIPT_DIR}"/../../../../prebuilts/jdk/jdk17/linux-x86"
-OUT_INTERMEDIATES=${SCRIPT_DIR}"/../../../../out/soong/.intermediates"
+STUDIO_JDK=${SCRIPT_DIR}"/../../../../prebuilts/jdk/jdk21/linux-x86"
+TEST_JAR=${SCRIPT_DIR}"/../../../../out/host/linux-x86/framework/layoutlib-create-tests.jar"
 
 ${STUDIO_JDK}/bin/java -ea \
-    -cp ${OUT_INTERMEDIATES}/external/junit/junit/linux_glibc_common/javac/junit.jar:${OUT_INTERMEDIATES}/external/hamcrest/hamcrest-core/hamcrest/linux_glibc_common/javac/hamcrest.jar:${OUT_INTERMEDIATES}/frameworks/layoutlib/create/layoutlib_create/linux_glibc_common/combined/layoutlib_create.jar:${OUT_INTERMEDIATES}/frameworks/layoutlib/create/tests/layoutlib-create-tests/linux_glibc_common/combined/layoutlib-create-tests.jar:${SCRIPT_DIR}/res \
+    -cp ${TEST_JAR}:${SCRIPT_DIR}/res \
     org.junit.runner.JUnitCore \
     com.android.tools.layoutlib.create.AllTests
 
diff --git a/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java b/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
index 0fa7ecb764..3655ec23b7 100644
--- a/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
+++ b/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
@@ -155,7 +155,7 @@ public class PromoteClassClassAdapterTest {
         PromoteClassClassAdapter adapter = new PromoteClassClassAdapter(log, Set.of(
                 PackageProtectedClass.class.getName()));
         reader.accept(adapter, 0);
-        assertTrue(log.mLog.contains("[visit] - version=55, access=[public], " +
+        assertTrue(log.mLog.contains("[visit] - version=61, access=[public], " +
                 "name=com/android/tools/layoutlib/create/PackageProtectedClass, signature=null, " +
                 "superName=java/lang/Object, interfaces=[]"));
 
diff --git a/jni/LayoutlibLoader.cpp b/jni/LayoutlibLoader.cpp
new file mode 100644
index 0000000000..4a5f925535
--- /dev/null
+++ b/jni/LayoutlibLoader.cpp
@@ -0,0 +1,188 @@
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
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <android_runtime/AndroidRuntime.h>
+#include <android_view_InputDevice.h>
+#include <jni_wrappers.h>
+
+#include <clocale>
+#include <sstream>
+#include <unordered_map>
+#include <vector>
+
+using namespace std;
+
+static jclass bridge;
+static jclass layoutLog;
+static jmethodID getLogId;
+static jmethodID logMethodId;
+
+namespace android {
+
+extern int register_android_view_LayoutlibRenderer(JNIEnv* env);
+
+#define REG_JNI(name) \
+    { name }
+struct RegJNIRec {
+    int (*mProc)(JNIEnv*);
+};
+
+static const RegJNIRec gRegJNI[] = {
+        REG_JNI(register_android_view_LayoutlibRenderer),
+};
+
+int register_jni_procs(JNIEnv* env) {
+    for (size_t i = 0; i < NELEM(android::gRegJNI); i++) {
+        if (android::gRegJNI[i].mProc(env) < 0) {
+            return -1;
+        }
+    }
+
+    return 0;
+}
+
+static vector<string> parseCsv(const string& csvString) {
+    vector<string> result;
+    istringstream stream(csvString);
+    string segment;
+    while (getline(stream, segment, ',')) {
+        result.push_back(segment);
+    }
+    return result;
+}
+
+// Creates an array of InputDevice from key character map files
+static void init_keyboard(const vector<string>& keyboardPaths) {
+    JNIEnv* env = AndroidRuntime::getJNIEnv();
+    jclass inputDevice = FindClassOrDie(env, "android/view/InputDevice");
+    jobjectArray inputDevicesArray =
+            env->NewObjectArray(keyboardPaths.size(), inputDevice, nullptr);
+    int keyboardId = 1;
+
+    for (const string& path : keyboardPaths) {
+        base::Result<std::shared_ptr<KeyCharacterMap>> charMap =
+                KeyCharacterMap::load(path, KeyCharacterMap::Format::BASE);
+
+        InputDeviceInfo info = InputDeviceInfo();
+        info.initialize(keyboardId, 0, 0, InputDeviceIdentifier(),
+                        "keyboard " + std::to_string(keyboardId), true, false,
+                        ui::LogicalDisplayId::DEFAULT);
+        info.setKeyboardType(AINPUT_KEYBOARD_TYPE_ALPHABETIC);
+        info.setKeyCharacterMap(*charMap);
+
+        jobject inputDeviceObj = android_view_InputDevice_create(env, info);
+        if (inputDeviceObj) {
+            env->SetObjectArrayElement(inputDevicesArray, keyboardId - 1, inputDeviceObj);
+            env->DeleteLocalRef(inputDeviceObj);
+        }
+        keyboardId++;
+    }
+
+    if (bridge == nullptr) {
+        bridge = FindClassOrDie(env, "com/android/layoutlib/bridge/Bridge");
+        bridge = MakeGlobalRefOrDie(env, bridge);
+    }
+    jmethodID setInputManager = GetStaticMethodIDOrDie(env, bridge, "setInputManager",
+                                                       "([Landroid/view/InputDevice;)V");
+    env->CallStaticVoidMethod(bridge, setInputManager, inputDevicesArray);
+    env->DeleteLocalRef(inputDevicesArray);
+}
+
+void LayoutlibLogger(base::LogId, base::LogSeverity severity, const char* tag, const char* file,
+                     unsigned int line, const char* message) {
+    JNIEnv* env = AndroidRuntime::getJNIEnv();
+    jint logPrio = severity;
+    jstring tagString = env->NewStringUTF(tag);
+    jstring messageString = env->NewStringUTF(message);
+
+    jobject bridgeLog = env->CallStaticObjectMethod(bridge, getLogId);
+
+    env->CallVoidMethod(bridgeLog, logMethodId, logPrio, tagString, messageString);
+
+    env->DeleteLocalRef(tagString);
+    env->DeleteLocalRef(messageString);
+    env->DeleteLocalRef(bridgeLog);
+}
+
+void LayoutlibAborter(const char* abort_message) {
+    // Layoutlib should not call abort() as it would terminate Studio.
+    // Throw an exception back to Java instead.
+    JNIEnv* env = AndroidRuntime::getJNIEnv();
+    jniThrowRuntimeException(env, "The Android framework has encountered a fatal error");
+}
+
+class LayoutlibRuntime : public AndroidRuntime {
+public:
+    LayoutlibRuntime() : AndroidRuntime(nullptr, 0) {}
+
+    void onVmCreated(JNIEnv* env) override {
+        AndroidRuntime::onVmCreated(env);
+        android::base::SetLogger(LayoutlibLogger);
+        android::base::SetAborter(LayoutlibAborter);
+    }
+
+    void onStarted() override {
+        JNIEnv* env = AndroidRuntime::getJNIEnv();
+        register_jni_procs(env);
+
+        jmethodID setSystemPropertiesMethod =
+                GetStaticMethodIDOrDie(env, bridge, "setSystemProperties", "()V");
+        env->CallStaticVoidMethod(bridge, setSystemPropertiesMethod);
+
+        string keyboard_paths = base::GetProperty("ro.keyboard.paths", "");
+        vector<string> keyboardPaths = parseCsv(keyboard_paths);
+        init_keyboard(keyboardPaths);
+
+        AndroidRuntime::onStarted();
+    }
+};
+
+} // namespace android
+
+using namespace android;
+
+JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
+    JNIEnv* env = nullptr;
+    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
+        return JNI_ERR;
+    }
+
+    layoutLog = FindClassOrDie(env, "com/android/ide/common/rendering/api/ILayoutLog");
+    layoutLog = MakeGlobalRefOrDie(env, layoutLog);
+    logMethodId = GetMethodIDOrDie(env, layoutLog, "logAndroidFramework",
+                                   "(ILjava/lang/String;Ljava/lang/String;)V");
+    bridge = FindClassOrDie(env, "com/android/layoutlib/bridge/Bridge");
+    bridge = MakeGlobalRefOrDie(env, bridge);
+    getLogId = GetStaticMethodIDOrDie(env, bridge, "getLog",
+                                      "()Lcom/android/ide/common/rendering/api/ILayoutLog;");
+
+    Vector<String8> args;
+    LayoutlibRuntime runtime;
+
+    runtime.onVmCreated(env);
+    runtime.start("LayoutlibRuntime", args, false);
+
+    return JNI_VERSION_1_6;
+}
+
+JNIEXPORT void JNI_OnUnload(JavaVM* vm, void*) {
+    JNIEnv* env = nullptr;
+    vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
+    env->DeleteGlobalRef(bridge);
+    env->DeleteGlobalRef(layoutLog);
+}
diff --git a/jni/android_view_LayoutlibRenderer.cpp b/jni/android_view_LayoutlibRenderer.cpp
new file mode 100644
index 0000000000..ed701493fb
--- /dev/null
+++ b/jni/android_view_LayoutlibRenderer.cpp
@@ -0,0 +1,115 @@
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
+#include <gui/BufferQueue.h>
+#include <gui/IGraphicBufferConsumer.h>
+#include <gui/IGraphicBufferProducer.h>
+#include <ui/GraphicBuffer.h>
+
+#include "android_runtime/android_view_Surface.h"
+#include "core_jni_helpers.h"
+#include "jni.h"
+
+namespace android {
+
+jfieldID gNativeContextFieldId;
+
+/**
+ * Class to store information needed by the Layoutlib renderer
+ */
+class JNILayoutlibRendererContext : public RefBase {
+public:
+    ~JNILayoutlibRendererContext() override {
+        if (mBufferConsumer != nullptr) {
+            mBufferConsumer.clear();
+        }
+    }
+
+    void setBufferConsumer(const sp<IGraphicBufferConsumer>& consumer) {
+        mBufferConsumer = consumer;
+    }
+
+    IGraphicBufferConsumer* getBufferConsumer() {
+        return mBufferConsumer.get();
+    }
+
+private:
+    sp<IGraphicBufferConsumer> mBufferConsumer;
+};
+
+static jobject android_view_LayoutlibRenderer_createSurface(JNIEnv* env, jobject thiz) {
+    sp<IGraphicBufferProducer> gbProducer;
+    sp<IGraphicBufferConsumer> gbConsumer;
+    BufferQueue::createBufferQueue(&gbProducer, &gbConsumer);
+
+    // Save the IGraphicBufferConsumer in the context so that it can be reused for buffer creation
+    sp<JNILayoutlibRendererContext> newCtx = sp<JNILayoutlibRendererContext>::make();
+    newCtx->setBufferConsumer(gbConsumer);
+    auto* const currentCtx = reinterpret_cast<JNILayoutlibRendererContext*>(
+            env->GetLongField(thiz, gNativeContextFieldId));
+    if (newCtx != nullptr) {
+        // Create a strong reference to the new context to avoid it being destroyed
+        newCtx->incStrong((void*)android_view_LayoutlibRenderer_createSurface);
+    }
+    if (currentCtx != nullptr) {
+        // Delete the reference to the previous context as it is not needed and can be destroyed
+        currentCtx->decStrong((void*)android_view_LayoutlibRenderer_createSurface);
+    }
+    env->SetLongField(thiz, gNativeContextFieldId, reinterpret_cast<jlong>(newCtx.get()));
+
+    return android_view_Surface_createFromIGraphicBufferProducer(env, gbProducer);
+}
+
+static jobject android_view_LayoutlibRenderer_createBuffer(JNIEnv* env, jobject thiz, jint width,
+                                                           jint height) {
+    auto* ctx = reinterpret_cast<JNILayoutlibRendererContext*>(
+            env->GetLongField(thiz, gNativeContextFieldId));
+    if (ctx == nullptr) {
+        jniThrowException(env, "java/lang/IllegalStateException", "No surface has been created");
+        return nullptr;
+    }
+
+    IGraphicBufferConsumer* bufferConsumer = ctx->getBufferConsumer();
+    bufferConsumer->setDefaultBufferSize(width, height);
+    auto* bufferItem = new BufferItem();
+    bufferConsumer->acquireBuffer(bufferItem, 0);
+    sp<GraphicBuffer> buffer = bufferItem->mGraphicBuffer;
+
+    int bytesPerPixel = 4;
+    uint32_t dataSize = buffer->getStride() * buffer->getHeight() * bytesPerPixel;
+
+    void* pData = nullptr;
+    buffer->lockAsync(0, Rect::EMPTY_RECT, &pData, 0);
+
+    jobject byteBuffer = env->NewDirectByteBuffer(pData, dataSize);
+    return byteBuffer;
+}
+
+static const JNINativeMethod gMethods[] = {
+        {"nativeCreateSurface", "()Landroid/view/Surface;",
+         (void*)android_view_LayoutlibRenderer_createSurface},
+        {"nativeCreateBuffer", "(II)Ljava/nio/ByteBuffer;",
+         (void*)android_view_LayoutlibRenderer_createBuffer},
+};
+
+int register_android_view_LayoutlibRenderer(JNIEnv* env) {
+    jclass layoutlibRendererClass = FindClassOrDie(env, "android/view/LayoutlibRenderer");
+    gNativeContextFieldId = GetFieldIDOrDie(env, layoutlibRendererClass, "mNativeContext", "J");
+
+    return RegisterMethodsOrDie(env, "android/view/LayoutlibRenderer", gMethods, NELEM(gMethods));
+}
+
+} // namespace android
\ No newline at end of file
diff --git a/split_universal_binary.sh b/split_universal_binary.sh
index 55b5b3829b..f5e69acb1d 100755
--- a/split_universal_binary.sh
+++ b/split_universal_binary.sh
@@ -9,7 +9,7 @@ readonly SCRIPT_DIR="$(dirname "$0")"
 readonly ARM=arm64
 readonly X86=x86_64
 
-NATIVE_LIBRARIES=${SCRIPT_DIR}"/../../out/host/darwin-x86/lib64"
+NATIVE_LIBRARIES=${DIST_DIR}"/layoutlib_native/darwin"
 
 # Find lipo command used to create and manipulate universal binaries
 LIPO=$(/usr/bin/xcrun --find lipo)
diff --git a/validator/src/ResourceConverter.java b/validator/src/ResourceConverter.java
index 839f1919d8..93b741ab2d 100644
--- a/validator/src/ResourceConverter.java
+++ b/validator/src/ResourceConverter.java
@@ -22,6 +22,7 @@ import org.w3c.dom.NodeList;
 
 import java.io.File;
 import java.io.FileWriter;
+import java.nio.charset.StandardCharsets;
 import java.util.LinkedHashMap;
 import java.util.Map;
 import java.util.Map.Entry;
@@ -49,8 +50,7 @@ public class ResourceConverter {
     private static void writeStrings(Map<String, String> map, String outputPath) throws Exception {
         File output = new File(outputPath);
         output.createNewFile();
-        FileWriter writer = new FileWriter(output);
-        try {
+        try (FileWriter writer = new FileWriter(output, StandardCharsets.UTF_8)) {
             writer.write(getCopyRight());
             writer.write("\n");
             for (Entry<String, String> entry : map.entrySet()) {
@@ -58,8 +58,6 @@ public class ResourceConverter {
                 String value = entry.getValue();
                 writer.write(name + " = " + value + "\n");
             }
-        } finally {
-            writer.close();
         }
     }
 
@@ -92,18 +90,18 @@ public class ResourceConverter {
 
             StringBuilder valueBuilder = new StringBuilder();
             try {
-                /**
-                 * This is a very hacky way to bypass "ns1:g" tag in android's .xml.
-                 * Ideally we'll read the tag from the parent and apply it here, but it being the
-                 * deep node list I'm not currently sure how to parse it safely. Might need to look
-                 * into IntelliJ PSI tree we have in Studio. But I didn't want to add unnecessary
-                 * deps to LayoutLib.
-                 *
-                 * It also means resource namespaces are rendered useless after conversion.
+                /*
+                  This is a very hacky way to bypass "ns1:g" tag in android's .xml.
+                  Ideally we'll read the tag from the parent and apply it here, but it being the
+                  deep node list I'm not currently sure how to parse it safely. Might need to look
+                  into IntelliJ PSI tree we have in Studio. But I didn't want to add unnecessary
+                  deps to LayoutLib.
+
+                  It also means resource namespaces are rendered useless after conversion.
                  */
                 for (int j = 0; j < node.getChildNodes().getLength(); j++) {
                     Node child = node.getChildNodes().item(j);
-                    String toAdd = null;
+                    String toAdd;
                     if ("ns1:g".equals(child.getNodeName())) {
                         toAdd = child.getFirstChild().getNodeValue();
                     } else if ("xliff:g".equals(child.getNodeName())) {
@@ -126,15 +124,22 @@ public class ResourceConverter {
     }
 
     private static String getCopyRight() {
-        return "\n" + "#\n" + "# Copyright (C) 2020 The Android Open Source Project\n" + "#\n" +
-                "# Licensed under the Apache License, Version 2.0 (the \"License\");\n" +
-                "# you may not use this file except in compliance with the License.\n" +
-                "# You may obtain a copy of the License at\n" + "#\n" +
-                "#      http://www.apache.org/licenses/LICENSE-2.0\n" + "#\n" +
-                "# Unless required by applicable law or agreed to in writing, software\n" +
-                "# distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
-                "# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
-                "# See the License for the specific language governing permissions and\n" +
-                "# limitations under the License.\n" + "#";
+        return """
+
+                #
+                # Copyright (C) 2020 The Android Open Source Project
+                #
+                # Licensed under the Apache License, Version 2.0 (the "License");
+                # you may not use this file except in compliance with the License.
+                # You may obtain a copy of the License at
+                #
+                #      http://www.apache.org/licenses/LICENSE-2.0
+                #
+                # Unless required by applicable law or agreed to in writing, software
+                # distributed under the License is distributed on an "AS IS" BASIS,
+                # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+                # See the License for the specific language governing permissions and
+                # limitations under the License.
+                #""";
     }
 }
diff --git a/validator/src/com/android/tools/idea/validator/AtfBufferedImage.java b/validator/src/com/android/tools/idea/validator/AtfBufferedImage.java
index c5fc13fce0..3c5786c796 100644
--- a/validator/src/com/android/tools/idea/validator/AtfBufferedImage.java
+++ b/validator/src/com/android/tools/idea/validator/AtfBufferedImage.java
@@ -23,16 +23,12 @@ import com.android.tools.layoutlib.annotations.NotNull;
 import android.annotation.NonNull;
 
 import java.awt.image.BufferedImage;
-import java.awt.image.DataBufferInt;
-import java.awt.image.WritableRaster;
 import java.io.File;
 import java.io.IOException;
 
 import com.google.android.apps.common.testing.accessibility.framework.utils.contrast.Image;
 import javax.imageio.ImageIO;
 
-import static java.awt.image.BufferedImage.TYPE_INT_ARGB;
-
 /**
  * Image implementation to be used in Accessibility Test Framework.
  */
@@ -69,7 +65,6 @@ public class AtfBufferedImage implements Image {
             (int) (image.getHeight() * 1.0f / scaleY),
             scaleX,
             scaleY);
-        assert(image.getType() == TYPE_INT_ARGB);
 
         // FOR DEBUGGING ONLY
         if (LayoutValidator.shouldSaveCroppedImages()) {
@@ -128,18 +123,8 @@ public class AtfBufferedImage implements Image {
             return new int[0];
         }
 
-        BufferedImage cropped = mImage.getSubimage(
-                scaledLeft, scaledTop, scaledWidth, scaledHeight);
-        WritableRaster raster =
-                cropped.copyData(cropped.getRaster().createCompatibleWritableRaster());
-        int[] toReturn = ((DataBufferInt) raster.getDataBuffer()).getData();
-        mMetric.mImageMemoryBytes += toReturn.length * 4;
-
-        if (LayoutValidator.shouldSaveCroppedImages()) {
-            saveImage(cropped);
-        }
-
-        return toReturn;
+        return mImage.getRGB(scaledLeft, scaledTop, scaledWidth, scaledHeight, null, 0,
+                scaledWidth);
     }
 
     // FOR DEBUGGING ONLY
diff --git a/validator/src/com/android/tools/idea/validator/ValidatorData.java b/validator/src/com/android/tools/idea/validator/ValidatorData.java
index 167cab1789..bd519df05f 100644
--- a/validator/src/com/android/tools/idea/validator/ValidatorData.java
+++ b/validator/src/com/android/tools/idea/validator/ValidatorData.java
@@ -62,7 +62,7 @@ public class ValidatorData {
          * List of checks to use for the scan. If empty we use the default set
          * defined by {@link AccessibilityCheckPreset.LATEST}
          */
-        @NotNull public final HashSet<AccessibilityHierarchyCheck> mChecks = new HashSet();
+        @NotNull public final HashSet<AccessibilityHierarchyCheck> mChecks = new HashSet<>();
 
         public Policy(@NotNull EnumSet<Type> types, @NotNull EnumSet<Level> levels) {
             mTypes = types;
@@ -73,6 +73,7 @@ public class ValidatorData {
     /**
      * Issue describing the layout problem.
      */
+    @SuppressWarnings("WeakerAccess") // Public fields are accessed in Studio
     public static class Issue {
         @NotNull
         public final String mCategory;
@@ -181,6 +182,7 @@ public class ValidatorData {
     /**
      * Represents a view attribute which contains a namespace and an attribute name.
      */
+    @SuppressWarnings("WeakerAccess") // Public fields are accessed in Studio
     public static class ViewAttribute {
         /** The namespace used in XML files for this view attribute. */
         @NotNull public final String mNamespaceUri;
@@ -202,7 +204,7 @@ public class ValidatorData {
     /**
      * Suggested fix to the user or to the studio.
      */
-    public static interface Fix {
+    public interface Fix {
         /**
          * @return a human-readable description for this fix.
          */
@@ -221,6 +223,7 @@ public class ValidatorData {
      *       to an empty string.
      * </ul>
      */
+    @SuppressWarnings("WeakerAccess") // Public fields are accessed in Studio
     public static class SetViewAttributeFix implements Fix {
         /** The {@link ViewAttribute} suggested to be changed. */
         @NotNull public final ViewAttribute mViewAttribute;
@@ -246,6 +249,7 @@ public class ValidatorData {
     /**
      * Suggest removing a {@link ViewAttribute} to fix a specific {@link Issue}.
      */
+    @SuppressWarnings("WeakerAccess") // Public fields are accessed in Studio
     public static class RemoveViewAttributeFix implements Fix {
         /** The {@link ViewAttribute} suggested to be removed. */
         @NotNull public final ViewAttribute mViewAttribute;
diff --git a/validator/src/com/android/tools/idea/validator/ValidatorResult.java b/validator/src/com/android/tools/idea/validator/ValidatorResult.java
index 9d708b5bdf..48d342db63 100644
--- a/validator/src/com/android/tools/idea/validator/ValidatorResult.java
+++ b/validator/src/com/android/tools/idea/validator/ValidatorResult.java
@@ -130,7 +130,7 @@ public class ValidatorResult {
         public long mImageMemoryBytes = 0;
 
         /** Debugging purpose only. Use it with {@link LayoutValidator#shouldSaveCroppedImages()} */
-        public List<ImageSize> mImageSizes = new ArrayList<>();
+        public final List<ImageSize> mImageSizes = new ArrayList<>();
 
         private long mHierarchyCreationTimeStart;
 
diff --git a/validator/src/com/android/tools/idea/validator/ValidatorUtil.java b/validator/src/com/android/tools/idea/validator/ValidatorUtil.java
index fa2862d191..103cd4cc87 100644
--- a/validator/src/com/android/tools/idea/validator/ValidatorUtil.java
+++ b/validator/src/com/android/tools/idea/validator/ValidatorUtil.java
@@ -70,17 +70,17 @@ import com.google.common.collect.ImmutableSet;
 public class ValidatorUtil {
 
     static {
-        /**
-         * Overriding default ResourceBundle ATF uses. ATF would use generic Java resources
-         * instead of Android's .xml.
-         *
-         * By default ATF generates ResourceBundle to support Android specific env/ classloader,
-         * which is quite different from Layoutlib, which supports multiple classloader depending
-         * on env (testing vs in studio).
-         *
-         * To support ATF in Layoutlib, easiest way is to convert resources from Android xml to
-         * generic Java resources (strings.properties), and have the default ResourceBundle ATF
-         * uses be redirected.
+        /*
+          Overriding default ResourceBundle ATF uses. ATF would use generic Java resources
+          instead of Android's .xml.
+
+          By default ATF generates ResourceBundle to support Android specific env/ classloader,
+          which is quite different from Layoutlib, which supports multiple classloader depending
+          on env (testing vs in studio).
+
+          To support ATF in Layoutlib, easiest way is to convert resources from Android xml to
+          generic Java resources (strings.properties), and have the default ResourceBundle ATF
+          uses be redirected.
          */
         StringManager.setResourceBundleProvider(locale -> ResourceBundle.getBundle("strings"));
     }
@@ -278,8 +278,8 @@ public class ValidatorUtil {
     /**
      * @return the list filtered by the source class name. Useful for testing and debugging.
      */
-    public static List<Issue> filterByTypes(
-            List<ValidatorData.Issue> results, EnumSet<Type> types) {
+    private static List<Issue> filterByTypes(List<ValidatorData.Issue> results,
+            EnumSet<Type> types) {
         return results.stream().filter(
                 issue -> types.contains(issue.mType)).collect(Collectors.toList());
     }
@@ -304,19 +304,13 @@ public class ValidatorUtil {
     /** Convert {@link AccessibilityCheckResultType} to {@link ValidatorData.Level} */
     @NotNull
     private static ValidatorData.Level convertLevel(@NotNull AccessibilityCheckResultType type) {
-        switch (type) {
-            case ERROR:
-                return Level.ERROR;
-            case WARNING:
-                return Level.WARNING;
-            case INFO:
-                return Level.INFO;
+        return switch (type) {
+            case ERROR -> Level.ERROR;
+            case WARNING -> Level.WARNING;
+            case INFO -> Level.INFO;
             // TODO: Maybe useful later?
-            case SUPPRESSED:
-            case NOT_RUN:
-            default:
-                return Level.VERBOSE;
-        }
+            default -> Level.VERBOSE;
+        };
     }
 
     /**
@@ -346,26 +340,18 @@ public class ValidatorUtil {
     /** Convert {@link FixSuggestion} to {@link ValidatorData.Fix} */
     @Nullable
     private static ValidatorData.Fix convertFix(@NotNull FixSuggestion fixSuggestion) {
-        if (fixSuggestion instanceof CompoundFixSuggestions) {
-            CompoundFixSuggestions compoundFixSuggestions = (CompoundFixSuggestions)fixSuggestion;
-            List<ValidatorData.Fix> fixes =
-                    compoundFixSuggestions
-                            .getFixSuggestions()
-                            .stream()
-                            .map(ValidatorUtil::convertFix)
-                            .collect(Collectors.toList());
-            return new CompoundFix(
-                    fixes,
-                    compoundFixSuggestions.getDescription(Locale.ENGLISH));
-        } else if (fixSuggestion instanceof RemoveViewAttributeFixSuggestion) {
-            RemoveViewAttributeFixSuggestion removeViewAttributeFix =
-                    (RemoveViewAttributeFixSuggestion)fixSuggestion;
+        if (fixSuggestion instanceof CompoundFixSuggestions compoundFixSuggestions) {
+            List<ValidatorData.Fix> fixes = compoundFixSuggestions
+                    .getFixSuggestions()
+                    .stream()
+                    .map(ValidatorUtil::convertFix)
+                    .collect(Collectors.toList());
+            return new CompoundFix(fixes, compoundFixSuggestions.getDescription(Locale.ENGLISH));
+        } else if (fixSuggestion instanceof RemoveViewAttributeFixSuggestion removeViewAttributeFix) {
             return new RemoveViewAttributeFix(
                     convertViewAttribute(removeViewAttributeFix.getViewAttribute()),
                     removeViewAttributeFix.getDescription(Locale.ENGLISH));
-        } else if (fixSuggestion instanceof SetViewAttributeFixSuggestion) {
-            SetViewAttributeFixSuggestion setViewAttributeFixSuggestion =
-                    (SetViewAttributeFixSuggestion)fixSuggestion;
+        } else if (fixSuggestion instanceof SetViewAttributeFixSuggestion setViewAttributeFixSuggestion) {
             return new SetViewAttributeFix(
                     convertViewAttribute(setViewAttributeFixSuggestion.getViewAttribute()),
                     setViewAttributeFixSuggestion.getSuggestedValue(),
diff --git a/validator/validator.iml b/validator/validator.iml
index 094889e942..7692a9ec25 100644
--- a/validator/validator.iml
+++ b/validator/validator.iml
@@ -12,8 +12,8 @@
     <orderEntry type="library" name="layoutlib_api-prebuilt" level="project" />
     <orderEntry type="module" module-name="common" />
     <orderEntry type="library" name="guava" level="project" />
-    <orderEntry type="library" scope="TEST" name="hamcrest" level="project" />
     <orderEntry type="library" name="jsoup" level="project" />
     <orderEntry type="library" name="libprotobuf-java-lite" level="project" />
+    <orderEntry type="library" scope="TEST" name="hamcrest" level="project" />
   </component>
 </module>
\ No newline at end of file
```

