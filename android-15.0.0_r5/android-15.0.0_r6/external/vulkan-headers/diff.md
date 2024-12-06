```diff
diff --git a/Android.bp b/Android.bp
index 00feea7..cfb8cce 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,6 +55,13 @@ ndk_headers {
         "include/**/*.h",
     ],
     license: "LICENSES/Apache-2.0.txt",
+    // The Vulkan headers aren't self-contained. vulkan_fuchsia.h, at the very
+    // least, requires other headers to be included first.
+    //
+    // Low risk to disable verification here since upstream also cares about
+    // C-compatibility. Can remove if upstream ever decides they want to
+    // guarantee self-contained headers as well.
+    skip_verification: true,
 }
 
 // This module makes Vulkan headers available to other modules without
@@ -64,6 +71,7 @@ ndk_headers {
 cc_library_headers {
     name: "vulkan_headers",
     export_include_dirs: ["include"],
+    native_bridge_supported: true, // Used for verification in Berberis.
     host_supported: true,
     vendor_available: true,
     sdk_version: "24",
diff --git a/OWNERS b/OWNERS
index 07144e7..a335a5b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -7,8 +7,6 @@ cnorthrop@google.com
 geofflang@google.com
 ianelliott@google.com
 jessehall@google.com
-lfy@google.com
 natsu@google.com
 romanl@google.com
-vantablack@google.com
 yuxinhu@google.com
diff --git a/registry/vk.xml b/registry/vk.xml
index fa39728..3898d49 100644
--- a/registry/vk.xml
+++ b/registry/vk.xml
@@ -3810,6 +3810,19 @@ typedef void* <name>MTLSharedEvent_id</name>;
             <member optional="true">const <type>void</type>* <name>pNext</name></member>
             <member><type>VkBool32</type> <name>sharedImage</name></member>
         </type>
+        <type category="struct" name="VkGrallocUsageInfoANDROID">
+            <member values="VK_STRUCTURE_TYPE_GRALLOC_USAGE_INFO_ANDROID"><type>VkStructureType</type> <name>sType</name></member>
+            <member optional="true">const <type>void</type>* <name>pNext</name></member>
+            <member><type>VkFormat</type> <name>format</name></member>
+            <member><type>VkImageUsageFlags</type> <name>imageUsage</name></member>
+        </type>
+        <type category="struct" name="VkGrallocUsageInfo2ANDROID">
+            <member values="VK_STRUCTURE_TYPE_GRALLOC_USAGE_INFO_2_ANDROID"><type>VkStructureType</type> <name>sType</name></member>
+            <member optional="true">const <type>void</type>* <name>pNext</name></member>
+            <member><type>VkFormat</type> <name>format</name></member>
+            <member><type>VkImageUsageFlags</type> <name>imageUsage</name></member>
+            <member><type>VkSwapchainImageUsageFlagsANDROID</type> <name>swapchainImageUsage</name></member>
+        </type>
         <type category="struct" name="VkShaderResourceUsageAMD" returnedonly="true">
             <member><type>uint32_t</type> <name>numUsedVgprs</name></member>
             <member><type>uint32_t</type> <name>numUsedSgprs</name></member>
@@ -13199,6 +13212,18 @@ typedef void* <name>MTLSharedEvent_id</name>;
             <param><type>uint64_t</type>* <name>grallocConsumerUsage</name></param>
             <param><type>uint64_t</type>* <name>grallocProducerUsage</name></param>
         </command>
+        <command>
+            <proto><type>VkResult</type> <name>vkGetSwapchainGrallocUsage3ANDROID</name></proto>
+            <param><type>VkDevice</type> <name>device</name></param>
+            <param>const <type>VkGrallocUsageInfoANDROID</type>* <name>grallocUsageInfo</name></param>
+            <param><type>uint64_t</type>* <name>grallocUsage</name></param>
+        </command>
+        <command>
+            <proto><type>VkResult</type> <name>vkGetSwapchainGrallocUsage4ANDROID</name></proto>
+            <param><type>VkDevice</type> <name>device</name></param>
+            <param>const <type>VkGrallocUsageInfo2ANDROID</type>* <name>grallocUsageInfo</name></param>
+            <param><type>uint64_t</type>* <name>grallocUsage</name></param>
+        </command>
         <command>
             <proto><type>VkResult</type> <name>vkAcquireImageANDROID</name></proto>
             <param><type>VkDevice</type> <name>device</name></param>
@@ -16852,16 +16877,22 @@ typedef void* <name>MTLSharedEvent_id</name>;
                 <enum offset="0" extends="VkStructureType"                      name="VK_STRUCTURE_TYPE_NATIVE_BUFFER_ANDROID"/>
                 <enum offset="1" extends="VkStructureType"                      name="VK_STRUCTURE_TYPE_SWAPCHAIN_IMAGE_CREATE_INFO_ANDROID"/>
                 <enum offset="2" extends="VkStructureType"                      name="VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENTATION_PROPERTIES_ANDROID"/>
+                <enum offset="3" extends="VkStructureType"                      name="VK_STRUCTURE_TYPE_GRALLOC_USAGE_INFO_ANDROID"/>
+                <enum offset="4" extends="VkStructureType"                      name="VK_STRUCTURE_TYPE_GRALLOC_USAGE_INFO_2_ANDROID"/>
                 <type name="VkNativeBufferANDROID"/>
                 <type name="VkSwapchainImageCreateInfoANDROID"/>
                 <type name="VkPhysicalDevicePresentationPropertiesANDROID"/>
                 <type name="VkNativeBufferUsage2ANDROID"/>
                 <type name="VkSwapchainImageUsageFlagBitsANDROID"/>
                 <type name="VkSwapchainImageUsageFlagsANDROID"/>
+                <type name="VkGrallocUsageInfoANDROID"/>
+                <type name="VkGrallocUsageInfo2ANDROID"/>
                 <command name="vkGetSwapchainGrallocUsageANDROID"/>
                 <command name="vkAcquireImageANDROID"/>
                 <command name="vkQueueSignalReleaseImageANDROID"/>
                 <command name="vkGetSwapchainGrallocUsage2ANDROID"/>
+                <command name="vkGetSwapchainGrallocUsage3ANDROID"/>
+                <command name="vkGetSwapchainGrallocUsage4ANDROID"/>
             </require>
         </extension>
         <extension name="VK_EXT_debug_report" number="12" type="instance" author="GOOGLE" contact="Courtney Goeltzenleuchter @courtney-g" specialuse="debugging" supported="vulkan" deprecatedby="VK_EXT_debug_utils">
```

