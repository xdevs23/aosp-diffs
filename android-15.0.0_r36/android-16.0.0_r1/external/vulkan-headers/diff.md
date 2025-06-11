```diff
diff --git a/OWNERS b/OWNERS
index a335a5b..4332dc2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -10,3 +10,4 @@ jessehall@google.com
 natsu@google.com
 romanl@google.com
 yuxinhu@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/include/vulkan/vulkan_core.h b/include/vulkan/vulkan_core.h
index c72f85d..3057386 100644
--- a/include/vulkan/vulkan_core.h
+++ b/include/vulkan/vulkan_core.h
@@ -7843,6 +7843,7 @@ typedef struct VkPhysicalDeviceVulkan14Features {
     VkBool32           pipelineProtectedAccess;
     VkBool32           pipelineRobustness;
     VkBool32           hostImageCopy;
+    VkBool32           pushDescriptor;
 } VkPhysicalDeviceVulkan14Features;
 
 typedef struct VkPhysicalDeviceVulkan14Properties {
diff --git a/include/vulkan/vulkan_hash.hpp b/include/vulkan/vulkan_hash.hpp
index 3771f2f..cb40b3f 100644
--- a/include/vulkan/vulkan_hash.hpp
+++ b/include/vulkan/vulkan_hash.hpp
@@ -12699,6 +12699,7 @@ namespace std
       VULKAN_HPP_HASH_COMBINE( seed, physicalDeviceVulkan14Features.pipelineProtectedAccess );
       VULKAN_HPP_HASH_COMBINE( seed, physicalDeviceVulkan14Features.pipelineRobustness );
       VULKAN_HPP_HASH_COMBINE( seed, physicalDeviceVulkan14Features.hostImageCopy );
+      VULKAN_HPP_HASH_COMBINE( seed, physicalDeviceVulkan14Features.pushDescriptor );
       return seed;
     }
   };
diff --git a/include/vulkan/vulkan_structs.hpp b/include/vulkan/vulkan_structs.hpp
index 9cd92bc..5f68368 100644
--- a/include/vulkan/vulkan_structs.hpp
+++ b/include/vulkan/vulkan_structs.hpp
@@ -92555,6 +92555,7 @@ namespace VULKAN_HPP_NAMESPACE
                                                          VULKAN_HPP_NAMESPACE::Bool32 pipelineProtectedAccess_                = {},
                                                          VULKAN_HPP_NAMESPACE::Bool32 pipelineRobustness_                     = {},
                                                          VULKAN_HPP_NAMESPACE::Bool32 hostImageCopy_                          = {},
+                                                         VULKAN_HPP_NAMESPACE::Bool32 pushDescriptor_                         = {},
                                                          void *                       pNext_                                  = nullptr ) VULKAN_HPP_NOEXCEPT
       : pNext{ pNext_ }
       , globalPriorityQuery{ globalPriorityQuery_ }
@@ -92577,6 +92578,7 @@ namespace VULKAN_HPP_NAMESPACE
       , pipelineProtectedAccess{ pipelineProtectedAccess_ }
       , pipelineRobustness{ pipelineRobustness_ }
       , hostImageCopy{ hostImageCopy_ }
+      , pushDescriptor{ pushDescriptor_ }
     {
     }
 
@@ -92729,6 +92731,12 @@ namespace VULKAN_HPP_NAMESPACE
       hostImageCopy = hostImageCopy_;
       return *this;
     }
+
+    VULKAN_HPP_CONSTEXPR_14 PhysicalDeviceVulkan14Features & setPushDescriptor( VULKAN_HPP_NAMESPACE::Bool32 pushDescriptor_ ) VULKAN_HPP_NOEXCEPT
+    {
+      pushDescriptor = pushDescriptor_;
+      return *this;
+    }
 #endif /*VULKAN_HPP_NO_STRUCT_SETTERS*/
 
     operator VkPhysicalDeviceVulkan14Features const &() const VULKAN_HPP_NOEXCEPT
@@ -92766,6 +92774,7 @@ namespace VULKAN_HPP_NAMESPACE
                VULKAN_HPP_NAMESPACE::Bool32 const &,
                VULKAN_HPP_NAMESPACE::Bool32 const &,
                VULKAN_HPP_NAMESPACE::Bool32 const &,
+               VULKAN_HPP_NAMESPACE::Bool32 const &,
                VULKAN_HPP_NAMESPACE::Bool32 const &>
 #  endif
       reflect() const VULKAN_HPP_NOEXCEPT
@@ -92791,7 +92800,8 @@ namespace VULKAN_HPP_NAMESPACE
                        maintenance6,
                        pipelineProtectedAccess,
                        pipelineRobustness,
-                       hostImageCopy );
+                       hostImageCopy,
+                       pushDescriptor );
     }
 #endif
 
@@ -92812,7 +92822,7 @@ namespace VULKAN_HPP_NAMESPACE
              ( vertexAttributeInstanceRateZeroDivisor == rhs.vertexAttributeInstanceRateZeroDivisor ) && ( indexTypeUint8 == rhs.indexTypeUint8 ) &&
              ( dynamicRenderingLocalRead == rhs.dynamicRenderingLocalRead ) && ( maintenance5 == rhs.maintenance5 ) && ( maintenance6 == rhs.maintenance6 ) &&
              ( pipelineProtectedAccess == rhs.pipelineProtectedAccess ) && ( pipelineRobustness == rhs.pipelineRobustness ) &&
-             ( hostImageCopy == rhs.hostImageCopy );
+             ( hostImageCopy == rhs.hostImageCopy ) && ( pushDescriptor == rhs.pushDescriptor );
 #  endif
     }
 
@@ -92845,6 +92855,7 @@ namespace VULKAN_HPP_NAMESPACE
     VULKAN_HPP_NAMESPACE::Bool32        pipelineProtectedAccess                = {};
     VULKAN_HPP_NAMESPACE::Bool32        pipelineRobustness                     = {};
     VULKAN_HPP_NAMESPACE::Bool32        hostImageCopy                          = {};
+    VULKAN_HPP_NAMESPACE::Bool32        pushDescriptor                         = {};
   };
 
   template <>
diff --git a/registry/vk.xml b/registry/vk.xml
index 495e9b7..b05a476 100755
--- a/registry/vk.xml
+++ b/registry/vk.xml
@@ -5806,6 +5806,7 @@ typedef void* <name>MTLSharedEvent_id</name>;
             <member><type>VkBool32</type>                         <name>pipelineProtectedAccess</name></member>
             <member><type>VkBool32</type>                         <name>pipelineRobustness</name></member>
             <member><type>VkBool32</type>                         <name>hostImageCopy</name></member>
+            <member><type>VkBool32</type>                         <name>pushDescriptor</name></member>
         </type>
         <type category="struct" name="VkPhysicalDeviceVulkan14Properties" returnedonly="true" structextends="VkPhysicalDeviceProperties2">
             <member values="VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_4_PROPERTIES"><type>VkStructureType</type> <name>sType</name></member>
```

