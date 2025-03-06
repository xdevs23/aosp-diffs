```diff
diff --git a/core/fpdfapi/edit/cpdf_pagecontentgenerator.cpp b/core/fpdfapi/edit/cpdf_pagecontentgenerator.cpp
index be87afaea..586162c90 100644
--- a/core/fpdfapi/edit/cpdf_pagecontentgenerator.cpp
+++ b/core/fpdfapi/edit/cpdf_pagecontentgenerator.cpp
@@ -609,7 +609,7 @@ void CPDF_PageContentGenerator::ProcessGraphics(fxcrt::ostringstream* buf,
     }
     m_pDocument->AddIndirectObject(gsDict);
     name = RealizeResource(std::move(gsDict), "ExtGState");
-    pPageObj->SetGraphicsResourceNames({name});
+    pPageObj->m_GeneralState.SetGraphicsResourceNames({name});
     m_pObjHolder->GraphicsMapInsert(graphD, name);
   }
   *buf << "/" << PDF_NameEncode(name) << " gs ";
diff --git a/core/fpdfapi/page/cpdf_allstates.cpp b/core/fpdfapi/page/cpdf_allstates.cpp
index 996b3f795..e26c93165 100644
--- a/core/fpdfapi/page/cpdf_allstates.cpp
+++ b/core/fpdfapi/page/cpdf_allstates.cpp
@@ -25,7 +25,6 @@ CPDF_AllStates::~CPDF_AllStates() = default;
 
 void CPDF_AllStates::Copy(const CPDF_AllStates& src) {
   CopyStates(src);
-  m_GraphicsResourceNames = src.m_GraphicsResourceNames;
   m_TextMatrix = src.m_TextMatrix;
   m_ParentMatrix = src.m_ParentMatrix;
   m_CTM = src.m_CTM;
diff --git a/core/fpdfapi/page/cpdf_allstates.h b/core/fpdfapi/page/cpdf_allstates.h
index 3d4d9a37c..d7bbf29a3 100644
--- a/core/fpdfapi/page/cpdf_allstates.h
+++ b/core/fpdfapi/page/cpdf_allstates.h
@@ -7,10 +7,7 @@
 #ifndef CORE_FPDFAPI_PAGE_CPDF_ALLSTATES_H_
 #define CORE_FPDFAPI_PAGE_CPDF_ALLSTATES_H_
 
-#include <vector>
-
 #include "core/fpdfapi/page/cpdf_graphicstates.h"
-#include "core/fxcrt/bytestring.h"
 #include "core/fxcrt/fx_coordinates.h"
 
 class CPDF_Array;
@@ -27,7 +24,7 @@ class CPDF_AllStates final : public CPDF_GraphicStates {
                     CPDF_StreamContentParser* pParser);
   void SetLineDash(const CPDF_Array* pArray, float phase, float scale);
 
-  std::vector<ByteString> m_GraphicsResourceNames;
+
   CFX_Matrix m_TextMatrix;
   CFX_Matrix m_CTM;
   CFX_Matrix m_ParentMatrix;
diff --git a/core/fpdfapi/page/cpdf_generalstate.cpp b/core/fpdfapi/page/cpdf_generalstate.cpp
index 8ebefa3a3..10e4c43f4 100644
--- a/core/fpdfapi/page/cpdf_generalstate.cpp
+++ b/core/fpdfapi/page/cpdf_generalstate.cpp
@@ -263,6 +263,24 @@ CFX_Matrix* CPDF_GeneralState::GetMutableMatrix() {
   return &m_Ref.GetPrivateCopy()->m_Matrix;
 }
 
+void CPDF_GeneralState::SetGraphicsResourceNames(
+  std::vector<ByteString> names) {
+  m_Ref.GetPrivateCopy()->m_GraphicsResourceNames = std::move(names);
+}
+
+void CPDF_GeneralState::AppendGraphicsResourceName(ByteString name) {
+  m_Ref.GetPrivateCopy()->m_GraphicsResourceNames.push_back(std::move(name));
+}
+
+pdfium::span<const ByteString> CPDF_GeneralState::GetGraphicsResourceNames()
+  const {
+  const StateData* data = m_Ref.GetObject();
+  if (!data) {
+    return {};
+  }
+  return data->m_GraphicsResourceNames;
+}
+
 CPDF_GeneralState::StateData::StateData() = default;
 
 CPDF_GeneralState::StateData::StateData(const StateData& that)
diff --git a/core/fpdfapi/page/cpdf_generalstate.h b/core/fpdfapi/page/cpdf_generalstate.h
index 2fb228531..a04a0aff2 100644
--- a/core/fpdfapi/page/cpdf_generalstate.h
+++ b/core/fpdfapi/page/cpdf_generalstate.h
@@ -7,12 +7,15 @@
 #ifndef CORE_FPDFAPI_PAGE_CPDF_GENERALSTATE_H_
 #define CORE_FPDFAPI_PAGE_CPDF_GENERALSTATE_H_
 
+#include <vector>
+
 #include "constants/transparency.h"
 #include "core/fxcrt/bytestring.h"
 #include "core/fxcrt/fx_coordinates.h"
 #include "core/fxcrt/retain_ptr.h"
 #include "core/fxcrt/shared_copy_on_write.h"
 #include "core/fxge/dib/fx_dib.h"
+#include "third_party/base/containers/span.h"
 
 class CPDF_Dictionary;
 class CPDF_Object;
@@ -79,6 +82,10 @@ class CPDF_GeneralState {
   void SetMatrix(const CFX_Matrix& matrix);
   CFX_Matrix* GetMutableMatrix();
 
+  void SetGraphicsResourceNames(std::vector<ByteString> names);
+  void AppendGraphicsResourceName(ByteString name);
+  pdfium::span<const ByteString> GetGraphicsResourceNames() const;
+
  private:
   class StateData final : public Retainable {
    public:
@@ -107,6 +114,8 @@ class CPDF_GeneralState {
     RetainPtr<const CPDF_Object> m_pHT;
     float m_Flatness = 1.0f;
     float m_Smoothness = 0.0f;
+    // The resource names of the graphics states that apply to this object.
+    std::vector<ByteString> m_GraphicsResourceNames;
 
    private:
     StateData();
diff --git a/core/fpdfapi/page/cpdf_pageobject.cpp b/core/fpdfapi/page/cpdf_pageobject.cpp
index a7b2156d5..03c20d14d 100644
--- a/core/fpdfapi/page/cpdf_pageobject.cpp
+++ b/core/fpdfapi/page/cpdf_pageobject.cpp
@@ -75,9 +75,9 @@ const CPDF_FormObject* CPDF_PageObject::AsForm() const {
   return nullptr;
 }
 
-void CPDF_PageObject::SetGraphicsResourceNames(
-    std::vector<ByteString> resource_names) {
-  m_GraphicsResourceNames = std::move(resource_names);
+pdfium::span<const ByteString> CPDF_PageObject::GetGraphicsResourceNames()
+  const {
+  return m_GeneralState.GetGraphicsResourceNames();
 }
 
 void CPDF_PageObject::CopyData(const CPDF_PageObject* pSrc) {
diff --git a/core/fpdfapi/page/cpdf_pageobject.h b/core/fpdfapi/page/cpdf_pageobject.h
index ccdbbaff4..7eaaf41cf 100644
--- a/core/fpdfapi/page/cpdf_pageobject.h
+++ b/core/fpdfapi/page/cpdf_pageobject.h
@@ -9,12 +9,12 @@
 
 #include <stdint.h>
 
-#include <vector>
 
 #include "core/fpdfapi/page/cpdf_contentmarks.h"
 #include "core/fpdfapi/page/cpdf_graphicstates.h"
 #include "core/fxcrt/bytestring.h"
 #include "core/fxcrt/fx_coordinates.h"
+#include "third_party/base/containers/span.h"
 
 class CPDF_FormObject;
 class CPDF_ImageObject;
@@ -96,10 +96,7 @@ class CPDF_PageObject : public CPDF_GraphicStates {
     m_ResourceName = resource_name;
   }
 
-  const std::vector<ByteString>& GetGraphicsResourceNames() const {
-    return m_GraphicsResourceNames;
-  }
-  void SetGraphicsResourceNames(std::vector<ByteString> resource_names);
+  pdfium::span<const ByteString> GetGraphicsResourceNames() const;
 
  protected:
   void CopyData(const CPDF_PageObject* pSrcObject);
@@ -112,9 +109,6 @@ class CPDF_PageObject : public CPDF_GraphicStates {
   int32_t m_ContentStream;
   // The resource name for this object.
   ByteString m_ResourceName;
-  // Like `m_ResourceName` but for graphics. Though unlike the resource name,
-  // multiple graphics states can apply at once.
-  std::vector<ByteString> m_GraphicsResourceNames;
 };
 
 #endif  // CORE_FPDFAPI_PAGE_CPDF_PAGEOBJECT_H_
diff --git a/core/fpdfapi/page/cpdf_streamcontentparser.cpp b/core/fpdfapi/page/cpdf_streamcontentparser.cpp
index cae9d7201..6c559af99 100644
--- a/core/fpdfapi/page/cpdf_streamcontentparser.cpp
+++ b/core/fpdfapi/page/cpdf_streamcontentparser.cpp
@@ -429,7 +429,6 @@ void CPDF_StreamContentParser::SetGraphicStates(CPDF_PageObject* pObj,
   if (bText) {
     pObj->m_TextState = m_pCurStates->m_TextState;
   }
-  pObj->SetGraphicsResourceNames(m_pCurStates->m_GraphicsResourceNames);
 }
 
 // static
@@ -790,7 +789,6 @@ void CPDF_StreamContentParser::AddForm(RetainPtr<CPDF_Stream> pStream,
   auto pFormObj = std::make_unique<CPDF_FormObject>(GetCurrentStreamIndex(),
                                                     std::move(form), matrix);
   pFormObj->SetResourceName(name);
-  pFormObj->SetGraphicsResourceNames(m_pCurStates->m_GraphicsResourceNames);
   if (!m_pObjectHolder->BackgroundAlphaNeeded() &&
       pFormObj->form()->BackgroundAlphaNeeded()) {
     m_pObjectHolder->SetBackgroundAlphaNeeded(true);
@@ -916,7 +914,7 @@ void CPDF_StreamContentParser::Handle_SetExtendGraphState() {
     return;
 
   CHECK(!name.IsEmpty());
-  m_pCurStates->m_GraphicsResourceNames.push_back(std::move(name));
+  m_pCurStates->m_GeneralState.AppendGraphicsResourceName(std::move(name));
   m_pCurStates->ProcessExtGS(pGS.Get(), this);
 }
 
```

