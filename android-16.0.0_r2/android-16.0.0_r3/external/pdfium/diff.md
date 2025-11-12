```diff
diff --git a/Android.bp b/Android.bp
index 971bc6c4f..66a4ad015 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,6 +40,8 @@ license {
 
 cc_defaults {
     name: "pdfium-common",
+    // Upstream doesn't support C++23 yet: https://issues.chromium.org/issues/388068055
+    cpp_std: "gnu++20",
     cflags: [
         "-O3",
         "-fstrict-aliasing",
diff --git a/core/fpdfdoc/cpdf_generateap.cpp b/core/fpdfdoc/cpdf_generateap.cpp
index 66b767ab1..568fc2cb9 100644
--- a/core/fpdfdoc/cpdf_generateap.cpp
+++ b/core/fpdfdoc/cpdf_generateap.cpp
@@ -32,359 +32,595 @@
 #include "core/fpdfdoc/cpdf_color_utils.h"
 #include "core/fpdfdoc/cpdf_defaultappearance.h"
 #include "core/fpdfdoc/cpdf_formfield.h"
+#include "core/fpdfdoc/cpdf_interactiveform.h"
 #include "core/fpdfdoc/cpvt_fontmap.h"
 #include "core/fpdfdoc/cpvt_variabletext.h"
 #include "core/fpdfdoc/cpvt_word.h"
 #include "core/fxcrt/fx_string_wrappers.h"
+#include "core/fxcrt/notreached.h"
 #include "core/fxge/cfx_renderdevice.h"
 
 namespace {
 
+constexpr char kGSDictName[] = "GS";
+
 struct CPVT_Dash {
   CPVT_Dash(int32_t dash, int32_t gap, int32_t phase)
-      : nDash(dash), nGap(gap), nPhase(phase) {}
+      : dash(dash), gap(gap), phase(phase) {}
 
-  int32_t nDash;
-  int32_t nGap;
-  int32_t nPhase;
+  int32_t dash;
+  int32_t gap;
+  int32_t phase;
 };
 
 enum class PaintOperation { kStroke, kFill };
 
-ByteString GetPDFWordString(IPVT_FontMap* pFontMap,
-                            int32_t nFontIndex,
-                            uint16_t Word,
-                            uint16_t SubWord) {
-  if (SubWord > 0)
-    return ByteString::Format("%c", SubWord);
+ByteString GetPDFWordString(IPVT_FontMap* font_map,
+                            int32_t font_index,
+                            uint16_t word,
+                            uint16_t sub_word) {
+  if (sub_word > 0) {
+    return ByteString::Format("%c", sub_word);
+  }
 
-  if (!pFontMap)
+  if (!font_map) {
     return ByteString();
+  }
 
-  RetainPtr<CPDF_Font> pPDFFont = pFontMap->GetPDFFont(nFontIndex);
-  if (!pPDFFont)
+  RetainPtr<CPDF_Font> pdf_font = font_map->GetPDFFont(font_index);
+  if (!pdf_font) {
     return ByteString();
+  }
 
-  if (pPDFFont->GetBaseFontName() == "Symbol" ||
-      pPDFFont->GetBaseFontName() == "ZapfDingbats") {
-    return ByteString::Format("%c", Word);
+  if (pdf_font->GetBaseFontName() == "Symbol" ||
+      pdf_font->GetBaseFontName() == "ZapfDingbats") {
+    return ByteString::Format("%c", word);
   }
 
-  ByteString sWord;
-  uint32_t dwCharCode = pPDFFont->CharCodeFromUnicode(Word);
-  if (dwCharCode != CPDF_Font::kInvalidCharCode) {
-    pPDFFont->AppendChar(&sWord, dwCharCode);
+  ByteString word_string;
+  uint32_t char_code = pdf_font->CharCodeFromUnicode(word);
+  if (char_code != CPDF_Font::kInvalidCharCode) {
+    pdf_font->AppendChar(&word_string, char_code);
   }
-  return sWord;
+  return word_string;
 }
 
-ByteString GetWordRenderString(ByteStringView strWords) {
-  if (strWords.IsEmpty())
+ByteString GetWordRenderString(ByteStringView words) {
+  if (words.IsEmpty()) {
     return ByteString();
-  return PDF_EncodeString(strWords) + " Tj\n";
+  }
+  return PDF_EncodeString(words) + " Tj\n";
 }
 
-ByteString GetFontSetString(IPVT_FontMap* pFontMap,
-                            int32_t nFontIndex,
-                            float fFontSize) {
-  fxcrt::ostringstream sRet;
-  if (pFontMap) {
-    ByteString sFontAlias = pFontMap->GetPDFFontAlias(nFontIndex);
-    if (sFontAlias.GetLength() > 0 && fFontSize > 0) {
-      sRet << "/" << sFontAlias << " ";
-      WriteFloat(sRet, fFontSize) << " Tf\n";
+ByteString GetFontSetString(IPVT_FontMap* font_map,
+                            int32_t font_index,
+                            float font_size) {
+  fxcrt::ostringstream font_stream;
+  if (font_map) {
+    ByteString font_alias = font_map->GetPDFFontAlias(font_index);
+    if (font_alias.GetLength() > 0 && font_size > 0) {
+      font_stream << "/" << font_alias << " ";
+      WriteFloat(font_stream, font_size) << " Tf\n";
     }
   }
-  return ByteString(sRet);
+  return ByteString(font_stream);
+}
+
+void SetVtFontSize(float font_size, CPVT_VariableText& vt) {
+  if (FXSYS_IsFloatZero(font_size)) {
+    vt.SetAutoFontSize(true);
+  } else {
+    vt.SetFontSize(font_size);
+  }
+}
+
+// ISO 32000-1:2008 spec, table 166.
+// ISO 32000-2:2020 spec, table 168.
+struct BorderStyleInfo {
+  float width = 1;
+  BorderStyle style = BorderStyle::kSolid;
+  CPVT_Dash dash_pattern{3, 0, 0};
+};
+
+BorderStyleInfo GetBorderStyleInfo(const CPDF_Dictionary* border_style_dict) {
+  BorderStyleInfo border_style_info;
+  if (!border_style_dict) {
+    return border_style_info;
+  }
+
+  if (border_style_dict->KeyExist("W")) {
+    border_style_info.width = border_style_dict->GetFloatFor("W");
+  }
+
+  const ByteString border_style_string =
+      border_style_dict->GetByteStringFor("S");
+  if (border_style_string.GetLength()) {
+    switch (border_style_string[0]) {
+      case 'S':
+        border_style_info.style = BorderStyle::kSolid;
+        break;
+      case 'D':
+        border_style_info.style = BorderStyle::kDash;
+        break;
+      case 'B':
+        border_style_info.style = BorderStyle::kBeveled;
+        border_style_info.width *= 2;
+        break;
+      case 'I':
+        border_style_info.style = BorderStyle::kInset;
+        border_style_info.width *= 2;
+        break;
+      case 'U':
+        border_style_info.style = BorderStyle::kUnderline;
+        break;
+    }
+  }
+
+  RetainPtr<const CPDF_Array> dash_array = border_style_dict->GetArrayFor("D");
+  if (dash_array) {
+    border_style_info.dash_pattern =
+        CPVT_Dash(dash_array->GetIntegerAt(0), dash_array->GetIntegerAt(1),
+                  dash_array->GetIntegerAt(2));
+  }
+
+  return border_style_info;
+}
+
+// ISO 32000-1:2008 spec, table 189.
+// ISO 32000-2:2020 spec, table 192.
+struct AppearanceCharacteristics {
+  int rotation = 0;  // In degrees.
+  CFX_Color border_color;
+  CFX_Color background_color;
+};
+
+AppearanceCharacteristics GetAppearanceCharacteristics(
+    const CPDF_Dictionary* mk_dict) {
+  AppearanceCharacteristics appearance_characteristics;
+  if (!mk_dict) {
+    return appearance_characteristics;
+  }
+
+  appearance_characteristics.rotation =
+      mk_dict->GetIntegerFor(pdfium::appearance::kR);
+
+  RetainPtr<const CPDF_Array> border_color_array =
+      mk_dict->GetArrayFor(pdfium::appearance::kBC);
+  if (border_color_array) {
+    appearance_characteristics.border_color =
+        fpdfdoc::CFXColorFromArray(*border_color_array);
+  }
+  RetainPtr<const CPDF_Array> background_color_array =
+      mk_dict->GetArrayFor(pdfium::appearance::kBG);
+  if (background_color_array) {
+    appearance_characteristics.background_color =
+        fpdfdoc::CFXColorFromArray(*background_color_array);
+  }
+  return appearance_characteristics;
+}
+
+struct AnnotationDimensionsAndColor {
+  CFX_FloatRect bbox;
+  CFX_Matrix matrix;
+  CFX_Color border_color;
+  CFX_Color background_color;
+};
+
+AnnotationDimensionsAndColor GetAnnotationDimensionsAndColor(
+    const CPDF_Dictionary* annot_dict) {
+  const AppearanceCharacteristics appearance_characteristics =
+      GetAppearanceCharacteristics(annot_dict->GetDictFor("MK"));
+  const CFX_FloatRect annot_rect =
+      annot_dict->GetRectFor(pdfium::annotation::kRect);
+
+  CFX_FloatRect bbox_rect;
+  CFX_Matrix matrix;
+  switch (appearance_characteristics.rotation % 360) {
+    case 0:
+      bbox_rect = CFX_FloatRect(0, 0, annot_rect.right - annot_rect.left,
+                                annot_rect.top - annot_rect.bottom);
+      break;
+    case 90:
+      matrix = CFX_Matrix(0, 1, -1, 0, annot_rect.right - annot_rect.left, 0);
+      bbox_rect = CFX_FloatRect(0, 0, annot_rect.top - annot_rect.bottom,
+                                annot_rect.right - annot_rect.left);
+      break;
+    case 180:
+      matrix = CFX_Matrix(-1, 0, 0, -1, annot_rect.right - annot_rect.left,
+                          annot_rect.top - annot_rect.bottom);
+      bbox_rect = CFX_FloatRect(0, 0, annot_rect.right - annot_rect.left,
+                                annot_rect.top - annot_rect.bottom);
+      break;
+    case 270:
+      matrix = CFX_Matrix(0, -1, 1, 0, 0, annot_rect.top - annot_rect.bottom);
+      bbox_rect = CFX_FloatRect(0, 0, annot_rect.top - annot_rect.bottom,
+                                annot_rect.right - annot_rect.left);
+      break;
+  }
+
+  return {
+      .bbox = bbox_rect,
+      .matrix = matrix,
+      .border_color = appearance_characteristics.border_color,
+      .background_color = appearance_characteristics.background_color,
+  };
 }
 
-ByteString GenerateEditAP(IPVT_FontMap* pFontMap,
-                          CPVT_VariableText::Iterator* pIterator,
-                          const CFX_PointF& ptOffset,
-                          bool bContinuous,
-                          uint16_t SubWord) {
-  fxcrt::ostringstream sEditStream;
-  fxcrt::ostringstream sLineStream;
-  CFX_PointF ptOld;
-  CFX_PointF ptNew;
-  int32_t nCurFontIndex = -1;
+ByteString GetDefaultAppearanceString(CPDF_Dictionary* annot_dict,
+                                      CPDF_Dictionary* form_dict) {
+  ByteString default_appearance_string;
+  RetainPtr<const CPDF_Object> default_appearance_object =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, "DA");
+  if (default_appearance_object) {
+    default_appearance_string = default_appearance_object->GetString();
+  }
+  if (default_appearance_string.IsEmpty()) {
+    default_appearance_string = form_dict->GetByteStringFor("DA");
+  }
+  return default_appearance_string;
+}
+
+struct DefaultAppearanceInfo {
+  ByteString font_name;
+  float font_size;
+  CFX_Color text_color;
+};
+
+std::optional<DefaultAppearanceInfo> GetDefaultAppearanceInfo(
+    const ByteString& default_appearance_string) {
+  if (default_appearance_string.IsEmpty()) {
+    return std::nullopt;
+  }
+
+  CPDF_DefaultAppearance appearance(default_appearance_string);
+
+  float font_size = 0;
+  std::optional<ByteString> font = appearance.GetFont(&font_size);
+  if (!font.has_value()) {
+    return std::nullopt;
+  }
+
+  return DefaultAppearanceInfo{
+      .font_name = font.value(),
+      .font_size = font_size,
+      .text_color = appearance.GetColor().value_or(CFX_Color())};
+}
+
+bool CloneResourcesDictIfMissingFromStream(CPDF_Dictionary* stream_dict,
+                                           const CPDF_Dictionary* dr_dict) {
+  RetainPtr<CPDF_Dictionary> resources_dict =
+      stream_dict->GetMutableDictFor("Resources");
+  if (resources_dict) {
+    return false;
+  }
+
+  stream_dict->SetFor("Resources", dr_dict->Clone());
+  return true;
+}
+
+bool ValidateOrCreateFontResources(CPDF_Document* doc,
+                                   CPDF_Dictionary* stream_dict,
+                                   const CPDF_Dictionary* font_dict,
+                                   const ByteString& font_name) {
+  RetainPtr<CPDF_Dictionary> resources_dict =
+      stream_dict->GetMutableDictFor("Resources");
+  RetainPtr<CPDF_Dictionary> font_resource_dict =
+      resources_dict->GetMutableDictFor("Font");
+  if (!font_resource_dict) {
+    font_resource_dict = resources_dict->SetNewFor<CPDF_Dictionary>("Font");
+  }
+
+  if (!ValidateFontResourceDict(font_resource_dict.Get())) {
+    return false;
+  }
+
+  if (!font_resource_dict->KeyExist(font_name)) {
+    font_resource_dict->SetNewFor<CPDF_Reference>(font_name, doc,
+                                                  font_dict->GetObjNum());
+  }
+  return true;
+}
+
+ByteString GenerateEditAP(IPVT_FontMap* font_map,
+                          CPVT_VariableText::Iterator* vt_iterator,
+                          const CFX_PointF& offset,
+                          bool continuous,
+                          uint16_t sub_word) {
+  fxcrt::ostringstream edit_stream;
+  fxcrt::ostringstream line_stream;
+  CFX_PointF old_point;
+  CFX_PointF new_point;
+  int32_t current_font_index = -1;
   CPVT_WordPlace oldplace;
-  ByteString sWords;
-  pIterator->SetAt(0);
-  while (pIterator->NextWord()) {
-    CPVT_WordPlace place = pIterator->GetWordPlace();
-    if (bContinuous) {
+  ByteString words;
+  vt_iterator->SetAt(0);
+  while (vt_iterator->NextWord()) {
+    CPVT_WordPlace place = vt_iterator->GetWordPlace();
+    if (continuous) {
       if (place.LineCmp(oldplace) != 0) {
-        if (!sWords.IsEmpty()) {
-          sLineStream << GetWordRenderString(sWords.AsStringView());
-          sEditStream << sLineStream.str();
-          sLineStream.str("");
-          sWords.clear();
+        if (!words.IsEmpty()) {
+          line_stream << GetWordRenderString(words.AsStringView());
+          edit_stream << line_stream.str();
+          line_stream.str("");
+          words.clear();
         }
         CPVT_Word word;
-        if (pIterator->GetWord(word)) {
-          ptNew = CFX_PointF(word.ptWord.x + ptOffset.x,
-                             word.ptWord.y + ptOffset.y);
+        if (vt_iterator->GetWord(word)) {
+          new_point =
+              CFX_PointF(word.ptWord.x + offset.x, word.ptWord.y + offset.y);
         } else {
           CPVT_Line line;
-          pIterator->GetLine(line);
-          ptNew = CFX_PointF(line.ptLine.x + ptOffset.x,
-                             line.ptLine.y + ptOffset.y);
+          vt_iterator->GetLine(line);
+          new_point =
+              CFX_PointF(line.ptLine.x + offset.x, line.ptLine.y + offset.y);
         }
-        if (ptNew != ptOld) {
-          WritePoint(sLineStream, ptNew - ptOld) << " Td\n";
-          ptOld = ptNew;
+        if (new_point != old_point) {
+          WritePoint(line_stream, new_point - old_point) << " Td\n";
+          old_point = new_point;
         }
       }
       CPVT_Word word;
-      if (pIterator->GetWord(word)) {
-        if (word.nFontIndex != nCurFontIndex) {
-          if (!sWords.IsEmpty()) {
-            sLineStream << GetWordRenderString(sWords.AsStringView());
-            sWords.clear();
+      if (vt_iterator->GetWord(word)) {
+        if (word.nFontIndex != current_font_index) {
+          if (!words.IsEmpty()) {
+            line_stream << GetWordRenderString(words.AsStringView());
+            words.clear();
           }
-          sLineStream << GetFontSetString(pFontMap, word.nFontIndex,
+          line_stream << GetFontSetString(font_map, word.nFontIndex,
                                           word.fFontSize);
-          nCurFontIndex = word.nFontIndex;
+          current_font_index = word.nFontIndex;
         }
-        sWords += GetPDFWordString(pFontMap, nCurFontIndex, word.Word, SubWord);
+        words +=
+            GetPDFWordString(font_map, current_font_index, word.Word, sub_word);
       }
       oldplace = place;
     } else {
       CPVT_Word word;
-      if (pIterator->GetWord(word)) {
-        ptNew =
-            CFX_PointF(word.ptWord.x + ptOffset.x, word.ptWord.y + ptOffset.y);
-        if (ptNew != ptOld) {
-          WritePoint(sEditStream, ptNew - ptOld) << " Td\n";
-          ptOld = ptNew;
+      if (vt_iterator->GetWord(word)) {
+        new_point =
+            CFX_PointF(word.ptWord.x + offset.x, word.ptWord.y + offset.y);
+        if (new_point != old_point) {
+          WritePoint(edit_stream, new_point - old_point) << " Td\n";
+          old_point = new_point;
         }
-        if (word.nFontIndex != nCurFontIndex) {
-          sEditStream << GetFontSetString(pFontMap, word.nFontIndex,
+        if (word.nFontIndex != current_font_index) {
+          edit_stream << GetFontSetString(font_map, word.nFontIndex,
                                           word.fFontSize);
-          nCurFontIndex = word.nFontIndex;
+          current_font_index = word.nFontIndex;
         }
-        sEditStream << GetWordRenderString(
-            GetPDFWordString(pFontMap, nCurFontIndex, word.Word, SubWord)
+        edit_stream << GetWordRenderString(
+            GetPDFWordString(font_map, current_font_index, word.Word, sub_word)
                 .AsStringView());
       }
     }
   }
-  if (!sWords.IsEmpty()) {
-    sLineStream << GetWordRenderString(sWords.AsStringView());
-    sEditStream << sLineStream.str();
+  if (!words.IsEmpty()) {
+    line_stream << GetWordRenderString(words.AsStringView());
+    edit_stream << line_stream.str();
   }
-  return ByteString(sEditStream);
+  return ByteString(edit_stream);
 }
 
-ByteString GenerateColorAP(const CFX_Color& color, PaintOperation nOperation) {
-  fxcrt::ostringstream sColorStream;
+ByteString GenerateColorAP(const CFX_Color& color, PaintOperation operation) {
+  fxcrt::ostringstream color_stream;
   switch (color.nColorType) {
     case CFX_Color::Type::kRGB:
-      WriteFloat(sColorStream, color.fColor1) << " ";
-      WriteFloat(sColorStream, color.fColor2) << " ";
-      WriteFloat(sColorStream, color.fColor3) << " ";
-      sColorStream << (nOperation == PaintOperation::kStroke ? "RG" : "rg")
+      WriteFloat(color_stream, color.fColor1) << " ";
+      WriteFloat(color_stream, color.fColor2) << " ";
+      WriteFloat(color_stream, color.fColor3) << " ";
+      color_stream << (operation == PaintOperation::kStroke ? "RG" : "rg")
                    << "\n";
-      break;
+      return ByteString(color_stream);
     case CFX_Color::Type::kGray:
-      WriteFloat(sColorStream, color.fColor1) << " ";
-      sColorStream << (nOperation == PaintOperation::kStroke ? "G" : "g")
+      WriteFloat(color_stream, color.fColor1) << " ";
+      color_stream << (operation == PaintOperation::kStroke ? "G" : "g")
                    << "\n";
-      break;
+      return ByteString(color_stream);
     case CFX_Color::Type::kCMYK:
-      WriteFloat(sColorStream, color.fColor1) << " ";
-      WriteFloat(sColorStream, color.fColor2) << " ";
-      WriteFloat(sColorStream, color.fColor3) << " ";
-      WriteFloat(sColorStream, color.fColor4) << " ";
-      sColorStream << (nOperation == PaintOperation::kStroke ? "K" : "k")
+      WriteFloat(color_stream, color.fColor1) << " ";
+      WriteFloat(color_stream, color.fColor2) << " ";
+      WriteFloat(color_stream, color.fColor3) << " ";
+      WriteFloat(color_stream, color.fColor4) << " ";
+      color_stream << (operation == PaintOperation::kStroke ? "K" : "k")
                    << "\n";
-      break;
+      return ByteString(color_stream);
     case CFX_Color::Type::kTransparent:
-      break;
+      return ByteString();
   }
-  return ByteString(sColorStream);
+  NOTREACHED();
 }
 
 ByteString GenerateBorderAP(const CFX_FloatRect& rect,
-                            float width,
-                            const CFX_Color& color,
-                            const CFX_Color& crLeftTop,
-                            const CFX_Color& crRightBottom,
-                            BorderStyle nStyle,
-                            const CPVT_Dash& dash) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sColor;
-  const float fLeft = rect.left;
-  const float fRight = rect.right;
-  const float fTop = rect.top;
-  const float fBottom = rect.bottom;
-  if (width > 0.0f) {
-    const float half_width = width / 2.0f;
-    switch (nStyle) {
-      case BorderStyle::kSolid:
-        sColor = GenerateColorAP(color, PaintOperation::kFill);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WriteRect(sAppStream, rect) << " re\n";
-          CFX_FloatRect inner_rect = rect;
-          inner_rect.Deflate(width, width);
-          WriteRect(sAppStream, inner_rect) << " re f*\n";
-        }
-        break;
-      case BorderStyle::kDash:
-        sColor = GenerateColorAP(color, PaintOperation::kStroke);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WriteFloat(sAppStream, width)
-              << " w [" << dash.nDash << " " << dash.nGap << "] " << dash.nPhase
-              << " d\n";
-          WritePoint(sAppStream, {fLeft + half_width, fBottom + half_width})
-              << " m\n";
-          WritePoint(sAppStream, {fLeft + half_width, fTop - half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fRight - half_width, fTop - half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fRight - half_width, fBottom + half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fLeft + half_width, fBottom + half_width})
-              << " l S\n";
-        }
-        break;
-      case BorderStyle::kBeveled:
-      case BorderStyle::kInset:
-        sColor = GenerateColorAP(crLeftTop, PaintOperation::kFill);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WritePoint(sAppStream, {fLeft + half_width, fBottom + half_width})
-              << " m\n";
-          WritePoint(sAppStream, {fLeft + half_width, fTop - half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fRight - half_width, fTop - half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fRight - width, fTop - width}) << " l\n";
-          WritePoint(sAppStream, {fLeft + width, fTop - width}) << " l\n";
-          WritePoint(sAppStream, {fLeft + width, fBottom + width}) << " l f\n";
-        }
-        sColor = GenerateColorAP(crRightBottom, PaintOperation::kFill);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WritePoint(sAppStream, {fRight - half_width, fTop - half_width})
-              << " m\n";
-          WritePoint(sAppStream, {fRight - half_width, fBottom + half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fLeft + half_width, fBottom + half_width})
-              << " l\n";
-          WritePoint(sAppStream, {fLeft + width, fBottom + width}) << " l\n";
-          WritePoint(sAppStream, {fRight - width, fBottom + width}) << " l\n";
-          WritePoint(sAppStream, {fRight - width, fTop - width}) << " l f\n";
-        }
-        sColor = GenerateColorAP(color, PaintOperation::kFill);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WriteRect(sAppStream, rect) << " re\n";
-          CFX_FloatRect inner_rect = rect;
-          inner_rect.Deflate(half_width, half_width);
-          WriteRect(sAppStream, inner_rect) << " re f*\n";
-        }
-        break;
-      case BorderStyle::kUnderline:
-        sColor = GenerateColorAP(color, PaintOperation::kStroke);
-        if (sColor.GetLength() > 0) {
-          sAppStream << sColor;
-          WriteFloat(sAppStream, width) << " w\n";
-          WritePoint(sAppStream, {fLeft, fBottom + half_width}) << " m\n";
-          WritePoint(sAppStream, {fRight, fBottom + half_width}) << " l S\n";
-        }
-        break;
+                            const BorderStyleInfo& border_style_info,
+                            const CFX_Color& border_color) {
+  const float width = border_style_info.width;
+  if (width <= 0) {
+    return ByteString();
+  }
+
+  fxcrt::ostringstream app_stream;
+  const float left = rect.left;
+  const float bottom = rect.bottom;
+  const float right = rect.right;
+  const float top = rect.top;
+  const float half_width = width / 2.0f;
+  switch (border_style_info.style) {
+    case BorderStyle::kSolid: {
+      ByteString color_string =
+          GenerateColorAP(border_color, PaintOperation::kFill);
+      if (color_string.GetLength() > 0) {
+        app_stream << color_string;
+        WriteRect(app_stream, rect) << " re\n";
+        CFX_FloatRect inner_rect = rect;
+        inner_rect.Deflate(width, width);
+        WriteRect(app_stream, inner_rect) << " re f*\n";
+      }
+      return ByteString(app_stream);
+    }
+    case BorderStyle::kDash: {
+      ByteString color_string =
+          GenerateColorAP(border_color, PaintOperation::kStroke);
+      if (color_string.GetLength() > 0) {
+        const auto& dash = border_style_info.dash_pattern;
+        app_stream << color_string;
+        WriteFloat(app_stream, width) << " w [" << dash.dash << " " << dash.gap
+                                      << "] " << dash.phase << " d\n";
+        WritePoint(app_stream, {left + half_width, bottom + half_width})
+            << " m\n";
+        WritePoint(app_stream, {left + half_width, top - half_width}) << " l\n";
+        WritePoint(app_stream, {right - half_width, top - half_width})
+            << " l\n";
+        WritePoint(app_stream, {right - half_width, bottom + half_width})
+            << " l\n";
+        WritePoint(app_stream, {left + half_width, bottom + half_width})
+            << " l S\n";
+      }
+      return ByteString(app_stream);
+    }
+    case BorderStyle::kBeveled:
+    case BorderStyle::kInset: {
+      const float left_top_gray_value =
+          border_style_info.style == BorderStyle::kBeveled ? 1.0f : 0.5f;
+      app_stream << GenerateColorAP(
+          CFX_Color(CFX_Color::Type::kGray, left_top_gray_value),
+          PaintOperation::kFill);
+      WritePoint(app_stream, {left + half_width, bottom + half_width})
+          << " m\n";
+      WritePoint(app_stream, {left + half_width, top - half_width}) << " l\n";
+      WritePoint(app_stream, {right - half_width, top - half_width}) << " l\n";
+      WritePoint(app_stream, {right - width, top - width}) << " l\n";
+      WritePoint(app_stream, {left + width, top - width}) << " l\n";
+      WritePoint(app_stream, {left + width, bottom + width}) << " l f\n";
+
+      const float right_bottom_gray_value =
+          border_style_info.style == BorderStyle::kBeveled ? 0.5f : 0.75f;
+      app_stream << GenerateColorAP(
+          CFX_Color(CFX_Color::Type::kGray, right_bottom_gray_value),
+          PaintOperation::kFill);
+      WritePoint(app_stream, {right - half_width, top - half_width}) << " m\n";
+      WritePoint(app_stream, {right - half_width, bottom + half_width})
+          << " l\n";
+      WritePoint(app_stream, {left + half_width, bottom + half_width})
+          << " l\n";
+      WritePoint(app_stream, {left + width, bottom + width}) << " l\n";
+      WritePoint(app_stream, {right - width, bottom + width}) << " l\n";
+      WritePoint(app_stream, {right - width, top - width}) << " l f\n";
+
+      ByteString color_string =
+          GenerateColorAP(border_color, PaintOperation::kFill);
+      if (color_string.GetLength() > 0) {
+        app_stream << color_string;
+        WriteRect(app_stream, rect) << " re\n";
+        CFX_FloatRect inner_rect = rect;
+        inner_rect.Deflate(half_width, half_width);
+        WriteRect(app_stream, inner_rect) << " re f*\n";
+      }
+      return ByteString(app_stream);
+    }
+    case BorderStyle::kUnderline: {
+      ByteString color_string =
+          GenerateColorAP(border_color, PaintOperation::kStroke);
+      if (color_string.GetLength() > 0) {
+        app_stream << color_string;
+        WriteFloat(app_stream, width) << " w\n";
+        WritePoint(app_stream, {left, bottom + half_width}) << " m\n";
+        WritePoint(app_stream, {right, bottom + half_width}) << " l S\n";
+      }
+      return ByteString(app_stream);
     }
   }
-  return ByteString(sAppStream);
+  NOTREACHED();
 }
 
-ByteString GetColorStringWithDefault(const CPDF_Array* pColor,
-                                     const CFX_Color& crDefaultColor,
-                                     PaintOperation nOperation) {
-  if (pColor) {
-    CFX_Color color = fpdfdoc::CFXColorFromArray(*pColor);
-    return GenerateColorAP(color, nOperation);
+ByteString GetColorStringWithDefault(const CPDF_Array* color_array,
+                                     const CFX_Color& default_color,
+                                     PaintOperation operation) {
+  if (color_array) {
+    CFX_Color color = fpdfdoc::CFXColorFromArray(*color_array);
+    return GenerateColorAP(color, operation);
   }
 
-  return GenerateColorAP(crDefaultColor, nOperation);
+  return GenerateColorAP(default_color, operation);
 }
 
-float GetBorderWidth(const CPDF_Dictionary* pDict) {
-  RetainPtr<const CPDF_Dictionary> pBorderStyleDict = pDict->GetDictFor("BS");
-  if (pBorderStyleDict && pBorderStyleDict->KeyExist("W"))
-    return pBorderStyleDict->GetFloatFor("W");
+float GetBorderWidth(const CPDF_Dictionary* dict) {
+  RetainPtr<const CPDF_Dictionary> border_style_dict = dict->GetDictFor("BS");
+  if (border_style_dict && border_style_dict->KeyExist("W")) {
+    return border_style_dict->GetFloatFor("W");
+  }
 
-  auto pBorderArray = pDict->GetArrayFor(pdfium::annotation::kBorder);
-  if (pBorderArray && pBorderArray->size() > 2)
-    return pBorderArray->GetFloatAt(2);
+  auto border_array = dict->GetArrayFor(pdfium::annotation::kBorder);
+  if (border_array && border_array->size() > 2) {
+    return border_array->GetFloatAt(2);
+  }
 
   return 1;
 }
 
-RetainPtr<const CPDF_Array> GetDashArray(const CPDF_Dictionary* pDict) {
-  RetainPtr<const CPDF_Dictionary> pBorderStyleDict = pDict->GetDictFor("BS");
-  if (pBorderStyleDict && pBorderStyleDict->GetByteStringFor("S") == "D")
-    return pBorderStyleDict->GetArrayFor("D");
+RetainPtr<const CPDF_Array> GetDashArray(const CPDF_Dictionary* dict) {
+  RetainPtr<const CPDF_Dictionary> border_style_dict = dict->GetDictFor("BS");
+  if (border_style_dict && border_style_dict->GetByteStringFor("S") == "D") {
+    return border_style_dict->GetArrayFor("D");
+  }
 
-  RetainPtr<const CPDF_Array> pBorderArray =
-      pDict->GetArrayFor(pdfium::annotation::kBorder);
-  if (pBorderArray && pBorderArray->size() == 4)
-    return pBorderArray->GetArrayAt(3);
+  RetainPtr<const CPDF_Array> border_array =
+      dict->GetArrayFor(pdfium::annotation::kBorder);
+  if (border_array && border_array->size() == 4) {
+    return border_array->GetArrayAt(3);
+  }
 
   return nullptr;
 }
 
-ByteString GetDashPatternString(const CPDF_Dictionary* pDict) {
-  RetainPtr<const CPDF_Array> pDashArray = GetDashArray(pDict);
-  if (!pDashArray || pDashArray->IsEmpty())
+ByteString GetDashPatternString(const CPDF_Dictionary* dict) {
+  RetainPtr<const CPDF_Array> dash_array = GetDashArray(dict);
+  if (!dash_array || dash_array->IsEmpty()) {
     return ByteString();
+  }
 
   // Support maximum of ten elements in the dash array.
-  size_t pDashArrayCount = std::min<size_t>(pDashArray->size(), 10);
-  fxcrt::ostringstream sDashStream;
+  size_t dash_arrayCount = std::min<size_t>(dash_array->size(), 10);
+  fxcrt::ostringstream dash_stream;
 
-  sDashStream << "[";
-  for (size_t i = 0; i < pDashArrayCount; ++i)
-    WriteFloat(sDashStream, pDashArray->GetFloatAt(i)) << " ";
-  sDashStream << "] 0 d\n";
+  dash_stream << "[";
+  for (size_t i = 0; i < dash_arrayCount; ++i) {
+    WriteFloat(dash_stream, dash_array->GetFloatAt(i)) << " ";
+  }
+  dash_stream << "] 0 d\n";
 
-  return ByteString(sDashStream);
+  return ByteString(dash_stream);
 }
 
-ByteString GetPopupContentsString(CPDF_Document* pDoc,
-                                  const CPDF_Dictionary& pAnnotDict,
-                                  RetainPtr<CPDF_Font> pDefFont,
-                                  const ByteString& sFontName) {
-  WideString swValue(pAnnotDict.GetUnicodeTextFor(pdfium::form_fields::kT));
-  swValue += L'\n';
-  swValue += pAnnotDict.GetUnicodeTextFor(pdfium::annotation::kContents);
+ByteString GetPopupContentsString(CPDF_Document* doc,
+                                  const CPDF_Dictionary& annot_dict,
+                                  RetainPtr<CPDF_Font> default_font,
+                                  const ByteString& font_name) {
+  WideString value(annot_dict.GetUnicodeTextFor(pdfium::form_fields::kT));
+  value += L'\n';
+  value += annot_dict.GetUnicodeTextFor(pdfium::annotation::kContents);
 
-  CPVT_FontMap map(pDoc, nullptr, std::move(pDefFont), sFontName);
+  CPVT_FontMap map(doc, nullptr, std::move(default_font), font_name);
   CPVT_VariableText::Provider prd(&map);
   CPVT_VariableText vt(&prd);
-  vt.SetPlateRect(pAnnotDict.GetRectFor(pdfium::annotation::kRect));
+  vt.SetPlateRect(annot_dict.GetRectFor(pdfium::annotation::kRect));
   vt.SetFontSize(12);
   vt.SetAutoReturn(true);
   vt.SetMultiLine(true);
   vt.Initialize();
-  vt.SetText(swValue);
+  vt.SetText(value);
   vt.RearrangeAll();
 
-  CFX_PointF ptOffset(3.0f, -3.0f);
-  ByteString sContent =
-      GenerateEditAP(&map, vt.GetIterator(), ptOffset, false, 0);
+  CFX_PointF offset(3.0f, -3.0f);
+  ByteString content = GenerateEditAP(&map, vt.GetIterator(), offset, false, 0);
 
-  if (sContent.IsEmpty())
+  if (content.IsEmpty()) {
     return ByteString();
+  }
 
-  ByteString sColorAP = GenerateColorAP(
-      CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kFill);
+  ByteString color = GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0),
+                                     PaintOperation::kFill);
 
-  return ByteString{"BT\n", sColorAP.AsStringView(), sContent.AsStringView(),
+  return ByteString{"BT\n", color.AsStringView(), content.AsStringView(),
                     "ET\n", "Q\n"};
 }
 
@@ -398,6 +634,22 @@ RetainPtr<CPDF_Dictionary> GenerateFallbackFontDict(CPDF_Document* doc) {
   return font_dict;
 }
 
+RetainPtr<CPDF_Dictionary> GetFontFromDrFontDictOrGenerateFallback(
+    CPDF_Document* doc,
+    CPDF_Dictionary* dr_font_dict,
+    const ByteString& font_name) {
+  RetainPtr<CPDF_Dictionary> font_dict =
+      dr_font_dict->GetMutableDictFor(font_name);
+  if (font_dict) {
+    return font_dict;
+  }
+
+  RetainPtr<CPDF_Dictionary> new_font_dict = GenerateFallbackFontDict(doc);
+  dr_font_dict->SetNewFor<CPDF_Reference>(font_name, doc,
+                                          new_font_dict->GetObjNum());
+  return new_font_dict;
+}
+
 RetainPtr<CPDF_Dictionary> GenerateResourceFontDict(
     CPDF_Document* doc,
     const ByteString& font_name,
@@ -408,92 +660,94 @@ RetainPtr<CPDF_Dictionary> GenerateResourceFontDict(
   return resource_font_dict;
 }
 
-ByteString GetPaintOperatorString(bool bIsStrokeRect, bool bIsFillRect) {
-  if (bIsStrokeRect)
-    return bIsFillRect ? "b" : "s";
-  return bIsFillRect ? "f" : "n";
+ByteString GetPaintOperatorString(bool is_stroke_rect, bool is_fill_rect) {
+  if (is_stroke_rect) {
+    return is_fill_rect ? "b" : "s";
+  }
+  return is_fill_rect ? "f" : "n";
 }
 
 ByteString GenerateTextSymbolAP(const CFX_FloatRect& rect) {
-  fxcrt::ostringstream sAppStream;
-  sAppStream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 1, 1, 0),
+  fxcrt::ostringstream app_stream;
+  app_stream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 1, 1, 0),
                                 PaintOperation::kFill);
-  sAppStream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0),
+  app_stream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0),
                                 PaintOperation::kStroke);
 
-  constexpr int kBorderWidth = 1;
-  sAppStream << kBorderWidth << " w\n";
+  static constexpr int kBorderWidth = 1;
+  app_stream << kBorderWidth << " w\n";
 
-  constexpr float kHalfWidth = kBorderWidth / 2.0f;
-  constexpr int kTipDelta = 4;
+  static constexpr float kHalfWidth = kBorderWidth / 2.0f;
+  static constexpr int kTipDelta = 4;
 
-  CFX_FloatRect outerRect1 = rect;
-  outerRect1.Deflate(kHalfWidth, kHalfWidth);
-  outerRect1.bottom += kTipDelta;
+  CFX_FloatRect outer_rect1 = rect;
+  outer_rect1.Deflate(kHalfWidth, kHalfWidth);
+  outer_rect1.bottom += kTipDelta;
 
-  CFX_FloatRect outerRect2 = outerRect1;
-  outerRect2.left += kTipDelta;
-  outerRect2.right = outerRect2.left + kTipDelta;
-  outerRect2.top = outerRect2.bottom - kTipDelta;
-  float outerRect2Middle = (outerRect2.left + outerRect2.right) / 2;
+  CFX_FloatRect outer_rect2 = outer_rect1;
+  outer_rect2.left += kTipDelta;
+  outer_rect2.right = outer_rect2.left + kTipDelta;
+  outer_rect2.top = outer_rect2.bottom - kTipDelta;
+  float outer_rect2_middle = (outer_rect2.left + outer_rect2.right) / 2;
 
   // Draw outer boxes.
-  WritePoint(sAppStream, {outerRect1.left, outerRect1.bottom}) << " m\n";
-  WritePoint(sAppStream, {outerRect1.left, outerRect1.top}) << " l\n";
-  WritePoint(sAppStream, {outerRect1.right, outerRect1.top}) << " l\n";
-  WritePoint(sAppStream, {outerRect1.right, outerRect1.bottom}) << " l\n";
-  WritePoint(sAppStream, {outerRect2.right, outerRect2.bottom}) << " l\n";
-  WritePoint(sAppStream, {outerRect2Middle, outerRect2.top}) << " l\n";
-  WritePoint(sAppStream, {outerRect2.left, outerRect2.bottom}) << " l\n";
-  WritePoint(sAppStream, {outerRect1.left, outerRect1.bottom}) << " l\n";
+  WritePoint(app_stream, {outer_rect1.left, outer_rect1.bottom}) << " m\n";
+  WritePoint(app_stream, {outer_rect1.left, outer_rect1.top}) << " l\n";
+  WritePoint(app_stream, {outer_rect1.right, outer_rect1.top}) << " l\n";
+  WritePoint(app_stream, {outer_rect1.right, outer_rect1.bottom}) << " l\n";
+  WritePoint(app_stream, {outer_rect2.right, outer_rect2.bottom}) << " l\n";
+  WritePoint(app_stream, {outer_rect2_middle, outer_rect2.top}) << " l\n";
+  WritePoint(app_stream, {outer_rect2.left, outer_rect2.bottom}) << " l\n";
+  WritePoint(app_stream, {outer_rect1.left, outer_rect1.bottom}) << " l\n";
 
   // Draw inner lines.
-  CFX_FloatRect lineRect = outerRect1;
-  const float fXDelta = 2;
-  const float fYDelta = (lineRect.top - lineRect.bottom) / 4;
+  CFX_FloatRect line_rect = outer_rect1;
+  const float delta_x = 2;
+  const float delta_y = (line_rect.top - line_rect.bottom) / 4;
 
-  lineRect.left += fXDelta;
-  lineRect.right -= fXDelta;
+  line_rect.left += delta_x;
+  line_rect.right -= delta_x;
   for (int i = 0; i < 3; ++i) {
-    lineRect.top -= fYDelta;
-    WritePoint(sAppStream, {lineRect.left, lineRect.top}) << " m\n";
-    WritePoint(sAppStream, {lineRect.right, lineRect.top}) << " l\n";
+    line_rect.top -= delta_y;
+    WritePoint(app_stream, {line_rect.left, line_rect.top}) << " m\n";
+    WritePoint(app_stream, {line_rect.right, line_rect.top}) << " l\n";
   }
-  sAppStream << "B*\n";
+  app_stream << "B*\n";
 
-  return ByteString(sAppStream);
+  return ByteString(app_stream);
 }
 
 RetainPtr<CPDF_Dictionary> GenerateExtGStateDict(
-    const CPDF_Dictionary& pAnnotDict,
-    const ByteString& sExtGSDictName,
-    const ByteString& sBlendMode) {
-  auto pGSDict =
-      pdfium::MakeRetain<CPDF_Dictionary>(pAnnotDict.GetByteStringPool());
-  pGSDict->SetNewFor<CPDF_Name>("Type", "ExtGState");
-
-  float fOpacity = pAnnotDict.KeyExist("CA") ? pAnnotDict.GetFloatFor("CA") : 1;
-  pGSDict->SetNewFor<CPDF_Number>("CA", fOpacity);
-  pGSDict->SetNewFor<CPDF_Number>("ca", fOpacity);
-  pGSDict->SetNewFor<CPDF_Boolean>("AIS", false);
-  pGSDict->SetNewFor<CPDF_Name>("BM", sBlendMode);
-
-  auto pExtGStateDict =
-      pdfium::MakeRetain<CPDF_Dictionary>(pAnnotDict.GetByteStringPool());
-  pExtGStateDict->SetFor(sExtGSDictName, pGSDict);
-  return pExtGStateDict;
+    const CPDF_Dictionary& annot_dict,
+    const ByteString& blend_mode) {
+  auto gs_dict =
+      pdfium::MakeRetain<CPDF_Dictionary>(annot_dict.GetByteStringPool());
+  gs_dict->SetNewFor<CPDF_Name>("Type", "ExtGState");
+
+  float opacity = annot_dict.KeyExist("CA") ? annot_dict.GetFloatFor("CA") : 1;
+  gs_dict->SetNewFor<CPDF_Number>("CA", opacity);
+  gs_dict->SetNewFor<CPDF_Number>("ca", opacity);
+  gs_dict->SetNewFor<CPDF_Boolean>("AIS", false);
+  gs_dict->SetNewFor<CPDF_Name>("BM", blend_mode);
+
+  auto resources_dict =
+      pdfium::MakeRetain<CPDF_Dictionary>(annot_dict.GetByteStringPool());
+  resources_dict->SetFor(kGSDictName, std::move(gs_dict));
+  return resources_dict;
 }
 
-RetainPtr<CPDF_Dictionary> GenerateResourceDict(
-    CPDF_Document* pDoc,
-    RetainPtr<CPDF_Dictionary> pExtGStateDict,
-    RetainPtr<CPDF_Dictionary> pResourceFontDict) {
-  auto pResourceDict = pDoc->New<CPDF_Dictionary>();
-  if (pExtGStateDict)
-    pResourceDict->SetFor("ExtGState", pExtGStateDict);
-  if (pResourceFontDict)
-    pResourceDict->SetFor("Font", pResourceFontDict);
-  return pResourceDict;
+RetainPtr<CPDF_Dictionary> GenerateResourcesDict(
+    CPDF_Document* doc,
+    RetainPtr<CPDF_Dictionary> gs_dict,
+    RetainPtr<CPDF_Dictionary> font_resource_dict) {
+  auto resources_dict = doc->New<CPDF_Dictionary>();
+  if (gs_dict) {
+    resources_dict->SetFor("ExtGState", gs_dict);
+  }
+  if (font_resource_dict) {
+    resources_dict->SetFor("Font", font_resource_dict);
+  }
+  return resources_dict;
 }
 
 void GenerateAndSetAPDict(CPDF_Document* doc,
@@ -521,379 +775,668 @@ void GenerateAndSetAPDict(CPDF_Document* doc,
   ap_dict->SetNewFor<CPDF_Reference>("N", doc, normal_stream->GetObjNum());
 }
 
-bool GenerateCircleAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+ByteString GenerateTextFieldAP(const CPDF_Dictionary* annot_dict,
+                               const CFX_FloatRect& body_rect,
+                               float font_size,
+                               CPVT_VariableText& vt) {
+  RetainPtr<const CPDF_Object> v_field =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, pdfium::form_fields::kV);
+  WideString value = v_field ? v_field->GetUnicodeText() : WideString();
+  RetainPtr<const CPDF_Object> q_field =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, "Q");
+  const int32_t align = q_field ? q_field->GetInteger() : 0;
+  RetainPtr<const CPDF_Object> ff_field =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, pdfium::form_fields::kFf);
+  const uint32_t flags = ff_field ? ff_field->GetInteger() : 0;
+  RetainPtr<const CPDF_Object> max_len_field =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, "MaxLen");
+  const uint32_t max_len = max_len_field ? max_len_field->GetInteger() : 0;
+  vt.SetPlateRect(body_rect);
+  vt.SetAlignment(align);
+  SetVtFontSize(font_size, vt);
+
+  bool is_multi_line = (flags >> 12) & 1;
+  if (is_multi_line) {
+    vt.SetMultiLine(true);
+    vt.SetAutoReturn(true);
+  }
+  uint16_t sub_word = 0;
+  if ((flags >> 13) & 1) {
+    sub_word = '*';
+    vt.SetPasswordChar(sub_word);
+  }
+  bool is_char_array = (flags >> 24) & 1;
+  if (is_char_array) {
+    vt.SetCharArray(max_len);
+  } else {
+    vt.SetLimitChar(max_len);
+  }
+
+  vt.Initialize();
+  vt.SetText(value);
+  vt.RearrangeAll();
+  CFX_PointF offset;
+  if (!is_multi_line) {
+    offset = CFX_PointF(
+        0.0f, (vt.GetContentRect().Height() - body_rect.Height()) / 2.0f);
+  }
+  return GenerateEditAP(vt.GetProvider()->GetFontMap(), vt.GetIterator(),
+                        offset, !is_char_array, sub_word);
+}
+
+ByteString GenerateComboBoxAP(const CPDF_Dictionary* annot_dict,
+                              const CFX_FloatRect& body_rect,
+                              const CFX_Color& text_color,
+                              float font_size,
+                              CPVT_VariableText::Provider& provider) {
+  fxcrt::ostringstream body_stream;
+
+  RetainPtr<const CPDF_Object> v_field =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, pdfium::form_fields::kV);
+  WideString value = v_field ? v_field->GetUnicodeText() : WideString();
+  CPVT_VariableText vt(&provider);
+  CFX_FloatRect button_rect = body_rect;
+  button_rect.left = button_rect.right - 13;
+  button_rect.Normalize();
+  CFX_FloatRect edit_rect = body_rect;
+  edit_rect.right = button_rect.left;
+  edit_rect.Normalize();
+  vt.SetPlateRect(edit_rect);
+  SetVtFontSize(font_size, vt);
 
-  RetainPtr<const CPDF_Array> pInteriorColor = pAnnotDict->GetArrayFor("IC");
-  sAppStream << GetColorStringWithDefault(
-      pInteriorColor.Get(), CFX_Color(CFX_Color::Type::kTransparent),
+  vt.Initialize();
+  vt.SetText(value);
+  vt.RearrangeAll();
+  CFX_FloatRect content_rect = vt.GetContentRect();
+  CFX_PointF offset =
+      CFX_PointF(0.0f, (content_rect.Height() - edit_rect.Height()) / 2.0f);
+  ByteString edit =
+      GenerateEditAP(provider.GetFontMap(), vt.GetIterator(), offset, true, 0);
+  if (edit.GetLength() > 0) {
+    body_stream << "/Tx BMC\nq\n";
+    WriteRect(body_stream, edit_rect) << " re\nW\nn\n";
+    body_stream << "BT\n"
+                << GenerateColorAP(text_color, PaintOperation::kFill) << edit
+                << "ET\n"
+                << "Q\nEMC\n";
+  }
+  ByteString button =
+      GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 220.0f / 255.0f,
+                                220.0f / 255.0f, 220.0f / 255.0f),
+                      PaintOperation::kFill);
+  if (button.GetLength() > 0 && !button_rect.IsEmpty()) {
+    body_stream << "q\n" << button;
+    WriteRect(body_stream, button_rect) << " re f\n";
+    body_stream << "Q\n";
+    static const BorderStyleInfo kButtonBorderStyleInfo{
+        .width = 2, .style = BorderStyle::kBeveled, .dash_pattern{3, 0, 0}};
+    ByteString button_border =
+        GenerateBorderAP(button_rect, kButtonBorderStyleInfo,
+                         CFX_Color(CFX_Color::Type::kGray, 0));
+    if (button_border.GetLength() > 0) {
+      body_stream << "q\n" << button_border << "Q\n";
+    }
+
+    CFX_PointF center((button_rect.left + button_rect.right) / 2,
+                      (button_rect.top + button_rect.bottom) / 2);
+    if (FXSYS_IsFloatBigger(button_rect.Width(), 6) &&
+        FXSYS_IsFloatBigger(button_rect.Height(), 6)) {
+      body_stream << "q\n0 g\n";
+      WritePoint(body_stream, {center.x - 3, center.y + 1.5f}) << " m\n";
+      WritePoint(body_stream, {center.x + 3, center.y + 1.5f}) << " l\n";
+      WritePoint(body_stream, {center.x, center.y - 1.5f}) << " l\n";
+      WritePoint(body_stream, {center.x - 3, center.y + 1.5f}) << " l f\n";
+      body_stream << button << "Q\n";
+    }
+  }
+  return ByteString(body_stream);
+}
+
+ByteString GenerateListBoxAP(const CPDF_Dictionary* annot_dict,
+                             const CFX_FloatRect& body_rect,
+                             const CFX_Color& text_color,
+                             float font_size,
+                             CPVT_VariableText::Provider& provider) {
+  RetainPtr<const CPDF_Array> opts =
+      ToArray(CPDF_FormField::GetFieldAttrForDict(annot_dict, "Opt"));
+  if (!opts) {
+    return ByteString();
+  }
+
+  RetainPtr<const CPDF_Array> selections =
+      ToArray(CPDF_FormField::GetFieldAttrForDict(annot_dict, "I"));
+  RetainPtr<const CPDF_Object> top_index =
+      CPDF_FormField::GetFieldAttrForDict(annot_dict, "TI");
+  const int32_t top = top_index ? top_index->GetInteger() : 0;
+  fxcrt::ostringstream body_stream;
+
+  float fy = body_rect.top;
+  for (size_t i = top, sz = opts->size(); i < sz; i++) {
+    if (FXSYS_IsFloatSmaller(fy, body_rect.bottom)) {
+      break;
+    }
+
+    if (RetainPtr<const CPDF_Object> opt = opts->GetDirectObjectAt(i)) {
+      WideString item;
+      if (opt->IsString()) {
+        item = opt->GetUnicodeText();
+      } else if (const CPDF_Array* opt_array = opt->AsArray()) {
+        RetainPtr<const CPDF_Object> opt_item = opt_array->GetDirectObjectAt(1);
+        if (opt_item) {
+          item = opt_item->GetUnicodeText();
+        }
+      }
+      bool is_selected = false;
+      if (selections) {
+        for (size_t s = 0, ssz = selections->size(); s < ssz; s++) {
+          int value = selections->GetIntegerAt(s);
+          if (value >= 0 && i == static_cast<size_t>(value)) {
+            is_selected = true;
+            break;
+          }
+        }
+      }
+      CPVT_VariableText vt(&provider);
+      vt.SetPlateRect(
+          CFX_FloatRect(body_rect.left, 0.0f, body_rect.right, 0.0f));
+      vt.SetFontSize(FXSYS_IsFloatZero(font_size) ? 12.0f : font_size);
+      vt.Initialize();
+      vt.SetText(item);
+      vt.RearrangeAll();
+
+      const float item_height = vt.GetContentRect().Height();
+      if (is_selected) {
+        CFX_FloatRect item_rect = CFX_FloatRect(
+            body_rect.left, fy - item_height, body_rect.right, fy);
+        body_stream << "q\n"
+                    << GenerateColorAP(
+                           CFX_Color(CFX_Color::Type::kRGB, 0, 51.0f / 255.0f,
+                                     113.0f / 255.0f),
+                           PaintOperation::kFill);
+        WriteRect(body_stream, item_rect) << " re f\nQ\n";
+        body_stream << "BT\n"
+                    << GenerateColorAP(CFX_Color(CFX_Color::Type::kGray, 1),
+                                       PaintOperation::kFill)
+                    << GenerateEditAP(provider.GetFontMap(), vt.GetIterator(),
+                                      CFX_PointF(0.0f, fy), true, 0)
+                    << "ET\n";
+      } else {
+        body_stream << "BT\n"
+                    << GenerateColorAP(text_color, PaintOperation::kFill)
+                    << GenerateEditAP(provider.GetFontMap(), vt.GetIterator(),
+                                      CFX_PointF(0.0f, fy), true, 0)
+                    << "ET\n";
+      }
+      fy -= item_height;
+    }
+  }
+  return ByteString(body_stream);
+}
+
+bool GenerateCircleAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
+
+  RetainPtr<const CPDF_Array> interior_color = annot_dict->GetArrayFor("IC");
+  app_stream << GetColorStringWithDefault(
+      interior_color.Get(), CFX_Color(CFX_Color::Type::kTransparent),
       PaintOperation::kFill);
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  float fBorderWidth = GetBorderWidth(pAnnotDict);
-  bool bIsStrokeRect = fBorderWidth > 0;
+  float border_width = GetBorderWidth(annot_dict);
+  bool is_stroke_rect = border_width > 0;
 
-  if (bIsStrokeRect) {
-    sAppStream << fBorderWidth << " w ";
-    sAppStream << GetDashPatternString(pAnnotDict);
+  if (is_stroke_rect) {
+    app_stream << border_width << " w ";
+    app_stream << GetDashPatternString(annot_dict);
   }
 
-  CFX_FloatRect rect = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
   rect.Normalize();
 
-  if (bIsStrokeRect) {
+  if (is_stroke_rect) {
     // Deflating rect because stroking a path entails painting all points
     // whose perpendicular distance from the path in user space is less than
     // or equal to half the line width.
-    rect.Deflate(fBorderWidth / 2, fBorderWidth / 2);
+    rect.Deflate(border_width / 2, border_width / 2);
   }
 
-  const float fMiddleX = (rect.left + rect.right) / 2;
-  const float fMiddleY = (rect.top + rect.bottom) / 2;
+  const float middle_x = (rect.left + rect.right) / 2;
+  const float middle_y = (rect.top + rect.bottom) / 2;
 
-  // |fL| is precalculated approximate value of 4 * tan((3.14 / 2) / 4) / 3,
-  // where |fL| * radius is a good approximation of control points for
+  // `kL` is precalculated approximate value of 4 * tan((3.14 / 2) / 4) / 3,
+  // where `kL` * radius is a good approximation of control points for
   // arc with 90 degrees.
-  const float fL = 0.5523f;
-  const float fDeltaX = fL * rect.Width() / 2.0;
-  const float fDeltaY = fL * rect.Height() / 2.0;
+  static constexpr float kL = 0.5523f;
+  const float delta_x = kL * rect.Width() / 2.0;
+  const float delta_y = kL * rect.Height() / 2.0;
 
   // Starting point
-  sAppStream << fMiddleX << " " << rect.top << " m\n";
+  app_stream << middle_x << " " << rect.top << " m\n";
   // First Bezier Curve
-  sAppStream << fMiddleX + fDeltaX << " " << rect.top << " " << rect.right
-             << " " << fMiddleY + fDeltaY << " " << rect.right << " "
-             << fMiddleY << " c\n";
+  app_stream << middle_x + delta_x << " " << rect.top << " " << rect.right
+             << " " << middle_y + delta_y << " " << rect.right << " "
+             << middle_y << " c\n";
   // Second Bezier Curve
-  sAppStream << rect.right << " " << fMiddleY - fDeltaY << " "
-             << fMiddleX + fDeltaX << " " << rect.bottom << " " << fMiddleX
+  app_stream << rect.right << " " << middle_y - delta_y << " "
+             << middle_x + delta_x << " " << rect.bottom << " " << middle_x
              << " " << rect.bottom << " c\n";
   // Third Bezier Curve
-  sAppStream << fMiddleX - fDeltaX << " " << rect.bottom << " " << rect.left
-             << " " << fMiddleY - fDeltaY << " " << rect.left << " " << fMiddleY
+  app_stream << middle_x - delta_x << " " << rect.bottom << " " << rect.left
+             << " " << middle_y - delta_y << " " << rect.left << " " << middle_y
              << " c\n";
   // Fourth Bezier Curve
-  sAppStream << rect.left << " " << fMiddleY + fDeltaY << " "
-             << fMiddleX - fDeltaX << " " << rect.top << " " << fMiddleX << " "
+  app_stream << rect.left << " " << middle_y + delta_y << " "
+             << middle_x - delta_x << " " << rect.top << " " << middle_x << " "
              << rect.top << " c\n";
 
-  bool bIsFillRect = pInteriorColor && !pInteriorColor->IsEmpty();
-  sAppStream << GetPaintOperatorString(bIsStrokeRect, bIsFillRect) << "\n";
+  bool is_fill_rect = interior_color && !interior_color->IsEmpty();
+  app_stream << GetPaintOperatorString(is_stroke_rect, is_fill_rect) << "\n";
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        false /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateHighlightAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateFreeTextAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  RetainPtr<CPDF_Dictionary> root_dict = doc->GetMutableRoot();
+  if (!root_dict) {
+    return false;
+  }
+
+  RetainPtr<CPDF_Dictionary> form_dict =
+      root_dict->GetMutableDictFor("AcroForm");
+  if (!form_dict) {
+    form_dict = CPDF_InteractiveForm::InitAcroFormDict(doc);
+    CHECK(form_dict);
+  }
+
+  std::optional<DefaultAppearanceInfo> default_appearance_info =
+      GetDefaultAppearanceInfo(
+          GetDefaultAppearanceString(annot_dict, form_dict));
+  if (!default_appearance_info.has_value()) {
+    return false;
+  }
+
+  RetainPtr<CPDF_Dictionary> dr_dict = form_dict->GetMutableDictFor("DR");
+  if (!dr_dict) {
+    return false;
+  }
+
+  RetainPtr<CPDF_Dictionary> dr_font_dict = dr_dict->GetMutableDictFor("Font");
+  if (!ValidateFontResourceDict(dr_font_dict.Get())) {
+    return false;
+  }
+
+  const ByteString& font_name = default_appearance_info.value().font_name;
+  RetainPtr<CPDF_Dictionary> font_dict =
+      GetFontFromDrFontDictOrGenerateFallback(doc, dr_font_dict, font_name);
+  auto* doc_page_data = CPDF_DocPageData::FromDocument(doc);
+  RetainPtr<CPDF_Font> default_font = doc_page_data->GetFont(font_dict);
+  if (!default_font) {
+    return false;
+  }
+
+  fxcrt::ostringstream appearance_stream;
+  appearance_stream << "/" << kGSDictName << " gs ";
+
+  const BorderStyleInfo border_style_info =
+      GetBorderStyleInfo(annot_dict->GetDictFor("BS"));
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
+  const float half_border_width = border_style_info.width / 2.0f;
+  CFX_FloatRect background_rect = rect;
+  background_rect.Deflate(half_border_width, half_border_width);
+  CFX_FloatRect body_rect = background_rect;
+  body_rect.Deflate(half_border_width, half_border_width);
+
+  auto color_array = annot_dict->GetArrayFor(pdfium::annotation::kC);
+  if (color_array) {
+    CFX_Color color = fpdfdoc::CFXColorFromArray(*color_array);
+    appearance_stream << "q\n" << GenerateColorAP(color, PaintOperation::kFill);
+    WriteRect(appearance_stream, background_rect) << " re f\nQ\n";
+  }
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  const CFX_Color& text_color = default_appearance_info.value().text_color;
+  const ByteString border_stream =
+      GenerateBorderAP(rect, border_style_info, text_color);
+  if (border_stream.GetLength() > 0) {
+    appearance_stream << "q\n" << border_stream << "Q\n";
+  }
+
+  CPVT_FontMap map(doc, nullptr, std::move(default_font), font_name);
+  CPVT_VariableText::Provider provider(&map);
+  CPVT_VariableText vt(&provider);
+
+  vt.SetPlateRect(body_rect);
+  vt.SetAlignment(annot_dict->GetIntegerFor("Q"));
+  SetVtFontSize(default_appearance_info.value().font_size, vt);
+
+  vt.Initialize();
+  vt.SetText(annot_dict->GetUnicodeTextFor(pdfium::annotation::kContents));
+  vt.RearrangeAll();
+  const CFX_FloatRect content_rect = vt.GetContentRect();
+  CFX_PointF offset(0.0f, (content_rect.Height() - body_rect.Height()) / 2.0f);
+  const ByteString body =
+      GenerateEditAP(vt.GetProvider()->GetFontMap(), vt.GetIterator(), offset,
+                     /*continuous=*/true, /*sub_word=*/0);
+  if (body.GetLength() > 0) {
+    appearance_stream << "/Tx BMC\n" << "q\n";
+    if (content_rect.Width() > body_rect.Width() ||
+        content_rect.Height() > body_rect.Height()) {
+      WriteRect(appearance_stream, body_rect) << " re\nW\nn\n";
+    }
+    appearance_stream << "BT\n"
+                      << GenerateColorAP(text_color, PaintOperation::kFill)
+                      << body << "ET\n"
+                      << "Q\nEMC\n";
+  }
+
+  auto graphics_state_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resource_font_dict =
+      GenerateResourceFontDict(doc, font_name, font_dict->GetObjNum());
+  auto resource_dict = GenerateResourcesDict(
+      doc, std::move(graphics_state_dict), std::move(resource_font_dict));
+  GenerateAndSetAPDict(doc, annot_dict, &appearance_stream,
+                       std::move(resource_dict),
+                       /*is_text_markup_annotation=*/false);
+  return true;
+}
+
+bool GenerateHighlightAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
+
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 1, 1, 0), PaintOperation::kFill);
 
-  RetainPtr<const CPDF_Array> pArray = pAnnotDict->GetArrayFor("QuadPoints");
-  if (pArray) {
-    size_t nQuadPointCount = CPDF_Annot::QuadPointCount(pArray.Get());
-    for (size_t i = 0; i < nQuadPointCount; ++i) {
-      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(pAnnotDict, i);
+  RetainPtr<const CPDF_Array> quad_points_array =
+      annot_dict->GetArrayFor("QuadPoints");
+  if (quad_points_array) {
+    const size_t quad_point_count =
+        CPDF_Annot::QuadPointCount(quad_points_array.Get());
+    for (size_t i = 0; i < quad_point_count; ++i) {
+      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(annot_dict, i);
       rect.Normalize();
 
-      sAppStream << rect.left << " " << rect.top << " m " << rect.right << " "
+      app_stream << rect.left << " " << rect.top << " m " << rect.right << " "
                  << rect.top << " l " << rect.right << " " << rect.bottom
                  << " l " << rect.left << " " << rect.bottom << " l h f\n";
     }
   }
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Multiply");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Multiply");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        true /*IsTextMarkupAnnotation*/);
 
   return true;
 }
 
-bool GenerateInkAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  RetainPtr<const CPDF_Array> pInkList = pAnnotDict->GetArrayFor("InkList");
-  if (!pInkList || pInkList->IsEmpty())
+bool GenerateInkAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  RetainPtr<const CPDF_Array> ink_list = annot_dict->GetArrayFor("InkList");
+  if (!ink_list || ink_list->IsEmpty()) {
     return false;
+  }
 
-  float fBorderWidth = GetBorderWidth(pAnnotDict);
-  const bool bIsStroke = fBorderWidth > 0;
-  if (!bIsStroke)
+  float border_width = GetBorderWidth(annot_dict);
+  const bool is_stroke = border_width > 0;
+  if (!is_stroke) {
     return false;
+  }
 
-  ByteString sExtGSDictName = "GS";
-  fxcrt::ostringstream sAppStream;
-  sAppStream << "/" << sExtGSDictName << " gs ";
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  sAppStream << fBorderWidth << " w ";
-  sAppStream << GetDashPatternString(pAnnotDict);
+  app_stream << border_width << " w ";
+  app_stream << GetDashPatternString(annot_dict);
 
   // Set inflated rect as a new rect because paths near the border with large
   // width should not be clipped to the original rect.
-  CFX_FloatRect rect = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
-  rect.Inflate(fBorderWidth / 2, fBorderWidth / 2);
-  pAnnotDict->SetRectFor(pdfium::annotation::kRect, rect);
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
+  rect.Inflate(border_width / 2, border_width / 2);
+  annot_dict->SetRectFor(pdfium::annotation::kRect, rect);
 
-  for (size_t i = 0; i < pInkList->size(); i++) {
-    RetainPtr<const CPDF_Array> pInkCoordList = pInkList->GetArrayAt(i);
-    if (!pInkCoordList || pInkCoordList->size() < 2)
+  for (size_t i = 0; i < ink_list->size(); i++) {
+    RetainPtr<const CPDF_Array> coordinates_array = ink_list->GetArrayAt(i);
+    if (!coordinates_array || coordinates_array->size() < 2) {
       continue;
+    }
 
-    sAppStream << pInkCoordList->GetFloatAt(0) << " "
-               << pInkCoordList->GetFloatAt(1) << " m ";
+    app_stream << coordinates_array->GetFloatAt(0) << " "
+               << coordinates_array->GetFloatAt(1) << " m ";
 
-    for (size_t j = 0; j < pInkCoordList->size() - 1; j += 2) {
-      sAppStream << pInkCoordList->GetFloatAt(j) << " "
-                 << pInkCoordList->GetFloatAt(j + 1) << " l ";
+    for (size_t j = 0; j < coordinates_array->size() - 1; j += 2) {
+      app_stream << coordinates_array->GetFloatAt(j) << " "
+                 << coordinates_array->GetFloatAt(j + 1) << " l ";
     }
 
-    sAppStream << "S\n";
+    app_stream << "S\n";
   }
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        false /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateTextAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateTextAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
 
-  CFX_FloatRect rect = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
-  const float fNoteLength = 20;
-  CFX_FloatRect noteRect(rect.left, rect.bottom, rect.left + fNoteLength,
-                         rect.bottom + fNoteLength);
-  pAnnotDict->SetRectFor(pdfium::annotation::kRect, noteRect);
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
+  const float note_length = 20;
+  CFX_FloatRect note_rect(rect.left, rect.bottom, rect.left + note_length,
+                          rect.bottom + note_length);
+  annot_dict->SetRectFor(pdfium::annotation::kRect, note_rect);
 
-  sAppStream << GenerateTextSymbolAP(noteRect);
+  app_stream << GenerateTextSymbolAP(note_rect);
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        false /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateUnderlineAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateUnderlineAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  RetainPtr<const CPDF_Array> pArray = pAnnotDict->GetArrayFor("QuadPoints");
-  if (pArray) {
+  RetainPtr<const CPDF_Array> quad_points_array =
+      annot_dict->GetArrayFor("QuadPoints");
+  if (quad_points_array) {
     static constexpr int kLineWidth = 1;
-    sAppStream << kLineWidth << " w ";
-    size_t nQuadPointCount = CPDF_Annot::QuadPointCount(pArray.Get());
-    for (size_t i = 0; i < nQuadPointCount; ++i) {
-      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(pAnnotDict, i);
+    app_stream << kLineWidth << " w ";
+    const size_t quad_point_count =
+        CPDF_Annot::QuadPointCount(quad_points_array.Get());
+    for (size_t i = 0; i < quad_point_count; ++i) {
+      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(annot_dict, i);
       rect.Normalize();
-      sAppStream << rect.left << " " << rect.bottom + kLineWidth << " m "
+      app_stream << rect.left << " " << rect.bottom + kLineWidth << " m "
                  << rect.right << " " << rect.bottom + kLineWidth << " l S\n";
     }
   }
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        true /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GeneratePopupAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs\n";
+bool GeneratePopupAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs\n";
 
-  sAppStream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 1, 1, 0),
+  app_stream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 1, 1, 0),
                                 PaintOperation::kFill);
-  sAppStream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0),
+  app_stream << GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0),
                                 PaintOperation::kStroke);
 
-  const float fBorderWidth = 1;
-  sAppStream << fBorderWidth << " w\n";
+  const float border_width = 1;
+  app_stream << border_width << " w\n";
 
-  CFX_FloatRect rect = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
   rect.Normalize();
-  rect.Deflate(fBorderWidth / 2, fBorderWidth / 2);
+  rect.Deflate(border_width / 2, border_width / 2);
 
-  sAppStream << rect.left << " " << rect.bottom << " " << rect.Width() << " "
+  app_stream << rect.left << " " << rect.bottom << " " << rect.Width() << " "
              << rect.Height() << " re b\n";
 
-  RetainPtr<CPDF_Dictionary> font_dict = GenerateFallbackFontDict(pDoc);
-  auto* pData = CPDF_DocPageData::FromDocument(pDoc);
-  RetainPtr<CPDF_Font> pDefFont = pData->GetFont(font_dict);
-  if (!pDefFont)
+  RetainPtr<CPDF_Dictionary> font_dict = GenerateFallbackFontDict(doc);
+  auto* doc_page_data = CPDF_DocPageData::FromDocument(doc);
+  RetainPtr<CPDF_Font> default_font = doc_page_data->GetFont(font_dict);
+  if (!default_font) {
     return false;
+  }
 
   const ByteString font_name = "FONT";
   RetainPtr<CPDF_Dictionary> resource_font_dict =
-      GenerateResourceFontDict(pDoc, font_name, font_dict->GetObjNum());
-  RetainPtr<CPDF_Dictionary> pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  RetainPtr<CPDF_Dictionary> pResourceDict = GenerateResourceDict(
-      pDoc, std::move(pExtGStateDict), std::move(resource_font_dict));
-
-  sAppStream << GetPopupContentsString(pDoc, *pAnnotDict, std::move(pDefFont),
-                                       font_name);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+      GenerateResourceFontDict(doc, font_name, font_dict->GetObjNum());
+  RetainPtr<CPDF_Dictionary> gs_dict =
+      GenerateExtGStateDict(*annot_dict, "Normal");
+  RetainPtr<CPDF_Dictionary> resources_dict = GenerateResourcesDict(
+      doc, std::move(gs_dict), std::move(resource_font_dict));
+
+  app_stream << GetPopupContentsString(doc, *annot_dict,
+                                       std::move(default_font), font_name);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        false /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateSquareAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  const ByteString sExtGSDictName = "GS";
-  fxcrt::ostringstream sAppStream;
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateSquareAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
 
-  RetainPtr<const CPDF_Array> pInteriorColor = pAnnotDict->GetArrayFor("IC");
-  sAppStream << GetColorStringWithDefault(
-      pInteriorColor.Get(), CFX_Color(CFX_Color::Type::kTransparent),
+  RetainPtr<const CPDF_Array> interior_color = annot_dict->GetArrayFor("IC");
+  app_stream << GetColorStringWithDefault(
+      interior_color.Get(), CFX_Color(CFX_Color::Type::kTransparent),
       PaintOperation::kFill);
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  float fBorderWidth = GetBorderWidth(pAnnotDict);
-  const bool bIsStrokeRect = fBorderWidth > 0;
-  if (bIsStrokeRect) {
-    sAppStream << fBorderWidth << " w ";
-    sAppStream << GetDashPatternString(pAnnotDict);
+  float border_width = GetBorderWidth(annot_dict);
+  const bool is_stroke_rect = border_width > 0;
+  if (is_stroke_rect) {
+    app_stream << border_width << " w ";
+    app_stream << GetDashPatternString(annot_dict);
   }
 
-  CFX_FloatRect rect = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
+  CFX_FloatRect rect = annot_dict->GetRectFor(pdfium::annotation::kRect);
   rect.Normalize();
 
-  if (bIsStrokeRect) {
+  if (is_stroke_rect) {
     // Deflating rect because stroking a path entails painting all points
     // whose perpendicular distance from the path in user space is less than
     // or equal to half the line width.
-    rect.Deflate(fBorderWidth / 2, fBorderWidth / 2);
+    rect.Deflate(border_width / 2, border_width / 2);
   }
 
-  const bool bIsFillRect = pInteriorColor && (pInteriorColor->size() > 0);
-  sAppStream << rect.left << " " << rect.bottom << " " << rect.Width() << " "
+  const bool is_fill_rect = interior_color && (interior_color->size() > 0);
+  app_stream << rect.left << " " << rect.bottom << " " << rect.Width() << " "
              << rect.Height() << " re "
-             << GetPaintOperatorString(bIsStrokeRect, bIsFillRect) << "\n";
+             << GetPaintOperatorString(is_stroke_rect, is_fill_rect) << "\n";
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        false /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateSquigglyAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateSquigglyAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  RetainPtr<const CPDF_Array> pArray = pAnnotDict->GetArrayFor("QuadPoints");
-  if (pArray) {
+  RetainPtr<const CPDF_Array> quad_points_array =
+      annot_dict->GetArrayFor("QuadPoints");
+  if (quad_points_array) {
     static constexpr int kLineWidth = 1;
     static constexpr int kDelta = 2;
-    sAppStream << kLineWidth << " w ";
-    size_t nQuadPointCount = CPDF_Annot::QuadPointCount(pArray.Get());
-    for (size_t i = 0; i < nQuadPointCount; ++i) {
-      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(pAnnotDict, i);
+    app_stream << kLineWidth << " w ";
+    const size_t quad_point_count =
+        CPDF_Annot::QuadPointCount(quad_points_array.Get());
+    for (size_t i = 0; i < quad_point_count; ++i) {
+      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(annot_dict, i);
       rect.Normalize();
 
-      const float fTop = rect.bottom + kDelta;
-      const float fBottom = rect.bottom;
-      sAppStream << rect.left << " " << fTop << " m ";
+      const float top = rect.bottom + kDelta;
+      const float bottom = rect.bottom;
+      app_stream << rect.left << " " << top << " m ";
 
-      float fX = rect.left + kDelta;
+      float x = rect.left + kDelta;
       bool isUpwards = false;
-      while (fX < rect.right) {
-        sAppStream << fX << " " << (isUpwards ? fTop : fBottom) << " l ";
-        fX += kDelta;
+      while (x < rect.right) {
+        app_stream << x << " " << (isUpwards ? top : bottom) << " l ";
+        x += kDelta;
         isUpwards = !isUpwards;
       }
 
-      float fRemainder = rect.right - (fX - kDelta);
+      float remainder = rect.right - (x - kDelta);
       if (isUpwards)
-        sAppStream << rect.right << " " << fBottom + fRemainder << " l ";
+        app_stream << rect.right << " " << bottom + remainder << " l ";
       else
-        sAppStream << rect.right << " " << fTop - fRemainder << " l ";
+        app_stream << rect.right << " " << top - remainder << " l ";
 
-      sAppStream << "S\n";
+      app_stream << "S\n";
     }
   }
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        true /*IsTextMarkupAnnotation*/);
   return true;
 }
 
-bool GenerateStrikeOutAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
-  fxcrt::ostringstream sAppStream;
-  ByteString sExtGSDictName = "GS";
-  sAppStream << "/" << sExtGSDictName << " gs ";
+bool GenerateStrikeOutAP(CPDF_Document* doc, CPDF_Dictionary* annot_dict) {
+  fxcrt::ostringstream app_stream;
+  app_stream << "/" << kGSDictName << " gs ";
 
-  sAppStream << GetColorStringWithDefault(
-      pAnnotDict->GetArrayFor(pdfium::annotation::kC).Get(),
+  app_stream << GetColorStringWithDefault(
+      annot_dict->GetArrayFor(pdfium::annotation::kC).Get(),
       CFX_Color(CFX_Color::Type::kRGB, 0, 0, 0), PaintOperation::kStroke);
 
-  RetainPtr<const CPDF_Array> pArray = pAnnotDict->GetArrayFor("QuadPoints");
-  if (pArray) {
-    size_t nQuadPointCount = CPDF_Annot::QuadPointCount(pArray.Get());
-    for (size_t i = 0; i < nQuadPointCount; ++i) {
-      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(pAnnotDict, i);
+  RetainPtr<const CPDF_Array> quad_points_array =
+      annot_dict->GetArrayFor("QuadPoints");
+  if (quad_points_array) {
+    const size_t quad_point_count =
+        CPDF_Annot::QuadPointCount(quad_points_array.Get());
+    for (size_t i = 0; i < quad_point_count; ++i) {
+      CFX_FloatRect rect = CPDF_Annot::RectFromQuadPoints(annot_dict, i);
       rect.Normalize();
 
-      float fY = (rect.top + rect.bottom) / 2;
-      constexpr int kLineWidth = 1;
-      sAppStream << kLineWidth << " w " << rect.left << " " << fY << " m "
-                 << rect.right << " " << fY << " l S\n";
+      float y = (rect.top + rect.bottom) / 2;
+      static constexpr int kLineWidth = 1;
+      app_stream << kLineWidth << " w " << rect.left << " " << y << " m "
+                 << rect.right << " " << y << " l S\n";
     }
   }
 
-  auto pExtGStateDict =
-      GenerateExtGStateDict(*pAnnotDict, sExtGSDictName, "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sAppStream, std::move(pResourceDict),
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+  GenerateAndSetAPDict(doc, annot_dict, &app_stream, std::move(resources_dict),
                        true /*IsTextMarkupAnnotation*/);
   return true;
 }
@@ -901,463 +1444,180 @@ bool GenerateStrikeOutAP(CPDF_Document* pDoc, CPDF_Dictionary* pAnnotDict) {
 }  // namespace
 
 // static
-void CPDF_GenerateAP::GenerateFormAP(CPDF_Document* pDoc,
-                                     CPDF_Dictionary* pAnnotDict,
+void CPDF_GenerateAP::GenerateFormAP(CPDF_Document* doc,
+                                     CPDF_Dictionary* annot_dict,
                                      FormType type) {
-  RetainPtr<CPDF_Dictionary> pRootDict = pDoc->GetMutableRoot();
-  if (!pRootDict)
+  RetainPtr<CPDF_Dictionary> root_dict = doc->GetMutableRoot();
+  if (!root_dict) {
     return;
+  }
 
-  RetainPtr<CPDF_Dictionary> pFormDict =
-      pRootDict->GetMutableDictFor("AcroForm");
-  if (!pFormDict)
+  RetainPtr<CPDF_Dictionary> form_dict =
+      root_dict->GetMutableDictFor("AcroForm");
+  if (!form_dict) {
     return;
+  }
 
-  ByteString DA;
-  RetainPtr<const CPDF_Object> pDAObj =
-      CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "DA");
-  if (pDAObj)
-    DA = pDAObj->GetString();
-  if (DA.IsEmpty())
-    DA = pFormDict->GetByteStringFor("DA");
-  if (DA.IsEmpty())
+  std::optional<DefaultAppearanceInfo> default_appearance_info =
+      GetDefaultAppearanceInfo(
+          GetDefaultAppearanceString(annot_dict, form_dict));
+  if (!default_appearance_info.has_value()) {
     return;
+  }
 
-  CPDF_DefaultAppearance appearance(DA);
-
-  float fFontSize = 0;
-  std::optional<ByteString> font = appearance.GetFont(&fFontSize);
-  if (!font.has_value())
+  RetainPtr<CPDF_Dictionary> dr_dict = form_dict->GetMutableDictFor("DR");
+  if (!dr_dict) {
     return;
+  }
 
-  ByteString font_name = font.value();
-
-  CFX_Color crText = fpdfdoc::CFXColorFromString(DA);
-  RetainPtr<CPDF_Dictionary> pDRDict = pFormDict->GetMutableDictFor("DR");
-  if (!pDRDict)
+  RetainPtr<CPDF_Dictionary> dr_font_dict = dr_dict->GetMutableDictFor("Font");
+  if (!ValidateFontResourceDict(dr_font_dict.Get())) {
     return;
+  }
 
-  RetainPtr<CPDF_Dictionary> pDRFontDict = pDRDict->GetMutableDictFor("Font");
-  if (!ValidateFontResourceDict(pDRFontDict.Get()))
+  const ByteString& font_name = default_appearance_info.value().font_name;
+  RetainPtr<CPDF_Dictionary> font_dict =
+      GetFontFromDrFontDictOrGenerateFallback(doc, dr_font_dict, font_name);
+  auto* doc_page_data = CPDF_DocPageData::FromDocument(doc);
+  RetainPtr<CPDF_Font> default_font = doc_page_data->GetFont(font_dict);
+  if (!default_font) {
     return;
-
-  RetainPtr<CPDF_Dictionary> pFontDict =
-      pDRFontDict->GetMutableDictFor(font_name);
-  if (!pFontDict) {
-    pFontDict = GenerateFallbackFontDict(pDoc);
-    pDRFontDict->SetNewFor<CPDF_Reference>(font_name, pDoc,
-                                           pFontDict->GetObjNum());
   }
-  auto* pData = CPDF_DocPageData::FromDocument(pDoc);
-  RetainPtr<CPDF_Font> pDefFont = pData->GetFont(pFontDict);
-  if (!pDefFont)
-    return;
 
-  CFX_FloatRect rcAnnot = pAnnotDict->GetRectFor(pdfium::annotation::kRect);
-  RetainPtr<const CPDF_Dictionary> pMKDict = pAnnotDict->GetDictFor("MK");
-  int32_t nRotate =
-      pMKDict ? pMKDict->GetIntegerFor(pdfium::appearance::kR) : 0;
+  const AnnotationDimensionsAndColor annot_dimensions_and_color =
+      GetAnnotationDimensionsAndColor(annot_dict);
+  fxcrt::ostringstream app_stream;
+  const ByteString background = GenerateColorAP(
+      annot_dimensions_and_color.background_color, PaintOperation::kFill);
+  if (background.GetLength() > 0) {
+    app_stream << "q\n" << background;
+    WriteRect(app_stream, annot_dimensions_and_color.bbox) << " re f\nQ\n";
+  }
 
-  CFX_FloatRect rcBBox;
-  CFX_Matrix matrix;
-  switch (nRotate % 360) {
-    case 0:
-      rcBBox = CFX_FloatRect(0, 0, rcAnnot.right - rcAnnot.left,
-                             rcAnnot.top - rcAnnot.bottom);
-      break;
-    case 90:
-      matrix = CFX_Matrix(0, 1, -1, 0, rcAnnot.right - rcAnnot.left, 0);
-      rcBBox = CFX_FloatRect(0, 0, rcAnnot.top - rcAnnot.bottom,
-                             rcAnnot.right - rcAnnot.left);
-      break;
-    case 180:
-      matrix = CFX_Matrix(-1, 0, 0, -1, rcAnnot.right - rcAnnot.left,
-                          rcAnnot.top - rcAnnot.bottom);
-      rcBBox = CFX_FloatRect(0, 0, rcAnnot.right - rcAnnot.left,
-                             rcAnnot.top - rcAnnot.bottom);
-      break;
-    case 270:
-      matrix = CFX_Matrix(0, -1, 1, 0, 0, rcAnnot.top - rcAnnot.bottom);
-      rcBBox = CFX_FloatRect(0, 0, rcAnnot.top - rcAnnot.bottom,
-                             rcAnnot.right - rcAnnot.left);
-      break;
+  const BorderStyleInfo border_style_info =
+      GetBorderStyleInfo(annot_dict->GetDictFor("BS"));
+  const ByteString border_stream =
+      GenerateBorderAP(annot_dimensions_and_color.bbox, border_style_info,
+                       annot_dimensions_and_color.border_color);
+  if (border_stream.GetLength() > 0) {
+    app_stream << "q\n" << border_stream << "Q\n";
   }
 
-  BorderStyle nBorderStyle = BorderStyle::kSolid;
-  float fBorderWidth = 1;
-  CPVT_Dash dsBorder(3, 0, 0);
-  CFX_Color crLeftTop;
-  CFX_Color crRightBottom;
-  if (RetainPtr<const CPDF_Dictionary> pBSDict = pAnnotDict->GetDictFor("BS")) {
-    if (pBSDict->KeyExist("W"))
-      fBorderWidth = pBSDict->GetFloatFor("W");
+  CFX_FloatRect body_rect = annot_dimensions_and_color.bbox;
+  body_rect.Deflate(border_style_info.width, border_style_info.width);
 
-    if (RetainPtr<const CPDF_Array> pArray = pBSDict->GetArrayFor("D")) {
-      dsBorder = CPVT_Dash(pArray->GetIntegerAt(0), pArray->GetIntegerAt(1),
-                           pArray->GetIntegerAt(2));
-    }
-    if (pBSDict->GetByteStringFor("S").GetLength()) {
-      switch (pBSDict->GetByteStringFor("S")[0]) {
-        case 'S':
-          nBorderStyle = BorderStyle::kSolid;
-          break;
-        case 'D':
-          nBorderStyle = BorderStyle::kDash;
-          break;
-        case 'B':
-          nBorderStyle = BorderStyle::kBeveled;
-          fBorderWidth *= 2;
-          crLeftTop = CFX_Color(CFX_Color::Type::kGray, 1);
-          crRightBottom = CFX_Color(CFX_Color::Type::kGray, 0.5);
-          break;
-        case 'I':
-          nBorderStyle = BorderStyle::kInset;
-          fBorderWidth *= 2;
-          crLeftTop = CFX_Color(CFX_Color::Type::kGray, 0.5);
-          crRightBottom = CFX_Color(CFX_Color::Type::kGray, 0.75);
-          break;
-        case 'U':
-          nBorderStyle = BorderStyle::kUnderline;
-          break;
+  RetainPtr<CPDF_Dictionary> ap_dict =
+      annot_dict->GetOrCreateDictFor(pdfium::annotation::kAP);
+  RetainPtr<CPDF_Stream> normal_stream = ap_dict->GetMutableStreamFor("N");
+  RetainPtr<CPDF_Dictionary> resources_dict;
+  if (normal_stream) {
+    RetainPtr<CPDF_Dictionary> stream_dict = normal_stream->GetMutableDict();
+    const bool cloned =
+        CloneResourcesDictIfMissingFromStream(stream_dict, dr_dict);
+    if (!cloned) {
+      if (!ValidateOrCreateFontResources(doc, stream_dict, font_dict,
+                                         font_name)) {
+        return;
       }
     }
-  }
-  CFX_Color crBorder;
-  CFX_Color crBG;
-  if (pMKDict) {
-    RetainPtr<const CPDF_Array> pArray =
-        pMKDict->GetArrayFor(pdfium::appearance::kBC);
-    if (pArray)
-      crBorder = fpdfdoc::CFXColorFromArray(*pArray);
-    pArray = pMKDict->GetArrayFor(pdfium::appearance::kBG);
-    if (pArray)
-      crBG = fpdfdoc::CFXColorFromArray(*pArray);
-  }
-  fxcrt::ostringstream sAppStream;
-  ByteString sBG = GenerateColorAP(crBG, PaintOperation::kFill);
-  if (sBG.GetLength() > 0) {
-    sAppStream << "q\n" << sBG;
-    WriteRect(sAppStream, rcBBox) << " re f\nQ\n";
-  }
-  ByteString sBorderStream =
-      GenerateBorderAP(rcBBox, fBorderWidth, crBorder, crLeftTop, crRightBottom,
-                       nBorderStyle, dsBorder);
-  if (sBorderStream.GetLength() > 0)
-    sAppStream << "q\n" << sBorderStream << "Q\n";
-
-  CFX_FloatRect rcBody =
-      CFX_FloatRect(rcBBox.left + fBorderWidth, rcBBox.bottom + fBorderWidth,
-                    rcBBox.right - fBorderWidth, rcBBox.top - fBorderWidth);
-  rcBody.Normalize();
-
-  RetainPtr<CPDF_Dictionary> pAPDict =
-      pAnnotDict->GetOrCreateDictFor(pdfium::annotation::kAP);
-  RetainPtr<CPDF_Stream> pNormalStream = pAPDict->GetMutableStreamFor("N");
-  RetainPtr<CPDF_Dictionary> pStreamDict;
-  if (pNormalStream) {
-    pStreamDict = pNormalStream->GetMutableDict();
-    RetainPtr<CPDF_Dictionary> pStreamResList =
-        pStreamDict->GetMutableDictFor("Resources");
-    if (pStreamResList) {
-      RetainPtr<CPDF_Dictionary> pStreamResFontList =
-          pStreamResList->GetMutableDictFor("Font");
-      if (pStreamResFontList) {
-        if (!ValidateFontResourceDict(pStreamResFontList.Get()))
-          return;
-      } else {
-        pStreamResFontList = pStreamResList->SetNewFor<CPDF_Dictionary>("Font");
-      }
-      if (!pStreamResFontList->KeyExist(font_name)) {
-        pStreamResFontList->SetNewFor<CPDF_Reference>(font_name, pDoc,
-                                                      pFontDict->GetObjNum());
-      }
-    } else {
-      pStreamDict->SetFor("Resources", pFormDict->GetDictFor("DR")->Clone());
-    }
-    pStreamDict->SetMatrixFor("Matrix", matrix);
-    pStreamDict->SetRectFor("BBox", rcBBox);
+    resources_dict = stream_dict->GetMutableDictFor("Resources");
   } else {
-    pNormalStream =
-        pDoc->NewIndirect<CPDF_Stream>(pdfium::MakeRetain<CPDF_Dictionary>());
-    pAPDict->SetNewFor<CPDF_Reference>("N", pDoc, pNormalStream->GetObjNum());
+    normal_stream =
+        doc->NewIndirect<CPDF_Stream>(pdfium::MakeRetain<CPDF_Dictionary>());
+    ap_dict->SetNewFor<CPDF_Reference>("N", doc, normal_stream->GetObjNum());
   }
-  CPVT_FontMap map(
-      pDoc, pStreamDict ? pStreamDict->GetMutableDictFor("Resources") : nullptr,
-      std::move(pDefFont), font_name);
-  CPVT_VariableText::Provider prd(&map);
 
+  const float font_size = default_appearance_info.value().font_size;
+  const CFX_Color& text_color = default_appearance_info.value().text_color;
+  CPVT_FontMap map(doc, std::move(resources_dict), std::move(default_font),
+                   font_name);
+  CPVT_VariableText::Provider provider(&map);
   switch (type) {
     case CPDF_GenerateAP::kTextField: {
-      RetainPtr<const CPDF_Object> pV = CPDF_FormField::GetFieldAttrForDict(
-          pAnnotDict, pdfium::form_fields::kV);
-      WideString swValue = pV ? pV->GetUnicodeText() : WideString();
-      RetainPtr<const CPDF_Object> pQ =
-          CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "Q");
-      int32_t nAlign = pQ ? pQ->GetInteger() : 0;
-      RetainPtr<const CPDF_Object> pFf = CPDF_FormField::GetFieldAttrForDict(
-          pAnnotDict, pdfium::form_fields::kFf);
-      uint32_t dwFlags = pFf ? pFf->GetInteger() : 0;
-      RetainPtr<const CPDF_Object> pMaxLen =
-          CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "MaxLen");
-      uint32_t dwMaxLen = pMaxLen ? pMaxLen->GetInteger() : 0;
-      CPVT_VariableText vt(&prd);
-      vt.SetPlateRect(rcBody);
-      vt.SetAlignment(nAlign);
-      if (FXSYS_IsFloatZero(fFontSize))
-        vt.SetAutoFontSize(true);
-      else
-        vt.SetFontSize(fFontSize);
-
-      bool bMultiLine = (dwFlags >> 12) & 1;
-      if (bMultiLine) {
-        vt.SetMultiLine(true);
-        vt.SetAutoReturn(true);
-      }
-      uint16_t subWord = 0;
-      if ((dwFlags >> 13) & 1) {
-        subWord = '*';
-        vt.SetPasswordChar(subWord);
-      }
-      bool bCharArray = (dwFlags >> 24) & 1;
-      if (bCharArray)
-        vt.SetCharArray(dwMaxLen);
-      else
-        vt.SetLimitChar(dwMaxLen);
-
-      vt.Initialize();
-      vt.SetText(swValue);
-      vt.RearrangeAll();
-      CFX_FloatRect rcContent = vt.GetContentRect();
-      CFX_PointF ptOffset;
-      if (!bMultiLine) {
-        ptOffset =
-            CFX_PointF(0.0f, (rcContent.Height() - rcBody.Height()) / 2.0f);
-      }
-      ByteString sBody = GenerateEditAP(&map, vt.GetIterator(), ptOffset,
-                                        !bCharArray, subWord);
-      if (sBody.GetLength() > 0) {
-        sAppStream << "/Tx BMC\n"
-                   << "q\n";
-        if (rcContent.Width() > rcBody.Width() ||
-            rcContent.Height() > rcBody.Height()) {
-          WriteRect(sAppStream, rcBody) << " re\nW\nn\n";
+      CPVT_VariableText vt(&provider);
+      ByteString body =
+          GenerateTextFieldAP(annot_dict, body_rect, font_size, vt);
+      if (body.GetLength() > 0) {
+        const CFX_FloatRect content_rect = vt.GetContentRect();
+        app_stream << "/Tx BMC\n" << "q\n";
+        if (content_rect.Width() > body_rect.Width() ||
+            content_rect.Height() > body_rect.Height()) {
+          WriteRect(app_stream, body_rect) << " re\nW\nn\n";
         }
-        sAppStream << "BT\n"
-                   << GenerateColorAP(crText, PaintOperation::kFill) << sBody
+        app_stream << "BT\n"
+                   << GenerateColorAP(text_color, PaintOperation::kFill) << body
                    << "ET\n"
                    << "Q\nEMC\n";
       }
       break;
     }
     case CPDF_GenerateAP::kComboBox: {
-      RetainPtr<const CPDF_Object> pV = CPDF_FormField::GetFieldAttrForDict(
-          pAnnotDict, pdfium::form_fields::kV);
-      WideString swValue = pV ? pV->GetUnicodeText() : WideString();
-      CPVT_VariableText vt(&prd);
-      CFX_FloatRect rcButton = rcBody;
-      rcButton.left = rcButton.right - 13;
-      rcButton.Normalize();
-      CFX_FloatRect rcEdit = rcBody;
-      rcEdit.right = rcButton.left;
-      rcEdit.Normalize();
-      vt.SetPlateRect(rcEdit);
-      if (FXSYS_IsFloatZero(fFontSize))
-        vt.SetAutoFontSize(true);
-      else
-        vt.SetFontSize(fFontSize);
-
-      vt.Initialize();
-      vt.SetText(swValue);
-      vt.RearrangeAll();
-      CFX_FloatRect rcContent = vt.GetContentRect();
-      CFX_PointF ptOffset =
-          CFX_PointF(0.0f, (rcContent.Height() - rcEdit.Height()) / 2.0f);
-      ByteString sEdit =
-          GenerateEditAP(&map, vt.GetIterator(), ptOffset, true, 0);
-      if (sEdit.GetLength() > 0) {
-        sAppStream << "/Tx BMC\nq\n";
-        WriteRect(sAppStream, rcEdit) << " re\nW\nn\n";
-        sAppStream << "BT\n"
-                   << GenerateColorAP(crText, PaintOperation::kFill) << sEdit
-                   << "ET\n"
-                   << "Q\nEMC\n";
-      }
-      ByteString sButton =
-          GenerateColorAP(CFX_Color(CFX_Color::Type::kRGB, 220.0f / 255.0f,
-                                    220.0f / 255.0f, 220.0f / 255.0f),
-                          PaintOperation::kFill);
-      if (sButton.GetLength() > 0 && !rcButton.IsEmpty()) {
-        sAppStream << "q\n" << sButton;
-        WriteRect(sAppStream, rcButton) << " re f\n";
-        sAppStream << "Q\n";
-        ByteString sButtonBorder =
-            GenerateBorderAP(rcButton, 2, CFX_Color(CFX_Color::Type::kGray, 0),
-                             CFX_Color(CFX_Color::Type::kGray, 1),
-                             CFX_Color(CFX_Color::Type::kGray, 0.5),
-                             BorderStyle::kBeveled, CPVT_Dash(3, 0, 0));
-        if (sButtonBorder.GetLength() > 0)
-          sAppStream << "q\n" << sButtonBorder << "Q\n";
-
-        CFX_PointF ptCenter = CFX_PointF((rcButton.left + rcButton.right) / 2,
-                                         (rcButton.top + rcButton.bottom) / 2);
-        if (FXSYS_IsFloatBigger(rcButton.Width(), 6) &&
-            FXSYS_IsFloatBigger(rcButton.Height(), 6)) {
-          sAppStream << "q\n"
-                     << " 0 g\n";
-          WritePoint(sAppStream, {ptCenter.x - 3, ptCenter.y + 1.5f}) << " m\n";
-          WritePoint(sAppStream, {ptCenter.x + 3, ptCenter.y + 1.5f}) << " l\n";
-          WritePoint(sAppStream, {ptCenter.x, ptCenter.y - 1.5f}) << " l\n";
-          WritePoint(sAppStream, {ptCenter.x - 3, ptCenter.y + 1.5f})
-              << " l f\n";
-          sAppStream << sButton << "Q\n";
-        }
-      }
+      app_stream << GenerateComboBoxAP(annot_dict, body_rect, text_color,
+                                       font_size, provider);
       break;
     }
     case CPDF_GenerateAP::kListBox: {
-      RetainPtr<const CPDF_Array> pOpts =
-          ToArray(CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "Opt"));
-      RetainPtr<const CPDF_Array> pSels =
-          ToArray(CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "I"));
-      RetainPtr<const CPDF_Object> pTi =
-          CPDF_FormField::GetFieldAttrForDict(pAnnotDict, "TI");
-      int32_t nTop = pTi ? pTi->GetInteger() : 0;
-      fxcrt::ostringstream sBody;
-      if (pOpts) {
-        float fy = rcBody.top;
-        for (size_t i = nTop, sz = pOpts->size(); i < sz; i++) {
-          if (FXSYS_IsFloatSmaller(fy, rcBody.bottom))
-            break;
-
-          if (RetainPtr<const CPDF_Object> pOpt = pOpts->GetDirectObjectAt(i)) {
-            WideString swItem;
-            if (pOpt->IsString()) {
-              swItem = pOpt->GetUnicodeText();
-            } else if (const CPDF_Array* pArray = pOpt->AsArray()) {
-              RetainPtr<const CPDF_Object> pDirectObj =
-                  pArray->GetDirectObjectAt(1);
-              if (pDirectObj)
-                swItem = pDirectObj->GetUnicodeText();
-            }
-            bool bSelected = false;
-            if (pSels) {
-              for (size_t s = 0, ssz = pSels->size(); s < ssz; s++) {
-                int value = pSels->GetIntegerAt(s);
-                if (value >= 0 && i == static_cast<size_t>(value)) {
-                  bSelected = true;
-                  break;
-                }
-              }
-            }
-            CPVT_VariableText vt(&prd);
-            vt.SetPlateRect(
-                CFX_FloatRect(rcBody.left, 0.0f, rcBody.right, 0.0f));
-            vt.SetFontSize(FXSYS_IsFloatZero(fFontSize) ? 12.0f : fFontSize);
-            vt.Initialize();
-            vt.SetText(swItem);
-            vt.RearrangeAll();
-
-            float fItemHeight = vt.GetContentRect().Height();
-            if (bSelected) {
-              CFX_FloatRect rcItem = CFX_FloatRect(
-                  rcBody.left, fy - fItemHeight, rcBody.right, fy);
-              sBody << "q\n"
-                    << GenerateColorAP(
-                           CFX_Color(CFX_Color::Type::kRGB, 0, 51.0f / 255.0f,
-                                     113.0f / 255.0f),
-                           PaintOperation::kFill);
-              WriteRect(sBody, rcItem) << " re f\nQ\n";
-              sBody << "BT\n"
-                    << GenerateColorAP(CFX_Color(CFX_Color::Type::kGray, 1),
-                                       PaintOperation::kFill)
-                    << GenerateEditAP(&map, vt.GetIterator(),
-                                      CFX_PointF(0.0f, fy), true, 0)
-                    << "ET\n";
-            } else {
-              sBody << "BT\n"
-                    << GenerateColorAP(crText, PaintOperation::kFill)
-                    << GenerateEditAP(&map, vt.GetIterator(),
-                                      CFX_PointF(0.0f, fy), true, 0)
-                    << "ET\n";
-            }
-            fy -= fItemHeight;
-          }
-        }
-      }
-      if (sBody.tellp() > 0) {
-        sAppStream << "/Tx BMC\nq\n";
-        WriteRect(sAppStream, rcBody) << " re\nW\nn\n"
-                                      << sBody.str() << "Q\nEMC\n";
+      const ByteString body = GenerateListBoxAP(
+          annot_dict, body_rect, text_color, font_size, provider);
+      if (body.GetLength() > 0) {
+        app_stream << "/Tx BMC\nq\n";
+        WriteRect(app_stream, body_rect) << " re\nW\nn\n" << body << "Q\nEMC\n";
       }
       break;
     }
   }
 
-  if (!pNormalStream)
-    return;
+  normal_stream->SetDataFromStringstreamAndRemoveFilter(&app_stream);
+  RetainPtr<CPDF_Dictionary> stream_dict = normal_stream->GetMutableDict();
+  stream_dict->SetMatrixFor("Matrix", annot_dimensions_and_color.matrix);
+  stream_dict->SetRectFor("BBox", annot_dimensions_and_color.bbox);
 
-  pNormalStream->SetDataFromStringstreamAndRemoveFilter(&sAppStream);
-  pStreamDict = pNormalStream->GetMutableDict();
-  pStreamDict->SetMatrixFor("Matrix", matrix);
-  pStreamDict->SetRectFor("BBox", rcBBox);
-  RetainPtr<CPDF_Dictionary> pStreamResList =
-      pStreamDict->GetMutableDictFor("Resources");
-  if (!pStreamResList) {
-    pStreamDict->SetFor("Resources", pFormDict->GetDictFor("DR")->Clone());
+  const bool cloned =
+      CloneResourcesDictIfMissingFromStream(stream_dict, dr_dict);
+  if (cloned) {
     return;
   }
 
-  RetainPtr<CPDF_Dictionary> pStreamResFontList =
-      pStreamResList->GetMutableDictFor("Font");
-  if (pStreamResFontList) {
-    if (!ValidateFontResourceDict(pStreamResFontList.Get()))
-      return;
-  } else {
-    pStreamResFontList = pStreamResList->SetNewFor<CPDF_Dictionary>("Font");
-  }
-
-  if (!pStreamResFontList->KeyExist(font_name)) {
-    pStreamResFontList->SetNewFor<CPDF_Reference>(font_name, pDoc,
-                                                  pFontDict->GetObjNum());
-  }
+  ValidateOrCreateFontResources(doc, stream_dict, font_dict, font_name);
 }
 
 // static
-void CPDF_GenerateAP::GenerateEmptyAP(CPDF_Document* pDoc,
-                                      CPDF_Dictionary* pAnnotDict) {
-  auto pExtGStateDict = GenerateExtGStateDict(*pAnnotDict, "GS", "Normal");
-  auto pResourceDict =
-      GenerateResourceDict(pDoc, std::move(pExtGStateDict), nullptr);
-
-  fxcrt::ostringstream sStream;
-  GenerateAndSetAPDict(pDoc, pAnnotDict, &sStream, std::move(pResourceDict),
+void CPDF_GenerateAP::GenerateEmptyAP(CPDF_Document* doc,
+                                      CPDF_Dictionary* annot_dict) {
+  auto gs_dict = GenerateExtGStateDict(*annot_dict, "Normal");
+  auto resources_dict = GenerateResourcesDict(doc, std::move(gs_dict), nullptr);
+
+  fxcrt::ostringstream stream;
+  GenerateAndSetAPDict(doc, annot_dict, &stream, std::move(resources_dict),
                        false);
 }
 
 // static
-bool CPDF_GenerateAP::GenerateAnnotAP(CPDF_Document* pDoc,
-                                      CPDF_Dictionary* pAnnotDict,
+bool CPDF_GenerateAP::GenerateAnnotAP(CPDF_Document* doc,
+                                      CPDF_Dictionary* annot_dict,
                                       CPDF_Annot::Subtype subtype) {
   switch (subtype) {
     case CPDF_Annot::Subtype::CIRCLE:
-      return GenerateCircleAP(pDoc, pAnnotDict);
+      return GenerateCircleAP(doc, annot_dict);
+    case CPDF_Annot::Subtype::FREETEXT:
+      return GenerateFreeTextAP(doc, annot_dict);
     case CPDF_Annot::Subtype::HIGHLIGHT:
-      return GenerateHighlightAP(pDoc, pAnnotDict);
+      return GenerateHighlightAP(doc, annot_dict);
     case CPDF_Annot::Subtype::INK:
-      return GenerateInkAP(pDoc, pAnnotDict);
+      return GenerateInkAP(doc, annot_dict);
     case CPDF_Annot::Subtype::POPUP:
-      return GeneratePopupAP(pDoc, pAnnotDict);
+      return GeneratePopupAP(doc, annot_dict);
     case CPDF_Annot::Subtype::SQUARE:
-      return GenerateSquareAP(pDoc, pAnnotDict);
+      return GenerateSquareAP(doc, annot_dict);
     case CPDF_Annot::Subtype::SQUIGGLY:
-      return GenerateSquigglyAP(pDoc, pAnnotDict);
+      return GenerateSquigglyAP(doc, annot_dict);
     case CPDF_Annot::Subtype::STRIKEOUT:
-      return GenerateStrikeOutAP(pDoc, pAnnotDict);
+      return GenerateStrikeOutAP(doc, annot_dict);
     case CPDF_Annot::Subtype::TEXT:
-      return GenerateTextAP(pDoc, pAnnotDict);
+      return GenerateTextAP(doc, annot_dict);
     case CPDF_Annot::Subtype::UNDERLINE:
-      return GenerateUnderlineAP(pDoc, pAnnotDict);
+      return GenerateUnderlineAP(doc, annot_dict);
     default:
       return false;
   }
-}
+}
\ No newline at end of file
diff --git a/core/fpdfdoc/cpdf_interactiveform.cpp b/core/fpdfdoc/cpdf_interactiveform.cpp
index e2da3f9d3..ccff6feba 100644
--- a/core/fpdfdoc/cpdf_interactiveform.cpp
+++ b/core/fpdfdoc/cpdf_interactiveform.cpp
@@ -45,7 +45,7 @@
 
 namespace {
 
-const int nMaxRecursion = 32;
+constexpr int kMaxRecursion = 32;
 
 #if BUILDFLAG(IS_WIN)
 struct PDF_FONTDATA {
@@ -57,8 +57,10 @@ int CALLBACK EnumFontFamExProc(ENUMLOGFONTEXA* lpelfe,
                                NEWTEXTMETRICEX* lpntme,
                                DWORD FontType,
                                LPARAM lParam) {
-  if (FontType != 0x004 || strchr(lpelfe->elfLogFont.lfFaceName, '@'))
+  if (FontType != 0x004 ||
+      UNSAFE_TODO(strchr(lpelfe->elfLogFont.lfFaceName, '@'))) {
     return 1;
+  }
 
   PDF_FONTDATA* pData = (PDF_FONTDATA*)lParam;
   pData->lf = lpelfe->elfLogFont;
@@ -66,17 +68,17 @@ int CALLBACK EnumFontFamExProc(ENUMLOGFONTEXA* lpelfe,
   return 0;
 }
 
-bool RetrieveSpecificFont(FX_Charset charSet,
+bool RetrieveSpecificFont(FX_Charset charset,
                           LPCSTR pcsFontName,
                           LOGFONTA& lf) {
   lf = {};  // Aggregate initialization, not construction.
   static_assert(std::is_aggregate_v<std::remove_reference_t<decltype(lf)>>);
-  lf.lfCharSet = static_cast<int>(charSet);
+  lf.lfCharSet = static_cast<int>(charset);
   lf.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
   if (pcsFontName) {
     // TODO(dsinclair): Should this be strncpy?
     // NOLINTNEXTLINE(runtime/printf)
-    strcpy(lf.lfFaceName, pcsFontName);
+    UNSAFE_TODO(strcpy(lf.lfFaceName, pcsFontName));
   }
 
   PDF_FONTDATA fd = {};  // Aggregate initialization, not construction.
@@ -92,11 +94,11 @@ bool RetrieveSpecificFont(FX_Charset charSet,
 }
 #endif  // BUILDFLAG(IS_WIN)
 
-ByteString GetNativeFontName(FX_Charset charSet, void* pLogFont) {
-  ByteString csFontName;
+ByteString GetNativeFontName(FX_Charset charset, void* log_font) {
+  ByteString font_name;
 #if BUILDFLAG(IS_WIN)
   LOGFONTA lf = {};
-  if (charSet == FX_Charset::kANSI) {
+  if (charset == FX_Charset::kANSI) {
     return CFX_Font::kDefaultAnsiFontName;
   }
 
@@ -107,239 +109,261 @@ ByteString GetNativeFontName(FX_Charset charSet, void* pLogFont) {
     return ByteString();
   }
 
-  bool bRet = false;
+  bool result = false;
   const ByteString default_font_name =
-      CFX_Font::GetDefaultFontNameByCharset(charSet);
-  if (!default_font_name.IsEmpty())
-    bRet = RetrieveSpecificFont(charSet, default_font_name.c_str(), lf);
-  if (!bRet) {
-    bRet =
-        RetrieveSpecificFont(charSet, CFX_Font::kUniversalDefaultFontName, lf);
-  }
-  if (!bRet)
-    bRet = RetrieveSpecificFont(charSet, "Microsoft Sans Serif", lf);
-  if (!bRet)
-    bRet = RetrieveSpecificFont(charSet, nullptr, lf);
-  if (bRet) {
-    if (pLogFont) {
-      UNSAFE_TODO(FXSYS_memcpy(pLogFont, &lf, sizeof(LOGFONTA)));
+      CFX_Font::GetDefaultFontNameByCharset(charset);
+  if (!default_font_name.IsEmpty()) {
+    result = RetrieveSpecificFont(charset, default_font_name.c_str(), lf);
+  }
+  if (!result) {
+    result =
+        RetrieveSpecificFont(charset, CFX_Font::kUniversalDefaultFontName, lf);
+  }
+  if (!result) {
+    result = RetrieveSpecificFont(charset, "Microsoft Sans Serif", lf);
+  }
+  if (!result) {
+    result = RetrieveSpecificFont(charset, nullptr, lf);
+  }
+  if (result) {
+    if (log_font) {
+      UNSAFE_TODO(FXSYS_memcpy(log_font, &lf, sizeof(LOGFONTA)));
     }
-    csFontName = lf.lfFaceName;
+    font_name = lf.lfFaceName;
   }
 #endif
-  return csFontName;
+  return font_name;
 }
 
-ByteString GenerateNewFontResourceName(const CPDF_Dictionary* pResDict,
-                                       const ByteString& csPrefix) {
+ByteString GenerateNewFontResourceName(const CPDF_Dictionary* resource_dict,
+                                       ByteString prefix) {
   static const char kDummyFontName[] = "ZiTi";
-  ByteString csStr = csPrefix;
-  if (csStr.IsEmpty())
-    csStr = kDummyFontName;
+  if (prefix.IsEmpty()) {
+    prefix = kDummyFontName;
+  }
 
-  const size_t szCount = csStr.GetLength();
+  const size_t prefix_length = prefix.GetLength();
   size_t m = 0;
-  ByteString csTmp;
-  while (m < strlen(kDummyFontName) && m < szCount)
-    csTmp += csStr[m++];
-  while (m < strlen(kDummyFontName)) {
-    csTmp += '0' + m % 10;
+  ByteString actual_prefix;
+  while (m < UNSAFE_TODO(strlen(kDummyFontName)) && m < prefix_length) {
+    actual_prefix += prefix[m++];
+  }
+  while (m < UNSAFE_TODO(strlen(kDummyFontName))) {
+    actual_prefix += '0' + m % 10;
     m++;
   }
 
-  RetainPtr<const CPDF_Dictionary> pDict = pResDict->GetDictFor("Font");
+  RetainPtr<const CPDF_Dictionary> pDict = resource_dict->GetDictFor("Font");
   DCHECK(pDict);
 
   int num = 0;
-  ByteString bsNum;
+  ByteString key_number;
   while (true) {
-    ByteString csKey = csTmp + bsNum;
-    if (!pDict->KeyExist(csKey))
-      return csKey;
-
-    if (m < szCount)
-      csTmp += csStr[m++];
-    else
-      bsNum = ByteString::FormatInteger(num++);
+    ByteString key = actual_prefix + key_number;
+    if (!pDict->KeyExist(key)) {
+      return key;
+    }
+
+    if (m < prefix_length) {
+      actual_prefix += prefix[m++];
+    } else {
+      key_number = ByteString::FormatInteger(num++);
+    }
     m++;
   }
 }
 
-RetainPtr<CPDF_Font> AddStandardFont(CPDF_Document* pDocument) {
-  auto* pPageData = CPDF_DocPageData::FromDocument(pDocument);
+RetainPtr<CPDF_Font> AddStandardFont(CPDF_Document* document) {
+  auto* page_data = CPDF_DocPageData::FromDocument(document);
   static const CPDF_FontEncoding encoding(FontEncoding::kWinAnsi);
-  return pPageData->AddStandardFont(CFX_Font::kDefaultAnsiFontName, &encoding);
+  return page_data->AddStandardFont(CFX_Font::kDefaultAnsiFontName, &encoding);
 }
 
-RetainPtr<CPDF_Font> AddNativeFont(FX_Charset charSet,
-                                   CPDF_Document* pDocument) {
-  DCHECK(pDocument);
+RetainPtr<CPDF_Font> AddNativeFont(FX_Charset charset,
+                                   CPDF_Document* document) {
+  DCHECK(document);
 
 #if BUILDFLAG(IS_WIN)
   LOGFONTA lf;
-  ByteString csFontName = GetNativeFontName(charSet, &lf);
-  if (!csFontName.IsEmpty()) {
-    if (csFontName == CFX_Font::kDefaultAnsiFontName)
-      return AddStandardFont(pDocument);
-    return CPDF_DocPageData::FromDocument(pDocument)->AddWindowsFont(&lf);
+  ByteString font_name = GetNativeFontName(charset, &lf);
+  if (!font_name.IsEmpty()) {
+    if (font_name == CFX_Font::kDefaultAnsiFontName) {
+      return AddStandardFont(document);
+    }
+    return CPDF_DocPageData::FromDocument(document)->AddWindowsFont(&lf);
   }
 #endif
   return nullptr;
 }
 
-bool FindFont(const CPDF_Dictionary* pFormDict,
-              const CPDF_Font* pFont,
-              ByteString* csNameTag) {
-  RetainPtr<const CPDF_Dictionary> pDR = pFormDict->GetDictFor("DR");
-  if (!pDR)
+bool FindFont(const CPDF_Dictionary* form_dict,
+              const CPDF_Font* font,
+              ByteString* name_tag) {
+  RetainPtr<const CPDF_Dictionary> pDR = form_dict->GetDictFor("DR");
+  if (!pDR) {
     return false;
+  }
 
-  RetainPtr<const CPDF_Dictionary> pFonts = pDR->GetDictFor("Font");
+  RetainPtr<const CPDF_Dictionary> font_dict = pDR->GetDictFor("Font");
   // TODO(tsepez): this eventually locks the dict, pass locker instead.
-  if (!ValidateFontResourceDict(pFonts.Get()))
+  if (!ValidateFontResourceDict(font_dict.Get())) {
     return false;
+  }
 
-  CPDF_DictionaryLocker locker(std::move(pFonts));
+  CPDF_DictionaryLocker locker(std::move(font_dict));
   for (const auto& it : locker) {
-    const ByteString& csKey = it.first;
-    RetainPtr<const CPDF_Dictionary> pElement =
+    const ByteString& key = it.first;
+    RetainPtr<const CPDF_Dictionary> element =
         ToDictionary(it.second->GetDirect());
-    if (!ValidateDictType(pElement.Get(), "Font"))
+    if (!ValidateDictType(element.Get(), "Font")) {
       continue;
-    if (pFont->FontDictIs(pElement)) {
-      *csNameTag = csKey;
+    }
+    if (font->FontDictIs(element)) {
+      *name_tag = key;
       return true;
     }
   }
   return false;
 }
 
-bool FindFontFromDoc(const CPDF_Dictionary* pFormDict,
-                     CPDF_Document* pDocument,
-                     ByteString csFontName,
-                     RetainPtr<CPDF_Font>& pFont,
-                     ByteString* csNameTag) {
-  if (csFontName.IsEmpty())
+bool FindFontFromDoc(const CPDF_Dictionary* form_dict,
+                     CPDF_Document* document,
+                     ByteString font_name,
+                     RetainPtr<CPDF_Font>& font,
+                     ByteString* name_tag) {
+  if (font_name.IsEmpty()) {
     return false;
+  }
 
-  RetainPtr<const CPDF_Dictionary> pDR = pFormDict->GetDictFor("DR");
-  if (!pDR)
+  RetainPtr<const CPDF_Dictionary> pDR = form_dict->GetDictFor("DR");
+  if (!pDR) {
     return false;
+  }
 
-  RetainPtr<const CPDF_Dictionary> pFonts = pDR->GetDictFor("Font");
-  if (!ValidateFontResourceDict(pFonts.Get()))
+  RetainPtr<const CPDF_Dictionary> font_dict = pDR->GetDictFor("Font");
+  if (!ValidateFontResourceDict(font_dict.Get())) {
     return false;
+  }
 
-  csFontName.Remove(' ');
-  CPDF_DictionaryLocker locker(pFonts);
+  font_name.Remove(' ');
+  CPDF_DictionaryLocker locker(font_dict);
   for (const auto& it : locker) {
-    const ByteString& csKey = it.first;
-    RetainPtr<CPDF_Dictionary> pElement =
+    const ByteString& key = it.first;
+    RetainPtr<CPDF_Dictionary> element =
         ToDictionary(it.second->GetMutableDirect());
-    if (!ValidateDictType(pElement.Get(), "Font"))
+    if (!ValidateDictType(element.Get(), "Font")) {
       continue;
+    }
 
-    auto* pData = CPDF_DocPageData::FromDocument(pDocument);
-    pFont = pData->GetFont(std::move(pElement));
-    if (!pFont)
+    auto* pData = CPDF_DocPageData::FromDocument(document);
+    font = pData->GetFont(std::move(element));
+    if (!font) {
       continue;
+    }
 
-    ByteString csBaseFont = pFont->GetBaseFontName();
-    csBaseFont.Remove(' ');
-    if (csBaseFont == csFontName) {
-      *csNameTag = csKey;
+    ByteString base_font = font->GetBaseFontName();
+    base_font.Remove(' ');
+    if (base_font == font_name) {
+      *name_tag = key;
       return true;
     }
   }
   return false;
 }
 
-void AddFont(CPDF_Dictionary* pFormDict,
-             CPDF_Document* pDocument,
-             const RetainPtr<CPDF_Font>& pFont,
-             ByteString* csNameTag) {
-  DCHECK(pFormDict);
-  DCHECK(pFont);
+void AddFont(CPDF_Dictionary* form_dict,
+             CPDF_Document* document,
+             const RetainPtr<CPDF_Font>& font,
+             ByteString* name_tag) {
+  DCHECK(form_dict);
+  DCHECK(font);
 
-  ByteString csTag;
-  if (FindFont(pFormDict, pFont.Get(), &csTag)) {
-    *csNameTag = std::move(csTag);
+  ByteString tag;
+  if (FindFont(form_dict, font.Get(), &tag)) {
+    *name_tag = std::move(tag);
     return;
   }
 
-  RetainPtr<CPDF_Dictionary> pDR = pFormDict->GetOrCreateDictFor("DR");
-  RetainPtr<CPDF_Dictionary> pFonts = pDR->GetOrCreateDictFor("Font");
+  RetainPtr<CPDF_Dictionary> pDR = form_dict->GetOrCreateDictFor("DR");
+  RetainPtr<CPDF_Dictionary> font_dict = pDR->GetOrCreateDictFor("Font");
 
-  if (csNameTag->IsEmpty())
-    *csNameTag = pFont->GetBaseFontName();
+  if (name_tag->IsEmpty()) {
+    *name_tag = font->GetBaseFontName();
+  }
 
-  csNameTag->Remove(' ');
-  *csNameTag = GenerateNewFontResourceName(pDR.Get(), *csNameTag);
-  pFonts->SetNewFor<CPDF_Reference>(*csNameTag, pDocument,
-                                    pFont->GetFontDictObjNum());
+  name_tag->Remove(' ');
+  *name_tag = GenerateNewFontResourceName(pDR.Get(), *name_tag);
+  font_dict->SetNewFor<CPDF_Reference>(*name_tag, document,
+                                       font->GetFontDictObjNum());
 }
 
 FX_Charset GetNativeCharSet() {
   return FX_GetCharsetFromCodePage(FX_GetACP());
 }
 
-RetainPtr<CPDF_Dictionary> InitDict(CPDF_Document* pDocument) {
-  auto pFormDict = pDocument->NewIndirect<CPDF_Dictionary>();
-  pDocument->GetMutableRoot()->SetNewFor<CPDF_Reference>(
-      "AcroForm", pDocument, pFormDict->GetObjNum());
-
-  ByteString csBaseName;
-  FX_Charset charSet = GetNativeCharSet();
-  RetainPtr<CPDF_Font> pFont = AddStandardFont(pDocument);
-  if (pFont) {
-    AddFont(pFormDict.Get(), pDocument, pFont, &csBaseName);
-  }
-  if (charSet != FX_Charset::kANSI) {
-    ByteString csFontName = GetNativeFontName(charSet, nullptr);
-    if (!pFont || csFontName != CFX_Font::kDefaultAnsiFontName) {
-      pFont = AddNativeFont(charSet, pDocument);
-      if (pFont) {
-        csBaseName.clear();
-        AddFont(pFormDict.Get(), pDocument, pFont, &csBaseName);
+RetainPtr<CPDF_Dictionary> InitDict(CPDF_Document* document) {
+  auto form_dict = document->NewIndirect<CPDF_Dictionary>();
+  document->GetMutableRoot()->SetNewFor<CPDF_Reference>("AcroForm", document,
+                                                        form_dict->GetObjNum());
+
+  ByteString base_name;
+  FX_Charset charset = GetNativeCharSet();
+  RetainPtr<CPDF_Font> font = AddStandardFont(document);
+  if (font) {
+    AddFont(form_dict.Get(), document, font, &base_name);
+  }
+  if (charset != FX_Charset::kANSI) {
+    ByteString font_name = GetNativeFontName(charset, nullptr);
+    if (!font || font_name != CFX_Font::kDefaultAnsiFontName) {
+      RetainPtr<CPDF_Font> native_font = AddNativeFont(charset, document);
+      if (native_font) {
+        base_name.clear();
+        AddFont(form_dict.Get(), document, native_font, &base_name);
+        font = std::move(native_font);
       }
     }
   }
-  ByteString csDA;
-  if (pFont)
-    csDA = "/" + PDF_NameEncode(csBaseName) + " 0 Tf ";
-  csDA += "0 g";
-  pFormDict->SetNewFor<CPDF_String>("DA", csDA);
-  return pFormDict;
+  ByteString default_appearance;
+  if (font) {
+    default_appearance = "/" + PDF_NameEncode(base_name) + " 12 Tf ";
+  }
+  default_appearance += "0 g";
+  form_dict->SetNewFor<CPDF_String>("DA", std::move(default_appearance));
+  return form_dict;
 }
 
-RetainPtr<CPDF_Font> GetNativeFont(const CPDF_Dictionary* pFormDict,
-                                   CPDF_Document* pDocument,
-                                   FX_Charset charSet,
-                                   ByteString* csNameTag) {
-  RetainPtr<const CPDF_Dictionary> pDR = pFormDict->GetDictFor("DR");
-  if (!pDR)
+RetainPtr<CPDF_Font> GetNativeFont(const CPDF_Dictionary* form_dict,
+                                   CPDF_Document* document,
+                                   FX_Charset charset,
+                                   ByteString* name_tag) {
+  RetainPtr<const CPDF_Dictionary> pDR = form_dict->GetDictFor("DR");
+  if (!pDR) {
     return nullptr;
+  }
 
-  RetainPtr<const CPDF_Dictionary> pFonts = pDR->GetDictFor("Font");
-  if (!ValidateFontResourceDict(pFonts.Get()))
+  RetainPtr<const CPDF_Dictionary> font_dict = pDR->GetDictFor("Font");
+  if (!ValidateFontResourceDict(font_dict.Get())) {
     return nullptr;
+  }
 
-  CPDF_DictionaryLocker locker(pFonts);
+  CPDF_DictionaryLocker locker(font_dict);
   for (const auto& it : locker) {
-    const ByteString& csKey = it.first;
-    RetainPtr<CPDF_Dictionary> pElement =
+    const ByteString& key = it.first;
+    RetainPtr<CPDF_Dictionary> element =
         ToDictionary(it.second->GetMutableDirect());
-    if (!ValidateDictType(pElement.Get(), "Font"))
+    if (!ValidateDictType(element.Get(), "Font")) {
       continue;
+    }
 
-    auto* pData = CPDF_DocPageData::FromDocument(pDocument);
-    RetainPtr<CPDF_Font> pFind = pData->GetFont(std::move(pElement));
-    if (!pFind)
+    auto* pData = CPDF_DocPageData::FromDocument(document);
+    RetainPtr<CPDF_Font> pFind = pData->GetFont(std::move(element));
+    if (!pFind) {
       continue;
+    }
 
     auto maybe_charset = pFind->GetSubstFontCharset();
-    if (maybe_charset.has_value() && maybe_charset.value() == charSet) {
-      *csNameTag = csKey;
+    if (maybe_charset.has_value() && maybe_charset.value() == charset) {
+      *name_tag = key;
       return pFind;
     }
   }
@@ -353,12 +377,14 @@ class CFieldNameExtractor {
 
   WideStringView GetNext() {
     size_t start_pos = m_iCur;
-    while (m_iCur < m_FullName.GetLength() && m_FullName[m_iCur] != L'.')
+    while (m_iCur < m_FullName.GetLength() && m_FullName[m_iCur] != L'.') {
       ++m_iCur;
+    }
 
     size_t length = m_iCur - start_pos;
-    if (m_iCur < m_FullName.GetLength() && m_FullName[m_iCur] == L'.')
+    if (m_iCur < m_FullName.GetLength() && m_FullName[m_iCur] == L'.') {
       ++m_iCur;
+    }
 
     return m_FullName.AsStringView().Substr(start_pos, length);
   }
@@ -379,8 +405,8 @@ class CFieldTree {
         : m_ShortName(short_name), m_level(level) {}
     ~Node() = default;
 
-    void AddChildNode(std::unique_ptr<Node> pNode) {
-      m_Children.push_back(std::move(pNode));
+    void AddChildNode(std::unique_ptr<Node> node) {
+      m_Children.push_back(std::move(node));
     }
 
     size_t GetChildrenCount() const { return m_Children.size(); }
@@ -395,8 +421,8 @@ class CFieldTree {
 
     size_t CountFields() const { return CountFieldsInternal(); }
 
-    void SetField(std::unique_ptr<CPDF_FormField> pField) {
-      m_pField = std::move(pField);
+    void SetField(std::unique_ptr<CPDF_FormField> field) {
+      m_pField = std::move(field);
     }
 
     CPDF_FormField* GetField() const { return m_pField.get(); }
@@ -406,26 +432,30 @@ class CFieldTree {
    private:
     CPDF_FormField* GetFieldInternal(size_t* pFieldsToGo) {
       if (m_pField) {
-        if (*pFieldsToGo == 0)
+        if (*pFieldsToGo == 0) {
           return m_pField.get();
+        }
 
         --*pFieldsToGo;
       }
       for (size_t i = 0; i < GetChildrenCount(); ++i) {
-        CPDF_FormField* pField = GetChildAt(i)->GetFieldInternal(pFieldsToGo);
-        if (pField)
-          return pField;
+        CPDF_FormField* field = GetChildAt(i)->GetFieldInternal(pFieldsToGo);
+        if (field) {
+          return field;
+        }
       }
       return nullptr;
     }
 
     size_t CountFieldsInternal() const {
       size_t count = 0;
-      if (m_pField)
+      if (m_pField) {
         ++count;
+      }
 
-      for (size_t i = 0; i < GetChildrenCount(); ++i)
+      for (size_t i = 0; i < GetChildrenCount(); ++i) {
         count += GetChildAt(i)->CountFieldsInternal();
+      }
       return count;
     }
 
@@ -439,7 +469,7 @@ class CFieldTree {
   ~CFieldTree();
 
   bool SetField(const WideString& full_name,
-                std::unique_ptr<CPDF_FormField> pField);
+                std::unique_ptr<CPDF_FormField> field);
   CPDF_FormField* GetField(const WideString& full_name);
 
   Node* GetRoot() { return m_pRoot.get(); }
@@ -457,108 +487,125 @@ CFieldTree::~CFieldTree() = default;
 
 CFieldTree::Node* CFieldTree::AddChild(Node* pParent,
                                        const WideString& short_name) {
-  if (!pParent)
+  if (!pParent) {
     return nullptr;
+  }
 
   int level = pParent->GetLevel() + 1;
-  if (level > nMaxRecursion)
+  if (level > kMaxRecursion) {
     return nullptr;
+  }
 
-  auto pNew = std::make_unique<Node>(short_name, pParent->GetLevel() + 1);
-  Node* pChild = pNew.get();
-  pParent->AddChildNode(std::move(pNew));
+  auto new_node = std::make_unique<Node>(short_name, pParent->GetLevel() + 1);
+  Node* pChild = new_node.get();
+  pParent->AddChildNode(std::move(new_node));
   return pChild;
 }
 
 CFieldTree::Node* CFieldTree::Lookup(Node* pParent, WideStringView short_name) {
-  if (!pParent)
+  if (!pParent) {
     return nullptr;
+  }
 
   for (size_t i = 0; i < pParent->GetChildrenCount(); ++i) {
-    Node* pNode = pParent->GetChildAt(i);
-    if (pNode->GetShortName() == short_name)
-      return pNode;
+    Node* node = pParent->GetChildAt(i);
+    if (node->GetShortName() == short_name) {
+      return node;
+    }
   }
   return nullptr;
 }
 
 bool CFieldTree::SetField(const WideString& full_name,
-                          std::unique_ptr<CPDF_FormField> pField) {
-  if (full_name.IsEmpty())
+                          std::unique_ptr<CPDF_FormField> field) {
+  if (full_name.IsEmpty()) {
     return false;
+  }
 
-  Node* pNode = GetRoot();
-  Node* pLast = nullptr;
+  Node* node = GetRoot();
+  Node* last_node = nullptr;
   CFieldNameExtractor name_extractor(full_name);
   while (true) {
     WideStringView name_view = name_extractor.GetNext();
-    if (name_view.IsEmpty())
+    if (name_view.IsEmpty()) {
       break;
-    pLast = pNode;
-    pNode = Lookup(pLast, name_view);
-    if (pNode)
+    }
+    last_node = node;
+    node = Lookup(last_node, name_view);
+    if (node) {
       continue;
-    pNode = AddChild(pLast, WideString(name_view));
-    if (!pNode)
+    }
+    node = AddChild(last_node, WideString(name_view));
+    if (!node) {
       return false;
+    }
   }
-  if (pNode == GetRoot())
+  if (node == GetRoot()) {
     return false;
+  }
 
-  pNode->SetField(std::move(pField));
+  node->SetField(std::move(field));
   return true;
 }
 
 CPDF_FormField* CFieldTree::GetField(const WideString& full_name) {
-  if (full_name.IsEmpty())
+  if (full_name.IsEmpty()) {
     return nullptr;
+  }
 
-  Node* pNode = GetRoot();
-  Node* pLast = nullptr;
+  Node* node = GetRoot();
+  Node* last_node = nullptr;
   CFieldNameExtractor name_extractor(full_name);
-  while (pNode) {
+  while (node) {
     WideStringView name_view = name_extractor.GetNext();
-    if (name_view.IsEmpty())
+    if (name_view.IsEmpty()) {
       break;
-    pLast = pNode;
-    pNode = Lookup(pLast, name_view);
+    }
+    last_node = node;
+    node = Lookup(last_node, name_view);
   }
-  return pNode ? pNode->GetField() : nullptr;
+  return node ? node->GetField() : nullptr;
 }
 
 CFieldTree::Node* CFieldTree::FindNode(const WideString& full_name) {
-  if (full_name.IsEmpty())
+  if (full_name.IsEmpty()) {
     return nullptr;
+  }
 
-  Node* pNode = GetRoot();
-  Node* pLast = nullptr;
+  Node* node = GetRoot();
+  Node* last_node = nullptr;
   CFieldNameExtractor name_extractor(full_name);
-  while (pNode) {
+  while (node) {
     WideStringView name_view = name_extractor.GetNext();
-    if (name_view.IsEmpty())
+    if (name_view.IsEmpty()) {
       break;
-    pLast = pNode;
-    pNode = Lookup(pLast, name_view);
+    }
+    last_node = node;
+    node = Lookup(last_node, name_view);
   }
-  return pNode;
+  return node;
 }
 
-CPDF_InteractiveForm::CPDF_InteractiveForm(CPDF_Document* pDocument)
-    : m_pDocument(pDocument), m_pFieldTree(std::make_unique<CFieldTree>()) {
+CPDF_InteractiveForm::CPDF_InteractiveForm(CPDF_Document* document)
+    : m_pDocument(document), m_pFieldTree(std::make_unique<CFieldTree>()) {
   RetainPtr<CPDF_Dictionary> pRoot = m_pDocument->GetMutableRoot();
-  if (!pRoot)
+  if (!pRoot) {
     return;
+  }
 
   m_pFormDict = pRoot->GetMutableDictFor("AcroForm");
-  if (!m_pFormDict)
+  if (!m_pFormDict) {
     return;
+  }
 
-  RetainPtr<CPDF_Array> pFields = m_pFormDict->GetMutableArrayFor("Fields");
-  if (!pFields)
+  RetainPtr<CPDF_Array> fields = m_pFormDict->GetMutableArrayFor("Fields");
+  if (!fields) {
     return;
+  }
 
-  for (size_t i = 0; i < pFields->size(); ++i)
-    LoadField(pFields->GetMutableDictAt(i), 0);
+  for (size_t i = 0; i < fields->size(); ++i) {
+    LoadField(fields->GetMutableDictAt(i), 0);
+  }
 }
 
 CPDF_InteractiveForm::~CPDF_InteractiveForm() = default;
@@ -577,96 +624,111 @@ void CPDF_InteractiveForm::SetUpdateAP(bool bUpdateAP) {
 
 // static
 RetainPtr<CPDF_Font> CPDF_InteractiveForm::AddNativeInteractiveFormFont(
-    CPDF_Document* pDocument,
-    ByteString* csNameTag) {
-  DCHECK(pDocument);
-  DCHECK(csNameTag);
-
-  RetainPtr<CPDF_Dictionary> pFormDict =
-      pDocument->GetMutableRoot()->GetMutableDictFor("AcroForm");
-  if (!pFormDict)
-    pFormDict = InitDict(pDocument);
-
-  FX_Charset charSet = GetNativeCharSet();
-  ByteString csTemp;
-  RetainPtr<CPDF_Font> pFont =
-      GetNativeFont(pFormDict.Get(), pDocument, charSet, &csTemp);
-  if (pFont) {
-    *csNameTag = std::move(csTemp);
-    return pFont;
-  }
-  ByteString csFontName = GetNativeFontName(charSet, nullptr);
-  if (FindFontFromDoc(pFormDict.Get(), pDocument, csFontName, pFont, csNameTag))
-    return pFont;
-
-  pFont = AddNativeFont(charSet, pDocument);
-  if (!pFont)
+    CPDF_Document* document,
+    ByteString* name_tag) {
+  DCHECK(document);
+  DCHECK(name_tag);
+
+  RetainPtr<CPDF_Dictionary> form_dict =
+      document->GetMutableRoot()->GetMutableDictFor("AcroForm");
+  if (!form_dict) {
+    form_dict = InitDict(document);
+  }
+
+  FX_Charset charset = GetNativeCharSet();
+  ByteString tag;
+  RetainPtr<CPDF_Font> font =
+      GetNativeFont(form_dict.Get(), document, charset, &tag);
+  if (font) {
+    *name_tag = std::move(tag);
+    return font;
+  }
+  ByteString font_name = GetNativeFontName(charset, nullptr);
+  if (FindFontFromDoc(form_dict.Get(), document, font_name, font, name_tag)) {
+    return font;
+  }
+
+  font = AddNativeFont(charset, document);
+  if (!font) {
     return nullptr;
+  }
+
+  AddFont(form_dict.Get(), document, font, name_tag);
+  return font;
+}
 
-  AddFont(pFormDict.Get(), pDocument, pFont, csNameTag);
-  return pFont;
+// static
+RetainPtr<CPDF_Dictionary> CPDF_InteractiveForm::InitAcroFormDict(
+    CPDF_Document* document) {
+  return InitDict(document);
 }
 
-size_t CPDF_InteractiveForm::CountFields(const WideString& csFieldName) const {
-  if (csFieldName.IsEmpty())
+size_t CPDF_InteractiveForm::CountFields(const WideString& field_name) const {
+  if (field_name.IsEmpty()) {
     return m_pFieldTree->GetRoot()->CountFields();
+  }
 
-  CFieldTree::Node* pNode = m_pFieldTree->FindNode(csFieldName);
-  return pNode ? pNode->CountFields() : 0;
+  CFieldTree::Node* node = m_pFieldTree->FindNode(field_name);
+  return node ? node->CountFields() : 0;
 }
 
 CPDF_FormField* CPDF_InteractiveForm::GetField(
     size_t index,
-    const WideString& csFieldName) const {
-  if (csFieldName.IsEmpty())
+    const WideString& field_name) const {
+  if (field_name.IsEmpty()) {
     return m_pFieldTree->GetRoot()->GetFieldAtIndex(index);
+  }
 
-  CFieldTree::Node* pNode = m_pFieldTree->FindNode(csFieldName);
-  return pNode ? pNode->GetFieldAtIndex(index) : nullptr;
+  CFieldTree::Node* node = m_pFieldTree->FindNode(field_name);
+  return node ? node->GetFieldAtIndex(index) : nullptr;
 }
 
 CPDF_FormField* CPDF_InteractiveForm::GetFieldByDict(
-    const CPDF_Dictionary* pFieldDict) const {
-  if (!pFieldDict)
+    const CPDF_Dictionary* field_dict) const {
+  if (!field_dict) {
     return nullptr;
+  }
 
-  WideString csWName = CPDF_FormField::GetFullNameForDict(pFieldDict);
-  return m_pFieldTree->GetField(csWName);
+  return m_pFieldTree->GetField(CPDF_FormField::GetFullNameForDict(field_dict));
 }
 
 const CPDF_FormControl* CPDF_InteractiveForm::GetControlAtPoint(
-    const CPDF_Page* pPage,
+    const CPDF_Page* page,
     const CFX_PointF& point,
     int* z_order) const {
-  RetainPtr<const CPDF_Array> pAnnotList = pPage->GetAnnotsArray();
-  if (!pAnnotList)
+  RetainPtr<const CPDF_Array> annots = page->GetAnnotsArray();
+  if (!annots) {
     return nullptr;
+  }
 
-  for (size_t i = pAnnotList->size(); i > 0; --i) {
+  for (size_t i = annots->size(); i > 0; --i) {
     size_t annot_index = i - 1;
-    RetainPtr<const CPDF_Dictionary> pAnnot =
-        pAnnotList->GetDictAt(annot_index);
-    if (!pAnnot)
+    RetainPtr<const CPDF_Dictionary> annot = annots->GetDictAt(annot_index);
+    if (!annot) {
       continue;
+    }
 
-    const auto it = m_ControlMap.find(pAnnot.Get());
-    if (it == m_ControlMap.end())
+    const auto it = m_ControlMap.find(annot.Get());
+    if (it == m_ControlMap.end()) {
       continue;
+    }
 
-    const CPDF_FormControl* pControl = it->second.get();
-    if (!pControl->GetRect().Contains(point))
+    const CPDF_FormControl* control = it->second.get();
+    if (!control->GetRect().Contains(point)) {
       continue;
+    }
 
-    if (z_order)
+    if (z_order) {
       *z_order = static_cast<int>(annot_index);
-    return pControl;
+    }
+    return control;
   }
   return nullptr;
 }
 
 CPDF_FormControl* CPDF_InteractiveForm::GetControlByDict(
-    const CPDF_Dictionary* pWidgetDict) const {
-  const auto it = m_ControlMap.find(pWidgetDict);
+    const CPDF_Dictionary* widget_dict) const {
+  const auto it = m_ControlMap.find(widget_dict);
   return it != m_ControlMap.end() ? it->second.get() : nullptr;
 }
 
@@ -675,67 +737,80 @@ bool CPDF_InteractiveForm::NeedConstructAP() const {
 }
 
 int CPDF_InteractiveForm::CountFieldsInCalculationOrder() {
-  if (!m_pFormDict)
+  if (!m_pFormDict) {
     return 0;
+  }
 
   RetainPtr<const CPDF_Array> pArray = m_pFormDict->GetArrayFor("CO");
   return pArray ? fxcrt::CollectionSize<int>(*pArray) : 0;
 }
 
 CPDF_FormField* CPDF_InteractiveForm::GetFieldInCalculationOrder(int index) {
-  if (!m_pFormDict || index < 0)
+  if (!m_pFormDict || index < 0) {
     return nullptr;
+  }
 
   RetainPtr<const CPDF_Array> pArray = m_pFormDict->GetArrayFor("CO");
-  if (!pArray)
+  if (!pArray) {
     return nullptr;
+  }
 
-  RetainPtr<const CPDF_Dictionary> pElement =
+  RetainPtr<const CPDF_Dictionary> element =
       ToDictionary(pArray->GetDirectObjectAt(index));
-  return pElement ? GetFieldByDict(pElement.Get()) : nullptr;
+  return element ? GetFieldByDict(element.Get()) : nullptr;
 }
 
 int CPDF_InteractiveForm::FindFieldInCalculationOrder(
-    const CPDF_FormField* pField) {
-  if (!m_pFormDict)
+    const CPDF_FormField* field) {
+  if (!m_pFormDict) {
     return -1;
+  }
 
   RetainPtr<const CPDF_Array> pArray = m_pFormDict->GetArrayFor("CO");
-  if (!pArray)
+  if (!pArray) {
     return -1;
+  }
 
-  std::optional<size_t> maybe_found = pArray->Find(pField->GetFieldDict());
-  if (!maybe_found.has_value())
+  std::optional<size_t> maybe_found = pArray->Find(field->GetFieldDict());
+  if (!maybe_found.has_value()) {
     return -1;
+  }
 
   return pdfium::checked_cast<int>(maybe_found.value());
 }
 
 RetainPtr<CPDF_Font> CPDF_InteractiveForm::GetFormFont(
-    ByteString csNameTag) const {
-  ByteString csAlias = PDF_NameDecode(csNameTag.AsStringView());
-  if (!m_pFormDict || csAlias.IsEmpty())
+    ByteString name_tag) const {
+  if (!m_pFormDict) {
     return nullptr;
+  }
+  ByteString alias = PDF_NameDecode(name_tag.AsStringView());
+  if (alias.IsEmpty()) {
+    return nullptr;
+  }
 
   RetainPtr<CPDF_Dictionary> pDR = m_pFormDict->GetMutableDictFor("DR");
-  if (!pDR)
+  if (!pDR) {
     return nullptr;
+  }
 
-  RetainPtr<CPDF_Dictionary> pFonts = pDR->GetMutableDictFor("Font");
-  if (!ValidateFontResourceDict(pFonts.Get()))
+  RetainPtr<CPDF_Dictionary> font_dict = pDR->GetMutableDictFor("Font");
+  if (!ValidateFontResourceDict(font_dict.Get())) {
     return nullptr;
+  }
 
-  RetainPtr<CPDF_Dictionary> pElement = pFonts->GetMutableDictFor(csAlias);
-  if (!ValidateDictType(pElement.Get(), "Font"))
+  RetainPtr<CPDF_Dictionary> element = font_dict->GetMutableDictFor(alias);
+  if (!ValidateDictType(element.Get(), "Font")) {
     return nullptr;
+  }
 
-  return GetFontForElement(std::move(pElement));
+  return GetFontForElement(std::move(element));
 }
 
 RetainPtr<CPDF_Font> CPDF_InteractiveForm::GetFontForElement(
-    RetainPtr<CPDF_Dictionary> pElement) const {
+    RetainPtr<CPDF_Dictionary> element) const {
   auto* pData = CPDF_DocPageData::FromDocument(m_pDocument);
-  return pData->GetFont(std::move(pElement));
+  return pData->GetFont(std::move(element));
 }
 
 CPDF_DefaultAppearance CPDF_InteractiveForm::GetDefaultAppearance() const {
@@ -752,15 +827,18 @@ void CPDF_InteractiveForm::ResetForm(pdfium::span<CPDF_FormField*> fields,
   CFieldTree::Node* pRoot = m_pFieldTree->GetRoot();
   const size_t nCount = pRoot->CountFields();
   for (size_t i = 0; i < nCount; ++i) {
-    CPDF_FormField* pField = pRoot->GetFieldAtIndex(i);
-    if (!pField)
+    CPDF_FormField* field = pRoot->GetFieldAtIndex(i);
+    if (!field) {
       continue;
+    }
 
-    if (bIncludeOrExclude == pdfium::Contains(fields, pField))
-      pField->ResetField();
+    if (bIncludeOrExclude == pdfium::Contains(fields, field)) {
+      field->ResetField();
+    }
   }
-  if (m_pFormNotify)
+  if (m_pFormNotify) {
     m_pFormNotify->AfterFormReset(this);
+  }
 }
 
 void CPDF_InteractiveForm::ResetForm() {
@@ -768,137 +846,154 @@ void CPDF_InteractiveForm::ResetForm() {
 }
 
 const std::vector<UnownedPtr<CPDF_FormControl>>&
-CPDF_InteractiveForm::GetControlsForField(const CPDF_FormField* pField) {
-  return m_ControlLists[pdfium::WrapUnowned(pField)];
+CPDF_InteractiveForm::GetControlsForField(const CPDF_FormField* field) {
+  return m_ControlLists[pdfium::WrapUnowned(field)];
 }
 
-void CPDF_InteractiveForm::LoadField(RetainPtr<CPDF_Dictionary> pFieldDict,
+void CPDF_InteractiveForm::LoadField(RetainPtr<CPDF_Dictionary> field_dict,
                                      int nLevel) {
-  if (nLevel > nMaxRecursion)
+  if (nLevel > kMaxRecursion) {
     return;
-  if (!pFieldDict)
+  }
+  if (!field_dict) {
     return;
+  }
 
-  uint32_t dwParentObjNum = pFieldDict->GetObjNum();
-  RetainPtr<CPDF_Array> pKids =
-      pFieldDict->GetMutableArrayFor(pdfium::form_fields::kKids);
-  if (!pKids) {
-    AddTerminalField(std::move(pFieldDict));
+  uint32_t dwParentObjNum = field_dict->GetObjNum();
+  RetainPtr<CPDF_Array> kids =
+      field_dict->GetMutableArrayFor(pdfium::form_fields::kKids);
+  if (!kids) {
+    AddTerminalField(std::move(field_dict));
     return;
   }
 
-  RetainPtr<const CPDF_Dictionary> pFirstKid = pKids->GetDictAt(0);
-  if (!pFirstKid)
+  RetainPtr<const CPDF_Dictionary> pFirstKid = kids->GetDictAt(0);
+  if (!pFirstKid) {
     return;
+  }
 
   if (!pFirstKid->KeyExist(pdfium::form_fields::kT) &&
       !pFirstKid->KeyExist(pdfium::form_fields::kKids)) {
-    AddTerminalField(std::move(pFieldDict));
+    AddTerminalField(std::move(field_dict));
     return;
   }
-  for (size_t i = 0; i < pKids->size(); i++) {
-    RetainPtr<CPDF_Dictionary> pChildDict = pKids->GetMutableDictAt(i);
-    if (pChildDict && pChildDict->GetObjNum() != dwParentObjNum)
+  for (size_t i = 0; i < kids->size(); i++) {
+    RetainPtr<CPDF_Dictionary> pChildDict = kids->GetMutableDictAt(i);
+    if (pChildDict && pChildDict->GetObjNum() != dwParentObjNum) {
       LoadField(std::move(pChildDict), nLevel + 1);
+    }
   }
 }
 
-void CPDF_InteractiveForm::FixPageFields(CPDF_Page* pPage) {
-  RetainPtr<CPDF_Array> pAnnots = pPage->GetMutableAnnotsArray();
-  if (!pAnnots)
+void CPDF_InteractiveForm::FixPageFields(CPDF_Page* page) {
+  RetainPtr<CPDF_Array> annots = page->GetMutableAnnotsArray();
+  if (!annots) {
     return;
+  }
 
-  for (size_t i = 0; i < pAnnots->size(); i++) {
-    RetainPtr<CPDF_Dictionary> pAnnot = pAnnots->GetMutableDictAt(i);
-    if (pAnnot && pAnnot->GetNameFor("Subtype") == "Widget")
-      LoadField(std::move(pAnnot), 0);
+  for (size_t i = 0; i < annots->size(); i++) {
+    RetainPtr<CPDF_Dictionary> annot = annots->GetMutableDictAt(i);
+    if (annot && annot->GetNameFor("Subtype") == "Widget") {
+      LoadField(std::move(annot), 0);
+    }
   }
 }
 
 void CPDF_InteractiveForm::AddTerminalField(
-    RetainPtr<CPDF_Dictionary> pFieldDict) {
-  if (!pFieldDict->KeyExist(pdfium::form_fields::kFT)) {
+    RetainPtr<CPDF_Dictionary> field_dict) {
+  if (!field_dict->KeyExist(pdfium::form_fields::kFT)) {
     // Key "FT" is required for terminal fields, it is also inheritable.
     RetainPtr<const CPDF_Dictionary> pParentDict =
-        pFieldDict->GetDictFor(pdfium::form_fields::kParent);
-    if (!pParentDict || !pParentDict->KeyExist(pdfium::form_fields::kFT))
+        field_dict->GetDictFor(pdfium::form_fields::kParent);
+    if (!pParentDict || !pParentDict->KeyExist(pdfium::form_fields::kFT)) {
       return;
+    }
   }
 
-  WideString csWName = CPDF_FormField::GetFullNameForDict(pFieldDict.Get());
-  if (csWName.IsEmpty())
+  WideString field_name = CPDF_FormField::GetFullNameForDict(field_dict.Get());
+  if (field_name.IsEmpty()) {
     return;
+  }
 
-  CPDF_FormField* pField = nullptr;
-  pField = m_pFieldTree->GetField(csWName);
-  if (!pField) {
-    RetainPtr<CPDF_Dictionary> pParent(pFieldDict);
-    if (!pFieldDict->KeyExist(pdfium::form_fields::kT) &&
-        pFieldDict->GetNameFor("Subtype") == "Widget") {
-      pParent = pFieldDict->GetMutableDictFor(pdfium::form_fields::kParent);
-      if (!pParent)
-        pParent = pFieldDict;
+  CPDF_FormField* field = m_pFieldTree->GetField(field_name);
+  if (!field) {
+    RetainPtr<CPDF_Dictionary> pParent(field_dict);
+    if (!field_dict->KeyExist(pdfium::form_fields::kT) &&
+        field_dict->GetNameFor("Subtype") == "Widget") {
+      pParent = field_dict->GetMutableDictFor(pdfium::form_fields::kParent);
+      if (!pParent) {
+        pParent = field_dict;
+      }
     }
 
-    if (pParent && pParent != pFieldDict &&
+    if (pParent && pParent != field_dict &&
         !pParent->KeyExist(pdfium::form_fields::kFT)) {
-      if (pFieldDict->KeyExist(pdfium::form_fields::kFT)) {
+      if (field_dict->KeyExist(pdfium::form_fields::kFT)) {
         RetainPtr<const CPDF_Object> pFTValue =
-            pFieldDict->GetDirectObjectFor(pdfium::form_fields::kFT);
-        if (pFTValue)
+            field_dict->GetDirectObjectFor(pdfium::form_fields::kFT);
+        if (pFTValue) {
           pParent->SetFor(pdfium::form_fields::kFT, pFTValue->Clone());
+        }
       }
 
-      if (pFieldDict->KeyExist(pdfium::form_fields::kFf)) {
+      if (field_dict->KeyExist(pdfium::form_fields::kFf)) {
         RetainPtr<const CPDF_Object> pFfValue =
-            pFieldDict->GetDirectObjectFor(pdfium::form_fields::kFf);
-        if (pFfValue)
+            field_dict->GetDirectObjectFor(pdfium::form_fields::kFf);
+        if (pFfValue) {
           pParent->SetFor(pdfium::form_fields::kFf, pFfValue->Clone());
+        }
       }
     }
 
-    auto newField = std::make_unique<CPDF_FormField>(this, std::move(pParent));
-    pField = newField.get();
-    RetainPtr<const CPDF_Object> pTObj =
-        pFieldDict->GetObjectFor(pdfium::form_fields::kT);
-    if (ToReference(pTObj)) {
-      RetainPtr<CPDF_Object> pClone = pTObj->CloneDirectObject();
-      if (pClone)
-        pFieldDict->SetFor(pdfium::form_fields::kT, std::move(pClone));
-      else
-        pFieldDict->SetNewFor<CPDF_Name>(pdfium::form_fields::kT, ByteString());
+    auto new_field = std::make_unique<CPDF_FormField>(this, std::move(pParent));
+    field = new_field.get();
+    RetainPtr<const CPDF_Object> t_obj =
+        field_dict->GetObjectFor(pdfium::form_fields::kT);
+    if (ToReference(t_obj)) {
+      RetainPtr<CPDF_Object> t_obj_clone = t_obj->CloneDirectObject();
+      if (t_obj_clone && t_obj_clone->IsString()) {
+        field_dict->SetFor(pdfium::form_fields::kT, std::move(t_obj_clone));
+      } else {
+        field_dict->SetNewFor<CPDF_String>(pdfium::form_fields::kT,
+                                           ByteString());
+      }
     }
-    if (!m_pFieldTree->SetField(csWName, std::move(newField)))
+    if (!m_pFieldTree->SetField(field_name, std::move(new_field))) {
       return;
+    }
   }
 
-  RetainPtr<CPDF_Array> pKids =
-      pFieldDict->GetMutableArrayFor(pdfium::form_fields::kKids);
-  if (!pKids) {
-    if (pFieldDict->GetNameFor("Subtype") == "Widget")
-      AddControl(pField, std::move(pFieldDict));
+  RetainPtr<CPDF_Array> kids =
+      field_dict->GetMutableArrayFor(pdfium::form_fields::kKids);
+  if (!kids) {
+    if (field_dict->GetNameFor("Subtype") == "Widget") {
+      AddControl(field, std::move(field_dict));
+    }
     return;
   }
-  for (size_t i = 0; i < pKids->size(); i++) {
-    RetainPtr<CPDF_Dictionary> pKid = pKids->GetMutableDictAt(i);
-    if (pKid && pKid->GetNameFor("Subtype") == "Widget")
-      AddControl(pField, std::move(pKid));
+  for (size_t i = 0; i < kids->size(); i++) {
+    RetainPtr<CPDF_Dictionary> kid = kids->GetMutableDictAt(i);
+    if (kid && kid->GetNameFor("Subtype") == "Widget") {
+      AddControl(field, std::move(kid));
+    }
   }
 }
 
 CPDF_FormControl* CPDF_InteractiveForm::AddControl(
-    CPDF_FormField* pField,
-    RetainPtr<CPDF_Dictionary> pWidgetDict) {
-  DCHECK(pWidgetDict);
-  const auto it = m_ControlMap.find(pWidgetDict.Get());
-  if (it != m_ControlMap.end())
+    CPDF_FormField* field,
+    RetainPtr<CPDF_Dictionary> widget_dict) {
+  DCHECK(widget_dict);
+  const auto it = m_ControlMap.find(widget_dict.Get());
+  if (it != m_ControlMap.end()) {
     return it->second.get();
+  }
 
-  auto pNew = std::make_unique<CPDF_FormControl>(pField, pWidgetDict, this);
-  CPDF_FormControl* pControl = pNew.get();
-  m_ControlMap[pWidgetDict] = std::move(pNew);
-  m_ControlLists[pdfium::WrapUnowned(pField)].emplace_back(pControl);
-  return pControl;
+  auto new_control =
+      std::make_unique<CPDF_FormControl>(field, widget_dict, this);
+  CPDF_FormControl* control = new_control.get();
+  m_ControlMap[widget_dict] = std::move(new_control);
+  m_ControlLists[pdfium::WrapUnowned(field)].emplace_back(control);
+  return control;
 }
 
 bool CPDF_InteractiveForm::CheckRequiredFields(
@@ -907,26 +1002,29 @@ bool CPDF_InteractiveForm::CheckRequiredFields(
   CFieldTree::Node* pRoot = m_pFieldTree->GetRoot();
   const size_t nCount = pRoot->CountFields();
   for (size_t i = 0; i < nCount; ++i) {
-    CPDF_FormField* pField = pRoot->GetFieldAtIndex(i);
-    if (!pField)
+    CPDF_FormField* field = pRoot->GetFieldAtIndex(i);
+    if (!field) {
       continue;
+    }
 
-    int32_t iType = pField->GetType();
+    int32_t iType = field->GetType();
     if (iType == CPDF_FormField::kPushButton ||
         iType == CPDF_FormField::kCheckBox ||
         iType == CPDF_FormField::kListBox) {
       continue;
     }
-    if (pField->IsNoExport())
+    if (field->IsNoExport()) {
       continue;
+    }
 
     bool bFind = true;
-    if (fields)
-      bFind = pdfium::Contains(*fields, pField);
+    if (fields) {
+      bFind = pdfium::Contains(*fields, field);
+    }
     if (bIncludeOrExclude == bFind) {
-      RetainPtr<const CPDF_Dictionary> pFieldDict = pField->GetFieldDict();
-      if (pField->IsRequired() &&
-          pFieldDict->GetByteStringFor(pdfium::form_fields::kV).IsEmpty()) {
+      RetainPtr<const CPDF_Dictionary> field_dict = field->GetFieldDict();
+      if (field->IsRequired() &&
+          field_dict->GetByteStringFor(pdfium::form_fields::kV).IsEmpty()) {
         return false;
       }
     }
@@ -939,8 +1037,9 @@ std::unique_ptr<CFDF_Document> CPDF_InteractiveForm::ExportToFDF(
   std::vector<CPDF_FormField*> fields;
   CFieldTree::Node* pRoot = m_pFieldTree->GetRoot();
   const size_t nCount = pRoot->CountFields();
-  for (size_t i = 0; i < nCount; ++i)
+  for (size_t i = 0; i < nCount; ++i) {
     fields.push_back(pRoot->GetFieldAtIndex(i));
+  }
   return ExportToFDF(pdf_path, fields, true);
 }
 
@@ -949,96 +1048,104 @@ std::unique_ptr<CFDF_Document> CPDF_InteractiveForm::ExportToFDF(
     const std::vector<CPDF_FormField*>& fields,
     bool bIncludeOrExclude) const {
   std::unique_ptr<CFDF_Document> pDoc = CFDF_Document::CreateNewDoc();
-  if (!pDoc)
+  if (!pDoc) {
     return nullptr;
+  }
 
   RetainPtr<CPDF_Dictionary> pMainDict =
       pDoc->GetMutableRoot()->GetMutableDictFor("FDF");
   if (!pdf_path.IsEmpty()) {
-    auto pNewDict = pDoc->New<CPDF_Dictionary>();
-    pNewDict->SetNewFor<CPDF_Name>("Type", "Filespec");
+    auto new_dict = pDoc->New<CPDF_Dictionary>();
+    new_dict->SetNewFor<CPDF_Name>("Type", "Filespec");
     WideString wsStr = CPDF_FileSpec::EncodeFileName(pdf_path);
-    pNewDict->SetNewFor<CPDF_String>(pdfium::stream::kF, wsStr.ToDefANSI());
-    pNewDict->SetNewFor<CPDF_String>("UF", wsStr.AsStringView());
-    pMainDict->SetFor("F", pNewDict);
+    new_dict->SetNewFor<CPDF_String>(pdfium::stream::kF, wsStr.ToDefANSI());
+    new_dict->SetNewFor<CPDF_String>("UF", wsStr.AsStringView());
+    pMainDict->SetFor("F", new_dict);
   }
 
-  auto pFields = pMainDict->SetNewFor<CPDF_Array>("Fields");
+  auto fields_array = pMainDict->SetNewFor<CPDF_Array>("Fields");
   CFieldTree::Node* pRoot = m_pFieldTree->GetRoot();
   const size_t nCount = pRoot->CountFields();
   for (size_t i = 0; i < nCount; ++i) {
-    CPDF_FormField* pField = pRoot->GetFieldAtIndex(i);
-    if (!pField || pField->GetType() == CPDF_FormField::kPushButton)
+    CPDF_FormField* field = pRoot->GetFieldAtIndex(i);
+    if (!field || field->GetType() == CPDF_FormField::kPushButton) {
       continue;
+    }
 
-    uint32_t dwFlags = pField->GetFieldFlags();
-    if (dwFlags & pdfium::form_flags::kNoExport)
+    uint32_t dwFlags = field->GetFieldFlags();
+    if (dwFlags & pdfium::form_flags::kNoExport) {
       continue;
+    }
 
-    if (bIncludeOrExclude != pdfium::Contains(fields, pField))
+    if (bIncludeOrExclude != pdfium::Contains(fields, field)) {
       continue;
+    }
 
     if ((dwFlags & pdfium::form_flags::kRequired) != 0 &&
-        pField->GetFieldDict()
+        field->GetFieldDict()
             ->GetByteStringFor(pdfium::form_fields::kV)
             .IsEmpty()) {
       continue;
     }
 
     WideString fullname =
-        CPDF_FormField::GetFullNameForDict(pField->GetFieldDict());
-    auto pFieldDict = pDoc->New<CPDF_Dictionary>();
-    pFieldDict->SetNewFor<CPDF_String>(pdfium::form_fields::kT,
+        CPDF_FormField::GetFullNameForDict(field->GetFieldDict());
+    auto field_dict = pDoc->New<CPDF_Dictionary>();
+    field_dict->SetNewFor<CPDF_String>(pdfium::form_fields::kT,
                                        fullname.AsStringView());
-    if (pField->GetType() == CPDF_FormField::kCheckBox ||
-        pField->GetType() == CPDF_FormField::kRadioButton) {
-      WideString csExport = pField->GetCheckValue(false);
-      ByteString csBExport = PDF_EncodeText(csExport.AsStringView());
-      RetainPtr<const CPDF_Object> pOpt = pField->GetFieldAttr("Opt");
-      if (pOpt) {
-        pFieldDict->SetNewFor<CPDF_String>(pdfium::form_fields::kV, csBExport);
+    if (field->GetType() == CPDF_FormField::kCheckBox ||
+        field->GetType() == CPDF_FormField::kRadioButton) {
+      ByteString export_value =
+          PDF_EncodeText(field->GetCheckValue(false).AsStringView());
+      RetainPtr<const CPDF_Object> opt = field->GetFieldAttr("Opt");
+      if (opt) {
+        field_dict->SetNewFor<CPDF_String>(pdfium::form_fields::kV,
+                                           export_value);
       } else {
-        pFieldDict->SetNewFor<CPDF_Name>(pdfium::form_fields::kV, csBExport);
+        field_dict->SetNewFor<CPDF_Name>(pdfium::form_fields::kV, export_value);
       }
     } else {
-      RetainPtr<const CPDF_Object> pV =
-          pField->GetFieldAttr(pdfium::form_fields::kV);
-      if (pV)
-        pFieldDict->SetFor(pdfium::form_fields::kV, pV->CloneDirectObject());
+      RetainPtr<const CPDF_Object> value =
+          field->GetFieldAttr(pdfium::form_fields::kV);
+      if (value) {
+        field_dict->SetFor(pdfium::form_fields::kV, value->CloneDirectObject());
+      }
     }
-    pFields->Append(pFieldDict);
+    fields_array->Append(field_dict);
   }
   return pDoc;
 }
 
-void CPDF_InteractiveForm::SetNotifierIface(NotifierIface* pNotify) {
-  m_pFormNotify = pNotify;
+void CPDF_InteractiveForm::SetNotifierIface(NotifierIface* notify) {
+  m_pFormNotify = notify;
 }
 
-bool CPDF_InteractiveForm::NotifyBeforeValueChange(CPDF_FormField* pField,
-                                                   const WideString& csValue) {
-  return !m_pFormNotify || m_pFormNotify->BeforeValueChange(pField, csValue);
+bool CPDF_InteractiveForm::NotifyBeforeValueChange(CPDF_FormField* field,
+                                                   const WideString& value) {
+  return !m_pFormNotify || m_pFormNotify->BeforeValueChange(field, value);
 }
 
-void CPDF_InteractiveForm::NotifyAfterValueChange(CPDF_FormField* pField) {
-  if (m_pFormNotify)
-    m_pFormNotify->AfterValueChange(pField);
+void CPDF_InteractiveForm::NotifyAfterValueChange(CPDF_FormField* field) {
+  if (m_pFormNotify) {
+    m_pFormNotify->AfterValueChange(field);
+  }
 }
 
 bool CPDF_InteractiveForm::NotifyBeforeSelectionChange(
-    CPDF_FormField* pField,
-    const WideString& csValue) {
-  return !m_pFormNotify ||
-         m_pFormNotify->BeforeSelectionChange(pField, csValue);
+    CPDF_FormField* field,
+    const WideString& value) {
+  return !m_pFormNotify || m_pFormNotify->BeforeSelectionChange(field, value);
 }
 
-void CPDF_InteractiveForm::NotifyAfterSelectionChange(CPDF_FormField* pField) {
-  if (m_pFormNotify)
-    m_pFormNotify->AfterSelectionChange(pField);
+void CPDF_InteractiveForm::NotifyAfterSelectionChange(CPDF_FormField* field) {
+  if (m_pFormNotify) {
+    m_pFormNotify->AfterSelectionChange(field);
+  }
 }
 
 void CPDF_InteractiveForm::NotifyAfterCheckedStatusChange(
-    CPDF_FormField* pField) {
-  if (m_pFormNotify)
-    m_pFormNotify->AfterCheckedStatusChange(pField);
-}
+    CPDF_FormField* field) {
+  if (m_pFormNotify) {
+    m_pFormNotify->AfterCheckedStatusChange(field);
+  }
+}
\ No newline at end of file
diff --git a/core/fpdfdoc/cpdf_interactiveform.h b/core/fpdfdoc/cpdf_interactiveform.h
index 4e5d18a4d..e6431c477 100644
--- a/core/fpdfdoc/cpdf_interactiveform.h
+++ b/core/fpdfdoc/cpdf_interactiveform.h
@@ -38,42 +38,45 @@ class CPDF_InteractiveForm {
    public:
     virtual ~NotifierIface() = default;
 
-    virtual bool BeforeValueChange(CPDF_FormField* pField,
-                                   const WideString& csValue) = 0;
-    virtual void AfterValueChange(CPDF_FormField* pField) = 0;
-    virtual bool BeforeSelectionChange(CPDF_FormField* pField,
-                                       const WideString& csValue) = 0;
-    virtual void AfterSelectionChange(CPDF_FormField* pField) = 0;
-    virtual void AfterCheckedStatusChange(CPDF_FormField* pField) = 0;
-    virtual void AfterFormReset(CPDF_InteractiveForm* pForm) = 0;
+    virtual bool BeforeValueChange(CPDF_FormField* field,
+                                   const WideString& value) = 0;
+    virtual void AfterValueChange(CPDF_FormField* field) = 0;
+    virtual bool BeforeSelectionChange(CPDF_FormField* field,
+                                       const WideString& value) = 0;
+    virtual void AfterSelectionChange(CPDF_FormField* field) = 0;
+    virtual void AfterCheckedStatusChange(CPDF_FormField* field) = 0;
+    virtual void AfterFormReset(CPDF_InteractiveForm* form) = 0;
   };
 
-  explicit CPDF_InteractiveForm(CPDF_Document* pDocument);
+  explicit CPDF_InteractiveForm(CPDF_Document* document);
   ~CPDF_InteractiveForm();
 
   static bool IsUpdateAPEnabled();
   static void SetUpdateAP(bool bUpdateAP);
   static RetainPtr<CPDF_Font> AddNativeInteractiveFormFont(
-      CPDF_Document* pDocument,
-      ByteString* csNameTag);
+      CPDF_Document* document,
+      ByteString* name_tag);
+  // Adds a new /AcroForm dictionary to the root dictionary of `document`.
+  // Returns the newly created dictionary.
+  static RetainPtr<CPDF_Dictionary> InitAcroFormDict(CPDF_Document* document);
 
-  size_t CountFields(const WideString& csFieldName) const;
-  CPDF_FormField* GetField(size_t index, const WideString& csFieldName) const;
-  CPDF_FormField* GetFieldByDict(const CPDF_Dictionary* pFieldDict) const;
+  size_t CountFields(const WideString& field_name) const;
+  CPDF_FormField* GetField(size_t index, const WideString& field_name) const;
+  CPDF_FormField* GetFieldByDict(const CPDF_Dictionary* field) const;
 
-  const CPDF_FormControl* GetControlAtPoint(const CPDF_Page* pPage,
+  const CPDF_FormControl* GetControlAtPoint(const CPDF_Page* page,
                                             const CFX_PointF& point,
                                             int* z_order) const;
-  CPDF_FormControl* GetControlByDict(const CPDF_Dictionary* pWidgetDict) const;
+  CPDF_FormControl* GetControlByDict(const CPDF_Dictionary* widget_dict) const;
 
   bool NeedConstructAP() const;
   int CountFieldsInCalculationOrder();
   CPDF_FormField* GetFieldInCalculationOrder(int index);
-  int FindFieldInCalculationOrder(const CPDF_FormField* pField);
+  int FindFieldInCalculationOrder(const CPDF_FormField* field);
 
-  RetainPtr<CPDF_Font> GetFormFont(ByteString csNameTag) const;
+  RetainPtr<CPDF_Font> GetFormFont(ByteString name_tag) const;
   RetainPtr<CPDF_Font> GetFontForElement(
-      RetainPtr<CPDF_Dictionary> pElement) const;
+      RetainPtr<CPDF_Dictionary> element) const;
   CPDF_DefaultAppearance GetDefaultAppearance() const;
   int GetFormAlignment() const;
   bool CheckRequiredFields(const std::vector<CPDF_FormField*>* fields,
@@ -88,26 +91,25 @@ class CPDF_InteractiveForm {
   void ResetForm();
   void ResetForm(pdfium::span<CPDF_FormField*> fields, bool bIncludeOrExclude);
 
-  void SetNotifierIface(NotifierIface* pNotify);
-  void FixPageFields(CPDF_Page* pPage);
+  void SetNotifierIface(NotifierIface* notify);
+  void FixPageFields(CPDF_Page* page);
 
   // Wrap callbacks thru NotifierIface.
-  bool NotifyBeforeValueChange(CPDF_FormField* pField,
-                               const WideString& csValue);
-  void NotifyAfterValueChange(CPDF_FormField* pField);
-  bool NotifyBeforeSelectionChange(CPDF_FormField* pField,
-                                   const WideString& csValue);
-  void NotifyAfterSelectionChange(CPDF_FormField* pField);
-  void NotifyAfterCheckedStatusChange(CPDF_FormField* pField);
+  bool NotifyBeforeValueChange(CPDF_FormField* field, const WideString& value);
+  void NotifyAfterValueChange(CPDF_FormField* field);
+  bool NotifyBeforeSelectionChange(CPDF_FormField* field,
+                                   const WideString& value);
+  void NotifyAfterSelectionChange(CPDF_FormField* field);
+  void NotifyAfterCheckedStatusChange(CPDF_FormField* field);
 
   const std::vector<UnownedPtr<CPDF_FormControl>>& GetControlsForField(
-      const CPDF_FormField* pField);
+      const CPDF_FormField* field);
 
  private:
-  void LoadField(RetainPtr<CPDF_Dictionary> pFieldDict, int nLevel);
-  void AddTerminalField(RetainPtr<CPDF_Dictionary> pFieldDict);
-  CPDF_FormControl* AddControl(CPDF_FormField* pField,
-                               RetainPtr<CPDF_Dictionary> pWidgetDict);
+  void LoadField(RetainPtr<CPDF_Dictionary> field_dict, int nLevel);
+  void AddTerminalField(RetainPtr<CPDF_Dictionary> field_dict);
+  CPDF_FormControl* AddControl(CPDF_FormField* field,
+                               RetainPtr<CPDF_Dictionary> widget_dict);
 
   static bool s_bUpdateAP;
 
@@ -127,4 +129,4 @@ class CPDF_InteractiveForm {
   UnownedPtr<NotifierIface> m_pFormNotify;
 };
 
-#endif  // CORE_FPDFDOC_CPDF_INTERACTIVEFORM_H_
+#endif  // CORE_FPDFDOC_CPDF_INTERACTIVEFORM_H_
\ No newline at end of file
diff --git a/core/fpdfdoc/cpvt_variabletext.cpp b/core/fpdfdoc/cpvt_variabletext.cpp
index c890e85c1..bf38becec 100644
--- a/core/fpdfdoc/cpvt_variabletext.cpp
+++ b/core/fpdfdoc/cpvt_variabletext.cpp
@@ -873,6 +873,10 @@ void CPVT_VariableText::SetProvider(Provider* pProvider) {
   m_pVTProvider = pProvider;
 }
 
+CPVT_VariableText::Provider* CPVT_VariableText::GetProvider() {
+  return m_pVTProvider;
+}
+
 CFX_PointF CPVT_VariableText::GetBTPoint() const {
   return CFX_PointF(m_rcPlate.left, m_rcPlate.top);
 }
diff --git a/core/fpdfdoc/cpvt_variabletext.h b/core/fpdfdoc/cpvt_variabletext.h
index a378dbbfd..01982d2b3 100644
--- a/core/fpdfdoc/cpvt_variabletext.h
+++ b/core/fpdfdoc/cpvt_variabletext.h
@@ -70,6 +70,7 @@ class CPVT_VariableText {
   ~CPVT_VariableText();
 
   void SetProvider(Provider* pProvider);
+  Provider* GetProvider();
   CPVT_VariableText::Iterator* GetIterator();
 
   CFX_FloatRect GetContentRect() const;
```

