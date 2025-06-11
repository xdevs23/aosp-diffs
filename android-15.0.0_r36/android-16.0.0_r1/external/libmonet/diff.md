```diff
diff --git a/METADATA b/METADATA
new file mode 100644
index 0000000..c55e6a2
--- /dev/null
+++ b/METADATA
@@ -0,0 +1,8 @@
+name: "libmonet"
+description: ""
+third_party {
+  license_type: NOTICE
+  identifier {
+    type: "Piper"
+  }
+}
\ No newline at end of file
diff --git a/dynamiccolor/DynamicScheme.java b/dynamiccolor/DynamicScheme.java
index 97b1131..2244fa8 100644
--- a/dynamiccolor/DynamicScheme.java
+++ b/dynamiccolor/DynamicScheme.java
@@ -19,6 +19,7 @@ package com.google.ux.material.libmonet.dynamiccolor;
 import com.google.ux.material.libmonet.hct.Hct;
 import com.google.ux.material.libmonet.palettes.TonalPalette;
 import com.google.ux.material.libmonet.utils.MathUtils;
+import java.util.Optional;
 
 /**
  * Provides important settings for creating colors dynamically, and 6 color palettes. Requires: 1. A
@@ -49,6 +50,30 @@ public class DynamicScheme {
       TonalPalette tertiaryPalette,
       TonalPalette neutralPalette,
       TonalPalette neutralVariantPalette) {
+    this(
+        sourceColorHct,
+        variant,
+        isDark,
+        contrastLevel,
+        primaryPalette,
+        secondaryPalette,
+        tertiaryPalette,
+        neutralPalette,
+        neutralVariantPalette,
+        Optional.empty());
+  }
+
+  public DynamicScheme(
+      Hct sourceColorHct,
+      Variant variant,
+      boolean isDark,
+      double contrastLevel,
+      TonalPalette primaryPalette,
+      TonalPalette secondaryPalette,
+      TonalPalette tertiaryPalette,
+      TonalPalette neutralPalette,
+      TonalPalette neutralVariantPalette,
+      Optional<TonalPalette> errorPalette) {
     this.sourceColorArgb = sourceColorHct.toInt();
     this.sourceColorHct = sourceColorHct;
     this.variant = variant;
@@ -60,7 +85,7 @@ public class DynamicScheme {
     this.tertiaryPalette = tertiaryPalette;
     this.neutralPalette = neutralPalette;
     this.neutralVariantPalette = neutralVariantPalette;
-    this.errorPalette = TonalPalette.fromHueAndChroma(25.0, 84.0);
+    this.errorPalette = errorPalette.orElse(TonalPalette.fromHueAndChroma(25.0, 84.0));
   }
 
   /**
diff --git a/dynamiccolor/MaterialDynamicColors.java b/dynamiccolor/MaterialDynamicColors.java
index dfa9f54..586ba4b 100644
--- a/dynamiccolor/MaterialDynamicColors.java
+++ b/dynamiccolor/MaterialDynamicColors.java
@@ -19,6 +19,9 @@ package com.google.ux.material.libmonet.dynamiccolor;
 import android.annotation.NonNull;
 import com.google.ux.material.libmonet.dislike.DislikeAnalyzer;
 import com.google.ux.material.libmonet.hct.Hct;
+import java.util.Arrays;
+import java.util.List;
+import java.util.function.Supplier;
 
 /** Named colors, otherwise known as tokens, or roles, in the Material Design system. */
 // Prevent lint for Function.apply not being available on Android before API level 14 (4.0.1).
@@ -933,6 +936,73 @@ public final class MaterialDynamicColors {
         "text_hint_inverse", (s) -> s.neutralPalette, (s) -> s.isDark ? 10.0 : 90.0);
   }
 
+  /** All dynamic colors in Material Design system. */
+  public final List<Supplier<DynamicColor>> allDynamicColors() {
+    return Arrays.asList(
+        this::primaryPaletteKeyColor,
+        this::secondaryPaletteKeyColor,
+        this::tertiaryPaletteKeyColor,
+        this::neutralPaletteKeyColor,
+        this::neutralVariantPaletteKeyColor,
+        this::background,
+        this::onBackground,
+        this::surface,
+        this::surfaceDim,
+        this::surfaceBright,
+        this::surfaceContainerLowest,
+        this::surfaceContainerLow,
+        this::surfaceContainer,
+        this::surfaceContainerHigh,
+        this::surfaceContainerHighest,
+        this::onSurface,
+        this::surfaceVariant,
+        this::onSurfaceVariant,
+        this::inverseSurface,
+        this::inverseOnSurface,
+        this::outline,
+        this::outlineVariant,
+        this::shadow,
+        this::scrim,
+        this::surfaceTint,
+        this::primary,
+        this::onPrimary,
+        this::primaryContainer,
+        this::onPrimaryContainer,
+        this::inversePrimary,
+        this::secondary,
+        this::onSecondary,
+        this::secondaryContainer,
+        this::onSecondaryContainer,
+        this::tertiary,
+        this::onTertiary,
+        this::tertiaryContainer,
+        this::onTertiaryContainer,
+        this::error,
+        this::onError,
+        this::errorContainer,
+        this::onErrorContainer,
+        this::primaryFixed,
+        this::primaryFixedDim,
+        this::onPrimaryFixed,
+        this::onPrimaryFixedVariant,
+        this::secondaryFixed,
+        this::secondaryFixedDim,
+        this::onSecondaryFixed,
+        this::onSecondaryFixedVariant,
+        this::tertiaryFixed,
+        this::tertiaryFixedDim,
+        this::onTertiaryFixed,
+        this::onTertiaryFixedVariant,
+        this::controlActivated,
+        this::controlNormal,
+        this::controlHighlight,
+        this::textPrimaryInverse,
+        this::textSecondaryAndTertiaryInverse,
+        this::textPrimaryInverseDisableOnly,
+        this::textSecondaryAndTertiaryInverseDisabled,
+        this::textHintInverse);
+  }
+
   private boolean isFidelity(DynamicScheme scheme) {
     if (this.isExtendedFidelity
         && scheme.variant != Variant.MONOCHROME
diff --git a/palettes/CorePalette.java b/palettes/CorePalette.java
index 710a268..ff6b8a9 100644
--- a/palettes/CorePalette.java
+++ b/palettes/CorePalette.java
@@ -24,7 +24,12 @@ import com.google.ux.material.libmonet.hct.Hct;
 /**
  * An intermediate concept between the key color for a UI theme, and a full color scheme. 5 sets of
  * tones are generated, all except one use the same hue as the key color, and all vary in chroma.
+ *
+ * @deprecated Use {@link com.google.ux.material.libmonet.dynamiccolor.DynamicScheme} for color
+ *     scheme generation. Use {@link com.google.ux.material.libmonet.palettes.CorePalettes} for core
+ *     palettes container class.
  */
+@Deprecated
 public final class CorePalette {
   public TonalPalette a1;
   public TonalPalette a2;
@@ -37,7 +42,11 @@ public final class CorePalette {
    * Create key tones from a color.
    *
    * @param argb ARGB representation of a color
+   * @deprecated Use {@link com.google.ux.material.libmonet.dynamiccolor.DynamicScheme} for color
+   *     scheme generation. Use {@link com.google.ux.material.libmonet.palettes.CorePalettes} for
+   *     core palettes container class.
    */
+  @Deprecated
   public static CorePalette of(int argb) {
     return new CorePalette(argb, false);
   }
@@ -46,7 +55,11 @@ public final class CorePalette {
    * Create content key tones from a color.
    *
    * @param argb ARGB representation of a color
+   * @deprecated Use {@link com.google.ux.material.libmonet.dynamiccolor.DynamicScheme} for color
+   *     scheme generation. Use {@link com.google.ux.material.libmonet.palettes.CorePalettes} for
+   *     core palettes container class.
    */
+  @Deprecated
   public static CorePalette contentOf(int argb) {
     return new CorePalette(argb, true);
   }
diff --git a/palettes/CorePalettes.java b/palettes/CorePalettes.java
new file mode 100644
index 0000000..c36fb4e
--- /dev/null
+++ b/palettes/CorePalettes.java
@@ -0,0 +1,45 @@
+/*
+ * Copyright 2024 Google LLC
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
+package com.google.ux.material.libmonet.palettes;
+
+/**
+ * Comprises foundational palettes to build a color scheme.
+ *
+ * <p>Generated from a source color, these palettes will then be part of a [DynamicScheme] together
+ * with appearance preferences.
+ */
+public final class CorePalettes {
+  public TonalPalette primary;
+  public TonalPalette secondary;
+  public TonalPalette tertiary;
+  public TonalPalette neutral;
+  public TonalPalette neutralVariant;
+
+  /** Creates a new CorePalettes. */
+  public CorePalettes(
+      TonalPalette primary,
+      TonalPalette secondary,
+      TonalPalette tertiary,
+      TonalPalette neutral,
+      TonalPalette neutralVariant) {
+    this.primary = primary;
+    this.secondary = secondary;
+    this.tertiary = tertiary;
+    this.neutral = neutral;
+    this.neutralVariant = neutralVariant;
+  }
+}
diff --git a/palettes/TonalPalette.java b/palettes/TonalPalette.java
index bcb8657..6357aef 100644
--- a/palettes/TonalPalette.java
+++ b/palettes/TonalPalette.java
@@ -22,6 +22,8 @@ import java.util.Map;
 
 /**
  * A convenience class for retrieving colors that are constant in hue and chroma, but vary in tone.
+ *
+ * <p>TonalPalette is intended for use in a single thread due to its stateful caching.
  */
 public final class TonalPalette {
   Map<Integer, Integer> cache;
@@ -74,8 +76,6 @@ public final class TonalPalette {
    * @param tone HCT tone, measured from 0 to 100.
    * @return ARGB representation of a color with that tone.
    */
-  // AndroidJdkLibsChecker is higher priority than ComputeIfAbsentUseValue (b/119581923)
-  @SuppressWarnings("ComputeIfAbsentUseValue")
   public int tone(int tone) {
     Integer color = cache.get(tone);
     if (color == null) {
@@ -171,8 +171,13 @@ public final class TonalPalette {
 
     // Find the maximum chroma for a given tone
     private double maxChroma(int tone) {
-      return chromaCache.computeIfAbsent(
-          tone, (Integer key) -> Hct.from(hue, MAX_CHROMA_VALUE, key).getChroma());
+      if (chromaCache.get(tone) == null) {
+        Double newChroma = Hct.from(hue, MAX_CHROMA_VALUE, tone).getChroma();
+        if (newChroma != null) {
+          chromaCache.put(tone, newChroma);
+        }
+      }
+      return chromaCache.get(tone);
     }
   }
 }
```

