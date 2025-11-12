```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index f1e4324..f1a0b35 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -46,4 +46,4 @@
       ]
     }
   ]
-}
\ No newline at end of file
+}
diff --git a/dynamiccolor/ColorSpec.java b/dynamiccolor/ColorSpec.java
new file mode 100644
index 0000000..0fd1f74
--- /dev/null
+++ b/dynamiccolor/ColorSpec.java
@@ -0,0 +1,318 @@
+/*
+ * Copyright 2025 Google LLC
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
+package com.google.ux.material.libmonet.dynamiccolor;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme.Platform;
+import com.google.ux.material.libmonet.hct.Hct;
+import com.google.ux.material.libmonet.palettes.TonalPalette;
+import java.util.Optional;
+
+/** An interface defining all the necessary methods that could be different between specs. */
+public interface ColorSpec {
+
+  /** All available spec versions. */
+  public enum SpecVersion {
+    SPEC_2021,
+    SPEC_2025,
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Main Palettes                                              //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor primaryPaletteKeyColor();
+
+  @NonNull
+  public DynamicColor secondaryPaletteKeyColor();
+
+  @NonNull
+  public DynamicColor tertiaryPaletteKeyColor();
+
+  @NonNull
+  public DynamicColor neutralPaletteKeyColor();
+
+  @NonNull
+  public DynamicColor neutralVariantPaletteKeyColor();
+
+  @NonNull
+  public DynamicColor errorPaletteKeyColor();
+
+  ////////////////////////////////////////////////////////////////
+  // Surfaces [S]                                               //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor background();
+
+  @NonNull
+  public DynamicColor onBackground();
+
+  @NonNull
+  public DynamicColor surface();
+
+  @NonNull
+  public DynamicColor surfaceDim();
+
+  @NonNull
+  public DynamicColor surfaceBright();
+
+  @NonNull
+  public DynamicColor surfaceContainerLowest();
+
+  @NonNull
+  public DynamicColor surfaceContainerLow();
+
+  @NonNull
+  public DynamicColor surfaceContainer();
+
+  @NonNull
+  public DynamicColor surfaceContainerHigh();
+
+  @NonNull
+  public DynamicColor surfaceContainerHighest();
+
+  @NonNull
+  public DynamicColor onSurface();
+
+  @NonNull
+  public DynamicColor surfaceVariant();
+
+  @NonNull
+  public DynamicColor onSurfaceVariant();
+
+  @NonNull
+  public DynamicColor inverseSurface();
+
+  @NonNull
+  public DynamicColor inverseOnSurface();
+
+  @NonNull
+  public DynamicColor outline();
+
+  @NonNull
+  public DynamicColor outlineVariant();
+
+  @NonNull
+  public DynamicColor shadow();
+
+  @NonNull
+  public DynamicColor scrim();
+
+  @NonNull
+  public DynamicColor surfaceTint();
+
+  ////////////////////////////////////////////////////////////////
+  // Primaries [P]                                              //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor primary();
+
+  @Nullable
+  public DynamicColor primaryDim();
+
+  @NonNull
+  public DynamicColor onPrimary();
+
+  @NonNull
+  public DynamicColor primaryContainer();
+
+  @NonNull
+  public DynamicColor onPrimaryContainer();
+
+  @NonNull
+  public DynamicColor inversePrimary();
+
+  ////////////////////////////////////////////////////////////////
+  // Secondaries [Q]                                            //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor secondary();
+
+  @Nullable
+  public DynamicColor secondaryDim();
+
+  @NonNull
+  public DynamicColor onSecondary();
+
+  @NonNull
+  public DynamicColor secondaryContainer();
+
+  @NonNull
+  public DynamicColor onSecondaryContainer();
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiaries [T]                                             //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor tertiary();
+
+  @Nullable
+  public DynamicColor tertiaryDim();
+
+  @NonNull
+  public DynamicColor onTertiary();
+
+  @NonNull
+  public DynamicColor tertiaryContainer();
+
+  @NonNull
+  public DynamicColor onTertiaryContainer();
+
+  ////////////////////////////////////////////////////////////////
+  // Errors [E]                                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor error();
+
+  @Nullable
+  public DynamicColor errorDim();
+
+  @NonNull
+  public DynamicColor onError();
+
+  @NonNull
+  public DynamicColor errorContainer();
+
+  @NonNull
+  public DynamicColor onErrorContainer();
+
+  ////////////////////////////////////////////////////////////////
+  // Primary Fixed Colors [PF]                                  //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor primaryFixed();
+
+  @NonNull
+  public DynamicColor primaryFixedDim();
+
+  @NonNull
+  public DynamicColor onPrimaryFixed();
+
+  @NonNull
+  public DynamicColor onPrimaryFixedVariant();
+
+  ////////////////////////////////////////////////////////////////
+  // Secondary Fixed Colors [QF]                                //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor secondaryFixed();
+
+  @NonNull
+  public DynamicColor secondaryFixedDim();
+
+  @NonNull
+  public DynamicColor onSecondaryFixed();
+
+  @NonNull
+  public DynamicColor onSecondaryFixedVariant();
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiary Fixed Colors [TF]                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor tertiaryFixed();
+
+  @NonNull
+  public DynamicColor tertiaryFixedDim();
+
+  @NonNull
+  public DynamicColor onTertiaryFixed();
+
+  @NonNull
+  public DynamicColor onTertiaryFixedVariant();
+
+  //////////////////////////////////////////////////////////////////
+  // Android-only Colors                                          //
+  //////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor controlActivated();
+
+  @NonNull
+  public DynamicColor controlNormal();
+
+  @NonNull
+  public DynamicColor controlHighlight();
+
+  @NonNull
+  public DynamicColor textPrimaryInverse();
+
+  @NonNull
+  public DynamicColor textSecondaryAndTertiaryInverse();
+
+  @NonNull
+  public DynamicColor textPrimaryInverseDisableOnly();
+
+  @NonNull
+  public DynamicColor textSecondaryAndTertiaryInverseDisabled();
+
+  @NonNull
+  public DynamicColor textHintInverse();
+
+  ////////////////////////////////////////////////////////////////
+  // Other                                                      //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public DynamicColor highestSurface(@NonNull DynamicScheme s);
+
+  /////////////////////////////////////////////////////////////////
+  // Color value calculations                                    //
+  /////////////////////////////////////////////////////////////////
+
+  Hct getHct(DynamicScheme scheme, DynamicColor color);
+
+  double getTone(DynamicScheme scheme, DynamicColor color);
+
+  //////////////////////////////////////////////////////////////////
+  // Scheme Palettes                                              //
+  //////////////////////////////////////////////////////////////////
+
+  @NonNull
+  public TonalPalette getPrimaryPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+
+  @NonNull
+  public TonalPalette getSecondaryPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+
+  @NonNull
+  public TonalPalette getTertiaryPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+
+  @NonNull
+  public TonalPalette getNeutralPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+
+  @NonNull
+  public TonalPalette getNeutralVariantPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+
+  @NonNull
+  public Optional<TonalPalette> getErrorPalette(
+      Variant variant, Hct sourceColorHct, boolean isDark, Platform platform, double contrastLevel);
+}
diff --git a/dynamiccolor/ColorSpec2021.java b/dynamiccolor/ColorSpec2021.java
new file mode 100644
index 0000000..7e28cf1
--- /dev/null
+++ b/dynamiccolor/ColorSpec2021.java
@@ -0,0 +1,1455 @@
+/*
+ * Copyright 2025 Google LLC
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
+package com.google.ux.material.libmonet.dynamiccolor;
+
+import static java.lang.Math.max;
+import static java.lang.Math.min;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import com.google.errorprone.annotations.Var;
+import com.google.ux.material.libmonet.contrast.Contrast;
+import com.google.ux.material.libmonet.dislike.DislikeAnalyzer;
+import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme.Platform;
+import com.google.ux.material.libmonet.hct.Hct;
+import com.google.ux.material.libmonet.palettes.TonalPalette;
+import com.google.ux.material.libmonet.temperature.TemperatureCache;
+import com.google.ux.material.libmonet.utils.MathUtils;
+import java.util.ArrayList;
+import java.util.Optional;
+
+/** {@link ColorSpec} implementation for the 2021 spec. */
+class ColorSpec2021 implements ColorSpec {
+
+  ////////////////////////////////////////////////////////////////
+  // Main Palettes                                              //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor primaryPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("primary_palette_key_color")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> s.primaryPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("secondary_palette_key_color")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> s.secondaryPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("tertiary_palette_key_color")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone((s) -> s.tertiaryPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor neutralPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("neutral_palette_key_color")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.neutralPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor neutralVariantPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("neutral_variant_palette_key_color")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.neutralVariantPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor errorPaletteKeyColor() {
+    return new DynamicColor.Builder()
+        .setName("error_palette_key_color")
+        .setPalette((s) -> s.errorPalette)
+        .setTone((s) -> s.errorPalette.getKeyColor().getTone())
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Surfaces [S]                                               //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor background() {
+    return new DynamicColor.Builder()
+        .setName("background")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 6.0 : 98.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onBackground() {
+    return new DynamicColor.Builder()
+        .setName("on_background")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 90.0 : 10.0)
+        .setBackground((s) -> background())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 3.0, 4.5, 7.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surface() {
+    return new DynamicColor.Builder()
+        .setName("surface")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 6.0 : 98.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceDim() {
+    return new DynamicColor.Builder()
+        .setName("surface_dim")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) -> s.isDark ? 6.0 : new ContrastCurve(87.0, 87.0, 80.0, 75.0).get(s.contrastLevel))
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceBright() {
+    return new DynamicColor.Builder()
+        .setName("surface_bright")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) -> s.isDark ? new ContrastCurve(24.0, 24.0, 29.0, 34.0).get(s.contrastLevel) : 98.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerLowest() {
+    return new DynamicColor.Builder()
+        .setName("surface_container_lowest")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) -> s.isDark ? new ContrastCurve(4.0, 4.0, 2.0, 0.0).get(s.contrastLevel) : 100.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerLow() {
+    return new DynamicColor.Builder()
+        .setName("surface_container_low")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) ->
+                s.isDark
+                    ? new ContrastCurve(10.0, 10.0, 11.0, 12.0).get(s.contrastLevel)
+                    : new ContrastCurve(96.0, 96.0, 96.0, 95.0).get(s.contrastLevel))
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainer() {
+    return new DynamicColor.Builder()
+        .setName("surface_container")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) ->
+                s.isDark
+                    ? new ContrastCurve(12.0, 12.0, 16.0, 20.0).get(s.contrastLevel)
+                    : new ContrastCurve(94.0, 94.0, 92.0, 90.0).get(s.contrastLevel))
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerHigh() {
+    return new DynamicColor.Builder()
+        .setName("surface_container_high")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) ->
+                s.isDark
+                    ? new ContrastCurve(17.0, 17.0, 21.0, 25.0).get(s.contrastLevel)
+                    : new ContrastCurve(92.0, 92.0, 88.0, 85.0).get(s.contrastLevel))
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerHighest() {
+    return new DynamicColor.Builder()
+        .setName("surface_container_highest")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone(
+            (s) ->
+                s.isDark
+                    ? new ContrastCurve(22.0, 22.0, 26.0, 30.0).get(s.contrastLevel)
+                    : new ContrastCurve(90.0, 90.0, 84.0, 80.0).get(s.contrastLevel))
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSurface() {
+    return new DynamicColor.Builder()
+        .setName("on_surface")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 90.0 : 10.0)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceVariant() {
+    return new DynamicColor.Builder()
+        .setName("surface_variant")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 30.0 : 90.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSurfaceVariant() {
+    return new DynamicColor.Builder()
+        .setName("on_surface_variant")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 80.0 : 30.0)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inverseSurface() {
+    return new DynamicColor.Builder()
+        .setName("inverse_surface")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 90.0 : 20.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inverseOnSurface() {
+    return new DynamicColor.Builder()
+        .setName("inverse_on_surface")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 20.0 : 95.0)
+        .setBackground((s) -> inverseSurface())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor outline() {
+    return new DynamicColor.Builder()
+        .setName("outline")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 60.0 : 50.0)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.5, 3.0, 4.5, 7.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor outlineVariant() {
+    return new DynamicColor.Builder()
+        .setName("outline_variant")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 30.0 : 80.0)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor shadow() {
+    return new DynamicColor.Builder()
+        .setName("shadow")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> 0.0)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor scrim() {
+    return new DynamicColor.Builder()
+        .setName("scrim")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> 0.0)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceTint() {
+    return new DynamicColor.Builder()
+        .setName("surface_tint")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> s.isDark ? 80.0 : 40.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Primaries [P]                                              //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor primary() {
+    return new DynamicColor.Builder()
+        .setName("primary")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 100.0 : 0.0;
+              }
+              return s.isDark ? 80.0 : 40.0;
+            })
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 7.0))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(primaryContainer(), primary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor primaryDim() {
+    return null;
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimary() {
+    return new DynamicColor.Builder()
+        .setName("on_primary")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 10.0 : 90.0;
+              }
+              return s.isDark ? 20.0 : 100.0;
+            })
+        .setBackground((s) -> primary())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor primaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("primary_container")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone(
+            (s) -> {
+              if (isFidelity(s)) {
+                return s.sourceColorHct.getTone();
+              }
+              if (isMonochrome(s)) {
+                return s.isDark ? 85.0 : 25.0;
+              }
+              return s.isDark ? 30.0 : 90.0;
+            })
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(primaryContainer(), primary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("on_primary_container")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone(
+            (s) -> {
+              if (isFidelity(s)) {
+                return DynamicColor.foregroundTone(primaryContainer().tone.apply(s), 4.5);
+              }
+              if (isMonochrome(s)) {
+                return s.isDark ? 0.0 : 100.0;
+              }
+              return s.isDark ? 90.0 : 30.0;
+            })
+        .setBackground((s) -> primaryContainer())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inversePrimary() {
+    return new DynamicColor.Builder()
+        .setName("inverse_primary")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> s.isDark ? 40.0 : 80.0)
+        .setBackground((s) -> inverseSurface())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 7.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Secondaries [Q]                                            //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor secondary() {
+    return new DynamicColor.Builder()
+        .setName("secondary")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> s.isDark ? 80.0 : 40.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 7.0))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    secondaryContainer(), secondary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor secondaryDim() {
+    return null;
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondary() {
+    return new DynamicColor.Builder()
+        .setName("on_secondary")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 10.0 : 100.0;
+              }
+              return s.isDark ? 20.0 : 100.0;
+            })
+        .setBackground((s) -> secondary())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("secondary_container")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone(
+            (s) -> {
+              final double initialTone = s.isDark ? 30.0 : 90.0;
+              if (isMonochrome(s)) {
+                return s.isDark ? 30.0 : 85.0;
+              }
+              if (!isFidelity(s)) {
+                return initialTone;
+              }
+              return findDesiredChromaByTone(
+                  s.secondaryPalette.getHue(),
+                  s.secondaryPalette.getChroma(),
+                  initialTone,
+                  !s.isDark);
+            })
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    secondaryContainer(), secondary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("on_secondary_container")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 90.0 : 10.0;
+              }
+              if (!isFidelity(s)) {
+                return s.isDark ? 90.0 : 30.0;
+              }
+              return DynamicColor.foregroundTone(secondaryContainer().tone.apply(s), 4.5);
+            })
+        .setBackground((s) -> secondaryContainer())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiaries [T]                                             //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor tertiary() {
+    return new DynamicColor.Builder()
+        .setName("tertiary")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 90.0 : 25.0;
+              }
+              return s.isDark ? 80.0 : 40.0;
+            })
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 7.0))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    tertiaryContainer(), tertiary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor tertiaryDim() {
+    return null;
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiary() {
+    return new DynamicColor.Builder()
+        .setName("on_tertiary")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 10.0 : 90.0;
+              }
+              return s.isDark ? 20.0 : 100.0;
+            })
+        .setBackground((s) -> tertiary())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("tertiary_container")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 60.0 : 49.0;
+              }
+              if (!isFidelity(s)) {
+                return s.isDark ? 30.0 : 90.0;
+              }
+              final Hct proposedHct = s.tertiaryPalette.getHct(s.sourceColorHct.getTone());
+              return DislikeAnalyzer.fixIfDisliked(proposedHct).getTone();
+            })
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    tertiaryContainer(), tertiary(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryContainer() {
+    return new DynamicColor.Builder()
+        .setName("on_tertiary_container")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 0.0 : 100.0;
+              }
+              if (!isFidelity(s)) {
+                return s.isDark ? 90.0 : 30.0;
+              }
+              return DynamicColor.foregroundTone(tertiaryContainer().tone.apply(s), 4.5);
+            })
+        .setBackground((s) -> tertiaryContainer())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Errors [E]                                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor error() {
+    return new DynamicColor.Builder()
+        .setName("error")
+        .setPalette((s) -> s.errorPalette)
+        .setTone((s) -> s.isDark ? 80.0 : 40.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 7.0))
+        .setToneDeltaPair(
+            (s) -> new ToneDeltaPair(errorContainer(), error(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor errorDim() {
+    return null;
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onError() {
+    return new DynamicColor.Builder()
+        .setName("on_error")
+        .setPalette((s) -> s.errorPalette)
+        .setTone((s) -> s.isDark ? 20.0 : 100.0)
+        .setBackground((s) -> error())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor errorContainer() {
+    return new DynamicColor.Builder()
+        .setName("error_container")
+        .setPalette((s) -> s.errorPalette)
+        .setTone((s) -> s.isDark ? 30.0 : 90.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) -> new ToneDeltaPair(errorContainer(), error(), 10.0, TonePolarity.NEARER, false))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onErrorContainer() {
+    return new DynamicColor.Builder()
+        .setName("on_error_container")
+        .setPalette((s) -> s.errorPalette)
+        .setTone(
+            (s) -> {
+              if (isMonochrome(s)) {
+                return s.isDark ? 90.0 : 10.0;
+              }
+              return s.isDark ? 90.0 : 30.0;
+            })
+        .setBackground((s) -> errorContainer())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Primary Fixed Colors [PF]                                  //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor primaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("primary_fixed")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 40.0 : 90.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    this.primaryFixed(), this.primaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor primaryFixedDim() {
+    return new DynamicColor.Builder()
+        .setName("primary_fixed_dim")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 30.0 : 80.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    primaryFixed(), primaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("on_primary_fixed")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 100.0 : 10.0)
+        .setBackground((s) -> primaryFixedDim())
+        .setSecondBackground((s) -> primaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryFixedVariant() {
+    return new DynamicColor.Builder()
+        .setName("on_primary_fixed_variant")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 90.0 : 30.0)
+        .setBackground((s) -> primaryFixedDim())
+        .setSecondBackground((s) -> primaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Secondary Fixed Colors [QF]                                //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("secondary_fixed")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 80.0 : 90.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    secondaryFixed(), secondaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryFixedDim() {
+    return new DynamicColor.Builder()
+        .setName("secondary_fixed_dim")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 70.0 : 80.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    secondaryFixed(), secondaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("on_secondary_fixed")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> 10.0)
+        .setBackground((s) -> secondaryFixedDim())
+        .setSecondBackground((s) -> secondaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryFixedVariant() {
+    return new DynamicColor.Builder()
+        .setName("on_secondary_fixed_variant")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 25.0 : 30.0)
+        .setBackground((s) -> secondaryFixedDim())
+        .setSecondBackground((s) -> secondaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiary Fixed Colors [TF]                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("tertiary_fixed")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 40.0 : 90.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    tertiaryFixed(), tertiaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryFixedDim() {
+    return new DynamicColor.Builder()
+        .setName("tertiary_fixed_dim")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 30.0 : 80.0)
+        .setIsBackground(true)
+        .setBackground(this::highestSurface)
+        .setContrastCurve((s) -> new ContrastCurve(1.0, 1.0, 3.0, 4.5))
+        .setToneDeltaPair(
+            (s) ->
+                new ToneDeltaPair(
+                    tertiaryFixed(), tertiaryFixedDim(), 10.0, TonePolarity.LIGHTER, true))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryFixed() {
+    return new DynamicColor.Builder()
+        .setName("on_tertiary_fixed")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 100.0 : 10.0)
+        .setBackground((s) -> tertiaryFixedDim())
+        .setSecondBackground((s) -> tertiaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(4.5, 7.0, 11.0, 21.0))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryFixedVariant() {
+    return new DynamicColor.Builder()
+        .setName("on_tertiary_fixed_variant")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone((s) -> isMonochrome(s) ? 90.0 : 30.0)
+        .setBackground((s) -> tertiaryFixedDim())
+        .setSecondBackground((s) -> tertiaryFixed())
+        .setContrastCurve((s) -> new ContrastCurve(3.0, 4.5, 7.0, 11.0))
+        .build();
+  }
+
+  //////////////////////////////////////////////////////////////////
+  // Android-only Colors                                          //
+  //////////////////////////////////////////////////////////////////
+
+  /**
+   * These colors were present in Android framework before Android U, and used by MDC controls. They
+   * should be avoided, if possible. It's unclear if they're used on multiple backgrounds, and if
+   * they are, they can't be adjusted for contrast.* For now, they will be set with no background,
+   * and those won't adjust for contrast, avoiding issues.
+   *
+   * <p>* For example, if the same color is on a white background _and_ black background, there's no
+   * way to increase contrast with either without losing contrast with the other.
+   */
+  // colorControlActivated documented as colorAccent in M3 & GM3.
+  // colorAccent documented as colorSecondary in M3 and colorPrimary in GM3.
+  // Android used Material's Container as Primary/Secondary/Tertiary at launch.
+  // Therefore, this is a duplicated version of Primary Container.
+  @NonNull
+  @Override
+  public DynamicColor controlActivated() {
+    return new DynamicColor.Builder()
+        .setName("control_activated")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone((s) -> s.isDark ? 30.0 : 90.0)
+        .setIsBackground(true)
+        .build();
+  }
+
+  // colorControlNormal documented as textColorSecondary in M3 & GM3.
+  // In Material, textColorSecondary points to onSurfaceVariant in the non-disabled state,
+  // which is Neutral Variant T30/80 in light/dark.
+  @NonNull
+  @Override
+  public DynamicColor controlNormal() {
+    return new DynamicColor.Builder()
+        .setName("control_normal")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 80.0 : 30.0)
+        .build();
+  }
+
+  // colorControlHighlight documented, in both M3 & GM3:
+  // Light mode: #1f000000 dark mode: #33ffffff.
+  // These are black and white with some alpha.
+  // 1F hex = 31 decimal; 31 / 255 = 12% alpha.
+  // 33 hex = 51 decimal; 51 / 255 = 20% alpha.
+  // DynamicColors do not support alpha currently, and _may_ not need it for this use case,
+  // depending on how MDC resolved alpha for the other cases.
+  // Returning black in dark mode, white in light mode.
+  @NonNull
+  @Override
+  public DynamicColor controlHighlight() {
+    return new DynamicColor.Builder()
+        .setName("control_highlight")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 100.0 : 0.0)
+        .setOpacity((s) -> s.isDark ? 0.20 : 0.12)
+        .build();
+  }
+
+  // textColorPrimaryInverse documented, in both M3 & GM3, documented as N10/N90.
+  @NonNull
+  @Override
+  public DynamicColor textPrimaryInverse() {
+    return new DynamicColor.Builder()
+        .setName("text_primary_inverse")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 10.0 : 90.0)
+        .build();
+  }
+
+  // textColorSecondaryInverse and textColorTertiaryInverse both documented, in both M3 & GM3, as
+  // NV30/NV80
+  @NonNull
+  @Override
+  public DynamicColor textSecondaryAndTertiaryInverse() {
+    return new DynamicColor.Builder()
+        .setName("text_secondary_and_tertiary_inverse")
+        .setPalette((s) -> s.neutralVariantPalette)
+        .setTone((s) -> s.isDark ? 30.0 : 80.0)
+        .build();
+  }
+
+  // textColorPrimaryInverseDisableOnly documented, in both M3 & GM3, as N10/N90
+  @NonNull
+  @Override
+  public DynamicColor textPrimaryInverseDisableOnly() {
+    return new DynamicColor.Builder()
+        .setName("text_primary_inverse_disable_only")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 10.0 : 90.0)
+        .build();
+  }
+
+  // textColorSecondaryInverse and textColorTertiaryInverse in disabled state both documented,
+  // in both M3 & GM3, as N10/N90
+  @NonNull
+  @Override
+  public DynamicColor textSecondaryAndTertiaryInverseDisabled() {
+    return new DynamicColor.Builder()
+        .setName("text_secondary_and_tertiary_inverse_disabled")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 10.0 : 90.0)
+        .build();
+  }
+
+  // textColorHintInverse documented, in both M3 & GM3, as N10/N90
+  @NonNull
+  @Override
+  public DynamicColor textHintInverse() {
+    return new DynamicColor.Builder()
+        .setName("text_hint_inverse")
+        .setPalette((s) -> s.neutralPalette)
+        .setTone((s) -> s.isDark ? 10.0 : 90.0)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Other                                                      //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor highestSurface(@NonNull DynamicScheme s) {
+    return s.isDark ? surfaceBright() : surfaceDim();
+  }
+
+  private boolean isFidelity(DynamicScheme scheme) {
+    return scheme.variant == Variant.FIDELITY || scheme.variant == Variant.CONTENT;
+  }
+
+  private static boolean isMonochrome(DynamicScheme scheme) {
+    return scheme.variant == Variant.MONOCHROME;
+  }
+
+  private static double findDesiredChromaByTone(
+      double hue, double chroma, double tone, boolean byDecreasingTone) {
+    double answer = tone;
+
+    Hct closestToChroma = Hct.from(hue, chroma, tone);
+    if (closestToChroma.getChroma() < chroma) {
+      double chromaPeak = closestToChroma.getChroma();
+      while (closestToChroma.getChroma() < chroma) {
+        answer += byDecreasingTone ? -1.0 : 1.0;
+        Hct potentialSolution = Hct.from(hue, chroma, answer);
+        if (chromaPeak > potentialSolution.getChroma()) {
+          break;
+        }
+        if (Math.abs(potentialSolution.getChroma() - chroma) < 0.4) {
+          break;
+        }
+
+        double potentialDelta = Math.abs(potentialSolution.getChroma() - chroma);
+        double currentDelta = Math.abs(closestToChroma.getChroma() - chroma);
+        if (potentialDelta < currentDelta) {
+          closestToChroma = potentialSolution;
+        }
+        chromaPeak = Math.max(chromaPeak, potentialSolution.getChroma());
+      }
+    }
+
+    return answer;
+  }
+
+  /////////////////////////////////////////////////////////////////
+  // Color value calculations                                    //
+  /////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public Hct getHct(DynamicScheme scheme, DynamicColor color) {
+    // This is crucial for aesthetics: we aren't simply the taking the standard color
+    // and changing its tone for contrast. Rather, we find the tone for contrast, then
+    // use the specified chroma from the palette to construct a new color.
+    //
+    // For example, this enables colors with standard tone of T90, which has limited chroma, to
+    // "recover" intended chroma as contrast increases.
+    double tone = getTone(scheme, color);
+    return color.palette.apply(scheme).getHct(tone);
+  }
+
+  @Override
+  public double getTone(DynamicScheme scheme, DynamicColor color) {
+    boolean decreasingContrast = scheme.contrastLevel < 0;
+    ToneDeltaPair toneDeltaPair =
+        color.toneDeltaPair == null ? null : color.toneDeltaPair.apply(scheme);
+
+    // Case 1: dual foreground, pair of colors with delta constraint.
+    if (toneDeltaPair != null) {
+      DynamicColor roleA = toneDeltaPair.getRoleA();
+      DynamicColor roleB = toneDeltaPair.getRoleB();
+      double delta = toneDeltaPair.getDelta();
+      TonePolarity polarity = toneDeltaPair.getPolarity();
+      boolean stayTogether = toneDeltaPair.getStayTogether();
+
+      boolean aIsNearer =
+          (polarity == TonePolarity.NEARER
+              || (polarity == TonePolarity.LIGHTER && !scheme.isDark)
+              || (polarity == TonePolarity.DARKER && !scheme.isDark));
+      DynamicColor nearer = aIsNearer ? roleA : roleB;
+      DynamicColor farther = aIsNearer ? roleB : roleA;
+      boolean amNearer = color.name.equals(nearer.name);
+      double expansionDir = scheme.isDark ? 1 : -1;
+      @Var double nTone = nearer.tone.apply(scheme);
+      @Var double fTone = farther.tone.apply(scheme);
+
+      // 1st round: solve to min, each
+      if (color.background != null
+          && nearer.contrastCurve != null
+          && farther.contrastCurve != null) {
+        DynamicColor bg = color.background.apply(scheme);
+        ContrastCurve nContrastCurve = nearer.contrastCurve.apply(scheme);
+        ContrastCurve fContrastCurve = farther.contrastCurve.apply(scheme);
+        if (bg != null && nContrastCurve != null && fContrastCurve != null) {
+          double nContrast = nContrastCurve.get(scheme.contrastLevel);
+          double fContrast = fContrastCurve.get(scheme.contrastLevel);
+          double bgTone = bg.getTone(scheme);
+
+          // If a color is good enough, it is not adjusted.
+          // Initial and adjusted tones for `nearer`
+          if (Contrast.ratioOfTones(bgTone, nTone) < nContrast) {
+            nTone = DynamicColor.foregroundTone(bgTone, nContrast);
+          }
+          // Initial and adjusted tones for `farther`
+          if (Contrast.ratioOfTones(bgTone, fTone) < fContrast) {
+            fTone = DynamicColor.foregroundTone(bgTone, fContrast);
+          }
+
+          if (decreasingContrast) {
+            // If decreasing contrast, adjust color to the "bare minimum"
+            // that satisfies contrast.
+            nTone = DynamicColor.foregroundTone(bgTone, nContrast);
+            fTone = DynamicColor.foregroundTone(bgTone, fContrast);
+          }
+        }
+      }
+
+      // If constraint is not satisfied, try another round.
+      if ((fTone - nTone) * expansionDir < delta) {
+        // 2nd round: expand farther to match delta.
+        fTone = MathUtils.clampDouble(0, 100, nTone + delta * expansionDir);
+        // If constraint is not satisfied, try another round.
+        if ((fTone - nTone) * expansionDir < delta) {
+          // 3rd round: contract nearer to match delta.
+          nTone = MathUtils.clampDouble(0, 100, fTone - delta * expansionDir);
+        }
+      }
+
+      // Avoids the 50-59 awkward zone.
+      if (50 <= nTone && nTone < 60) {
+        // If `nearer` is in the awkward zone, move it away, together with
+        // `farther`.
+        if (expansionDir > 0) {
+          nTone = 60;
+          fTone = max(fTone, nTone + delta * expansionDir);
+        } else {
+          nTone = 49;
+          fTone = min(fTone, nTone + delta * expansionDir);
+        }
+      } else if (50 <= fTone && fTone < 60) {
+        if (stayTogether) {
+          // Fixes both, to avoid two colors on opposite sides of the "awkward
+          // zone".
+          if (expansionDir > 0) {
+            nTone = 60;
+            fTone = max(fTone, nTone + delta * expansionDir);
+          } else {
+            nTone = 49;
+            fTone = min(fTone, nTone + delta * expansionDir);
+          }
+        } else {
+          // Not required to stay together; fixes just one.
+          if (expansionDir > 0) {
+            fTone = 60;
+          } else {
+            fTone = 49;
+          }
+        }
+      }
+
+      // Returns `nTone` if this color is `nearer`, otherwise `fTone`.
+      return amNearer ? nTone : fTone;
+    } else {
+      // Case 2: No contrast pair; just solve for itself.
+      @Var double answer = color.tone.apply(scheme);
+
+      if (color.background == null
+          || color.background.apply(scheme) == null
+          || color.contrastCurve == null
+          || color.contrastCurve.apply(scheme) == null) {
+        return answer; // No adjustment for colors with no background.
+      }
+
+      double bgTone = color.background.apply(scheme).getTone(scheme);
+      double desiredRatio = color.contrastCurve.apply(scheme).get(scheme.contrastLevel);
+
+      if (Contrast.ratioOfTones(bgTone, answer) >= desiredRatio) {
+        // Don't "improve" what's good enough.
+      } else {
+        // Rough improvement.
+        answer = DynamicColor.foregroundTone(bgTone, desiredRatio);
+      }
+
+      if (decreasingContrast) {
+        answer = DynamicColor.foregroundTone(bgTone, desiredRatio);
+      }
+
+      if (color.isBackground && 50 <= answer && answer < 60) {
+        // Must adjust
+        if (Contrast.ratioOfTones(49, bgTone) >= desiredRatio) {
+          answer = 49;
+        } else {
+          answer = 60;
+        }
+      }
+
+      if (color.secondBackground == null || color.secondBackground.apply(scheme) == null) {
+        return answer;
+      }
+
+      // Case 3: Adjust for dual backgrounds.
+      double bgTone1 = color.background.apply(scheme).getTone(scheme);
+      double bgTone2 = color.secondBackground.apply(scheme).getTone(scheme);
+
+      double upper = max(bgTone1, bgTone2);
+      double lower = min(bgTone1, bgTone2);
+
+      if (Contrast.ratioOfTones(upper, answer) >= desiredRatio
+          && Contrast.ratioOfTones(lower, answer) >= desiredRatio) {
+        return answer;
+      }
+
+      // The darkest light tone that satisfies the desired ratio,
+      // or -1 if such ratio cannot be reached.
+      double lightOption = Contrast.lighter(upper, desiredRatio);
+
+      // The lightest dark tone that satisfies the desired ratio,
+      // or -1 if such ratio cannot be reached.
+      double darkOption = Contrast.darker(lower, desiredRatio);
+
+      // Tones suitable for the foreground.
+      ArrayList<Double> availables = new ArrayList<>();
+      if (lightOption != -1) {
+        availables.add(lightOption);
+      }
+      if (darkOption != -1) {
+        availables.add(darkOption);
+      }
+
+      boolean prefersLight =
+          DynamicColor.tonePrefersLightForeground(bgTone1)
+              || DynamicColor.tonePrefersLightForeground(bgTone2);
+      if (prefersLight) {
+        return (lightOption == -1) ? 100 : lightOption;
+      }
+      if (availables.size() == 1) {
+        return availables.get(0);
+      }
+      return (darkOption == -1) ? 0 : darkOption;
+    }
+  }
+
+  //////////////////////////////////////////////////////////////////
+  // Scheme Palettes                                              //
+  //////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public TonalPalette getPrimaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT, FIDELITY ->
+          TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma());
+      case FRUIT_SALAD ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() - 50.0), 48.0);
+      case MONOCHROME -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case NEUTRAL -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 12.0);
+      case RAINBOW -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 48.0);
+      case TONAL_SPOT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 36.0);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 240), 40);
+      case VIBRANT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 200.0);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getSecondaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT, FIDELITY ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(),
+              max(sourceColorHct.getChroma() - 32.0, sourceColorHct.getChroma() * 0.5));
+      case FRUIT_SALAD ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() - 50.0), 36.0);
+      case MONOCHROME -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case NEUTRAL -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 8.0);
+      case RAINBOW -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0);
+      case TONAL_SPOT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 21, 51, 121, 151, 191, 271, 321, 360},
+                  new double[] {45, 95, 45, 20, 45, 90, 45, 45, 45}),
+              24.0);
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 41, 61, 101, 131, 181, 251, 301, 360},
+                  new double[] {18, 15, 10, 12, 15, 18, 15, 12, 12}),
+              24.0);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getTertiaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT ->
+          TonalPalette.fromHct(
+              DislikeAnalyzer.fixIfDisliked(
+                  new TemperatureCache(sourceColorHct)
+                      .getAnalogousColors(/* count= */ 3, /* divisions= */ 6)
+                      .get(2)));
+      case FIDELITY ->
+          TonalPalette.fromHct(
+              DislikeAnalyzer.fixIfDisliked(new TemperatureCache(sourceColorHct).getComplement()));
+      case FRUIT_SALAD -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 36.0);
+      case MONOCHROME -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case NEUTRAL -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0);
+      case RAINBOW, TONAL_SPOT ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 60.0), 24.0);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 21, 51, 121, 151, 191, 271, 321, 360},
+                  new double[] {120, 120, 20, 45, 20, 15, 20, 120, 120}),
+              32.0);
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 41, 61, 101, 131, 181, 251, 301, 360},
+                  new double[] {35, 30, 20, 25, 30, 35, 30, 25, 25}),
+              32.0);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getNeutralPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT, FIDELITY ->
+          TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma() / 8.0);
+      case FRUIT_SALAD -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 10.0);
+      case MONOCHROME -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case NEUTRAL -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 2.0);
+      case RAINBOW -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case TONAL_SPOT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 6.0);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 15), 8);
+      case VIBRANT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 10);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getNeutralVariantPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(), (sourceColorHct.getChroma() / 8.0) + 4.0);
+      case FIDELITY ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(), (sourceColorHct.getChroma() / 8.0) + 4.0);
+      case FRUIT_SALAD -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0);
+      case MONOCHROME -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case NEUTRAL -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 2.0);
+      case RAINBOW -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0);
+      case TONAL_SPOT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 8.0);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 15), 12);
+      case VIBRANT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 12);
+    };
+  }
+
+  @NonNull
+  @Override
+  public Optional<TonalPalette> getErrorPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case CONTENT,
+          FIDELITY,
+          FRUIT_SALAD,
+          MONOCHROME,
+          NEUTRAL,
+          RAINBOW,
+          TONAL_SPOT,
+          EXPRESSIVE,
+          VIBRANT ->
+          Optional.empty();
+    };
+  }
+}
diff --git a/dynamiccolor/ColorSpec2025.java b/dynamiccolor/ColorSpec2025.java
new file mode 100644
index 0000000..0020b0d
--- /dev/null
+++ b/dynamiccolor/ColorSpec2025.java
@@ -0,0 +1,1905 @@
+/*
+ * Copyright 2025 Google LLC
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
+package com.google.ux.material.libmonet.dynamiccolor;
+
+import static com.google.ux.material.libmonet.dynamiccolor.DynamicScheme.Platform.PHONE;
+import static com.google.ux.material.libmonet.dynamiccolor.DynamicScheme.Platform.WATCH;
+import static com.google.ux.material.libmonet.dynamiccolor.ToneDeltaPair.DeltaConstraint.EXACT;
+import static com.google.ux.material.libmonet.dynamiccolor.ToneDeltaPair.DeltaConstraint.FARTHER;
+import static com.google.ux.material.libmonet.dynamiccolor.TonePolarity.DARKER;
+import static com.google.ux.material.libmonet.dynamiccolor.TonePolarity.RELATIVE_LIGHTER;
+import static com.google.ux.material.libmonet.dynamiccolor.Variant.EXPRESSIVE;
+import static com.google.ux.material.libmonet.dynamiccolor.Variant.NEUTRAL;
+import static com.google.ux.material.libmonet.dynamiccolor.Variant.TONAL_SPOT;
+import static com.google.ux.material.libmonet.dynamiccolor.Variant.VIBRANT;
+import static java.lang.Math.max;
+import static java.lang.Math.min;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import com.google.ux.material.libmonet.contrast.Contrast;
+import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme.Platform;
+import com.google.ux.material.libmonet.dynamiccolor.ToneDeltaPair.DeltaConstraint;
+import com.google.ux.material.libmonet.hct.Hct;
+import com.google.ux.material.libmonet.palettes.TonalPalette;
+import com.google.ux.material.libmonet.utils.MathUtils;
+import java.util.ArrayList;
+import java.util.Optional;
+
+/** {@link ColorSpec} implementation for the 2025 spec. */
+final class ColorSpec2025 extends ColorSpec2021 {
+
+  ////////////////////////////////////////////////////////////////
+  // Surfaces [S]                                               //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor background() {
+    // Remapped to surface for 2025 spec.
+    DynamicColor color2025 = surface().toBuilder().setName("background").build();
+    return super.background().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onBackground() {
+    // Remapped to onSurface for 2025 spec.
+    DynamicColor color2025 = onSurface().toBuilder().setName("on_background").build();
+    return super.onBackground().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surface() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.isDark) {
+                      return 4.0;
+                    } else {
+                      if (Hct.isYellow(s.neutralPalette.getHue())) {
+                        return 99.0;
+                      } else if (s.variant == VIBRANT) {
+                        return 97.0;
+                      } else {
+                        return 98.0;
+                      }
+                    }
+                  } else {
+                    return 0.0;
+                  }
+                })
+            .setIsBackground(true)
+            .build();
+    return super.surface().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceDim() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_dim")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.isDark) {
+                    return 4.0;
+                  } else {
+                    if (Hct.isYellow(s.neutralPalette.getHue())) {
+                      return 90.0;
+                    } else if (s.variant == VIBRANT) {
+                      return 85.0;
+                    } else {
+                      return 87.0;
+                    }
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (!s.isDark) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.5;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? 2.7 : 1.75;
+                    } else if (s.variant == VIBRANT) {
+                      return 1.36;
+                    }
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceDim().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceBright() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_bright")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.isDark) {
+                    return 18.0;
+                  } else {
+                    if (Hct.isYellow(s.neutralPalette.getHue())) {
+                      return 99.0;
+                    } else if (s.variant == VIBRANT) {
+                      return 97.0;
+                    } else {
+                      return 98.0;
+                    }
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.isDark) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.5;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? 2.7 : 1.75;
+                    } else if (s.variant == VIBRANT) {
+                      return 1.36;
+                    }
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceBright().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerLowest() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_container_lowest")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone((s) -> s.isDark ? 0.0 : 100.0)
+            .setIsBackground(true)
+            .build();
+    return super.surfaceContainerLowest().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerLow() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_container_low")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.isDark) {
+                      return 6.0;
+                    } else {
+                      if (Hct.isYellow(s.neutralPalette.getHue())) {
+                        return 98.0;
+                      } else if (s.variant == VIBRANT) {
+                        return 95.0;
+                      } else {
+                        return 96.0;
+                      }
+                    }
+                  } else {
+                    return 15.0;
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 1.3;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.25;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? 1.3 : 1.15;
+                    } else if (s.variant == VIBRANT) {
+                      return 1.08;
+                    }
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceContainerLow().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_container")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.isDark) {
+                      return 9.0;
+                    } else {
+                      if (Hct.isYellow(s.neutralPalette.getHue())) {
+                        return 96.0;
+                      } else if (s.variant == VIBRANT) {
+                        return 92.0;
+                      } else {
+                        return 94.0;
+                      }
+                    }
+                  } else {
+                    return 20.0;
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 1.6;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.4;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? 1.6 : 1.3;
+                    } else if (s.variant == VIBRANT) {
+                      return 1.15;
+                    }
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerHigh() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_container_high")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.isDark) {
+                      return 12.0;
+                    } else {
+                      if (Hct.isYellow(s.neutralPalette.getHue())) {
+                        return 94.0;
+                      } else if (s.variant == VIBRANT) {
+                        return 90.0;
+                      } else {
+                        return 92.0;
+                      }
+                    }
+                  } else {
+                    return 25.0;
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 1.9;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.5;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? 1.95 : 1.45;
+                    } else if (s.variant == VIBRANT) {
+                      return 1.22;
+                    }
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceContainerHigh().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceContainerHighest() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("surface_container_highest")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.isDark) {
+                    return 15.0;
+                  } else {
+                    if (Hct.isYellow(s.neutralPalette.getHue())) {
+                      return 92.0;
+                    } else if (s.variant == VIBRANT) {
+                      return 88.0;
+                    } else {
+                      return 90.0;
+                    }
+                  }
+                })
+            .setIsBackground(true)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.variant == NEUTRAL) {
+                    return 2.2;
+                  } else if (s.variant == TONAL_SPOT) {
+                    return 1.7;
+                  } else if (s.variant == EXPRESSIVE) {
+                    return Hct.isYellow(s.neutralPalette.getHue()) ? 2.3 : 1.6;
+                  } else if (s.variant == VIBRANT) {
+                    return 1.29;
+                  }
+                  return 1.0;
+                })
+            .build();
+    return super.surfaceContainerHighest().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSurface() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_surface")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone(
+                (s) -> {
+                  if (s.variant == Variant.VIBRANT) {
+                    return tMaxC(s.neutralPalette, 0, 100, 1.1);
+                  } else {
+                    return DynamicColor.getInitialToneFromBackground(
+                            (scheme) -> {
+                              if (scheme.platform == PHONE) {
+                                return scheme.isDark ? surfaceBright() : surfaceDim();
+                              } else {
+                                return surfaceContainerHigh();
+                              }
+                            })
+                        .apply(s);
+                  }
+                })
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.2;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? (s.isDark ? 3.0 : 2.3) : 1.6;
+                    }
+                  }
+                  return 1.0;
+                })
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve((s) -> s.isDark ? getContrastCurve(11) : getContrastCurve(9))
+            .build();
+    return super.onSurface().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceVariant() {
+    // Remapped to surfaceContainerHighest for 2025 spec.
+    DynamicColor color2025 =
+        surfaceContainerHighest().toBuilder().setName("surface_variant").build();
+    return super.surfaceVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSurfaceVariant() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_surface_variant")
+            .setPalette((s) -> s.neutralPalette)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.2;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? (s.isDark ? 3.0 : 2.3) : 1.6;
+                    }
+                  }
+                  return 1.0;
+                })
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .build();
+    return super.onSurfaceVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inverseSurface() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("inverse_surface")
+            .setPalette((s) -> s.neutralPalette)
+            .setTone((s) -> s.isDark ? 98.0 : 4.0)
+            .setIsBackground(true)
+            .build();
+    return super.inverseSurface().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inverseOnSurface() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("inverse_on_surface")
+            .setPalette((s) -> s.neutralPalette)
+            .setBackground((s) -> inverseSurface())
+            .setContrastCurve((s) -> getContrastCurve(7))
+            .build();
+    return super.inverseOnSurface().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor outline() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("outline")
+            .setPalette((s) -> s.neutralPalette)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.2;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? (s.isDark ? 3.0 : 2.3) : 1.6;
+                    }
+                  }
+                  return 1.0;
+                })
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(3) : getContrastCurve(4.5))
+            .build();
+    return super.outline().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor outlineVariant() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("outline_variant")
+            .setPalette((s) -> s.neutralPalette)
+            .setChromaMultiplier(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    if (s.variant == NEUTRAL) {
+                      return 2.2;
+                    } else if (s.variant == TONAL_SPOT) {
+                      return 1.7;
+                    } else if (s.variant == EXPRESSIVE) {
+                      return Hct.isYellow(s.neutralPalette.getHue()) ? (s.isDark ? 3.0 : 2.3) : 1.6;
+                    }
+                  }
+                  return 1.0;
+                })
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(1.5) : getContrastCurve(3))
+            .build();
+    return super.outlineVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor surfaceTint() {
+    // Remapped to primary for 2025 spec.
+    DynamicColor color2025 = primary().toBuilder().setName("surface_tint").build();
+    return super.surfaceTint().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Primaries [P]                                              //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor primary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("primary")
+            .setPalette((s) -> s.primaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.variant == NEUTRAL) {
+                    if (s.platform == PHONE) {
+                      return s.isDark ? 80.0 : 40.0;
+                    } else {
+                      return 90.0;
+                    }
+                  } else if (s.variant == TONAL_SPOT) {
+                    if (s.platform == PHONE) {
+                      if (s.isDark) {
+                        return 80.0;
+                      } else {
+                        return tMaxC(s.primaryPalette);
+                      }
+                    } else {
+                      return tMaxC(s.primaryPalette, 0, 90);
+                    }
+                  } else if (s.variant == EXPRESSIVE) {
+                    return tMaxC(
+                        s.primaryPalette,
+                        0,
+                        Hct.isYellow(s.primaryPalette.getHue())
+                            ? 25
+                            : Hct.isCyan(s.primaryPalette.getHue()) ? 88 : 98);
+                  } else { // VIBRANT
+                    return tMaxC(
+                        s.primaryPalette, 0, Hct.isCyan(s.primaryPalette.getHue()) ? 88 : 98);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == PHONE
+                        ? new ToneDeltaPair(
+                            primaryContainer(), primary(), 5.0, RELATIVE_LIGHTER, FARTHER)
+                        : null)
+            .build();
+    return super.primary().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor primaryDim() {
+    return new DynamicColor.Builder()
+        .setName("primary_dim")
+        .setPalette((s) -> s.primaryPalette)
+        .setTone(
+            (s) -> {
+              if (s.variant == NEUTRAL) {
+                return 85.0;
+              } else if (s.variant == TONAL_SPOT) {
+                return tMaxC(s.primaryPalette, 0, 90);
+              } else {
+                return tMaxC(s.primaryPalette);
+              }
+            })
+        .setIsBackground(true)
+        .setBackground((s) -> surfaceContainerHigh())
+        .setContrastCurve((s) -> getContrastCurve(4.5))
+        .setToneDeltaPair((s) -> new ToneDeltaPair(primaryDim(), primary(), 5.0, DARKER, FARTHER))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_primary")
+            .setPalette((s) -> s.primaryPalette)
+            .setBackground((s) -> s.platform == PHONE ? primary() : primaryDim())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onPrimary().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor primaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("primary_container")
+            .setPalette((s) -> s.primaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return 30.0;
+                  } else if (s.variant == NEUTRAL) {
+                    return s.isDark ? 30.0 : 90.0;
+                  } else if (s.variant == TONAL_SPOT) {
+                    return s.isDark
+                        ? tMinC(s.primaryPalette, 35, 93)
+                        : tMaxC(s.primaryPalette, 0, 90);
+                  } else if (s.variant == EXPRESSIVE) {
+                    return s.isDark
+                        ? tMaxC(s.primaryPalette, 30, 93)
+                        : tMaxC(
+                            s.primaryPalette, 78, Hct.isCyan(s.primaryPalette.getHue()) ? 88 : 90);
+                  } else { // VIBRANT
+                    return s.isDark
+                        ? tMinC(s.primaryPalette, 66, 93)
+                        : tMaxC(
+                            s.primaryPalette, 66, Hct.isCyan(s.primaryPalette.getHue()) ? 88 : 93);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return null;
+                  }
+                })
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == WATCH
+                        ? new ToneDeltaPair(primaryContainer(), primaryDim(), 10.0, DARKER, FARTHER)
+                        : null)
+            .setContrastCurve(
+                (s) -> s.platform == PHONE && s.contrastLevel > 0 ? getContrastCurve(1.5) : null)
+            .build();
+    return super.primaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_primary_container")
+            .setPalette((s) -> s.primaryPalette)
+            .setBackground((s) -> primaryContainer())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onPrimaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor inversePrimary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("inverse_primary")
+            .setPalette((s) -> s.primaryPalette)
+            .setTone((s) -> tMaxC(s.primaryPalette))
+            .setBackground((s) -> inverseSurface())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.inversePrimary().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Secondaries [Q]                                            //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor secondary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("secondary")
+            .setPalette((s) -> s.secondaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return s.variant == NEUTRAL ? 90.0 : tMaxC(s.secondaryPalette, 0, 90);
+                  } else if (s.variant == NEUTRAL) {
+                    return s.isDark ? tMinC(s.secondaryPalette, 0, 98) : tMaxC(s.secondaryPalette);
+                  } else if (s.variant == VIBRANT) {
+                    return tMaxC(s.secondaryPalette, 0, s.isDark ? 90 : 98);
+                  } else { // EXPRESSIVE and TONAL_SPOT
+                    return s.isDark ? 80.0 : tMaxC(s.secondaryPalette);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == PHONE
+                        ? new ToneDeltaPair(
+                            secondaryContainer(), secondary(), 5.0, RELATIVE_LIGHTER, FARTHER)
+                        : null)
+            .build();
+    return super.secondary().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor secondaryDim() {
+    return new DynamicColor.Builder()
+        .setName("secondary_dim")
+        .setPalette((s) -> s.secondaryPalette)
+        .setTone(
+            (s) -> {
+              if (s.variant == NEUTRAL) {
+                return 85.0;
+              } else {
+                return tMaxC(s.secondaryPalette, 0, 90);
+              }
+            })
+        .setIsBackground(true)
+        .setBackground((s) -> surfaceContainerHigh())
+        .setContrastCurve((s) -> getContrastCurve(4.5))
+        .setToneDeltaPair(
+            (s) -> new ToneDeltaPair(secondaryDim(), secondary(), 5.0, DARKER, FARTHER))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_secondary")
+            .setPalette((s) -> s.secondaryPalette)
+            .setBackground((s) -> s.platform == PHONE ? secondary() : secondaryDim())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onSecondary().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("secondary_container")
+            .setPalette((s) -> s.secondaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return 30.0;
+                  } else if (s.variant == VIBRANT) {
+                    return s.isDark
+                        ? tMinC(s.secondaryPalette, 30, 40)
+                        : tMaxC(s.secondaryPalette, 84, 90);
+                  } else if (s.variant == EXPRESSIVE) {
+                    return s.isDark ? 15.0 : tMaxC(s.secondaryPalette, 90, 95);
+                  } else {
+                    return s.isDark ? 25.0 : 90.0;
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return null;
+                  }
+                })
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == WATCH
+                        ? new ToneDeltaPair(
+                            secondaryContainer(), secondaryDim(), 10.0, DARKER, FARTHER)
+                        : null)
+            .setContrastCurve(
+                (s) -> s.platform == PHONE && s.contrastLevel > 0 ? getContrastCurve(1.5) : null)
+            .build();
+    return super.secondaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_secondary_container")
+            .setPalette((s) -> s.secondaryPalette)
+            .setBackground((s) -> secondaryContainer())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onSecondaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiaries [T]                                             //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor tertiary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("tertiary")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return s.variant == TONAL_SPOT
+                        ? tMaxC(s.tertiaryPalette, 0, 90)
+                        : tMaxC(s.tertiaryPalette);
+                  } else if (s.variant == EXPRESSIVE || s.variant == VIBRANT) {
+                    return tMaxC(
+                        s.tertiaryPalette,
+                        /* lowerBound= */ 0,
+                        /* upperBound= */ Hct.isCyan(s.tertiaryPalette.getHue())
+                            ? 88
+                            : (s.isDark ? 98 : 100));
+                  } else { // NEUTRAL and TONAL_SPOT
+                    return s.isDark ? tMaxC(s.tertiaryPalette, 0, 98) : tMaxC(s.tertiaryPalette);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == PHONE
+                        ? new ToneDeltaPair(
+                            tertiaryContainer(), tertiary(), 5.0, RELATIVE_LIGHTER, FARTHER)
+                        : null)
+            .build();
+    return super.tertiary().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor tertiaryDim() {
+    return new DynamicColor.Builder()
+        .setName("tertiary_dim")
+        .setPalette((s) -> s.tertiaryPalette)
+        .setTone(
+            (s) -> {
+              if (s.variant == TONAL_SPOT) {
+                return tMaxC(s.tertiaryPalette, 0, 90);
+              } else {
+                return tMaxC(s.tertiaryPalette);
+              }
+            })
+        .setIsBackground(true)
+        .setBackground((s) -> surfaceContainerHigh())
+        .setContrastCurve((s) -> getContrastCurve(4.5))
+        .setToneDeltaPair((s) -> new ToneDeltaPair(tertiaryDim(), tertiary(), 5.0, DARKER, FARTHER))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiary() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_tertiary")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setBackground((s) -> s.platform == PHONE ? tertiary() : tertiaryDim())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onTertiary().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("tertiary_container")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return s.variant == TONAL_SPOT
+                        ? tMaxC(s.tertiaryPalette, 0, 90)
+                        : tMaxC(s.tertiaryPalette);
+                  } else {
+                    if (s.variant == NEUTRAL) {
+                      return s.isDark
+                          ? tMaxC(s.tertiaryPalette, 0, 93)
+                          : tMaxC(s.tertiaryPalette, 0, 96);
+                    } else if (s.variant == TONAL_SPOT) {
+                      return tMaxC(s.tertiaryPalette, 0, s.isDark ? 93 : 100);
+                    } else if (s.variant == EXPRESSIVE) {
+                      return tMaxC(
+                          s.tertiaryPalette,
+                          /* lowerBound= */ 75,
+                          /* upperBound= */ Hct.isCyan(s.tertiaryPalette.getHue())
+                              ? 88
+                              : (s.isDark ? 93 : 100));
+                    } else { // VIBRANT
+                      return s.isDark
+                          ? tMaxC(s.tertiaryPalette, 0, 93)
+                          : tMaxC(s.tertiaryPalette, 72, 100);
+                    }
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return null;
+                  }
+                })
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == WATCH
+                        ? new ToneDeltaPair(
+                            tertiaryContainer(), tertiaryDim(), 10.0, DARKER, FARTHER)
+                        : null)
+            .setContrastCurve(
+                (s) -> s.platform == PHONE && s.contrastLevel > 0 ? getContrastCurve(1.5) : null)
+            .build();
+    return super.tertiaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_tertiary_container")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setBackground((s) -> tertiaryContainer())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onTertiaryContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Errors [E]                                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor error() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("error")
+            .setPalette((s) -> s.errorPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? tMinC(s.errorPalette, 0, 98) : tMaxC(s.errorPalette);
+                  } else {
+                    return tMinC(s.errorPalette);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return surfaceContainerHigh();
+                  }
+                })
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == PHONE
+                        ? new ToneDeltaPair(
+                            errorContainer(), error(), 5.0, RELATIVE_LIGHTER, FARTHER)
+                        : null)
+            .build();
+    return super.error().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @Nullable
+  @Override
+  public DynamicColor errorDim() {
+    return new DynamicColor.Builder()
+        .setName("error_dim")
+        .setPalette((s) -> s.errorPalette)
+        .setTone((s) -> tMinC(s.errorPalette))
+        .setIsBackground(true)
+        .setBackground((s) -> surfaceContainerHigh())
+        .setContrastCurve((s) -> getContrastCurve(4.5))
+        .setToneDeltaPair((s) -> new ToneDeltaPair(errorDim(), error(), 5.0, DARKER, FARTHER))
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onError() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_error")
+            .setPalette((s) -> s.errorPalette)
+            .setBackground((s) -> s.platform == PHONE ? error() : errorDim())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(6) : getContrastCurve(7))
+            .build();
+    return super.onError().toBuilder().extendSpecVersion(SpecVersion.SPEC_2025, color2025).build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor errorContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("error_container")
+            .setPalette((s) -> s.errorPalette)
+            .setTone(
+                (s) -> {
+                  if (s.platform == WATCH) {
+                    return 30.0;
+                  } else {
+                    return s.isDark ? tMinC(s.errorPalette, 30, 93) : tMaxC(s.errorPalette, 0, 90);
+                  }
+                })
+            .setIsBackground(true)
+            .setBackground(
+                (s) -> {
+                  if (s.platform == PHONE) {
+                    return s.isDark ? surfaceBright() : surfaceDim();
+                  } else {
+                    return null;
+                  }
+                })
+            .setToneDeltaPair(
+                (s) ->
+                    s.platform == WATCH
+                        ? new ToneDeltaPair(errorContainer(), errorDim(), 10.0, DARKER, FARTHER)
+                        : null)
+            .setContrastCurve(
+                (s) -> s.platform == PHONE && s.contrastLevel > 0 ? getContrastCurve(1.5) : null)
+            .build();
+    return super.errorContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onErrorContainer() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_error_container")
+            .setPalette((s) -> s.errorPalette)
+            .setBackground((s) -> errorContainer())
+            .setContrastCurve(
+                (s) -> s.platform == PHONE ? getContrastCurve(4.5) : getContrastCurve(7))
+            .build();
+    return super.onErrorContainer().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Primary Fixed Colors [PF]                                  //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor primaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("primary_fixed")
+            .setPalette((s) -> s.primaryPalette)
+            .setTone(
+                (s) -> {
+                  DynamicScheme tempS = DynamicScheme.from(s, /* isDark= */ false);
+                  return primaryContainer().getTone(tempS);
+                })
+            .setIsBackground(true)
+            .build();
+    return super.primaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor primaryFixedDim() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("primary_fixed_dim")
+            .setPalette((s) -> s.primaryPalette)
+            .setTone((s) -> primaryFixed().getTone(s))
+            .setIsBackground(true)
+            .setToneDeltaPair(
+                (s) -> new ToneDeltaPair(primaryFixedDim(), primaryFixed(), 5.0, DARKER, EXACT))
+            .build();
+    return super.primaryFixedDim().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_primary_fixed")
+            .setPalette((s) -> s.primaryPalette)
+            .setBackground((s) -> primaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(7))
+            .build();
+    return super.onPrimaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onPrimaryFixedVariant() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_primary_fixed_variant")
+            .setPalette((s) -> s.primaryPalette)
+            .setBackground((s) -> primaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(4.5))
+            .build();
+    return super.onPrimaryFixedVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Secondary Fixed Colors [QF]                                //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("secondary_fixed")
+            .setPalette((s) -> s.secondaryPalette)
+            .setTone(
+                (s) -> {
+                  DynamicScheme tempS = DynamicScheme.from(s, /* isDark= */ false);
+                  return secondaryContainer().getTone(tempS);
+                })
+            .setIsBackground(true)
+            .build();
+    return super.secondaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor secondaryFixedDim() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("secondary_fixed_dim")
+            .setPalette((s) -> s.secondaryPalette)
+            .setTone((s) -> secondaryFixed().getTone(s))
+            .setIsBackground(true)
+            .setToneDeltaPair(
+                (s) -> new ToneDeltaPair(secondaryFixedDim(), secondaryFixed(), 5.0, DARKER, EXACT))
+            .build();
+    return super.secondaryFixedDim().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_secondary_fixed")
+            .setPalette((s) -> s.secondaryPalette)
+            .setBackground((s) -> secondaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(7))
+            .build();
+    return super.onSecondaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onSecondaryFixedVariant() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_secondary_fixed_variant")
+            .setPalette((s) -> s.secondaryPalette)
+            .setBackground((s) -> secondaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(4.5))
+            .build();
+    return super.onSecondaryFixedVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Tertiary Fixed Colors [TF]                                 //
+  ////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("tertiary_fixed")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setTone(
+                (s) -> {
+                  DynamicScheme tempS = DynamicScheme.from(s, /* isDark= */ false);
+                  return tertiaryContainer().getTone(tempS);
+                })
+            .setIsBackground(true)
+            .build();
+    return super.tertiaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor tertiaryFixedDim() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("tertiary_fixed_dim")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setTone((s) -> tertiaryFixed().getTone(s))
+            .setIsBackground(true)
+            .setToneDeltaPair(
+                (s) -> new ToneDeltaPair(tertiaryFixedDim(), tertiaryFixed(), 5.0, DARKER, EXACT))
+            .build();
+    return super.tertiaryFixedDim().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryFixed() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_tertiary_fixed")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setBackground((s) -> tertiaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(7))
+            .build();
+    return super.onTertiaryFixed().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor onTertiaryFixedVariant() {
+    DynamicColor color2025 =
+        new DynamicColor.Builder()
+            .setName("on_tertiary_fixed_variant")
+            .setPalette((s) -> s.tertiaryPalette)
+            .setBackground((s) -> tertiaryFixedDim())
+            .setContrastCurve((s) -> getContrastCurve(4.5))
+            .build();
+    return super.onTertiaryFixedVariant().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  //////////////////////////////////////////////////////////////////
+  // Android-only Colors                                          //
+  //////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public DynamicColor controlActivated() {
+    // Remapped to primaryContainer for 2025 spec.
+    DynamicColor color2025 = primaryContainer().toBuilder().setName("control_activated").build();
+    return super.controlActivated().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor controlNormal() {
+    // Remapped to onSurfaceVariant for 2025 spec.
+    DynamicColor color2025 = onSurfaceVariant().toBuilder().setName("control_normal").build();
+    return super.controlNormal().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  @NonNull
+  @Override
+  public DynamicColor textPrimaryInverse() {
+    // Remapped to inverseOnSurface for 2025 spec.
+    DynamicColor color2025 = inverseOnSurface().toBuilder().setName("text_primary_inverse").build();
+    return super.textPrimaryInverse().toBuilder()
+        .extendSpecVersion(SpecVersion.SPEC_2025, color2025)
+        .build();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Other                                                      //
+  ////////////////////////////////////////////////////////////////
+
+  private static double findBestToneForChroma(
+      double hue, double chroma, double tone, boolean byDecreasingTone) {
+    double answer = tone;
+    Hct bestCandidate = Hct.from(hue, chroma, answer);
+    while (bestCandidate.getChroma() < chroma) {
+      if (tone < 0 || tone > 100) {
+        break;
+      }
+      tone += byDecreasingTone ? -1.0 : 1.0;
+      Hct newCandidate = Hct.from(hue, chroma, tone);
+      if (bestCandidate.getChroma() < newCandidate.getChroma()) {
+        bestCandidate = newCandidate;
+        answer = tone;
+      }
+    }
+    return answer;
+  }
+
+  private static double tMaxC(TonalPalette palette) {
+    return tMaxC(palette, 0, 100);
+  }
+
+  private static double tMaxC(TonalPalette palette, double lowerBound, double upperBound) {
+    return tMaxC(palette, lowerBound, upperBound, 1);
+  }
+
+  private static double tMaxC(
+      TonalPalette palette, double lowerBound, double upperBound, double chromaMultiplier) {
+    double answer =
+        findBestToneForChroma(palette.getHue(), palette.getChroma() * chromaMultiplier, 100, true);
+    return MathUtils.clampDouble(lowerBound, upperBound, answer);
+  }
+
+  private static double tMinC(TonalPalette palette) {
+    return tMinC(palette, 0, 100);
+  }
+
+  private static double tMinC(TonalPalette palette, double lowerBound, double upperBound) {
+    double answer = findBestToneForChroma(palette.getHue(), palette.getChroma(), 0, false);
+    return MathUtils.clampDouble(lowerBound, upperBound, answer);
+  }
+
+  private static ContrastCurve getContrastCurve(double defaultContrast) {
+    if (defaultContrast == 1.5) {
+      return new ContrastCurve(1.5, 1.5, 3, 4.5);
+    } else if (defaultContrast == 3) {
+      return new ContrastCurve(3, 3, 4.5, 7);
+    } else if (defaultContrast == 4.5) {
+      return new ContrastCurve(4.5, 4.5, 7, 11);
+    } else if (defaultContrast == 6) {
+      return new ContrastCurve(6, 6, 7, 11);
+    } else if (defaultContrast == 7) {
+      return new ContrastCurve(7, 7, 11, 21);
+    } else if (defaultContrast == 9) {
+      return new ContrastCurve(9, 9, 11, 21);
+    } else if (defaultContrast == 11) {
+      return new ContrastCurve(11, 11, 21, 21);
+    } else if (defaultContrast == 21) {
+      return new ContrastCurve(21, 21, 21, 21);
+    } else {
+      // Shouldn't happen.
+      return new ContrastCurve(defaultContrast, defaultContrast, 7, 21);
+    }
+  }
+
+  /////////////////////////////////////////////////////////////////
+  // Color value calculations                                    //
+  /////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public Hct getHct(DynamicScheme scheme, DynamicColor color) {
+    // This is crucial for aesthetics: we aren't simply the taking the standard color
+    // and changing its tone for contrast. Rather, we find the tone for contrast, then
+    // use the specified chroma from the palette to construct a new color.
+    //
+    // For example, this enables colors with standard tone of T90, which has limited chroma, to
+    // "recover" intended chroma as contrast increases.
+    TonalPalette palette = color.palette.apply(scheme);
+    double tone = getTone(scheme, color);
+    double hue = palette.getHue();
+    double chromaMultiplier =
+        color.chromaMultiplier == null ? 1 : color.chromaMultiplier.apply(scheme);
+    double chroma = palette.getChroma() * chromaMultiplier;
+
+    return Hct.from(hue, chroma, tone);
+  }
+
+  @Override
+  public double getTone(DynamicScheme scheme, DynamicColor color) {
+    ToneDeltaPair toneDeltaPair =
+        color.toneDeltaPair == null ? null : color.toneDeltaPair.apply(scheme);
+
+    // Case 0: tone delta pair.
+    if (toneDeltaPair != null) {
+      DynamicColor roleA = toneDeltaPair.getRoleA();
+      DynamicColor roleB = toneDeltaPair.getRoleB();
+      TonePolarity polarity = toneDeltaPair.getPolarity();
+      DeltaConstraint constraint = toneDeltaPair.getConstraint();
+      double absoluteDelta =
+          polarity == TonePolarity.DARKER
+                  || (polarity == TonePolarity.RELATIVE_LIGHTER && scheme.isDark)
+                  || (polarity == TonePolarity.RELATIVE_DARKER && !scheme.isDark)
+              ? -toneDeltaPair.getDelta()
+              : toneDeltaPair.getDelta();
+
+      boolean amRoleA = color.name.equals(roleA.name);
+      DynamicColor selfRole = amRoleA ? roleA : roleB;
+      DynamicColor referenceRole = amRoleA ? roleB : roleA;
+      double selfTone = selfRole.tone.apply(scheme);
+      double referenceTone = referenceRole.getTone(scheme);
+      double relativeDelta = absoluteDelta * (amRoleA ? 1 : -1);
+
+      switch (constraint) {
+        case EXACT:
+          selfTone = MathUtils.clampDouble(0, 100, referenceTone + relativeDelta);
+          break;
+        case NEARER:
+          if (relativeDelta > 0) {
+            selfTone =
+                MathUtils.clampDouble(
+                    0,
+                    100,
+                    MathUtils.clampDouble(referenceTone, referenceTone + relativeDelta, selfTone));
+          } else {
+            selfTone =
+                MathUtils.clampDouble(
+                    0,
+                    100,
+                    MathUtils.clampDouble(referenceTone + relativeDelta, referenceTone, selfTone));
+          }
+          break;
+        case FARTHER:
+          if (relativeDelta > 0) {
+            selfTone = MathUtils.clampDouble(referenceTone + relativeDelta, 100, selfTone);
+          } else {
+            selfTone = MathUtils.clampDouble(0, referenceTone + relativeDelta, selfTone);
+          }
+          break;
+      }
+
+      if (color.background != null && color.contrastCurve != null) {
+        DynamicColor background = color.background.apply(scheme);
+        ContrastCurve contrastCurve = color.contrastCurve.apply(scheme);
+        if (background != null && contrastCurve != null) {
+          double bgTone = background.getTone(scheme);
+          double selfContrast = contrastCurve.get(scheme.contrastLevel);
+          selfTone =
+              Contrast.ratioOfTones(bgTone, selfTone) >= selfContrast && scheme.contrastLevel >= 0
+                  ? selfTone
+                  : DynamicColor.foregroundTone(bgTone, selfContrast);
+        }
+      }
+
+      // This can avoid the awkward tones for background colors including the access fixed colors.
+      // Accent fixed dim colors should not be adjusted.
+      if (color.isBackground && !color.name.endsWith("_fixed_dim")) {
+        if (selfTone >= 57) {
+          selfTone = MathUtils.clampDouble(65, 100, selfTone);
+        } else {
+          selfTone = MathUtils.clampDouble(0, 49, selfTone);
+        }
+      }
+
+      return selfTone;
+    } else {
+      // Case 1: No tone delta pair; just solve for itself.
+      double answer = color.tone.apply(scheme);
+
+      if (color.background == null
+          || color.background.apply(scheme) == null
+          || color.contrastCurve == null
+          || color.contrastCurve.apply(scheme) == null) {
+        return answer; // No adjustment for colors with no background.
+      }
+
+      double bgTone = color.background.apply(scheme).getTone(scheme);
+      double desiredRatio = color.contrastCurve.apply(scheme).get(scheme.contrastLevel);
+
+      // Recalculate the tone from desired contrast ratio if the current
+      // contrast ratio is not enough or desired contrast level is decreasing
+      // (<0).
+      answer =
+          Contrast.ratioOfTones(bgTone, answer) >= desiredRatio && scheme.contrastLevel >= 0
+              ? answer
+              : DynamicColor.foregroundTone(bgTone, desiredRatio);
+
+      // This can avoid the awkward tones for background colors including the access fixed colors.
+      // Accent fixed dim colors should not be adjusted.
+      if (color.isBackground && !color.name.endsWith("_fixed_dim")) {
+        if (answer >= 57) {
+          answer = MathUtils.clampDouble(65, 100, answer);
+        } else {
+          answer = MathUtils.clampDouble(0, 49, answer);
+        }
+      }
+
+      if (color.secondBackground == null || color.secondBackground.apply(scheme) == null) {
+        return answer;
+      }
+
+      // Case 2: Adjust for dual backgrounds.
+      double bgTone1 = color.background.apply(scheme).getTone(scheme);
+      double bgTone2 = color.secondBackground.apply(scheme).getTone(scheme);
+      double upper = max(bgTone1, bgTone2);
+      double lower = min(bgTone1, bgTone2);
+
+      if (Contrast.ratioOfTones(upper, answer) >= desiredRatio
+          && Contrast.ratioOfTones(lower, answer) >= desiredRatio) {
+        return answer;
+      }
+
+      // The darkest light tone that satisfies the desired ratio,
+      // or -1 if such ratio cannot be reached.
+      double lightOption = Contrast.lighter(upper, desiredRatio);
+
+      // The lightest dark tone that satisfies the desired ratio,
+      // or -1 if such ratio cannot be reached.
+      double darkOption = Contrast.darker(lower, desiredRatio);
+
+      // Tones suitable for the foreground.
+      ArrayList<Double> availables = new ArrayList<>();
+      if (lightOption != -1) {
+        availables.add(lightOption);
+      }
+      if (darkOption != -1) {
+        availables.add(darkOption);
+      }
+
+      boolean prefersLight =
+          DynamicColor.tonePrefersLightForeground(bgTone1)
+              || DynamicColor.tonePrefersLightForeground(bgTone2);
+      if (prefersLight) {
+        return (lightOption < 0) ? 100 : lightOption;
+      }
+      if (availables.size() == 1) {
+        return availables.get(0);
+      }
+      return (darkOption < 0) ? 0 : darkOption;
+    }
+  }
+
+  //////////////////////////////////////////////////////////////////
+  // Scheme Palettes                                              //
+  //////////////////////////////////////////////////////////////////
+
+  @NonNull
+  @Override
+  public TonalPalette getPrimaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case NEUTRAL ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(),
+              platform == PHONE
+                  ? (Hct.isBlue(sourceColorHct.getHue()) ? 12 : 8)
+                  : (Hct.isBlue(sourceColorHct.getHue()) ? 16 : 12));
+      case TONAL_SPOT ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(), platform == PHONE && isDark ? 26 : 32);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(), platform == PHONE ? (isDark ? 36 : 48) : 40);
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), platform == PHONE ? 74 : 56);
+      default -> super.getPrimaryPalette(variant, sourceColorHct, isDark, platform, contrastLevel);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getSecondaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case NEUTRAL ->
+          TonalPalette.fromHueAndChroma(
+              sourceColorHct.getHue(),
+              platform == PHONE
+                  ? (Hct.isBlue(sourceColorHct.getHue()) ? 6 : 4)
+                  : (Hct.isBlue(sourceColorHct.getHue()) ? 10 : 6));
+      case TONAL_SPOT -> TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 105, 140, 204, 253, 278, 300, 333, 360},
+                  new double[] {-160, 155, -100, 96, -96, -156, -165, -160}),
+              platform == PHONE ? (isDark ? 16 : 24) : 24);
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 38, 105, 140, 333, 360},
+                  new double[] {-14, 10, -14, 10, -14}),
+              platform == PHONE ? 56 : 36);
+      default ->
+          super.getSecondaryPalette(variant, sourceColorHct, isDark, platform, contrastLevel);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getTertiaryPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case NEUTRAL ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 38, 105, 161, 204, 278, 333, 360},
+                  new double[] {-32, 26, 10, -39, 24, -15, -32}),
+              platform == PHONE ? 20 : 36);
+      case TONAL_SPOT ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 20, 71, 161, 333, 360},
+                  new double[] {-40, 48, -32, 40, -32}),
+              platform == PHONE ? 28 : 32);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 105, 140, 204, 253, 278, 300, 333, 360},
+                  new double[] {-165, 160, -105, 101, -101, -160, -170, -165}),
+              48);
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(
+              DynamicScheme.getRotatedHue(
+                  sourceColorHct,
+                  new double[] {0, 38, 71, 105, 140, 161, 253, 333, 360},
+                  new double[] {-72, 35, 24, -24, 62, 50, 62, -72}),
+              56);
+      default -> super.getTertiaryPalette(variant, sourceColorHct, isDark, platform, contrastLevel);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getNeutralPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    return switch (variant) {
+      case NEUTRAL ->
+          TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), platform == PHONE ? 1.4 : 6);
+      case TONAL_SPOT ->
+          TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), platform == PHONE ? 5 : 10);
+      case EXPRESSIVE ->
+          TonalPalette.fromHueAndChroma(
+              getExpressiveNeutralHue(sourceColorHct),
+              getExpressiveNeutralChroma(sourceColorHct, isDark, platform));
+      case VIBRANT ->
+          TonalPalette.fromHueAndChroma(
+              getVibrantNeutralHue(sourceColorHct),
+              getVibrantNeutralChroma(sourceColorHct, platform));
+      default -> super.getNeutralPalette(variant, sourceColorHct, isDark, platform, contrastLevel);
+    };
+  }
+
+  @NonNull
+  @Override
+  public TonalPalette getNeutralVariantPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    switch (variant) {
+      case NEUTRAL:
+        return TonalPalette.fromHueAndChroma(
+            sourceColorHct.getHue(), (platform == PHONE ? 1.4 : 6) * 2.2);
+      case TONAL_SPOT:
+        return TonalPalette.fromHueAndChroma(
+            sourceColorHct.getHue(), (platform == PHONE ? 5 : 10) * 1.7);
+      case EXPRESSIVE:
+        double expressiveNeutralHue = getExpressiveNeutralHue(sourceColorHct);
+        double expressiveNeutralChroma =
+            getExpressiveNeutralChroma(sourceColorHct, isDark, platform);
+        return TonalPalette.fromHueAndChroma(
+            expressiveNeutralHue,
+            expressiveNeutralChroma
+                * (expressiveNeutralHue >= 105 && expressiveNeutralHue < 125 ? 1.6 : 2.3));
+      case VIBRANT:
+        double vibrantNeutralHue = getVibrantNeutralHue(sourceColorHct);
+        double vibrantNeutralChroma = getVibrantNeutralChroma(sourceColorHct, platform);
+        return TonalPalette.fromHueAndChroma(vibrantNeutralHue, vibrantNeutralChroma * 1.29);
+      default:
+        return super.getNeutralVariantPalette(
+            variant, sourceColorHct, isDark, platform, contrastLevel);
+    }
+  }
+
+  @NonNull
+  @Override
+  public Optional<TonalPalette> getErrorPalette(
+      Variant variant,
+      Hct sourceColorHct,
+      boolean isDark,
+      Platform platform,
+      double contrastLevel) {
+    double errorHue =
+        DynamicScheme.getPiecewiseValue(
+            sourceColorHct,
+            new double[] {0, 3, 13, 23, 33, 43, 153, 273, 360},
+            new double[] {12, 22, 32, 12, 22, 32, 22, 12});
+    return switch (variant) {
+      case NEUTRAL ->
+          Optional.of(TonalPalette.fromHueAndChroma(errorHue, platform == PHONE ? 50 : 40));
+      case TONAL_SPOT ->
+          Optional.of(TonalPalette.fromHueAndChroma(errorHue, platform == PHONE ? 60 : 48));
+      case EXPRESSIVE ->
+          Optional.of(TonalPalette.fromHueAndChroma(errorHue, platform == PHONE ? 64 : 48));
+      case VIBRANT ->
+          Optional.of(TonalPalette.fromHueAndChroma(errorHue, platform == PHONE ? 80 : 60));
+      default -> super.getErrorPalette(variant, sourceColorHct, isDark, platform, contrastLevel);
+    };
+  }
+
+  private static double getExpressiveNeutralHue(Hct sourceColorHct) {
+    return DynamicScheme.getRotatedHue(
+        sourceColorHct,
+        new double[] {0, 71, 124, 253, 278, 300, 360},
+        new double[] {10, 0, 10, 0, 10, 0});
+  }
+
+  private static double getExpressiveNeutralChroma(
+      Hct sourceColorHct, boolean isDark, Platform platform) {
+    double neutralHue = getExpressiveNeutralHue(sourceColorHct);
+    return platform == PHONE ? (isDark ? (Hct.isYellow(neutralHue) ? 6 : 14) : 18) : 12;
+  }
+
+  private static double getVibrantNeutralHue(Hct sourceColorHct) {
+    return DynamicScheme.getRotatedHue(
+        sourceColorHct,
+        new double[] {0, 38, 105, 140, 333, 360},
+        new double[] {-14, 10, -14, 10, -14});
+  }
+
+  private static double getVibrantNeutralChroma(Hct sourceColorHct, Platform platform) {
+    double neutralHue = getVibrantNeutralHue(sourceColorHct);
+    return platform == PHONE ? 28 : (Hct.isBlue(neutralHue) ? 28 : 20);
+  }
+}
diff --git a/dynamiccolor/ColorSpecs.java b/dynamiccolor/ColorSpecs.java
new file mode 100644
index 0000000..ca0f2a2
--- /dev/null
+++ b/dynamiccolor/ColorSpecs.java
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2025 Google LLC
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
+package com.google.ux.material.libmonet.dynamiccolor;
+
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+
+/** A utility class to get the correct color spec for a given spec version. */
+public final class ColorSpecs {
+
+  private static final ColorSpec SPEC_2021 = new ColorSpec2021();
+  private static final ColorSpec SPEC_2025 = new ColorSpec2025();
+
+  public static final ColorSpec get() {
+    return get(SpecVersion.SPEC_2021);
+  }
+
+  public static final ColorSpec get(SpecVersion specVersion) {
+    return get(specVersion, false);
+  }
+
+  public static final ColorSpec get(SpecVersion specVersion, boolean isExtendedFidelity) {
+    return specVersion == SpecVersion.SPEC_2025 ? SPEC_2025 : SPEC_2021;
+  }
+
+  private ColorSpecs() {}
+}
diff --git a/dynamiccolor/DynamicColor.java b/dynamiccolor/DynamicColor.java
index e42969e..c590e92 100644
--- a/dynamiccolor/DynamicColor.java
+++ b/dynamiccolor/DynamicColor.java
@@ -16,17 +16,14 @@
 
 package com.google.ux.material.libmonet.dynamiccolor;
 
-import static java.lang.Math.max;
-import static java.lang.Math.min;
-
 import android.annotation.NonNull;
 import android.annotation.Nullable;
-import com.google.errorprone.annotations.Var;
+import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import com.google.ux.material.libmonet.contrast.Contrast;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
 import com.google.ux.material.libmonet.hct.Hct;
 import com.google.ux.material.libmonet.palettes.TonalPalette;
 import com.google.ux.material.libmonet.utils.MathUtils;
-import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.function.Function;
 
@@ -60,9 +57,10 @@ public final class DynamicColor {
   public final Function<DynamicScheme, TonalPalette> palette;
   public final Function<DynamicScheme, Double> tone;
   public final boolean isBackground;
+  public final Function<DynamicScheme, Double> chromaMultiplier;
   public final Function<DynamicScheme, DynamicColor> background;
   public final Function<DynamicScheme, DynamicColor> secondBackground;
-  public final ContrastCurve contrastCurve;
+  public final Function<DynamicScheme, ContrastCurve> contrastCurve;
   public final Function<DynamicScheme, ToneDeltaPair> toneDeltaPair;
 
   public final Function<DynamicScheme, Double> opacity;
@@ -107,16 +105,16 @@ public final class DynamicColor {
       @Nullable Function<DynamicScheme, DynamicColor> secondBackground,
       @Nullable ContrastCurve contrastCurve,
       @Nullable Function<DynamicScheme, ToneDeltaPair> toneDeltaPair) {
-
-    this.name = name;
-    this.palette = palette;
-    this.tone = tone;
-    this.isBackground = isBackground;
-    this.background = background;
-    this.secondBackground = secondBackground;
-    this.contrastCurve = contrastCurve;
-    this.toneDeltaPair = toneDeltaPair;
-    this.opacity = null;
+    this(
+        name,
+        palette,
+        tone,
+        isBackground,
+        background,
+        secondBackground,
+        contrastCurve,
+        toneDeltaPair,
+        /* opacity= */ null);
   }
 
   /**
@@ -159,10 +157,35 @@ public final class DynamicColor {
       @Nullable ContrastCurve contrastCurve,
       @Nullable Function<DynamicScheme, ToneDeltaPair> toneDeltaPair,
       @Nullable Function<DynamicScheme, Double> opacity) {
+    this(
+        name,
+        palette,
+        tone,
+        isBackground,
+        null,
+        background,
+        secondBackground,
+        (s) -> contrastCurve,
+        toneDeltaPair,
+        opacity);
+  }
+
+  public DynamicColor(
+      @NonNull String name,
+      @NonNull Function<DynamicScheme, TonalPalette> palette,
+      @NonNull Function<DynamicScheme, Double> tone,
+      boolean isBackground,
+      @Nullable Function<DynamicScheme, Double> chromaMultiplier,
+      @Nullable Function<DynamicScheme, DynamicColor> background,
+      @Nullable Function<DynamicScheme, DynamicColor> secondBackground,
+      @Nullable Function<DynamicScheme, ContrastCurve> contrastCurve,
+      @Nullable Function<DynamicScheme, ToneDeltaPair> toneDeltaPair,
+      @Nullable Function<DynamicScheme, Double> opacity) {
     this.name = name;
     this.palette = palette;
     this.tone = tone;
     this.isBackground = isBackground;
+    this.chromaMultiplier = chromaMultiplier;
     this.background = background;
     this.secondBackground = secondBackground;
     this.contrastCurve = contrastCurve;
@@ -270,7 +293,7 @@ public final class DynamicColor {
    */
   public int getArgb(@NonNull DynamicScheme scheme) {
     int argb = getHct(scheme).toInt();
-    if (opacity == null) {
+    if (opacity == null || opacity.apply(scheme) == null) {
       return argb;
     }
     double percentage = opacity.apply(scheme);
@@ -290,14 +313,8 @@ public final class DynamicColor {
     if (cachedAnswer != null) {
       return cachedAnswer;
     }
-    // This is crucial for aesthetics: we aren't simply the taking the standard color
-    // and changing its tone for contrast. Rather, we find the tone for contrast, then
-    // use the specified chroma from the palette to construct a new color.
-    //
-    // For example, this enables colors with standard tone of T90, which has limited chroma, to
-    // "recover" intended chroma as contrast increases.
-    double tone = getTone(scheme);
-    Hct answer = palette.apply(scheme).getHct(tone);
+
+    Hct answer = ColorSpecs.get(scheme.specVersion).getHct(scheme, this);
     // NOMUTANTS--trivial test with onerous dependency injection requirement.
     if (hctCache.size() > 4) {
       hctCache.clear();
@@ -309,178 +326,7 @@ public final class DynamicColor {
 
   /** Returns the tone in HCT, ranging from 0 to 100, of the resolved color given scheme. */
   public double getTone(@NonNull DynamicScheme scheme) {
-    boolean decreasingContrast = scheme.contrastLevel < 0;
-
-    // Case 1: dual foreground, pair of colors with delta constraint.
-    if (toneDeltaPair != null) {
-      ToneDeltaPair toneDeltaPair = this.toneDeltaPair.apply(scheme);
-      DynamicColor roleA = toneDeltaPair.getRoleA();
-      DynamicColor roleB = toneDeltaPair.getRoleB();
-      double delta = toneDeltaPair.getDelta();
-      TonePolarity polarity = toneDeltaPair.getPolarity();
-      boolean stayTogether = toneDeltaPair.getStayTogether();
-
-      DynamicColor bg = background.apply(scheme);
-      double bgTone = bg.getTone(scheme);
-
-      boolean aIsNearer =
-          (polarity == TonePolarity.NEARER
-              || (polarity == TonePolarity.LIGHTER && !scheme.isDark)
-              || (polarity == TonePolarity.DARKER && scheme.isDark));
-      DynamicColor nearer = aIsNearer ? roleA : roleB;
-      DynamicColor farther = aIsNearer ? roleB : roleA;
-      boolean amNearer = name.equals(nearer.name);
-      double expansionDir = scheme.isDark ? 1 : -1;
-
-      // 1st round: solve to min, each
-      double nContrast = nearer.contrastCurve.get(scheme.contrastLevel);
-      double fContrast = farther.contrastCurve.get(scheme.contrastLevel);
-
-      // If a color is good enough, it is not adjusted.
-      // Initial and adjusted tones for `nearer`
-      double nInitialTone = nearer.tone.apply(scheme);
-      @Var
-      double nTone =
-          Contrast.ratioOfTones(bgTone, nInitialTone) >= nContrast
-              ? nInitialTone
-              : DynamicColor.foregroundTone(bgTone, nContrast);
-      // Initial and adjusted tones for `farther`
-      double fInitialTone = farther.tone.apply(scheme);
-      @Var
-      double fTone =
-          Contrast.ratioOfTones(bgTone, fInitialTone) >= fContrast
-              ? fInitialTone
-              : DynamicColor.foregroundTone(bgTone, fContrast);
-
-      if (decreasingContrast) {
-        // If decreasing contrast, adjust color to the "bare minimum"
-        // that satisfies contrast.
-        nTone = DynamicColor.foregroundTone(bgTone, nContrast);
-        fTone = DynamicColor.foregroundTone(bgTone, fContrast);
-      }
-
-      // If constraint is not satisfied, try another round.
-      if ((fTone - nTone) * expansionDir < delta) {
-        // 2nd round: expand farther to match delta.
-        fTone = MathUtils.clampDouble(0, 100, nTone + delta * expansionDir);
-        // If constraint is not satisfied, try another round.
-        if ((fTone - nTone) * expansionDir < delta) {
-          // 3rd round: contract nearer to match delta.
-          nTone = MathUtils.clampDouble(0, 100, fTone - delta * expansionDir);
-        }
-      }
-
-      // Avoids the 50-59 awkward zone.
-      if (50 <= nTone && nTone < 60) {
-        // If `nearer` is in the awkward zone, move it away, together with
-        // `farther`.
-        if (expansionDir > 0) {
-          nTone = 60;
-          fTone = max(fTone, nTone + delta * expansionDir);
-        } else {
-          nTone = 49;
-          fTone = min(fTone, nTone + delta * expansionDir);
-        }
-      } else if (50 <= fTone && fTone < 60) {
-        if (stayTogether) {
-          // Fixes both, to avoid two colors on opposite sides of the "awkward
-          // zone".
-          if (expansionDir > 0) {
-            nTone = 60;
-            fTone = max(fTone, nTone + delta * expansionDir);
-          } else {
-            nTone = 49;
-            fTone = min(fTone, nTone + delta * expansionDir);
-          }
-        } else {
-          // Not required to stay together; fixes just one.
-          if (expansionDir > 0) {
-            fTone = 60;
-          } else {
-            fTone = 49;
-          }
-        }
-      }
-
-      // Returns `nTone` if this color is `nearer`, otherwise `fTone`.
-      return amNearer ? nTone : fTone;
-    } else {
-      // Case 2: No contrast pair; just solve for itself.
-      @Var double answer = tone.apply(scheme);
-
-      if (background == null) {
-        return answer; // No adjustment for colors with no background.
-      }
-
-      double bgTone = background.apply(scheme).getTone(scheme);
-
-      double desiredRatio = contrastCurve.get(scheme.contrastLevel);
-
-      if (Contrast.ratioOfTones(bgTone, answer) >= desiredRatio) {
-        // Don't "improve" what's good enough.
-      } else {
-        // Rough improvement.
-        answer = DynamicColor.foregroundTone(bgTone, desiredRatio);
-      }
-
-      if (decreasingContrast) {
-        answer = DynamicColor.foregroundTone(bgTone, desiredRatio);
-      }
-
-      if (isBackground && 50 <= answer && answer < 60) {
-        // Must adjust
-        if (Contrast.ratioOfTones(49, bgTone) >= desiredRatio) {
-          answer = 49;
-        } else {
-          answer = 60;
-        }
-      }
-
-      if (secondBackground != null) {
-        // Case 3: Adjust for dual backgrounds.
-
-        double bgTone1 = background.apply(scheme).getTone(scheme);
-        double bgTone2 = secondBackground.apply(scheme).getTone(scheme);
-
-        double upper = max(bgTone1, bgTone2);
-        double lower = min(bgTone1, bgTone2);
-
-        if (Contrast.ratioOfTones(upper, answer) >= desiredRatio
-            && Contrast.ratioOfTones(lower, answer) >= desiredRatio) {
-          return answer;
-        }
-
-        // The darkest light tone that satisfies the desired ratio,
-        // or -1 if such ratio cannot be reached.
-        double lightOption = Contrast.lighter(upper, desiredRatio);
-
-        // The lightest dark tone that satisfies the desired ratio,
-        // or -1 if such ratio cannot be reached.
-        double darkOption = Contrast.darker(lower, desiredRatio);
-
-        // Tones suitable for the foreground.
-        ArrayList<Double> availables = new ArrayList<>();
-        if (lightOption != -1) {
-          availables.add(lightOption);
-        }
-        if (darkOption != -1) {
-          availables.add(darkOption);
-        }
-
-        boolean prefersLight =
-            DynamicColor.tonePrefersLightForeground(bgTone1)
-                || DynamicColor.tonePrefersLightForeground(bgTone2);
-        if (prefersLight) {
-          return (lightOption == -1) ? 100 : lightOption;
-        }
-        if (availables.size() == 1) {
-          return availables.get(0);
-        }
-        return (darkOption == -1) ? 0 : darkOption;
-      }
-
-      return answer;
-    }
+    return ColorSpecs.get(scheme.specVersion).getTone(scheme, this);
   }
 
   /**
@@ -543,4 +389,215 @@ public final class DynamicColor {
   public static boolean toneAllowsLightForeground(double tone) {
     return Math.round(tone) <= 49;
   }
+
+  public static Function<DynamicScheme, Double> getInitialToneFromBackground(
+      @Nullable Function<DynamicScheme, DynamicColor> background) {
+    if (background == null) {
+      return (s) -> 50.0;
+    }
+    return (s) -> background.apply(s) != null ? background.apply(s).getTone(s) : 50.0;
+  }
+
+  public Builder toBuilder() {
+    return new Builder()
+        .setName(this.name)
+        .setPalette(this.palette)
+        .setTone(this.tone)
+        .setIsBackground(this.isBackground)
+        .setChromaMultiplier(this.chromaMultiplier)
+        .setBackground(this.background)
+        .setSecondBackground(this.secondBackground)
+        .setContrastCurve(this.contrastCurve)
+        .setToneDeltaPair(this.toneDeltaPair)
+        .setOpacity(this.opacity);
+  }
+
+  /** Builder for {@link DynamicColor}. */
+  public static class Builder {
+    private String name;
+    private Function<DynamicScheme, TonalPalette> palette;
+    private Function<DynamicScheme, Double> tone;
+    private boolean isBackground;
+    private Function<DynamicScheme, Double> chromaMultiplier;
+    private Function<DynamicScheme, DynamicColor> background;
+    private Function<DynamicScheme, DynamicColor> secondBackground;
+    private Function<DynamicScheme, ContrastCurve> contrastCurve;
+    private Function<DynamicScheme, ToneDeltaPair> toneDeltaPair;
+    private Function<DynamicScheme, Double> opacity;
+
+    @CanIgnoreReturnValue
+    public Builder setName(@NonNull String name) {
+      this.name = name;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setPalette(@NonNull Function<DynamicScheme, TonalPalette> palette) {
+      this.palette = palette;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setTone(@NonNull Function<DynamicScheme, Double> tone) {
+      this.tone = tone;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setIsBackground(boolean isBackground) {
+      this.isBackground = isBackground;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setChromaMultiplier(@NonNull Function<DynamicScheme, Double> chromaMultiplier) {
+      this.chromaMultiplier = chromaMultiplier;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setBackground(@NonNull Function<DynamicScheme, DynamicColor> background) {
+      this.background = background;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setSecondBackground(
+        @NonNull Function<DynamicScheme, DynamicColor> secondBackground) {
+      this.secondBackground = secondBackground;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setContrastCurve(@NonNull Function<DynamicScheme, ContrastCurve> contrastCurve) {
+      this.contrastCurve = contrastCurve;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setToneDeltaPair(@NonNull Function<DynamicScheme, ToneDeltaPair> toneDeltaPair) {
+      this.toneDeltaPair = toneDeltaPair;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    public Builder setOpacity(@NonNull Function<DynamicScheme, Double> opacity) {
+      this.opacity = opacity;
+      return this;
+    }
+
+    @CanIgnoreReturnValue
+    Builder extendSpecVersion(SpecVersion specVersion, DynamicColor extendedColor) {
+      validateExtendedColor(specVersion, extendedColor);
+
+      return new Builder()
+          .setName(this.name)
+          .setIsBackground(this.isBackground)
+          .setPalette(
+              (s) -> {
+                Function<DynamicScheme, TonalPalette> palette =
+                    s.specVersion == specVersion ? extendedColor.palette : this.palette;
+                return palette != null ? palette.apply(s) : null;
+              })
+          .setTone(
+              (s) -> {
+                Function<DynamicScheme, Double> tone =
+                    s.specVersion == specVersion ? extendedColor.tone : this.tone;
+                return tone != null ? tone.apply(s) : null;
+              })
+          .setChromaMultiplier(
+              (s) -> {
+                Function<DynamicScheme, Double> chromaMultiplier =
+                    s.specVersion == specVersion
+                        ? extendedColor.chromaMultiplier
+                        : this.chromaMultiplier;
+                return chromaMultiplier != null ? chromaMultiplier.apply(s) : 1.0;
+              })
+          .setBackground(
+              (s) -> {
+                Function<DynamicScheme, DynamicColor> background =
+                    s.specVersion == specVersion ? extendedColor.background : this.background;
+                return background != null ? background.apply(s) : null;
+              })
+          .setSecondBackground(
+              (s) -> {
+                Function<DynamicScheme, DynamicColor> secondBackground =
+                    s.specVersion == specVersion
+                        ? extendedColor.secondBackground
+                        : this.secondBackground;
+                return secondBackground != null ? secondBackground.apply(s) : null;
+              })
+          .setContrastCurve(
+              (s) -> {
+                Function<DynamicScheme, ContrastCurve> contrastCurve =
+                    s.specVersion == specVersion ? extendedColor.contrastCurve : this.contrastCurve;
+                return contrastCurve != null ? contrastCurve.apply(s) : null;
+              })
+          .setToneDeltaPair(
+              (s) -> {
+                Function<DynamicScheme, ToneDeltaPair> toneDeltaPair =
+                    s.specVersion == specVersion ? extendedColor.toneDeltaPair : this.toneDeltaPair;
+                return toneDeltaPair != null ? toneDeltaPair.apply(s) : null;
+              })
+          .setOpacity(
+              (s) -> {
+                Function<DynamicScheme, Double> opacity =
+                    s.specVersion == specVersion ? extendedColor.opacity : this.opacity;
+                return opacity != null ? opacity.apply(s) : null;
+              });
+    }
+
+    public DynamicColor build() {
+      if (this.background == null && this.secondBackground != null) {
+        throw new IllegalArgumentException(
+            "Color " + name + " has secondBackground defined, but background is not defined.");
+      }
+      if (this.background == null && this.contrastCurve != null) {
+        throw new IllegalArgumentException(
+            "Color " + name + " has contrastCurve defined, but background is not defined.");
+      }
+      if (this.background != null && this.contrastCurve == null) {
+        throw new IllegalArgumentException(
+            "Color " + name + " has background defined, but contrastCurve is not defined.");
+      }
+      return new DynamicColor(
+          this.name,
+          this.palette,
+          this.tone == null ? getInitialToneFromBackground(this.background) : this.tone,
+          this.isBackground,
+          this.chromaMultiplier,
+          this.background,
+          this.secondBackground,
+          this.contrastCurve,
+          this.toneDeltaPair,
+          this.opacity);
+    }
+
+    private void validateExtendedColor(SpecVersion specVersion, DynamicColor extendedColor) {
+      if (!this.name.equals(extendedColor.name)) {
+        throw new IllegalArgumentException(
+            "Attempting to extend color "
+                + this.name
+                + " with color "
+                + extendedColor.name
+                + " of different name for spec version "
+                + specVersion
+                + ".");
+      }
+      if (this.isBackground != extendedColor.isBackground) {
+        throw new IllegalArgumentException(
+            "Attempting to extend color "
+                + this.name
+                + " as a "
+                + (this.isBackground ? "background" : "foreground")
+                + " with color "
+                + extendedColor.name
+                + " as a "
+                + (extendedColor.isBackground ? "background" : "foreground")
+                + " for spec version "
+                + specVersion
+                + ".");
+      }
+    }
+  }
 }
diff --git a/dynamiccolor/DynamicScheme.java b/dynamiccolor/DynamicScheme.java
index 2244fa8..4ad33d3 100644
--- a/dynamiccolor/DynamicScheme.java
+++ b/dynamiccolor/DynamicScheme.java
@@ -16,9 +16,14 @@
 
 package com.google.ux.material.libmonet.dynamiccolor;
 
+import static java.lang.Math.min;
+
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
 import com.google.ux.material.libmonet.hct.Hct;
 import com.google.ux.material.libmonet.palettes.TonalPalette;
 import com.google.ux.material.libmonet.utils.MathUtils;
+import java.text.DecimalFormat;
+import java.util.Locale;
 import java.util.Optional;
 
 /**
@@ -27,12 +32,40 @@ import java.util.Optional;
  * (-1 to 1, currently contrast ratio 3.0 and 7.0)
  */
 public class DynamicScheme {
+
+  public static final SpecVersion DEFAULT_SPEC_VERSION = SpecVersion.SPEC_2025;
+  public static final Platform DEFAULT_PLATFORM = Platform.PHONE;
+
+  /** The platform on which this scheme is intended to be used. */
+  public enum Platform {
+    PHONE,
+    WATCH
+  }
+
+  /** The source color of the scheme in ARGB format. */
   public final int sourceColorArgb;
+
+  /** The source color of the scheme in HCT format. */
   public final Hct sourceColorHct;
+
+  /** The variant of the scheme. */
   public final Variant variant;
+
+  /** Whether or not the scheme is dark mode. */
   public final boolean isDark;
+
+  /** The platform on which this scheme is intended to be used. */
+  public final Platform platform;
+
+  /**
+   * Value from -1 to 1. -1 represents minimum contrast. 0 represents standard (i.e. the design as
+   * spec'd), and 1 represents maximum contrast.
+   */
   public final double contrastLevel;
 
+  /** The spec version of the scheme. */
+  public final SpecVersion specVersion;
+
   public final TonalPalette primaryPalette;
   public final TonalPalette secondaryPalette;
   public final TonalPalette tertiaryPalette;
@@ -74,11 +107,41 @@ public class DynamicScheme {
       TonalPalette neutralPalette,
       TonalPalette neutralVariantPalette,
       Optional<TonalPalette> errorPalette) {
+    this(
+        sourceColorHct,
+        variant,
+        isDark,
+        contrastLevel,
+        Platform.PHONE,
+        SpecVersion.SPEC_2021,
+        primaryPalette,
+        secondaryPalette,
+        tertiaryPalette,
+        neutralPalette,
+        neutralVariantPalette,
+        errorPalette);
+  }
+
+  public DynamicScheme(
+      Hct sourceColorHct,
+      Variant variant,
+      boolean isDark,
+      double contrastLevel,
+      Platform platform,
+      SpecVersion specVersion,
+      TonalPalette primaryPalette,
+      TonalPalette secondaryPalette,
+      TonalPalette tertiaryPalette,
+      TonalPalette neutralPalette,
+      TonalPalette neutralVariantPalette,
+      Optional<TonalPalette> errorPalette) {
     this.sourceColorArgb = sourceColorHct.toInt();
     this.sourceColorHct = sourceColorHct;
     this.variant = variant;
     this.isDark = isDark;
     this.contrastLevel = contrastLevel;
+    this.platform = platform;
+    this.specVersion = specVersion;
 
     this.primaryPalette = primaryPalette;
     this.secondaryPalette = secondaryPalette;
@@ -88,34 +151,96 @@ public class DynamicScheme {
     this.errorPalette = errorPalette.orElse(TonalPalette.fromHueAndChroma(25.0, 84.0));
   }
 
+  public static DynamicScheme from(DynamicScheme other, boolean isDark) {
+    return new DynamicScheme(
+        other.sourceColorHct,
+        other.variant,
+        isDark,
+        other.contrastLevel,
+        other.platform,
+        other.specVersion,
+        other.primaryPalette,
+        other.secondaryPalette,
+        other.tertiaryPalette,
+        other.neutralPalette,
+        other.neutralVariantPalette,
+        Optional.of(other.errorPalette));
+  }
+
   /**
-   * Given a set of hues and set of hue rotations, locate which hues the source color's hue is
-   * between, apply the rotation at the same index as the first hue in the range, and return the
-   * rotated hue.
+   * Returns a new hue based on a piecewise function and input color hue.
+   *
+   * <p>For example, for the following function:
+   *
+   * <pre>
+   * result = 26, if 0 <= hue < 101;
+   * result = 39, if 101 <= hue < 210;
+   * result = 28, if 210 <= hue < 360.
+   * </pre>
+   *
+   * <p>call the function as:
+   *
+   * <pre>
+   * double[] hueBreakpoints = {0, 101, 210, 360};
+   * double[] hues = {26, 39, 28};
+   * double result = scheme.piecewise(sourceColor, hueBreakpoints, hues);
+   * </pre>
    *
-   * @param sourceColorHct The color whose hue should be rotated.
-   * @param hues A set of hues.
-   * @param rotations A set of hue rotations.
-   * @return Color's hue with a rotation applied.
+   * @param sourceColorHct The input value.
+   * @param hueBreakpoints The breakpoints, in sorted order. No default lower or upper bounds are
+   *     assumed.
+   * @param hues The hues that should be applied when source color's hue is >= the same index in
+   *     hueBreakpoints array, and < the hue at the next index in hueBreakpoints array. Otherwise,
+   *     the source color's hue is returned.
    */
-  public static double getRotatedHue(Hct sourceColorHct, double[] hues, double[] rotations) {
-    final double sourceHue = sourceColorHct.getHue();
-    if (rotations.length == 1) {
-      return MathUtils.sanitizeDegreesDouble(sourceHue + rotations[0]);
-    }
-    final int size = hues.length;
-    for (int i = 0; i <= (size - 2); i++) {
-      final double thisHue = hues[i];
-      final double nextHue = hues[i + 1];
-      if (thisHue < sourceHue && sourceHue < nextHue) {
-        return MathUtils.sanitizeDegreesDouble(sourceHue + rotations[i]);
+  public static double getPiecewiseValue(
+      Hct sourceColorHct, double[] hueBreakpoints, double[] hues) {
+    int size = min(hueBreakpoints.length - 1, hues.length);
+    double sourceHue = sourceColorHct.getHue();
+    for (int i = 0; i < size; i++) {
+      if (sourceHue >= hueBreakpoints[i] && sourceHue < hueBreakpoints[i + 1]) {
+        return MathUtils.sanitizeDegreesDouble(hues[i]);
       }
     }
-    // If this statement executes, something is wrong, there should have been a rotation
-    // found using the arrays.
+    // No condition matched, return the source value.
     return sourceHue;
   }
 
+  /**
+   * Returns a shifted hue based on a piecewise function and input color hue.
+   *
+   * <p>For example, for the following function:
+   *
+   * <pre>
+   * result = hue + 26, if 0 <= hue < 101;
+   * result = hue - 39, if 101 <= hue < 210;
+   * result = hue + 28, if 210 <= hue < 360.
+   * </pre>
+   *
+   * <p>call the function as:
+   *
+   * <pre>
+   * double[] hueBreakpoints = {0, 101, 210, 360};
+   * double[] rotations = {26, -39, 28};
+   * double result = scheme.getRotatedHue(sourceColor, hueBreakpoints, rotations);
+   *
+   * @param sourceColorHct the source color of the theme, in HCT.
+   * @param hueBreakpoints The "breakpoints", i.e. the hues at which a rotation should be apply. No
+   * default lower or upper bounds are assumed.
+   * @param rotations The rotation that should be applied when source color's hue is >= the same
+   *     index in hues array, and < the hue at the next index in hues array. Otherwise, the source
+   *     color's hue is returned.
+   */
+  public static double getRotatedHue(
+      Hct sourceColorHct, double[] hueBreakpoints, double[] rotations) {
+    double rotation = getPiecewiseValue(sourceColorHct, hueBreakpoints, rotations);
+    if (min(hueBreakpoints.length - 1, rotations.length) <= 0) {
+      // No condition matched, return the source hue.
+      rotation = 0;
+    }
+    return MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + rotation);
+  }
+
   public Hct getHct(DynamicColor dynamicColor) {
     return dynamicColor.getHct(this);
   }
@@ -124,6 +249,18 @@ public class DynamicScheme {
     return dynamicColor.getArgb(this);
   }
 
+  @Override
+  public String toString() {
+    return String.format(
+        "Scheme: variant=%s, mode=%s, platform=%s, contrastLevel=%s, seed=%s, specVersion=%s",
+        variant.name(),
+        isDark ? "dark" : "light",
+        platform.name().toLowerCase(Locale.ENGLISH),
+        new DecimalFormat("0.0").format(contrastLevel),
+        sourceColorHct,
+        specVersion);
+  }
+
   public int getPrimaryPaletteKeyColor() {
     return getArgb(new MaterialDynamicColors().primaryPaletteKeyColor());
   }
diff --git a/dynamiccolor/MaterialDynamicColors.java b/dynamiccolor/MaterialDynamicColors.java
index 586ba4b..b2f9edb 100644
--- a/dynamiccolor/MaterialDynamicColors.java
+++ b/dynamiccolor/MaterialDynamicColors.java
@@ -17,8 +17,7 @@
 package com.google.ux.material.libmonet.dynamiccolor;
 
 import android.annotation.NonNull;
-import com.google.ux.material.libmonet.dislike.DislikeAnalyzer;
-import com.google.ux.material.libmonet.hct.Hct;
+import android.annotation.Nullable;
 import java.util.Arrays;
 import java.util.List;
 import java.util.function.Supplier;
@@ -31,818 +30,349 @@ import java.util.function.Supplier;
 // AndroidManifest with an SDK set higher than 14.
 @SuppressWarnings({"AndroidJdkLibsChecker", "NewApi"})
 public final class MaterialDynamicColors {
-  /** Optionally use fidelity on most color schemes. */
-  private final boolean isExtendedFidelity;
 
-  public MaterialDynamicColors() {
-    this.isExtendedFidelity = false;
-  }
-
-  // Temporary constructor to support extended fidelity experiment.
-  // TODO(b/291720794): Once schemes that will permanently use fidelity are identified,
-  // remove this and default to the decided behavior.
-  public MaterialDynamicColors(boolean isExtendedFidelity) {
-    this.isExtendedFidelity = isExtendedFidelity;
-  }
+  private static final ColorSpec colorSpec = new ColorSpec2025();
 
   @NonNull
   public DynamicColor highestSurface(@NonNull DynamicScheme s) {
-    return s.isDark ? surfaceBright() : surfaceDim();
+    return colorSpec.highestSurface(s);
   }
 
-  // Compatibility Keys Colors for Android
+  ////////////////////////////////////////////////////////////////
+  // Main Palettes                                              //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
   public DynamicColor primaryPaletteKeyColor() {
-    return DynamicColor.fromPalette(
-        /* name= */ "primary_palette_key_color",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> s.primaryPalette.getKeyColor().getTone());
+    return colorSpec.primaryPaletteKeyColor();
   }
 
   @NonNull
   public DynamicColor secondaryPaletteKeyColor() {
-    return DynamicColor.fromPalette(
-        /* name= */ "secondary_palette_key_color",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> s.secondaryPalette.getKeyColor().getTone());
+    return colorSpec.secondaryPaletteKeyColor();
   }
 
   @NonNull
   public DynamicColor tertiaryPaletteKeyColor() {
-    return DynamicColor.fromPalette(
-        /* name= */ "tertiary_palette_key_color",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> s.tertiaryPalette.getKeyColor().getTone());
+    return colorSpec.tertiaryPaletteKeyColor();
   }
 
   @NonNull
   public DynamicColor neutralPaletteKeyColor() {
-    return DynamicColor.fromPalette(
-        /* name= */ "neutral_palette_key_color",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.neutralPalette.getKeyColor().getTone());
+    return colorSpec.neutralPaletteKeyColor();
   }
 
   @NonNull
   public DynamicColor neutralVariantPaletteKeyColor() {
-    return DynamicColor.fromPalette(
-        /* name= */ "neutral_variant_palette_key_color",
-        /* palette= */ (s) -> s.neutralVariantPalette,
-        /* tone= */ (s) -> s.neutralVariantPalette.getKeyColor().getTone());
+    return colorSpec.neutralVariantPaletteKeyColor();
   }
 
+  @NonNull
+  public DynamicColor errorPaletteKeyColor() {
+    return colorSpec.errorPaletteKeyColor();
+  }
+
+  ////////////////////////////////////////////////////////////////
+  // Surfaces [S]                                               //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
   public DynamicColor background() {
-    return new DynamicColor(
-        /* name= */ "background",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 6.0 : 98.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.background();
   }
 
   @NonNull
   public DynamicColor onBackground() {
-    return new DynamicColor(
-        /* name= */ "on_background",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 90.0 : 10.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> background(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 3.0, 4.5, 7.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.onBackground();
   }
 
   @NonNull
   public DynamicColor surface() {
-    return new DynamicColor(
-        /* name= */ "surface",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 6.0 : 98.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surface();
   }
 
   @NonNull
   public DynamicColor surfaceDim() {
-    return new DynamicColor(
-        /* name= */ "surface_dim",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark ? 6.0 : new ContrastCurve(87.0, 87.0, 80.0, 75.0).get(s.contrastLevel),
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceDim();
   }
 
   @NonNull
   public DynamicColor surfaceBright() {
-    return new DynamicColor(
-        /* name= */ "surface_bright",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark ? new ContrastCurve(24.0, 24.0, 29.0, 34.0).get(s.contrastLevel) : 98.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceBright();
   }
 
   @NonNull
   public DynamicColor surfaceContainerLowest() {
-    return new DynamicColor(
-        /* name= */ "surface_container_lowest",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark ? new ContrastCurve(4.0, 4.0, 2.0, 0.0).get(s.contrastLevel) : 100.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceContainerLowest();
   }
 
   @NonNull
   public DynamicColor surfaceContainerLow() {
-    return new DynamicColor(
-        /* name= */ "surface_container_low",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark
-                ? new ContrastCurve(10.0, 10.0, 11.0, 12.0).get(s.contrastLevel)
-                : new ContrastCurve(96.0, 96.0, 96.0, 95.0).get(s.contrastLevel),
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceContainerLow();
   }
 
   @NonNull
   public DynamicColor surfaceContainer() {
-    return new DynamicColor(
-        /* name= */ "surface_container",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark
-                ? new ContrastCurve(12.0, 12.0, 16.0, 20.0).get(s.contrastLevel)
-                : new ContrastCurve(94.0, 94.0, 92.0, 90.0).get(s.contrastLevel),
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceContainer();
   }
 
   @NonNull
   public DynamicColor surfaceContainerHigh() {
-    return new DynamicColor(
-        /* name= */ "surface_container_high",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark
-                ? new ContrastCurve(17.0, 17.0, 21.0, 25.0).get(s.contrastLevel)
-                : new ContrastCurve(92.0, 92.0, 88.0, 85.0).get(s.contrastLevel),
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceContainerHigh();
   }
 
   @NonNull
   public DynamicColor surfaceContainerHighest() {
-    return new DynamicColor(
-        /* name= */ "surface_container_highest",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) ->
-            s.isDark
-                ? new ContrastCurve(22.0, 22.0, 26.0, 30.0).get(s.contrastLevel)
-                : new ContrastCurve(90.0, 90.0, 84.0, 80.0).get(s.contrastLevel),
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceContainerHighest();
   }
 
   @NonNull
   public DynamicColor onSurface() {
-    return new DynamicColor(
-        /* name= */ "on_surface",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 90.0 : 10.0,
-        /* isBackground= */ false,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.onSurface();
   }
 
   @NonNull
   public DynamicColor surfaceVariant() {
-    return new DynamicColor(
-        /* name= */ "surface_variant",
-        /* palette= */ (s) -> s.neutralVariantPalette,
-        /* tone= */ (s) -> s.isDark ? 30.0 : 90.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceVariant();
   }
 
   @NonNull
   public DynamicColor onSurfaceVariant() {
-    return new DynamicColor(
-        /* name= */ "on_surface_variant",
-        /* palette= */ (s) -> s.neutralVariantPalette,
-        /* tone= */ (s) -> s.isDark ? 80.0 : 30.0,
-        /* isBackground= */ false,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.onSurfaceVariant();
   }
 
   @NonNull
   public DynamicColor inverseSurface() {
-    return new DynamicColor(
-        /* name= */ "inverse_surface",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 90.0 : 20.0,
-        /* isBackground= */ false,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.inverseSurface();
   }
 
   @NonNull
   public DynamicColor inverseOnSurface() {
-    return new DynamicColor(
-        /* name= */ "inverse_on_surface",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 20.0 : 95.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> inverseSurface(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.inverseOnSurface();
   }
 
   @NonNull
   public DynamicColor outline() {
-    return new DynamicColor(
-        /* name= */ "outline",
-        /* palette= */ (s) -> s.neutralVariantPalette,
-        /* tone= */ (s) -> s.isDark ? 60.0 : 50.0,
-        /* isBackground= */ false,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.5, 3.0, 4.5, 7.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.outline();
   }
 
   @NonNull
   public DynamicColor outlineVariant() {
-    return new DynamicColor(
-        /* name= */ "outline_variant",
-        /* palette= */ (s) -> s.neutralVariantPalette,
-        /* tone= */ (s) -> s.isDark ? 30.0 : 80.0,
-        /* isBackground= */ false,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ null);
+    return colorSpec.outlineVariant();
   }
 
   @NonNull
   public DynamicColor shadow() {
-    return new DynamicColor(
-        /* name= */ "shadow",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> 0.0,
-        /* isBackground= */ false,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.shadow();
   }
 
   @NonNull
   public DynamicColor scrim() {
-    return new DynamicColor(
-        /* name= */ "scrim",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> 0.0,
-        /* isBackground= */ false,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.scrim();
   }
 
   @NonNull
   public DynamicColor surfaceTint() {
-    return new DynamicColor(
-        /* name= */ "surface_tint",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> s.isDark ? 80.0 : 40.0,
-        /* isBackground= */ true,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null);
+    return colorSpec.surfaceTint();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // Primaries [P]                                              //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
   public DynamicColor primary() {
-    return new DynamicColor(
-        /* name= */ "primary",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 100.0 : 0.0;
-          }
-          return s.isDark ? 80.0 : 40.0;
-        },
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 7.0),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(primaryContainer(), primary(), 10.0, TonePolarity.NEARER, false));
+    return colorSpec.primary();
+  }
+
+  @Nullable
+  public DynamicColor primaryDim() {
+    return colorSpec.primaryDim();
   }
 
   @NonNull
   public DynamicColor onPrimary() {
-    return new DynamicColor(
-        /* name= */ "on_primary",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 10.0 : 90.0;
-          }
-          return s.isDark ? 20.0 : 100.0;
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> primary(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.onPrimary();
   }
 
   @NonNull
   public DynamicColor primaryContainer() {
-    return new DynamicColor(
-        /* name= */ "primary_container",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> {
-          if (isFidelity(s)) {
-            return s.sourceColorHct.getTone();
-          }
-          if (isMonochrome(s)) {
-            return s.isDark ? 85.0 : 25.0;
-          }
-          return s.isDark ? 30.0 : 90.0;
-        },
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(primaryContainer(), primary(), 10.0, TonePolarity.NEARER, false));
+    return colorSpec.primaryContainer();
   }
 
   @NonNull
   public DynamicColor onPrimaryContainer() {
-    return new DynamicColor(
-        /* name= */ "on_primary_container",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> {
-          if (isFidelity(s)) {
-            return DynamicColor.foregroundTone(primaryContainer().tone.apply(s), 4.5);
-          }
-          if (isMonochrome(s)) {
-            return s.isDark ? 0.0 : 100.0;
-          }
-          return s.isDark ? 90.0 : 30.0;
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> primaryContainer(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.onPrimaryContainer();
   }
 
   @NonNull
   public DynamicColor inversePrimary() {
-    return new DynamicColor(
-        /* name= */ "inverse_primary",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> s.isDark ? 40.0 : 80.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> inverseSurface(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 7.0),
-        /* toneDeltaPair= */ null);
+    return colorSpec.inversePrimary();
   }
 
+  /////////////////////////////////////////////////////////////////
+  // Primary Fixed Colors [PF]                                   //
+  /////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor secondary() {
-    return new DynamicColor(
-        /* name= */ "secondary",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> s.isDark ? 80.0 : 40.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 7.0),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(secondaryContainer(), secondary(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor primaryFixed() {
+    return colorSpec.primaryFixed();
   }
 
   @NonNull
-  public DynamicColor onSecondary() {
-    return new DynamicColor(
-        /* name= */ "on_secondary",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 10.0 : 100.0;
-          } else {
-            return s.isDark ? 20.0 : 100.0;
-          }
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> secondary(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor primaryFixedDim() {
+    return colorSpec.primaryFixedDim();
   }
 
   @NonNull
-  public DynamicColor secondaryContainer() {
-    return new DynamicColor(
-        /* name= */ "secondary_container",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> {
-          final double initialTone = s.isDark ? 30.0 : 90.0;
-          if (isMonochrome(s)) {
-            return s.isDark ? 30.0 : 85.0;
-          }
-          if (!isFidelity(s)) {
-            return initialTone;
-          }
-          return findDesiredChromaByTone(
-              s.secondaryPalette.getHue(), s.secondaryPalette.getChroma(), initialTone, !s.isDark);
-        },
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(secondaryContainer(), secondary(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor onPrimaryFixed() {
+    return colorSpec.onPrimaryFixed();
   }
 
   @NonNull
-  public DynamicColor onSecondaryContainer() {
-    return new DynamicColor(
-        /* name= */ "on_secondary_container",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 90.0 : 10.0;
-          }
-          if (!isFidelity(s)) {
-            return s.isDark ? 90.0 : 30.0;
-          }
-          return DynamicColor.foregroundTone(secondaryContainer().tone.apply(s), 4.5);
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> secondaryContainer(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onPrimaryFixedVariant() {
+    return colorSpec.onPrimaryFixedVariant();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // Secondaries [Q]                                            //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor tertiary() {
-    return new DynamicColor(
-        /* name= */ "tertiary",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 90.0 : 25.0;
-          }
-          return s.isDark ? 80.0 : 40.0;
-        },
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 7.0),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(tertiaryContainer(), tertiary(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor secondary() {
+    return colorSpec.secondary();
+  }
+
+  @Nullable
+  public DynamicColor secondaryDim() {
+    return colorSpec.secondaryDim();
   }
 
   @NonNull
-  public DynamicColor onTertiary() {
-    return new DynamicColor(
-        /* name= */ "on_tertiary",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 10.0 : 90.0;
-          }
-          return s.isDark ? 20.0 : 100.0;
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> tertiary(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onSecondary() {
+    return colorSpec.onSecondary();
   }
 
   @NonNull
-  public DynamicColor tertiaryContainer() {
-    return new DynamicColor(
-        /* name= */ "tertiary_container",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 60.0 : 49.0;
-          }
-          if (!isFidelity(s)) {
-            return s.isDark ? 30.0 : 90.0;
-          }
-          final Hct proposedHct = s.tertiaryPalette.getHct(s.sourceColorHct.getTone());
-          return DislikeAnalyzer.fixIfDisliked(proposedHct).getTone();
-        },
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(tertiaryContainer(), tertiary(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor secondaryContainer() {
+    return colorSpec.secondaryContainer();
   }
 
   @NonNull
-  public DynamicColor onTertiaryContainer() {
-    return new DynamicColor(
-        /* name= */ "on_tertiary_container",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 0.0 : 100.0;
-          }
-          if (!isFidelity(s)) {
-            return s.isDark ? 90.0 : 30.0;
-          }
-          return DynamicColor.foregroundTone(tertiaryContainer().tone.apply(s), 4.5);
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> tertiaryContainer(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onSecondaryContainer() {
+    return colorSpec.onSecondaryContainer();
   }
 
+  /////////////////////////////////////////////////////////////////
+  // Secondary Fixed Colors [QF]                                 //
+  /////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor error() {
-    return new DynamicColor(
-        /* name= */ "error",
-        /* palette= */ (s) -> s.errorPalette,
-        /* tone= */ (s) -> s.isDark ? 80.0 : 40.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 7.0),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(errorContainer(), error(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor secondaryFixed() {
+    return colorSpec.secondaryFixed();
   }
 
   @NonNull
-  public DynamicColor onError() {
-    return new DynamicColor(
-        /* name= */ "on_error",
-        /* palette= */ (s) -> s.errorPalette,
-        /* tone= */ (s) -> s.isDark ? 20.0 : 100.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> error(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor secondaryFixedDim() {
+    return colorSpec.secondaryFixedDim();
   }
 
   @NonNull
-  public DynamicColor errorContainer() {
-    return new DynamicColor(
-        /* name= */ "error_container",
-        /* palette= */ (s) -> s.errorPalette,
-        /* tone= */ (s) -> s.isDark ? 30.0 : 90.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(errorContainer(), error(), 10.0, TonePolarity.NEARER, false));
+  public DynamicColor onSecondaryFixed() {
+    return colorSpec.onSecondaryFixed();
   }
 
   @NonNull
-  public DynamicColor onErrorContainer() {
-    return new DynamicColor(
-        /* name= */ "on_error_container",
-        /* palette= */ (s) -> s.errorPalette,
-        /* tone= */ (s) -> {
-          if (isMonochrome(s)) {
-            return s.isDark ? 90.0 : 10.0;
-          }
-          return s.isDark ? 90.0 : 30.0;
-        },
-        /* isBackground= */ false,
-        /* background= */ (s) -> errorContainer(),
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onSecondaryFixedVariant() {
+    return colorSpec.onSecondaryFixedVariant();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // Tertiaries [T]                                             //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor primaryFixed() {
-    return new DynamicColor(
-        /* name= */ "primary_fixed",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 40.0 : 90.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(primaryFixed(), primaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor tertiary() {
+    return colorSpec.tertiary();
+  }
+
+  @Nullable
+  public DynamicColor tertiaryDim() {
+    return colorSpec.tertiaryDim();
   }
 
   @NonNull
-  public DynamicColor primaryFixedDim() {
-    return new DynamicColor(
-        /* name= */ "primary_fixed_dim",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 30.0 : 80.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(primaryFixed(), primaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor onTertiary() {
+    return colorSpec.onTertiary();
   }
 
   @NonNull
-  public DynamicColor onPrimaryFixed() {
-    return new DynamicColor(
-        /* name= */ "on_primary_fixed",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 100.0 : 10.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> primaryFixedDim(),
-        /* secondBackground= */ (s) -> primaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor tertiaryContainer() {
+    return colorSpec.tertiaryContainer();
   }
 
   @NonNull
-  public DynamicColor onPrimaryFixedVariant() {
-    return new DynamicColor(
-        /* name= */ "on_primary_fixed_variant",
-        /* palette= */ (s) -> s.primaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 90.0 : 30.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> primaryFixedDim(),
-        /* secondBackground= */ (s) -> primaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onTertiaryContainer() {
+    return colorSpec.onTertiaryContainer();
   }
 
+  /////////////////////////////////////////////////////////////////
+  // Tertiary Fixed Colors [TF]                                  //
+  /////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor secondaryFixed() {
-    return new DynamicColor(
-        /* name= */ "secondary_fixed",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 80.0 : 90.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(
-                secondaryFixed(), secondaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor tertiaryFixed() {
+    return colorSpec.tertiaryFixed();
   }
 
   @NonNull
-  public DynamicColor secondaryFixedDim() {
-    return new DynamicColor(
-        /* name= */ "secondary_fixed_dim",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 70.0 : 80.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(
-                secondaryFixed(), secondaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor tertiaryFixedDim() {
+    return colorSpec.tertiaryFixedDim();
   }
 
   @NonNull
-  public DynamicColor onSecondaryFixed() {
-    return new DynamicColor(
-        /* name= */ "on_secondary_fixed",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> 10.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> secondaryFixedDim(),
-        /* secondBackground= */ (s) -> secondaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onTertiaryFixed() {
+    return colorSpec.onTertiaryFixed();
   }
 
   @NonNull
-  public DynamicColor onSecondaryFixedVariant() {
-    return new DynamicColor(
-        /* name= */ "on_secondary_fixed_variant",
-        /* palette= */ (s) -> s.secondaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 25.0 : 30.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> secondaryFixedDim(),
-        /* secondBackground= */ (s) -> secondaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onTertiaryFixedVariant() {
+    return colorSpec.onTertiaryFixedVariant();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // Errors [E]                                                 //
+  ////////////////////////////////////////////////////////////////
+
   @NonNull
-  public DynamicColor tertiaryFixed() {
-    return new DynamicColor(
-        /* name= */ "tertiary_fixed",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 40.0 : 90.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(
-                tertiaryFixed(), tertiaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor error() {
+    return colorSpec.error();
+  }
+
+  @Nullable
+  public DynamicColor errorDim() {
+    return colorSpec.errorDim();
   }
 
   @NonNull
-  public DynamicColor tertiaryFixedDim() {
-    return new DynamicColor(
-        /* name= */ "tertiary_fixed_dim",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 30.0 : 80.0,
-        /* isBackground= */ true,
-        /* background= */ this::highestSurface,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(1.0, 1.0, 3.0, 4.5),
-        /* toneDeltaPair= */ (s) ->
-            new ToneDeltaPair(
-                tertiaryFixed(), tertiaryFixedDim(), 10.0, TonePolarity.LIGHTER, true));
+  public DynamicColor onError() {
+    return colorSpec.onError();
   }
 
   @NonNull
-  public DynamicColor onTertiaryFixed() {
-    return new DynamicColor(
-        /* name= */ "on_tertiary_fixed",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 100.0 : 10.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> tertiaryFixedDim(),
-        /* secondBackground= */ (s) -> tertiaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor errorContainer() {
+    return colorSpec.errorContainer();
   }
 
   @NonNull
-  public DynamicColor onTertiaryFixedVariant() {
-    return new DynamicColor(
-        /* name= */ "on_tertiary_fixed_variant",
-        /* palette= */ (s) -> s.tertiaryPalette,
-        /* tone= */ (s) -> isMonochrome(s) ? 90.0 : 30.0,
-        /* isBackground= */ false,
-        /* background= */ (s) -> tertiaryFixedDim(),
-        /* secondBackground= */ (s) -> tertiaryFixed(),
-        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
-        /* toneDeltaPair= */ null);
+  public DynamicColor onErrorContainer() {
+    return colorSpec.onErrorContainer();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // Android-only colors                                        //
+  ////////////////////////////////////////////////////////////////
+
   /**
    * These colors were present in Android framework before Android U, and used by MDC controls. They
    * should be avoided, if possible. It's unclear if they're used on multiple backgrounds, and if
@@ -852,14 +382,14 @@ public final class MaterialDynamicColors {
    * <p>* For example, if the same color is on a white background _and_ black background, there's no
    * way to increase contrast with either without losing contrast with the other.
    */
+
   // colorControlActivated documented as colorAccent in M3 & GM3.
   // colorAccent documented as colorSecondary in M3 and colorPrimary in GM3.
   // Android used Material's Container as Primary/Secondary/Tertiary at launch.
   // Therefore, this is a duplicated version of Primary Container.
   @NonNull
   public DynamicColor controlActivated() {
-    return DynamicColor.fromPalette(
-        "control_activated", (s) -> s.primaryPalette, (s) -> s.isDark ? 30.0 : 90.0);
+    return colorSpec.controlActivated();
   }
 
   // colorControlNormal documented as textColorSecondary in M3 & GM3.
@@ -867,8 +397,7 @@ public final class MaterialDynamicColors {
   // which is Neutral Variant T30/80 in light/dark.
   @NonNull
   public DynamicColor controlNormal() {
-    return DynamicColor.fromPalette(
-        "control_normal", (s) -> s.neutralVariantPalette, (s) -> s.isDark ? 80.0 : 30.0);
+    return colorSpec.controlNormal();
   }
 
   // colorControlHighlight documented, in both M3 & GM3:
@@ -881,61 +410,45 @@ public final class MaterialDynamicColors {
   // Returning black in dark mode, white in light mode.
   @NonNull
   public DynamicColor controlHighlight() {
-    return new DynamicColor(
-        /* name= */ "control_highlight",
-        /* palette= */ (s) -> s.neutralPalette,
-        /* tone= */ (s) -> s.isDark ? 100.0 : 0.0,
-        /* isBackground= */ false,
-        /* background= */ null,
-        /* secondBackground= */ null,
-        /* contrastCurve= */ null,
-        /* toneDeltaPair= */ null,
-        /* opacity= */ s -> s.isDark ? 0.20 : 0.12);
+    return colorSpec.controlHighlight();
   }
 
   // textColorPrimaryInverse documented, in both M3 & GM3, documented as N10/N90.
   @NonNull
   public DynamicColor textPrimaryInverse() {
-    return DynamicColor.fromPalette(
-        "text_primary_inverse", (s) -> s.neutralPalette, (s) -> s.isDark ? 10.0 : 90.0);
+    return colorSpec.textPrimaryInverse();
   }
 
   // textColorSecondaryInverse and textColorTertiaryInverse both documented, in both M3 & GM3, as
   // NV30/NV80
   @NonNull
   public DynamicColor textSecondaryAndTertiaryInverse() {
-    return DynamicColor.fromPalette(
-        "text_secondary_and_tertiary_inverse",
-        (s) -> s.neutralVariantPalette,
-        (s) -> s.isDark ? 30.0 : 80.0);
+    return colorSpec.textSecondaryAndTertiaryInverse();
   }
 
   // textColorPrimaryInverseDisableOnly documented, in both M3 & GM3, as N10/N90
   @NonNull
   public DynamicColor textPrimaryInverseDisableOnly() {
-    return DynamicColor.fromPalette(
-        "text_primary_inverse_disable_only",
-        (s) -> s.neutralPalette,
-        (s) -> s.isDark ? 10.0 : 90.0);
+    return colorSpec.textPrimaryInverseDisableOnly();
   }
 
   // textColorSecondaryInverse and textColorTertiaryInverse in disabled state both documented,
   // in both M3 & GM3, as N10/N90
   @NonNull
   public DynamicColor textSecondaryAndTertiaryInverseDisabled() {
-    return DynamicColor.fromPalette(
-        "text_secondary_and_tertiary_inverse_disabled",
-        (s) -> s.neutralPalette,
-        (s) -> s.isDark ? 10.0 : 90.0);
+    return colorSpec.textSecondaryAndTertiaryInverseDisabled();
   }
 
   // textColorHintInverse documented, in both M3 & GM3, as N10/N90
   @NonNull
   public DynamicColor textHintInverse() {
-    return DynamicColor.fromPalette(
-        "text_hint_inverse", (s) -> s.neutralPalette, (s) -> s.isDark ? 10.0 : 90.0);
+    return colorSpec.textHintInverse();
   }
 
+  ////////////////////////////////////////////////////////////////
+  // All Colors                                                 //
+  ////////////////////////////////////////////////////////////////
+
   /** All dynamic colors in Material Design system. */
   public final List<Supplier<DynamicColor>> allDynamicColors() {
     return Arrays.asList(
@@ -944,6 +457,7 @@ public final class MaterialDynamicColors {
         this::tertiaryPaletteKeyColor,
         this::neutralPaletteKeyColor,
         this::neutralVariantPaletteKeyColor,
+        this::errorPaletteKeyColor,
         this::background,
         this::onBackground,
         this::surface,
@@ -957,42 +471,46 @@ public final class MaterialDynamicColors {
         this::onSurface,
         this::surfaceVariant,
         this::onSurfaceVariant,
-        this::inverseSurface,
-        this::inverseOnSurface,
         this::outline,
         this::outlineVariant,
+        this::inverseSurface,
+        this::inverseOnSurface,
         this::shadow,
         this::scrim,
         this::surfaceTint,
         this::primary,
+        this::primaryDim,
         this::onPrimary,
         this::primaryContainer,
         this::onPrimaryContainer,
+        this::primaryFixed,
+        this::primaryFixedDim,
+        this::onPrimaryFixed,
+        this::onPrimaryFixedVariant,
         this::inversePrimary,
         this::secondary,
+        this::secondaryDim,
         this::onSecondary,
         this::secondaryContainer,
         this::onSecondaryContainer,
-        this::tertiary,
-        this::onTertiary,
-        this::tertiaryContainer,
-        this::onTertiaryContainer,
-        this::error,
-        this::onError,
-        this::errorContainer,
-        this::onErrorContainer,
-        this::primaryFixed,
-        this::primaryFixedDim,
-        this::onPrimaryFixed,
-        this::onPrimaryFixedVariant,
         this::secondaryFixed,
         this::secondaryFixedDim,
         this::onSecondaryFixed,
         this::onSecondaryFixedVariant,
+        this::tertiary,
+        this::tertiaryDim,
+        this::onTertiary,
+        this::tertiaryContainer,
+        this::onTertiaryContainer,
         this::tertiaryFixed,
         this::tertiaryFixedDim,
         this::onTertiaryFixed,
         this::onTertiaryFixedVariant,
+        this::error,
+        this::errorDim,
+        this::onError,
+        this::errorContainer,
+        this::onErrorContainer,
         this::controlActivated,
         this::controlNormal,
         this::controlHighlight,
@@ -1002,46 +520,4 @@ public final class MaterialDynamicColors {
         this::textSecondaryAndTertiaryInverseDisabled,
         this::textHintInverse);
   }
-
-  private boolean isFidelity(DynamicScheme scheme) {
-    if (this.isExtendedFidelity
-        && scheme.variant != Variant.MONOCHROME
-        && scheme.variant != Variant.NEUTRAL) {
-      return true;
-    }
-    return scheme.variant == Variant.FIDELITY || scheme.variant == Variant.CONTENT;
-  }
-
-  private static boolean isMonochrome(DynamicScheme scheme) {
-    return scheme.variant == Variant.MONOCHROME;
-  }
-
-  static double findDesiredChromaByTone(
-      double hue, double chroma, double tone, boolean byDecreasingTone) {
-    double answer = tone;
-
-    Hct closestToChroma = Hct.from(hue, chroma, tone);
-    if (closestToChroma.getChroma() < chroma) {
-      double chromaPeak = closestToChroma.getChroma();
-      while (closestToChroma.getChroma() < chroma) {
-        answer += byDecreasingTone ? -1.0 : 1.0;
-        Hct potentialSolution = Hct.from(hue, chroma, answer);
-        if (chromaPeak > potentialSolution.getChroma()) {
-          break;
-        }
-        if (Math.abs(potentialSolution.getChroma() - chroma) < 0.4) {
-          break;
-        }
-
-        double potentialDelta = Math.abs(potentialSolution.getChroma() - chroma);
-        double currentDelta = Math.abs(closestToChroma.getChroma() - chroma);
-        if (potentialDelta < currentDelta) {
-          closestToChroma = potentialSolution;
-        }
-        chromaPeak = Math.max(chromaPeak, potentialSolution.getChroma());
-      }
-    }
-
-    return answer;
-  }
 }
diff --git a/dynamiccolor/ToneDeltaPair.java b/dynamiccolor/ToneDeltaPair.java
index cc8dc22..2770fd3 100644
--- a/dynamiccolor/ToneDeltaPair.java
+++ b/dynamiccolor/ToneDeltaPair.java
@@ -27,6 +27,13 @@ import android.annotation.NonNull;
  * relationship or a contrast guarantee.
  */
 public final class ToneDeltaPair {
+  /** Describes how to fulfill a tone delta pair constraint. */
+  public enum DeltaConstraint {
+    EXACT,
+    NEARER,
+    FARTHER
+  }
+
   /** The first role in a pair. */
   private final DynamicColor roleA;
 
@@ -45,6 +52,9 @@ public final class ToneDeltaPair {
    */
   private final boolean stayTogether;
 
+  /** How to fulfill the tone delta pair constraint. */
+  private final DeltaConstraint constraint;
+
   /**
    * Documents a constraint in tone distance between two DynamicColors.
    *
@@ -53,9 +63,10 @@ public final class ToneDeltaPair {
    * <p>For instance, ToneDeltaPair(A, B, 15, 'darker', stayTogether) states that A's tone should be
    * at least 15 darker than B's.
    *
-   * <p>'nearer' and 'farther' describes closeness to the surface roles. For instance,
-   * ToneDeltaPair(A, B, 10, 'nearer', stayTogether) states that A should be 10 lighter than B in
-   * light mode, and 10 darker than B in dark mode.
+   * <p>'relative_darker' and 'relative_lighter' describes the tone adjustment relative to the
+   * surface color trend (white in light mode; black in dark mode). For instance, ToneDeltaPair(A,
+   * B, 10, 'relative_lighter', 'farther') states that A should be at least 10 lighter than B in
+   * light mode, and at least 10 darker than B in dark mode.
    *
    * @param roleA The first role in a pair.
    * @param roleB The second role in a pair.
@@ -76,6 +87,32 @@ public final class ToneDeltaPair {
     this.delta = delta;
     this.polarity = polarity;
     this.stayTogether = stayTogether;
+    this.constraint = DeltaConstraint.EXACT;
+  }
+
+  /**
+   * Documents a constraint in tone distance between two DynamicColors.
+   *
+   * @see #ToneDeltaPair(DynamicColor, DynamicColor, double, TonePolarity, boolean)
+   * @param roleA The first role in a pair.
+   * @param roleB The second role in a pair.
+   * @param delta Required difference between tones. Absolute value, negative values have undefined
+   *     behavior.
+   * @param polarity The relative relation between tones of roleA and roleB, as described above.
+   * @param constraint How to fulfill the tone delta pair constraint.
+   */
+  public ToneDeltaPair(
+      DynamicColor roleA,
+      DynamicColor roleB,
+      double delta,
+      TonePolarity polarity,
+      DeltaConstraint constraint) {
+    this.roleA = roleA;
+    this.roleB = roleB;
+    this.delta = delta;
+    this.polarity = polarity;
+    this.stayTogether = true;
+    this.constraint = constraint;
   }
 
   @NonNull
@@ -100,4 +137,9 @@ public final class ToneDeltaPair {
   public boolean getStayTogether() {
     return stayTogether;
   }
+
+  @NonNull
+  public DeltaConstraint getConstraint() {
+    return constraint;
+  }
 }
diff --git a/dynamiccolor/TonePolarity.java b/dynamiccolor/TonePolarity.java
index a0d2df1..7735e91 100644
--- a/dynamiccolor/TonePolarity.java
+++ b/dynamiccolor/TonePolarity.java
@@ -19,15 +19,26 @@ package com.google.ux.material.libmonet.dynamiccolor;
 /**
  * Describes the relationship in lightness between two colors.
  *
- * <p>'nearer' and 'farther' describes closeness to the surface roles. For instance,
- * ToneDeltaPair(A, B, 10, 'nearer', stayTogether) states that A should be 10 lighter than B in
- * light mode, and 10 darker than B in dark mode.
+ * <p>'relative_darker' and 'relative_lighter' describes the tone adjustment relative to the surface
+ * color trend (white in light mode; black in dark mode). For instance, ToneDeltaPair(A, B, 10,
+ * 'relative_lighter', 'farther') states that A should be at least 10 lighter than B in light mode,
+ * and at least 10 darker than B in dark mode.
  *
  * <p>See `ToneDeltaPair` for details.
  */
 public enum TonePolarity {
   DARKER,
   LIGHTER,
+  RELATIVE_DARKER,
+  RELATIVE_LIGHTER,
+  /**
+   * @deprecated Use {@link ToneDeltaPair.DeltaConstraint} instead.
+   */
+  @Deprecated
   NEARER,
+  /**
+   * @deprecated Use {@link ToneDeltaPair.DeltaConstraint} instead.
+   */
+  @Deprecated
   FARTHER;
 }
diff --git a/hct/Hct.java b/hct/Hct.java
index 97ee5e6..ddbe4c3 100644
--- a/hct/Hct.java
+++ b/hct/Hct.java
@@ -117,6 +117,29 @@ public final class Hct {
     setInternalState(HctSolver.solveToInt(hue, chroma, newTone));
   }
 
+  @Override
+  public String toString() {
+    return "HCT("
+        + (int) Math.round(hue)
+        + ", "
+        + (int) Math.round(chroma)
+        + ", "
+        + (int) Math.round(tone)
+        + ")";
+  }
+
+  public static boolean isBlue(double hue) {
+    return hue >= 250 && hue < 270;
+  }
+
+  public static boolean isYellow(double hue) {
+    return hue >= 105 && hue < 125;
+  }
+
+  public static boolean isCyan(double hue) {
+    return hue >= 170 && hue < 207;
+  }
+
   /**
    * Translate a color into different ViewingConditions.
    *
diff --git a/palettes/TonalPalette.java b/palettes/TonalPalette.java
index 6357aef..583e3fb 100644
--- a/palettes/TonalPalette.java
+++ b/palettes/TonalPalette.java
@@ -79,7 +79,11 @@ public final class TonalPalette {
   public int tone(int tone) {
     Integer color = cache.get(tone);
     if (color == null) {
-      color = Hct.from(this.hue, this.chroma, tone).toInt();
+      if (tone == 99 && Hct.isYellow(this.hue)) {
+        color = averageArgb(this.tone(98), this.tone(100));
+      } else {
+        color = Hct.from(this.hue, this.chroma, tone).toInt();
+      }
       cache.put(tone, color);
     }
     return color;
@@ -105,6 +109,19 @@ public final class TonalPalette {
     return this.keyColor;
   }
 
+  private int averageArgb(int argb1, int argb2) {
+    int red1 = (argb1 >>> 16) & 0xff;
+    int green1 = (argb1 >>> 8) & 0xff;
+    int blue1 = argb1 & 0xff;
+    int red2 = (argb2 >>> 16) & 0xff;
+    int green2 = (argb2 >>> 8) & 0xff;
+    int blue2 = argb2 & 0xff;
+    int red = Math.round((red1 + red2) / 2f);
+    int green = Math.round((green1 + green2) / 2f);
+    int blue = Math.round((blue1 + blue2) / 2f);
+    return (255 << 24 | (red & 255) << 16 | (green & 255) << 8 | (blue & 255)) >>> 0;
+  }
+
   /** Key color is a color that represents the hue and chroma of a tonal palette. */
   private static final class KeyColor {
     private final double hue;
diff --git a/quantize/QuantizerWu.java b/quantize/QuantizerWu.java
index c89e254..e8f8cb5 100644
--- a/quantize/QuantizerWu.java
+++ b/quantize/QuantizerWu.java
@@ -326,45 +326,43 @@ public final class QuantizerWu implements Quantizer {
   }
 
   static int bottom(Box cube, Direction direction, int[] moment) {
-    switch (direction) {
-      case RED:
-        return -moment[getIndex(cube.r0, cube.g1, cube.b1)]
-            + moment[getIndex(cube.r0, cube.g1, cube.b0)]
-            + moment[getIndex(cube.r0, cube.g0, cube.b1)]
-            - moment[getIndex(cube.r0, cube.g0, cube.b0)];
-      case GREEN:
-        return -moment[getIndex(cube.r1, cube.g0, cube.b1)]
-            + moment[getIndex(cube.r1, cube.g0, cube.b0)]
-            + moment[getIndex(cube.r0, cube.g0, cube.b1)]
-            - moment[getIndex(cube.r0, cube.g0, cube.b0)];
-      case BLUE:
-        return -moment[getIndex(cube.r1, cube.g1, cube.b0)]
-            + moment[getIndex(cube.r1, cube.g0, cube.b0)]
-            + moment[getIndex(cube.r0, cube.g1, cube.b0)]
-            - moment[getIndex(cube.r0, cube.g0, cube.b0)];
-    }
-    throw new IllegalArgumentException("unexpected direction " + direction);
+    return switch (direction) {
+      case RED ->
+          -moment[getIndex(cube.r0, cube.g1, cube.b1)]
+              + moment[getIndex(cube.r0, cube.g1, cube.b0)]
+              + moment[getIndex(cube.r0, cube.g0, cube.b1)]
+              - moment[getIndex(cube.r0, cube.g0, cube.b0)];
+      case GREEN ->
+          -moment[getIndex(cube.r1, cube.g0, cube.b1)]
+              + moment[getIndex(cube.r1, cube.g0, cube.b0)]
+              + moment[getIndex(cube.r0, cube.g0, cube.b1)]
+              - moment[getIndex(cube.r0, cube.g0, cube.b0)];
+      case BLUE ->
+          -moment[getIndex(cube.r1, cube.g1, cube.b0)]
+              + moment[getIndex(cube.r1, cube.g0, cube.b0)]
+              + moment[getIndex(cube.r0, cube.g1, cube.b0)]
+              - moment[getIndex(cube.r0, cube.g0, cube.b0)];
+    };
   }
 
   static int top(Box cube, Direction direction, int position, int[] moment) {
-    switch (direction) {
-      case RED:
-        return (moment[getIndex(position, cube.g1, cube.b1)]
-            - moment[getIndex(position, cube.g1, cube.b0)]
-            - moment[getIndex(position, cube.g0, cube.b1)]
-            + moment[getIndex(position, cube.g0, cube.b0)]);
-      case GREEN:
-        return (moment[getIndex(cube.r1, position, cube.b1)]
-            - moment[getIndex(cube.r1, position, cube.b0)]
-            - moment[getIndex(cube.r0, position, cube.b1)]
-            + moment[getIndex(cube.r0, position, cube.b0)]);
-      case BLUE:
-        return (moment[getIndex(cube.r1, cube.g1, position)]
-            - moment[getIndex(cube.r1, cube.g0, position)]
-            - moment[getIndex(cube.r0, cube.g1, position)]
-            + moment[getIndex(cube.r0, cube.g0, position)]);
-    }
-    throw new IllegalArgumentException("unexpected direction " + direction);
+    return switch (direction) {
+      case RED ->
+          (moment[getIndex(position, cube.g1, cube.b1)]
+              - moment[getIndex(position, cube.g1, cube.b0)]
+              - moment[getIndex(position, cube.g0, cube.b1)]
+              + moment[getIndex(position, cube.g0, cube.b0)]);
+      case GREEN ->
+          (moment[getIndex(cube.r1, position, cube.b1)]
+              - moment[getIndex(cube.r1, position, cube.b0)]
+              - moment[getIndex(cube.r0, position, cube.b1)]
+              + moment[getIndex(cube.r0, position, cube.b0)]);
+      case BLUE ->
+          (moment[getIndex(cube.r1, cube.g1, position)]
+              - moment[getIndex(cube.r1, cube.g0, position)]
+              - moment[getIndex(cube.r0, cube.g1, position)]
+              + moment[getIndex(cube.r0, cube.g0, position)]);
+    };
   }
 
   private static enum Direction {
diff --git a/scheme/SchemeContent.java b/scheme/SchemeContent.java
index 41c127c..9a9cdc6 100644
--- a/scheme/SchemeContent.java
+++ b/scheme/SchemeContent.java
@@ -16,14 +16,11 @@
 
 package com.google.ux.material.libmonet.scheme;
 
-import static java.lang.Math.max;
-
-import com.google.ux.material.libmonet.dislike.DislikeAnalyzer;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.temperature.TemperatureCache;
 
 /**
  * A scheme that places the source color in Scheme.primaryContainer.
@@ -38,23 +35,37 @@ import com.google.ux.material.libmonet.temperature.TemperatureCache;
  * appearance.
  */
 public class SchemeContent extends DynamicScheme {
+
   public SchemeContent(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeContent(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.CONTENT,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma()),
-        TonalPalette.fromHueAndChroma(
-            sourceColorHct.getHue(),
-            max(sourceColorHct.getChroma() - 32.0, sourceColorHct.getChroma() * 0.5)),
-        TonalPalette.fromHct(
-            DislikeAnalyzer.fixIfDisliked(
-                new TemperatureCache(sourceColorHct)
-                    .getAnalogousColors(/* count= */ 3, /* divisions= */ 6)
-                    .get(2))),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma() / 8.0),
-        TonalPalette.fromHueAndChroma(
-            sourceColorHct.getHue(), (sourceColorHct.getChroma() / 8.0) + 4.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.CONTENT, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
+
diff --git a/scheme/SchemeExpressive.java b/scheme/SchemeExpressive.java
index 4773b05..ce9fe4c 100644
--- a/scheme/SchemeExpressive.java
+++ b/scheme/SchemeExpressive.java
@@ -16,34 +16,46 @@
 
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.utils.MathUtils;
 
 /** A playful theme - the source color's hue does not appear in the theme. */
 public class SchemeExpressive extends DynamicScheme {
-  // NOMUTANTS--arbitrary increments/decrements, correctly, still passes tests.
-  private static final double[] HUES = {0, 21, 51, 121, 151, 191, 271, 321, 360};
-  private static final double[] SECONDARY_ROTATIONS = {45, 95, 45, 20, 45, 90, 45, 45, 45};
-  private static final double[] TERTIARY_ROTATIONS = {120, 120, 20, 45, 20, 15, 20, 120, 120};
 
   public SchemeExpressive(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeExpressive(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.EXPRESSIVE,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 240.0), 40.0),
-        TonalPalette.fromHueAndChroma(
-            DynamicScheme.getRotatedHue(sourceColorHct, HUES, SECONDARY_ROTATIONS), 24.0),
-        TonalPalette.fromHueAndChroma(
-            DynamicScheme.getRotatedHue(sourceColorHct, HUES, TERTIARY_ROTATIONS), 32.0),
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 15.0), 8.0),
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 15.0), 12.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(
+                Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(
+                Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.EXPRESSIVE, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
diff --git a/scheme/SchemeFidelity.java b/scheme/SchemeFidelity.java
index 8bb56ba..619c2f3 100644
--- a/scheme/SchemeFidelity.java
+++ b/scheme/SchemeFidelity.java
@@ -16,12 +16,11 @@
 
 package com.google.ux.material.libmonet.scheme;
 
-import com.google.ux.material.libmonet.dislike.DislikeAnalyzer;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.temperature.TemperatureCache;
 
 /**
  * A scheme that places the source color in Scheme.primaryContainer.
@@ -34,20 +33,36 @@ import com.google.ux.material.libmonet.temperature.TemperatureCache;
  * maintains constant appearance.
  */
 public class SchemeFidelity extends DynamicScheme {
+
   public SchemeFidelity(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeFidelity(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.FIDELITY,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma()),
-        TonalPalette.fromHueAndChroma(
-            sourceColorHct.getHue(),
-            Math.max(sourceColorHct.getChroma() - 32.0, sourceColorHct.getChroma() * 0.5)),
-        TonalPalette.fromHct(
-            DislikeAnalyzer.fixIfDisliked(new TemperatureCache(sourceColorHct).getComplement())),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), sourceColorHct.getChroma() / 8.0),
-        TonalPalette.fromHueAndChroma(
-            sourceColorHct.getHue(), (sourceColorHct.getChroma() / 8.0) + 4.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.FIDELITY, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
diff --git a/scheme/SchemeFruitSalad.java b/scheme/SchemeFruitSalad.java
index b481f4a..ff62bd4 100644
--- a/scheme/SchemeFruitSalad.java
+++ b/scheme/SchemeFruitSalad.java
@@ -15,26 +15,48 @@
  */
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.utils.MathUtils;
 
 /** A playful theme - the source color's hue does not appear in the theme. */
 public class SchemeFruitSalad extends DynamicScheme {
+
   public SchemeFruitSalad(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeFruitSalad(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.FRUIT_SALAD,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() - 50.0), 48.0),
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() - 50.0), 36.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 36.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 10.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(
+                Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(
+                Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(
+                Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(
+                Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.FRUIT_SALAD, sourceColorHct, isDark, platform, contrastLevel));
   }
-}
\ No newline at end of file
+}
diff --git a/scheme/SchemeMonochrome.java b/scheme/SchemeMonochrome.java
index 7ecaae0..cdeb838 100644
--- a/scheme/SchemeMonochrome.java
+++ b/scheme/SchemeMonochrome.java
@@ -16,23 +16,46 @@
 
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
 
 /** A monochrome theme, colors are purely black / white / gray. */
 public class SchemeMonochrome extends DynamicScheme {
+
   public SchemeMonochrome(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeMonochrome(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.MONOCHROME,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(
+                Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(
+                Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.MONOCHROME, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
diff --git a/scheme/SchemeNeutral.java b/scheme/SchemeNeutral.java
index f4d74d5..4742473 100644
--- a/scheme/SchemeNeutral.java
+++ b/scheme/SchemeNeutral.java
@@ -15,23 +15,44 @@
  */
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
 
 /** A theme that's slightly more chromatic than monochrome, which is purely black / white / gray. */
 public class SchemeNeutral extends DynamicScheme {
+
   public SchemeNeutral(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeNeutral(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.NEUTRAL,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 12.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 8.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 2.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 2.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.NEUTRAL, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
diff --git a/scheme/SchemeRainbow.java b/scheme/SchemeRainbow.java
index 6736647..5fad086 100644
--- a/scheme/SchemeRainbow.java
+++ b/scheme/SchemeRainbow.java
@@ -15,25 +15,44 @@
  */
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.utils.MathUtils;
 
 /** A playful theme - the source color's hue does not appear in the theme. */
 public class SchemeRainbow extends DynamicScheme {
+
   public SchemeRainbow(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeRainbow(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.RAINBOW,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 48.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0),
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 60.0), 24.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 0.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.RAINBOW, sourceColorHct, isDark, platform, contrastLevel));
   }
-}
\ No newline at end of file
+}
diff --git a/scheme/SchemeTonalSpot.java b/scheme/SchemeTonalSpot.java
index 58db3e4..6b32ffd 100644
--- a/scheme/SchemeTonalSpot.java
+++ b/scheme/SchemeTonalSpot.java
@@ -15,25 +15,46 @@
  */
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
-import com.google.ux.material.libmonet.utils.MathUtils;
 
 /** A calm theme, sedated colors that aren't particularly chromatic. */
 public class SchemeTonalSpot extends DynamicScheme {
+
   public SchemeTonalSpot(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeTonalSpot(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.TONAL_SPOT,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 36.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 16.0),
-        TonalPalette.fromHueAndChroma(
-            MathUtils.sanitizeDegreesDouble(sourceColorHct.getHue() + 60.0), 24.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 6.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 8.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(
+                Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(
+                Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.TONAL_SPOT, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
diff --git a/scheme/SchemeVibrant.java b/scheme/SchemeVibrant.java
index 417bd49..2b8defb 100644
--- a/scheme/SchemeVibrant.java
+++ b/scheme/SchemeVibrant.java
@@ -15,29 +15,44 @@
  */
 package com.google.ux.material.libmonet.scheme;
 
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion;
+import com.google.ux.material.libmonet.dynamiccolor.ColorSpecs;
 import com.google.ux.material.libmonet.dynamiccolor.DynamicScheme;
 import com.google.ux.material.libmonet.dynamiccolor.Variant;
 import com.google.ux.material.libmonet.hct.Hct;
-import com.google.ux.material.libmonet.palettes.TonalPalette;
 
 /** A loud theme, colorfulness is maximum for Primary palette, increased for others. */
 public class SchemeVibrant extends DynamicScheme {
-  private static final double[] HUES = {0, 41, 61, 101, 131, 181, 251, 301, 360};
-  private static final double[] SECONDARY_ROTATIONS = {18, 15, 10, 12, 15, 18, 15, 12, 12};
-  private static final double[] TERTIARY_ROTATIONS = {35, 30, 20, 25, 30, 35, 30, 25, 25};
 
   public SchemeVibrant(Hct sourceColorHct, boolean isDark, double contrastLevel) {
+    this(sourceColorHct, isDark, contrastLevel, DEFAULT_SPEC_VERSION, DEFAULT_PLATFORM);
+  }
+
+  public SchemeVibrant(
+      Hct sourceColorHct,
+      boolean isDark,
+      double contrastLevel,
+      SpecVersion specVersion,
+      Platform platform) {
     super(
         sourceColorHct,
         Variant.VIBRANT,
         isDark,
         contrastLevel,
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 200.0),
-        TonalPalette.fromHueAndChroma(
-            DynamicScheme.getRotatedHue(sourceColorHct, HUES, SECONDARY_ROTATIONS), 24.0),
-        TonalPalette.fromHueAndChroma(
-            DynamicScheme.getRotatedHue(sourceColorHct, HUES, TERTIARY_ROTATIONS), 32.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 10.0),
-        TonalPalette.fromHueAndChroma(sourceColorHct.getHue(), 12.0));
+        platform,
+        specVersion,
+        ColorSpecs.get(specVersion)
+            .getPrimaryPalette(Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getSecondaryPalette(Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getTertiaryPalette(Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralPalette(Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getNeutralVariantPalette(
+                Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel),
+        ColorSpecs.get(specVersion)
+            .getErrorPalette(Variant.VIBRANT, sourceColorHct, isDark, platform, contrastLevel));
   }
 }
```

