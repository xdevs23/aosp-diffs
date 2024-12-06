```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..f1e4324
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,49 @@
+{
+  "presubmit": [
+    {
+      "name": "CtsGraphicsTestCases",
+      "options": [
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        }
+      ]
+    }
+  ],
+  // v2/sysui/suite/test-mapping-sysui-screenshot-test
+  "sysui-screenshot-test": [
+    {
+      "name": "SystemUIGoogleScreenshotTests",
+      "options": [
+        {
+          "exclude-annotation": "org.junit.Ignore"
+        },
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        },
+        {
+          "exclude-annotation": "android.platform.test.annotations.FlakyTest"
+        },
+        {
+          "exclude-annotation": "android.platform.test.annotations.Postsubmit"
+        }
+      ]
+    },
+    {
+      "name": "SystemUIGoogleKeyguardScreenshotTests",
+      "options": [
+        {
+          "exclude-annotation": "org.junit.Ignore"
+        },
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        },
+        {
+          "exclude-annotation": "android.platform.test.annotations.FlakyTest"
+        },
+        {
+          "exclude-annotation": "android.platform.test.annotations.Postsubmit"
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/dynamiccolor/MaterialDynamicColors.java b/dynamiccolor/MaterialDynamicColors.java
index 776ff7f..dfa9f54 100644
--- a/dynamiccolor/MaterialDynamicColors.java
+++ b/dynamiccolor/MaterialDynamicColors.java
@@ -434,12 +434,12 @@ public final class MaterialDynamicColors {
           if (isMonochrome(s)) {
             return s.isDark ? 0.0 : 100.0;
           }
-          return s.isDark ? 90.0 : 10.0;
+          return s.isDark ? 90.0 : 30.0;
         },
         /* isBackground= */ false,
         /* background= */ (s) -> primaryContainer(),
         /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
+        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
         /* toneDeltaPair= */ null);
   }
 
@@ -519,15 +519,18 @@ public final class MaterialDynamicColors {
         /* name= */ "on_secondary_container",
         /* palette= */ (s) -> s.secondaryPalette,
         /* tone= */ (s) -> {
-          if (!isFidelity(s)) {
+          if (isMonochrome(s)) {
             return s.isDark ? 90.0 : 10.0;
           }
+          if (!isFidelity(s)) {
+            return s.isDark ? 90.0 : 30.0;
+          }
           return DynamicColor.foregroundTone(secondaryContainer().tone.apply(s), 4.5);
         },
         /* isBackground= */ false,
         /* background= */ (s) -> secondaryContainer(),
         /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
+        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
         /* toneDeltaPair= */ null);
   }
 
@@ -601,14 +604,14 @@ public final class MaterialDynamicColors {
             return s.isDark ? 0.0 : 100.0;
           }
           if (!isFidelity(s)) {
-            return s.isDark ? 90.0 : 10.0;
+            return s.isDark ? 90.0 : 30.0;
           }
           return DynamicColor.foregroundTone(tertiaryContainer().tone.apply(s), 4.5);
         },
         /* isBackground= */ false,
         /* background= */ (s) -> tertiaryContainer(),
         /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
+        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
         /* toneDeltaPair= */ null);
   }
 
@@ -658,11 +661,16 @@ public final class MaterialDynamicColors {
     return new DynamicColor(
         /* name= */ "on_error_container",
         /* palette= */ (s) -> s.errorPalette,
-        /* tone= */ (s) -> s.isDark ? 90.0 : 10.0,
+        /* tone= */ (s) -> {
+          if (isMonochrome(s)) {
+            return s.isDark ? 90.0 : 10.0;
+          }
+          return s.isDark ? 90.0 : 30.0;
+        },
         /* isBackground= */ false,
         /* background= */ (s) -> errorContainer(),
         /* secondBackground= */ null,
-        /* contrastCurve= */ new ContrastCurve(4.5, 7.0, 11.0, 21.0),
+        /* contrastCurve= */ new ContrastCurve(3.0, 4.5, 7.0, 11.0),
         /* toneDeltaPair= */ null);
   }
 
diff --git a/palettes/TonalPalette.java b/palettes/TonalPalette.java
index 618d324..bcb8657 100644
--- a/palettes/TonalPalette.java
+++ b/palettes/TonalPalette.java
@@ -57,7 +57,8 @@ public final class TonalPalette {
    * @return Tones matching hue and chroma.
    */
   public static TonalPalette fromHueAndChroma(double hue, double chroma) {
-    return new TonalPalette(hue, chroma, createKeyColor(hue, chroma));
+    final Hct keyColor = new KeyColor(hue, chroma).create();
+    return new TonalPalette(hue, chroma, keyColor);
   }
 
   private TonalPalette(double hue, double chroma, Hct keyColor) {
@@ -67,44 +68,6 @@ public final class TonalPalette {
     this.keyColor = keyColor;
   }
 
-  /** The key color is the first tone, starting from T50, matching the given hue and chroma. */
-  private static Hct createKeyColor(double hue, double chroma) {
-    double startTone = 50.0;
-    Hct smallestDeltaHct = Hct.from(hue, chroma, startTone);
-    double smallestDelta = Math.abs(smallestDeltaHct.getChroma() - chroma);
-    // Starting from T50, check T+/-delta to see if they match the requested
-    // chroma.
-    //
-    // Starts from T50 because T50 has the most chroma available, on
-    // average. Thus it is most likely to have a direct answer and minimize
-    // iteration.
-    for (double delta = 1.0; delta < 50.0; delta += 1.0) {
-      // Termination condition rounding instead of minimizing delta to avoid
-      // case where requested chroma is 16.51, and the closest chroma is 16.49.
-      // Error is minimized, but when rounded and displayed, requested chroma
-      // is 17, key color's chroma is 16.
-      if (Math.round(chroma) == Math.round(smallestDeltaHct.getChroma())) {
-        return smallestDeltaHct;
-      }
-
-      final Hct hctAdd = Hct.from(hue, chroma, startTone + delta);
-      final double hctAddDelta = Math.abs(hctAdd.getChroma() - chroma);
-      if (hctAddDelta < smallestDelta) {
-        smallestDelta = hctAddDelta;
-        smallestDeltaHct = hctAdd;
-      }
-
-      final Hct hctSubtract = Hct.from(hue, chroma, startTone - delta);
-      final double hctSubtractDelta = Math.abs(hctSubtract.getChroma() - chroma);
-      if (hctSubtractDelta < smallestDelta) {
-        smallestDelta = hctSubtractDelta;
-        smallestDeltaHct = hctSubtract;
-      }
-    }
-
-    return smallestDeltaHct;
-  }
-
   /**
    * Create an ARGB color with HCT hue and chroma of this Tones instance, and the provided HCT tone.
    *
@@ -141,4 +104,75 @@ public final class TonalPalette {
   public Hct getKeyColor() {
     return this.keyColor;
   }
+
+  /** Key color is a color that represents the hue and chroma of a tonal palette. */
+  private static final class KeyColor {
+    private final double hue;
+    private final double requestedChroma;
+
+    // Cache that maps tone to max chroma to avoid duplicated HCT calculation.
+    private final Map<Integer, Double> chromaCache = new HashMap<>();
+    private static final double MAX_CHROMA_VALUE = 200.0;
+
+    /** Key color is a color that represents the hue and chroma of a tonal palette */
+    public KeyColor(double hue, double requestedChroma) {
+      this.hue = hue;
+      this.requestedChroma = requestedChroma;
+    }
+
+    /**
+     * Creates a key color from a [hue] and a [chroma]. The key color is the first tone, starting
+     * from T50, matching the given hue and chroma.
+     *
+     * @return Key color [Hct]
+     */
+    public Hct create() {
+      // Pivot around T50 because T50 has the most chroma available, on
+      // average. Thus it is most likely to have a direct answer.
+      final int pivotTone = 50;
+      final int toneStepSize = 1;
+      // Epsilon to accept values slightly higher than the requested chroma.
+      final double epsilon = 0.01;
+
+      // Binary search to find the tone that can provide a chroma that is closest
+      // to the requested chroma.
+      int lowerTone = 0;
+      int upperTone = 100;
+      while (lowerTone < upperTone) {
+        final int midTone = (lowerTone + upperTone) / 2;
+        boolean isAscending = maxChroma(midTone) < maxChroma(midTone + toneStepSize);
+        boolean sufficientChroma = maxChroma(midTone) >= requestedChroma - epsilon;
+
+        if (sufficientChroma) {
+          // Either range [lowerTone, midTone] or [midTone, upperTone] has
+          // the answer, so search in the range that is closer the pivot tone.
+          if (Math.abs(lowerTone - pivotTone) < Math.abs(upperTone - pivotTone)) {
+            upperTone = midTone;
+          } else {
+            if (lowerTone == midTone) {
+              return Hct.from(this.hue, this.requestedChroma, lowerTone);
+            }
+            lowerTone = midTone;
+          }
+        } else {
+          // As there is no sufficient chroma in the midTone, follow the direction to the chroma
+          // peak.
+          if (isAscending) {
+            lowerTone = midTone + toneStepSize;
+          } else {
+            // Keep midTone for potential chroma peak.
+            upperTone = midTone;
+          }
+        }
+      }
+
+      return Hct.from(this.hue, this.requestedChroma, lowerTone);
+    }
+
+    // Find the maximum chroma for a given tone
+    private double maxChroma(int tone) {
+      return chromaCache.computeIfAbsent(
+          tone, (Integer key) -> Hct.from(hue, MAX_CHROMA_VALUE, key).getChroma());
+    }
+  }
 }
```

