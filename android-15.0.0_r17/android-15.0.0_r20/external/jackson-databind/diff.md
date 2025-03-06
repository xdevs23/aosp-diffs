```diff
diff --git a/src/main/java/com/fasterxml/jackson/databind/JsonNode.java b/src/main/java/com/fasterxml/jackson/databind/JsonNode.java
index 0c94ca294..924b38bb4 100644
--- a/src/main/java/com/fasterxml/jackson/databind/JsonNode.java
+++ b/src/main/java/com/fasterxml/jackson/databind/JsonNode.java
@@ -405,6 +405,29 @@ public abstract class JsonNode
      */
     public boolean canConvertToLong() { return false; }
 
+    /**
+     * Method that can be used to check whether contained value
+     * is numeric (returns true for {@link #isNumber()}) and
+     * can be losslessly converted to integral number (specifically,
+     * {@link BigInteger} but potentially others, see
+     * {@link #canConvertToInt} and {@link #canConvertToInt}).
+     * Latter part allows floating-point numbers
+     * (for which {@link #isFloatingPointNumber()} returns {@code true})
+     * that do not have fractional part.
+     * Note that "not-a-number" values of {@code double} and {@code float}
+     * will return {@code false} as they can not be converted to matching
+     * integral representations.
+     *
+     * @return True if the value is an actual number with no fractional
+     *    part; false for non-numeric types, NaN representations of floating-point
+     *    numbers, and floating-point numbers with fractional part.
+     *
+     * @since 2.12
+     */
+    public boolean canConvertToExactIntegral() {
+        return isIntegralNumber();
+    }
+
     /*
     /**********************************************************
     /* Public API, straight value access
@@ -935,6 +958,21 @@ public abstract class JsonNode
         return ClassUtil.emptyIterator();
     }
 
+    /**
+     * Accessor that will return properties of {@code ObjectNode}
+     * similar to how {@link Map#entrySet()} works; 
+     * for other node types will return empty {@link java.util.Set}.
+     *
+     * @return Set of properties, if this node is an {@code ObjectNode}
+     * ({@link JsonNode#isObject()} returns {@code true}); empty
+     * {@link java.util.Set} otherwise.
+     *
+     * @since 2.15
+     */
+    public Set<Map.Entry<String, JsonNode>> properties() {
+        return Collections.emptySet();
+    }
+
     /*
     /**********************************************************
     /* Public API, find methods
```

