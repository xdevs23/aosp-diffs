```diff
diff --git a/tests/libufdt_verify/ufdt_test_overlay.cpp b/tests/libufdt_verify/ufdt_test_overlay.cpp
index 603228d..6b43335 100644
--- a/tests/libufdt_verify/ufdt_test_overlay.cpp
+++ b/tests/libufdt_verify/ufdt_test_overlay.cpp
@@ -66,6 +66,37 @@ static bool compare_child_nodes(struct ufdt_node *node_a, struct ufdt_node *node
     return result;
 }
 
+/**
+ * ufdt_node_get_parent - Retrieves the parent node of a specified node in the ufdt tree
+ * @tree: Pointer to the ufdt tree structure (used for traversing the device tree)
+ * @node: Target node whose parent needs to be found (must not be NULL)
+ * @parent: Output parameter to store the address of the found parent node pointer
+ *
+ * Return:
+ *   - true:  Successfully found the parent node; @parent points to a valid node
+ *   - false: Parent not found (e.g., node is root or invalid input); @parent is set to NULL
+ *
+ * Description:
+ *   This function traverses the device tree to locate the direct parent of the given node.
+ *
+ */
+static bool ufdt_node_get_parent(struct ufdt* tree, struct ufdt_node* node,
+                                 struct ufdt_node** parent) {
+    struct ufdt_node **it;
+    for_each_node(it, tree->root) {
+        struct ufdt_node* overlay_node = ufdt_node_get_node_by_path(*it, "__overlay__");
+        if (overlay_node == NULL) {
+            continue;
+        }
+        if (ufdt_node_get_phandle(overlay_node) == ufdt_node_get_phandle(node))
+        {
+            *parent = *it;
+            return true;
+        }
+    }
+    return false;
+}
+
 /*
  * Method to compare two nodes with tag FDT_PROP. Also accounts for the cases where
  * the property type is phandle.
@@ -108,11 +139,32 @@ static bool ufdt_compare_property(struct ufdt_node* node_final, struct ufdt_node
                 /*
                  * verify that the target nodes are valid and point to the same node.
                  */
-                if ((target_node_a == NULL) || (target_node_b == NULL) ||
-                    strcmp(ufdt_node_name(target_node_a),
-                           ufdt_node_name(target_node_b)) != 0) {
+                if ((target_node_a == NULL) || (target_node_b == NULL)) {
                     return false;
                 }
+                if (strcmp(ufdt_node_name(target_node_b), "__overlay__") == 0)
+                {
+                    struct ufdt_node *frag_node = NULL;
+                    struct ufdt_node *cmp_node = NULL;
+
+                    if (ufdt_node_get_parent(tree_overlay, target_node_b, &frag_node) == false) {
+                        return false;
+                    }
+
+                    ufdt_overlay_get_target(tree_final, frag_node, &cmp_node);
+                    if (cmp_node == NULL) {
+                        return false;
+                    }
+
+                    if (ufdt_node_get_phandle(cmp_node) != ufdt_node_get_phandle(target_node_a)) {
+                        return false;
+                    }
+
+                } else {
+                    if (strcmp(ufdt_node_name(target_node_a), ufdt_node_name(target_node_b)) != 0) {
+                        return false;
+                    }
+                }
             }
         }
     }
```

