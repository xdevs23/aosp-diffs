```diff
diff --git a/src/com/android/quicksearchbox/ui/DefaultSuggestionViewFactory.kt b/src/com/android/quicksearchbox/ui/DefaultSuggestionViewFactory.kt
index 5559f13..6273b7f 100644
--- a/src/com/android/quicksearchbox/ui/DefaultSuggestionViewFactory.kt
+++ b/src/com/android/quicksearchbox/ui/DefaultSuggestionViewFactory.kt
@@ -30,7 +30,7 @@ class DefaultSuggestionViewFactory(context: Context?) : SuggestionViewFactory {
   private var mViewTypes: HashSet<String>? = null
 
   /** Must only be called from the constructor */
-  protected fun addFactory(factory: SuggestionViewFactory?) {
+  protected fun addFactory(factory: SuggestionViewFactory) {
     mFactories.addFirst(factory)
   }
 
```

