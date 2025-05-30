```
da9eeb7: AddLoadHookWithPriority function (Spandan Das <spandandas@google.com>)
cc1c206: Support ModuleProxy in a few blueprint singleton methods. (Yu Liu <yudiliu@google.com>)
1d99261: Add support for selects on string lists (Cole Faust <colefaust@google.com>)
97bbbf6: Add VisitAllModuleVariantProxies to blueprint. (Yu Liu <yudiliu@google.com>)
778c835: Do not read moduleInfo map in Context.ModuleErrorf (Jihoon Kang <jihoonkang@google.com>)
60f7014: Support ModuleProxy in OtherModuleType, OtherModuleErrorf. Also removed ... (Yu Liu <yudiliu@google.com>)
ef71ba9: Change GetModuleFromPathDep to use ModuleProxy. (Yu Liu <yudiliu@google.com>)
9fa6ea5: Replace FinalModule with IsFinalModule. (Yu Liu <yudiliu@google.com>)
ce87cd8: Sort the subninja list of the incremental modules. (Yu Liu <yudiliu@google.com>)
35714dc: Add VisitAllModuleProxies and VisitAllModuleVariantProxies. (Yu Liu <yudiliu@google.com>)
2743fea: Support repacking lists of structs (Cole Faust <colefaust@google.com>)
5c855ad: bpfmt: Extend visibility to cargo_embargo (Pierre-Clément Tosi <ptosi@google.com>)
cd57e03: Add NeverFar() option for transition mutators (Cole Faust <colefaust@google.com>)
203ef32: Introduce the bp api `OtherModuleIsAutoGenerated` (Jihoon Kang <jihoonkang@google.com>)
946017e: Dedup addDependency and addVariationDependency (Cole Faust <colefaust@google.com>)
7905d7e: Remove the 1-variant fallback (Cole Faust <colefaust@google.com>)
9dfaaec: Use maps.Clone() (Cole Faust <colefaust@google.com>)
fd04a91: Revert "Add a UniqueList that can store a slice in the unique package" (Colin Cross <ccross@android.com>)
34d9407: Revert "Use unique.Handle for DepSets" (Colin Cross <ccross@android.com>)
e748cf8: Remove the 1-variant fallback in vendor/ (Cole Faust <colefaust@google.com>)
26923eb: Fix slices.Grow() calls (Cole Faust <colefaust@google.com>)
a3c144d: Partially remove the 1-variant fallback (Cole Faust <colefaust@google.com>)
602d141: Don't print errors in RunBlueprint (Colin Cross <ccross@android.com>)
5686ac4: Move some gob helpers to a new package. (Yu Liu <yudiliu@google.com>)
5753849: Split bpmodify command into a library (Colin Cross <ccross@android.com>)
289f3e3: Use unique.Handle for DepSets (Colin Cross <ccross@android.com>)
0808295: Add a UniqueList that can store a slice in the unique package (Colin Cross <ccross@android.com>)
c706bf2: Move DepSet to blueprint (Colin Cross <ccross@android.com>)
2b45552: Introduce CreateModuleInDirectory(...) (Jihoon Kang <jihoonkang@google.com>)
2066b02: Add error methods to transition mutator contexts (Cole Faust <colefaust@google.com>)
3eef82c: Support Int64 in fieldToExpr (mrziwang <mrziwang@google.com>)
97aa334: Don't wrote empty module based ninja files. (Yu Liu <yudiliu@google.com>)
d469c91: More minor optimizations to updateDependencies (Colin Cross <ccross@android.com>)
c49fbf2: Optimize out some calls to c.updateDependencies() (Colin Cross <ccross@android.com>)
bc7accb: Remove c.modulesSorted (Colin Cross <ccross@android.com>)
705cd21: Remove distinction between parallel and non-parallel mutators (Colin Cross <ccross@android.com>)
5ff6ab7: Add test for disallowing mutator functions (Colin Cross <ccross@android.com>)
62f80fa: Add comment describing directDeps vs newDirectDeps (Colin Cross <ccross@android.com>)
e61e26a: Run blueprint module implementations on all variants (Cole Faust <colefaust@google.com>)
d5f678a: Coalesce compatible mutators (Colin Cross <ccross@android.com>)
da7cb34: Update gotestmain.go for go 1.23 (Colin Cross <ccross@android.com>)
51aa659: Update finished mutator checks (Colin Cross <ccross@android.com>)
3b98058: Update directDeps immediately when adding new dependencies (Colin Cross <ccross@android.com>)
b1bb3f6: Annotate mutators that use methods that prevent mutator coalescing (Colin Cross <ccross@android.com>)
3b7bb5d: Minor optimizations when running mutators (Colin Cross <ccross@android.com>)
9a4e015: Remove unused TopDownMutatorContext methods (Colin Cross <ccross@android.com>)
3e3af9d: Make blueprint mutators parallel (Colin Cross <ccross@android.com>)
fa2ed53: Change the way to support custom gob encoder and decoder. (Yu Liu <yudiliu@google.com>)
079d1b9: Add ModuleProxy that should be used when visiting deps. (Yu Liu <yudiliu@google.com>)
32f934e: Remove the 1-variant fallback from reverse dependencies (Cole Faust <colefaust@google.com>)
b62b6ec: Add utilities to repack a property struct to a bp file (Cole Faust <colefaust@google.com>)
6659e20: Revert "Add tests for new reverse dependency behaviors" (Cole Faust <colefaust@google.com>)
20758c3: Revert "Remove the 1-variant fallback from reverse dependencies" (Pechetty Sravani (xWF) <pechetty@google.com>)
ddf9bb8: Add tests for new reverse dependency behaviors (Cole Faust <colefaust@google.com>)
e8090f2: Remove the 1-variant fallback from reverse dependencies (Cole Faust <colefaust@google.com>)
81f60b4: Add AddReverseVariationDependency (Cole Faust <colefaust@google.com>)
9e0ece8: Move HasMutatorFinished to EarlyModuleContext (Cole Faust <colefaust@google.com>)
511ea71: Remove the ability to configure the provider check (Cole Faust <colefaust@google.com>)
fe62964: Remove aliases (Cole Faust <colefaust@google.com>)
87fe5cc: Remove CreateVariations and related functions (Cole Faust <colefaust@google.com>)
```

