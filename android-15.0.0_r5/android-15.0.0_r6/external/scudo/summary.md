```
cecaa1a: [scudo] Remove unused field in BatchGroup (#109322) (ChiaHungDuan <chiahungduan@google.com>)
e5299e1: Revert "[scudo] Update secondary cache time-based release logic (#107507... (Thurston Dang <thurston@google.com>)
b3f6867: [scudo] Update secondary cache time-based release logic (#107507) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
80b681e: [scudo] Add thread-safety annotation on getMemoryGroupFragmentationIn… (... (ChiaHungDuan <chiahungduan@google.com>)
1fa6e19: Reapply "[scudo] Fix the logic of MaxAllowedFragmentedPages" (#108130) (... (ChiaHungDuan <chiahungduan@google.com>)
8da432c: Revert "[scudo] Fix the logic of MaxAllowedFragmentedPages" (#108130) (ChiaHungDuan <chiahungduan@google.com>)
4632745: [scudo] Fix the logic of MaxAllowedFragmentedPages (#107927) (ChiaHungDuan <chiahungduan@google.com>)
7befc97: Add static_assert verifing page size is constexpr. (Christopher Ferris <cferris@google.com>)
9d05ab3: [scudo] Add fragmentation info for each memory group (#107475) (ChiaHungDuan <chiahungduan@google.com>)
8092cb4: [scudo] Add a method to use a hard-coded page size (#106646) (Christopher Ferris <cferris1000@users.noreply.gi...)
23e2b3c: [scudo] Use variable instead of recomputing. (#106647) (Christopher Ferris <cferris1000@users.noreply.gi...)
d22a02a: [scudo] Update secondary cache released pages bound. (#106466) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
07740f2: [scudo] Make comment compatible with gcc (#106137) (Caslyn Tonelli <6718161+Caslyn@users.noreply.git...)
6dc0426: [scudo] Fix expectation in ScudoTimingTest.VerifyMax (#106062) (Fabio D'Urso <fdurso@google.com>)
79fcb0c: [scudo] Add partial chunk heuristic to retrieval algorithm. (#105009) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
5389414: Revert "[scudo] Add partial chunk heuristic to retrieval algorithm." (#1... (ChiaHungDuan <chiahungduan@google.com>)
a9ea2a9: [scudo] Add partial chunk heuristic to retrieval algorithm. (#104807) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
cc715ee: Revert "[scudo] Separated committed and decommitted entries." (#104045) (ChiaHungDuan <chiahungduan@google.com>)
4a57314: [compiler-rt] Define `__STDC_FORMAT_MACROS` to ensure `PRId64` is availa... (Mosè Giordano <mose@gnu.org>)
9e57ee6: [scudo] Support linking with index in IntrusiveList (#101262) (ChiaHungDuan <chiahungduan@google.com>)
35d3333: [scudo] Separated committed and decommitted entries. (#101409) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
6010058: [scudo] Added test fixture for cache tests. (#102230) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
0cb542e: [scudo] Die when store is called on MapAllocatorNoCache objects. (#10240... (Christopher Ferris <cferris1000@users.noreply.gi...)
7701301: [scudo] Avoid accessing inaccessible pages in unmap() in secondary (#102... (ChiaHungDuan <chiahungduan@google.com>)
83d9c2f: [scudo][NFC] Add a default unmap() to unmap all pages (#102234) (ChiaHungDuan <chiahungduan@google.com>)
b92d82f: [scudo] Refactor store() and retrieve(). (#102024) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
d07ceeb: [scudo] Remove benchmarks file. (#102077) (Christopher Ferris <cferris1000@users.noreply.gi...)
9dfc8a8: Share warning cflags between main build and tests. (Christopher Ferris <cferris@google.com>)
8fa98c9: Format Android.bp. (Christopher Ferris <cferris@google.com>)
5e1d960: Fix the SCUDO_DEBUG definition. (Christopher Ferris <cferris@google.com>)
5cdf989: Revert "[scudo] Separated committed and decommitted entries." (#101375) (ChiaHungDuan <chiahungduan@google.com>)
4af939d: [scudo] Separated committed and decommitted entries. (#100818) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
2ae2c34: Revert^2 "[NFCI][scudo] Remove unused variable 'MaxCount' (#100201)" (Satish Yalla <satishy@google.com>)
023abc6: Revert "[NFCI][scudo] Remove unused variable 'MaxCount' (#100201)" (PODISHETTY KUMAR <podishettyk@google.com>)
81cfb34: [NFCI][scudo] Remove unused variable 'MaxCount' (#100201) (Thurston Dang <thurston@google.com>)
8a6eaa2: Revert "[scudo] Added LRU eviction policy to secondary cache. (#99409)" (Priyanka Advani (xWF) <padvani@google.com>)
0fcba39: [scudo] Added LRU eviction policy to secondary cache. (#99409) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
57327b3: [scudo] Add static vector functionality. (#98986) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
2d10479: [scudo] Add a maximum value into the timer. (#96989) (Christopher Ferris <cferris1000@users.noreply.gi...)
d911103: [scudo][fuchsia] Give dispatched VMOs a (temporary) name (#97578) (Fabio D'Urso <fdurso@google.com>)
8b402e1: [scudo] Change CompactPtrT and CompactPtrScale to optional (#90797) (ChiaHungDuan <chiahungduan@google.com>)
c2e7623: [scudo] Minor refactoring of secondary cache test (#95995) (ChiaHungDuan <chiahungduan@google.com>)
e85e558: [scudo] Add TEST_SKIP macro to skip the current test (#96192) (Fabio D'Urso <fdurso@google.com>)
be4cad4: Reland "[scudo] Apply filling when realloc shrinks and re-grows a block ... (Fabio D'Urso <fdurso@google.com>)
7ea77a5: [scudo] Test secondary cache options only if enabled (#95872) (Caslyn Tonelli <6718161+Caslyn@users.noreply.git...)
e480499: [scudo] Update error handling for seondary cache entry count (#95595) (Joshua Baehring <98630690+JoshuaMBa@users.norepl...)
```

