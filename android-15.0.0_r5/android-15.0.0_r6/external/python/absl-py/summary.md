```
9b1225c: Add Soong build files for absl-py (Junyu Lai <junyulai@google.com>)
eac3796: Update MODULE.bazel (HONG Yifan <elsk@google.com>)
8abdd60: Preparing the release of absl-py 2.1.0. (Yilei Yang <yileiyang@google.com>)
1e13a8c: Fix absl.testing.xml_reporter for Python 3.12.1 when all tests are skipp... (Yilei Yang <yileiyang@google.com>)
78af725: Do not fail on Python 3.12 when there are tests but all skipped. (Yilei Yang <yileiyang@google.com>)
2af184b: absl.flags._argument_parser: Mark EnumClassSerializer as generic. (Rebecca Chen <rechen@google.com>)
6929bf0: Add `serialize` method to `FlagHolder`. (Jesse Farebrother <jfarebro@google.com>)
64d3b6a: Fix #199: Correctly check `_inherited_absl_flags` by comparing to `None`... (Yilei Yang <yileiyang@google.com>)
0ff1e24: Add an assertDataclassEqual method that provides better errors when it f... (Abseil Team <absl-team@google.com>)
9499935: Add flags.override_value. (Abseil Team <absl-team@google.com>)
407b2d5: Unwind flag modifications on validation failure. (Abseil Team <absl-team@google.com>)
37dad4d: Preparing the release of absl-py 2.0.0. (Yilei Yang <yileiyang@google.com>)
1edf2ab: `absltest`: do not fail tests on Python 3.12+ when no tests ran and: - E... (Yilei Yang <yileiyang@google.com>)
f9281cb: Clean up unit tests that no longer apply for Python 3.12 compatibility. (Yilei Yang <yileiyang@google.com>)
7092100: Explicitly fail when a Mapping or Set object is passed to assertSequence... (Yilei Yang <yileiyang@google.com>)
e5f96d9: Add a test case for parameterized async tests using IsolatedAsyncioTestC... (Yilei Yang <yileiyang@google.com>)
8e3ad2e: Align `logging.exception` signature with that or Python's builtin by add... (Abseil Team <absl-team@google.com>)
9764133: Internal change. (Abseil Team <absl-team@google.com>)
9e54320: Update parameterized.CoopTestCase to work with python3 metaclasses. (Stephen Thorne <sthorne@google.com>)
cadd68c: Correct argument name `user_msg` of `fail` in TestCase in absltest. The ... (Abseil Team <absl-team@google.com>)
552ebe9: Always import typing since we have dropped Python 2 support. (Abseil Team <absl-team@google.com>)
1a6806d: Small typo fix in the module docsting of parameterized.py (Abseil Team <absl-team@google.com>)
38b837f: Add rules_python loads to absl. (Richard Levasseur <rlevasseur@google.com>)
882c967: Annotate absltest.TestCase.fail to help pytype's analysis. (Abseil Team <absl-team@google.com>)
492b944: Internal change (Sergei Lebedev <slebedev@google.com>)
1a27b3a: Marked absl.flags.FlagValues as having dynamic attributes (Sergei Lebedev <slebedev@google.com>)
5511454: Improve a few type annotations in absl.flags: (Yilei Yang <yileiyang@google.com>)
ab4339c: Merge absltest_py3_test to absltest_test now that we don't support Pytho... (Yilei Yang <yileiyang@google.com>)
2a7003e: Inline flag annotations. (Abseil Team <absl-team@google.com>)
f0e2b78: Always import faulthandler since we have dropped Python 2 support. (Yilei Yang <yileiyang@google.com>)
ba6b5ad: Export the non harmful `g-import-not-at-top` pylint pragmas. (Yilei Yang <yileiyang@google.com>)
ab8d6c4: Adjust blank lines. (Yilei Yang <yileiyang@google.com>)
2e7fd78: Move the GitHub workflow and ci files to their correct location. (Yilei Yang <yileiyang@google.com>)
4282e20: Create GitHub CI configurations. (Yilei Yang <yileiyang@google.com>)
e1a4073: Delete these setup/teardown methods, they are not necessary and also wro... (Yilei Yang <yileiyang@google.com>)
7dc9527: Prevent setting str type for enum_values. (Abseil Team <absl-team@google.com>)
c67f2ea: Expose absl.logging flags as FlagHolders. (Abseil Team <absl-team@google.com>)
7e34be5: Add type stub file for absl.logging. (Abseil Team <absl-team@google.com>)
28bf989: Fix or acknowledge unsoundness caught with pytype --strict-none-binding. (Abseil Team <absl-team@google.com>)
c7e2c67: Add type stubs for _helpers module. (Abseil Team <absl-team@google.com>)
13443af: Specify Flag.default types. (Abseil Team <absl-team@google.com>)
37d9784: Provide `fnctl.ioctl` arg as bytes. (Abseil Team <absl-team@google.com>)
b3b4d90: Fix register_flag_by_module_id annotation. (Abseil Team <absl-team@google.com>)
c1e1b75: Use validator interface in type annotation. (Abseil Team <absl-team@google.com>)
bfbd9bc: Inline flag annotation type comments. (Abseil Team <absl-team@google.com>)
9c2c1b6: Explicitly declare the package(). (Yilei Yang <yileiyang@google.com>)
b12daa7: Remove these unused default argument values. (Yilei Yang <yileiyang@google.com>)
65c81c2: Expose Flag._serialize to type checker (Karol M. Langner <langner@google.com>)
813f251: Enforce alphabetical sorting order by test name in the test.xml output. (Abseil Team <absl-team@google.com>)
d97533c: Break up the regex matches in xml_reporter_test, allowing test suites wi... (Abseil Team <absl-team@google.com>)
6d560aa: Merge changes from https://github.com/abseil/abseil-py/pull/216. (Yilei Yang <yileiyang@google.com>)
2d59b42: Use better assert methods. (Yilei "Dolee" Yang <hi@mangoumbrella.com>)
366775a: Update deprecated aliases for Python 3.12 compatibility. (Karthikeyan Singaravelan <tir.karthi@gmail.com>)
3b13ba5: Adjust `AbslTest.assertSameStructure()` to use the test case's registere... (Abseil Team <absl-team@google.com>)
52d8215: Delegate enter_context to enterContext and enterClassContext when avaiab... (Abseil Team <absl-team@google.com>)
786a9f2: Replace `.parsed` with `.present` in docstring for `flagsaver.as_parsed`... (Abseil Team <absl-team@google.com>)
6cafb1d: Addition of type annotations and pytype supressions to allow the unittes... (Stephen Thorne <sthorne@google.com>)
f199f3a: Update license rules. (Yilei Yang <yileiyang@google.com>)
35b643d: update license rules (Abseil Team <absl-team@google.com>)
bf38679: Merge #214. (Yilei Yang <yileiyang@google.com>)
7739277: Fix indentation. (Yilei "Dolee" Yang <yileiyang@google.com>)
5c3b2da: Make the bad stream test more clear. (Yilei "Dolee" Yang <yileiyang@google.com>)
61cc761: Check that stream is not None instead of catching AttributeError. (Jan Wedekind <jan.wedekind@roke.co.uk>)
08a4a39: Add assertion that flush was called (Jan Wedekind <jan.wedekind@roke.co.uk>)
92f1e89: Handle case where stream is None when flushing it. (Jan Wedekind <jan.wedekind@roke.co.uk>)
e2d6481: Fix the readthedocs dependency requirements. (Yilei Yang <yileiyang@google.com>)
61b1ba4: Fix a merge error in CHANGELOG.md (Yilei Yang <yileiyang@google.com>)
75e4f78: Remove unneeded variable. (Abseil Team <absl-team@google.com>)
db7dc90: Use .dev0 as development versions before we make an actual release. (Yilei Yang <yileiyang@google.com>)
5fd2001: Rollback the logging change. (Wilsin Gosti <wilsin@google.com>)
9e051b4: Drop Python 3.6 support in absl-py. (Yilei Yang <yileiyang@google.com>)
3707441: Allow forwarding kwargs to logging.log from more log utility methods. (Abseil Team <absl-team@google.com>)
```

