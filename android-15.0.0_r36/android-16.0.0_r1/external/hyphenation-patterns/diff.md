```diff
diff --git a/OWNERS b/OWNERS
index 5ba93af..4784091 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,3 +4,4 @@ goldmanj@google.com
 # Backup owners
 nona@google.com
 siyamed@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/patterns.mk b/patterns.mk
index a8a2e13..5cfd3ef 100644
--- a/patterns.mk
+++ b/patterns.mk
@@ -16,61 +16,4 @@
 # PRODUCT_COPY_FILES to install the pattern files, so that the NOTICE file can
 # get installed too.
 
-pattern_locales := \
-    af \
-    as \
-    be \
-    bg \
-    bn \
-    cs \
-    cu \
-    cy \
-    da \
-    de-1901 \
-    de-1996 \
-    de-ch-1901 \
-    el \
-    en-gb \
-    en-us \
-    es \
-    et \
-    eu \
-    fr \
-    ga \
-    gl \
-    gu \
-    hi \
-    hr \
-    hu \
-    hy \
-    it \
-    ka \
-    kn \
-    la \
-    lt \
-    lv \
-    ml \
-    mn-cyrl \
-    mr \
-    mul-ethi \
-    nb \
-    nl \
-    nn \
-    or \
-    pa \
-    pl \
-    pt \
-    ru \
-    sk \
-    sl \
-    sq \
-    sv \
-    ta \
-    te \
-    tk \
-    uk \
-    und-ethi
-
-PRODUCT_PACKAGES := $(addprefix hyph-,$(pattern_locales))
-
-pattern_locales :=
+PRODUCT_PACKAGES := hyph-data
```

