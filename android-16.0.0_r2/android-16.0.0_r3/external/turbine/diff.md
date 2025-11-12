```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 7284efb..dbb4168 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -61,7 +61,7 @@ jobs:
           cache: 'maven'
       - name: 'Set up JDK ${{ matrix.java }}'
         if: ${{ matrix.java != 'EA' }}
-        uses: actions/setup-java@v2
+        uses: actions/setup-java@v3.4.1
         with:
           java-version: ${{ matrix.java }}
           distribution: 'zulu'
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
index f5a01d7..ce11a83 100644
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -17,7 +17,7 @@ jobs:
         uses: actions/checkout@v2.4.0
 
       - name: Set up JDK
-        uses: actions/setup-java@v2.5.0
+        uses: actions/setup-java@v3.4.1
         with:
           java-version: 17
           distribution: 'zulu'
diff --git a/METADATA b/METADATA
index e354d0f..469db9e 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 1
-    day: 18
+    month: 5
+    day: 7
   }
   homepage: "https://github.com/google/turbine"
   identifier {
     type: "Git"
     value: "https://github.com/google/turbine"
-    version: "5d422e5bc6ff4928223ea049856d27590661db04"
+    version: "7d09f865692da20e13a79108700f97d8570f4a96"
   }
 }
diff --git a/java/com/google/turbine/binder/Binder.java b/java/com/google/turbine/binder/Binder.java
index ee2a674..1784129 100644
--- a/java/com/google/turbine/binder/Binder.java
+++ b/java/com/google/turbine/binder/Binder.java
@@ -181,7 +181,10 @@ public final class Binder {
             log);
     tenv =
         disambiguateTypeAnnotations(
-            syms, tenv, CompoundEnv.<ClassSymbol, TypeBoundClass>of(classPathEnv).append(tenv));
+            syms,
+            tenv,
+            CompoundEnv.<ClassSymbol, TypeBoundClass>of(classPathEnv).append(tenv),
+            log);
     tenv =
         canonicalizeTypes(
             syms, tenv, CompoundEnv.<ClassSymbol, TypeBoundClass>of(classPathEnv).append(tenv));
@@ -453,7 +456,7 @@ public final class Binder {
         if (((Type.ClassTy) field.type()).sym().equals(ClassSymbol.STRING)) {
           break;
         }
-        // fall through
+      // fall through
       default:
         return false;
     }
@@ -467,11 +470,12 @@ public final class Binder {
   private static Env<ClassSymbol, SourceTypeBoundClass> disambiguateTypeAnnotations(
       ImmutableSet<ClassSymbol> syms,
       Env<ClassSymbol, SourceTypeBoundClass> stenv,
-      Env<ClassSymbol, TypeBoundClass> tenv) {
+      Env<ClassSymbol, TypeBoundClass> tenv,
+      TurbineLog log) {
     SimpleEnv.Builder<ClassSymbol, SourceTypeBoundClass> builder = SimpleEnv.builder();
     for (ClassSymbol sym : syms) {
       SourceTypeBoundClass base = stenv.getNonNull(sym);
-      builder.put(sym, DisambiguateTypeAnnotations.bind(base, tenv));
+      builder.put(sym, DisambiguateTypeAnnotations.bind(base, tenv, log));
     }
     return builder.build();
   }
diff --git a/java/com/google/turbine/binder/ConstBinder.java b/java/com/google/turbine/binder/ConstBinder.java
index e75da34..2bd676d 100644
--- a/java/com/google/turbine/binder/ConstBinder.java
+++ b/java/com/google/turbine/binder/ConstBinder.java
@@ -298,7 +298,7 @@ public class ConstBinder {
         if (((Type.ClassTy) type).sym().equals(ClassSymbol.STRING)) {
           break;
         }
-        // falls through
+      // falls through
       default:
         return null;
     }
diff --git a/java/com/google/turbine/binder/DisambiguateTypeAnnotations.java b/java/com/google/turbine/binder/DisambiguateTypeAnnotations.java
index 65c1021..307c8db 100644
--- a/java/com/google/turbine/binder/DisambiguateTypeAnnotations.java
+++ b/java/com/google/turbine/binder/DisambiguateTypeAnnotations.java
@@ -33,8 +33,8 @@ import com.google.turbine.binder.bound.TypeBoundClass.ParamInfo;
 import com.google.turbine.binder.bound.TypeBoundClass.RecordComponentInfo;
 import com.google.turbine.binder.env.Env;
 import com.google.turbine.binder.sym.ClassSymbol;
-import com.google.turbine.diag.TurbineError;
 import com.google.turbine.diag.TurbineError.ErrorKind;
+import com.google.turbine.diag.TurbineLog;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.TurbineElementType;
 import com.google.turbine.type.AnnoInfo;
@@ -67,17 +67,20 @@ import java.util.Map;
  * and move it to the appropriate location.
  */
 public final class DisambiguateTypeAnnotations {
+
   public static SourceTypeBoundClass bind(
-      SourceTypeBoundClass base, Env<ClassSymbol, TypeBoundClass> env) {
+      SourceTypeBoundClass base, Env<ClassSymbol, TypeBoundClass> env, TurbineLog log) {
+
+    DisambiguateTypeAnnotations binder = new DisambiguateTypeAnnotations(env, log);
     return new SourceTypeBoundClass(
         base.interfaceTypes(),
         base.permits(),
         base.superClassType(),
         base.typeParameterTypes(),
         base.access(),
-        bindComponents(env, base.components(), TurbineElementType.RECORD_COMPONENT),
-        bindMethods(env, base.methods()),
-        bindFields(env, base.fields()),
+        binder.bindComponents(base.components(), TurbineElementType.RECORD_COMPONENT),
+        binder.bindMethods(base.methods()),
+        binder.bindFields(base.fields()),
         base.owner(),
         base.kind(),
         base.children(),
@@ -86,25 +89,31 @@ public final class DisambiguateTypeAnnotations {
         base.scope(),
         base.memberImports(),
         base.annotationMetadata(),
-        groupRepeated(env, base.annotations()),
+        binder.groupRepeated(base.annotations()),
         base.source(),
         base.decl());
   }
 
-  private static ImmutableList<MethodInfo> bindMethods(
-      Env<ClassSymbol, TypeBoundClass> env, ImmutableList<MethodInfo> fields) {
+  private final Env<ClassSymbol, TypeBoundClass> env;
+  private final TurbineLog log;
+
+  private DisambiguateTypeAnnotations(Env<ClassSymbol, TypeBoundClass> env, TurbineLog log) {
+    this.env = env;
+    this.log = log;
+  }
+
+  private ImmutableList<MethodInfo> bindMethods(ImmutableList<MethodInfo> fields) {
     ImmutableList.Builder<MethodInfo> result = ImmutableList.builder();
     for (MethodInfo field : fields) {
-      result.add(bindMethod(env, field));
+      result.add(bindMethod(field));
     }
     return result.build();
   }
 
-  private static MethodInfo bindMethod(Env<ClassSymbol, TypeBoundClass> env, MethodInfo base) {
+  private MethodInfo bindMethod(MethodInfo base) {
     ImmutableList.Builder<AnnoInfo> declarationAnnotations = ImmutableList.builder();
     Type returnType =
         disambiguate(
-            env,
             base.name().equals("<init>")
                 ? TurbineElementType.CONSTRUCTOR
                 : TurbineElementType.METHOD,
@@ -115,51 +124,39 @@ public final class DisambiguateTypeAnnotations {
         base.sym(),
         base.tyParams(),
         returnType,
-        bindParameters(env, base.parameters(), TurbineElementType.PARAMETER),
+        bindParameters(base.parameters(), TurbineElementType.PARAMETER),
         base.exceptions(),
         base.access(),
         base.defaultValue(),
         base.decl(),
         declarationAnnotations.build(),
-        base.receiver() != null
-            ? bindParam(env, base.receiver(), TurbineElementType.PARAMETER)
-            : null);
+        base.receiver() != null ? bindParam(base.receiver(), TurbineElementType.PARAMETER) : null);
   }
 
-  private static ImmutableList<ParamInfo> bindParameters(
-      Env<ClassSymbol, TypeBoundClass> env,
-      ImmutableList<ParamInfo> params,
-      TurbineElementType declarationTarget) {
+  private ImmutableList<ParamInfo> bindParameters(
+      ImmutableList<ParamInfo> params, TurbineElementType declarationTarget) {
     ImmutableList.Builder<ParamInfo> result = ImmutableList.builder();
     for (ParamInfo param : params) {
-      result.add(bindParam(env, param, declarationTarget));
+      result.add(bindParam(param, declarationTarget));
     }
     return result.build();
   }
 
-  private static ParamInfo bindParam(
-      Env<ClassSymbol, TypeBoundClass> env, ParamInfo base, TurbineElementType declarationTarget) {
+  private ParamInfo bindParam(ParamInfo base, TurbineElementType declarationTarget) {
     ImmutableList.Builder<AnnoInfo> declarationAnnotations = ImmutableList.builder();
     Type type =
-        disambiguate(
-            env, declarationTarget, base.type(), base.annotations(), declarationAnnotations);
+        disambiguate(declarationTarget, base.type(), base.annotations(), declarationAnnotations);
     return new ParamInfo(base.sym(), type, declarationAnnotations.build(), base.access());
   }
 
-  private static ImmutableList<RecordComponentInfo> bindComponents(
-      Env<ClassSymbol, TypeBoundClass> env,
-      ImmutableList<RecordComponentInfo> components,
-      TurbineElementType declarationTarget) {
+  private ImmutableList<RecordComponentInfo> bindComponents(
+      ImmutableList<RecordComponentInfo> components, TurbineElementType declarationTarget) {
     ImmutableList.Builder<RecordComponentInfo> result = ImmutableList.builder();
     for (RecordComponentInfo component : components) {
       ImmutableList.Builder<AnnoInfo> declarationAnnotations = ImmutableList.builder();
       Type type =
           disambiguate(
-              env,
-              declarationTarget,
-              component.type(),
-              component.annotations(),
-              declarationAnnotations);
+              declarationTarget, component.type(), component.annotations(), declarationAnnotations);
       result.add(
           new RecordComponentInfo(
               component.sym(), type, declarationAnnotations.build(), component.access()));
@@ -171,18 +168,17 @@ public final class DisambiguateTypeAnnotations {
    * Moves type annotations in {@code annotations} to {@code type}, and adds any declaration
    * annotations on {@code type} to {@code declarationAnnotations}.
    */
-  private static Type disambiguate(
-      Env<ClassSymbol, TypeBoundClass> env,
+  private Type disambiguate(
       TurbineElementType declarationTarget,
       Type type,
       ImmutableList<AnnoInfo> annotations,
       ImmutableList.Builder<AnnoInfo> declarationAnnotations) {
     // desugar @Repeatable annotations before disambiguating: annotation containers may target
     // a subset of the types targeted by their element annotation
-    annotations = groupRepeated(env, annotations);
+    annotations = groupRepeated(annotations);
     ImmutableList.Builder<AnnoInfo> typeAnnotations = ImmutableList.builder();
     for (AnnoInfo anno : annotations) {
-      ImmutableSet<TurbineElementType> target = getTarget(env, anno);
+      ImmutableSet<TurbineElementType> target = getTarget(anno);
       if (target.contains(TurbineElementType.TYPE_USE)) {
         typeAnnotations.add(anno);
       }
@@ -193,8 +189,7 @@ public final class DisambiguateTypeAnnotations {
     return addAnnotationsToType(type, typeAnnotations.build());
   }
 
-  private static ImmutableSet<TurbineElementType> getTarget(
-      Env<ClassSymbol, TypeBoundClass> env, AnnoInfo anno) {
+  private ImmutableSet<TurbineElementType> getTarget(AnnoInfo anno) {
     ClassSymbol sym = anno.sym();
     if (sym == null) {
       return AnnotationMetadata.DEFAULT_TARGETS;
@@ -210,20 +205,19 @@ public final class DisambiguateTypeAnnotations {
     return metadata.target();
   }
 
-  private static ImmutableList<FieldInfo> bindFields(
-      Env<ClassSymbol, TypeBoundClass> env, ImmutableList<FieldInfo> fields) {
+  private ImmutableList<FieldInfo> bindFields(ImmutableList<FieldInfo> fields) {
     ImmutableList.Builder<FieldInfo> result = ImmutableList.builder();
     for (FieldInfo field : fields) {
-      result.add(bindField(env, field));
+      result.add(bindField(field));
     }
     return result.build();
   }
 
-  private static FieldInfo bindField(Env<ClassSymbol, TypeBoundClass> env, FieldInfo base) {
+  private FieldInfo bindField(FieldInfo base) {
     ImmutableList.Builder<AnnoInfo> declarationAnnotations = ImmutableList.builder();
     Type type =
         disambiguate(
-            env, TurbineElementType.FIELD, base.type(), base.annotations(), declarationAnnotations);
+            TurbineElementType.FIELD, base.type(), base.annotations(), declarationAnnotations);
     return new FieldInfo(
         base.sym(), type, base.access(), declarationAnnotations.build(), base.decl(), base.value());
   }
@@ -284,7 +278,11 @@ public final class DisambiguateTypeAnnotations {
    * here, but it would require another rewrite pass.
    */
   public static ImmutableList<AnnoInfo> groupRepeated(
-      Env<ClassSymbol, TypeBoundClass> env, ImmutableList<AnnoInfo> annotations) {
+      Env<ClassSymbol, TypeBoundClass> env, TurbineLog log, ImmutableList<AnnoInfo> annotations) {
+    return new DisambiguateTypeAnnotations(env, log).groupRepeated(annotations);
+  }
+
+  private ImmutableList<AnnoInfo> groupRepeated(ImmutableList<AnnoInfo> annotations) {
     Multimap<ClassSymbol, AnnoInfo> repeated =
         MultimapBuilder.linkedHashKeys().arrayListValues().build();
     ImmutableList.Builder<AnnoInfo> result = ImmutableList.builder();
@@ -309,12 +307,10 @@ public final class DisambiguateTypeAnnotations {
         }
         ClassSymbol container = info.annotationMetadata().repeatable();
         if (container == null) {
-          if (isKotlinRepeatable(info)) {
-            continue;
-          }
           AnnoInfo anno = infos.iterator().next();
-          throw TurbineError.format(
-              anno.source(), anno.position(), ErrorKind.NONREPEATABLE_ANNOTATION, symbol);
+          log.withSource(anno.source())
+              .error(anno.position(), ErrorKind.NONREPEATABLE_ANNOTATION, symbol);
+          continue;
         }
         result.add(
             new AnnoInfo(
@@ -328,20 +324,4 @@ public final class DisambiguateTypeAnnotations {
     }
     return result.build();
   }
-
-  // Work-around for https://youtrack.jetbrains.net/issue/KT-34189.
-  // Kotlin stubs include repeated annotations that are valid in Kotlin (i.e. meta-annotated with
-  // @kotlin.annotation.Repeatable), even though they are invalid Java.
-  // TODO(b/142002426): kill this with fire
-  static boolean isKotlinRepeatable(TypeBoundClass info) {
-    for (AnnoInfo metaAnno : info.annotations()) {
-      if (metaAnno.sym() != null
-          && metaAnno.sym().binaryName().equals("kotlin/annotation/Repeatable")) {
-        return true;
-      }
-    }
-    return false;
-  }
-
-  private DisambiguateTypeAnnotations() {}
 }
diff --git a/java/com/google/turbine/deps/Dependencies.java b/java/com/google/turbine/deps/Dependencies.java
index 5ce9b5d..e669920 100644
--- a/java/com/google/turbine/deps/Dependencies.java
+++ b/java/com/google/turbine/deps/Dependencies.java
@@ -39,6 +39,7 @@ import com.google.turbine.proto.DepsProto;
 import com.google.turbine.type.AnnoInfo;
 import com.google.turbine.type.Type;
 import java.io.BufferedInputStream;
+import java.io.File;
 import java.io.IOError;
 import java.io.IOException;
 import java.io.InputStream;
@@ -75,7 +76,8 @@ public final class Dependencies {
     for (String jarFile : jars) {
       deps.addDependency(
           DepsProto.Dependency.newBuilder()
-              .setPath(jarFile)
+              // Ensure that the path is written with forward slashes on all platforms.
+              .setPath(jarFile.replace(File.separatorChar, '/'))
               .setKind(DepsProto.Dependency.Kind.EXPLICIT));
     }
     // we don't current write jdeps for failed compilations
diff --git a/java/com/google/turbine/diag/LineMap.java b/java/com/google/turbine/diag/LineMap.java
index 37d055b..ec01432 100644
--- a/java/com/google/turbine/diag/LineMap.java
+++ b/java/com/google/turbine/diag/LineMap.java
@@ -40,13 +40,13 @@ public class LineMap {
     for (int idx = 0; idx < source.length(); idx++) {
       char ch = source.charAt(idx);
       switch (ch) {
-          // handle CR line endings
+        // handle CR line endings
         case '\r':
           // ...and CRLF
           if (idx + 1 < source.length() && source.charAt(idx + 1) == '\n') {
             idx++;
           }
-          // falls through
+        // falls through
         case '\n':
           builder.put(Range.closedOpen(last, idx + 1), line++);
           last = idx + 1;
diff --git a/java/com/google/turbine/lower/Lower.java b/java/com/google/turbine/lower/Lower.java
index ce6ec6d..fbd0e25 100644
--- a/java/com/google/turbine/lower/Lower.java
+++ b/java/com/google/turbine/lower/Lower.java
@@ -66,6 +66,7 @@ import com.google.turbine.bytecode.sig.SigWriter;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.diag.TurbineError;
 import com.google.turbine.diag.TurbineError.ErrorKind;
+import com.google.turbine.diag.TurbineLog;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.TurbineFlag;
 import com.google.turbine.model.TurbineTyKind;
@@ -148,23 +149,25 @@ public class Lower {
     Set<ClassSymbol> symbols = new LinkedHashSet<>();
     // Output Java 8 bytecode at minimum, for type annotations
     int majorVersion = max(options.languageVersion().majorVersion(), 52);
+    TurbineLog log = new TurbineLog();
     for (ClassSymbol sym : units.keySet()) {
       result.put(
           sym.binaryName(),
-          lower(units.get(sym), env, sym, symbols, majorVersion, options.emitPrivateFields()));
+          lower(units.get(sym), env, log, sym, symbols, majorVersion, options.emitPrivateFields()));
     }
     if (modules.size() == 1) {
       // single module mode: the module-info.class file is at the root
-      result.put("module-info", lower(getOnlyElement(modules), env, symbols, majorVersion));
+      result.put("module-info", lower(getOnlyElement(modules), env, log, symbols, majorVersion));
     } else {
       // multi-module mode: the output module-info.class are in a directory corresponding to their
       // package
       for (SourceModuleInfo module : modules) {
         result.put(
             module.name().replace('.', '/') + "/module-info",
-            lower(module, env, symbols, majorVersion));
+            lower(module, env, log, symbols, majorVersion));
       }
     }
+    log.maybeThrow();
     return Lowered.create(result.buildOrThrow(), ImmutableSet.copyOf(symbols));
   }
 
@@ -172,26 +175,30 @@ public class Lower {
   private static byte[] lower(
       SourceTypeBoundClass info,
       Env<ClassSymbol, TypeBoundClass> env,
+      TurbineLog log,
       ClassSymbol sym,
       Set<ClassSymbol> symbols,
       int majorVersion,
       boolean emitPrivateFields) {
-    return new Lower(env).lower(info, sym, symbols, majorVersion, emitPrivateFields);
+    return new Lower(env, log).lower(info, sym, symbols, majorVersion, emitPrivateFields);
   }
 
   private static byte[] lower(
       SourceModuleInfo module,
       CompoundEnv<ClassSymbol, TypeBoundClass> env,
+      TurbineLog log,
       Set<ClassSymbol> symbols,
       int majorVersion) {
-    return new Lower(env).lower(module, symbols, majorVersion);
+    return new Lower(env, log).lower(module, symbols, majorVersion);
   }
 
   private final LowerSignature sig = new LowerSignature();
   private final Env<ClassSymbol, TypeBoundClass> env;
+  private final TurbineLog log;
 
-  public Lower(Env<ClassSymbol, TypeBoundClass> env) {
+  public Lower(Env<ClassSymbol, TypeBoundClass> env, TurbineLog log) {
     this.env = env;
+    this.log = log;
   }
 
   private byte[] lower(SourceModuleInfo module, Set<ClassSymbol> symbols, int majorVersion) {
@@ -794,7 +801,7 @@ public class Lower {
       TargetType boundTargetType) {
     int typeParameterIndex = 0;
     for (TyVarInfo p : typeParameters) {
-      for (AnnoInfo anno : groupRepeated(env, p.annotations())) {
+      for (AnnoInfo anno : groupRepeated(env, log, p.annotations())) {
         AnnotationInfo info = lowerAnnotation(anno);
         if (info == null) {
           continue;
@@ -880,7 +887,7 @@ public class Lower {
 
     /** Lower a list of type annotations. */
     private void lowerTypeAnnotations(ImmutableList<AnnoInfo> annos, TypePath path) {
-      for (AnnoInfo anno : groupRepeated(env, annos)) {
+      for (AnnoInfo anno : groupRepeated(env, log, annos)) {
         AnnotationInfo info = lowerAnnotation(anno);
         if (info == null) {
           continue;
diff --git a/java/com/google/turbine/parse/ConstExpressionParser.java b/java/com/google/turbine/parse/ConstExpressionParser.java
index 1db47cb..934b91c 100644
--- a/java/com/google/turbine/parse/ConstExpressionParser.java
+++ b/java/com/google/turbine/parse/ConstExpressionParser.java
@@ -204,11 +204,11 @@ public class ConstExpressionParser {
         eat();
         return castTail(TurbineConstantTypeKind.FLOAT);
       default:
-        return notCast();
+        return notPrimitiveCast();
     }
   }
 
-  private @Nullable Expression notCast() {
+  private @Nullable Expression notPrimitiveCast() {
     Expression expr = expression(null);
     if (expr == null) {
       return null;
@@ -231,7 +231,7 @@ public class ConstExpressionParser {
         case IDENT:
           Expression expression = primary(false);
           if (expression == null) {
-            throw error(ErrorKind.EXPRESSION_ERROR);
+            return null;
           }
           return new Tree.TypeCast(position, asClassTy(cvar.position(), cvar.name()), expression);
         default:
@@ -487,7 +487,7 @@ public class ConstExpressionParser {
     switch (token) {
       case EOF:
       case SEMI:
-        // TODO(cushon): only allow in annotations?
+      // TODO(cushon): only allow in annotations?
       case COMMA:
       case RPAREN:
         return result;
diff --git a/java/com/google/turbine/parse/Parser.java b/java/com/google/turbine/parse/Parser.java
index 7fed666..5b05fd8 100644
--- a/java/com/google/turbine/parse/Parser.java
+++ b/java/com/google/turbine/parse/Parser.java
@@ -226,7 +226,7 @@ public class Parser {
               break;
             }
           }
-          // fall through
+        // fall through
         default:
           throw error(token);
       }
@@ -750,7 +750,7 @@ public class Parser {
             annos = ImmutableList.builder();
             break;
           }
-          // fall through
+        // fall through
         case BOOLEAN:
         case BYTE:
         case SHORT:
diff --git a/java/com/google/turbine/parse/StreamLexer.java b/java/com/google/turbine/parse/StreamLexer.java
index a14b826..7c7d9de 100644
--- a/java/com/google/turbine/parse/StreamLexer.java
+++ b/java/com/google/turbine/parse/StreamLexer.java
@@ -432,7 +432,7 @@ public class StreamLexer implements Lexer {
                   if (reader.done()) {
                     return Token.EOF;
                   }
-                  // falls through
+                // falls through
                 default:
                   sb.appendCodePoint(ch);
                   eat();
@@ -512,7 +512,7 @@ public class StreamLexer implements Lexer {
           if (reader.done()) {
             return Token.EOF;
           }
-          // falls through
+        // falls through
         default:
           sb.appendCodePoint(ch);
           eat();
@@ -670,7 +670,7 @@ public class StreamLexer implements Lexer {
       case '2':
       case '3':
         zeroToThree = true;
-        // falls through
+      // falls through
       case '4':
       case '5':
       case '6':
@@ -708,7 +708,7 @@ public class StreamLexer implements Lexer {
                   }
                 }
               }
-              // fall through
+            // fall through
             default:
               return value;
           }
diff --git a/java/com/google/turbine/processing/TurbineAnnotationProxy.java b/java/com/google/turbine/processing/TurbineAnnotationProxy.java
index 967ead9..81b4b75 100644
--- a/java/com/google/turbine/processing/TurbineAnnotationProxy.java
+++ b/java/com/google/turbine/processing/TurbineAnnotationProxy.java
@@ -19,10 +19,14 @@ package com.google.turbine.processing;
 import static com.google.common.base.Preconditions.checkArgument;
 import static java.util.Objects.requireNonNull;
 
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.Iterables;
+import com.google.turbine.binder.bound.AnnotationMetadata;
 import com.google.turbine.binder.bound.EnumConstantValue;
 import com.google.turbine.binder.bound.TurbineAnnotationValue;
 import com.google.turbine.binder.bound.TurbineClassValue;
 import com.google.turbine.binder.bound.TypeBoundClass;
+import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.Const.ArrayInitValue;
 import com.google.turbine.model.Const.Value;
@@ -34,9 +38,11 @@ import java.lang.reflect.Method;
 import java.lang.reflect.Proxy;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.Objects;
 import javax.lang.model.type.MirroredTypeException;
 import javax.lang.model.type.MirroredTypesException;
 import javax.lang.model.type.TypeMirror;
+import org.jspecify.annotations.Nullable;
 
 /** An {@link InvocationHandler} for reflectively accessing annotations. */
 class TurbineAnnotationProxy implements InvocationHandler {
@@ -68,6 +74,52 @@ class TurbineAnnotationProxy implements InvocationHandler {
     this.anno = anno;
   }
 
+  static <A extends Annotation> @Nullable A getAnnotation(
+      ModelFactory factory, ImmutableList<AnnoInfo> annos, Class<A> annotationType) {
+    ClassSymbol sym = new ClassSymbol(annotationType.getName().replace('.', '/'));
+    TypeBoundClass info = factory.getSymbol(sym);
+    if (info == null) {
+      return null;
+    }
+    for (AnnoInfo anno : annos) {
+      if (sym.equals(anno.sym())) {
+        return create(factory, annotationType, anno);
+      }
+    }
+    return null;
+  }
+
+  static final <A extends Annotation> A @Nullable [] getAnnotationsByType(
+      ModelFactory factory, ImmutableList<AnnoInfo> annos, Class<A> annotationType) {
+    ClassSymbol sym = new ClassSymbol(annotationType.getName().replace('.', '/'));
+    TypeBoundClass info = factory.getSymbol(sym);
+    if (info == null) {
+      return null;
+    }
+    AnnotationMetadata metadata = info.annotationMetadata();
+    if (metadata == null) {
+      return null;
+    }
+    List<A> result = new ArrayList<>();
+    for (AnnoInfo anno : annos) {
+      if (sym.equals(anno.sym())) {
+        result.add(TurbineAnnotationProxy.create(factory, annotationType, anno));
+        continue;
+      }
+      if (Objects.equals(anno.sym(), metadata.repeatable())) {
+        // requireNonNull is safe because java.lang.annotation.Repeatable declares `value`.
+        Const.ArrayInitValue arrayValue =
+            (Const.ArrayInitValue) requireNonNull(anno.values().get("value"));
+        for (Const element : arrayValue.elements()) {
+          result.add(
+              TurbineAnnotationProxy.create(
+                  factory, annotationType, ((TurbineAnnotationValue) element).info()));
+        }
+      }
+    }
+    return Iterables.toArray(result, annotationType);
+  }
+
   @Override
   public Object invoke(Object proxy, Method method, Object[] args) {
     switch (method.getName()) {
diff --git a/java/com/google/turbine/processing/TurbineElement.java b/java/com/google/turbine/processing/TurbineElement.java
index 72d5ffd..383dede 100644
--- a/java/com/google/turbine/processing/TurbineElement.java
+++ b/java/com/google/turbine/processing/TurbineElement.java
@@ -25,11 +25,8 @@ import com.google.common.base.Suppliers;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.ImmutableSet;
-import com.google.common.collect.Iterables;
 import com.google.common.collect.Sets;
-import com.google.turbine.binder.bound.AnnotationMetadata;
 import com.google.turbine.binder.bound.SourceTypeBoundClass;
-import com.google.turbine.binder.bound.TurbineAnnotationValue;
 import com.google.turbine.binder.bound.TypeBoundClass;
 import com.google.turbine.binder.bound.TypeBoundClass.FieldInfo;
 import com.google.turbine.binder.bound.TypeBoundClass.MethodInfo;
@@ -47,8 +44,6 @@ import com.google.turbine.binder.sym.Symbol;
 import com.google.turbine.binder.sym.TyVarSymbol;
 import com.google.turbine.diag.TurbineError;
 import com.google.turbine.diag.TurbineError.ErrorKind;
-import com.google.turbine.model.Const;
-import com.google.turbine.model.Const.ArrayInitValue;
 import com.google.turbine.model.TurbineFlag;
 import com.google.turbine.tree.Tree.MethDecl;
 import com.google.turbine.tree.Tree.VarDecl;
@@ -59,7 +54,6 @@ import com.google.turbine.type.Type.ClassTy.SimpleClassTy;
 import com.google.turbine.type.Type.ErrorTy;
 import java.lang.annotation.Annotation;
 import java.util.ArrayDeque;
-import java.util.ArrayList;
 import java.util.Deque;
 import java.util.EnumSet;
 import java.util.HashMap;
@@ -133,46 +127,12 @@ public abstract class TurbineElement implements Element {
 
   @Override
   public <A extends Annotation> A getAnnotation(Class<A> annotationType) {
-    ClassSymbol sym = new ClassSymbol(annotationType.getName().replace('.', '/'));
-    TypeBoundClass info = factory.getSymbol(sym);
-    if (info == null) {
-      return null;
-    }
-    AnnoInfo anno = getAnnotation(annos(), sym);
-    if (anno == null) {
-      return null;
-    }
-    return TurbineAnnotationProxy.create(factory, annotationType, anno);
+    return TurbineAnnotationProxy.getAnnotation(factory, annos(), annotationType);
   }
 
   @Override
   public final <A extends Annotation> A[] getAnnotationsByType(Class<A> annotationType) {
-    ClassSymbol sym = new ClassSymbol(annotationType.getName().replace('.', '/'));
-    TypeBoundClass info = factory.getSymbol(sym);
-    if (info == null) {
-      return null;
-    }
-    AnnotationMetadata metadata = info.annotationMetadata();
-    if (metadata == null) {
-      return null;
-    }
-    List<A> result = new ArrayList<>();
-    for (AnnoInfo anno : annos()) {
-      if (anno.sym().equals(sym)) {
-        result.add(TurbineAnnotationProxy.create(factory, annotationType, anno));
-        continue;
-      }
-      if (anno.sym().equals(metadata.repeatable())) {
-        // requireNonNull is safe because java.lang.annotation.Repeatable declares `value`.
-        ArrayInitValue arrayValue = (ArrayInitValue) requireNonNull(anno.values().get("value"));
-        for (Const element : arrayValue.elements()) {
-          result.add(
-              TurbineAnnotationProxy.create(
-                  factory, annotationType, ((TurbineAnnotationValue) element).info()));
-        }
-      }
-    }
-    return Iterables.toArray(result, annotationType);
+    return TurbineAnnotationProxy.getAnnotationsByType(factory, annos(), annotationType);
   }
 
   @Override
diff --git a/java/com/google/turbine/processing/TurbineTypeMirror.java b/java/com/google/turbine/processing/TurbineTypeMirror.java
index 60ca690..6e57b2e 100644
--- a/java/com/google/turbine/processing/TurbineTypeMirror.java
+++ b/java/com/google/turbine/processing/TurbineTypeMirror.java
@@ -81,12 +81,12 @@ public abstract class TurbineTypeMirror implements TypeMirror {
 
   @Override
   public final <A extends Annotation> A getAnnotation(Class<A> annotationType) {
-    throw new AssertionError();
+    return TurbineAnnotationProxy.getAnnotation(factory, annos(), annotationType);
   }
 
   @Override
   public final <A extends Annotation> A[] getAnnotationsByType(Class<A> annotationType) {
-    throw new AssertionError();
+    return TurbineAnnotationProxy.getAnnotationsByType(factory, annos(), annotationType);
   }
 
   public abstract Type asTurbineType();
diff --git a/javatests/com/google/turbine/binder/BinderErrorTest.java b/javatests/com/google/turbine/binder/BinderErrorTest.java
index e1e1eff..8d16e83 100644
--- a/javatests/com/google/turbine/binder/BinderErrorTest.java
+++ b/javatests/com/google/turbine/binder/BinderErrorTest.java
@@ -1024,6 +1024,23 @@ public class BinderErrorTest {
           "                                      ^",
         },
       },
+      {
+        {
+          "@interface Anno {}", //
+          "class Test {",
+          "  @Anno @Anno int x;",
+          "  @Anno @Anno int y;",
+          "}",
+        },
+        {
+          "<>:3: error: Anno is not @Repeatable",
+          "  @Anno @Anno int x;",
+          "  ^",
+          "<>:4: error: Anno is not @Repeatable",
+          "  @Anno @Anno int y;",
+          "  ^",
+        },
+      },
     };
     return Arrays.asList((Object[][]) testCases);
   }
diff --git a/javatests/com/google/turbine/deps/TransitiveTest.java b/javatests/com/google/turbine/deps/TransitiveTest.java
index 69d719b..ce26dd6 100644
--- a/javatests/com/google/turbine/deps/TransitiveTest.java
+++ b/javatests/com/google/turbine/deps/TransitiveTest.java
@@ -34,6 +34,7 @@ import com.google.turbine.main.Main;
 import com.google.turbine.proto.DepsProto;
 import com.google.turbine.proto.DepsProto.Dependency.Kind;
 import java.io.BufferedInputStream;
+import java.io.File;
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
@@ -196,7 +197,11 @@ public class TransitiveTest {
     // liba is recorded as an explicit dep, even thought it's only present as a transitive class
     // repackaged in lib
     assertThat(readDeps(libcDeps))
-        .containsExactly(liba.toString(), Kind.EXPLICIT, libb.toString(), Kind.EXPLICIT);
+        .containsExactly(
+            liba.toString().replace(File.separatorChar, '/'),
+            Kind.EXPLICIT,
+            libb.toString().replace(File.separatorChar, '/'),
+            Kind.EXPLICIT);
   }
 
   private static ImmutableMap<String, Kind> readDeps(Path libcDeps) throws IOException {
diff --git a/javatests/com/google/turbine/lower/LowerIntegrationTest.java b/javatests/com/google/turbine/lower/LowerIntegrationTest.java
index bac2b5a..74abe49 100644
--- a/javatests/com/google/turbine/lower/LowerIntegrationTest.java
+++ b/javatests/com/google/turbine/lower/LowerIntegrationTest.java
@@ -266,6 +266,7 @@ public class LowerIntegrationTest {
       "non_const.test",
       "noncanon.test",
       "noncanon_static_wild.test",
+      "nonconst_array_cast.test",
       "nonconst_unary_expression.test",
       "one.test",
       "outer.test",
diff --git a/javatests/com/google/turbine/lower/LowerTest.java b/javatests/com/google/turbine/lower/LowerTest.java
index 2de4650..57e5a8e 100644
--- a/javatests/com/google/turbine/lower/LowerTest.java
+++ b/javatests/com/google/turbine/lower/LowerTest.java
@@ -38,6 +38,7 @@ import com.google.turbine.binder.sym.ParamSymbol;
 import com.google.turbine.binder.sym.TyVarSymbol;
 import com.google.turbine.bytecode.ByteReader;
 import com.google.turbine.bytecode.ConstantPoolReader;
+import com.google.turbine.diag.SourceFile;
 import com.google.turbine.diag.TurbineError;
 import com.google.turbine.model.TurbineConstantTypeKind;
 import com.google.turbine.model.TurbineFlag;
@@ -751,6 +752,44 @@ public class LowerTest {
     assertThat(fields).containsExactly("y");
   }
 
+  @Test
+  public void repeatedTypeAnnotationError() throws Exception {
+    BindingResult bound =
+        Binder.bind(
+            ImmutableList.of(
+                Parser.parse(
+                    new SourceFile(
+                        "Test.java",
+                        """
+                        import java.lang.annotation.ElementType;
+                        import java.lang.annotation.Target;
+                        import java.util.List;
+                        @Target({ElementType.TYPE_USE}) @interface Anno {}
+                        class Test {
+                          List<@Anno @Anno Integer> xs;
+                          }
+                        """))),
+            ClassPathBinder.bindClasspath(ImmutableList.of()),
+            TURBINE_BOOTCLASSPATH,
+            /* moduleVersion= */ Optional.empty());
+    TurbineError turbineError =
+        assertThrows(
+            TurbineError.class,
+            () ->
+                Lower.lowerAll(
+                    Lower.LowerOptions.createDefault(),
+                    bound.units(),
+                    bound.modules(),
+                    bound.classPathEnv()));
+    assertThat(turbineError)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "Test.java:6: error: Anno is not @Repeatable",
+                "  List<@Anno @Anno Integer> xs;",
+                "       ^"));
+  }
+
   static String lines(String... lines) {
     return Joiner.on(System.lineSeparator()).join(lines);
   }
diff --git a/javatests/com/google/turbine/lower/testdata/nonconst_array_cast.test b/javatests/com/google/turbine/lower/testdata/nonconst_array_cast.test
new file mode 100644
index 0000000..860ddcd
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/nonconst_array_cast.test
@@ -0,0 +1,17 @@
+=== Z.java ===
+
+public class Z {
+
+  static class S {}
+
+  static final S[] MS = {};
+
+  static final class K {}
+
+  abstract static class KS extends S {
+    abstract K[] g();
+  }
+
+  private static final K M = ((KS) MS[0]).g()[0];
+}
+
diff --git a/javatests/com/google/turbine/parse/ParseErrorTest.java b/javatests/com/google/turbine/parse/ParseErrorTest.java
index 9abb562..eddb232 100644
--- a/javatests/com/google/turbine/parse/ParseErrorTest.java
+++ b/javatests/com/google/turbine/parse/ParseErrorTest.java
@@ -302,7 +302,7 @@ public class ParseErrorTest {
         .hasMessageThat()
         .isEqualTo(
             lines(
-                "<>:1: error: could not evaluate constant expression",
+                "<>:1: error: invalid annotation argument",
                 "@j(@truetugt^(oflur)!%t",
                 "                     ^"));
   }
diff --git a/javatests/com/google/turbine/processing/TurbineAnnotationProxyTest.java b/javatests/com/google/turbine/processing/TurbineAnnotationProxyTest.java
index a8c00aa..b8ba711 100644
--- a/javatests/com/google/turbine/processing/TurbineAnnotationProxyTest.java
+++ b/javatests/com/google/turbine/processing/TurbineAnnotationProxyTest.java
@@ -19,10 +19,14 @@ package com.google.turbine.processing;
 import static com.google.common.collect.ImmutableList.toImmutableList;
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.turbine.testing.TestResources.getResourceBytes;
+import static java.lang.annotation.ElementType.TYPE;
+import static java.lang.annotation.ElementType.TYPE_USE;
+import static java.util.Arrays.stream;
 import static org.junit.Assert.assertThrows;
 
 import com.google.common.base.Joiner;
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.Iterables;
 import com.google.common.primitives.Ints;
 import com.google.common.testing.EqualsTester;
 import com.google.turbine.binder.Binder;
@@ -44,6 +48,7 @@ import java.lang.annotation.Inherited;
 import java.lang.annotation.Repeatable;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.util.Arrays;
@@ -51,11 +56,13 @@ import java.util.Optional;
 import java.util.jar.JarEntry;
 import java.util.jar.JarOutputStream;
 import javax.lang.model.element.TypeElement;
+import javax.lang.model.element.VariableElement;
 import javax.lang.model.type.DeclaredType;
 import javax.lang.model.type.MirroredTypeException;
 import javax.lang.model.type.MirroredTypesException;
 import javax.lang.model.type.TypeKind;
 import javax.lang.model.type.TypeMirror;
+import javax.lang.model.util.ElementFilter;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TemporaryFolder;
@@ -80,6 +87,7 @@ public class TurbineAnnotationProxyTest {
     Class<?>[] cx() default {};
   }
 
+  @Target({TYPE, TYPE_USE})
   @Retention(RetentionPolicy.RUNTIME)
   @Inherited
   public @interface B {
@@ -89,11 +97,13 @@ public class TurbineAnnotationProxyTest {
   @Retention(RetentionPolicy.RUNTIME)
   public @interface C {}
 
+  @Target({TYPE, TYPE_USE})
   @Retention(RetentionPolicy.RUNTIME)
   public @interface RS {
     R[] value() default {};
   }
 
+  @Target({TYPE, TYPE_USE})
   @Repeatable(RS.class)
   @Retention(RetentionPolicy.RUNTIME)
   public @interface R {
@@ -113,6 +123,7 @@ public class TurbineAnnotationProxyTest {
       addClass(jos, B.class);
       addClass(jos, C.class);
       addClass(jos, R.class);
+      addClass(jos, RS.class);
     }
 
     TestInput input =
@@ -127,12 +138,15 @@ public class TurbineAnnotationProxyTest {
                     "class Super {}",
                     "=== Test.java ===",
                     "import " + A.class.getCanonicalName() + ";",
+                    "import " + B.class.getCanonicalName() + ";",
                     "import " + R.class.getCanonicalName() + ";",
                     "@A(xs = {1,2,3}, cx = {Integer.class, Long.class})",
                     "@R(1)",
                     "@R(2)",
                     "@R(3)",
-                    "class Test extends Super {}",
+                    "class Test extends Super {",
+                    "  @B(4) @R(5) @R(6) int x;",
+                    "}",
                     ""));
 
     ImmutableList<CompUnit> units =
@@ -188,6 +202,18 @@ public class TurbineAnnotationProxyTest {
                 R.class.getCanonicalName(),
                 R.class.getCanonicalName()));
 
+    VariableElement f = Iterables.getOnlyElement(ElementFilter.fieldsIn(te.getEnclosedElements()));
+    TypeMirror ft = f.asType();
+    assertThat(ft.getAnnotation(B.class).value()).isEqualTo(4);
+    assertThat(stream(ft.getAnnotation(RS.class).value()).map(r -> r.value()))
+        .containsExactly(5, 6);
+    assertThat(stream(ft.getAnnotationsByType(R.class)).map(r -> r.value())).containsExactly(5, 6);
+    assertThat(
+            stream(ft.getAnnotationsByType(RS.class))
+                .flatMap(r -> stream(r.value()))
+                .map(r -> r.value()))
+        .containsExactly(5, 6);
+
     new EqualsTester()
         .addEqualityGroup(a, te.getAnnotation(A.class))
         .addEqualityGroup(b, te.getAnnotation(B.class))
@@ -200,6 +226,75 @@ public class TurbineAnnotationProxyTest {
         .testEquals();
   }
 
+  @Test
+  public void missingClasses() throws IOException {
+
+    Path lib = temporaryFolder.newFile("lib.jar").toPath();
+    try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(lib))) {
+      addClass(jos, TurbineAnnotationProxyTest.class);
+      addClass(jos, A.class);
+      addClass(jos, B.class);
+      addClass(jos, C.class);
+      addClass(jos, R.class);
+      addClass(jos, RS.class);
+    }
+
+    TestInput input =
+        TestInput.parse(
+            Joiner.on('\n')
+                .join(
+                    "=== Test.java ===",
+                    "import " + A.class.getCanonicalName() + ";",
+                    "import " + B.class.getCanonicalName() + ";",
+                    "import " + C.class.getCanonicalName() + ";",
+                    "import " + R.class.getCanonicalName() + ";",
+                    "class Test {",
+                    "  @A(xs = {1,2,3}, cx = {Integer.class, Long.class})",
+                    "  @B(42)",
+                    "  @C",
+                    "  @R(1)",
+                    "  @R(2)",
+                    "  @R(3)",
+                    "  int x;",
+                    "}",
+                    ""));
+
+    ImmutableList<CompUnit> units =
+        input.sources.entrySet().stream()
+            .map(e -> new SourceFile(e.getKey(), e.getValue()))
+            .map(Parser::parse)
+            .collect(toImmutableList());
+
+    Path bindingLib = temporaryFolder.newFile("bindingLib.jar").toPath();
+
+    try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(bindingLib))) {
+      addClass(jos, TurbineAnnotationProxyTest.class);
+    }
+
+    Binder.BindingResult bound =
+        Binder.bind(
+            units,
+            ClassPathBinder.bindClasspath(ImmutableList.of(lib)),
+            TestClassPaths.TURBINE_BOOTCLASSPATH,
+            Optional.empty());
+
+    Env<ClassSymbol, TypeBoundClass> env =
+        CompoundEnv.<ClassSymbol, TypeBoundClass>of(
+                ClassPathBinder.bindClasspath(ImmutableList.of(bindingLib)).env())
+            .append(new SimpleEnv<>(bound.units()));
+    ModelFactory factory = new ModelFactory(env, ClassLoader.getSystemClassLoader(), bound.tli());
+    TurbineTypeElement te = factory.typeElement(new ClassSymbol("Test"));
+    VariableElement f = Iterables.getOnlyElement(ElementFilter.fieldsIn(te.getEnclosedElements()));
+
+    assertThat(f.getAnnotation(A.class)).isNull();
+    assertThat(f.getAnnotation(B.class)).isNull();
+    assertThat(f.getAnnotation(C.class)).isNull();
+    assertThat(f.getAnnotation(R.class)).isNull();
+    assertThat(f.getAnnotation(RS.class)).isNull();
+    assertThat(f.getAnnotationsByType(R.class)).isNull();
+    assertThat(f.getAnnotationsByType(RS.class)).isNull();
+  }
+
   private static void addClass(JarOutputStream jos, Class<?> clazz) throws IOException {
     String entryPath = clazz.getName().replace('.', '/') + ".class";
     jos.putNextEntry(new JarEntry(entryPath));
diff --git a/pom.xml b/pom.xml
index 12fa494..b429c12 100644
--- a/pom.xml
+++ b/pom.xml
@@ -32,7 +32,7 @@
   <properties>
     <asm.version>9.7</asm.version>
     <guava.version>32.1.1-jre</guava.version>
-    <errorprone.version>2.36.0</errorprone.version>
+    <errorprone.version>2.37.0</errorprone.version>
     <maven-javadoc-plugin.version>3.3.1</maven-javadoc-plugin.version>
     <maven-source-plugin.version>3.2.1</maven-source-plugin.version>
     <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
```

