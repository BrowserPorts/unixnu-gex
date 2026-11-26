// GexLLP64: clang's wasm64 target with Windows x64's data model (LLP64), for
// Wine's PE side under 64-bit Wine. clang has no
// wasm64 Windows triple; this plugin changes the data model of the
// wasm64-unknown-unknown target before anything is parsed:
//   long 32 bits; long double = double (MSVC); size_t, ptrdiff_t, intptr_t,
//   intmax_t and int64_t are long long; wint_t is unsigned short.
// The predefined macros are computed before plugins run, so llp64.h
// (mkmacros.sh, force-included) redefines them as x86_64 MSVC's. Use with
// -mms-bitfields and -fshort-wchar. A layout test checks the result.
//
//   clang --target=wasm64-unknown-unknown -fplugin=GexLLP64.so -include llp64.h ...
//
// It also gives dllexport and dllimport their PE meaning on a target that
// drops them: a declaration marked with either has default visibility, so a
// DLL exports what MinGW code marks dllexport and refers to what it marks
// dllimport by name (clang's wasm default visibility is hidden, like a PE
// symbol nobody exports). The wasm target knows no dllexport attribute, so
// gexcc-win renames the two (-Ddllexport=__gexw_dllexport,
// -Ddllimport=__gexw_dllimport) to this plugin's attributes, in both
// __declspec(...) and __attribute__((...)) spellings.
//
// And it keeps what clang's wasm C ABI loses that Win64 needs: a struct
// whose one element is a float or a double (struct { double d; }) is passed
// and returned as that scalar on wasm, where Win64 passes and returns it as
// a 4- or 8-byte struct, in an integer register. The IR says only `double`.
// At the end of the translation unit, before code generation, the plugin
// notes each function with such a parameter or result, by its symbol name,
// and GexIcall (the pass plugin, in the same clang process) asks for it
// through gexw_struct_fp (see there).
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Attr.h"
#include "clang/Sema/ParsedAttr.h"
#include "clang/Sema/Sema.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/ADT/APFloat.h"

#include <map>
#include <string>

using namespace clang;

namespace {

// Symbol name -> its struct-FP mask (gexw_struct_fp).
std::map<std::string, std::string> &structFPs() {
  static std::map<std::string, std::string> m;
  return m;
}

// A record clang's wasm ABI passes as its one float or double: no C++ copy
// semantics that make it indirect, no bases, one field that is not an empty
// record (an array of one unwrapped, a record recursed into), and the same
// size as that scalar. Conservative: a shape this does not know is not one,
// and GexIcall keeps treating the scalar as a scalar.
bool singleFP(ASTContext &Ctx, QualType T) {
  T = T.getCanonicalType();
  const auto *RT = T->getAs<RecordType>();
  if (!RT) return false;
  const RecordDecl *RD = RT->getDecl()->getDefinition();
  if (!RD || RD->hasFlexibleArrayMember()) return false;
  if (const auto *CD = dyn_cast<CXXRecordDecl>(RD))
    if (!CD->canPassInRegisters() || CD->getNumBases() || CD->getNumVBases()) return false;
  QualType E;
  for (const FieldDecl *FD : RD->fields()) {
    if (FD->isBitField()) return false;
    QualType FT = FD->getType().getCanonicalType();
    if (const auto *CD = FT->getAsCXXRecordDecl(); CD && CD->isEmpty()) continue;
    if (!E.isNull()) return false;
    E = FT;
  }
  if (E.isNull()) return false;
  while (const auto *AT = Ctx.getAsConstantArrayType(E)) {
    if (AT->getSize() != 1) return false;
    E = AT->getElementType().getCanonicalType();
  }
  if (E->getAs<RecordType>()) {
    if (!singleFP(Ctx, E)) return false;
  } else {
    const auto *BT = E->getAs<BuiltinType>();
    if (!BT || !(BT->getKind() == BuiltinType::Float || BT->getKind() == BuiltinType::Double ||
                 BT->getKind() == BuiltinType::LongDouble))
      return false;
  }
  return Ctx.getTypeSize(T) == 32 || Ctx.getTypeSize(T) == 64;
}

// A record the wasm ABI drops from the parameters (an empty one).
bool emptyRecord(QualType T) {
  const auto *RT = T.getCanonicalType()->getAs<RecordType>();
  if (!RT) return false;
  const RecordDecl *RD = RT->getDecl()->getDefinition();
  if (!RD) return false;
  if (const auto *CD = dyn_cast<CXXRecordDecl>(RD)) return CD->canPassInRegisters() && CD->isEmpty();
  return RD->field_empty();
}

struct StructFPs : RecursiveASTVisitor<StructFPs> {
  ASTContext &Ctx;
  ASTNameGenerator Names;
  explicit StructFPs(ASTContext &C) : Ctx(C), Names(C) {}
  bool shouldVisitTemplateInstantiations() const { return true; }
  bool shouldVisitImplicitCode() const { return true; }
  bool VisitFunctionDecl(FunctionDecl *D) {
    if (D->isDependentContext() || D->isTemplated() || D->isVariadic()) return true;
    // the result, then `this` for a method, then each parameter:
    // R a struct-FP, e an empty record (dropped), . anything else
    std::string m(1, singleFP(Ctx, D->getReturnType()) ? 'R' : '.');
    bool any = m[0] == 'R';
    if (const auto *MD = dyn_cast<CXXMethodDecl>(D); MD && MD->isInstance()) m += '.';
    for (const ParmVarDecl *P : D->parameters()) {
      char c = singleFP(Ctx, P->getType()) ? 'R' : emptyRecord(P->getType()) ? 'e' : '.';
      any |= c == 'R';
      m += c;
    }
    if (!any) return true;
    if (isa<CXXConstructorDecl>(D) || isa<CXXDestructorDecl>(D)) {
      for (const std::string &n : Names.getAllManglings(D)) structFPs()[n] = m;
    } else {
      structFPs()[Names.getName(D)] = m;
    }
    return true;
  }
};

struct StructFPConsumer : ASTConsumer {
  void HandleTranslationUnit(ASTContext &Ctx) override {
    StructFPs V(Ctx);
    V.TraverseDecl(Ctx.getTranslationUnitDecl());
  }
};

// The integer-type choices are protected members of TransferrableTargetInfo;
// a member pointer formed in a derived class reaches them on any TargetInfo.
struct Model : TargetInfo {
  using TI = TransferrableTargetInfo;
  static void apply(TargetInfo &T) {
    T.LongWidth = T.LongAlign = 32;
    T.LongDoubleWidth = T.LongDoubleAlign = 64;
    T.LongDoubleFormat = &llvm::APFloat::IEEEdouble();
    IntType TI::*ll[] = {&Model::SizeType, &Model::IntMaxType, &Model::PtrDiffType, &Model::IntPtrType,
                         &Model::Int64Type};
    for (auto m : ll)
      T.*m = (m == &Model::SizeType) ? UnsignedLongLong : SignedLongLong;
    T.*(&Model::WIntType) = UnsignedShort;
  }
};

struct Action : PluginASTAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<StructFPConsumer>();
  }
  bool ParseArgs(const CompilerInstance &CI, const std::vector<std::string> &) override {
    const TargetInfo &T = CI.getTarget();
    if (T.getTriple().getArch() != llvm::Triple::wasm64) {
      CI.getDiagnostics().Report(CI.getDiagnostics().getCustomDiagID(
          DiagnosticsEngine::Error, "GexLLP64: the target must be wasm64"));
      return false;
    }
    Model::apply(const_cast<TargetInfo &>(T));
    return true;
  }
  ActionType getActionType() override { return AddBeforeMainAction; }
};

struct DllAttr : ParsedAttrInfo {
  DllAttr() {
    static constexpr Spelling S[] = {{ParsedAttr::AS_Declspec, "__gexw_dllexport"},
                                     {ParsedAttr::AS_GNU, "__gexw_dllexport"},
                                     {ParsedAttr::AS_Declspec, "__gexw_dllimport"},
                                     {ParsedAttr::AS_GNU, "__gexw_dllimport"}};
    Spellings = S;
  }
  bool diagAppertainsToDecl(Sema &, const ParsedAttr &, const Decl *D) const override {
    return isa<FunctionDecl>(D) || isa<VarDecl>(D) || isa<CXXRecordDecl>(D);
  }
  AttrHandling handleDeclAttribute(Sema &S, Decl *D, const ParsedAttr &) const override {
    if (!D->hasAttr<VisibilityAttr>())
      D->addAttr(VisibilityAttr::CreateImplicit(S.Context, VisibilityAttr::Default));
    return AttributeApplied;
  }
};

} // namespace

// GexIcall's question: the struct-FP mask of the function named `name` in
// this translation unit, or null when it has none. The mask is its result
// ('R' a struct of one float or double, '.' anything else), then one letter
// for each parameter clang knows, `this` first for a method ('R', 'e' an
// empty record that wasm drops, '.' anything else). A struct return through
// a hidden pointer is not among them (the IR's sret parameter is skipped).
extern "C" __attribute__((visibility("default"))) const char *gexw_struct_fp(const char *name) {
  auto &m = structFPs();
  auto it = m.find(name);
  return it == m.end() ? nullptr : it->second.c_str();
}

static ParsedAttrInfoRegistry::Add<DllAttr> Y("gexw-dll", "dllexport and dllimport as default visibility");
static FrontendPluginRegistry::Add<Action> X("gex-llp64", "Windows x64 data model (LLP64) on wasm64");
