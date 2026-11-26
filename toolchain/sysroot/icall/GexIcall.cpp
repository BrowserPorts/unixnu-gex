// The ICALL pass: native Wine code calling
// through a function pointer may be calling application (guest x86) code.
//
// Every indirect call becomes the select form, the fastest one measured:
//
//   gexw_set_icall_target(p)
//   callee = p < 0x3f0000 ? p : __gexw_exit.<sig>
//   call callee(args...)
//
// or on wasm64 the branch form (see run()):
//
//   if (p < limit) call p(args...)
//   else { gexw_set_icall_target(p); call __gexw_exit.<sig>(args...) }
//
// A function pointer below 0x3f0000 (gex-kernel's NT trampolines) is a function-table index (native
// code), called directly; anything else is a guest address. On wasm64 the
// bound is not that constant but the thread's `gex.icall_limit64` (see
// limit() below): the slots its table holds, so an index into a module
// another thread has just installed takes the exit stub until this thread
// has caught up, and the host catches it up before it runs the function. The exit stub,
// one per wasm signature (linkonce_odr), lays the arguments out as i386
// stack words and calls __gexw_guest_call / __gexw_guest_call_fp
// (gexw_rt.c), which run the guest function through gex's function table
// and hand back EDX:EAX or ST0.
//
// Build: toolchain/sysroot/icall/build.sh. Use: clang -fpass-plugin=GexIcall.so.
// Variadic indirect calls are left alone (counted; GEXW_ICALL_STATS=1).
//
// Entry thunks (the other direction, ARM64EC's name): a native function
// whose address is taken may reach i386 code as a function-table index (a
// window procedure in a class, a COM vtable). For each such function the
// pass writes `__gexe.<name>`, an entry adapter like winebuild's (gex's
// F_body through gexrt's __gexw_entry: the arguments from the guest stack,
// the result in EAX, EDX:EAX or ST0, the arguments popped if the function
// is stdcall, which corecrt.h marks with annotate("gex.stdcall")), and
// records the pair { function, thunk } in the data section `gexw_entries`.
// gex binds each thunk at its function's table index as a guest address,
// so a guest call or jump to that index runs the native function.
//
// On wasm64 (64-bit Wine: LLP64 lowered to wasm32) the
// guest is x86-64 and there is one calling convention, Win64's: the exit
// stubs lay the arguments out as 8-byte slots (__gexw_guest_call64 puts the
// first four in RCX, RDX, R8, R9 and XMM0-3 alike, and every slot on the
// stack past the home area), the entry thunks read them back by slot
// (__gexw_arg, __gexw_argf64, ...), and a struct by value that is not 1, 2,
// 4 or 8 bytes travels by reference, as Win64 passes it. The pass also
// records each defined function's signature with what the wasm types lose
// (a byval struct's size, a struct return's size, pointer or integer) in
// the custom section gexw.sig64, which winebuild's wasm64 adapters read
// (sig64() below). On wasm32 too: winebuild's i386 adapters take a struct
// by value of one word, which the .spec spells as an int, by reference from
// it.
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/ReplaceConstant.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/LICM.h"
#include "llvm/Transforms/Scalar/LoopPassManager.h"
#include <map>
#include <set>
#include <cstdlib>
#include <cstring>
#include <cstdio>

using namespace llvm;

namespace {

constexpr uint64_t ICALL_LIMIT = 0x3f0000;

std::string sigName(FunctionType *FT, const DataLayout &DL) {
  auto t = [&](Type *T) -> std::string {
    if (T->isVoidTy()) return "v";
    if (T->isPointerTy()) return "p";
    if (T->isFloatTy()) return "f";
    if (T->isDoubleTy()) return "d";
    if (T->isIntegerTy()) return "i" + std::to_string(T->getIntegerBitWidth());
    std::string s;
    raw_string_ostream o(s);
    T->print(o);
    return "x" + std::to_string(std::hash<std::string>()(o.str()) & 0xffff);
  };
  std::string s = "__gexw_exit." + t(FT->getReturnType()) + "_";
  for (Type *P : FT->params()) s += t(P);
  return s;
}

static bool structFP(Function &F, bool &ret, std::vector<bool> &ps);

// The signature string of gexw.sig64: result, ':', parameters; v void,
// i an integer of up to 32 bits, I a 64-bit integer, p a pointer, f float,
// d double, X a 128-bit integer, bN a struct of N bytes by value, and a
// leading sN for a struct of N bytes returned through the first parameter;
// F and D a struct of one float or one double, which wasm passes as the
// scalar and Win64 as a 4- or 8-byte struct, in an integer slot (structFP).
std::string sig64(Function &F, const DataLayout &DL) {
  FunctionType *FT = F.getFunctionType();
  auto t = [&](Type *T) -> std::string {
    if (T->isVoidTy()) return "v";
    if (T->isPointerTy()) return "p";
    if (T->isFloatTy()) return "f";
    if (T->isDoubleTy()) return "d";
    if (T->isIntegerTy() && T->getIntegerBitWidth() <= 32) return "i";
    if (T->isIntegerTy(64)) return "I";
    if (T->isIntegerTy(128)) return "X";
    return "?";
  };
  std::string s, ps;
  unsigned first = 0;
  bool retInt;
  std::vector<bool> intFP;
  structFP(F, retInt, intFP);
  auto fp = [](Type *T) { return T->isFloatTy() ? "F" : "D"; };
  if (FT->getNumParams() && F.hasParamAttribute(0, Attribute::StructRet)) {
    s = "s" + std::to_string(DL.getTypeAllocSize(F.getParamStructRetType(0)));
    first = 1;
  } else {
    s = retInt ? fp(FT->getReturnType()) : t(FT->getReturnType());
  }
  for (unsigned i = first; i < FT->getNumParams(); i++) {
    if (Type *BT = F.getParamByValType(i)) ps += "b" + std::to_string(DL.getTypeAllocSize(BT));
    else if (intFP[i]) ps += fp(FT->getParamType(i));
    else ps += t(FT->getParamType(i));
  }
  if (FT->isVarArg()) ps += ".";
  return s + ":" + ps;
}

static bool smallStruct(uint64_t n) { return n == 1 || n == 2 || n == 4 || n == 8; }

// Which of F's float and double parameters (by IR index), and whether its
// float or double result, were a struct of that one scalar in the source
// (struct { double d; }): clang's wasm C ABI passes and returns such a struct
// as the scalar, where Win64 passes and returns it in an integer register,
// as any struct of 4 or 8 bytes. The IR has lost it; GexLLP64 (the clang
// plugin of the same compile) noted it from the AST: its gexw_struct_fp.
// False, all clear, when nothing says so (no plugin: rustc, or a compile
// without it), or when the note does not fit F's IR (then F is treated as
// before, its scalars as scalars).
static bool structFP(Function &F, bool &ret, std::vector<bool> &ps) {
  using Look = const char *(*)(const char *);
  static Look look = (Look)sys::DynamicLibrary::SearchForAddressOfSymbol("gexw_struct_fp");
  FunctionType *FT = F.getFunctionType();
  ret = false;
  ps.assign(FT->getNumParams(), false);
  const char *m = look ? look(F.getName().str().c_str()) : nullptr;
  if (!m || !*m) return false;
  auto fail = [&] {
    ret = false;
    ps.assign(FT->getNumParams(), false);
    return false;
  };
  bool sret = false;
  const char *c = m + 1;
  for (unsigned i = 0; i < FT->getNumParams(); i++) {
    if (F.hasParamAttribute(i, Attribute::StructRet)) {
      sret = true;
      continue;
    }
    while (*c == 'e') c++;
    if (!*c) return fail();
    if (*c == 'R') {
      Type *P = FT->getParamType(i);
      if (!(P->isFloatTy() || P->isDoubleTy()) || F.getParamByValType(i)) return fail();
      ps[i] = true;
    }
    c++;
  }
  while (*c == 'e') c++;
  if (*c) return fail();
  if (m[0] == 'R') {
    Type *R = FT->getReturnType();
    if (sret || !(R->isFloatTy() || R->isDoubleTy())) return fail();
    ret = true;
  }
  bool any = ret;
  for (bool b : ps) any |= b;
  return any;
}

struct GexIcall : PassInfoMixin<GexIcall> {
  bool Wasm64 = false;

  // The bound on wasm64: `gex.icall_limit64` (gex_abi::ftab::ICALL_LIMIT64;
  // the host has an i32 `gex.icall_limit` beside it for wasm32 code, which
  // still compares with 0x3f0000), a mutable global each thread's instances
  // import (one per wasmtime store, one per Worker), which the host keeps
  // at the slots that thread's table holds, raised as it catches up, never
  // past gex_abi::ftab::NATIVE_FN_TOP. An index at or above it is a module
  // installed since this thread last caught up: the exit stub takes it as
  // a guest address, gex's call-out catches the thread up, and the entry
  // thunk bound at that index runs the function. This thread's table only
  // grows, so any value it has read stays a safe bound for it: the load is
  // marked invariant, and LLVM may hoist it (and the compare, for a
  // loop-invariant pointer) as it would the constant. A stale value is at
  // worst low, and costs the exit stub's second look.
  Value *limit(Module &M, IRBuilder<> &B, Type *IP) {
    LoadInst *L = B.CreateLoad(IP, limitGlobal(M));
    L->setMetadata(LLVMContext::MD_invariant_load, MDNode::get(M.getContext(), {}));
    return L;
  }

  GlobalVariable *limitGlobal(Module &M) {
    const char *name = "__gexw_icall_limit_g";
    GlobalVariable *G = M.getGlobalVariable(name);
    if (!G) {
      G = new GlobalVariable(M, Type::getInt64Ty(M.getContext()), false, GlobalValue::ExternalLinkage, nullptr, name,
                             nullptr, GlobalValue::NotThreadLocal, 1);
      M.appendModuleInlineAsm(".import_module __gexw_icall_limit_g, gex\n"
                              ".import_name __gexw_icall_limit_g, icall_limit64\n");
    }
    return G;
  }

  Function *getTarget(Module &M, const char *name, FunctionType *FT) {
    return cast<Function>(M.getOrInsertFunction(name, FT).getCallee());
  }

  // The exit stub for calls of type FT (byval attributes are taken from the
  // first call site seen; they are part of the C type in practice).
  Function *exitStub(Module &M, CallBase &CB) {
    FunctionType *FT = CB.getFunctionType();
    const DataLayout &DL = M.getDataLayout();
    std::string name = sigName(FT, DL);
    // byval parameters change the stack layout: give them their own stubs.
    for (unsigned i = 0; i < FT->getNumParams(); i++)
      if (Type *BT = CB.getParamByValType(i))
        name += ".bv" + std::to_string(i) + "_" + std::to_string(DL.getTypeAllocSize(BT));
    // and so does a struct return (a pointer the stub writes, not a value):
    // `void f(int *, int)` and `struct s12 f(int)` are one wasm type, and a
    // stub of the other's layout dropped or shifted an argument
    if (FT->getNumParams() && CB.paramHasAttr(0, Attribute::StructRet))
      name += ".sr" + std::to_string(DL.getTypeAllocSize(CB.getParamStructRetType(0)));
    if (Function *F = M.getFunction(name)) return F;

    LLVMContext &C = M.getContext();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C);
    Type *Ptr = PointerType::get(C, 0);
    Function *F = Function::Create(FT, GlobalValue::LinkOnceODRLinkage, name, M);
    F->setVisibility(GlobalValue::HiddenVisibility);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr("gexw-no-icall");
    BasicBlock *BB = BasicBlock::Create(C, "entry", F);
    IRBuilder<> B(BB);
    if (Wasm64) {
      exitStub64(M, CB, F, B);
      return F;
    }

    // Count the i386 stack words.
    unsigned words = 0;
    for (unsigned i = 0; i < FT->getNumParams(); i++) {
      Type *P = FT->getParamType(i);
      if (Type *BT = CB.getParamByValType(i)) words += (DL.getTypeAllocSize(BT) + 3) / 4;
      else if (P->isIntegerTy(64) || P->isDoubleTy() || P->isFP128Ty()) words += 2;
      else words += 1;
    }
    Value *Buf = B.CreateAlloca(I32, B.getInt32(words ? words : 1));
    unsigned w = 0;
    for (unsigned i = 0; i < FT->getNumParams(); i++) {
      Argument *A = F->getArg(i);
      Type *P = A->getType();
      auto slot = [&](unsigned k) { return B.CreateGEP(I32, Buf, B.getInt32(k)); };
      if (Type *BT = CB.getParamByValType(i)) {
        uint64_t sz = DL.getTypeAllocSize(BT);
        B.CreateMemCpy(slot(w), Align(4), A, Align(1), sz);
        w += (sz + 3) / 4;
      } else if (P->isIntegerTy(64) || P->isDoubleTy() || P->isFP128Ty()) {
        // (wasm32's long double is 128 bits wide; Windows' on i386, a double)
        Value *V = P->isIntegerTy(64) ? (Value *)A
                 : B.CreateBitCast(P->isFP128Ty() ? B.CreateFPTrunc(A, B.getDoubleTy()) : (Value *)A, I64);
        B.CreateStore(B.CreateTrunc(V, I32), slot(w));
        B.CreateStore(B.CreateTrunc(B.CreateLShr(V, 32), I32), slot(w + 1));
        w += 2;
      } else if (P->isPointerTy()) {
        B.CreateStore(B.CreatePtrToInt(A, I32), slot(w++));
      } else if (P->isFloatTy()) {
        B.CreateStore(B.CreateBitCast(A, I32), slot(w++));
      } else if (P->isIntegerTy()) {
        // i386 passes narrow integers widened to a word.
        B.CreateStore(B.CreateZExtOrTrunc(A, I32), slot(w++));
      } else {
        report_fatal_error("gex icall: unsupported parameter type in " + Twine(name));
      }
    }
    Function *Get = getTarget(M, "gexw_get_icall_target", FunctionType::get(I32, false));
    Value *T = B.CreateCall(Get);
    Type *R = FT->getReturnType();
    if (R->isFloatingPointTy()) {
      Function *Call = getTarget(M, "__gexw_guest_call_fp", FunctionType::get(B.getDoubleTy(), {I32, Ptr, I32}, false));
      Value *V = B.CreateCall(Call, {T, Buf, B.getInt32(words)});
      B.CreateRet(R->isFloatTy() ? B.CreateFPTrunc(V, R) : R->isFP128Ty() ? B.CreateFPExt(V, R) : V);
    } else {
      Function *Call = getTarget(M, "__gexw_guest_call", FunctionType::get(I64, {I32, Ptr, I32}, false));
      Value *V = B.CreateCall(Call, {T, Buf, B.getInt32(words)});
      if (R->isVoidTy()) B.CreateRetVoid();
      else if (R->isPointerTy()) B.CreateRet(B.CreateIntToPtr(B.CreateTrunc(V, I32), R));
      else if (R->isIntegerTy()) B.CreateRet(B.CreateTrunc(V, R));
      else report_fatal_error("gex icall: unsupported return type in " + Twine(name));
    }
    return F;
  }

  // The Win64 exit stub: every argument an 8-byte slot (see the top).
  void exitStub64(Module &M, CallBase &CB, Function *F, IRBuilder<> &B) {
    LLVMContext &C = M.getContext();
    const DataLayout &DL = M.getDataLayout();
    FunctionType *FT = F->getFunctionType();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C);
    Type *Ptr = PointerType::get(C, 0);
    unsigned first = 0;
    Value *SRet = nullptr;
    uint64_t sretSize = 0;
    if (FT->getNumParams() && CB.paramHasAttr(0, Attribute::StructRet)) {
      SRet = F->getArg(0);
      sretSize = DL.getTypeAllocSize(CB.getParamStructRetType(0));
      first = 1;
    }
    // An index this thread's table holds by now (`gex.icall_limit64` read
    // again: the caller's value may be one it read before a catch-up): call
    // it here. Anything else goes out as a guest call.
    Function *Get = getTarget(M, "gexw_get_icall_target", FunctionType::get(I64, false));
    Value *T = B.CreateCall(Get);
    {
      GlobalVariable *Held = limitGlobal(M);
      BasicBlock *OwnBB = BasicBlock::Create(C, "own", F), *ExitBB = BasicBlock::Create(C, "exit", F);
      B.CreateCondBr(B.CreateICmpULT(T, B.CreateLoad(I64, Held)), OwnBB, ExitBB);
      IRBuilder<> OB(OwnBB);
      SmallVector<Value *, 8> Args;
      for (Argument &A : F->args()) Args.push_back(&A);
      CallInst *CI = OB.CreateCall(FT, OB.CreateIntToPtr(T, Ptr), Args);
      // the call site's parameter attributes (byval, sret), as the select's
      for (unsigned i = 0; i < FT->getNumParams(); i++)
        CI->setAttributes(CI->getAttributes().addParamAttributes(C, i, AttrBuilder(C, CB.getAttributes().getParamAttrs(i))));
      if (FT->getReturnType()->isVoidTy()) OB.CreateRetVoid();
      else OB.CreateRet(CI);
      B.SetInsertPoint(ExitBB);
    }
    unsigned n = FT->getNumParams() - first + (SRet && !smallStruct(sretSize) ? 1 : 0);
    Value *Buf = B.CreateAlloca(I64, B.getInt32(n ? n : 1));
    unsigned w = 0;
    auto slot = [&](unsigned k) { return B.CreateGEP(I64, Buf, B.getInt32(k)); };
    // a large struct return: the caller's buffer is the first argument
    if (SRet && !smallStruct(sretSize)) B.CreateStore(B.CreatePtrToInt(SRet, I64), slot(w++));
    for (unsigned i = first; i < FT->getNumParams(); i++) {
      Argument *A = F->getArg(i);
      Type *P = A->getType();
      if (Type *BT = CB.getParamByValType(i)) {
        uint64_t sz = DL.getTypeAllocSize(BT);
        if (smallStruct(sz)) {
          B.CreateStore(B.getInt64(0), slot(w));
          B.CreateMemCpy(slot(w), Align(8), A, Align(1), sz);
        } else {
          B.CreateStore(B.CreatePtrToInt(A, I64), slot(w));  // by reference
        }
      } else if (P->isPointerTy()) {
        B.CreateStore(B.CreatePtrToInt(A, I64), slot(w));
      } else if (P->isDoubleTy()) {
        B.CreateStore(B.CreateBitCast(A, I64), slot(w));
      } else if (P->isFloatTy()) {
        B.CreateStore(B.CreateZExt(B.CreateBitCast(A, I32), I64), slot(w));
      } else if (P->isIntegerTy(128)) {
        // Win64 passes a 16-byte value by reference
        Value *T = B.CreateAlloca(P);
        B.CreateStore(A, T);
        B.CreateStore(B.CreatePtrToInt(T, I64), slot(w));
      } else if (P->isIntegerTy()) {
        B.CreateStore(B.CreateZExtOrTrunc(A, I64), slot(w));
      } else {
        report_fatal_error("gex icall: unsupported parameter type in " + F->getName());
      }
      w++;
    }
    Type *R = FT->getReturnType();
    Function *Call = getTarget(M, "__gexw_guest_call64", FunctionType::get(I64, {I64, Ptr, I32, I32}, false));
    Value *V = B.CreateCall(Call, {T, Buf, B.getInt32(w), B.getInt32(R->isFloatingPointTy() ? 1 : 0)});
    if (SRet && smallStruct(sretSize)) {
      // a 1, 2, 4 or 8-byte struct comes back in RAX
      Value *Tmp = B.CreateAlloca(I64);
      B.CreateStore(V, Tmp);
      B.CreateMemCpy(SRet, Align(1), Tmp, Align(8), sretSize);
    }
    if (R->isVoidTy()) B.CreateRetVoid();
    else if (R->isDoubleTy()) B.CreateRet(B.CreateBitCast(V, R));
    else if (R->isFloatTy()) B.CreateRet(B.CreateBitCast(B.CreateTrunc(V, I32), R));
    else if (R->isPointerTy()) B.CreateRet(B.CreateIntToPtr(V, R));
    else if (R->isIntegerTy() && R->getIntegerBitWidth() <= 64) B.CreateRet(B.CreateZExtOrTrunc(V, R));
    else report_fatal_error("gex icall: unsupported return type in " + F->getName());
  }

  // A C++ declaration clang gave its placeholder type: `void ()`, which it
  // uses for a function whose real type this object cannot lower (a
  // parameter or result of a type incomplete here: `unique_ptr<LinkEvent>`,
  // `already_AddRefed<T>`), and which code here never calls: only its
  // address is used (a vtable's initialiser, a call's argument, a store).
  // Its type is not the function's, so nothing may be made from it: a
  // thunk calling it through `void ()` links to a trap (wcc64's mismatch
  // check). The address it hands out is the definition's, which comes with
  // the definition's own thunk and facts. (A direct call names the type
  // the caller knows; a declaration with one is left alone.) That holds
  // as every object of a gexcc-win module goes through this pass, its C++
  // runtime and archives included; a real `void f()` defined in an object
  // that did not (assembly, a foreign archive) and only addressed here gets
  // no thunk, and gex finds no facts for its address.
  static bool placeholderDecl(Function &F) {
    if (!F.isDeclaration() || !F.getName().starts_with("_Z")) return false;
    FunctionType *T = F.getFunctionType();
    if (!T->getReturnType()->isVoidTy() || T->getNumParams() || T->isVarArg()) return false;
    for (const Use &U : F.uses())
      if (auto *CB = dyn_cast<CallBase>(U.getUser()))
        if (CB->isCallee(&U)) return false;
    return true;
  }

  // Is F's address taken by anything other than calls and metadata?
  static bool escapes(Function &F) {
    for (const Use &U : F.uses()) {
      const User *Us = U.getUser();
      if (auto *CB = dyn_cast<CallBase>(Us))
        if (CB->isCallee(&U)) continue;
      // (a function's personality, as wasm EH's __gxx_wasm_personality_v0,
      // is no address anything holds: the back end drops it, and libc++abi
      // defines no such symbol, so a record naming it failed every link of
      // a C++ program with exceptions)
      if (isa<Function>(Us)) continue;
      if (auto *GV = dyn_cast<GlobalVariable>(Us))
        if (GV->getSection() == "llvm.metadata") continue;
      if (auto *CE = dyn_cast<Constant>(Us)) {
        // annotation and used-list entries are constant structs/arrays
        // reachable only from llvm.metadata globals
        bool meta = true;
        SmallVector<const User *, 8> work{CE};
        while (!work.empty() && meta) {
          const User *X = work.pop_back_val();
          if (auto *G = dyn_cast<GlobalVariable>(X)) {
            if (G->getSection() != "llvm.metadata" && G->getName() != "llvm.used" &&
                G->getName() != "llvm.compiler.used")
              meta = false;
            continue;
          }
          if (!isa<Constant>(X)) { meta = false; break; }
          if (X->use_empty()) continue;
          for (const User *Y : X->users()) work.push_back(Y);
        }
        if (meta) continue;
      }
      return true;
    }
    return false;
  }

  // The i386 convention a native function has towards the guest, from its
  // annotation (llvm.global.annotations): corecrt.h/minwindef.h's
  // __stdcall, __thiscall, __fastcall on wasm32.
  enum Conv { CDECL, STDCALL, THISCALL, FASTCALL };
  static std::map<Function *, Conv> conventions(Module &M) {
    std::map<Function *, Conv> out;
    GlobalVariable *A = M.getGlobalVariable("llvm.global.annotations");
    if (!A || !A->hasInitializer()) return out;
    auto *Arr = dyn_cast<ConstantArray>(A->getInitializer());
    if (!Arr) return out;
    for (Value *Op : Arr->operands()) {
      auto *S = dyn_cast<ConstantStruct>(Op);
      if (!S || S->getNumOperands() < 2) continue;
      auto *F = dyn_cast<Function>(S->getOperand(0)->stripPointerCasts());
      auto *Str = dyn_cast<GlobalVariable>(S->getOperand(1)->stripPointerCasts());
      if (!F || !Str || !Str->hasInitializer()) continue;
      if (auto *CDA = dyn_cast<ConstantDataArray>(Str->getInitializer())) {
        if (!CDA->isCString()) continue;
        StringRef a = CDA->getAsCString();
        if (a == "gex.stdcall") out.emplace(F, STDCALL);
        else if (a == "gex.thiscall") out[F] = THISCALL;
        else if (a == "gex.fastcall") out[F] = FASTCALL;
      }
    }
    return out;
  }

  // The entry thunk of F (see the top), or null if its signature has no
  // i386 shape here.
  Function *entryThunk(Module &M, Function &F, Conv conv) {
    LLVMContext &C = M.getContext();
    const DataLayout &DL = M.getDataLayout();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *F32 = Type::getFloatTy(C),
         *F64 = Type::getDoubleTy(C);
    Type *Ptr = PointerType::get(C, 0);
    FunctionType *FT = F.getFunctionType();
    if (FT->isVarArg()) return nullptr;
    if (Wasm64) return entryThunk64(M, F);
    FunctionType *BodyT = FunctionType::get(I32, {I32, I32, I32, I64}, false);
    std::string base = "__gexe." + F.getName().str();
    Function *Body = Function::Create(BodyT, GlobalValue::InternalLinkage, base + ".body", M);
    Body->addFnAttr("gexw-no-icall");
    BasicBlock *BB = BasicBlock::Create(C, "entry", Body);
    IRBuilder<> B(BB);
    Value *Ctx = Body->getArg(0), *Ret = Body->getArg(3);
    auto helper = [&](const char *n, Type *R, ArrayRef<Type *> P) {
      return M.getOrInsertFunction(n, FunctionType::get(R, P, false));
    };
    unsigned off = 0, first = 0;
    std::vector<Value *> args;
    // A struct return: 1, 2, 4 or 8 bytes come back in EDX:EAX (MSVC's
    // i386 rule); larger ones through the caller's hidden pointer, the
    // first stack word, which is also the result.
    Value *SRet = nullptr;
    uint64_t sretSize = 0;
    bool sretReg = false;
    if (FT->getNumParams() && F.hasParamAttribute(0, Attribute::StructRet)) {
      Type *ST = F.getParamStructRetType(0);
      sretSize = DL.getTypeAllocSize(ST);
      sretReg = sretSize == 1 || sretSize == 2 || sretSize == 4 || sretSize == 8;
      if (sretReg) {
        SRet = B.CreateAlloca(I64);
        B.CreateStore(B.getInt64(0), SRet);
        args.push_back(SRet);
      } else {
        SRet = B.CreateCall(helper("__gexw_arg32", I32, {I32, I32}), {Ctx, B.getInt32(0)});
        args.push_back(B.CreateIntToPtr(SRet, Ptr));
        off = 4;
      }
      first = 1;
    }
    // thiscall: `this` in ECX; fastcall: the first two word-sized integer
    // or pointer arguments in ECX and EDX. The rest are on the stack, and
    // the callee pops them (as stdcall).
    unsigned regs = 0, maxregs = conv == THISCALL ? 1 : conv == FASTCALL ? 2 : 0;
    for (unsigned i = first; i < FT->getNumParams(); i++) {
      Type *P = FT->getParamType(i);
      if (regs < maxregs && !F.getParamByValType(i) &&
          (P->isPointerTy() || (P->isIntegerTy() && P->getIntegerBitWidth() <= 32))) {
        Value *A = B.CreateCall(helper("__gexw_reg", I32, {I32, I32}), {Ctx, B.getInt32(regs == 0 ? 1 : 2)});
        args.push_back(P->isPointerTy() ? B.CreateIntToPtr(A, P) : B.CreateTrunc(A, P));
        regs++;
        continue;
      }
      regs = maxregs;  /* fastcall: past a stack argument, the rest are too */
      if (Type *BT = F.getParamByValType(i)) {
        Value *A = B.CreateCall(helper("__gexw_argptr", I32, {I32, I32}), {Ctx, B.getInt32(off)});
        args.push_back(B.CreateIntToPtr(A, Ptr));
        off += (DL.getTypeAllocSize(BT) + 3) & ~3u;
      } else if (P->isIntegerTy(64)) {
        args.push_back(B.CreateCall(helper("__gexw_arg64", I64, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 8;
      } else if (P->isDoubleTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf64", F64, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 8;
      } else if (P->isFloatTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf32", F32, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 4;
      } else if (P->isPointerTy()) {
        Value *A = B.CreateCall(helper("__gexw_arg32", I32, {I32, I32}), {Ctx, B.getInt32(off)});
        args.push_back(B.CreateIntToPtr(A, P));
        off += 4;
      } else if (P->isIntegerTy() && P->getIntegerBitWidth() <= 32) {
        Value *A = B.CreateCall(helper("__gexw_arg32", I32, {I32, I32}), {Ctx, B.getInt32(off)});
        args.push_back(B.CreateTrunc(A, P));
        off += 4;
      } else {
        Body->eraseFromParent();
        return nullptr;
      }
    }
    unsigned pop = conv == CDECL ? 0 : off;
    Value *R = B.CreateCall(FT, &F, args);
    Type *RT = FT->getReturnType();
    Value *Out;
    if (SRet && sretReg) {
      Value *V = B.CreateLoad(I64, SRet);
      Out = B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I32, I64}), {Ctx, Ret, B.getInt32(pop), V});
    } else if (SRet) {
      Out = B.CreateCall(helper("__gexw_ret32", I32, {I32, I64, I32, I32}), {Ctx, Ret, B.getInt32(pop), SRet});
    } else if (RT->isVoidTy()) {
      Out = B.CreateCall(helper("__gexw_ret32", I32, {I32, I64, I32, I32}), {Ctx, Ret, B.getInt32(pop), B.getInt32(0)});
    } else if (RT->isFloatTy() || RT->isDoubleTy()) {
      Value *V = RT->isFloatTy() ? B.CreateFPExt(R, F64) : R;
      Out = B.CreateCall(helper("__gexw_ret_fp", I32, {I32, I64, I32, F64}), {Ctx, Ret, B.getInt32(pop), V});
    } else if (RT->isIntegerTy(64)) {
      Out = B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I32, I64}), {Ctx, Ret, B.getInt32(pop), R});
    } else if (RT->isPointerTy() || (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32)) {
      Value *V = RT->isPointerTy() ? B.CreatePtrToInt(R, I32) : B.CreateZExtOrTrunc(R, I32);
      Out = B.CreateCall(helper("__gexw_ret32", I32, {I32, I64, I32, I32}), {Ctx, Ret, B.getInt32(pop), V});
    } else {
      Body->eraseFromParent();
      return nullptr;
    }
    B.CreateRet(Out);

    Function *T = Function::Create(BodyT, GlobalValue::InternalLinkage, base, M);
    T->addFnAttr("gexw-no-icall");
    IRBuilder<> TB(BasicBlock::Create(C, "entry", T));
    FunctionCallee Entry = helper("__gexw_entry", I32, {I32, I32, I32, I64, Ptr});
    TB.CreateRet(TB.CreateCall(Entry, {T->getArg(0), T->getArg(1), T->getArg(2), T->getArg(3), Body}));
    return T;
  }

  // The Win64 entry thunk of F: argument k (after a struct return's
  // pointer, if any) is slot k (see the top). Null if a type has no Win64
  // shape here.
  Function *entryThunk64(Module &M, Function &F) {
    LLVMContext &C = M.getContext();
    const DataLayout &DL = M.getDataLayout();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *F32 = Type::getFloatTy(C),
         *F64 = Type::getDoubleTy(C);
    Type *Ptr = PointerType::get(C, 0);
    FunctionType *FT = F.getFunctionType();
    FunctionType *BodyT = FunctionType::get(I32, {I32, I32, I32, I64}, false);
    std::string base = "__gexe." + F.getName().str();
    Function *Body = Function::Create(BodyT, GlobalValue::InternalLinkage, base + ".body", M);
    Body->addFnAttr("gexw-no-icall");
    IRBuilder<> B(BasicBlock::Create(C, "entry", Body));
    Value *Ctx = Body->getArg(0), *Ret = Body->getArg(3);
    auto helper = [&](const char *n, Type *R, ArrayRef<Type *> P) {
      return M.getOrInsertFunction(n, FunctionType::get(R, P, false));
    };
    auto arg = [&](unsigned k) { return B.CreateCall(helper("__gexw_arg", I64, {I32, I32}), {Ctx, B.getInt32(k)}); };
    std::vector<Value *> args;
    unsigned k = 0, first = 0;
    Value *SRet = nullptr;
    bool sretReg = false;
    if (FT->getNumParams() && F.hasParamAttribute(0, Attribute::StructRet)) {
      sretReg = smallStruct(DL.getTypeAllocSize(F.getParamStructRetType(0)));
      if (sretReg) {
        SRet = B.CreateAlloca(I64);
        B.CreateStore(B.getInt64(0), SRet);
      } else {
        SRet = B.CreateIntToPtr(arg(k++), Ptr);
      }
      args.push_back(SRet);
      first = 1;
    }
    // (a struct of one float or double: Win64's integer slot, as its bits)
    bool retInt;
    std::vector<bool> intFP;
    structFP(F, retInt, intFP);
    for (unsigned i = first; i < FT->getNumParams(); i++, k++) {
      Type *P = FT->getParamType(i);
      if (Type *BT = F.getParamByValType(i)) {
        if (smallStruct(DL.getTypeAllocSize(BT)))
          args.push_back(B.CreateIntToPtr(B.CreateCall(helper("__gexw_argptr", I64, {I32, I32}), {Ctx, B.getInt32(k)}), Ptr));
        else
          args.push_back(B.CreateIntToPtr(arg(k), Ptr));
      } else if (intFP[i]) {
        args.push_back(P->isDoubleTy() ? B.CreateBitCast(arg(k), F64) : B.CreateBitCast(B.CreateTrunc(arg(k), I32), F32));
      } else if (P->isPointerTy()) {
        args.push_back(B.CreateIntToPtr(arg(k), P));
      } else if (P->isDoubleTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf64", F64, {I32, I32}), {Ctx, B.getInt32(k)}));
      } else if (P->isFloatTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf32", F32, {I32, I32}), {Ctx, B.getInt32(k)}));
      } else if (P->isIntegerTy(128)) {
        args.push_back(B.CreateLoad(P, B.CreateIntToPtr(arg(k), Ptr)));
      } else if (P->isIntegerTy() && P->getIntegerBitWidth() <= 64) {
        args.push_back(B.CreateTrunc(arg(k), P));
      } else {
        Body->eraseFromParent();
        return nullptr;
      }
    }
    Value *R = B.CreateCall(FT, &F, args);
    Type *RT = FT->getReturnType();
    Value *Out;
    auto ret64 = [&](Value *V) {
      return B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I64}), {Ctx, Ret, V});
    };
    if (SRet && sretReg) Out = ret64(B.CreateLoad(I64, SRet));
    else if (SRet) Out = ret64(B.CreatePtrToInt(SRet, I64));
    else if (RT->isVoidTy()) Out = B.CreateCall(helper("__gexw_ret_void", I32, {I32, I64}), {Ctx, Ret});
    else if (retInt) Out = ret64(RT->isDoubleTy() ? B.CreateBitCast(R, I64) : B.CreateZExt(B.CreateBitCast(R, I32), I64));
    else if (RT->isDoubleTy()) Out = B.CreateCall(helper("__gexw_ret_f64", I32, {I32, I64, F64}), {Ctx, Ret, R});
    else if (RT->isFloatTy()) Out = B.CreateCall(helper("__gexw_ret_f32", I32, {I32, I64, F32}), {Ctx, Ret, R});
    else if (RT->isPointerTy()) Out = ret64(B.CreatePtrToInt(R, I64));
    else if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 64) Out = ret64(B.CreateZExt(R, I64));
    else {
      Body->eraseFromParent();
      return nullptr;
    }
    B.CreateRet(Out);

    Function *T = Function::Create(BodyT, GlobalValue::InternalLinkage, base, M);
    T->addFnAttr("gexw-no-icall");
    IRBuilder<> TB(BasicBlock::Create(C, "entry", T));
    FunctionCallee Entry = helper("__gexw_entry", I32, {I32, I32, I32, I64, Ptr});
    TB.CreateRet(TB.CreateCall(Entry, {T->getArg(0), T->getArg(1), T->getArg(2), T->getArg(3), Body}));
    return T;
  }

  // gexw.sig64: every function this object defines for others, with its
  // signature (sig64 above), as `name sig` lines.
  static void emitSigs(Module &M) {
    std::string text;
    for (Function &F : M) {
      if (F.isDeclaration() || F.hasLocalLinkage() || F.hasFnAttribute("gexw-no-icall") || F.isIntrinsic()) continue;
      StringRef n = F.getName();
      if (n.starts_with("__gexe.") || n.starts_with("llvm.")) continue;
      bool plain = true;
      for (char c : n) plain &= isalnum((unsigned char)c) || c == '_' || c == '$' || c == '.' || c == '@' || c == '?';
      if (!plain) continue;
      text += n.str() + " " + sig64(F, M.getDataLayout()) + "\\n";
    }
    if (!text.empty())
      M.appendModuleInlineAsm(".section .custom_section.gexw.sig64,\"\",@\n.ascii \"" + text + "\"\n");
  }

  // The pairs as a used, internal array in `section`.
  static void emitPairs(Module &M, const std::vector<std::pair<Function *, Function *>> &pairs,
                        const char *name, const char *section) {
    if (pairs.empty()) return;
    LLVMContext &C = M.getContext();
    Type *Ptr = PointerType::get(C, 0);
    StructType *PairT = StructType::get(Ptr, Ptr);
    std::vector<Constant *> elems;
    for (auto &[F, T] : pairs) elems.push_back(ConstantStruct::get(PairT, {F, T}));
    ArrayType *AT = ArrayType::get(PairT, elems.size());
    auto *G = new GlobalVariable(M, AT, true, GlobalValue::InternalLinkage, ConstantArray::get(AT, elems), name);
    G->setSection(section);
    G->setAlignment(Align(M.getDataLayout().getPointerSize()));
    appendToUsed(M, {G});
  }

  // ---- Class adapters (wasm64's default; wasm32 has thunks still) ----
  //
  // In place of a thunk per function, one adapter per class: the function's
  // wasm type and the facts that type does not say (gex_kernel::ftab::facts:
  // a struct return's kind, which parameters are small structs by value).
  // The adapter has the thunks' F_body shape and reads its target from
  // ctx::LAST_TARGET, which every guest transfer through the table sets, so
  // it serves every function of its class. For each class this object's
  // escaping functions use, the pass writes the adapter, its body, a
  // witness (a function of the class's wasm type, never called: gex reads
  // the class's wasm type from its table slot, whatever the link and
  // wasm-opt made of the types) and a directory record { adapter, witness,
  // facts } in the data section `gexw_adapters`; for each escaping function
  // whose facts are not 0, a record { function, facts } in `gexw_facts`. gex
  // finds a guest call's adapter by the callee's slot (FuncMap::get).

  // (and on a float or double parameter, the byval bit 1 << (2 + i) says a
  // struct of that one scalar, in its integer slot: see structFP)
  static constexpr uint32_t FACT_SRET_SMALL = 1, FACT_SRET_BIG = 2, FACT_RET_INT = 1u << 30, FACT_REFUSED = 1u << 31;
  static constexpr unsigned CTX_LAST_TARGET = 352;  // gex_abi ctx::LAST_TARGET

  // (the default; GEXW_ENTRY=thunks keeps the thunk per function)
  static bool classesMode() {
    const char *e = getenv("GEXW_ENTRY");
    return !e || strcmp(e, "thunks");
  }

  // wasm32's: opted into (GEXW_ENTRY=classes) until its legs pass
  static bool classesMode32() {
    const char *e = getenv("GEXW_ENTRY");
    return e && !strcmp(e, "classes");
  }

  // F's class: the canonical type of F as wasm sees it (pointers as i64,
  // integers of up to 32 bits as i32) in CT, and its facts. False, with
  // FACT_REFUSED, when the guest cannot call it.
  bool classOf(Function &F, FunctionType *&CT, uint32_t &facts) {
    LLVMContext &C = F.getContext();
    const DataLayout &DL = F.getParent()->getDataLayout();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C);
    FunctionType *FT = F.getFunctionType();
    facts = 0;
    auto canon = [&](Type *T) -> Type * {
      if (T->isPointerTy() || T->isIntegerTy(64)) return I64;
      if (T->isIntegerTy() && T->getIntegerBitWidth() <= 32) return I32;
      if (T->isFloatTy() || T->isDoubleTy() || T->isIntegerTy(128)) return T;
      return nullptr;
    };
    if (FT->isVarArg()) {
      facts = FACT_REFUSED;
      return false;
    }
    std::vector<Type *> ps;
    for (unsigned i = 0; i < FT->getNumParams(); i++) {
      Type *P = FT->getParamType(i);
      if (i == 0 && F.hasParamAttribute(0, Attribute::StructRet)) {
        facts |= smallStruct(DL.getTypeAllocSize(F.getParamStructRetType(0))) ? FACT_SRET_SMALL : FACT_SRET_BIG;
        ps.push_back(I64);
        continue;
      }
      if (Type *BT = F.getParamByValType(i)) {
        if (smallStruct(DL.getTypeAllocSize(BT))) {
          if (i >= 28) {
            facts = FACT_REFUSED;
            return false;
          }
          facts |= 1u << (2 + i);
        }
        ps.push_back(I64);
        continue;
      }
      Type *T = canon(P);
      if (!T) {
        facts = FACT_REFUSED;
        return false;
      }
      ps.push_back(T);
    }
    Type *R = FT->getReturnType();
    Type *RT = R->isVoidTy() ? R : canon(R);
    if (!RT || RT->isIntegerTy(128)) {
      facts = FACT_REFUSED;
      return false;
    }
    bool retInt;
    std::vector<bool> intFP;
    if (structFP(F, retInt, intFP)) {
      for (unsigned i = 0; i < intFP.size(); i++) {
        if (!intFP[i]) continue;
        if (i >= 28) {
          facts = FACT_REFUSED;
          return false;
        }
        facts |= 1u << (2 + i);
      }
      if (retInt) facts |= FACT_RET_INT;
    }
    CT = FunctionType::get(RT, ps, false);
    return true;
  }

  static std::string typeKey(FunctionType *CT) {
    auto t = [](Type *T) -> char {
      if (T->isVoidTy()) return 'v';
      if (T->isIntegerTy(32)) return 'i';
      if (T->isIntegerTy(64)) return 'I';
      if (T->isIntegerTy(128)) return 'X';
      if (T->isFloatTy()) return 'f';
      return 'd';
    };
    std::string s(1, t(CT->getReturnType()));
    s += '_';
    for (Type *P : CT->params()) s += t(P);
    return s;
  }

  // The witness of wasm type CT: a function never called, whose table slot
  // says the class's wasm type.
  Function *witness(Module &M, FunctionType *CT) {
    std::string name = "__gexw_ty." + typeKey(CT);
    if (Function *W = M.getFunction(name)) return W;
    Function *W = Function::Create(CT, GlobalValue::LinkOnceODRLinkage, name, M);
    W->setVisibility(GlobalValue::HiddenVisibility);
    W->addFnAttr("gexw-no-icall");
    W->addFnAttr(Attribute::NoInline);
    IRBuilder<> B(BasicBlock::Create(M.getContext(), "entry", W));
    B.CreateUnreachable();
    return W;
  }

  // The Win64 adapter of class (CT, facts): entryThunk64's body with the
  // target from ctx::LAST_TARGET.
  Function *adapter64(Module &M, FunctionType *CT, uint32_t facts) {
    char hex[16];
    snprintf(hex, sizeof hex, "%x", facts);
    std::string name = "__gexw_adapt." + typeKey(CT) + "." + hex;
    if (Function *A = M.getFunction(name)) return A;
    LLVMContext &C = M.getContext();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *F32 = Type::getFloatTy(C),
         *F64 = Type::getDoubleTy(C);
    Type *Ptr = PointerType::get(C, 0);
    FunctionType *BodyT = FunctionType::get(I32, {I32, I32, I32, I64}, false);
    Function *Body = Function::Create(BodyT, GlobalValue::LinkOnceODRLinkage, name + ".body", M);
    Body->setVisibility(GlobalValue::HiddenVisibility);
    Body->addFnAttr("gexw-no-icall");
    IRBuilder<> B(BasicBlock::Create(C, "entry", Body));
    Value *Ctx = Body->getArg(0), *Ret = Body->getArg(3);
    auto helper = [&](const char *n, Type *R, ArrayRef<Type *> P) {
      return M.getOrInsertFunction(n, FunctionType::get(R, P, false));
    };
    // the target first: a call-out below changes it
    Value *At = B.CreateIntToPtr(B.CreateAdd(B.CreateZExt(Ctx, I64), B.getInt64(CTX_LAST_TARGET)), Ptr);
    Value *Target = B.CreateIntToPtr(B.CreateLoad(I64, At), Ptr);
    auto arg = [&](unsigned k) { return B.CreateCall(helper("__gexw_arg", I64, {I32, I32}), {Ctx, B.getInt32(k)}); };
    std::vector<Value *> args;
    unsigned k = 0, first = 0;
    Value *SRet = nullptr;
    if (facts & FACT_SRET_SMALL) {
      SRet = B.CreateAlloca(I64);
      B.CreateStore(B.getInt64(0), SRet);
      args.push_back(B.CreatePtrToInt(SRet, I64));
      first = 1;
    } else if (facts & FACT_SRET_BIG) {
      SRet = arg(k++);
      args.push_back(SRet);
      first = 1;
    }
    for (unsigned i = first; i < CT->getNumParams(); i++, k++) {
      Type *P = CT->getParamType(i);
      bool bit = facts & (1u << (2 + i));
      if (bit && P->isDoubleTy()) args.push_back(B.CreateBitCast(arg(k), F64));
      else if (bit && P->isFloatTy()) args.push_back(B.CreateBitCast(B.CreateTrunc(arg(k), I32), F32));
      else if (bit) args.push_back(B.CreateCall(helper("__gexw_argptr", I64, {I32, I32}), {Ctx, B.getInt32(k)}));
      else if (P->isIntegerTy(64)) args.push_back(arg(k));
      else if (P->isIntegerTy(32)) args.push_back(B.CreateTrunc(arg(k), I32));
      else if (P->isIntegerTy(128)) args.push_back(B.CreateLoad(P, B.CreateIntToPtr(arg(k), Ptr)));
      else if (P->isDoubleTy()) args.push_back(B.CreateCall(helper("__gexw_argf64", F64, {I32, I32}), {Ctx, B.getInt32(k)}));
      else args.push_back(B.CreateCall(helper("__gexw_argf32", F32, {I32, I32}), {Ctx, B.getInt32(k)}));
    }
    Value *R = B.CreateCall(CT, Target, args);
    Type *RT = CT->getReturnType();
    auto ret64 = [&](Value *V) { return B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I64}), {Ctx, Ret, V}); };
    Value *Out;
    if (facts & FACT_SRET_SMALL) Out = ret64(B.CreateLoad(I64, SRet));
    else if (facts & FACT_SRET_BIG) Out = ret64(SRet);
    else if (RT->isVoidTy()) Out = B.CreateCall(helper("__gexw_ret_void", I32, {I32, I64}), {Ctx, Ret});
    else if (facts & FACT_RET_INT)
      Out = ret64(RT->isDoubleTy() ? B.CreateBitCast(R, I64) : B.CreateZExt(B.CreateBitCast(R, I32), I64));
    else if (RT->isDoubleTy()) Out = B.CreateCall(helper("__gexw_ret_f64", I32, {I32, I64, F64}), {Ctx, Ret, R});
    else if (RT->isFloatTy()) Out = B.CreateCall(helper("__gexw_ret_f32", I32, {I32, I64, F32}), {Ctx, Ret, R});
    else Out = ret64(RT->isIntegerTy(64) ? R : B.CreateZExt(R, I64));
    B.CreateRet(Out);

    Function *A = Function::Create(BodyT, GlobalValue::LinkOnceODRLinkage, name, M);
    A->setVisibility(GlobalValue::HiddenVisibility);
    A->addFnAttr("gexw-no-icall");
    IRBuilder<> AB(BasicBlock::Create(C, "entry", A));
    FunctionCallee Entry = helper("__gexw_entry", I32, {I32, I32, I32, I64, Ptr});
    AB.CreateRet(AB.CreateCall(Entry, {A->getArg(0), A->getArg(1), A->getArg(2), A->getArg(3), Body}));
    return A;
  }

  // Records of pointer-sized words in `section`, an internal used array
  // (with an all-zero record first, which gex skips: the section exists in
  // every object of this mode, so its bounds always link), and the bounds
  // `bounds` = { __start_<section>, __stop_<section> } (linkonce_odr).
  void emitRecords(Module &M, std::vector<std::vector<Constant *>> recs, unsigned words, const char *name,
                   const char *section, const char *bounds) {
    LLVMContext &C = M.getContext();
    Type *I64 = Type::getInt64Ty(C);
    Type *Ptr = PointerType::get(C, 0);
    // (wasm32's records are of 32-bit words: a table index relocates as one)
    Type *W = Wasm64 ? I64 : Type::getInt32Ty(C);
    std::vector<Type *> ft(words, W);
    StructType *RT = StructType::get(C, ft);
    std::vector<Constant *> elems;
    elems.push_back(Constant::getNullValue(RT));
    for (auto &r : recs) {
      std::vector<Constant *> f;
      for (Constant *c : r)
        f.push_back(c->getType()->isPointerTy() ? ConstantExpr::getPtrToInt(c, W)
                    : c->getType() == W ? c : ConstantInt::get(W, cast<ConstantInt>(c)->getZExtValue()));
      elems.push_back(ConstantStruct::get(RT, f));
    }
    ArrayType *AT = ArrayType::get(RT, elems.size());
    auto *G = new GlobalVariable(M, AT, true, GlobalValue::InternalLinkage, ConstantArray::get(AT, elems), name);
    G->setSection(section);
    G->setAlignment(Align(Wasm64 ? 8 : 4));
    appendToUsed(M, {G});
    if (!M.getNamedValue(bounds)) {
      std::string sec(section);
      auto ext = [&](const std::string &n) {
        return new GlobalVariable(M, Type::getInt8Ty(C), true, GlobalValue::ExternalLinkage, nullptr, n);
      };
      GlobalVariable *Start = ext("__start_" + sec), *Stop = ext("__stop_" + sec);
      ArrayType *BT = ArrayType::get(Ptr, 2);
      auto *Bd = new GlobalVariable(M, BT, true, GlobalValue::LinkOnceODRLinkage,
                                    ConstantArray::get(BT, {Start, Stop}), bounds);
      Bd->setAlignment(Align(Wasm64 ? 8 : 4));
      appendToUsed(M, {Bd});
    }
  }

  // i386 facts (their own encoding: gex reads facts as an opaque key, but
  // for FACT_REFUSED): the convention (bits 0-1), a struct return's kind
  // (bits 2-3), and up to four structs by value, six bits each from bit 4:
  // the parameters since the one before (or the first), 0 to 7, and its
  // stack words, 1 to 7 (so an entry is never 0).
  static constexpr uint32_t I_SRET_REG = 1u << 2, I_SRET_MEM = 1u << 3;

  // F's i386 class: its wasm32 type in CT (pointers and integers of up to
  // 32 bits as i32) and its facts. False when no adapter serves it: varargs
  // (FACT_REFUSED; the guest cannot call it), or a shape the facts cannot
  // say (facts 0; F keeps an entry thunk of its own).
  bool classOf32(Function &F, Conv conv, FunctionType *&CT, uint32_t &facts) {
    LLVMContext &C = F.getContext();
    const DataLayout &DL = F.getParent()->getDataLayout();
    Type *I32 = Type::getInt32Ty(C);
    FunctionType *FT = F.getFunctionType();
    facts = 0;
    if (FT->isVarArg()) {
      facts = FACT_REFUSED;
      return false;
    }
    auto canon = [&](Type *T) -> Type * {
      if (T->isPointerTy() || (T->isIntegerTy() && T->getIntegerBitWidth() <= 32)) return I32;
      if (T->isIntegerTy(64) || T->isFloatTy() || T->isDoubleTy()) return T;
      return nullptr;
    };
    uint32_t f = conv;
    unsigned nbv = 0, next = 0;
    std::vector<Type *> ps;
    for (unsigned i = 0; i < FT->getNumParams(); i++) {
      if (i == 0 && F.hasParamAttribute(0, Attribute::StructRet)) {
        f |= smallStruct(DL.getTypeAllocSize(F.getParamStructRetType(0))) ? I_SRET_REG : I_SRET_MEM;
        ps.push_back(I32);
        continue;
      }
      if (Type *BT = F.getParamByValType(i)) {
        uint64_t words = (DL.getTypeAllocSize(BT) + 3) / 4;
        if (nbv == 4 || i - next > 7 || words == 0 || words > 7) return false;
        f |= (uint32_t)((i - next) | words << 3) << (4 + 6 * nbv++);
        next = i + 1;
        ps.push_back(I32);
        continue;
      }
      Type *T = canon(FT->getParamType(i));
      if (!T) return false;
      ps.push_back(T);
    }
    Type *R = FT->getReturnType();
    Type *RT = R->isVoidTy() ? R : canon(R);
    if (!RT) return false;
    CT = FunctionType::get(RT, ps, false);
    facts = f;
    return true;
  }

  // The words of the by-value struct at parameter i in i386 facts, or 0.
  static unsigned byvalWords(uint32_t facts, unsigned i) {
    // (a struct return's parameter is the first: the count starts there)
    unsigned next = 0;
    for (unsigned k = 0; k < 4; k++) {
      uint32_t e = facts >> (4 + 6 * k) & 63;
      if (!e) return 0;
      unsigned at = next + (e & 7);
      if (at == i) return e >> 3;
      if (at > i) return 0;
      next = at + 1;
    }
    return 0;
  }

  // The i386 adapter of class (CT, facts): entryThunk's body with the
  // target from ctx::LAST_TARGET.
  Function *adapter32(Module &M, FunctionType *CT, uint32_t facts) {
    char hex[16];
    snprintf(hex, sizeof hex, "%x", facts);
    std::string name = "__gexw_adapt." + typeKey(CT) + "." + hex;
    if (Function *A = M.getFunction(name)) return A;
    LLVMContext &C = M.getContext();
    Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *F32 = Type::getFloatTy(C),
         *F64 = Type::getDoubleTy(C);
    Type *Ptr = PointerType::get(C, 0);
    FunctionType *BodyT = FunctionType::get(I32, {I32, I32, I32, I64}, false);
    Function *Body = Function::Create(BodyT, GlobalValue::LinkOnceODRLinkage, name + ".body", M);
    Body->setVisibility(GlobalValue::HiddenVisibility);
    Body->addFnAttr("gexw-no-icall");
    IRBuilder<> B(BasicBlock::Create(C, "entry", Body));
    Value *Ctx = Body->getArg(0), *Ret = Body->getArg(3);
    auto helper = [&](const char *n, Type *R, ArrayRef<Type *> P) {
      return M.getOrInsertFunction(n, FunctionType::get(R, P, false));
    };
    // the target first: a call-out below changes it
    Value *At = B.CreateIntToPtr(B.CreateAdd(Ctx, B.getInt32(CTX_LAST_TARGET)), Ptr);
    Value *Target = B.CreateIntToPtr(B.CreateTrunc(B.CreateLoad(I64, At), I32), Ptr);
    Conv conv = (Conv)(facts & 3);
    unsigned off = 0, first = 0;
    std::vector<Value *> args;
    Value *SRet = nullptr;
    if (facts & I_SRET_REG) {
      SRet = B.CreateAlloca(I64);
      B.CreateStore(B.getInt64(0), SRet);
      args.push_back(B.CreatePtrToInt(SRet, I32));
      first = 1;
    } else if (facts & I_SRET_MEM) {
      SRet = B.CreateCall(helper("__gexw_arg32", I32, {I32, I32}), {Ctx, B.getInt32(0)});
      args.push_back(SRet);
      off = 4;
      first = 1;
    }
    unsigned regs = 0, maxregs = conv == THISCALL ? 1 : conv == FASTCALL ? 2 : 0;
    for (unsigned i = first; i < CT->getNumParams(); i++) {
      Type *P = CT->getParamType(i);
      unsigned bw = byvalWords(facts, i);
      if (regs < maxregs && !bw && P->isIntegerTy(32)) {
        args.push_back(B.CreateCall(helper("__gexw_reg", I32, {I32, I32}), {Ctx, B.getInt32(regs == 0 ? 1 : 2)}));
        regs++;
        continue;
      }
      regs = maxregs;
      if (bw) {
        args.push_back(B.CreateCall(helper("__gexw_argptr", I32, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 4 * bw;
      } else if (P->isIntegerTy(64)) {
        args.push_back(B.CreateCall(helper("__gexw_arg64", I64, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 8;
      } else if (P->isDoubleTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf64", F64, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 8;
      } else if (P->isFloatTy()) {
        args.push_back(B.CreateCall(helper("__gexw_argf32", F32, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 4;
      } else {
        args.push_back(B.CreateCall(helper("__gexw_arg32", I32, {I32, I32}), {Ctx, B.getInt32(off)}));
        off += 4;
      }
    }
    unsigned pop = conv == CDECL ? 0 : off;
    Value *R = B.CreateCall(CT, Target, args);
    Type *RT = CT->getReturnType();
    Value *Out;
    auto ret32 = [&](Value *V) {
      return B.CreateCall(helper("__gexw_ret32", I32, {I32, I64, I32, I32}), {Ctx, Ret, B.getInt32(pop), V});
    };
    if (facts & I_SRET_REG)
      Out = B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I32, I64}), {Ctx, Ret, B.getInt32(pop), B.CreateLoad(I64, SRet)});
    else if (facts & I_SRET_MEM) Out = ret32(SRet);
    else if (RT->isVoidTy()) Out = ret32(B.getInt32(0));
    else if (RT->isFloatTy() || RT->isDoubleTy())
      Out = B.CreateCall(helper("__gexw_ret_fp", I32, {I32, I64, I32, F64}),
                         {Ctx, Ret, B.getInt32(pop), RT->isFloatTy() ? B.CreateFPExt(R, F64) : R});
    else if (RT->isIntegerTy(64))
      Out = B.CreateCall(helper("__gexw_ret", I32, {I32, I64, I32, I64}), {Ctx, Ret, B.getInt32(pop), R});
    else Out = ret32(R);
    B.CreateRet(Out);

    Function *A = Function::Create(BodyT, GlobalValue::LinkOnceODRLinkage, name, M);
    A->setVisibility(GlobalValue::HiddenVisibility);
    A->addFnAttr("gexw-no-icall");
    IRBuilder<> AB(BasicBlock::Create(C, "entry", A));
    FunctionCallee Entry = helper("__gexw_entry", I32, {I32, I32, I32, I64, Ptr});
    AB.CreateRet(AB.CreateCall(Entry, {A->getArg(0), A->getArg(1), A->getArg(2), A->getArg(3), Body}));
    return A;
  }

  // wasm32's class adapters: classAdapters' records, with the i386
  // conventions. A function a facts record names is pinned, so the
  // records go only where facts must: escaping functions, and a defined
  // function with a convention of its own that another object may hand
  // out (entryThunks' methods, and stdcall too: gex takes a function no
  // record names as cdecl). A function no class serves keeps its thunk.
  unsigned classAdapters32(Module &M) {
    LLVMContext &C = M.getContext();
    Type *I32 = Type::getInt32Ty(C);
    std::map<Function *, Conv> cv = conventions(M);
    std::vector<std::vector<Constant *>> dir, facts;
    std::vector<std::pair<Function *, Function *>> pairs;
    std::set<Function *> seen;
    for (Function &F : M) {
      if (F.hasFnAttribute("gexw-no-icall") || F.isIntrinsic()) continue;
      StringRef n = F.getName();
      if (n.starts_with("__gexw") || n.starts_with("__gexe.") || n.contains("gexp_") || n.starts_with("llvm.")) continue;
      Conv conv = cv.count(&F) ? cv[&F] : CDECL;
      bool own = conv != CDECL && !F.hasLocalLinkage();
      bool esc = escapes(F);
      if (!esc && !own) continue;
      // (a declaration's class is its definition's, whose object writes
      // the record; one whose convention this object knows says it too)
      if (F.isDeclaration() && conv == CDECL) continue;
      FunctionType *CT = nullptr;
      uint32_t f = 0;
      if (!classOf32(F, conv, CT, f)) {
        // (a function with no thunk either is said, so that no class of
        // its wasm type serves it)
        Function *T = f & FACT_REFUSED || F.isDeclaration() ? nullptr : entryThunk(M, F, conv);
        if (T) pairs.push_back({&F, T});
        else facts.push_back({&F, ConstantInt::get(I32, FACT_REFUSED)});
        continue;
      }
      if (f) facts.push_back({&F, ConstantInt::get(I32, f)});
      Function *A = adapter32(M, CT, f);
      if (seen.insert(A).second) dir.push_back({A, witness(M, CT), ConstantInt::get(I32, f)});
    }
    emitRecords(M, dir, 3, "__gexw_adapt.dir", "gexw_adapters", "__gexw_adapters");
    emitRecords(M, facts, 2, "__gexw_adapt.facts", "gexw_facts", "__gexw_facts");
    if (!pairs.empty()) emitPairs(M, pairs, "__gexe.pairs", "gexw_entries");
    return dir.size() + pairs.size();
  }

  unsigned classAdapters(Module &M) {
    LLVMContext &C = M.getContext();
    Type *I64 = Type::getInt64Ty(C);
    std::vector<std::vector<Constant *>> dir, facts;
    std::set<Function *> seen;
    std::vector<Function *> fs;
    for (Function &F : M) {
      if (F.hasFnAttribute("gexw-no-icall") || F.isIntrinsic()) continue;
      StringRef n = F.getName();
      if (n.starts_with("__gexw") || n.starts_with("__gexe.") || n.contains("gexp_") || n.starts_with("llvm.")) continue;
      // (a declaration's facts are its definition's; the object handing
      // out a function defined elsewhere still needs its class's adapter)
      if (escapes(F) && !placeholderDecl(F)) fs.push_back(&F);
    }
    for (Function *F : fs) {
      FunctionType *CT = nullptr;
      uint32_t f = 0;
      bool ok = classOf(*F, CT, f);
      if (f) facts.push_back({F, ConstantInt::get(I64, f)});
      if (!ok) continue;
      Function *A = adapter64(M, CT, f);
      if (seen.insert(A).second) dir.push_back({A, witness(M, CT), ConstantInt::get(I64, f)});
    }
    emitRecords(M, dir, 3, "__gexw_adapt.dir", "gexw_adapters", "__gexw_adapters");
    emitRecords(M, facts, 2, "__gexw_adapt.facts", "gexw_facts", "__gexw_facts");
    return dir.size();
  }

  unsigned entryThunks(Module &M) {
    std::map<Function *, Conv> cv = conventions(M);
    std::vector<std::pair<Function *, Function *>> pairs, decl_pairs;
    std::vector<Function *> fs, decls;
    for (Function &F : M) {
      if (F.hasFnAttribute("gexw-no-icall") || F.isIntrinsic()) continue;
      StringRef n = F.getName();
      if (n.starts_with("__gexw") || n.starts_with("__gexe.") || n.contains("gexp_") || n.starts_with("llvm.")) continue;
      if (F.isDeclaration()) {
        // A function defined elsewhere whose address this object hands out
        // (a table of server routines next to their definitions in another
        // object, a function imported from another DLL): a thunk of its
        // own, which gex binds only when no object defining the function
        // gave one (`gexw_entries_decl`): the definition knows its
        // convention, this object may not.
        // (not one whose type is clang's placeholder: `placeholderDecl`)
        if (escapes(F) && !placeholderDecl(F)) decls.push_back(&F);
        continue;
      }
      // (a thiscall method may be referenced only from a vtable written in
      // assembly, which the IR does not show: msvcrt's and msvcp's)
      bool method = cv.count(&F) && cv[&F] == THISCALL && !F.hasLocalLinkage();
      if (escapes(F) || method) fs.push_back(&F);
    }
    for (Function *F : fs)
      if (Function *T = entryThunk(M, *F, cv.count(F) ? cv[F] : CDECL))
        pairs.push_back({F, T});
    for (Function *F : decls)
      if (Function *T = entryThunk(M, *F, cv.count(F) ? cv[F] : CDECL))
        decl_pairs.push_back({F, T});
    emitPairs(M, pairs, "__gexe.pairs", "gexw_entries");
    emitPairs(M, decl_pairs, "__gexe.declpairs", "gexw_entries_decl");
    return pairs.size() + decl_pairs.size();
  }

  // Narrow integers (BYTE, BOOLEAN, CHAR, WCHAR, WORD, SHORT) where PE code meets this module's. Windows'
  // conventions leave the upper bits of a narrow argument or result undefined (MSVC passes a BYTE as `mov cl,
  // [mem]`); wasm's C ABI has the caller extend them and the callee rely on it. So no function defined here
  // relies on its caller's extension: its narrow parameters lose zeroext/signext, and codegen extends them on
  // entry instead. No indirect call (one that may reach guest code) relies on the callee's either: the call's
  // narrow result loses its attribute and is extended after the call. Callers still extend what they pass and
  // functions what they return, so a module built without this pass sees nothing change. A function with a
  // musttail call keeps its parameters' attributes (the call must match them).
  unsigned narrowInts(Module &M) {
    unsigned n = 0;
    auto narrow = [](Type *T) { return T->isIntegerTy() && T->getIntegerBitWidth() < 32; };
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      bool musttail = false;
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (!CB) continue;
          if (auto *CI = dyn_cast<CallInst>(CB); CI && CI->isMustTailCall()) musttail = true;
          if (CB->getCalledFunction() || CB->isInlineAsm() || !narrow(CB->getType())) continue;
          if (CB->hasRetAttr(Attribute::ZExt) || CB->hasRetAttr(Attribute::SExt)) {
            CB->removeRetAttr(Attribute::ZExt);
            CB->removeRetAttr(Attribute::SExt);
            n++;
          }
        }
      if (musttail) continue;
      for (Argument &A : F.args())
        if (narrow(A.getType()) && (A.hasAttribute(Attribute::ZExt) || A.hasAttribute(Attribute::SExt))) {
          A.removeAttr(Attribute::ZExt);
          A.removeAttr(Attribute::SExt);
          n++;
        }
    }
    return n;
  }

  // winecrt0's (unix_lib.c), linked into every module the pass builds:
  // dso_local, so a module without it fails its link rather than taking
  // another module's through GOT.mem
  static GlobalVariable *Base0(Module &M, Type *Ptr) {
    auto *G = cast<GlobalVariable>(M.getOrInsertGlobal("__gexw_image_base", Ptr));
    if (G->isDeclaration()) G->setDSOLocal(true);
    return G;
  }
  static bool reaches(const Constant *C, const Constant *T, SmallPtrSet<const Constant *, 16> &seen) {
    if (C == T) return true;
    if (isa<GlobalValue>(C) || !seen.insert(C).second) return false;
    for (const Use &O : C->operands())
      if (reaches(cast<Constant>(O.get()), T, seen)) return true;
    return false;
  }
  // `C` as a value at B, `T` in it being `V`
  static Value *materialize(Constant *C, Constant *T, Value *V, IRBuilder<> &B) {
    if (C == T) return V;
    // (a fresh set per level: quadratic in the nesting, which an
    // initialiser's is not deep enough to matter)
    SmallPtrSet<const Constant *, 16> seen;
    if (!reaches(C, T, seen)) return C;
    if (auto *CE = dyn_cast<ConstantExpr>(C)) {
      Instruction *I = CE->getAsInstruction();
      for (unsigned i = 0; i < I->getNumOperands(); i++)
        if (auto *O = dyn_cast<Constant>(I->getOperand(i))) I->setOperand(i, materialize(O, T, V, B));
      return B.Insert(I);
    }
    Value *Agg = PoisonValue::get(C->getType());
    for (unsigned i = 0; i < C->getNumOperands(); i++) {
      Value *E = materialize(cast<Constant>(C->getOperand(i)), T, V, B);
      Agg = C->getType()->isVectorTy() ? B.CreateInsertElement(Agg, E, B.getInt32(i)) : B.CreateInsertValue(Agg, E, i);
    }
    return Agg;
  }

  // `__ImageBase`, the module's own image (MSVC's and MinGW's linkers define
  // it; `(HMODULE)&__ImageBase` is a module's handle to itself): here no
  // linker can, since the module's PE image is mapped where the loader puts
  // it, and again elsewhere after a FreeLibrary and a new load while the
  // wasm instance stays. The loader writes that base into the module's own
  // `__gexw_image_base` (winecrt0) at each first mapping, so every use of
  // `__ImageBase`'s address reads it there, at the use. A use in a global's
  // initialiser cannot (it is fixed before any mapping): an error naming
  // the source file, never a wrong value.
  unsigned imageBase(Module &M) {
    GlobalVariable *IB = M.getGlobalVariable("__ImageBase", true);
    if (!IB || !IB->isDeclaration() || IB->use_empty()) return 0;
    LLVMContext &C = M.getContext();
    Type *Ptr = PointerType::get(C, 0);
    auto *Base = Base0(M, Ptr);
    // A function's const aggregate holding it (`const WNDCLASSW wc = {
    // .hInstance = (HMODULE)&__ImageBase }`: clang makes it a private
    // unnamed_addr constant it copies from, by memcpy or loads) is built
    // instead in a stack copy, one per function, filled before each use
    // with the loaded base in its __ImageBase parts. Only such a copy
    // source: an object whose own address can escape (a function's static
    // const, a file's const table, anything another global holds) would
    // get a dead and different address per use, so it stays an error,
    // below.
    for (GlobalVariable &G : make_early_inc_range(M.globals())) {
      if (&G == IB || !G.hasInitializer() || !G.isConstant() || !G.hasPrivateLinkage() || !G.hasGlobalUnnamedAddr())
        continue;
      SmallPtrSet<const Constant *, 16> seen;
      if (!reaches(G.getInitializer(), IB, seen)) continue;
      // (its constant-expression users made instructions first, which
      // changes nothing for a global then left alone: the optimiser's
      // partial copies read it through GEPs)
      convertUsersOfConstantsToInstructions({&G});
      std::function<bool(const Value *)> copied = [&](const Value *P) {
        return all_of(P->uses(), [&](const Use &U) {
          const User *Us = U.getUser();
          if (auto *L = dyn_cast<LoadInst>(Us)) return L->getPointerOperand() == P;
          if (auto *T = dyn_cast<MemTransferInst>(Us)) return T->getRawSource() == P && T->getRawDest() != P;
          if (auto *GEP = dyn_cast<GetElementPtrInst>(Us)) return GEP->getPointerOperand() == P && copied(GEP);
          return false;
        });
      };
      // (clang's copy source of a function's local aggregate, `__const.F.x`,
      // stands for that local: the optimiser may hand its address on in
      // place of the copy, within the local's lifetime, and one stack copy
      // per function serves it, its contents the same at every store)
      bool local = G.getName().starts_with("__const.") &&
                   all_of(G.users(), [](const User *U) { return isa<Instruction>(U); });
      if (!local && !copied(&G)) continue;
      std::map<Function *, AllocaInst *> copies;
      SmallVector<Use *, 8> gu;
      for (Use &U : G.uses()) gu.push_back(&U);
      for (Use *U : gu) {
        auto *I = cast<Instruction>(U->getUser());
        Instruction *At = I;
        if (auto *Phi = dyn_cast<PHINode>(I)) At = Phi->getIncomingBlock(*U)->getTerminator();
        AllocaInst *&Copy = copies[I->getFunction()];
        if (!Copy) {
          IRBuilder<> E(&*I->getFunction()->getEntryBlock().getFirstInsertionPt());
          Copy = E.CreateAlloca(G.getValueType(), nullptr, G.getName() + ".imagebase");
          Copy->setAlignment(G.getAlign().valueOrOne());
        }
        IRBuilder<> B(At);
        Value *V = B.CreateLoad(Ptr, Base, "imagebase");
        B.CreateAlignedStore(materialize(G.getInitializer(), IB, V, B), Copy, G.getAlign().valueOrOne());
        U->set(Copy);
      }
      G.eraseFromParent();
    }
    IB->removeDeadConstantUsers();
    // (constant expressions inside instructions become instructions, so each
    // use is an instruction's operand or a global's initialiser)
    convertUsersOfConstantsToInstructions({IB});
    unsigned n = 0;
    std::map<BasicBlock *, LoadInst *> atEnd;
    SmallVector<Use *, 16> uses;
    for (Use &U : IB->uses()) uses.push_back(&U);
    for (Use *U : uses) {
      auto *I = dyn_cast<Instruction>(U->getUser());
      if (!I) {
        C.emitError(Twine(M.getSourceFileName()) + ": __ImageBase in a global's initialiser: the module's "
                    "image base is known only once it is mapped (take it in code)");
        continue;
      }
      // (a phi's operand is read at the end of its incoming block, one
      // load there for every phi operand from that block: a switch's two
      // cases into one successor list it twice, with the same value)
      if (auto *Phi = dyn_cast<PHINode>(I)) {
        BasicBlock *From = Phi->getIncomingBlock(*U);
        LoadInst *&L = atEnd[From];
        if (!L) L = new LoadInst(Ptr, Base, "imagebase", From->getTerminator()->getIterator());
        U->set(L);
      } else {
        U->set(new LoadInst(Ptr, Base, "imagebase", I->getIterator()));
      }
      n++;
    }
    return n;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    Wasm64 = Triple(M.getTargetTriple()).getArch() == Triple::wasm64;
    Type *I32 = Type::getInt32Ty(C);
    // the pointer-sized integer a function pointer is compared as
    Type *IP = Wasm64 ? Type::getInt64Ty(C) : I32;
    unsigned narrowed = narrowInts(M);
    imageBase(M);
    emitSigs(M);
    unsigned thunks = getenv("GEXW_NO_ENTRY_THUNKS") ? 0
                      : Wasm64 && classesMode() ? classAdapters(M)
                      : !Wasm64 && classesMode32() ? classAdapters32(M)
                      : entryThunks(M);
    FunctionType *SetT = FunctionType::get(Type::getVoidTy(C), {IP}, false);
    // gexrt's setter of one variable: it returns and does not unwind (so a
    // limit load after it in a loop may still be hoisted)
    if (Function *Set = cast<Function>(M.getOrInsertFunction("gexw_set_icall_target", SetT).getCallee())) {
      Set->addFnAttr(Attribute::NoUnwind);
      Set->addFnAttr(Attribute::WillReturn);
    }
    unsigned done = 0, varargs = 0;
    std::vector<CallBase *> sites;
    for (Function &F : M) {
      if (F.isDeclaration() || F.hasFnAttribute("gexw-no-icall")) continue;
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *CB = dyn_cast<CallBase>(&I))
            if (!CB->getCalledFunction() && !CB->isInlineAsm() &&
                !isa<Function>(CB->getCalledOperand()->stripPointerCasts()))
              sites.push_back(CB);
    }
    for (CallBase *CB : sites) {
      if (CB->getFunctionType()->isVarArg()) {
        varargs++;
        continue;
      }
      Function *Stub = exitStub(M, *CB);
      IRBuilder<> B(CB);
      Value *Callee = CB->getCalledOperand();
      Value *P = B.CreatePtrToInt(Callee, IP);
      // (in a C++ catch funclet, with the call's funclet bundle: a call
      // there without one is dropped as unreachable by WinEHPrepare)
      SmallVector<OperandBundleDef, 1> Funclet;
      if (auto OB = CB->getOperandBundle(LLVMContext::OB_funclet)) Funclet.emplace_back(*OB);
      Value *Limit = Wasm64 ? limit(M, B, IP) : (Value *)ConstantInt::get(IP, ICALL_LIMIT);
      Value *Native = B.CreateICmpULT(P, Limit);
      // wasm64: the branch form, the stub called directly on its own path,
      // so the call_indirect only ever sees native targets: an engine that
      // speculates on a call_indirect's targets (V8 inlines the ones it has
      // seen) then does not keep speculating on the stub at a site that ran
      // while the limit was below its target. An invoke or a musttail call
      // keeps the select form.
      auto *Call = dyn_cast<CallInst>(CB);
      if (!Wasm64 || !Call || Call->isMustTailCall()) {
        B.CreateCall(M.getOrInsertFunction("gexw_set_icall_target", SetT), {P}, Funclet);
        CB->setCalledOperand(B.CreateSelect(Native, Callee, Stub));
        done++;
        continue;
      }
      MDNode *Likely = MDBuilder(C).createLikelyBranchWeights();
      Instruction *ThenT, *ElseT;
      SplitBlockAndInsertIfThenElse(Native, Call, &ThenT, &ElseT, Likely);
      auto *Fast = cast<CallInst>(Call->clone());
      Fast->insertBefore(ThenT->getIterator());
      // (the target for the stub only: a native callee does not read it)
      IRBuilder<> EB(ElseT);
      EB.CreateCall(M.getOrInsertFunction("gexw_set_icall_target", SetT), {P}, Funclet);
      auto *Slow = cast<CallInst>(Call->clone());
      Slow->setCalledOperand(Stub);
      Slow->insertBefore(ElseT->getIterator());
      if (!Call->getType()->isVoidTy()) {
        PHINode *Phi = PHINode::Create(Call->getType(), 2, "", Call->getIterator());
        Phi->addIncoming(Fast, Fast->getParent());
        Phi->addIncoming(Slow, Slow->getParent());
        Phi->takeName(Call);
        Call->replaceAllUsesWith(Phi);
      }
      Call->eraseFromParent();
      done++;
    }
    if (getenv("GEXW_ICALL_STATS"))
      errs() << "gex icall: " << M.getName() << ": " << done << " sites, " << varargs << " variadic left alone, "
             << thunks << " entry thunks, " << narrowed << " narrow integers extended here\n";
    return done || thunks || narrowed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "GexIcall", "0.1", [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
                  MPM.addPass(GexIcall());
                  // the limit's loads (invariant): one per function where
                  // they agree, and out of loops with the compare, as the
                  // optimizer did for the constant before this pass ran
                  FunctionPassManager FPM;
                  FPM.addPass(EarlyCSEPass(true));
                  FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass(LICMOptions()), true));
                  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                });
          }};
}
