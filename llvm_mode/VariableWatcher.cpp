/************************************************************************
        > File Name: VariableWatcher.cpp
        > Author: zinc
        > Mail: burymynamel@163.com
        > Created Time: Thu 24 Sep 2020 02:42:49 PM CST
 ************************************************************************/
#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <unordered_set>

//#define PASS_LOG
using namespace llvm;

namespace {

//----------------------
// New PM implementation
//----------------------
struct VariableWatcher : PassInfoMixin<VariableWatcher> {

  bool runOnModule(Module &M) {
    unsigned inst_count = 0;
    unsigned VarNameNum = 0;
    bool Instrumented = false;
    auto &CTX = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(CTX);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(CTX);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(CTX);
    IntegerType *IntMapSizeTy = IntegerType::getIntNTy(CTX, MAP_SIZE_POW2);

#ifdef PASS_LOG
    /* printf function */
    // declaration of printf
    PointerType *PrintfArgTy = PointerType::getUnqual(Type::getInt8Ty(CTX));
    FunctionType *PrintfTy =
        FunctionType::get(IntegerType::getInt32Ty(CTX), PrintfArgTy,
                          /*IsVarArgs=*/true);
    FunctionCallee Printf = M.getOrInsertFunction("printf", PrintfTy);

    // set attributes
    Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
    PrintfF->setDoesNotThrow();
    PrintfF->addParamAttr(0, Attribute::NoCapture);
    PrintfF->addParamAttr(0, Attribute::ReadOnly);

    // inject a global variable that will hold the printf format string
    Constant *IntFormatStr = ConstantDataArray::getString(
        CTX, "[runtime log] file: %s name: %s value: %lld => %lld idx: %d "
             "counter: %d\n");
    Constant *FltFormatStr = ConstantDataArray::getString(
        CTX, "[runtime log] file: %s name: %s value: %lf => %lf\n");
    Constant *IntFormatStrVar =
        M.getOrInsertGlobal("IntFormatStr", IntFormatStr->getType());
    if (auto *Var = dyn_cast<GlobalVariable>(IntFormatStrVar)) {
      if (!Var->hasInitializer())
        Var->setInitializer(IntFormatStr);
      Var->setLinkage(GlobalValue::PrivateLinkage);
    }
    Constant *FltFormatStrVar =
        M.getOrInsertGlobal("FltFormatStr", FltFormatStr->getType());
    if (auto *Var = dyn_cast<GlobalVariable>(FltFormatStrVar)) {
      if (!Var->hasInitializer())
        Var->setInitializer(FltFormatStr);
      Var->setLinkage(GlobalValue::PrivateLinkage);
    }

    Constant *ModuleName =
        ConstantDataArray::getString(CTX, M.getModuleIdentifier());
    Constant *ModuleNameVar =
        M.getOrInsertGlobal("ModuleName", ModuleName->getType());
    dyn_cast<GlobalVariable>(ModuleNameVar)->setInitializer(ModuleName);
    dyn_cast<GlobalVariable>(ModuleNameVar)
        ->setLinkage(GlobalValue::PrivateLinkage);
    /* printf function end*/
#endif

    // get globals for share region
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__state_map_ptr");

    std::map<Value *, unsigned int> VariableSet;
    std::map<StringRef, unsigned int> MemberSet;

    outs() << "file: [" << M.getModuleIdentifier() << "]\n";
    for (auto &F : M) {
      outs() << "function: [" << F.getName() << "]\n";
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            bool IsMember = false;
            bool IsVariable = false;
            Value *PtrValue = SI->getPointerOperand();
            unsigned map_size = MAP_SIZE_POW2;
            unsigned int Num;
            ConstantInt *Number = nullptr;

            if (SI->getMetadata("labyrinth.label.state_describing.member")) {
              IsMember = true;
              StringRef MemName = PtrValue->getName();
              // outs() << "member: " << MemName << "\n";

              // trim member variable number
              size_t len = MemName.size();
              for (size_t i = 0; i < len; ++i) {
                if (isDigit(MemName[i])) {
                  MemName = MemName.take_front(i);
                  // outs() << "trim name: " << MemName << "\n";
                  break;
                }
              }

              if (MemberSet.count(MemName)) {
                Num = MemberSet.at(MemName);
                outs() << "member: " << Num << " name:" << MemName << "\n";
              } else {
                Num = AFL_R(MAP_SIZE);
                MemberSet.insert(
                    std::pair<StringRef, unsigned int>(MemName, Num));
                outs() << "first member: " << Num << " name: " << MemName
                       << "\n";
              }
              Number = ConstantInt::get(IntMapSizeTy, Num);
            }

            if (SI->getMetadata("labyrinth.label.state_describing.variable")) {
              IsVariable = true;
              if (IsMember) {
                outs() << "Both error\n";
              }

              // get variable number
              StringRef VarName = PtrValue->getName();
              if (VariableSet.count(PtrValue)) {
                Num = VariableSet.at(PtrValue);
                outs() << "var: " << Num << " name: " << VarName << "\n";
              } else {
                Num = AFL_R(MAP_SIZE);
                VariableSet.insert(
                    std::pair<Value *, unsigned int>(PtrValue, Num));
                outs() << "first var: " << Num << " name: " << VarName << "\n";
              }
              Number = ConstantInt::get(IntMapSizeTy, Num);
            }

            if (IsMember || IsVariable) {

              // instrumentation
              IRBuilder<> IRB(SI->getNextNonDebugInstruction());
              LoadInst *Load = IRB.CreateLoad(PtrValue);

              // casting float and double into integer
              Value *Cast = nullptr;
              Type *ValueTy =
                  Load->getPointerOperandType()->getPointerElementType();
              if (ValueTy->isPointerTy()) {
                continue;
              } else if (ValueTy->isIntegerTy()) {
                Cast = Load;
              } else if (ValueTy->isFloatTy()) {
                Cast = IRB.CreateBitCast(Load, Int32Ty);
              } else if (ValueTy->isDoubleTy()) {
                Cast = IRB.CreateBitCast(Load, Int64Ty);
              }

              // bitwidth transformation
              Value *Xor = nullptr;
              if (Cast != nullptr) {
                IntegerType *IntTy = dyn_cast<IntegerType>(Cast->getType());
                unsigned bitwidth = IntTy->getBitWidth();
                if (bitwidth < map_size) {
                  Cast = IRB.CreateZExt(Cast,
                                        IntegerType::getIntNTy(CTX, map_size));
                } else if (bitwidth > map_size) {
                  switch (bitwidth) {
                  case 64: {
                    Value *tmp = IRB.CreateTrunc(Cast, Int16Ty);
                    for (int i = 1; i <= 3; ++i) {
                      Value *part = IRB.CreateLShr(Cast, 16 * i);
                      part = IRB.CreateTrunc(part, Int16Ty);
                      tmp = IRB.CreateXor(tmp, part);
                    }
                    if (map_size > 16)
                      tmp = IRB.CreateZExt(tmp, IntMapSizeTy);
                    Cast = tmp;
                    break;
                  }
                  case 32: {
                    Value *high = IRB.CreateLShr(Cast, 16);
                    high = IRB.CreateTrunc(high, Int16Ty);
                    Value *low = IRB.CreateTrunc(Cast, Int16Ty);
                    Cast = IRB.CreateXor(high, low);
                    if (map_size > 16)
                      Cast = IRB.CreateZExt(Cast, IntMapSizeTy);
                    break;
                  }
                  default:
                    Cast = IRB.CreateTrunc(Cast, IntMapSizeTy);
                    break;
                  }
                }
                Xor = IRB.CreateXor(Cast, Number);

                // other type
              } else {
                Xor = Number;
                outs() << "[pass-log] "
                       << "cast part: other type: " << *Load << "\n";
              }

              // get map idx
              LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
              Value *Ext = IRB.CreateZExt(Xor, Int32Ty);
              Value *MapPtrIdx = IRB.CreateGEP(MapPtr, Ext);

              // update counter
              LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
              Value *Inc = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
              IRB.CreateStore(Inc, MapPtrIdx);

              /* log */
#ifdef PASS_LOG
              IRBuilder<> IRB2(SI);
              LoadInst *Before = IRB2.CreateLoad(PtrValue);
              LoadInst *After = IRB.CreateLoad(PtrValue);

              Type *AfterTy = After->getType();
              Value *Cmp = nullptr;
              Value *FormatStrPtr = nullptr;
              if (AfterTy->isIntegerTy()) {
                Cmp = IRB.CreateICmpNE(Before, After);
                FormatStrPtr = IRB.CreatePointerCast(
                    IntFormatStrVar, PrintfArgTy, "IntFormatStr");

              } else if (AfterTy->isFloatTy() || AfterTy->isDoubleTy()) {
                Cmp = IRB.CreateFCmpUEQ(Before, After);
                FormatStrPtr = IRB.CreatePointerCast(
                    FltFormatStrVar, PrintfArgTy, "FltFormatStr");

              } else {
                outs() << "[pass-log] "
                       << "log part: other type: " << AfterTy->getTypeID()
                       << "\n";
              }

              if (Cmp != nullptr && FormatStrPtr != nullptr) {
                Instruction *Split =
                    dyn_cast<Instruction>(Cmp)->getNextNonDebugInstruction();
                // outs() << "[pass-log] " << "cmp next inst: " << *Split <<
                // "\n";
                auto *ThenTerm = SplitBlockAndInsertIfThen(
                    Cmp, Split, false, nullptr, nullptr, nullptr, nullptr);

                IRB.SetInsertPoint(ThenTerm);
                Value *ModuleNamePtr = IRB.CreatePointerCast(
                    ModuleNameVar, PrintfArgTy, "ModuleName");
                StringRef VarName = PtrValue->getName();
                VarNameNum++;
                Constant *VarNameStr =
                    ConstantDataArray::getString(CTX, VarName.str());
                Constant *VarNameStrVar =
                    M.getOrInsertGlobal(".name" + std::to_string(VarNameNum),
                                        VarNameStr->getType());
                if (auto *Var = dyn_cast<GlobalVariable>(VarNameStrVar)) {
                  if (!Var->hasInitializer())
                    Var->setInitializer(VarNameStr);
                  Var->setLinkage(GlobalValue::PrivateLinkage);
                }
                Value *VarNameStrPtr =
                    IRB.CreatePointerCast(VarNameStrVar, PrintfArgTy);

                IRB.CreateCall(Printf,
                               {FormatStrPtr, ModuleNamePtr, VarNameStrPtr,
                                Before, After, Ext, Counter});
              }
              /* log end */
#endif

              inst_count++;
            }
          }
        }
      }
      outs() << "function: [" << F.getName() << "] end\n\n";
    }
    outs() << "file: [" << M.getModuleIdentifier() << "] end\n";
    outs() << "=================================================\n";

    OKF("State-Pass Instrumented %u locations.", inst_count);

    if (inst_count)
      Instrumented = true;
    return Instrumented;

  } // runOnModule end

  // main entry point
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = runOnModule(M);

    return (Changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
  }
}; // namespace

//-------------------------
// Legacy PM implementation
//-------------------------
struct LegacyVariableWatcher : public ModulePass {

  static char ID;

  LegacyVariableWatcher() : ModulePass(ID) {}
  bool runOnModule(Module &M) override {
    bool changed = Impl.runOnModule(M);

    return changed;
  }

  VariableWatcher Impl; // reusing the new PM implementation
};

} // namespace

/* New PM Registration */
PassPluginLibraryInfo getVariableWatcherPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "VariableWatcher", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "VW") {
                    MPM.addPass(VariableWatcher());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getVariableWatcherPluginInfo();
}

/* Legacy PM Registration
   The ID is used yo uniquely identity the pass
   */
char LegacyVariableWatcher::ID = 0;

static RegisterPass<LegacyVariableWatcher>
    X("legacy-VW",           // pass arg
      "VariableWatcherPass", // name
      false,                 // doesn't modify the CFG => false
      false                  // is analysis pass => false
    );

static void registerVariableWatcherPass(const PassManagerBuilder &,
                                        legacy::PassManagerBase &PM) {
  PM.add(new LegacyVariableWatcher());
}

static RegisterStandardPasses
    RegisterVariableWatcherPass(PassManagerBuilder::EP_OptimizerLast,
                                registerVariableWatcherPass);

static RegisterStandardPasses
    RegisterVariableWatcherPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                 registerVariableWatcherPass);
