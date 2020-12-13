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

#define MAX_PRE_LEN 6

using namespace llvm;

namespace {

//----------------------
// New PM implementation
//----------------------
struct VariableWatcher : PassInfoMixin<VariableWatcher> {

  bool runOnModule(Module &M) {
    int inst_count = 0;
    bool Instrumented = false;
    auto &CTX = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(CTX);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(CTX);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(CTX);

    // get globals for share region
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__state_map_ptr");

    StringMap<unsigned int> GlobalVarsSet;
    auto &GlobalList = M.getGlobalList();
    outs() << "\nGLOBAL LIST\n";
    for (auto &GV : GlobalList) {
      if (GV.getMetadata("labyrinth.label.state_describing")) {
        GlobalVarsSet.insert_or_assign(GV.getName(), AFL_R(MAP_SIZE));
        outs() << GV.getName() << " : " << GlobalVarsSet.lookup(GV.getName())
               << "\n";
      }
    }
    outs() << "\n";

    StringMap<unsigned int> LocalVarsSet;

    // // declaration of printf
    // PointerType *PrintfArgTy = PointerType::getUnqual(Type::getInt8Ty(CTX));
    // FunctionType *PrintfTy =
    //     FunctionType::get(IntegerType::getInt32Ty(CTX), PrintfArgTy,
    //                       /*IsVarArgs=*/true);
    // FunctionCallee Printf = M.getOrInsertFunction("printf", PrintfTy);

    // // set attributes
    // Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
    // PrintfF->setDoesNotThrow();
    // PrintfF->addParamAttr(0, Attribute::NoCapture);
    // PrintfF->addParamAttr(0, Attribute::ReadOnly);

    // // inject a global variable that will hold the printf format string
    // Constant *IntFormatStr =
    //     ConstantDataArray::getString(CTX, "%lld => %lld\n");
    // Constant *FloatFormatStr =
    //     ConstantDataArray::getString(CTX, "%lf => %lf\n");
    // Constant *IntFormatStrVar =
    //     M.getOrInsertGlobal("IntFormatStr", IntFormatStr->getType());
    // dyn_cast<GlobalVariable>(IntFormatStrVar)->setInitializer(IntFormatStr);
    // Constant *FloatFormatStrVar =
    //     M.getOrInsertGlobal("FloatFormatStr", FloatFormatStr->getType());
    // dyn_cast<GlobalVariable>(FloatFormatStrVar)->setInitializer(FloatFormatStr);

    for (auto &F : M) {
      for (auto &BB : F) {
        for (auto &Inst : BB) {

          if (StoreInst *SI = dyn_cast<StoreInst>(&Inst)) {
            if (MDNode *N =
                    SI->getMetadata("labyrinth.label.state_describing")) {

              Value *PtrValue = SI->getPointerOperand();
              outs() << "pointer address: " << PtrValue << "\n";

              StringRef VarName = PtrValue->getName();
              uint16_t RandomNum;
              uint16_t ConstIdx = -1;
              Value *VarIdx = nullptr;
              bool first = false;

              IRBuilder<> Builder(SI->getNextNonDebugInstruction());

              outs() << "Store Inst: " << *SI << "\n";

              /* global varibale */
              if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PtrValue)) {
                outs() << "1.\n";
                outs() << "Global var: " << VarName << "\n";
                // skip global pointer
                if (GV->getValueType()->isPointerTy()) {
                  continue;
                }

                /* local pointer declaration, not instrumented */
              } else if (PtrValue->getType()
                             ->getPointerElementType()
                             ->isPointerTy()) {
                outs() << "2.\n";
                VarName = SI->getPointerOperand()->getName();
                outs() << "pointer name: " << VarName << "\n";
                outs() << "not instrumented\n\n";
                continue;

                /* indexed by variable */
              } else if (auto *GEPI = dyn_cast<GetElementPtrInst>(PtrValue)) {
                outs() << "3.\n";
                VarName = GEPI->getPointerOperand()->getName();
                outs() << "GEP Inst: " << *GEPI << "\n";

                if (GEPI->getNumIndices() >= 2) {
                  if (auto *CI = dyn_cast<ConstantInt>(GEPI->getOperand(2))) {
                    ConstIdx = CI->getZExtValue();
                    outs() << "idx: " << ConstIdx << "\n";

                  } else {
                    Value *Idx = GEPI->getOperand(2);
                    outs() << "var idx: " << *Idx << "\n";
                    VarIdx = Idx;
                  }
                }

                if (auto *PO =
                        dyn_cast<GEPOperator>(GEPI->getPointerOperand())) {
                  VarName = PO->getPointerOperand()->getName();
                  outs() << "GEP Operator Inst: " << *PO << "\n";
                }

                while (auto *PI = dyn_cast<GetElementPtrInst>(
                           GEPI->getPointerOperand())) {
                  GEPI = PI;
                  VarName = GEPI->getPointerOperand()->getName();
                  outs() << "GEP2 Inst: " << *GEPI << "\n";
                  if (GEPI->getNumIndices() >= 2) {
                    if (auto *CI = dyn_cast<ConstantInt>(GEPI->getOperand(2))) {
                      if (ConstIdx == -1) {
                        ConstIdx = CI->getZExtValue();
                      } else {
                        ConstIdx <<= 1;
                        ConstIdx ^= CI->getZExtValue();
                      }
                    } else {
                      Value *Idx = GEPI->getOperand(2);
                      outs() << *Idx << "\n";
                      // TODO: xor inst
                    }
                  }
                }

                while (VarName == "") {
                  if (auto *LI =
                          dyn_cast<LoadInst>(GEPI->getPointerOperand())) {
                    VarName = LI->getPointerOperand()->getName();
                    outs() << "VarName: " << VarName << "\n";
                    if (auto *PI = dyn_cast<GetElementPtrInst>(
                            LI->getPointerOperand())) {
                      VarName = PI->getPointerOperand()->getName();
                      GEPI = PI;
                    }
                  }
                }

                outs() << "Variable Index: " << VarName << "\n";

                // prev inst for debug
                outs() << "Pre Inst:\n";
                Instruction *II = SI;
                for (int i = 1; i <= MAX_PRE_LEN; ++i) {
                  if (!II)
                    break;
                  II = II->getPrevNonDebugInstruction();
                  outs() << *II << "\n";
                }
                outs() << "\n";

                // indexed by constant
              } else if (auto *GEPCstI = dyn_cast<GEPOperator>(PtrValue)) {
                outs() << "4.\n";
                VarName = GEPCstI->getPointerOperand()->getName();

                unsigned Indices = GEPCstI->getNumIndices();
                for (unsigned i = 2; i <= Indices; ++i) {
                  outs() << *(GEPCstI->getOperand(i)) << " ";
                  if (auto *CI =
                          dyn_cast<ConstantInt>(GEPCstI->getOperand(i))) {
                    if (i == 2)
                      ConstIdx = CI->getZExtValue();
                    else {
                      ConstIdx <<= 1;
                      ConstIdx ^= CI->getZExtValue();
                    }
                  }
                  outs() << "idx: " << ConstIdx << "\n";
                }
                outs() << "Const Index: " << VarName << "\n";
                outs() << "GEP Operator Inst: " << *GEPCstI << "\n";

              } else {
                outs() << "\nother situation\n";
              }

              if (GlobalVarsSet.count(VarName)) {
                RandomNum = GlobalVarsSet.lookup(VarName);
                outs() << "Global Var ==> " << VarName << " : " << RandomNum
                       << "\n\n";

              } else {
                if (!LocalVarsSet.count(VarName)) {
                  RandomNum = AFL_R(MAP_SIZE);
                  LocalVarsSet.insert_or_assign(VarName, RandomNum);
                } else {
                  RandomNum = LocalVarsSet.lookup(VarName);
                  first = true;
                }
                outs() << "Local var ==> " << VarName << " : "
                       << LocalVarsSet.lookup(VarName) << "\n\n";
              }

              // instrumentation
              // load current value
              LoadInst *Load = Builder.CreateLoad(PtrValue);
              Load->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(CTX, None));
              outs() << "load current value\n";

              // casting different type into int
              Value *Cast = nullptr;
              Type *LoadTy =
                  Load->getPointerOperandType()->getPointerElementType();
              switch (LoadTy->getTypeID()) {
              case Type::FloatTyID:
                outs() << "float type\n";
                Cast = Builder.CreateBitCast(Load, Int32Ty);
                break;

              case Type::DoubleTyID:
                outs() << "double type\n";
                Cast = Builder.CreateBitCast(Load, Int64Ty);
                break;

              case Type::IntegerTyID:
                outs() << "integer type\n";
                Cast = Load;
                break;

              default:
                outs() << "other type: " << LoadTy->getTypeID() << "\n";
                break;
              }

              // transform bitwidth to int16 type
              switch (Cast->getType()->getIntegerBitWidth()) {
              case 64: {
                Value *tmp = Cast;
                for (int i = 3; i >= 0; --i) {
                  Value *Part = Builder.CreateLShr(tmp, i * 16);
                  outs() << "Part: " << *Part << "\n";
                  Part = Builder.CreateTrunc(Part, Int16Ty);
                  if (i == 3)
                    Cast = Part;
                  else
                    Cast = Builder.CreateXor(Cast, Part);
                  outs() << "Cast: " << *Cast << "\n";
                }
              } break;

              case 32: {
                Value *LV = Builder.CreateLShr(Cast, 16);
                LV = Builder.CreateTrunc(LV, Int16Ty);
                Value *RV = Builder.CreateTrunc(Cast, Int16Ty);
                Cast = Builder.CreateXor(LV, RV);
                break;
              }

              case 16:
                break;

              default:
                Cast = Builder.CreateZExt(Load, Int16Ty);
                break;
              }

              outs() << "casting type\n";

              // caculating index
              if (ConstIdx != -1) {
                RandomNum ^= ConstIdx;
              }

              ConstantInt *Num = ConstantInt::get(Int16Ty, RandomNum);
              Value *Xor = nullptr;
              if (Cast != nullptr) {
                Xor = Builder.CreateXor(Cast, Num);
              }
              outs() << "calc index\n\n";

              // inject a call to printf
              // Value *FormatStrPtr =
              //     Builder.CreatePointerCast(PrintfFormatStrVar, PrintfArgTy,
              //     "formatStr");
              // Builder.CreateCall(Printf, {FormatStrPtr, VarNum, Load, Xor});

              LoadInst *MapPtr = Builder.CreateLoad(AFLMapPtr);
              MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(CTX, None));
              Value *MapPtrIdx = Builder.CreateGEP(MapPtr, Xor);

              // updating bitmap
              LoadInst *Counter = Builder.CreateLoad(MapPtrIdx);
              Counter->setMetadata(M.getMDKindID("nosanitize"),
                                   MDNode::get(CTX, None));
              Value *Inc =
                  Builder.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
              Builder.CreateStore(Inc, MapPtrIdx)
                  ->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(CTX, None));

              /* log */
              // if (!first) {
              //   // compare the value
              //   IRBuilder<> BeforeB(SI);
              //   IRBuilder<> AfterB(SI->getNextNonDebugInstruction());
              //   Value *before = BeforeB.CreateLoad(PtrValue);
              //   Value *after = AfterB.CreateLoad(PtrValue);

              //   Type *ValueTy = after->getType();
              //   Value *CmpValue = nullptr;
              //   switch (ValueTy->getTypeID()) {
              //   case Type::IntegerTyID:
              //     CmpValue = AfterB.CreateICmpNE(before, after);
              //     break;

              //   case Type::FloatTyID:
              //   case Type::DoubleTyID:
              //     CmpValue = AfterB.CreateFCmpUEQ(before, after);
              //     break;

              //   default:
              //     outs() << "[LOG]: other type!\n";
              //     break;
              //   }

              //   if (auto *Cmp = dyn_cast<CmpInst>(CmpValue)) {
              //     SplitBlockAndInsertIfThen(CmpValue, Cmp->getNextNonDebugInstruction(), false, nullptr, nullptr, nullptr, nullptr);
                  
              //   }                

              // }

              inst_count++;
            }
          }
        }
      }
    }

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
