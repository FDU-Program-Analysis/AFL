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
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <unordered_set>

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
    IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);

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

    // declaration of printf
    // PointerType *PrintfArgTy = PointerType::getUnqual(Type::getInt8Ty(CTX));
    // FunctionType *PrintfTy = FunctionType::get(
    //     IntegerType::getInt32Ty(CTX),
    //     PrintfArgTy,
    //     /*IsVarArgs=*/true);
    // FunctionCallee Printf = M.getOrInsertFunction("printf", PrintfTy);

    // // set attributes
    // Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
    // PrintfF->setDoesNotThrow();
    // PrintfF->addParamAttr(0, Attribute::NoCapture);
    // PrintfF->addParamAttr(0, Attribute::ReadOnly);

    // // inject a global variable that will hold the printf format string
    // Constant *PrintfFormatStr = ConstantDataArray::getString(CTX, 
    //     "update bitmap: SHM[VarNum: %-6d ^ Value: %-6d = Index: %-6d]\n");
    // Constant *PrintfFormatStrVar = 
    //     M.getOrInsertGlobal("PrintfFormatStr", PrintfFormatStr->getType());
    // dyn_cast<GlobalVariable>(PrintfFormatStrVar)->setInitializer(PrintfFormatStr);


    for (auto &F : M) {
      for (auto &BB : F) {
        for (auto &Inst : BB) {

          if (StoreInst *SI = dyn_cast<StoreInst>(&Inst)) {
            if (MDNode *N =
                    SI->getMetadata("labyrinth.label.state_describing")) {

              Value *PtrValue = SI->getPointerOperand();
              StringRef VarName = PtrValue->getName();
              unsigned int RandomNum;
              uint64_t idx = -1;

              IRBuilder<> Builder(SI->getNextNonDebugInstruction());
              Value *Inst = nullptr;

              // global varibale
              if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PtrValue)) {
                outs() << "Global var: " << VarName << "\n";
                outs() << "Global Inst: " << *SI << "\n";
                // skip pointer
                if (GV->getValueType()->isPointerTy()) {
                  continue;
                }

                // array/struct indexed by variable
              } else if (auto *GEPI = dyn_cast<GetElementPtrInst>(PtrValue)) {
                VarName = GEPI->getPointerOperand()->getName();
                outs() << "GEP Inst: " << *GEPI << "\n";
                if (GEPI->getNumIndices() >= 2) {
                  if (!dyn_cast<ConstantInt>(GEPI->getOperand(2))) {
                    Value *VarIdx = GEPI->getOperand(2);
                    outs() << *VarIdx << "\n";
                    Inst = VarIdx;
                  }
                }
                
                while (auto *PI = dyn_cast<GetElementPtrInst>(GEPI->getPointerOperand())) {
                  GEPI = PI;
                  VarName = GEPI->getPointerOperand()->getName();
                  outs() << "GEP Inst: " << *GEPI << "\n";
                  if (GEPI->getNumIndices() >= 2) {
                    if (!dyn_cast<ConstantInt>(GEPI->getOperand(2))) {
                      Value *VarIdx = GEPI->getOperand(2);
                      outs() << *VarIdx << "\n";
                      if (Inst != nullptr) {
                        auto *XorIdx = Builder.CreateXor(VarIdx, Inst);
                        Inst = XorIdx;
                        outs() << "Xor Inst: " << *Inst << "\n";
                      }
                    }
                  }
              
                }

                if (auto *PO = dyn_cast<GEPOperator>(GEPI->getPointerOperand())) {
                  VarName = PO->getPointerOperand()->getName();
                  outs() << "GEP Inst: " << *PO << "\n";                  
                }

                outs() << "Variable Index Var: " << VarName << "\n";
                outs() << "Store Inst: " << *SI << "\n";

                // array/struct indexed by constant
              } else if (auto *GEPCstI = dyn_cast<GEPOperator>(PtrValue)) {
                VarName = GEPCstI->getPointerOperand()->getName();

                unsigned Indices = GEPCstI->getNumIndices();
                for (unsigned i = 2; i <= Indices; ++i) {
                  outs() << *(GEPCstI->getOperand(i)) << " ";
                  if (auto *CI = dyn_cast<ConstantInt>(GEPCstI->getOperand(i))) {
                    if (i == 2) 
                      idx = CI->getZExtValue();
                    else 
                      idx ^= CI->getZExtValue();
                  }
                  outs() << "idx: " << idx << "\n";

                }
                outs() << "Const Index: " << VarName << "\n";
                outs() << "GEP Const Inst: " << *GEPCstI << "\n";

                // pointer (defination), not instrumented
              } else if (PtrValue->getType()
                             ->getPointerElementType()
                             ->isPointerTy()) {
                VarName = SI->getPointerOperand()->getName();
                outs() << "pointer name: " << VarName << "\n";
                outs() << "not-instrumented\n";
                outs() << *SI << "\n";
                continue;

              } else {
                if (LoadInst *LI = dyn_cast<LoadInst>(PtrValue)) {
                  VarName = LI->getPointerOperand()->getName();
                  outs() << VarName << "\n";
                  outs() << *LI << "\n";
                  outs() << *SI << "\n";
                }
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
                }
                outs() << "Local var ==> " << VarName << " : "
                       << LocalVarsSet.lookup(VarName) << "\n\n";
              }

              // instrumentation
              // load current value
              LoadInst *Load = Builder.CreateLoad(PtrValue);
              Load->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(CTX, None));
              
              // casting different type into int
              Value *Cast = nullptr;
              if (!Load->getPointerOperandType()->getPointerElementType()->isIntegerTy()) {
                Cast = Builder.CreateFPCast(Load, Int32Ty);
              }

              // caculating index
              if (idx != -1) {
                RandomNum ^= idx;
              }
              ConstantInt *VarNum = ConstantInt::get(Int32Ty, RandomNum);
              Value *Xor = nullptr;
              if (Cast != nullptr) {
                Xor = Builder.CreateXor(Cast, VarNum);
              } else {
                Xor = Builder.CreateXor(Load, VarNum);  
              }
              
              // inject a call to printf
              // Value *FormatStrPtr = 
              //     Builder.CreatePointerCast(PrintfFormatStrVar, PrintfArgTy, "formatStr");
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

              inst_count++;
            }
          }
        }
      }
    }

    // outs() << "\ninstruction number: " << inst_count << "\n";
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

static RegisterStandardPasses RegisterVariableWatcherPass(
    PassManagerBuilder::EP_OptimizerLast, registerVariableWatcherPass);

static RegisterStandardPasses RegisterVariableWatcherPass0(
  PassManagerBuilder::EP_EnabledOnOptLevel0, registerVariableWatcherPass);
