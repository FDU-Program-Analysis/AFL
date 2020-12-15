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
    int VarNum = 0;

    IntegerType *Int8Ty = IntegerType::getInt8Ty(CTX);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(CTX);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(CTX);

    // get globals for share region
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__state_map_ptr");

    std::map<Value*, uint16_t> VariableSet;

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
    Constant *IntFormatStr =
        ConstantDataArray::getString(CTX, "[log] file: %s name: %s value: %lld => %lld\n");
    Constant *FltFormatStr =
        ConstantDataArray::getString(CTX, "[log] file: %s name: %s value: %lf => %lf\n");

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

    Constant *ModuleName = ConstantDataArray::getString(CTX, M.getModuleIdentifier());
    Constant *ModuleNameVar = M.getOrInsertGlobal("ModuleName", ModuleName->getType());
    dyn_cast<GlobalVariable>(ModuleNameVar)->setInitializer(ModuleName);
    dyn_cast<GlobalVariable>(ModuleNameVar)->setLinkage(GlobalValue::PrivateLinkage);

    outs() << "module: " << M.getModuleIdentifier() << "\n";
    
    for (auto &F : M) {
      for (auto &BB : F) {        
        for (auto &Inst : BB) {
          if (StoreInst *SI = dyn_cast<StoreInst>(&Inst)) {
            if (MDNode *N =
                    SI->getMetadata("labyrinth.label.state_describing")) {

              Value *PtrValue = SI->getPointerOperand();
              outs() << "pointer address: " << PtrValue << "\n";

              uint16_t RandomNum;
              bool first = false;
              Instruction *Next = SI->getNextNonDebugInstruction();
              IRBuilder<> Builder(Next);

              // get variable name
              StringRef VarName = PtrValue->getName();
              if (VarName == "") {
                // TODO: 
              }

              outs() << "Store Inst: " << *SI << "\n";

              if (VariableSet.find(PtrValue) != VariableSet.end()) {
                RandomNum = VariableSet.at(PtrValue);
                outs() <<"name: " << VarName <<" : " << PtrValue << " : " << RandomNum << "\n";

              } else {
                RandomNum = AFL_R(MAP_SIZE);
                VariableSet.insert(std::pair<Value*, uint16_t>(PtrValue, RandomNum));
                first = true;
                outs() << "variabel first appearance\n"; 
                outs() <<"name: " << VarName <<" : " << PtrValue << " : " << RandomNum << "\n";
              }
              
              /* instrumentation */
              // load current value
              LoadInst *Load = Builder.CreateLoad(PtrValue);
              Load->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(CTX, None));
              //outs() << "load current value\n";

              // // casting different type into int
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
                continue;
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

              //outs() << "casting type\n";

              ConstantInt *Num = ConstantInt::get(Int16Ty, RandomNum);
              Value *Xor = nullptr;
              if (Cast != nullptr) {
                Xor = Builder.CreateXor(Cast, Num);
              }
              //outs() << "calc index\n";

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
                // compare the value
                IRBuilder<> IRB(SI);
                auto *before = IRB.CreateLoad(PtrValue);
                IRB.SetInsertPoint(SI->getNextNonDebugInstruction());
                auto *after = IRB.CreateLoad(PtrValue);

                Type *ValueTy = after->getType();
                Value *CmpValue = nullptr;
                Value* FormatStrPtr = nullptr;
                switch (ValueTy->getTypeID()) {
                case Type::IntegerTyID:
                  CmpValue = IRB.CreateICmpNE(before, after);
                  FormatStrPtr = IRB.CreatePointerCast(IntFormatStrVar, PrintfArgTy, "IntFormatStr");
                  break;

                case Type::FloatTyID:
                case Type::DoubleTyID:
                  CmpValue = IRB.CreateFCmpUEQ(before, after);
                  FormatStrPtr = IRB.CreatePointerCast(FltFormatStrVar, PrintfArgTy, "FltFormatStr");
                  break;

                default:
                  outs() << "other type!\n";
                  break;
                }

                Instruction *Split = dyn_cast<Instruction>(CmpValue)->getNextNonDebugInstruction();
                auto *ThenTerm = SplitBlockAndInsertIfThen(CmpValue, Split, false, nullptr, nullptr, nullptr, nullptr);

                IRB.SetInsertPoint(ThenTerm);
                Value *ModuleNamePtr = IRB.CreatePointerCast(ModuleNameVar, PrintfArgTy, "ModuleName");

                 VarNum++;
                 Constant *VarNameStr = ConstantDataArray::getString(CTX, VarName.str());
                 Constant *VarNameStrVar = M.getOrInsertGlobal(".name" + std::to_string(VarNum), VarNameStr->getType());
                 if (auto *Var = dyn_cast<GlobalVariable>(VarNameStrVar)) {
                    if (!Var->hasInitializer())
                    Var->setInitializer(VarNameStr);
                    Var->setLinkage(GlobalValue::PrivateLinkage);
                  }

                //  dyn_cast<GlobalVariable>(VarNameStrVar)->setInitializer(VarNameStr);
                //  dyn_cast<GlobalVariable>(ModuleNameVar)->setLinkage(GlobalValue::PrivateLinkage);
                Value *VarNameStrPtr = IRB.CreatePointerCast(VarNameStrVar, PrintfArgTy);
                IRB.CreateCall(Printf, {FormatStrPtr, ModuleNamePtr, VarNameStrPtr, before, after});
               }

              //outs() << "\n";
              inst_count++;
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
