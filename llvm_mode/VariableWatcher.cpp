/************************************************************************
        > File Name: VariableWatcher.cpp
        > Author: zinc
        > Mail: burymynamel@163.com
        > Created Time: Thu 24 Sep 2020 02:42:49 PM CST
 ************************************************************************/
#define AFL_LLVM_PASS
//#define PASS_LOG

#include "../config.h"
#include "../debug.h"

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <fstream>
#include <iostream>
#include <unordered_set>

//#define PASS_LOG
using namespace llvm;

/* parsing params */
cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc(
        "Output directory contains Ftargets.txtm Fnames.txt and BBnames.txt."),
    cl::value_desc("outdir"));

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing distance of each BB to targets."),
    cl::value_desc("distance"));

/* some function need to be skip */
static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
      "asan.", "llvm.",  "sancov.", "__ubsan_handle_",
      "free",  "malloc", "calloc",  "realloc"};

  for (auto const &FuncName : Blacklist) {
    if (F->getName().startswith(FuncName)) {
      return true;
    }
  }

  return false;
}

/* get instruction debug location infomation */
/* NOTE: the compile flag '-g' must be added, otherwise the getDebugLoc cannot recognize location*/
static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
}

namespace llvm {

/* customize dot graph drawer */
template <> struct DOTGraphTraits<Function *> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple = true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

//----------------------
// New PM implementation
//----------------------
struct VariableWatcher : PassInfoMixin<VariableWatcher> {

  bool isStateInst(Instruction &I, bool &is_transition);
  void getGroupAndValue(Instruction &I, bool is_transition, std::string &transition, std::string &check);
  bool runOnModule(Module &M);

  // main entry point
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = runOnModule(M);
    return (Changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
  }

}; // namespace


bool VariableWatcher::isStateInst(Instruction &I, bool &is_transition) {
  bool is_target = false;
  /* get stateful variable/member label */
  if (I.getMetadata("labyrinth.label.state_describing.member")) {
    is_target = true;
    is_transition = true;

  } else if (I.getMetadata("labyrinth.label.state_describing.variable")) {
    is_target = true;
    if (dyn_cast<StoreInst>(&I))
      is_transition = true;
    else
      is_transition = false;
    
  } else if (I.getMetadata("labyrinth.label.state_describing.case")) {
    is_target = true;
    is_transition = false;
  }
  return is_target;
}


void VariableWatcher::getGroupAndValue(Instruction &I, bool is_transition, std::string &transition, std::string &check) {
  
  SmallVector<std::pair<unsigned, MDNode*>, 3> Nodes;

  /* get group and value info from metadata */
  I.getAllMetadataOtherThanDebugLoc(Nodes);
  auto Node = Nodes[Nodes.size() - 1];
                
  if (Node.second->getNumOperands() == 2) {
    if(MDString *MDS = dyn_cast<MDString>(Node.second->getOperand(0).get())) {
      if (is_transition)
        transition = transition + "G" + MDS->getString().str();
      else
        check = check + "G" + MDS->getString().str();
      }

    if(MDString *MDS = dyn_cast<MDString>(Node.second->getOperand(1).get())) {
      if (is_transition)
        transition = transition + "V" + MDS->getString().str() + ",";
      else
        check = check + "V" + MDS->getString().str() + ",";
    }
  }  
}

bool VariableWatcher::runOnModule(Module &M)   {

    unsigned inst_count = 0;
    bool Instrumented = false;
    bool is_labyrinth_preprocessing = false;
    bool is_labyrinth_Instrumentation = false;

    if (!OutDirectory.empty() && !DistanceFile.empty()) {
      FATAL("Cannot specify both '-outdir' and '-distance'!");
      return false;
    }

    std::map<std::string, int> bb_to_dis;

    if (!OutDirectory.empty()) {

      is_labyrinth_preprocessing = true;

    } else if (!DistanceFile.empty()) {

      std::ifstream df(DistanceFile);
      if (df.is_open()) {

        std::string line;
        while (getline(df, line)) {

          std::size_t pos = line.find(",");
          std::string bb_name = line.substr(0, pos);
          int bb_dis =
              (int)(100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

          bb_to_dis.emplace(bb_name, bb_dis);
        }
        df.close();
        is_labyrinth_Instrumentation = true;

      } else {
        FATAL("Unable to find %s.", DistanceFile.c_str());
        return false;
      }
    }

    /* show a banner */
    if (is_labyrinth_preprocessing || is_labyrinth_Instrumentation)
      SAYF(cCYA "state-llvm-pass " cBRI VERSION cRST " (%s mode)\n",
           (is_labyrinth_preprocessing ? "preprocessing"
                                       : "distance instrumentation"));

    if (is_labyrinth_preprocessing) {

      std::ofstream bbnames(OutDirectory + "/BBnames.txt",
                            std::ofstream::out | std::ofstream::app);
      std::ofstream bbcalls(OutDirectory + "/BBcalls.txt",
                            std::ofstream::out | std::ofstream::app);
      std::ofstream bbtargets(OutDirectory + "/BBtargets.txt",
                              std::ofstream::out | std::ofstream::app);
      std::ofstream fnames(OutDirectory + "/Fnames.txt",
                           std::ofstream::out | std::ofstream::app);
      std::ofstream ftargets(OutDirectory + "/Ftargets.txt",
                             std::ofstream::out | std::ofstream::app);

      std::string dotfiles(OutDirectory + "/dot-files");
      if (sys::fs::create_directory(dotfiles)) {
        FATAL("Could not create directory %s", dotfiles.c_str());
      }

      outs() << "[debug]"
             << "file: " << M.getModuleIdentifier() << "\n";
      for (auto &F : M) {

        outs() << "[debug]"
               << "function: " << F.getName() << "\n";

        bool has_BBs = false;
        bool is_target_BB = false;

        std::string funcName = F.getName();
        std::string filename;

        for (auto &BB : F) {

          std::string bb_name("");
          unsigned line;
          std::string transition("");
          std::string check("");

          for (auto &I : BB) {

            getDebugLoc(&I, filename, line);
            
            static const std::string Xlibs("/usr/");
            if (filename.empty() || line == 0 ||
                !filename.compare(0, Xlibs.size(), Xlibs)) {
              continue;
            }

            /* concat BB name */
            if (bb_name.empty()) {
              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos) {
                filename = filename.substr(found + 1);
              }

              bb_name = filename + ":" + std::to_string(line);
            }
            
            bool is_transition = false; // true for transition, false for check
            if (isStateInst(I, is_transition)) {
              outs() << "[debug] StateInst:" << I <<"\n";

              inst_count++;
              bbtargets << bb_name << "\n";
              is_target_BB = true;

              getGroupAndValue(I, is_transition, transition, check);
            }

            /* record call site */
            if (auto *CI = dyn_cast<CallInst>(&I)) {

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos) {
                filename = filename.substr(found + 1);
              }

              if (auto *CalledFunc = CI->getCalledFunction()) {
                if (!isBlacklisted(CalledFunc)) {
                  bbcalls << bb_name << "," << CalledFunc->getName().str()
                          << "\n";
                }
              }
            }
          }

          /* set BB name */
          if (!bb_name.empty()) {

            BB.setName(bb_name + ":");
            if (!BB.hasName()) {
              std::string newname = bb_name + ":";
              Twine t(newname);
              SmallString<256> NameData;
              StringRef NameRef = t.toStringRef(NameData);
              BB.setValueName(ValueName::Create(NameRef));
            }
            
            if (!transition.empty()) {
              transition = "transition:" + transition;
              transition.pop_back();
              outs() << "[debug]" << transition << "\n";
            }

            if (!check.empty()) {
              check = "check:" + check;
              check.pop_back();
              outs() << "[debug]" << check << "\n";
            }

            // std::string suffix = transition + ":" + check; 
            // BB.setName(BB.getName().str() + suffix);

            bbnames << BB.getName().str() << "\n";
            has_BBs = true;
          }
        }

        /* print CFG */
        if (has_BBs) {
          outs() << "[debug]"
                 << "generating CFG for function: " << funcName << "\n";

          std::string CFGFileName = dotfiles + "/cfg." + funcName + ".dot";
          std::error_code EC;
          raw_fd_ostream CFGFile(CFGFileName, EC, sys::fs::F_None);
          if (!EC) {
            WriteGraph(CFGFile, &F, true);
          }

          /* write name of function which BB belongs */
          if (is_target_BB) {
            ftargets << funcName << "\n";
          }

          fnames << funcName << "\n";
        }
        outs() << "[debug]"
               << "------------- function end -------------"
               << "\n";
      }
      outs() << "[debug]"
             << "---------------- file end ----------------"
             << "\n\n";

      /* Instrumentation for distance */
    } else if (is_labyrinth_Instrumentation) {

      LLVMContext &CTX = M.getContext();

      IntegerType *Int8Ty = IntegerType::getInt8Ty(CTX);
      IntegerType *Int16Ty = IntegerType::getInt16Ty(CTX);
      IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);
      IntegerType *Int64Ty = IntegerType::getInt64Ty(CTX);

#ifdef WORD_SIZE_64
      IntegerType *LargestType = Int64Ty;
      ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
      IntegerType *LargestType = Int32Ty;
      ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif

      ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
      ConstantInt *One = ConstantInt::get(LargestType, 1);

      /* get SHM region in AFL, and the distance and counter located behind the
       * AFLMapPtr */
      GlobalVariable *AFLMapPtr = M.getGlobalVariable("__afl_area_ptr");

#ifdef PASS_LOG
        /* printf function */
        // declaration of printf
        PointerType *PrintfArgTy = PointerType::getUnqual(Type::getInt8Ty(CTX));
        FunctionType *PrintfTy = FunctionType::get(IntegerType::getInt32Ty(CTX), 
            PrintfArgTy, /*IsVarArgs=*/true);
        FunctionCallee Printf = M.getOrInsertFunction("printf", PrintfTy);

        // set attributes
        Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
        PrintfF->setDoesNotThrow();
        PrintfF->addParamAttr(0, Attribute::NoCapture);
        PrintfF->addParamAttr(0, Attribute::ReadOnly);

        // inject a global variable that will hold the printf format string
        Constant *FormatStr = ConstantDataArray::getString(
            CTX, "[runtime log] distance: %d, count %d\n");
        Constant *FormatStrVar =
            M.getOrInsertGlobal("FormatStr", FormatStr->getType());
        if (auto *Var = dyn_cast<GlobalVariable>(FormatStrVar)) {
          if (!Var->hasInitializer())
            Var->setInitializer(FormatStr);
          Var->setLinkage(GlobalValue::PrivateLinkage);
        }

        Constant *BBNameFormatStr = ConstantDataArray::getString(
            CTX, "[runtime log] BB name: %s\n");
        Constant *BBNameFormatStrVar =
            M.getOrInsertGlobal("BBNameFormatStr", FormatStr->getType());
        if (auto *Var = dyn_cast<GlobalVariable>(BBNameFormatStrVar)) {
          if (!Var->hasInitializer())
            Var->setInitializer(BBNameFormatStr);
          Var->setLinkage(GlobalValue::PrivateLinkage);
        }

        /* printf function end*/
#endif


      outs() << "[debug]"
             << "file: " << M.getModuleIdentifier() << "\n";
      for (auto &F : M) {

        int distance = -1;

        for (auto &BB : F) {

          distance = -1;
          std::string bb_name;

          for (auto &I : BB) {

            std::string filename;
            unsigned line;

            getDebugLoc(&I, filename, line);
            if (filename.empty() || line == 0)
              continue;

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos) {
              filename = filename.substr(found + 1);
            }

            bb_name = filename + ":" + std::to_string(line);
            break;
          }

          /* find BB's distance */
          if (!bb_name.empty()) {
            std::map<std::string, int>::iterator it;
            for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it) {
              if (it->first.compare(bb_name) == 0) {
                distance = it->second;
              }
            }
          }

          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));

#ifdef PASS_LOG
          auto BBNameStrPtr = IRB.CreateGlobalStringPtr(bb_name);
          Value *BBNameFormatStrPtr = IRB.CreateBitCast(BBNameFormatStrVar, PrintfArgTy, "BBNameFormatStr");
          IRB.CreateCall(Printf, {BBNameFormatStrPtr, BBNameStrPtr});
#endif

          if (distance > 0) {

            outs() << "[debug]" << "BB name: " << bb_name 
                   << " distance: " << distance << "\n";

            ConstantInt *Distance =
                ConstantInt::get(LargestType, (unsigned)distance);

            /* add distance to shm[MAP_SIZE] */
            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            Value *MapDistPtr = IRB.CreateBitCast(
                IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
            LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
            MapDist->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(CTX, None));

            Value *IncDist = IRB.CreateAdd(MapDist, Distance);
            IRB.CreateStore(IncDist, MapDistPtr)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(CTX, None));

            /* increase count at shm[MAP_SIZE + 4 or 8] */
            Value *MapCntPtr = IRB.CreateBitCast(
                IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
            LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
            MapCnt->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(CTX, None));

            Value *IncCnt = IRB.CreateAdd(MapCnt, One);
            IRB.CreateStore(IncCnt, MapCntPtr)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(CTX, None));
#ifdef PASS_LOG
            /* print runtime log */
            Value *FormatStrPtr = IRB.CreateBitCast(FormatStrVar, PrintfArgTy, "FormatStr");
            IRB.CreateCall(Printf,{FormatStrPtr, MapDist, MapCnt});

#endif
            inst_count++;
          }
        }
      }

      outs() << "[debug]"
             << "Instrumented " << inst_count << " locations\n";
    }
    //===================================================================================

    //     unsigned VarNameNum = 0;
    //     bool Instrumented = false;
    //     auto &CTX = M.getContext();

    //     IntegerType *Int8Ty = IntegerType::getInt8Ty(CTX);
    //     IntegerType *Int16Ty = IntegerType::getInt16Ty(CTX);
    //     IntegerType *Int32Ty = IntegerType::getInt32Ty(CTX);
    //     IntegerType *Int64Ty = IntegerType::getInt64Ty(CTX);
    //     IntegerType *IntMapSizeTy = IntegerType::getIntNTy(CTX,
    //     MAP_SIZE_POW2);


    //     } else {
    //       /* traversal */
    //       outs() << "file: [" << M.getModuleIdentifier() << "]\n";
    //       for (auto &F : M) {

    //         outs() << "function: [" << F.getName() << "]\n";
    //         for (auto &BB : F) {

    //           for (auto &I : BB) {
    //             if (auto *SI = dyn_cast<StoreInst>(&I)) {
    //               bool IsMember = false;
    //               bool IsVariable = false;
    //               Value *PtrValue = SI->getPointerOperand();
    //               unsigned map_size = MAP_SIZE_POW2;
    //               unsigned int Num;
    //               ConstantInt *Number = nullptr;

    //               if
    //               (SI->getMetadata("labyrinth.label.state_describing.member"))
    //               {
    //                 IsMember = true;
    //                 StringRef MemName = PtrValue->getName();
    //                 // outs() << "member: " << MemName << "\n";

    //                 // trim member variable number
    //                 size_t len = MemName.size();
    //                 for (size_t i = 0; i < len; ++i) {
    //                   if (isDigit(MemName[i])) {
    //                     MemName = MemName.take_front(i);
    //                     // outs() << "trim name: " << MemName << "\n";
    //                     break;
    //                   }
    //                 }

    //                 if (MemberSet.count(MemName)) {
    //                   Num = MemberSet.at(MemName);
    //                   outs() << "member: " << Num << " name:" << MemName <<
    //                   "\n";
    //                 } else {
    //                   Num = AFL_R(MAP_SIZE);
    //                   MemberSet.insert(
    //                       std::pair<StringRef, unsigned int>(MemName, Num));
    //                   outs() << "first member: " << Num << " name: " <<
    //                   MemName
    //                          << "\n";
    //                 }
    //                 Number = ConstantInt::get(IntMapSizeTy, Num);
    //               }

    //               if (SI->getMetadata(
    //                       "labyrinth.label.state_describing.variable")) {
    //                 IsVariable = true;
    //                 if (IsMember) {
    //                   outs() << "Both error\n";
    //                 }

    //                 // get variable number
    //                 StringRef VarName = PtrValue->getName();
    //                 if (VariableSet.count(PtrValue)) {
    //                   Num = VariableSet.at(PtrValue);
    //                   outs() << "var: " << Num << " name: " << VarName <<
    //                   "\n";
    //                 } else {
    //                   Num = AFL_R(MAP_SIZE);
    //                   VariableSet.insert(
    //                       std::pair<Value *, unsigned int>(PtrValue, Num));
    //                   outs() << "first var: " << Num << " name: " << VarName
    //                          << "\n";
    //                 }
    //                 Number = ConstantInt::get(IntMapSizeTy, Num);
    //               }

    //               if (IsMember || IsVariable) {

    //                 // instrumentation
    //                 IRBuilder<> IRB(SI->getNextNonDebugInstruction());
    //                 LoadInst *Load = IRB.CreateLoad(PtrValue);

    //                 // casting float and double into integer
    //                 Value *Cast = nullptr;
    //                 Type *ValueTy =
    //                     Load->getPointerOperandType()->getPointerElementType();
    //                 if (ValueTy->isPointerTy()) {
    //                   continue;
    //                 } else if (ValueTy->isIntegerTy()) {
    //                   Cast = Load;
    //                 } else if (ValueTy->isFloatTy()) {
    //                   Cast = IRB.CreateBitCast(Load, Int32Ty);
    //                 } else if (ValueTy->isDoubleTy()) {
    //                   Cast = IRB.CreateBitCast(Load, Int64Ty);
    //                 }

    //                 // bitwidth transformation
    //                 Value *Xor = nullptr;
    //                 if (Cast != nullptr) {
    //                   IntegerType *IntTy =
    //                   dyn_cast<IntegerType>(Cast->getType()); unsigned
    //                   bitwidth = IntTy->getBitWidth(); if (bitwidth <
    //                   map_size) {
    //                     Cast = IRB.CreateZExt(
    //                         Cast, IntegerType::getIntNTy(CTX, map_size));
    //                   } else if (bitwidth > map_size) {
    //                     switch (bitwidth) {
    //                     case 64: {
    //                       Value *tmp = IRB.CreateTrunc(Cast, Int16Ty);
    //                       for (int i = 1; i <= 3; ++i) {
    //                         Value *part = IRB.CreateLShr(Cast, 16 * i);
    //                         part = IRB.CreateTrunc(part, Int16Ty);
    //                         tmp = IRB.CreateXor(tmp, part);
    //                       }
    //                       if (map_size > 16)
    //                         tmp = IRB.CreateZExt(tmp, IntMapSizeTy);
    //                       Cast = tmp;
    //                       break;
    //                     }
    //                     case 32: {
    //                       Value *high = IRB.CreateLShr(Cast, 16);
    //                       high = IRB.CreateTrunc(high, Int16Ty);
    //                       Value *low = IRB.CreateTrunc(Cast, Int16Ty);
    //                       Cast = IRB.CreateXor(high, low);
    //                       if (map_size > 16)
    //                         Cast = IRB.CreateZExt(Cast, IntMapSizeTy);
    //                       break;
    //                     }
    //                     default:
    //                       Cast = IRB.CreateTrunc(Cast, IntMapSizeTy);
    //                       break;
    //                     }
    //                   }
    //                   Xor = IRB.CreateXor(Cast, Number);

    //                   // other type
    //                 } else {
    //                   Xor = Number;
    //                   outs() << "[pass-log] "
    //                          << "cast part: other type: " << *Load << "\n";
    //                 }

    //                 // get map idx
    //                 LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
    //                 Value *Ext = IRB.CreateZExt(Xor, Int32Ty);
    //                 Value *MapPtrIdx = IRB.CreateGEP(MapPtr, Ext);

    //                 // update counter
    //                 LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
    //                 Value *Inc =
    //                     IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
    //                 IRB.CreateStore(Inc, MapPtrIdx);


    //                 inst_count++;
    //               }
    //             }
    //           }
    //         }
    //         outs() << "function: [" << F.getName() << "] end\n\n";
    //       }
    //       outs() << "file: [" << M.getModuleIdentifier() << "] end\n";
    //       outs() << "=================================================\n";

    //       OKF("State-Pass Instrumented %u locations.", inst_count);
    //     }
    //=========================================================================================

    if (is_labyrinth_preprocessing || is_labyrinth_Instrumentation) {

      if (inst_count) {
        if (is_labyrinth_preprocessing)
          OKF("State-Pass recognize %u state variables.", inst_count);
        else {
          OKF("State-Pass Instrumented %u locations.", inst_count);
          Instrumented = true;
        }

      } else {
        OKF("No instrumentation state variable found.");
      }
    }

    return Instrumented;

  } // runOnModule end


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
