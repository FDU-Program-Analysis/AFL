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
#include <string>

//#define PASS_LOG
using namespace llvm;

/* stateful variable type */
typedef enum {
  TRANSITION,
  BR,
  SWITCH
} STATE_TYPE;

/* group and value */
typedef std::pair<unsigned, unsigned> GV;

/* parsing params */
cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc(
        "Output directory contains Ftargets.txtm Fnames.txt and BBnames.txt."),
    cl::value_desc("outdir"));

cl::opt<std::string> CFGFile(
    "cfg",
    cl::desc("control flow graph of the program need to be instrumented."),
    cl::value_desc("cfg"));

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

  bool isStateInst(Instruction &I, STATE_TYPE &stateType);

  void getGroupAndValue(Instruction &I, STATE_TYPE stateType, std::vector<GV> &GroupValue);
  
  std::string addStateSuffix(std::string bb, std::vector<GV> &tran, std::vector<GV> &check);

  bool runOnModule(Module &M);

  // main entry point
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = runOnModule(M);
    return (Changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
  }

}; // namespace


bool VariableWatcher::isStateInst(Instruction &I, STATE_TYPE &stateType) {
  bool is_target = false;
  /* get stateful variable/member label */
  if (I.getMetadata("labyrinth.label.state_describing.member")) {
    is_target = true;
    stateType = TRANSITION;

  } else if (I.getMetadata("labyrinth.label.state_describing.variable")) {
    is_target = true;
    if (dyn_cast<StoreInst>(&I))
      stateType = TRANSITION;
    else
      stateType = BR;
    
  } else if (I.getMetadata("labyrinth.label.state_describing.case")) {
    is_target = true;
    stateType = SWITCH;
  }
  return is_target;
}


void VariableWatcher::getGroupAndValue(Instruction &I, STATE_TYPE stateType, std::vector<GV> &GroupValue) {
  
  SmallVector<std::pair<unsigned, MDNode*>, 3> Nodes;

  /* get group and value info from metadata */
  I.getAllMetadataOtherThanDebugLoc(Nodes);
  auto Node = Nodes[Nodes.size() - 1];

  switch (stateType)
  {
  case SWITCH:
    for (int i = 0; i < Node.second->getNumOperands(); i++) {
      if (MDNode *MDN = dyn_cast<MDNode>(Node.second->getOperand(i).get())) {
        if (MDN->getNumOperands() == 2) {
          unsigned group, value;
          if (MDString *MDS = dyn_cast<MDString>(MDN->getOperand(0).get())) {
            group = std::stoi(MDS->getString().str());
          }

          if (MDString *MDS = dyn_cast<MDString>(MDN->getOperand(1).get())) {
            value = std::stoi(MDS->getString().str());
          }
          GroupValue.push_back(GV(group, value));
        }
      }
    }  
    break;

  case TRANSITION:
  case BR:
    if (Node.second->getNumOperands() == 2) {
      unsigned group, value;
      if (MDString *MDS = dyn_cast<MDString>(Node.second->getOperand(0).get())) {
        group = std::stoi(MDS->getString().str());
      }

      if (MDString *MDS = dyn_cast<MDString>(Node.second->getOperand(1).get())) {
        value = std::stoi(MDS->getString().str());
      }
      GroupValue.push_back(GV(group, value));
    }
    break;

  default:
    outs() << "[debug]" << "other type in [getGroupAndValue]\n";
    break;
  }

}

std::string VariableWatcher::addStateSuffix(std::string bb, std::vector<GV> &tran, std::vector<GV> &check) {
  std::string tmpstr = bb;
  if (!tran.empty()) {
    outs() << "[debug] " << "transition: ";
    tmpstr += ":tran:";
    int size = tran.size();
    for (int i = 0; i < size; i++) {
      outs() << "G" << tran[i].first << "V" << tran[i].second << " ";
      tmpstr += "G" + std::to_string(tran[i].first) + "V" + std::to_string(tran[i].second) + ","; 
    }
      tmpstr.pop_back();
      outs() << "\n";
  }

  if (!check.empty()) {
    outs() << "[debug] " << "check: ";
    tmpstr += ":check:";
    int size = check.size();
    for (int i = 0; i < size; i++) {
      outs() << "G" << check[i].first << "V" << check[i].second << " ";
      tmpstr += "G" + std::to_string(check[i].first) + "V" + std::to_string(check[i].second) + ",";
    }
    tmpstr.pop_back();
    outs() << "\n";
}
  tmpstr += ":";
  return tmpstr;
}

bool VariableWatcher::runOnModule(Module &M)   {

    unsigned inst_count = 0;
    bool Instrumented = false;
    bool is_labyrinth_preprocessing = false;
    bool is_labyrinth_Instrumentation = false;

    if (!OutDirectory.empty() && !CFGFile.empty()) {
      FATAL("Cannot specify both '-outdir' and '-distance'!");
      return false;
    }

    std::map<std::string, int> bb_to_node;

    if (!OutDirectory.empty()) {

      is_labyrinth_preprocessing = true;

    } else if (!CFGFile.empty()) {

      std::ifstream cfg(CFGFile);
      if (cfg.is_open()) {

        std::string line;
        while (getline(cfg, line)) {
          if (line.find("[label") != std::string::npos) {
            std::string nodeID = line.substr(4, line.find(" ")-4);
            std::string nodeName = line.substr(line.find("{")+1, line.find("}")-line.find("{")-1);
            outs() << "nodeId " << nodeID << " label: " << nodeName  << "\n";

            int ID = std::stoi(nodeID, 0, 16);
            bb_to_node.emplace(nodeName, ID);
          }
        }
        cfg.close();
        is_labyrinth_Instrumentation = true;

      } else {
        FATAL("Unable to find %s.", CFGFile.c_str());
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


      outs() << "file: " << M.getModuleIdentifier() << "\n";
      for (auto &F : M) {

        outs() << "function: " << F.getName() << "\n";

        bool has_BBs = false;
        bool is_target_func = false;

        std::string funcName = F.getName();
        std::string filename;

        for (auto &BB : F) {

          std::string bb_name("");
          unsigned line;
          bool is_target_BB = false;

          std::vector<GV> transition;
          std::vector<GV> check;

          std::vector<std::string> callees;

          for (auto &I : BB) {

            getDebugLoc(&I, filename, line);
            
            static const std::string Xlibs("/usr/");
            if (filename.empty() || line == 0 ||
                !filename.compare(0, Xlibs.size(), Xlibs)) {
              //outs() << "no location\n";
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
            
            STATE_TYPE state_type;
            if (isStateInst(I, state_type)) {
              outs() << "[debug] StateInst:" << I <<"\n";

              inst_count++;
              is_target_BB = true;

              getGroupAndValue(I, state_type, (state_type == TRANSITION ? transition : check));
            }

            /* record call site */
            if (auto *CI = dyn_cast<CallInst>(&I)) {

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos) {
                filename = filename.substr(found + 1);
              }

              if (auto *CalledFunc = CI->getCalledFunction()) {
                if (!isBlacklisted(CalledFunc)) {
                  callees.push_back(CalledFunc->getName().str());
                }
              }
            }

          }

          /* set BB name */
          if (!bb_name.empty()) {
            bb_name = addStateSuffix(bb_name, transition, check);
            BB.setName(bb_name);
            
            if (!BB.hasName()) {
              std::string newname = bb_name;
              Twine t(newname);
              SmallString<256> NameData;
              StringRef NameRef = t.toStringRef(NameData);
              BB.setValueName(ValueName::Create(NameRef));
            }

            if (!callees.empty()) {
              for (int i = 0; i < callees.size(); i++) {
                bbcalls << BB.getName().str() << "," << callees[i] << "\n";
              }
            }

            if (is_target_BB) {
              bbtargets << BB.getName().str() << "\n";
              is_target_func = true;
            }


            bbnames << BB.getName().str() << "\n";
            has_BBs = true;
          }

          outs() << "BBname: " << BB.getName() << "\n";
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
          if (is_target_func) {
            ftargets << funcName << "\n";
          }

          fnames << funcName << "\n";
        }
        outs() << "------------- function end -------------"
               << "\n";
      }
      outs() << "---------------- file end ----------------"
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
      

      GlobalVariable *LabyStatePtr = 
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__state_map_ptr");

      ConstantInt *One = ConstantInt::get(Int32Ty, 1);
      ConstantInt *SeqLoc = ConstantInt::get(Int32Ty, 4);

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


      outs() << "file: " << M.getModuleIdentifier() << "\n";

      for (auto &F : M) {

        for (auto &BB : F) {

          std::string bb_name;
          std::vector<GV> transition, check;

          for (auto &I : BB) {

            std::string filename;
            unsigned line;

            getDebugLoc(&I, filename, line);
            if (filename.empty() || line == 0) {
              continue;
            }

            if (bb_name.empty()) {
              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos) {
                filename = filename.substr(found + 1);
              }

              bb_name = filename + ":" + std::to_string(line);
              outs() << bb_name << "\n";
            }

            STATE_TYPE state_type;
            if (isStateInst(I, state_type)) {
              getGroupAndValue(I, state_type, (state_type == TRANSITION ? transition : check));
            }

          } // end I
          
          if (!bb_name.empty()) {
            bb_name = addStateSuffix(bb_name, transition, check);
            outs() << bb_name << "\n";
          }

          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));

#ifdef PASS_LOG
          auto BBNameStrPtr = IRB.CreateGlobalStringPtr(bb_name);
          Value *BBNameFormatStrPtr = IRB.CreateBitCast(BBNameFormatStrVar, PrintfArgTy, "BBNameFormatStr");
          IRB.CreateCall(Printf, {BBNameFormatStrPtr, BBNameStrPtr});
#endif

#ifdef PASS_LOG
            /* print runtime log */
            Value *FormatStrPtr = IRB.CreateBitCast(FormatStrVar, PrintfArgTy, "FormatStr");
            IRB.CreateCall(Printf,{FormatStrPtr, MapDist, MapCnt});

#endif

          if (!transition.empty() || !check.empty())  {

            /* Load the state shm base address, need to convert int8 to int32 first */
            LoadInst *StatePtr = IRB.CreateLoad(LabyStatePtr);

            /* Load counter */
            Value *CntPtr = IRB.CreateBitCast(StatePtr, Int32Ty->getPointerTo());
            LoadInst *Cnt = IRB.CreateLoad(CntPtr);
            Cnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(CTX, None));

            /* Increase the counter */
            Value *IncrCnt = IRB.CreateAdd(Cnt, One);
            Value *NewCnt = IRB.CreateSRem(IncrCnt, ConstantInt::get(Int32Ty, MAX_SEQ_WIN));
            IRB.CreateStore(NewCnt, CntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(CTX, None));

            /* update the node id to state[cnt % SIZE] */
            Value *SeqIdx = IRB.CreateAdd(SeqLoc, IRB.CreateMul(ConstantInt::get(Int32Ty, 4), NewCnt));
            Value *SeqPtr = IRB.CreateBitCast(IRB.CreateGEP(StatePtr, SeqIdx), Int32Ty->getPointerTo());            
            int id = bb_to_node.find(bb_name)->second;
            ConstantInt *NodeID = ConstantInt::get(Int32Ty, id);
            IRB.CreateStore(NodeID, SeqPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(CTX, None));

            inst_count++;
          }
        
        } // end BB
      }

      outs() << "Instrumented " << inst_count << " locations\n";
    }

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
