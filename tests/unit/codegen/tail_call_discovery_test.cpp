/**
 * @file        codegen/tail_call_discovery_test.cpp
 * @brief       Regression coverage for external unconditional branch discovery
 */

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <utility>

#include <rex/codegen/analyze.h>
#include <rex/codegen/binary_view.h>
#include <rex/codegen/codegen_context.h>
#include "codegen/decoded_binary.h"
#include <rex/codegen/function_graph.h>
#include <rex/codegen/function_scanner.h>
#include <rex/codegen/phases.h>
#include <rex/codegen/test_support.h>
namespace rex::codegen {
namespace {

constexpr uint32_t kBase = 0x82000000;
constexpr uint32_t kTarget = kBase + 0x20;

constexpr std::array<uint8_t, 48> kTailCallThunk = {
    0x48, 0x00, 0x00, 0x20,
    0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x60, 0x00, 0x00, 0x00,
    0x3D, 0x60, 0x82, 0x00, 0x39, 0x6B, 0x00, 0x04,
    0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
};
class ExportTableModule final : public TestModule {
 public:
  explicit ExportTableModule(uint32_t exportTableAddress)
      : exportTableAddress_(exportTableAddress) {}

  uint32_t export_table_address() const override { return exportTableAddress_; }

 private:
  uint32_t exportTableAddress_;
};


class EntryPointPipelineModule final : public runtime::Module {
 public:
  EntryPointPipelineModule() : runtime::Module(nullptr) {
    binary_sections_ = {
        {".text", kCodeBase, static_cast<uint32_t>(code_.size()), code_.data(), true, false},
        {".pdata", kPdataAddress, static_cast<uint32_t>(pdata_.size()), pdata_.data(), false, false},
    };
  }

  const std::string& name() const override { return name_; }
  bool is_executable() const override { return true; }
  bool ContainsAddress(uint32_t address) override {
    return address >= kCodeBase && address < kCodeBase + image_size();
  }
  uint32_t base_address() const override { return kCodeBase; }
  uint32_t image_size() const override {
    return kPdataAddress + static_cast<uint32_t>(pdata_.size()) - kCodeBase;
  }
  uint32_t entry_point() const override { return kEntryPoint; }
  uint32_t exception_directory_address() const override { return kPdataAddress; }
  uint32_t exception_directory_size() const override { return static_cast<uint32_t>(pdata_.size()); }

  static constexpr uint32_t kCodeBase = kBase;
  static constexpr uint32_t kEntryPoint = kCodeBase + 4;

 private:
  static constexpr uint32_t kPdataAddress = kCodeBase + 0x100;
  std::string name_{"entrypoint-pipeline"};
  std::array<uint8_t, 8> code_ = {
      0x4E, 0x80, 0x00, 0x20,  // blr, PDATA-covered predecessor
      0x4E, 0x80, 0x00, 0x20,  // blr, XEX entry point
  };
  std::array<uint8_t, 8> pdata_ = {
      0x82, 0x00, 0x00, 0x00,  // BeginAddress = kCodeBase
      0x00, 0x00, 0x02, 0x00,  // FunctionLength = 2 instructions
  };
};

class AddressTakenVeneerModule final : public runtime::Module {
 public:
  struct Options {
    bool addressTaken = true;
    bool executableTarget = true;
    bool nonzeroTarget = true;
    bool canonicalVeneer = true;
    bool dataSection = true;
    bool writableData = false;
    bool oriVeneer = false;
    bool unalignedDestination = false;
    bool codeMaterialized = false;
    bool zeroBase = false;
    bool clobberBase = false;
    bool branchBeforeLow = false;
    bool callBeforeLow = false;
    bool interveningLis = false;
    bool interveningLoad = false;
    bool overwriteLoadBase = false;
    bool updateLoadBase = false;
    bool updateStoreBase = false;
    uint32_t interleavedInstruction = 0;
    uint32_t veneerSize = 16;
    uint32_t pointerSize = 4;
  };

  explicit AddressTakenVeneerModule(Options options) : runtime::Module(nullptr) {
    if (!options.addressTaken || options.codeMaterialized)
      pointer_.fill(0);
    if (options.codeMaterialized) {
      caller_ = {0x48, 0x00, 0x00, 0x05,  // bl next instruction
                 0x3D, 0x40, 0x82, 0x00,  // lis r10, 0x8200
                 0x3A, 0x6F, 0x00, 0x04,  // addi r19, r15, 4
                 0x38, 0xA0, 0x00, 0x04,  // li r5, 4
                 0x38, 0xCA, 0x01, 0x00,  // addi r6, r10, 0x100
                 0x48, 0x00, 0x00, 0x05,  // bl next instruction; function pointer in r6
                 0x4E, 0x80, 0x00, 0x20}; // blr
      if (options.zeroBase) {
        caller_[16] = 0x38;
        caller_[17] = 0xC0;
        caller_[18] = 0x01;
        caller_[19] = 0x00;
      }
      if (options.clobberBase) {
        caller_[8] = 0x39;
        caller_[9] = 0x4F;
        caller_[10] = 0x00;
        caller_[11] = 0x04;
      }
      if (options.branchBeforeLow) {
        caller_[8] = 0x48;
        caller_[9] = 0x00;
        caller_[10] = 0x00;
        caller_[11] = 0x04;
      }
      if (options.callBeforeLow) {
        caller_[8] = 0x48;
        caller_[9] = 0x00;
        caller_[10] = 0x00;
        caller_[11] = 0x05;
      }
      if (options.interveningLis) {
        caller_[8] = 0x3D;
        caller_[9] = 0x60;
        caller_[10] = 0x82;
        caller_[11] = 0x02;
      }
      if (options.interveningLoad) {
        caller_ = {0x48, 0x00, 0x00, 0x05,  // bl next instruction
                   0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
                   0x80, 0x83, 0x00, 0x00,  // lwz r4, 0(r3)
                   0x38, 0xA0, 0x00, 0x04,  // li r5, 4
                   0x38, 0xCB, 0x01, 0x00,  // addi r6, r11, 0x100
                   0x48, 0x00, 0x00, 0x05,  // bl next instruction
                   0x4E, 0x80, 0x00, 0x20}; // blr
      }
      if (options.overwriteLoadBase) {
        caller_[8] = 0x81;
        caller_[9] = 0x63;
      }
      if (options.updateLoadBase) {
        caller_[8] = 0x84;
        caller_[9] = 0x8B;
      }
      if (options.updateStoreBase) {
        caller_[8] = 0x94;
        caller_[9] = 0x8B;
      }
      if (options.interleavedInstruction) {
        for (uint32_t byte = 0; byte < 4; ++byte)
          caller_[8 + byte] = static_cast<uint8_t>(options.interleavedInstruction >> (24 - 8 * byte));
      }
    }
    if (!options.nonzeroTarget)
      target_.fill(0);
    if (!options.canonicalVeneer)
      veneer_[15] = 0x21;

    if (options.oriVeneer) {
      targetAddress_ = kBase + 0x200;
      veneer_ = {0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
                 0x61, 0x6B, 0x02, 0x00,  // ori r11, r11, 0x200
                 0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
                 0x4E, 0x80, 0x04, 0x20}; // bctr
    }
    if (options.unalignedDestination)
      veneer_[7] = 0x01;

    binary_sections_ = {
        {".text", kCaller, static_cast<uint32_t>(caller_.size()), caller_.data(), true, false},
        {".xidata", kVeneer, options.veneerSize, veneer_.data(), true, false},
        {".text", targetAddress_, static_cast<uint32_t>(target_.size()), target_.data(),
         options.executableTarget, false},
        {options.dataSection ? (options.writableData ? ".data" : ".rdata") : ".text", kPointer,
         options.pointerSize, pointer_.data(), !options.dataSection, false},
    };
  }

  const std::string& name() const override { return name_; }
  bool is_executable() const override { return true; }
  bool ContainsAddress(uint32_t address) override {
    return address >= kBase && address < kBase + 0xFF04;
  }
  uint32_t base_address() const override { return kBase; }
  uint32_t image_size() const override { return 0xFF04; }
  uint32_t entry_point() const override { return kCaller; }

  static constexpr uint32_t kCaller = kBase;
  static constexpr uint32_t kVeneer = kBase + 0x100;
  static constexpr uint32_t kPointer = kBase + 0x300;
  uint32_t target_address() const { return targetAddress_; }

 private:
  uint32_t targetAddress_ = kBase + 0xFF00;
  std::string name_{"address-taken-veneer"};
  std::array<uint8_t, 28> caller_ = {0x4E, 0x80, 0x00, 0x20};  // blr
  std::array<uint8_t, 16> veneer_ = {
      0x3D, 0x60, 0x82, 0x01,  // lis r11, 0x8201
      0x39, 0x6B, 0xFF, 0x00,  // addi r11, r11, -0x100
      0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
      0x4E, 0x80, 0x04, 0x20,  // bctr
  };
  std::array<uint8_t, 4> target_ = {0x4E, 0x80, 0x00, 0x20};  // blr
  std::array<uint8_t, 4> pointer_ = {0x82, 0x00, 0x01, 0x00};  // pointer to veneer
};

TEST_CASE("Pipeline registers an executable entry point absent from PDATA", "[codegen]") {
  EntryPointPipelineModule module;

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  auto& state = ctx.analysisState();
  state.format = "xex";
  state.loadAddress = module.base_address();
  state.entryPoint = module.entry_point();
  state.imageSize = module.image_size();

  REQUIRE(Analyze(ctx));

  const auto* pdataFunction = ctx.graph.getFunction(EntryPointPipelineModule::kCodeBase);
  REQUIRE(pdataFunction != nullptr);
  CHECK(pdataFunction->containsAddress(EntryPointPipelineModule::kEntryPoint));

  const auto* entryFunction = ctx.graph.getFunction(EntryPointPipelineModule::kEntryPoint);
  REQUIRE(entryFunction != nullptr);
  CHECK(entryFunction->isSealed());
  CHECK_FALSE(entryFunction->blocks().empty());
}


TEST_CASE("Function graph finds an earlier overlapping owner", "[codegen]") {
  constexpr uint32_t ownerBase = 0x82BFF2A8;
  constexpr uint32_t interiorEntry = 0x82BFF2C0;
  constexpr uint32_t target = 0x82BFF2C4;

  FunctionGraph graph;
  auto* owner = graph.addFunction(ownerBase, 4, FunctionAuthority::GAP_FILL, false);
  REQUIRE(owner != nullptr);
  owner->discover({{ownerBase, 4}, {target, 4}}, {}, {});
  graph.notifyFunctionExtentChanged(ownerBase);
  REQUIRE(graph.addFunction(interiorEntry, 4, FunctionAuthority::DISCOVERED, true) != nullptr);

  CHECK(graph.getFunctionContaining(target) == owner);
  CHECK(graph.classifyTarget(target, *owner, false) == TargetKind::InternalLabel);
  CHECK(graph.classifyTarget(interiorEntry, *owner, true) == TargetKind::Function);
}

TEST_CASE("Scan ignores executable sections shorter than an instruction", "[codegen]") {
  constexpr std::array<uint8_t, 4> data = {0xFF, 0xFF, 0xFF, 0xFF};

  for (size_t size = 0; size < data.size(); ++size) {
    TestModule module;
    module.Load(kBase, data.data(), size);

    auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
    ctx.initDecoded();
    CHECK(ctx.decoded().instructionCount() == 0);
    CHECK(ctx.decoded().get(kBase) == nullptr);
    CHECK(ctx.decoded().range(kBase, kBase + 4).empty());
    CHECK_FALSE(ctx.decoded().isInCodeRegion(kBase));
    REQUIRE(phases::Scan(ctx));
    CHECK(ctx.scan.codeRegions.empty());
  }
}

TEST_CASE("Scan ignores a partial instruction at an executable section end", "[codegen]") {
  constexpr std::array<uint8_t, 5> data = {0x4E, 0x80, 0x00, 0x20, 0xFF};

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  CHECK(ctx.decoded().instructionCount() == 1);
  CHECK(ctx.decoded().get(kBase + 4) == nullptr);
  CHECK(ctx.decoded().range(kBase + 4, kBase + 5).empty());
  CHECK_FALSE(ctx.decoded().isInCodeRegion(kBase + 4));
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.scan.codeRegions.size() == 1);
  CHECK(ctx.scan.codeRegions[0].start == kBase);
  CHECK(ctx.scan.codeRegions[0].end == kBase + 4);
}

TEST_CASE("Scan floors export table cutoffs to complete instructions", "[codegen]") {
  constexpr std::array<uint8_t, 8> data = {
      0x4E, 0x80, 0x00, 0x20, 0x60, 0x00, 0x00, 0x00,
  };

  for (uint32_t offset = 4; offset < data.size(); ++offset) {
    ExportTableModule module(kBase + offset);
    module.Load(kBase, data.data(), data.size());

    auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
    REQUIRE(phases::Scan(ctx));
    REQUIRE(ctx.scan.codeRegions.size() == 1);
    CHECK(ctx.scan.codeRegions[0].start == kBase);
    CHECK(ctx.scan.codeRegions[0].end == kBase + 4);
  }
}

TEST_CASE("Backward conditional target is discovered as a callable tail target", "[codegen]") {
  constexpr uint32_t target = kBase;
  constexpr uint32_t callableEntry = kBase + 8;
  constexpr std::array<uint8_t, 16> data = {
      0x4E, 0x80, 0x00, 0x20,  // blr
      0x60, 0x00, 0x00, 0x00,  // nop
      0x41, 0x82, 0xFF, 0xF8,  // beq target
      0x4E, 0x80, 0x00, 0x20,  // blr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(callableEntry, 4, FunctionAuthority::DISCOVERED, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  const auto* targetNode = ctx.graph.getFunction(target);
  REQUIRE(targetNode != nullptr);
  CHECK(targetNode->authority() == FunctionAuthority::DISCOVERED);

  REQUIRE(phases::GapFill(ctx));
  REQUIRE(phases::Merge(ctx));
  REQUIRE(phases::Validate(ctx));

  const auto* callerNode = ctx.graph.getFunction(callableEntry);
  REQUIRE(callerNode != nullptr);
  REQUIRE(callerNode->tailCalls().size() == 1);
  CHECK(callerNode->tailCalls()[0].site == callableEntry);
  CHECK(callerNode->tailCalls()[0].target.asFunction() == targetNode);
  CHECK(ctx.graph.classifyTarget(target, *callerNode, false) == TargetKind::Function);
}

TEST_CASE("Backward direct call to a callable interior entry remains a call", "[codegen]") {
  constexpr uint32_t target = kBase;
  constexpr uint32_t caller = kBase + 4;
  constexpr std::array<uint8_t, 12> data = {
      0x4E, 0x80, 0x00, 0x20,  // blr
      0x4B, 0xFF, 0xFF, 0xFD,  // bl target
      0x4E, 0x80, 0x00, 0x20,  // blr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true) != nullptr);
  REQUIRE(ctx.graph.addFunction(caller, 4, FunctionAuthority::DISCOVERED, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  REQUIRE(phases::GapFill(ctx));
  REQUIRE(phases::Merge(ctx));
  REQUIRE(phases::Validate(ctx));

  const auto* callerNode = ctx.graph.getFunction(caller);
  REQUIRE(callerNode != nullptr);
  REQUIRE(callerNode->calls().size() == 1);
  CHECK(callerNode->calls()[0].site == caller);
  CHECK(callerNode->calls()[0].target.asFunction() == ctx.graph.getFunction(target));
  CHECK(ctx.graph.classifyTarget(target, *callerNode, true) == TargetKind::Function);
}


TEST_CASE("External unconditional branch target is discovered", "[codegen]") {
  // `b kTarget`, followed by code padding and a tail-call thunk at kTarget.
  // The source is bounded to one instruction, making this `b` a tail call.
  const auto data = kTailCallThunk;

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 4, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  REQUIRE(ctx.graph.getFunction(kTarget) != nullptr);

  REQUIRE(phases::GapFill(ctx));
  REQUIRE(phases::Merge(ctx));
  REQUIRE(phases::Validate(ctx));
}

TEST_CASE("Constant CTR tail target is discovered", "[codegen]") {
  constexpr uint32_t target = kBase + 0x20;
  constexpr std::array<uint8_t, 36> data = {
      0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
      0x39, 0x6B, 0x00, 0x20,  // addi r11, r11, 0x20
      0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
      0x4E, 0x80, 0x04, 0x20,  // bctr
      0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
      0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
      0x4E, 0x80, 0x00, 0x20,  // blr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 16, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  REQUIRE(ctx.graph.getFunction(target) != nullptr);

  REQUIRE(phases::GapFill(ctx));
  REQUIRE(phases::Merge(ctx));
  REQUIRE(phases::Validate(ctx));
}

TEST_CASE("Address-taken CTR veneer and its destination are discovered", "[codegen]") {
  auto checkDiscovered = [](AddressTakenVeneerModule::Options options) {
    AddressTakenVeneerModule module(options);
    auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
    ctx.initDecoded();
    REQUIRE(phases::Scan(ctx));

    REQUIRE(ctx.graph.addFunction(AddressTakenVeneerModule::kCaller,
                                  options.codeMaterialized ? 28 : 4,
                                  FunctionAuthority::CONFIG, true) != nullptr);
    REQUIRE(phases::Discover(ctx));
    const auto* veneer = ctx.graph.getFunction(AddressTakenVeneerModule::kVeneer);
    REQUIRE(veneer != nullptr);
    CHECK(veneer->isDiscovered());
    const auto* target = ctx.graph.getFunction(module.target_address());
    REQUIRE(target != nullptr);
    CHECK(target->isDiscovered());
  };

  SECTION("signed ADDI low half in .rdata") { checkDiscovered({}); }
  SECTION("unsigned ORI low half in .data") {
    checkDiscovered({.writableData = true, .oriVeneer = true});
  }
  SECTION("code-materialized veneer with interleaved unrelated writes") {
    checkDiscovered({.addressTaken = false, .codeMaterialized = true});
  }
  SECTION("later lis in another register preserves the materialized base") {
    checkDiscovered({.addressTaken = false, .codeMaterialized = true, .interveningLis = true});
  }
  SECTION("independent load preserves the materialized base") {
    checkDiscovered({.addressTaken = false, .codeMaterialized = true, .interveningLoad = true});
  }
  SECTION("independent rotate and mask writes preserve the materialized base") {
    for (uint32_t instruction : {0x512B44AEu, 0x514B44AEu, 0x54A5003Eu}) {
      // rlwimi r11,r9,8,18,23; rlwimi r11,r10,8,18,23; rotlwi r5,r5,0.
      checkDiscovered({.addressTaken = false, .codeMaterialized = true,
                       .interleavedInstruction = instruction});
    }
  }
  SECTION("independent word shifts preserve the materialized base") {
    for (uint32_t xo : {24u, 536u, 792u, 824u}) {
      // slw/srw/sraw/srawi r5,r11,r30 (or immediate 30); RS is not written.
      checkDiscovered({.addressTaken = false, .codeMaterialized = true,
                       .interleavedInstruction = 0x7D65F000u | (xo << 1)});
      checkDiscovered({.addressTaken = false, .codeMaterialized = true,
                       .interleavedInstruction = 0x7D45F000u | (xo << 1)});
    }
  }
}

TEST_CASE("Address-taken CTR veneer discovery requires valid source and targets", "[codegen]") {
  auto checkRejected = [](AddressTakenVeneerModule::Options options) {
    AddressTakenVeneerModule module(options);
    auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
    ctx.initDecoded();
    REQUIRE(phases::Scan(ctx));
    REQUIRE(ctx.graph.addFunction(AddressTakenVeneerModule::kCaller,
                                  options.codeMaterialized ? 28 : 4,
                                  FunctionAuthority::CONFIG, true) != nullptr);
    REQUIRE(phases::Discover(ctx));
    CHECK(ctx.graph.getFunction(AddressTakenVeneerModule::kVeneer) == nullptr);
    CHECK(ctx.graph.getFunction(module.target_address()) == nullptr);
  };
  SECTION("RA zero is not a prior lis source") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .zeroBase = true});
  }
  SECTION("tracked source register clobber stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .clobberBase = true});
  }
  SECTION("branch boundary stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .branchBeforeLow = true});
  }
  SECTION("call boundary stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .callBeforeLow = true});
  }
  SECTION("load overwriting the materialized source stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .interveningLoad = true,
                   .overwriteLoadBase = true});
  }
  SECTION("update-form load modifying the materialized base stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .interveningLoad = true,
                   .updateLoadBase = true});
  }
  SECTION("update-form store modifying the materialized base stops propagation") {
    checkRejected({.addressTaken = false, .codeMaterialized = true, .interveningLoad = true,
                   .updateStoreBase = true});
  }
  SECTION("rotate writing the materialized source stops propagation") {
    // rlwimi r10,r9,8,18,23 writes RA, not RS.
    checkRejected({.addressTaken = false, .codeMaterialized = true,
                   .interleavedInstruction = 0x512A44AEu});
  }
  SECTION("word shifts writing the materialized source stop propagation") {
    for (uint32_t xo : {24u, 536u, 792u, 824u})
      checkRejected({.addressTaken = false, .codeMaterialized = true,
                     .interleavedInstruction = 0x7D6AF000u | (xo << 1)});
  }
  SECTION("noncanonical literal destination is rejected") {
    checkRejected({.addressTaken = false, .canonicalVeneer = false, .codeMaterialized = true});
  }

  SECTION("unreferenced veneer") {
    checkRejected({.addressTaken = false});
  }
  SECTION("reference outside data sections") {
    checkRejected({.dataSection = false});
  }
  SECTION("partial reference word") {
    checkRejected({.pointerSize = 3});
  }
  SECTION("truncated veneer") {
    checkRejected({.veneerSize = 14});
  }
  SECTION("noncanonical terminal instruction") {
    checkRejected({.canonicalVeneer = false});
  }
  SECTION("nonexecutable destination") {
    checkRejected({.executableTarget = false});
  }
  SECTION("zero destination instruction") {
    checkRejected({.nonzeroTarget = false});
  }
  SECTION("unaligned destination") {
    checkRejected({.unalignedDestination = true});
  }
}

TEST_CASE("Constant CTR target outside executable code is not discovered", "[codegen]") {
  constexpr uint32_t target = kBase + 0x100;
  constexpr std::array<uint8_t, 16> data = {
      0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
      0x39, 0x6B, 0x01, 0x00,  // addi r11, r11, 0x100
      0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
      0x4E, 0x80, 0x04, 0x20,  // bctr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 16, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  CHECK(ctx.graph.getFunction(target) == nullptr);
}

TEST_CASE("Constant CTR target is not inferred across a branch into its setup", "[codegen]") {
  constexpr uint32_t target = kBase + 0x20;
  constexpr std::array<uint8_t, 36> data = {
      0x48, 0x00, 0x00, 0x08,  // b into the addi, skipping the lis
      0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
      0x39, 0x6B, 0x00, 0x20,  // addi r11, r11, 0x20
      0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
      0x4E, 0x80, 0x04, 0x20,  // bctr
      0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
      0x60, 0x00, 0x00, 0x00,
      0x4E, 0x80, 0x00, 0x20,  // blr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 20, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  CHECK(ctx.graph.getFunction(target) == nullptr);
}

TEST_CASE("Constant CTR call target is registered without becoming a tail call", "[codegen]") {
  constexpr uint32_t target = kBase + 0x20;
  constexpr std::array<uint8_t, 36> data = {
      0x3D, 0x60, 0x82, 0x00,  // lis r11, 0x8200
      0x39, 0x6B, 0x00, 0x20,  // addi r11, r11, 0x20
      0x7D, 0x69, 0x03, 0xA6,  // mtctr r11
      0x4E, 0x80, 0x04, 0x21,  // bctrl
      0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
      0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
      0x4E, 0x80, 0x00, 0x20,  // blr
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 16, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  REQUIRE(ctx.graph.getFunction(target) != nullptr);
  CHECK(ctx.graph.getFunction(kBase)->tailCalls().empty());
}

TEST_CASE("GapFill drains tail targets discovered after its pending snapshot", "[codegen]") {
  constexpr uint32_t target = kBase + 0x24;
  constexpr std::array<uint8_t, 52> data = {
      0x4E, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
      0x48, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x60, 0x00, 0x00, 0x00,
      0x3D, 0x60, 0x82, 0x00, 0x39, 0x6B, 0x00, 0x04,
      0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
  };

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 4, FunctionAuthority::CONFIG, true) != nullptr);
  REQUIRE(phases::Discover(ctx));

  REQUIRE(phases::GapFill(ctx));
  const auto* targetNode = ctx.graph.getFunction(target);
  REQUIRE(targetNode != nullptr);
  CHECK_FALSE(targetNode->blocks().empty());

  REQUIRE(phases::Merge(ctx));
  REQUIRE(targetNode->isSealed());
  REQUIRE(phases::Validate(ctx));
}

TEST_CASE("External unconditional branch outside executable code stays unresolved", "[codegen]") {
  auto data = kTailCallThunk;
  data[2] = 0x01;
  data[3] = 0x00;  // `b kBase + 0x100`, outside TestModule's executable section.

  TestModule module;
  module.Load(kBase, data.data(), data.size());

  auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
  ctx.initDecoded();
  REQUIRE(phases::Scan(ctx));
  REQUIRE(ctx.graph.addFunction(kBase, 4, FunctionAuthority::CONFIG, true) != nullptr);

  REQUIRE(phases::Discover(ctx));
  CHECK(ctx.graph.getFunction(kBase + 0x100) == nullptr);

  REQUIRE(phases::GapFill(ctx));
  REQUIRE(phases::Merge(ctx));
  CHECK_FALSE(phases::Validate(ctx));
}

TEST_CASE("Jump-table bounds follow an equivalent stack-slot reload", "[codegen]") {
  constexpr size_t kTableOffset = 0x100;
  constexpr uint32_t kTarget = kBase + 0x30;
  constexpr uint32_t kBound = 32;

  auto detect = [](uint32_t compareLoad, bool includeStaleComparison,
                   uint32_t branch = 0x41990020) {
    std::array<uint8_t, kTableOffset + (kBound + 3) * 4> data{};
    auto writeWord = [&data](size_t offset, uint32_t word) {
      data[offset] = static_cast<uint8_t>(word >> 24);
      data[offset + 1] = static_cast<uint8_t>(word >> 16);
      data[offset + 2] = static_cast<uint8_t>(word >> 8);
      data[offset + 3] = static_cast<uint8_t>(word);
    };

    writeWord(0x00, 0x90610080);  // stw r3, 128(r1)
    writeWord(0x04, includeStaleComparison ? 0x2F090000 : 0x60000000);
    writeWord(0x08, compareLoad);
    writeWord(0x0C, 0x2B0A0020);  // cmplwi cr6, r10, 32
    writeWord(0x10, branch);
    writeWord(0x14, 0x81210080);  // lwz r9, 128(r1)
    writeWord(0x18, 0x3D808200);  // lis r12, 0x8200
    writeWord(0x1C, 0x398C0100);  // addi r12, r12, 0x100
    writeWord(0x20, 0x5520103A);  // slwi r0, r9, 2
    writeWord(0x24, 0x7C0C002E);  // lwzx r0, r12, r0
    writeWord(0x28, 0x7C0903A6);  // mtctr r0
    writeWord(0x2C, 0x4E800420);  // bctr
    writeWord(0x30, 0x4E800020);  // blr

    for (uint32_t index = 0; index <= kBound + 1; ++index)
      writeWord(kTableOffset + index * 4, kTarget);
    writeWord(kTableOffset + (kBound + 2) * 4, kBase - 4);

    TestModule module;
    module.Load(kBase, data.data(), data.size());
    auto ctx = CodegenContext::Create(BinaryView::fromModule(module), RecompilerConfig{});
    ctx.initDecoded();
    return detectJumpTable(ctx.decoded(), kBase + 0x2C,
                           {kBase, kBase + static_cast<uint32_t>(data.size())}, kBase,
                           kBase + 0x30);
  };

  SECTION("uses the matching r1 stack slot despite a stale r9 comparison") {
    const auto table = detect(0x81410080, true);  // lwz r10, 128(r1)
    REQUIRE(table);
    CHECK(table->indexRegister == 9);
    CHECK(table->targets.size() == kBound + 1);
    CHECK(table->targets.back() == kTarget);
  }

  SECTION("does not accept a different stack slot") {
    const auto table = detect(0x81410084, false);  // lwz r10, 132(r1)
    REQUIRE(table);
    CHECK(table->targets.size() == kBound + 2);
  }

  SECTION("does not reuse a stale r9 comparison for a different stack slot") {
    const auto table = detect(0x81410084, true);  // lwz r10, 132(r1)
    REQUIRE(table);
    CHECK(table->targets.size() == kBound + 2);
  }

  SECTION("does not accept a different stack base") {
    const auto table = detect(0x81420080, false);  // lwz r10, 128(r2)
    REQUIRE(table);
    CHECK(table->targets.size() == kBound + 2);
  }

  SECTION("does not infer bounds from a non-branching GT test") {
    const auto table = detect(0x81410080, true, 0x40990020);  // ble cr6, kBase + 0x30
    REQUIRE(table);
    CHECK(table->targets.size() == kBound + 2);
  }

  SECTION("does not infer bounds from an indirect GT branch") {
    const auto table = detect(0x81410080, true, 0x4D990420);  // bgtctr cr6
    REQUIRE(table);
    CHECK(table->targets.size() == kBound + 2);
  }
}

}  // namespace
}  // namespace rex::codegen
