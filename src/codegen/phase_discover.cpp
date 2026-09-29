/**
 * @file        codegen/phase_discover.cpp
 * @brief       Discover phase: iterative function block discovery
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include "codegen_flags.h"
#include "decoded_binary.h"
#include <rex/codegen/function_scanner.h>

#include <array>
#include <optional>
#include <vector>

#include <rex/codegen/phases.h>
#include "phase_helpers.h"

#include <rex/codegen/vtable_scanner.h>
#include <rex/logging.h>

#include "codegen_logging.h"
#include <rex/memory/utils.h>

#include <ppc.h>

using rex::codegen::ppc::Opcode;
using rex::memory::load_and_swap;

namespace rex::codegen {

namespace {

//=============================================================================
// Discover Phase: iterative function block discovery
//=============================================================================

std::optional<uint32_t> canonicalVeneerTarget(CodegenContext& ctx, uint32_t candidate);

template <typename RegisterTarget>
void discoverCodeMaterializedVeneers(CodegenContext& ctx, const std::vector<Block>& blocks,
                                     RegisterTarget&& registerTarget) {
  auto& decoded = ctx.decoded();
  for (const auto& block : blocks) {
    std::array<uint32_t, 32> upper{};
    uint32_t validRegisters = 0;
    for (uint32_t addr = block.base; addr < block.base + block.size; addr += 4) {
      const auto* insn = decoded.get(addr);
      if (!insn)
        break;
      if (insn->is_branch()) {
        validRegisters = 0;
        continue;
      }

      bool knownWrites = true;
      // Preserve only constants whose GPR writes are modeled here; unknown opcodes clear all state.
      uint32_t writtenRegisters = 0;
      if (insn->opcode == Opcode::lis || insn->opcode == Opcode::li ||
          insn->opcode == Opcode::addi) {
        writtenRegisters = uint32_t{1} << insn->D.RT;
        if (insn->opcode == Opcode::addi && insn->D.RA != 0 &&
            (validRegisters & (uint32_t{1} << insn->D.RA))) {
          const uint32_t value = upper[insn->D.RA] +
              static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(insn->D.d)));
          if (canonicalVeneerTarget(ctx, value))
            registerTarget(value);
        }
      } else if (insn->opcode == Opcode::ori) {
        writtenRegisters = uint32_t{1} << insn->D.RA;
        if (validRegisters & (uint32_t{1} << insn->D.RT)) {
          const uint32_t value = upper[insn->D.RT] | static_cast<uint16_t>(insn->D.d);
          if (canonicalVeneerTarget(ctx, value))
            registerTarget(value);
        }
      } else if (insn->opcode == Opcode::mr || insn->opcode == Opcode::slw ||
                 insn->opcode == Opcode::srw || insn->opcode == Opcode::sraw ||
                 insn->opcode == Opcode::srawi) {
        writtenRegisters = uint32_t{1} << insn->X.RA;
      } else if (insn->format == ppc::InstrFormat::kM) {
        writtenRegisters = uint32_t{1} << insn->M.RA;
      } else if (insn->opcode == Opcode::lbz || insn->opcode == Opcode::lhz ||
                 insn->opcode == Opcode::lha || insn->opcode == Opcode::lwz) {
        writtenRegisters = uint32_t{1} << insn->D.RT;
      } else if (insn->opcode == Opcode::lbzu || insn->opcode == Opcode::lhzu ||
                 insn->opcode == Opcode::lwzu) {
        writtenRegisters = (uint32_t{1} << insn->D.RT) | (uint32_t{1} << insn->D.RA);
      } else if (insn->opcode == Opcode::ld) {
        writtenRegisters = uint32_t{1} << insn->DS.RT;
      } else if (insn->opcode == Opcode::ldu) {
        writtenRegisters = (uint32_t{1} << insn->DS.RT) | (uint32_t{1} << insn->DS.RA);
      } else if (insn->opcode == Opcode::stb || insn->opcode == Opcode::sth ||
                 insn->opcode == Opcode::stw || insn->opcode == Opcode::std ||
                 insn->opcode == Opcode::nop) {
      } else if (insn->opcode == Opcode::stbu || insn->opcode == Opcode::sthu ||
                 insn->opcode == Opcode::stwu) {
        writtenRegisters = uint32_t{1} << insn->D.RA;
      } else if (insn->opcode == Opcode::stdu) {
        writtenRegisters = uint32_t{1} << insn->DS.RA;
      } else {
        knownWrites = false;
      }

      if (!knownWrites) {
        validRegisters = 0;
        continue;
      }
      validRegisters &= ~writtenRegisters;
      if (insn->opcode == Opcode::lis) {
        upper[insn->D.RT] = static_cast<uint32_t>(static_cast<uint16_t>(insn->D.d)) << 16;
        validRegisters |= uint32_t{1} << insn->D.RT;
      }
    }
  }
}
void discoverFunction(CodegenContext& ctx, uint32_t funcAddr,
                      const std::unordered_set<uint32_t>& knownFunctions) {
  auto& graph = ctx.graph;
  auto& binary = ctx.binary();
  auto& decoded = ctx.decoded();

  auto* node = graph.getFunction(funcAddr);
  if (!node)
    return;

  // Skip if already discovered
  if (!node->canDiscover()) {
    REXCODEGEN_TRACE("Analyze: function 0x{:08X} already discovered, skipping", funcAddr);
    return;
  }

  // Imports don't need block discovery
  if (node->isImport()) {
    node->discoverAsImport();
    return;
  }

  REXCODEGEN_TRACE("Analyze: discovering function 0x{:08X} ({})", funcAddr, node->name());

  // Lookup pdataSize for exception handler boundary
  uint32_t pdataSize = 0;

  // For CONFIG functions: use only the explicitly declared size (if any)
  // If no size specified (size=0), let discovery find natural boundaries via region
  // Don't inherit PDATA sizes for CONFIG functions - they're user hints for entry points
  if (node->authority() == FunctionAuthority::CONFIG) {
    pdataSize = node->size();  // 0 if not specified, which is correct
    REXCODEGEN_TRACE("Analyze: 0x{:08X} is CONFIG, using declared size={}", funcAddr, pdataSize);
  } else {
    // For non-CONFIG functions, use PDATA size if available
    auto pdataIt = ctx.scan.pdataSizes.find(funcAddr);
    if (pdataIt != ctx.scan.pdataSizes.end()) {
      pdataSize = pdataIt->second;
      REXCODEGEN_TRACE("Analyze: 0x{:08X} using PDATA size={}", funcAddr, pdataSize);
    }
  }

  // Find the code region containing this function
  const CodeRegion* region = nullptr;
  for (const auto& r : ctx.scan.codeRegions) {
    if (r.contains(funcAddr)) {
      region = &r;
      break;
    }
  }
  if (!region) {
    REXCODEGEN_WARN("Analyze: function 0x{:08X} not in any code region", funcAddr);
    return;
  }

  // Direct branches and statically resolved transfers share this registration guard.
  auto registerTarget = [&](uint32_t target) {
    if (graph.isEntryPoint(target) || graph.isImport(target) ||
        binary.isInImportExportRange(target)) {
      return;
    }
    const auto* section = binary.findSection(target);
    if (!section || !section->executable || !section->data ||
        target - section->baseAddress + sizeof(uint32_t) > section->size ||
        load_and_swap<uint32_t>(section->data + target - section->baseAddress) == 0) {
      return;
    }
    graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
  };
  // Pass pdataSize so forward branches within function extent are correctly identified
  auto result = discoverBlocks(decoded, funcAddr, *region, knownFunctions, pdataSize,
                               &ctx.Config().switchTables);

  if (result.blocks.empty()) {
    REXCODEGEN_WARN("Analyze: no blocks found for function 0x{:08X}", funcAddr);
    return;
  }
  discoverCodeMaterializedVeneers(ctx, result.blocks, registerTarget);

  // snooper the function with the discovered blocks and instructions
  node->discover(std::move(result.blocks), std::move(result.instructions),
                 std::move(result.labels));
  graph.notifyFunctionExtentChanged(funcAddr);

  // Add jump tables (targets become labels in the function)
  for (const auto& jt : result.jumpTables) {
    graph.addJumpTableToFunction(funcAddr, jt);
  }

  for (uint32_t target : result.externalCalls) {
    registerTarget(target);
  }
  for (uint32_t target : result.tailCalls) {
    registerTarget(target);
  }
  for (uint32_t target : result.constantCtrTargets) {
    registerTarget(target);
  }
  for (const auto& branch : result.unresolvedBranches) {
    if (branch.isConditional) {
      registerTarget(branch.target);
    }
  }


  // Add unresolved branches for later resolution
  for (const auto& branch : result.unresolvedBranches) {
    graph.addUnresolvedJumpToFunction(funcAddr, branch.site, branch.target, branch.isCall,
                                      branch.isConditional);
  }

  // Scan exception handler regions for branches not in discovered blocks
  if (pdataSize > 0) {
    std::unordered_set<uint32_t> discoveredAddrs;
    for (const auto& block : result.blocks) {
      for (uint32_t addr = block.base; addr < block.base + block.size; addr += 4) {
        discoveredAddrs.insert(addr);
      }
    }

    uint32_t pdataEnd = funcAddr + pdataSize;
    const uint8_t* funcData = binary.translate(funcAddr);
    if (funcData) {
      for (uint32_t offset = 0; offset < pdataSize; offset += 4) {
        uint32_t site = funcAddr + offset;

        // Skip if already discovered by normal control flow
        if (discoveredAddrs.count(site))
          continue;

        // Skip if marked invalid
        auto invalidIt = ctx.analysisState().invalidInstructions.find(site);
        if (invalidIt != ctx.analysisState().invalidInstructions.end()) {
          continue;
        }

        uint32_t insn = load_and_swap<uint32_t>(funcData + offset);
        uint32_t opcode = PPC_OP(insn);

        if (opcode != PPC_OP_B && opcode != PPC_OP_BC)
          continue;

        uint32_t target = 0;
        bool isCall = PPC_BL(insn);
        bool isAbsolute = PPC_BA(insn);

        if (opcode == PPC_OP_B) {
          int32_t branchOffset = PPC_BI(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        } else {
          int32_t branchOffset = PPC_BD(insn);
          target = isAbsolute ? static_cast<uint32_t>(branchOffset) : site + branchOffset;
        }

        // Skip internal jumps within pdata region
        if (!isCall && target >= funcAddr && target < pdataEnd) {
          continue;
        }

        graph.addUnresolvedJumpToFunction(funcAddr, site, target, isCall, false);

        // Register call targets as new functions
        if (isCall && !graph.isEntryPoint(target) && !graph.isImport(target)) {
          if (binary.isInImportExportRange(target)) {
            continue;
          }
          graph.addFunction(target, 4, FunctionAuthority::DISCOVERED, true);
        }
      }
    }
  }
}

void discoverAllFunctions(CodegenContext& ctx) {
  REXCODEGEN_TRACE("Analyze: starting iterative discovery...");

  auto& graph = ctx.graph;
  auto& binary = ctx.binary();

  // Iterative discovery
  size_t iteration = 0;
  size_t lastFunctionCount = 0;
  const size_t maxIterations = REXCVAR_GET(max_discovery_iterations);

  while (iteration < maxIterations) {
    iteration++;

    size_t currentFunctionCount = graph.functionCount();
    if (currentFunctionCount == lastFunctionCount && iteration > 1) {
      REXCODEGEN_DEBUG("Analyze: fixed point at iteration {} ({} functions)", iteration,
                       currentFunctionCount);
      break;
    }

    lastFunctionCount = currentFunctionCount;

    auto knownFunctions = buildKnownFunctions(graph);
    if (discoverPendingFunctions(ctx, knownFunctions) == 0) {
      break;
    }
  }

  REXCODEGEN_TRACE("Analyze: {} functions after call graph expansion", graph.functionCount());

  // VTable scanning
  {
    VTableScanner vtScanner(binary);
    auto vtables = vtScanner.scan();

    size_t newFunctions = 0;

    for (const auto& vt : vtables) {
      for (size_t i = 0; i < vt.slots.size(); i++) {
        uint32_t funcAddr = vt.slots[i];

        if (graph.isEntryPoint(funcAddr))
          continue;
        if (binary.isInImportExportRange(funcAddr))
          continue;

        graph.addFunction(funcAddr, 4, FunctionAuthority::VTABLE, true);
        newFunctions++;
      }
    }

    REXCODEGEN_TRACE("Analyze: VTable scan found {} vtables, {} new functions", vtables.size(),
                     newFunctions);

    // Continue discovery for vtable functions
    if (newFunctions > 0) {
      size_t vtableIteration = 0;
      const size_t maxVtableIterations = REXCVAR_GET(max_vtable_iterations);

      while (vtableIteration < maxVtableIterations) {
        vtableIteration++;

        auto knownFunctions = buildKnownFunctions(graph);
        if (discoverPendingFunctions(ctx, knownFunctions) == 0)
          break;

        if (graph.functionCount() == lastFunctionCount)
          break;
        lastFunctionCount = graph.functionCount();
      }
    }
  }

  REXCODEGEN_TRACE("Analyze: {} total functions after vtable scan", graph.functionCount());
}

std::optional<uint32_t> canonicalVeneerTarget(CodegenContext& ctx, uint32_t candidate) {
  const auto& binary = ctx.binary();
  const auto* xidata = binary.findSectionByName(".xidata");
  if (!xidata || !xidata->executable || !xidata->data || candidate < xidata->baseAddress ||
      (candidate & 0xF) != 0) {
    return std::nullopt;
  }
  const uint32_t candidateOffset = candidate - xidata->baseAddress;
  if (candidateOffset > xidata->size || xidata->size - candidateOffset < 16)
    return std::nullopt;

  const uint8_t* code = xidata->data + candidateOffset;
  const uint32_t lis = load_and_swap<uint32_t>(code);
  const uint32_t low = load_and_swap<uint32_t>(code + 4);
  if ((lis & 0xFFFF0000) != 0x3D600000 ||
      ((low & 0xFFFF0000) != 0x396B0000 && (low & 0xFFFF0000) != 0x616B0000) ||
      load_and_swap<uint32_t>(code + 8) != 0x7D6903A6 ||
      load_and_swap<uint32_t>(code + 12) != 0x4E800420) {
    return std::nullopt;
  }

  const uint32_t high = (lis & 0xFFFF) << 16;
  const uint16_t lowImmediate = static_cast<uint16_t>(low);
  const uint32_t target = (low & 0xFFFF0000) == 0x396B0000
                              ? high + static_cast<uint32_t>(
                                           static_cast<int32_t>(
                                               static_cast<int16_t>(lowImmediate)))
                              : high | lowImmediate;
  if (target == 0 || (target & 3) != 0)
    return std::nullopt;
  const auto* targetSection = binary.findSection(target);
  if (!targetSection || !targetSection->executable || !targetSection->data)
    return std::nullopt;
  const uint32_t targetOffset = target - targetSection->baseAddress;
  if (targetOffset > targetSection->size ||
      targetSection->size - targetOffset < sizeof(uint32_t) ||
      load_and_swap<uint32_t>(targetSection->data + targetOffset) == 0) {
    return std::nullopt;
  }
  return target;
}

// Register canonical XEX veneers taken by non-executable data sections.
void discoverAddressTakenVeneers(CodegenContext& ctx) {
  auto& graph = ctx.graph;
  const auto& binary = ctx.binary();
  for (const auto& dataSection : binary.sections()) {
    if (dataSection.executable || !dataSection.data ||
        (dataSection.name != ".data" && dataSection.name != ".rdata") ||
        dataSection.size < sizeof(uint32_t)) {
      continue;
    }
    for (size_t offset = 0; offset <= dataSection.size - sizeof(uint32_t); offset += 4) {
      const uint32_t candidate = load_and_swap<uint32_t>(dataSection.data + offset);
      if (!canonicalVeneerTarget(ctx, candidate) || binary.isInImportExportRange(candidate) ||
          graph.isEntryPoint(candidate) || graph.isImport(candidate) || graph.getFunction(candidate)) {
        continue;
      }
      graph.addFunction(candidate, 16, FunctionAuthority::DISCOVERED, true);
    }
  }
}

}  // anonymous namespace

/// Discover blocks for all pending functions (shared helper, declared in phase_helpers.h).
size_t discoverPendingFunctions(CodegenContext& ctx,
                                const std::unordered_set<uint32_t>& knownFunctions) {
  std::vector<uint32_t> pending;
  for (const auto& [addr, node] : ctx.graph.functions()) {
    if (node->canDiscover()) {
      pending.push_back(addr);
    }
  }
  for (uint32_t funcAddr : pending) {
    discoverFunction(ctx, funcAddr, knownFunctions);
  }
  return pending.size();
}

namespace phases {

VoidResult Discover(CodegenContext& ctx, ProgressReporter* reporter) {
  (void)reporter;
  discoverAddressTakenVeneers(ctx);
  discoverAllFunctions(ctx);
  return Ok();
}

}  // namespace phases

}  // namespace rex::codegen
