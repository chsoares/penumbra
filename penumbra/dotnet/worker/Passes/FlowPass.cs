// Flow pass — NOP padding to shift instruction offsets.

using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyFlow(ModuleDef module)
    {
        // Simplified flow pass: NOP padding only.
        // Opaque predicates removed — they produced InvalidProgramException due to
        // stack imbalance issues. NOPs alone still defeat basic static analysis
        // pattern matching by shifting instruction offsets.
        var rng = new Random();
        foreach (var type in module.GetTypes())
        {
            if (IsSpecialType(type)) continue;
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                if (method.IsConstructor) continue;
                if (method.Body.HasExceptionHandlers) continue;
                if (method.IsVirtual || method.IsAbstract) continue;
                if (IsCompilerGenerated(method)) continue;
                if (IsInterfaceImpl(method)) continue;
                if (method.IsSpecialName) continue;
                var instrs = method.Body.Instructions;
                if (instrs.Count < 5) continue;

                // Collect all branch target instructions — never insert before these
                var branchTargets = new HashSet<Instruction>();
                foreach (var instr in instrs)
                {
                    if (instr.Operand is Instruction target)
                        branchTargets.Add(target);
                    if (instr.Operand is Instruction[] targets)
                        foreach (var t in targets)
                            branchTargets.Add(t);
                }

                // Insert NOP padding at safe positions only (work backwards)
                for (int i = instrs.Count - 1; i >= 1; i--)
                {
                    var cur = instrs[i];
                    // Skip branch targets — inserting before them confuses stack analysis
                    if (branchTargets.Contains(cur)) continue;
                    // Skip flow-control instructions
                    if (cur.OpCode.FlowControl == FlowControl.Branch) continue;
                    if (cur.OpCode.FlowControl == FlowControl.Cond_Branch) continue;
                    if (cur.OpCode.FlowControl == FlowControl.Return) continue;
                    if (cur.OpCode.FlowControl == FlowControl.Throw) continue;
                    // Don't insert after a branch either
                    if (i > 0 && instrs[i - 1].OpCode.FlowControl == FlowControl.Branch) continue;
                    if (i > 0 && instrs[i - 1].OpCode.FlowControl == FlowControl.Cond_Branch)
                        continue;

                    if (rng.NextDouble() < 0.15) // 15% chance
                        instrs.Insert(i, OpCodes.Nop.ToInstruction());
                }

                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
            }
        }
    }
}
