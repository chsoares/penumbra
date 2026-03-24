// Encrypt-strings pass — splits string literals with String.Concat.

using System;
using System.Linq;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyEncryptStrings(ModuleDef module)
    {
        // Strategy: split each string literal in half and reassemble with String.Concat.
        // This breaks exact string signatures while preserving runtime behavior.
        // No new types or methods added — only a single MemberRef for String.Concat.
        var concat = new MemberRefUser(module, "Concat",
            MethodSig.CreateStatic(module.CorLibTypes.String,
                module.CorLibTypes.String, module.CorLibTypes.String),
            module.CorLibTypes.String.TypeDefOrRef);

        int count = 0;

        foreach (var type in module.GetTypes())
        {
            // Skip compiler-generated types (async state machines, closures)
            if (IsSpecialType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                if (method.IsConstructor) continue;
                // Skip methods that reference async state machines — modifying
                // their bodies can corrupt field tokens for ILMerged assemblies
                if (method.Body.Instructions.Any(i =>
                    i.Operand is ITypeDefOrRef t && (t.Name.String.Contains('<')
                        || t.Name.String.Contains('>'))))
                    continue;

                var instrs = method.Body.Instructions;
                bool modified = false;
                for (int i = 0; i < instrs.Count; i++)
                {
                    if (instrs[i].OpCode != OpCodes.Ldstr || instrs[i].Operand is not string s)
                        continue;
                    if (s.Length < 4) continue; // too short to split meaningfully

                    // Split at a random point
                    int mid = s.Length / 3 + RandomNumberGenerator.GetInt32(s.Length / 3 + 1);
                    if (mid <= 0 || mid >= s.Length) mid = s.Length / 2;

                    // Modify existing ldstr in-place (preserves branch targets)
                    instrs[i].Operand = s[..mid];
                    instrs.Insert(i + 1, OpCodes.Ldstr.ToInstruction(s[mid..]));
                    instrs.Insert(i + 2, OpCodes.Call.ToInstruction(concat));
                    i += 2;
                    count++;
                    modified = true;
                }
                if (modified)
                {
                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();
                }
            }
        }
        Console.Error.WriteLine($"  [encrypt-strings] split {count} string literals");
    }
}
