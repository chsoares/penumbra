// Rename pass — randomizes type, method, field, and property names.

using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
    private static HashSet<string> CollectStringLiterals(ModuleDef module)
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string s)
                        strings.Add(s);
                }
            }
        }
        return strings;
    }

    private static void ApplyRename(ModuleDef module, bool safeRename)
    {
        var entryPoint = module.EntryPoint;
        var literals = safeRename ? CollectStringLiterals(module) : new HashSet<string>();

        // Track used names per category to guarantee uniqueness
        var usedTypes = new HashSet<string>(StringComparer.Ordinal);
        var usedMethods = new HashSet<string>(StringComparer.Ordinal);
        var usedFields = new HashSet<string>(StringComparer.Ordinal);
        var usedProps = new HashSet<string>(StringComparer.Ordinal);

        foreach (var type in module.GetTypes().ToList())
        {
            if (type.IsGlobalModuleType) continue;
            if (type.IsInterface) continue;
            if (IsSpecialType(type)) continue; // compiler-generated types
            if (IsCompilerGenerated(type)) continue;
            if (safeRename && literals.Contains(type.Name.String)) continue;

            // Don't rename types with interfaces, enums, or value types
            if (!type.HasInterfaces && !type.IsEnum && !type.IsValueType)
                type.Name = RandomTypeName(usedTypes);

            foreach (var method in type.Methods)
            {
                if (method.IsConstructor) continue;
                if (method == entryPoint) continue;
                if (IsInterfaceImpl(method)) continue;
                if (method.IsSpecialName) continue;
                if (IsCompilerGenerated(method)) continue;
                if (safeRename && literals.Contains(method.Name.String)) continue;
                method.Name = RandomMethodName(usedMethods);
            }

            foreach (var field in type.Fields)
            {
                if (IsCompilerGenerated(field)) continue;
                // Skip fields with compiler-generated names (backing fields, closures)
                if (field.Name.String.Contains('<') || field.Name.String.Contains('>')) continue;
                if (safeRename && literals.Contains(field.Name.String)) continue;
                field.Name = RandomFieldName(usedFields);
            }

            foreach (var prop in type.Properties)
            {
                if (safeRename && literals.Contains(prop.Name.String)) continue;
                prop.Name = RandomPropertyName(usedProps);
            }
        }
    }
}
