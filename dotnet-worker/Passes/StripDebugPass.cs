// Strip-debug pass — removes debug, compiler, and identifying metadata attributes.

using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;

namespace DotnetWorker;

internal static partial class Program
{
    // Debug/compiler attributes to remove entirely
    private static readonly HashSet<string> DebugAttributes = new()
    {
        "System.Diagnostics.DebuggableAttribute",
        "System.Runtime.CompilerServices.CompilationRelaxationsAttribute",
        "System.Runtime.CompilerServices.RuntimeCompatibilityAttribute",
    };

    // Assembly metadata attributes that can fingerprint the original tool
    private static readonly HashSet<string> MetadataAttributes = new()
    {
        "System.Reflection.AssemblyCompanyAttribute",
        "System.Reflection.AssemblyProductAttribute",
        "System.Reflection.AssemblyDescriptionAttribute",
        "System.Reflection.AssemblyCopyrightAttribute",
        "System.Reflection.AssemblyTrademarkAttribute",
        "System.Reflection.AssemblyTitleAttribute",
    };

    private static void ApplyStripDebug(ModuleDef module)
    {
        int removed = 0;
        int scrubbed = 0;

        // Remove assembly-level debug attributes
        var assembly = module.Assembly;
        if (assembly != null)
        {
            var toRemove = assembly.CustomAttributes
                .Where(a => DebugAttributes.Contains(a.TypeFullName))
                .ToList();

            foreach (var attr in toRemove)
            {
                assembly.CustomAttributes.Remove(attr);
                removed++;
            }

            // Scrub identifying metadata attributes (replace value with empty string)
            foreach (var attr in assembly.CustomAttributes)
            {
                if (!MetadataAttributes.Contains(attr.TypeFullName)) continue;
                if (attr.ConstructorArguments.Count == 0) continue;

                var oldVal = attr.ConstructorArguments[0].Value?.ToString() ?? "";
                if (string.IsNullOrEmpty(oldVal)) continue;

                attr.ConstructorArguments[0] = new CAArgument(
                    module.CorLibTypes.String, new UTF8String(""));
                scrubbed++;
                Console.Error.WriteLine(
                    $"  [strip-debug] scrubbed {attr.TypeFullName.Split('.').Last()}"
                    + $": \"{oldVal}\" -> \"\"");
            }
        }

        // Remove module-level debug custom attributes
        var moduleToRemove = module.CustomAttributes
            .Where(a => DebugAttributes.Contains(a.TypeFullName))
            .ToList();
        foreach (var attr in moduleToRemove)
        {
            module.CustomAttributes.Remove(attr);
            removed++;
        }

        Console.Error.WriteLine(
            $"  [strip-debug] removed {removed} debug attributes,"
            + $" scrubbed {scrubbed} metadata attributes");
    }
}
