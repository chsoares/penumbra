// Scrub-guid pass — regenerates the assembly GUID to break signature-based fingerprinting.

using System;
using System.Linq;
using dnlib.DotNet;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyScrubGuid(ModuleDef module)
    {
        var assembly = module.Assembly;
        if (assembly == null) return;

        int count = 0;

        // Replace GuidAttribute on the assembly with a fresh GUID
        var guidAttrs = assembly.CustomAttributes
            .Where(a => a.TypeFullName == "System.Runtime.InteropServices.GuidAttribute")
            .ToList();

        foreach (var attr in guidAttrs)
        {
            if (attr.ConstructorArguments.Count > 0)
            {
                var oldGuid = attr.ConstructorArguments[0].Value?.ToString() ?? "(none)";
                var newGuid = Guid.NewGuid().ToString("D");
                attr.ConstructorArguments[0] = new CAArgument(
                    module.CorLibTypes.String, new UTF8String(newGuid));
                count++;
                Console.Error.WriteLine(
                    $"  [scrub-guid] assembly GUID {oldGuid} -> {newGuid}");
            }
        }

        // Also regenerate the module MVID (Module Version ID)
        var oldMvid = module.Mvid ?? Guid.Empty;
        module.Mvid = Guid.NewGuid();
        count++;
        Console.Error.WriteLine(
            $"  [scrub-guid] MVID {oldMvid} -> {module.Mvid}");

        if (count == 0)
            Console.Error.WriteLine("  [scrub-guid] no GUIDs found to replace");
    }
}
