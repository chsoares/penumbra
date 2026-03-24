// Strip-debug pass — removes debug and compiler attributes.

using System.Linq;
using dnlib.DotNet;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyStripDebug(ModuleDef module)
    {
        // Remove assembly-level debug attributes
        var assembly = module.Assembly;
        if (assembly != null)
        {
            var toRemove = assembly.CustomAttributes
                .Where(a =>
                {
                    var name = a.TypeFullName;
                    return name == "System.Diagnostics.DebuggableAttribute"
                        || name == "System.Runtime.CompilerServices.CompilationRelaxationsAttribute"
                        || name == "System.Runtime.CompilerServices.RuntimeCompatibilityAttribute";
                })
                .ToList();

            foreach (var attr in toRemove)
                assembly.CustomAttributes.Remove(attr);
        }

        // Remove module-level debug custom attributes
        var moduleToRemove = module.CustomAttributes
            .Where(a => a.TypeFullName == "System.Diagnostics.DebuggableAttribute")
            .ToList();
        foreach (var attr in moduleToRemove)
            module.CustomAttributes.Remove(attr);
    }
}
