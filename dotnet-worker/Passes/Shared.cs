// Shared utilities used across multiple passes (rename, dinvoke, trojanize).

using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;

namespace DotnetWorker;

internal static partial class Program
{
    private static string RandomId()
    {
        return "_" + Guid.NewGuid().ToString("N")[..8];
    }

    // ── Plausible name generation ─────────────────────────────────────────

    private static readonly string[] Verbs = {
        "Get", "Set", "Create", "Update", "Delete", "Process", "Handle",
        "Parse", "Format", "Validate", "Transform", "Convert", "Load",
        "Save", "Read", "Write", "Open", "Close", "Init", "Reset",
        "Build", "Resolve", "Execute", "Dispatch", "Register", "Configure"
    };

    private static readonly string[] Nouns = {
        "Service", "Config", "Data", "Context", "Manager", "Factory",
        "Handler", "Provider", "Repository", "Controller", "Adapter",
        "Processor", "Validator", "Formatter", "Converter", "Builder",
        "Resolver", "Dispatcher", "Registry", "Cache", "Buffer",
        "Channel", "Pipeline", "Session", "Token", "Descriptor"
    };

    private static readonly string[] FieldPrefixes = {
        "current", "default", "cached", "internal", "primary",
        "active", "pending", "last", "next", "base"
    };

    private static readonly Random NameRng = new Random();

    private static string UniqueName(HashSet<string> used, Func<string> generator)
    {
        string name = generator();
        if (used.Add(name)) return name;
        // Collision — append incrementing suffix
        for (int i = 2; ; i++)
        {
            string candidate = name + i;
            if (used.Add(candidate)) return candidate;
        }
    }

    /// <summary>Type names: NounNoun (e.g., ServiceManager, DataProcessor)</summary>
    private static string RandomTypeName(HashSet<string> used)
    {
        return UniqueName(used, () =>
            Nouns[NameRng.Next(Nouns.Length)] + Nouns[NameRng.Next(Nouns.Length)]);
    }

    /// <summary>Method names: VerbNoun (e.g., GetService, ProcessData)</summary>
    private static string RandomMethodName(HashSet<string> used)
    {
        return UniqueName(used, () =>
            Verbs[NameRng.Next(Verbs.Length)] + Nouns[NameRng.Next(Nouns.Length)]);
    }

    /// <summary>Field names: prefixNoun (e.g., currentBuffer, cachedConfig)</summary>
    private static string RandomFieldName(HashSet<string> used)
    {
        return UniqueName(used, () =>
            FieldPrefixes[NameRng.Next(FieldPrefixes.Length)] + Nouns[NameRng.Next(Nouns.Length)]);
    }

    /// <summary>Property names: Noun (e.g., Service, Config)</summary>
    private static string RandomPropertyName(HashSet<string> used)
    {
        return UniqueName(used, () =>
            Nouns[NameRng.Next(Nouns.Length)]);
    }

    private static bool IsInterfaceImpl(MethodDef method)
    {
        // Skip methods that implement interfaces or are virtual/override
        if (method.IsVirtual || method.IsAbstract || method.IsNewSlot) return true;
        if (method.HasOverrides) return true;
        // Check if the declaring type implements any interfaces
        var type = method.DeclaringType;
        if (type != null && type.HasInterfaces)
        {
            foreach (var iface in type.Interfaces)
            {
                var ifaceType = iface.Interface.ResolveTypeDef();
                if (ifaceType == null) continue;
                foreach (var ifaceMethod in ifaceType.Methods)
                {
                    if (ifaceMethod.Name == method.Name) return true;
                }
            }
        }
        return false;
    }

    private static bool IsCompilerGenerated(IHasCustomAttribute member)
    {
        return member.CustomAttributes.Any(a =>
            a.TypeFullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
    }

    private static bool IsSpecialType(TypeDef type)
    {
        var name = type.Name.String;
        // Compiler-generated types: async state machines, closures, iterators
        return name.Contains('<') || name.Contains('>') || name.StartsWith("$");
    }
}
