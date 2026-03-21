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
