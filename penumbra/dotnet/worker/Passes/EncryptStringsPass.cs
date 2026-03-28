// Encrypt-strings pass — XOR-encrypts string literals with a helper decryptor method.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
    private static void ApplyEncryptStrings(ModuleDef module)
    {
        // Strategy: add a static Decrypt(string b64Data, string b64Key) method
        // to the <Module> global type. Replace each ldstr with two ldstr (encrypted
        // base64 data + key) and a call to Decrypt. The original strings disappear
        // from the binary entirely.

        var byteArraySig = new SZArraySig(module.CorLibTypes.Byte);

        // Build the decryptor method
        var decryptMethod = new MethodDefUser(
            RandomId(),
            MethodSig.CreateStatic(module.CorLibTypes.String,
                module.CorLibTypes.String, module.CorLibTypes.String),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static
                | MethodAttributes.HideBySig);

        decryptMethod.Body = new CilBody();
        var body = decryptMethod.Body;
        body.InitLocals = true;

        // Locals: byte[] data (0), byte[] key (1), int i (2), char[] chars (3), int i2 (4)
        body.Variables.Add(new Local(byteArraySig));                          // 0
        body.Variables.Add(new Local(byteArraySig));                          // 1
        body.Variables.Add(new Local(module.CorLibTypes.Int32));               // 2
        body.Variables.Add(new Local(new SZArraySig(module.CorLibTypes.Char))); // 3
        body.Variables.Add(new Local(module.CorLibTypes.Int32));               // 4

        // Import Convert.FromBase64String
        var convertType = module.CorLibTypes.GetTypeRef("System", "Convert");
        var fromBase64 = new MemberRefUser(module, "FromBase64String",
            MethodSig.CreateStatic(byteArraySig, module.CorLibTypes.String),
            convertType);

        // Import new String(char[])
        var stringCtor = new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Char)),
            module.CorLibTypes.String.TypeDefOrRef);

        var I = body.Instructions;

        // data = Convert.FromBase64String(arg0)
        I.Add(OpCodes.Ldarg_0.ToInstruction());
        I.Add(OpCodes.Call.ToInstruction(fromBase64));
        I.Add(OpCodes.Stloc_0.ToInstruction());
        // key = Convert.FromBase64String(arg1)
        I.Add(OpCodes.Ldarg_1.ToInstruction());
        I.Add(OpCodes.Call.ToInstruction(fromBase64));
        I.Add(OpCodes.Stloc_1.ToInstruction());

        // XOR loop: for (i = 0; i < data.Length; i++) data[i] ^= key[i % key.Length]
        I.Add(OpCodes.Ldc_I4_0.ToInstruction());
        I.Add(OpCodes.Stloc_2.ToInstruction());
        var loopCheck1 = OpCodes.Ldloc_2.ToInstruction();
        I.Add(OpCodes.Br_S.ToInstruction(loopCheck1));

        var loopBody1 = OpCodes.Ldloc_0.ToInstruction();
        I.Add(loopBody1);
        I.Add(OpCodes.Ldloc_2.ToInstruction());
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Ldloc_2.ToInstruction());
        I.Add(OpCodes.Ldelem_U1.ToInstruction());
        I.Add(OpCodes.Ldloc_1.ToInstruction());
        I.Add(OpCodes.Ldloc_2.ToInstruction());
        I.Add(OpCodes.Ldloc_1.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Rem.ToInstruction());
        I.Add(OpCodes.Ldelem_U1.ToInstruction());
        I.Add(OpCodes.Xor.ToInstruction());
        I.Add(OpCodes.Conv_U1.ToInstruction());
        I.Add(OpCodes.Stelem_I1.ToInstruction());
        I.Add(OpCodes.Ldloc_2.ToInstruction());
        I.Add(OpCodes.Ldc_I4_1.ToInstruction());
        I.Add(OpCodes.Add.ToInstruction());
        I.Add(OpCodes.Stloc_2.ToInstruction());

        I.Add(loopCheck1);
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Blt_S.ToInstruction(loopBody1));

        // chars = new char[data.Length]
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Char.TypeDefOrRef));
        I.Add(OpCodes.Stloc_3.ToInstruction());

        // for (i2 = 0; i2 < data.Length; i2++) chars[i2] = (char)data[i2]
        I.Add(OpCodes.Ldc_I4_0.ToInstruction());
        I.Add(OpCodes.Stloc_S.ToInstruction(body.Variables[4]));
        var loopCheck2 = OpCodes.Ldloc_S.ToInstruction(body.Variables[4]);
        I.Add(OpCodes.Br_S.ToInstruction(loopCheck2));

        var loopBody2 = OpCodes.Ldloc_3.ToInstruction();
        I.Add(loopBody2);
        I.Add(OpCodes.Ldloc_S.ToInstruction(body.Variables[4]));
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Ldloc_S.ToInstruction(body.Variables[4]));
        I.Add(OpCodes.Ldelem_U1.ToInstruction());
        I.Add(OpCodes.Stelem_I2.ToInstruction());
        I.Add(OpCodes.Ldloc_S.ToInstruction(body.Variables[4]));
        I.Add(OpCodes.Ldc_I4_1.ToInstruction());
        I.Add(OpCodes.Add.ToInstruction());
        I.Add(OpCodes.Stloc_S.ToInstruction(body.Variables[4]));

        I.Add(loopCheck2);
        I.Add(OpCodes.Ldloc_0.ToInstruction());
        I.Add(OpCodes.Ldlen.ToInstruction());
        I.Add(OpCodes.Conv_I4.ToInstruction());
        I.Add(OpCodes.Blt_S.ToInstruction(loopBody2));

        // return new string(chars)
        I.Add(OpCodes.Ldloc_3.ToInstruction());
        I.Add(OpCodes.Newobj.ToInstruction(stringCtor));
        I.Add(OpCodes.Ret.ToInstruction());

        body.SimplifyBranches();
        body.OptimizeBranches();
        body.OptimizeMacros();

        // Add decryptor to <Module> global type
        module.GlobalType.Methods.Add(decryptMethod);

        // Replace all ldstr instructions with encrypted versions
        int count = 0;
        foreach (var type in module.GetTypes())
        {
            if (IsSpecialType(type)) continue;

            foreach (var method in type.Methods)
            {
                if (method == decryptMethod) continue;
                if (!method.HasBody) continue;
                if (method.IsConstructor) continue;
                if (method.Body.Instructions.Any(i =>
                    i.Operand is ITypeDefOrRef t && (t.Name.String.Contains('<')
                        || t.Name.String.Contains('>'))))
                    continue;

                var instrs = method.Body.Instructions;
                bool modified = false;
                for (int i = 0; i < instrs.Count; i++)
                {
                    if (instrs[i].OpCode != OpCodes.Ldstr
                        || instrs[i].Operand is not string s)
                        continue;
                    if (string.IsNullOrEmpty(s)) continue;
                    if (s.Length > 500) continue; // skip very long strings

                    // XOR encrypt the string
                    var plainBytes = Encoding.UTF8.GetBytes(s);
                    var key = new byte[4];
                    RandomNumberGenerator.Fill(key);
                    var encrypted = new byte[plainBytes.Length];
                    for (int j = 0; j < plainBytes.Length; j++)
                        encrypted[j] = (byte)(plainBytes[j] ^ key[j % key.Length]);

                    var b64Data = Convert.ToBase64String(encrypted);
                    var b64Key = Convert.ToBase64String(key);

                    // Replace ldstr in-place (preserves branch targets)
                    instrs[i].Operand = b64Data;
                    instrs.Insert(i + 1, OpCodes.Ldstr.ToInstruction(b64Key));
                    instrs.Insert(i + 2, OpCodes.Call.ToInstruction(decryptMethod));
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
        Console.Error.WriteLine(
            $"  [encrypt-strings] encrypted {count} string literals with XOR");
    }
}
