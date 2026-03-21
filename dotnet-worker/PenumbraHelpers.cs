// Reference methods compiled as plain C# — cloned into target modules at runtime via dnlib Importer.
// This avoids hand-written IL which is error-prone and produces InvalidProgramException.

using System;
using System.IO;
using System.Reflection;

namespace DotnetWorker;

public static class PenumbraHelpers
{
    public static string Decrypt(string b64Data, string b64Key)
    {
        byte[] data = Convert.FromBase64String(b64Data);
        byte[] key = Convert.FromBase64String(b64Key);
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ key[i % key.Length]);
        char[] chars = new char[data.Length];
        for (int i = 0; i < data.Length; i++)
            chars[i] = (char)data[i];
        return new string(chars);
    }

    public static void LoadPayload(string[] args)
    {
        var asm = typeof(PenumbraHelpers).Assembly;
        var stream = asm.GetManifestResourceStream("payload.dat");
        var reader = new StreamReader(stream!);
        string payloadB64 = reader.ReadToEnd();
        stream = asm.GetManifestResourceStream("key.dat");
        reader = new StreamReader(stream!);
        string keyB64 = reader.ReadToEnd();
        byte[] enc = Convert.FromBase64String(payloadB64);
        byte[] key = Convert.FromBase64String(keyB64);
        byte[] plain = new byte[enc.Length];
        for (int i = 0; i < enc.Length; i++)
            plain[i] = (byte)(enc[i] ^ key[i % key.Length]);
        Assembly loaded = Assembly.Load(plain);
        MethodInfo? ep = loaded.EntryPoint;
        object[] invokeArgs = ep!.GetParameters().Length > 0
            ? new object[] { args }
            : Array.Empty<object>();
        ep.Invoke(null, invokeArgs);
    }
}
