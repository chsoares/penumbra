// Dotnet IL obfuscation worker — applies dnlib-based passes to .NET assemblies.
// Invoked as subprocess by penumbra.dotnet.il_worker.
// Pass implementations in Passes/ directory (partial class).

using System;
using dnlib.DotNet;

namespace DotnetWorker;

internal static partial class Program
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
        string? amsiFile = null;
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
                case "--amsi-file" when i + 1 < args.Length:
                    amsiFile = args[++i];
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
                    ApplyTrojanize(module, payloadFile, keyFile, amsiFile);
                    break;
                default:
                    Console.Error.WriteLine($"Unknown pass: {pass}");
                    return 1;
            }
        }

        Console.Error.WriteLine($"Writing output: {outputPath}");
        module.Write(outputPath);
        Console.Error.WriteLine("Done.");
        return 0;
    }
}
