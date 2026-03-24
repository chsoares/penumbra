using dnlib.DotNet;
using dnlib.DotNet.Emit;

var module = ModuleDefMD.Load(args[0]);

foreach (var type in module.GetTypes())
foreach (var method in type.Methods)
{
    if (method.Name != "PatchAmsi") continue;
    Console.WriteLine($"=== {method.FullName} ===");
    Console.WriteLine($"Locals ({method.Body.Variables.Count}):");
    for (int i = 0; i < method.Body.Variables.Count; i++)
        Console.WriteLine($"  [{i}] {method.Body.Variables[i].Type.FullName}");
    Console.WriteLine($"Instructions ({method.Body.Instructions.Count}):");
    foreach (var instr in method.Body.Instructions)
    {
        string op = instr.Operand switch {
            Instruction t => $"IL_{t.Offset:X4}",
            Local l => $"V_{l.Index}",
            Parameter p => $"A_{p.Index}",
            IMethod m => m.FullName,
            ITypeDefOrRef tr => tr.FullName,
            string s => $"\"{s}\"",
            byte[] b => $"[{string.Join(",", b.Select(x => $"0x{x:X2}"))}]",
            _ => instr.Operand?.ToString() ?? ""
        };
        Console.WriteLine($"  IL_{instr.Offset:X4}: {instr.OpCode,-20} {op}");
    }
    Console.WriteLine($"\nExceptionHandlers: {method.Body.ExceptionHandlers.Count}");
    foreach (var eh in method.Body.ExceptionHandlers)
        Console.WriteLine($"  {eh.HandlerType}: try IL_{eh.TryStart.Offset:X4}-IL_{eh.TryEnd.Offset:X4} handler IL_{eh.HandlerStart.Offset:X4}-IL_{eh.HandlerEnd?.Offset:X4}");
}
