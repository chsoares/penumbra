// DInvoke mutation pass — replaces PInvoke with dynamic resolution via NativeLibrary.

using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DotnetWorker;

internal static partial class Program
{
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
                    Console.Error.WriteLine(
                        $"  [dinvoke] skipping (complex params): {method.FullName}");
                    continue;
                }
                var implMap = method.ImplMap;
                pinvokeMethods.Add((method, implMap.Module.Name.String, implMap.Name.String));
            }
        }

        Console.Error.WriteLine(
            $"  [dinvoke] found {pinvokeMethods.Count} PInvoke methods to mutate");

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

            // 6. Replace the method body: call the resolver, which returns delegate,
            //    then invoke it
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
            var newParam = new ParamDefUser(origParam.Name, origParam.Sequence,
                origParam.Attributes);
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
}
