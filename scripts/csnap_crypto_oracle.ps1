param([string]$Output, [string]$Candidate, [string]$GenerateArchive)
# Self-authored .NET oracle. All passwords and payloads below are public test
# fixtures. Does not load or execute claude-switcher or touch user profiles.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
#pragma warning disable SYSLIB0060
public static class EnvScopeCsnapOracle {
  static byte[] Slice(byte[] source, int offset, int length) {
    var value = new byte[length]; Buffer.BlockCopy(source, offset, value, 0, length); return value;
  }
  static byte[] Keys(string password, byte[] salt) {
    using (var kdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, 200000, HashAlgorithmName.SHA256)) {
      return kdf.GetBytes(64);
    }
  }
  public static byte[] Encrypt(byte[] plaintext, string password, byte[] salt, byte[] iv) {
    var keys = Keys(password, salt);
    byte[] encrypted;
    using (var aes = Aes.Create()) {
      aes.Key = Slice(keys, 0, 32);
      aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
      using (var encoder = aes.CreateEncryptor()) encrypted = encoder.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }
    var result = new byte[72 + encrypted.Length];
    Buffer.BlockCopy(Encoding.ASCII.GetBytes("CSNAP001"), 0, result, 0, 8);
    Buffer.BlockCopy(salt, 0, result, 8, 16); Buffer.BlockCopy(iv, 0, result, 24, 16);
    Buffer.BlockCopy(encrypted, 0, result, 72, encrypted.Length);
    var signed = new byte[40 + encrypted.Length];
    Buffer.BlockCopy(result, 0, signed, 0, 40); Buffer.BlockCopy(encrypted, 0, signed, 40, encrypted.Length);
    using (var signer = new HMACSHA256(Slice(keys, 32, 32))) {
      Buffer.BlockCopy(signer.ComputeHash(signed), 0, result, 40, 32);
    }
    return result;
  }
  public static byte[] Decrypt(byte[] input, string password) {
    if (input.Length < 88 || (input.Length - 72) % 16 != 0 || Encoding.ASCII.GetString(input, 0, 8) != "CSNAP001") throw new Exception("header");
    var salt = Slice(input, 8, 16);
    var keys = Keys(password, salt);
    var signed = new byte[input.Length - 32];
    Buffer.BlockCopy(input, 0, signed, 0, 40); Buffer.BlockCopy(input, 72, signed, 40, input.Length - 72);
    using (var signer = new HMACSHA256(Slice(keys, 32, 32))) {
      var actual = signer.ComputeHash(signed); int difference = 0;
      for (int n = 0; n < 32; n++) difference |= actual[n] ^ input[n + 40];
      if (difference != 0) throw new Exception("authentication");
    }
    using (var aes = Aes.Create()) {
      aes.Key = Slice(keys, 0, 32); aes.IV = Slice(input, 24, 16);
      aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
      using (var decoder = aes.CreateDecryptor()) return decoder.TransformFinalBlock(input, 72, input.Length - 72);
    }
  }
}
'@
if ($GenerateArchive) {
    Add-Type -AssemblyName System.IO.Compression
    $memory = [IO.MemoryStream]::new()
    $zip = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        $data = @{
            '.claude-switcher-snapshot.json' = '{"format":"claude-switcher-snapshot","version":1,"account":"C","platform":"Windows"}'
            'fixture.txt' = 'INDEPENDENT_DOTNET_FIXTURE'
        }
        foreach ($name in $data.Keys) {
            $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try { $bytes = [Text.Encoding]::UTF8.GetBytes($data[$name]); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        }
        [void]$zip.CreateEntry('nested/empty/')
    } finally { $zip.Dispose() }
    try { $encrypted = [EnvScopeCsnapOracle]::Encrypt($memory.ToArray(), 'x', [byte[]](0..15), [byte[]](16..31)) } finally { $memory.Dispose() }
    $outputStream = [IO.File]::Open($GenerateArchive, [IO.FileMode]::CreateNew)
    try { $outputStream.Write($encrypted, 0, $encrypted.Length) } finally { $outputStream.Dispose() }
    @{ generated = $true; slot = 'C'; fixture_password = 'x'; vendor_executed = $false } | ConvertTo-Json -Compress
} elseif ($Candidate) {
    Add-Type -AssemblyName System.IO.Compression
    $payload = [EnvScopeCsnapOracle]::Decrypt([IO.File]::ReadAllBytes($Candidate), 'fixture8')
    $memory = [IO.MemoryStream]::new($payload, $false)
    $zip = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Read)
    try {
        $marker = $zip.GetEntry('.claude-switcher-snapshot.json')
        $reader = [IO.StreamReader]::new($marker.Open(), [Text.Encoding]::UTF8)
        try { $metadata = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        if ($metadata.format -ne 'claude-switcher-snapshot' -or $metadata.account -ne 'B' -or $metadata.version -ne 1) { throw 'marker' }
        $item = $zip.GetEntry('fixture.txt')
        $reader = [IO.StreamReader]::new($item.Open(), [Text.Encoding]::UTF8)
        try { if ($reader.ReadToEnd() -cne 'INDEPENDENT_DOTNET_FIXTURE') { throw 'payload' } } finally { $reader.Dispose() }
        @{ authenticated = $true; root_layout = $true; slot = 'B'; payload_verified = $true } | ConvertTo-Json -Compress
    } finally { $zip.Dispose(); $memory.Dispose() }
} else {
    $salt = [byte[]](0..15); $iv = [byte[]](16..31)
    $vectors = @()
    foreach ($password in @('fixture8', ('public-unicode-' + [char]0x6D4B + [char]0x8BD5 + [char]::ConvertFromUtf32(0x1F512)))) {
        foreach ($length in @(0, 16, 33)) {
            $plain = [byte[]]::new($length)
            for ($n = 0; $n -lt $length; $n++) { $plain[$n] = ($n * 31 + 7) % 256 }
            $encrypted = [EnvScopeCsnapOracle]::Encrypt($plain, $password, $salt, $iv)
            $decoded = [EnvScopeCsnapOracle]::Decrypt($encrypted, $password)
            if ([Convert]::ToBase64String($decoded) -cne [Convert]::ToBase64String($plain)) { throw 'oracle self-check' }
            $vectors += @{ password = $password; plaintext_base64 = [Convert]::ToBase64String($plain); encrypted_base64 = [Convert]::ToBase64String($encrypted) }
        }
    }
    $document = @{ oracle = 'Self-authored .NET AES / PBKDF2 / HMAC; no vendor execution'; version = 1; vectors = $vectors } | ConvertTo-Json -Depth 5
    if ($Output) { [IO.File]::WriteAllText($Output, $document + "`n", [Text.UTF8Encoding]::new($false)) }
    else { $document }
}
