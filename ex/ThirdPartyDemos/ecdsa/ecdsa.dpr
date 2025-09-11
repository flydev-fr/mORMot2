program ecdsa;

{ https://synopse.info/forum/viewtopic.php?pid=44357 }

{$I mormot.defines.inc}

uses
  System.SysUtils,
  System.Classes,
  //mormot.crypt.openssl,
  mormot.crypt.x509,
  mormot.crypt.ecc256r1,
  mormot.crypt.ecc,
  mormot.core.base,
  mormot.core.unicode,
  mormot.core.os,
  mormot.core.buffers,   // Base64uriToBin
  mormot.crypt.core,
  mormot.crypt.secure;   // CryptCertX509, TCryptCertValidity

function VerifyECDSASignature_(const aInputString: string;
  const aPEMCertificate: string; const aBase64UriSignature: RawUtf8): boolean;
var
  Crypter: TCryptAsym;
  Cert: ICryptCert;
  PubSPKI, PubDER: RawByteString;
  Sig: RawByteString;     // decoded from Base64Url (raw 64 or DER)
  Data: RawByteString;
  eccPub: TEccPublicKey;
begin
  result := false;

  Crypter := Asym('ES256');
  if Crypter = nil then exit;

  Cert := X509Load(StringToUtf8(aPEMCertificate));
  if Cert = nil then exit;

  // Get the X.509 SubjectPublicKey (SPKI ASN.1, uncompressed point)
  PubSPKI := Cert.GetPublicKey;
  if PubSPKI = '' then exit;

  // Rewrap SPKI to a format TCryptAsym expects:
  // Convert ASN.1 uncompressed point -> compressed TEccPublicKey -> DER
  if not Ecc256r1CompressAsn1(PubSPKI, eccPub) then
    exit;
  PubDER := EccToDer(eccPub);

  // Decode signature; accept raw 64 or DER
  Sig := Base64uriToBin(aBase64UriSignature);
  if Sig = '' then exit;
  if length(Sig) = SizeOf(TEccSignature) then
    // raw R||S -> DER SEQUENCE
    Sig := SetSignatureSecurityRaw(caaES256, Sig);

  Data := StringToUtf8(aInputString);

  // Will hash Data with SHA-256 internally then verify DER signature against DER pubkey
  result := Crypter.Verify(Data, PubDER, Sig, 'sha256');
end;

function VerifyEs256(const PemCert: RawByteString; const Data: RawByteString;
  const SigBase64Url: RawUtf8): boolean;
var
  cert: ICryptCert;
  sig: RawByteString;
  v: TCryptCertValidity;
begin
  result := false;

  if (PemCert = '') or (Data = '') or (SigBase64Url = '') then
    exit;

  // Create an X.509 ES256 certificate instance and load the PEM
  cert := CryptCertX509[caaES256].New;
  if (cert = nil) or not cert.Load(PemCert) then
  begin
    Writeln('ERROR: Failed to load ES256 X.509 certificate.');
    exit;
  end;

  // Decode Base64Url signature (raw 64-byte R||S or DER are both supported by Verify)
  sig := Base64uriToBin(SigBase64Url);
  if sig = '' then
  begin
    Writeln('ERROR: Invalid Base64Url signature.');
    exit;
  end;

  // Verify: hashes Data with SHA-256 internally for ES256
  // Ignore WrongUsage so certificates lacking/odd KeyUsage don't cause a false negative
  v := cert.Verify(sig, Data, [cvWrongUsage]);
  result := v in CV_VALIDSIGN;
end;

// -----------------------------------------------------------------------------

procedure ShowUsage;
begin
  Writeln('Usage:');
  Writeln('  testecdsa <cert.pem> <datafile> <signature_base64url | sigfile>');
  Writeln;
  Writeln('Examples:');
  Writeln('  testecdsa cert.pem data.bin eyJhbGciOiJFUzI1NiJ9...');
  Writeln('  testecdsa cert.pem data.bin sig.txt');
end;

var
  certPath, dataPath, sigArg: string;
  pem, data: RawByteString;
  sigText: RawUtf8;
begin
  try
    if ParamCount < 3 then
    begin
      ShowUsage;
      ExitCode := 2;
      exit;
    end;

    certPath := ParamStr(1);
    dataPath := ParamStr(2);
    sigArg   := ParamStr(3);

    pem := StringFromFile(certPath);
    if pem = '' then
    begin
      Writeln('ERROR: Unable to read certificate: ', certPath);
      ExitCode := 3;
      exit;
    end;

    data := StringFromFile(dataPath);
    if data = '' then
    begin
      Writeln('ERROR: Unable to read data file: ', dataPath);
      ExitCode := 4;
      exit;
    end;

    // If third arg is an existing file, read and compact; otherwise treat as inline Base64Url
    if FileExists(sigArg) then
      sigText := Trim(StringFromFile(sigArg))
    else
      sigText := RawUtf8(sigArg);

    Write('VerifyEs256(): ');
    if VerifyEs256(pem, data, sigText) then
    begin
      Writeln('OK');
      ExitCode := 0;
    end
    else
    begin
      Writeln('FAILED');
      ExitCode := 1;
    end;

    Write('VerifyECDSASignature_(): ');
    if VerifyECDSASignature_(data, pem, sigText) then
    begin
      Writeln('OK');
      ExitCode := 0;
    end
    else
    begin
      Writeln('FAILED');
      ExitCode := 1;
    end;

  Writeln(#13#10'Press ENTER to exit...');
  ConsoleWaitForEnterKey;

  except
    on E: Exception do
    begin
      Writeln('ERROR: ', E.ClassName, ': ', E.Message);
      ExitCode := 10;
    end;
  end;
end.


