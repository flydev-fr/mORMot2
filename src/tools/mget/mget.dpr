/// Command Line "mORMot GET" (mget) Tool
// - this program is a part of the Open Source Synopse mORMot framework 2,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md
program mget;

{
  *****************************************************************************

  The mORMot GET (mget) command-line tool retrieve files using HTTP or HTTPS
   - Similar to the homonymous GNU WGet tool, but with some unique features;
   - Can resume aborted downloads, using `RANGE` headers;
   - Can compute and verify the hash of the downloaded content;
   - Can brodcast and download from a local network peer cache.

  *****************************************************************************

  For PeerCache to work, please open port 8099 for TCP+UDP on the firewall:
    Debian:   sudo ufw allow from 192.168.0.0/24 to any port 8099
    Windows:  netsh firewall add portopening all 8099 peerCache
      (see the actual command supplied by "mget /help" response)
}

// ./mget --prompt --peer --debug --limitBandwidthMB 10 --hashValue 4544b35fd0526b1107c8058ea6be8a05087d1160ed46f0e1d3b3c5155f68ba7a "http://ictuswin.com/trans/Father%20Brown%20S01/Father Brown S01E04 -  The Man in the Tree 720P x264 RB58.mp4"

{$I ..\..\mormot.defines.inc}

{$ifdef OSWINDOWS}
  {$apptype console}
  {$R ..\..\mormot.win.default.manifest.res}
{$endif OSWINDOWS}

uses
  {$I ..\..\mormot.uses.inc}
  classes,
  sysutils,
  mormot.core.base,
  mormot.core.os,
  mormot.core.unicode,
  mormot.core.text,
  mormot.core.rtti,
  mormot.core.datetime,
  mormot.core.perf,
  mormot.core.buffers,
  mormot.core.data,
  mormot.core.variants,
  mormot.core.json,
  mormot.core.log,
  mormot.core.zip,
  mormot.net.sock,
  mormot.net.client,
  mormot.net.server,
  mormot.crypt.secure,
  mormot.lib.openssl11,
  mormot.tools.mget;


type
  // reflects the command line switches internal state after parsing parameters
  TGetParameters = (
    gpHelp,
    gpFailed,
    gpWithUrl,
    gpPromptMode);

function GetParameters(p: TMGetProcess; out url: RawUtf8): TGetParameters;
var
  c: TExecutableCommandLine;
  mac: TMacAddress;
  logfolder: TFileName;
  dest: RawUtf8;
  port: integer;
begin
  // some good enough general default values
  p.CacheFolder := MakePath([Executable.ProgramFilePath, 'cache'], true);
  p.tcpTimeoutSec := 10;
  p.peerSecret := 'secret';
  p.PeerSettings.Options := [pcoVerboseLog, pcoTryLastPeer, pcoTryAllPeers];
  p.PeerSettings.CacheTempPath := p.CacheFolder + 'temp';
  p.PeerSettings.CachePermPath := p.CacheFolder + 'perm';
  p.PeerSettings.LimitMBPerSec := 0; // no limit by default
  p.PeerSettings.BroadcastTimeoutMS := 1000; // 1 second delay seems fine
  if GetMainMacAddress(mac, [mafLocalOnly, mafRequireBroadcast]) then
    p.PeerSettings.InterfaceName := mac.IP; // default interface by IP (easy)
  // define main processing switches
  c := Executable.Command;
  c.CaseSensitiveNames := true;
  c.ExeDescription := FormatUtf8('mget %: retrieve files - and more' +
    '%proudly using mORMot 2 - synopse.info',
    [SYNOPSE_FRAMEWORK_VERSION, c.LineFeed]);
  if c.Arg(0, '[hash@]#http://uri resource address to retrieve') then
    url := c.Args[0];
  result := gpWithUrl;
  if c.Option(['P', 'prompt'], 'run in prompt mode (end on void input)') then
    result := gpPromptMode;
  dest := MakePath([GetCurrentDir, ExtractResourceName(url{%H-})]);
  p.DestFile := c.ParamS('&output',
    'destination #filename or existing foldername', dest);
  p.Silent := c.Option('&silent', 'generate no console output');
  p.NoResume := c.Option('&noresume',
     'disable auto-resume of interrupted partial download');
  p.Cache := c.Option('&cache', 'enable local Cache in --cachePath');
  p.Peer := c.Option('&peer', 'enable peer Cache process - see --peer* params');
  logfolder := c.ParamS('logFolder',
     '#folder to be used for --log or --debug output', Executable.ProgramFilePath);
  p.CacheFolder := c.ParamS('cachePath',
     '#folder to be used for local (not peer) --cache', p.CacheFolder);
  if c.Option('&log', 'enable logging in --logFolder') then
    p.Log := TSynLog;
  if c.Option('&debug', 'raw debugging on the console') then
  begin
    p.Log := TSynLog; // force logging even if -l was not specified
    p.Log.Family.EchoToConsole := LOG_VERBOSE; // - [sllTrace];
    p.LogSteps := true;
  end;
  p.Options.TLS.IgnoreCertificateErrors :=
    c.Option('tls&Weak', 'ignore TLS certificate errors');
  p.Options.TLS.CertificateFile  :=
    c.Param('&tlsCert', 'optional client TLS Certificate #filename');
  p.Options.TLS.CACertificatesFile  :=
    c.Param('tlsCA', 'optional client TLS Certificates Authority #filename');
  p.Options.TLS.PrivateKeyFile :=
    c.Param('tlsPrivKey', 'optional client TLS Private Key #filename');
  p.Options.TLS.PrivatePassword :=
    c.Param('tlsPrivPwd', 'optional client TLS Private Key #password');
  p.TrackNetwork := c.Option(
    'peerInterfaceTrack', 'track network interface changes for peer Cache');
  if c.Option(['?', 'help'], 'display this message') then
    result := gpHelp
  else if (result = gpWithUrl) and
          (Url = '') then
    result := gpFailed;
  // add Main and PeerCache params after all main settings using RTTI
  SetObjectFromExecutableCommandLine(p, '', ' for main process');
  SetObjectFromExecutableCommandLine(p.PeerSettings, 'peer', ' for peer Cache');
  // validate whole set of arguments
  case result of
    gpHelp:
      begin
        p.ToConsole('%', [c.FullDescription]);
        port := p.PeerSettings.Port;
        p.ToConsole('For peer Cache to work, please open TCP+UDP port %.', [port]);
        {$ifdef OSLINUX}
        p.ToConsole('    e.g. sudo ufw allow from % to any port %',
          [IP4Subnet(mac.IP, mac.NetMask), port]);
        {$endif OSLINUX}
        {$ifdef OSWINDOWS}
        if OSVersion >= wVista then
          p.ToConsole('  netsh advfirewall firewall add rule name="' +
            'peerCache % tcp" dir=in protocol=tcp localport=% action=allow'#13#10 +
            '  netsh advfirewall firewall add rule name="peerCache % udp" dir=in' +
            ' protocol=udp localport=% action=allow', [port, port, port, port])
        else
          p.ToConsole('  netsh firewall add portopening all % peerCache', [port]);
        {$endif OSWINDOWS}
      end;
    gpFailed:
      p.ToConsole('%', [c.FullDescription('', '', c.LineFeed + 'mget ' +
        c.SwitchAsText('help') + ' to display full usage description')]);
  else if c.ConsoleWriteUnknown then
    result := gpFailed;
  end;
  if result = gpFailed then
    exit;
  // setting the needed logging information
  if p.Log <> nil then
    with p.Log.Family do
    begin
      if logfolder <> '' then
      begin
        PerThreadLog := ptIdentifiedInOneFile;
        FileExistsAction := acAppend;
        AutoFlushTimeOut := 1;
        RotateFileCount := 2;
        RotateFileSizeKB := 2 shl 10;
        LogCompressAlgo := AlgoGZFast; // rotate as mget.1.gz every 2MB
        DestinationPath := EnsureDirectoryExists(logfolder);
      end;
      Level := LOG_VERBOSE; // should be set last
    end;
end;

var
  p: TMGetProcess;
  url: RawUtf8;
begin
  try
    // initialize OpenSSL if needed
    // - on Windows, define FORCE_OPENSSL conditional in your project option
    {$ifdef USE_OPENSSL}
    OpenSslInitialize;
    {$endif USE_OPENSSL}
    // is executed as a service/daemon or as a command line tool
    p := TMGetProcess.Create;
    try
      case GetParameters(p, url) of
        gpFailed:
          ExitCode := 1; // error
        gpWithUrl:
          p.Execute(url);
        gpPromptMode:
          begin
            p.StartPeerCache; // launch background THttpPeerCache
            repeat
              if url = '' then
              begin
                p.hashValue := '';
                p.DestFile := GetCurrentDir;
                p.ToConsole(
                  'Enter a [hash@]http://uri value (leave void to quit)', []);
                readln(url);
              end;
              if (url = '') or
                 (url = 'exit') then
                break;
              p.Execute(url);
              url := '';
            until false;
          end;
      end;
    finally
      p.Free;
    end;
  except
    on E: Exception do
    begin
      ConsoleShowFatalException(E, {waitforenterkey=}false);
      ExitCode := 2; // interrupted
    end;
  end;
end.

