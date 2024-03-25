# DotNet-MetaData

This repository accompanies the blog post located at: https://bartblaze.blogspot.com/2024/03/analyse-hunt-and-classify-malware-using.html

## DotNetMetadata.yar
Yara rule to display binary information to the console. Example use:
```
yara64.exe DotNetMetadata.yar c:\fakepath\all_samples
```

The Yara rule requires at least Yara 4.2.0, that said, it's always recommended to get the latest release from https://github.com/VirusTotal/yara/releases.

## DotNetMetadata.py
Python script to extract the GUID, MVID, TYPELIB, and Assembly Name of .NET binaries. Example use:
```
python DotNetMetadata.py c:\fakepath\all_samples -c samples_output.csv
```

The Python script requires pythonnet to be installed (`pip install pythonnet`) and expects `dnlib.dll` to be in the same directory. 

Get and compile dnlib from https://github.com/0xd4d/dnlib or download dnSpy-netframework.zip from https://github.com/dnSpyEx/dnSpy. The script should work correctly from dnlib version 3.3.2.0 up to and including 4.4.0.0.

## Sample rules
This folder contains sample rules described in the blog post. Do tweak and update according to your needs.

## Example output
Example output for a single file "Mpyiuepnw", a version of PureLogStealer with SHA256 hash: c201449a0845d659c32cc48f998b8cc95c20153bb1974e3a1ba80c53a90f1b27

### Using the Yara rule:
```
$ yara64.exe DotNetMetadata.yar c:\fakepath\Mpyiuepnw.vir
Original Filename: Mpyiuepnw.exe
Internal Name: Mpyiuepnw.exe
Imphash (use with caution): f34d5f2d4577ed6d9ceec516c1f5a744
Compile timestamp (epoch): 1710224522
Module name: Mpyiuepnw.exe
Assembly name: Mpyiuepnw
Typelib: 856e9a70-148f-4705-9549-d69a57e669b0
# of GUIDs: 1
dotnet.guid: 0
 -> guid (MVID) = 9066ee39-87f9-4468-9d70-b57c25f29a67
# of streams: 5
# of resources is: 9
dotnet.resource: 0
 -> name = Rdfeunq.Properties.Resources.resources
 -> offset = 715528
 -> length = 2818774
dotnet.resource: 1
 -> name = Mpyiuepnw.Attributes.WrapperManager.resources
 -> offset = 3534306
 -> length = 180
dotnet.resource: 2
 -> name = Mpyiuepnw.Collections.ImporterHelperCollection.resources
 -> offset = 3534490
 -> length = 180
dotnet.resource: 3
 -> name = Mpyiuepnw.Roles.ConfigOrderRole.resources
 -> offset = 3534674
 -> length = 2932
dotnet.resource: 4
 -> name = Mpyiuepnw.Roles.CodeManager.resources
 -> offset = 3537610
 -> length = 2933
dotnet.resource: 5
 -> name = NAudio.Pages.TemplateAuthenticationPage.resources
 -> offset = 3540547
 -> length = 180
dotnet.resource: 6
 -> name = Mpyiuepnw.Roles.SchemaManager.resources
 -> offset = 3540731
 -> length = 2936
dotnet.resource: 7
 -> name = Mpyiuepnw.Polices.SingletonSingleton.resources
 -> offset = 3543671
 -> length = 180
dotnet.resource: 8
 -> name = NAudio.Common.PrototypeSingleton.resources
 -> offset = 3543855
 -> length = 180
# of module references: 7
# of strings: 710
```

### Using the Python script:

#### Single file
```
$ python DotNetMetadata.py c:\fakepath\Mpyiuepnw.vir
File: c:\fakepath\Mpyiuepnw.vir
  Assembly Name: Mpyiuepnw
  MVID: 9066ee39-87f9-4468-9d70-b57c25f29a67
  GUID: 856e9a70-148f-4705-9549-d69a57e669b0
```

#### Folder
Using the Python script on a set of samples belonging to the Quasar malware family:
```
$  python DotNetMetadata.py c:\fakepath\quasar
File: c:\fakepath\quasar\02f0a7f184fcdaaa4d9a46ca29712c8daae0a46d2038bd362dc818025df8d553.vir
  Assembly Name: Client
  MVID: 60f5dce2-4de4-4c86-aa69-383ebe2f504c
  GUID: None

File: c:\fakepath\quasar\0790bb235f27fa3843f086dbdaac314c2c1b857e3b2b94c2777578765a7894a0.vir
  Assembly Name: spoolsv
  MVID: fb86b5ea-fecf-4314-9908-dfb44a648349
  GUID: ab37fd48-1226-4126-b12d-dea3361fb533

File: c:\fakepath\quasar\07f103ec9f4cf73a1ea534a7b1fed490045e8611c14cb66dfe8784f01ea63e5c.vir
  Assembly Name: Client
  MVID: 60f5dce2-4de4-4c86-aa69-383ebe2f504c
  GUID: None

File: c:\fakepath\quasar\0847a32772909b1685150473294dccd837d8ab3bf8d3a42fc75e8402c8fa9237.vir
  Assembly Name: Client
  MVID: 41eb6d08-2e57-46a1-826d-1b6049ebf6a6
  GUID: None

File: c:\fakepath\quasar\1332bb84dff1a55902b5eb2c76988f94a9edf4727d2c79871c47858b270f0856.vir
  Assembly Name: jkepkr
  MVID: da2e26cb-0ca3-474a-8fb6-08aa7ff3de20
  GUID: None

File: c:\fakepath\quasar\14b67f3273192e061b04c05bb81aea8794f58a856b762006fb2359f55230327c.vir
  Assembly Name: led注Sbm
  MVID: c4653540-cdba-4dba-965f-6b232d0313d8
  GUID: None

File: c:\fakepath\quasar\15931de8e192e8932d881c6d450d52090f92f9b5e9f0f0b903cc5ec033b58b54.vir
  Assembly Name: Client
  MVID: 60f5dce2-4de4-4c86-aa69-383ebe2f504c
  GUID: None
```

#### Example CSV Output:

Table:
| Filename | Assembly Name | GUID | MVID
| ------ | ------- | ------- | ------- |
| c:\fakepath\quasar\02f0a7f184fcdaaa4d9a46ca29712c8daae0a46d2038bd362dc818025df8d553.vir | Client | None | 60f5dce2-4de4-4c86-aa69-383ebe2f504c
| c:\fakepath\quasar\0790bb235f27fa3843f086dbdaac314c2c1b857e3b2b94c2777578765a7894a0.vir | spoolsv | ab37fd48-1226-4126-b12d-dea3361fb533 | fb86b5ea-fecf-4314-9908-dfb44a648349
| c:\fakepath\quasar\07f103ec9f4cf73a1ea534a7b1fed490045e8611c14cb66dfe8784f01ea63e5c.vir | Client | None | 60f5dce2-4de4-4c86-aa69-383ebe2f504c
| c:\fakepath\quasar\0847a32772909b1685150473294dccd837d8ab3bf8d3a42fc75e8402c8fa9237.vir | Client | None | 41eb6d08-2e57-46a1-826d-1b6049ebf6a6
| c:\fakepath\quasar\1332bb84dff1a55902b5eb2c76988f94a9edf4727d2c79871c47858b270f0856.vir | jkepkr | None | da2e26cb-0ca3-474a-8fb6-08aa7ff3de20
| c:\fakepath\quasar\14b67f3273192e061b04c05bb81aea8794f58a856b762006fb2359f55230327c.vir | led注Sbm | None | c4653540-cdba-4dba-965f-6b232d0313d8
| c:\fakepath\quasar\15931de8e192e8932d881c6d450d52090f92f9b5e9f0f0b903cc5ec033b58b54.vir | Client | None | 60f5dce2-4de4-4c86-aa69-383ebe2f504c

CSV:
![image](https://github.com/bartblaze/DotNet-MetaData/assets/3075118/cc829781-6846-44ee-978e-88e6a4ec7e89)
