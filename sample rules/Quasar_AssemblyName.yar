import "dotnet"
rule Quasar_AssemblyName
{
condition:
dotnet.assembly.name == "Client"
}
