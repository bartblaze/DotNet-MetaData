import "dotnet"
rule PureLogStealer_GUID
{
condition:
dotnet.guids[0]=="9066ee39-87f9-4468-9d70-b57c25f29a67" or
dotnet.typelib=="856e9a70-148f-4705-9549-d69a57e669b0"
}
