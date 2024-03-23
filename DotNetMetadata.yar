import "pe"
import "dotnet"
import "console"

rule DotNetMetadata
{
meta:
	description = "Extracts TYPELIB (GUID) and MVID from .NET binaries."
	author = "@bartblaze"
	reference = "https://github.com/bartblaze/DotNet-MetaData"
	
condition:
//Verify if dotnet
    dotnet.is_dotnet
	
//PE info
    and console.log("Original Filename: ", pe.version_info["OriginalFilename"])
    and console.log("Internal Name: ", pe.version_info["InternalName"])
    and console.log("Imphash (use with caution): ", pe.imphash())
    and console.log("Compile timestamp (epoch): ", pe.timestamp)
	
//Dotnet info
	and console.log("Module name: ", dotnet.module_name)
	and console.log("Assembly name: ", dotnet.assembly.name)
	and console.log("Typelib: ", dotnet.typelib)
	and console.log("# of GUIDs: ", dotnet.number_of_guids)
	and for all i in (0 .. dotnet.number_of_guids - 1) : (
		console.log("dotnet.guid: ", i)
		and console.log(" -> guid (MVID) = ", dotnet.guids[i])
    )
	and console.log("# of streams: ", dotnet.number_of_streams)
	and console.log("# of resources is: ", dotnet.number_of_resources)
	and for all i in (0 .. dotnet.number_of_resources - 1) : (
		console.log("dotnet.resource: ", i)
		and console.log(" -> name = ", dotnet.resources[i].name)
		and console.log(" -> offset = ", dotnet.resources[i].offset)
		and console.log(" -> length = ", dotnet.resources[i].length)
    )
	and console.log("# of module references: ", dotnet.number_of_modulerefs)
	and console.log("# of strings: ", dotnet.number_of_user_strings)
}
