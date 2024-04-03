#!/usr/bin/env python3
# This script allows to extract the GUID, MVID, TYPELIB, and Assembly Name of .NET binaries.
# These can then be used to create a Yara rule for hunting opportunities, or to build a collection and statistics.
# GUID: Also known as the TYPELIB ID, generated when creating a new project.
# MVID: Unique identifier for a .NET module, generated at build time.
# TYPELIB: the TYBELIB version.
# Assembly Name: The name of the .NET assembly
# TYPELIB ID/GUID and MVID: You can view these as the "imphash" but for .NET binaries (roughly)
# Get and compile dnlib from https://github.com/0xd4d/dnlib or download dnSpy-netframework.zip from https://github.com/dnSpyEx/dnSpy and grab dnlib.dll from the 'bin' folder 
# Tested with dnlib 3.3.2.0 and 4.4.0.0, any version from 3.x and onward should work
# Author: @bartblaze
# v0.1 - 2024-03-20 - Initial version
# v0.2 - 2024-03-22 - Added assembly name extraction
# v0.3 - 2024-04-02 - Small fixes and Linux support: the script can now also work on Linux, install Mono with 'sudo apt-get install mono-complete'
# v0.4 - 2024-04-03 - Better error handling on Linux.
import sys
import os
import argparse
import csv
import subprocess

try:
    import clr
except ImportError:
    print("pythonnet is not installed. Install it using 'pip install pythonnet' and try again.")
    sys.exit(1)
except RuntimeError as e:
    if "Could not find libmono" in str(e):
        print("Mono runtime (libmono) could not be found. Ensure Mono is installed and configured correctly!")
        print("Install mono-complete using the package manager for your OS.")
        sys.exit(1)
    elif "Failed to create a default .NET runtime" in str(e):
        print("Failed to create a default .NET runtime.")
        print("You may need to install additional Mono libraries or install mono-complete.")
        sys.exit(1)
    else:
        print("An unexpected error occurred while loading the .NET runtime:")
        print(e)
        sys.exit(1)

try:
    clr.AddReference('dnlib')
except Exception as e:
    print(f"Failed to add reference to dnlib: {e}")
    print("Ensure dnlib.dll is in the same folder as this script and it is correctly compiled for your OS!")
    sys.exit(1)

from dnlib.DotNet import ModuleDefMD, AssemblyDef
from System.IO import FileNotFoundException, DirectoryNotFoundException
from System import ArgumentException, BadImageFormatException
from System.Reflection import Assembly

# Argparser
parser = argparse.ArgumentParser(
    description="Extract metadata from .NET assemblies. Extracts GUID, MVID, TYPELIB, and Assembly Name.",
    epilog="Visit https://github.com/bartblaze/DotNet-MetaData for more information or to report issues."
)
parser.add_argument('path', type=str, nargs='?', help='path to the file or folder to analyse')
parser.add_argument('-r', '--recursive', action='store_true', help='search recursively in the folder (default OFF)')
parser.add_argument('-c', '--csv', type=str, help='create a CSV file with the info: filename, assembly name, guid, typelib, mvid')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose, shows errors and non-.NET assemblies')
parser.add_argument('-i', '--info', action='store_true', help='print environment information: Python, pythonnet, dnlib.dll and Yara version info')

args = parser.parse_args()

def get_yara_version():
    yara_executables = ["yara", "yara64", "yara32"]
    for exe in yara_executables:
        try:
            yara_version = subprocess.check_output([exe, "--version"], encoding="utf-8").strip()
            return f"{exe} version: {yara_version}"
        except Exception:
            continue
    return "YARA version not found."

def get_mono_version():
    try:
        mono_version = subprocess.check_output(["mono", "--version"], encoding="utf-8")
        return mono_version.splitlines()[0]
    except Exception as e:
        return f"Failed to get Mono version: {e}"

# Print info on Python, pythonnet, dnlib, .NET (Windows) or Mono (Linux) and Yara
def print_versions():
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"Python version: {python_version}")
    try:
        pythonnet_version = subprocess.check_output(["pip", "show", "pythonnet"], encoding="utf-8")
        for line in pythonnet_version.splitlines():
            if line.startswith("Version:"):
                print(f"pythonnet {line}")
    except Exception as e:
        print(f"Failed to get pythonnet version: {e}")
    try:
        dnlib_assembly = Assembly.LoadFile(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dnlib.dll'))
        dnlib_version = dnlib_assembly.GetName().Version
        print(f"dnlib.dll version: {dnlib_version}")
    except Exception as e:
        print(f"Failed to load dnlib.dll version: {e}")

    try:
        dotnet_version = subprocess.check_output(["dotnet", "--version"], encoding="utf-8").strip()
        print(f".NET environment version: {dotnet_version}")
    except Exception as e:
        print(f"Failed to get .NET environment version: {e}")

    print(get_mono_version())
    print(get_yara_version())

if args.info:
    print_versions()
    sys.exit(0)

if not args.path:
    print("Error: A path to a directory or a .NET binary file is required.")
    parser.print_usage()
    sys.exit(1)

# Grab meta
def get_metadata(assembly_path):
    try:
        module = ModuleDefMD.Load(assembly_path)
        mvid = module.Mvid
        assembly = AssemblyDef.Load(assembly_path)
        assembly_name = assembly.Name  # Extract the assembly name
        typelib = None
        guid = None
        for ca in assembly.CustomAttributes:
            if ca.TypeFullName == 'System.Runtime.InteropServices.GuidAttribute':
                guid = ca.ConstructorArguments[0].Value
            if ca.TypeFullName == 'System.Runtime.InteropServices.TypeLibVersionAttribute':
                typelib = (ca.ConstructorArguments[0].Value, ca.ConstructorArguments[1].Value)
        return str(assembly_name), str(mvid), str(guid), typelib
    except (FileNotFoundException, DirectoryNotFoundException, BadImageFormatException):
        if args.verbose:
            print(f"Skipping non-.NET or missing file: {assembly_path}")
        return None, None, None, None
    except ArgumentException as e:
        if args.verbose:
            print(f"Argument exception for file {assembly_path}: {e}")
        return None, None, None, None
    except Exception as e:
        if args.verbose:
            print(f"An unexpected error occurred while processing {assembly_path}: {e}")
        return None, None, None, None

def process_directory(directory_path):
    csv_data = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if not args.recursive and root != directory_path:
                continue
            assembly_path = os.path.join(root, file)
            assembly_name, mvid, guid, typelib = get_metadata(assembly_path)
            if mvid:
                print(f"File: {assembly_path}")
                print(f"  Assembly Name: {assembly_name}")
                print(f"  MVID: {mvid}")
                if guid:
                    print(f"  GUID: {guid}")
                if typelib:
                    print(f"  TYPELIB Version: {typelib[0]}.{typelib[1]}")
                print('')
                if args.csv:
                    csv_data.append([assembly_path, assembly_name, guid, f"{typelib[0]}.{typelib[1]}" if typelib else "", mvid])
    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Filename', 'Assembly Name', 'GUID', 'TYPELIB', 'MVID'])
            csvwriter.writerows(csv_data)

def process_path(path):
    if os.path.isfile(path):
        assembly_name, mvid, guid, typelib = get_metadata(path)
        if mvid:
            print(f"File: {path}")
            print(f"  Assembly Name: {assembly_name}")
            print(f"  MVID: {mvid}")
            if guid:
                print(f"  GUID: {guid}")
            if typelib:
                print(f"  TYPELIB Version: {typelib[0]}.{typelib[1]}")
            print('')
            if args.csv:
                with open(args.csv, 'w', newline='', encoding='utf-8') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(['Filename', 'Assembly Name', 'GUID', 'TYPELIB', 'MVID'])
                    csvwriter.writerow([path, assembly_name, guid, f"{typelib[0]}.{typelib[1]}" if typelib else "", mvid])
    elif os.path.isdir(path):
        process_directory(path)
    else:
        print(f"Provided path does not exist: {path}")
        sys.exit(1)

process_path(args.path)

if args.csv:
    print(f"CSV file successfully written to: {args.csv}")
