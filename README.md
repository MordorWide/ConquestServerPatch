# MordorWide ConquestServerPatcher

This repository contains the source code to run the dedicated server for `The Lord of the Rings: Conquest` using the EA Nation re-implementation MordorWide.

The application disables the SSL check and changes the endpoints from the shut-down EA servers to the re-implemented ones.

**Note:** You don't need this if you don't want to host a dedicated server on your own.

## How to Use
1. Install `Lord of the Rings: Conquest Dedicated PC Server` on your computer.
2. Go to the installation directory and rename the file `ConquestServer.exe` into `OriginalConquestServer.exe`. The exact file name is important! The directory may be `C:\Program Files (x86)\Electronic Arts\The Lord of the Rings - Conquest Dedicated Server (PC)`.
3. Download the `ConquestServer.exe` from this repository at the release page: [`ConquestServer.exe`](https://github.com/MordorWide/ConquestServerPatch/releases/latest)
4. Copy the downloaded file into the installation directory of the dedicated server.

## Manual Build
If you want to build the program yourself, do the following steps:
1. Setup the Visual C++ compiler suite (e.g. VS 2022), including CMake, and the Windows SDK.
2. Run the following steps in the PowerShell window:
```powershell
# Add CMake to the PATH variable
$env:Path = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;' + $env:Path

# Clone and enter this repository
git clone https://github.com/MordorWide/ConquestServerPatch MordorWide-ConquestServerPatch
cd MordorWide-ConquestServerPatch

# Prepare directory
mkdir build
cd build

# Make build scripts with x86 (32 bit) configuration
cmake -G "Visual Studio 17 2022" -A Win32 ..

# Build the exe file
cmake --build . --config Release

# Get the executable and cleanup the build directory
cd ..
cp build\Release\ConquestServer.exe ConquestServer.exe
rm -r build

# The file is compiled successfully.
```
