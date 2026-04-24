Fujitsu FR60 Ghidra Plugin
----
This repository contains a plugin for Ghidra that enables decompilation support for FR60 processors from Fujitsu. In
particular this project targets the MB91302A used in the PlayStation PSX. It includes a loader for the DVRP firmware
used in the PSX to help automatically setup memory ranges.

There is no reason why this plugin cannot be used with other processors from this instruction family, however some
functionality may be unimplemented, specifically the Co-Processor logic is completely stubbed out in this plugin.

## Building
This project is tested on Ghidra 12.0.4 and requires Java 21. Use the Gradle wrapper bundled with
the target Ghidra install so the build matches Ghidra's required Gradle version.
```shell
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.4_PUBLIC
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" buildExtension \
  -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
```

## Installing
Builds are distributed on the [RELEASES](https://github.com/desrdev/ghidra-fr60/releases) page. These can be installed
directly into Ghidra by selecting `File -> Install Extensions` from the main Ghidra UI.

The installation includes support for the FR60 instruction set, as well as a file loader that will detect DVRP fimrware
and automatically setup the memory space for the firmware by reading the header.

The decompiler will also automatically identify function calls that align with the Fujitsu C/C++ compiler's output,
however given hand rolled assembly was commonly used, not all functions will be correctly identified.

There is also an included script, `ResolveUTronSyscalls`, which will scan the application and identify the standard Fujitsu μTron syscalls,
automatically naming these syscalls. The function definition of each syscall is defined in the Fujitsu documentation
[HERE](https://www.fujitsu.com/downloads/MICRO/fma/pdfmcu/resofrke-cm71-00321-3e.pdf).

Would be great to have a way to automatically load these function signatures with this script, contributions welcome!
