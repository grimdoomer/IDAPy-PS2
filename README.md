# IDAPy-PS2
IDA python scripts for reverse engineering PS2 EE and IOP executables. Scripts are written for IDA 7.0, the scripts listed below can be loaded via File->Script file command.

## LabelKernelSyscalls.py
Labels the syscall table in an EE kernel executable, good way to perform initial analysis of a EE kernel image. The kernel image must be loaded at address 0x80000000.
![](/_images/kernel_syscalls.png)

## LabelExecutableSyscalls.py
Labels syscall stubs in an EE usermode (game, app, homebrew, etc) executable.
![](/_images/executable_syscalls.png)

## LabelIOPImports.py
Labels import and export tables in IOP modules. All function names are pulled from the corresponding json files in the IOP directory. Each json file contains a version number and list of module exports for that version of the module, as long as the version number in the json file is greater than or equal to the version number in the import/export table the functions will be labeled. The initial set of json files was built by scraping the [ps2sdk](https://github.com/ps2dev/ps2sdk) repository for module definition files. It's preferred to use the Sony function names over community names where possible.
![](/_images/iop_imports.png)
