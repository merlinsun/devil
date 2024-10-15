# DeVIL
**Debugger Validation via Cross-Level Differential Debugging**


## Table of Contents
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Result](#expr)


## Background
*DeVIL* employs Cross-Level Differential Debugging (*CLDD*) to validate debugger toolchains. *CLDD* involves comparing traces of dynamic program states at different levels of debugging strategies, specifically source-level debugging and instruction-level debugging. 


## Install

This project uses [gcc](https://gcc.gnu.org/), [gdb](http://www.gnu.org/software/gdb/), [llvm](http://llvm.org/) and [lldb](http://lldb.llvm.org/). Go check them out if you don't have them locally installed:

  `apt install python3 gcc gdb llvm lldb`


## Usage

### C Source File

* For a given c source program `test.c`, the command used for DeVIL over the GDB toolchain is:

  `python3 main.py -s test.c --compiler='gcc' --debugger='gdb'`
  

* For a given c source program `test.c`, the command used for DeVIL over the LLDB toolchain is:

  `python3 main.py -s test.c --compiler='clang' --debugger='lldb'`

### C Source Folder

* For a given folder `FilesDir` with multiple C source files, the command used for DeVIL over the GDB toolchain is:

  `python3 main.py -s FilesDir --compiler='gcc' --debugger='gdb'`

* For a given folder `FilesDir` with multiple C source files, the command used for DeVIL over the LLDB toolchain is:

  `python3 main.py -s FilesDir --compiler='clang' --debugger='lldb'`


* Note that, we recommend to use the parallel option when using our tool if your computer has multi-cores:
  ```bash
  $ python3 main.py --parallel -s FilesDir --compiler='gcc' --debugger='gdb'
  $ python3 main.py --parallel -s FilesDir --compiler='clang' --debugger='lldb'
  ```

* Let's take the gcc 12.1.0 testsuite for example
  ```bash
  $ wget https://ftp.gnu.org/gnu/gcc/gcc-12.1.0/gcc-12.1.0.tar.gz
  $ tar -zxvf gcc-12.1.10.tar.gz
  $ python3 main.py -s gcc-12.1.1/gcc/testsuite --parallel --compiler='gcc' --debugger='gdb'
  $ python3 main.py -s gcc-12.1.1/gcc/testsuite --parallel --compiler='clang' --debugger='lldb'
  ```


## Result

The results will be save into the `Expr` folder

* `step` folder saves the results for cross-level differential debugging
* `optimization` folder saves the results for differential optimizations (SOTA)
