# RT-Parse
> An analysis tool for tracing RTPS interactions within PCAP (TShark) capture files

## Building

### Setup
- Install CMake (developed using cmake 3.12.1)
- Install make (developed using GNU make 4.2.1) 
- Install a modern C++ compiler (developed using g++ 8.2.0)
- Install Boost C++ libraries (only used for program options) (developed using 1.67.0)

### Clone
- Clone this repository to your local machine using `https://github.com/simpsont-oci/rtparse`
- Switch into cloned directory

### Building
> Run CMake to generate Makefiles
```shell
$ cmake .
```
> Run make
```shell
$ make
```

### Running
> To see a list of available command parameters, run with `--help`
```shell
$ ./rtparse --help
```

## License

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
- **[BDS-3-Clause](http://opensource.org/licenses/BSD-3-Clause)**
- Copyright 2019 © <a href="http://objectcomputing.com" target="_blank">OCI</a>.