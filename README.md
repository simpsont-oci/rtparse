# RT-Parse
> An analysis tool for tracing RTPS interactions within PCAP (TShark) capture files

### Status
[![Build Status](https://travis-ci.org/simpsont-oci/rtparse.png)](https://travis-ci.org/simpsont-oci/rtparse)

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
> RT-Parse currently only runs against the tshark verbose output from a RTPS pcap file
```shell
$ tshark -r example.pcapng -V | tee example.tshark.verbose.txt
$ ./rtparse --file example.tshark.verbose.txt
```

### Contributing / Future Work
> A few thoughts for future development
- Separation of frames summary and frames output (split --show-conversation-frames)
- Support for parsing & frames output for raw pcap files (bypassing tshark, allowing frames to be reloaded into pcap analysis tool like wireshark)
- Support for parsing / analyzing DATA_FRAG, HEARTBEAT_FRAG, and NACK_FRAG submessages
- Support for filtering by "end" of conversation (make use of unregister / dispose messages)
- Latency and throughput analysis?
- Additional support for security?

## License

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
- **[BDS-3-Clause](http://opensource.org/licenses/BSD-3-Clause)**
- Copyright 2019 © <a href="http://objectcomputing.com" target="_blank">OCI</a>.
