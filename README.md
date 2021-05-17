# eXtended Merkle Signature Scheme Comparison on ARM Cortex-M4

The purpose of this README is to provide detailed introduction on how one can reproduce the experimental results in the corresponding thesis. Moreover, I am providing explanation of which parts of the code were adapted and how to make it runnable on ARM Cortex M4 and introduce various tests. 

## Setup

The OS of the host-device is an Ubuntu 20.04.2 LTS. All the implementations is tested on the STM32F407 discovery board, which is part of the ARM Cortex M4 family. This allowed the usage of the [**mupq**](https://github.com/mupq/pqm4) library. It offers:
* automated generation of test vectors and comparison against output of a reference implementation running host-side (i.e., on the computer the development board is connected to);
* automated benchmarking for speed, stack usage, and code-size;
* automated profiling of cycles spent in symmetric primitives (SHA-2, SHA-3, AES).

It is based on the [PQCRYPTO](https://pqcrypto.eu.org) project funded by the European Commission in the H2020 program.

Note that, the **pqm4** repository is actively investigated, and usually updated, hence please refer to commit *438ab82a10bc6081252f81cf7283efd00b4789e0*.


## Dependencies

There are several dependencies that need to be set before it is possible to compile code on the device.

### Dependencies needed to connect with the device

First of all, an ARM toolchain is needed. It contains integrated and validated packages featuring the gcc compiler, libraries for development on the ARM Cortex M processors. I installed via:
```bat
$ sudo apt-get install git make cmake libusb-1.0-0-dev
$ sudo apt-get install gcc build-essential
```

This step if often problematic on older Ubuntu versions (in particular older than 16.04). Alternative is to use PPA:
```bat
$ sudo add-apt-repository ppa:team-gcc-arm-embedded/ppa
$ sudo apt-get update
$ sudo apt-get install gcc-arm-embedded
```
Note that the `ppa` is not (currently) supported by newer Ubuntu versions. To this point, the ARM toolchain should have been properly installed. 


Second of all, one needs to install **stlink** to make it possible to flash binaries onto the board. Note that **stlink v1.6.0** is the latest version, which supports **mupq** (currently).

Installing **stlink v1.6.0**:

```bat
$ git clone https://github.com/stlink-org/stlink
$ cd stlink
$ git checkout v1.6.0
$ make release
$ cmake .
$ sudo make install # since I need special permissions for the configuration
$ sudo cp st-* /usr/local/bin
$ sudo cp *.so* /lib
$ sudo cp etc/udev/rules.d/49-stlinkv* /etc/udev/rules.d/
$ st-flash --version # finally assure that version is correct
```

### Dependencies needed to run the tests

`python-serial` is the only required library. However, there are specific function calls which require Python >=3.6 and <3.9.

### Connecting the board to the host

Such connection is needed to run the tests from **mupq**. One needs now a mini-USB cable and any UART device. In my work *DSD TECH USB to TTL Serial Adapter Converter with FTDI FT232RL Chip* is used. Jumper cables are needed to connect the `TXD`(also sometimes `TX`) pin of the USB to the `PA3` pin on the board, and also to connect `RXD`(or `RX`) of the UART with `PA2` on the board. In my case, I needed the connect the grounds (`GND`) inbetween.

To check that both are properly connected to the host machine, one should see both devices via the commands:

```bat
$ dmesg | grep tty  # expect the controller to have ttyUSB0
$ lsusb
```

Note that all the tests are now targeting `ttyUSB0`. If, however, the controller is recognized as something different, say `ttyUSB1`, then one needs to change line 63 of the file [interface.py](interface.py) to match the actual `tty`. In this example, it would be `self._dev = serial.Serial("/dev/ttyUSB1", 115200, timeout=10)`.

This should cover a usual set-up. This set-up is tested on recently installed virtual machines, and seems to cover usual potential edge cases. Or at least those that I faced myself.


## Running benchmarks

To execute XMSS with default height of 10, and no further optimizations, consider: 

```bat
$ python3 benchmarks.py
```

Executing the command above compiles 4 binaries for each implemenation which can be used to test and benchmark the schemes. The following binaries are assembled: 
 - `bin/crypto_sign_xmss_ref_test.bin` tests if the scheme works as expected. It tests if a generated signature can be verified correctly.
 - `bin/crypto_sign_xmss_ref_speed.bin` measures the runtime of `crypto_sign_keypair`, `crypto_sign`, and `crypto_sign_open` (the core XMSS procedures).
 - `bin/crypto_sign_xmss_ref_hashing.bin` measures the cycles spent in SHA-2 of `crypto_sign_keypair`, `crypto_sign`, and `crypto_sign_open` for signatures.
 - `bin/crypto_sign_xmss_ref_stack.bin` measures the stack consumption of each of the procedures involved. The memory allocated outside of the procedures (e.g., public keys, private keys, ciphertexts, signatures) is not included.
 
 
The binaries can be flashed to the board using `st-flash`, e.g., `$ st-flash write bin/crypto_sign_xmss_ref_test.bin 0x8000000`. To receive the output, run (on a separate terminal) `python3 hostside/host_unidirectional.py`.

The current benchmark results can be found in the benchmarks_F1, benchmarks_F2, benchmarks_F3 folders. They are really close, so only results from benchmarks_F1 are shown. The code-size measurements only include the code that is provided by the scheme implementation, i.e., exclude common code like hashing or C standard library functions. All cycle counts were obtained at (the default) 24MHz to avoid wait cycles due to the speed of the memory controller.

**To perform the tests as in the results, described, consider running the shell script [worker.sh](worker.sh)**.

To get the figures as in the paper, simply do ```$ python3 my_converter.py```.

## Environment variables

This thesis aims to compare the performance of different parameter sets for XMSS. It is possible to pass the following parameters to observe different results:

```
-DH= {0, 1, 2} (total height as in the required parameters, 0 corresponds to 10, 1 to 16, 2 to 20)
-DNO_BITMASK (if specified, remove the bitmask in signature generation)
-DPRE_COMP (if specified, pre-computatation of the pseudo-random-function)
-DFAST= {0, 1} (1 would allow improvements described in the second paper, otherwise setting block- and shift-size are ignored)
-DSHIFT= {8, ..., 15} (parameter T looking for best verification time)
-DBLOCK= {0, 1, 2} (SHA-2 processing that many 512-bit blocks, when the shift is allowed) 
```

If none of the options are passed defauls are `-DH=0 -DFAST=0`. If only `-DFAST=1` is specified, then `-DSHIFT=10 -DBLOCK=2` is taken.

To benchmark a specific schema:

```bat
$ CFLAGS="-DH=1  -DFAST=1 -DNO_BITMASK -DPRE_COMP" python3 benchmarks.py
```

All parameterizations correspond to actual required XMSS Parameters as in the [RFC](https://tools.ietf.org/id/draft-irtf-cfrg-xmss-hash-based-signatures-10.html).

## License

Major part of the code comes from [**mupq**](https://github.com/mupq/pqm4). Their license is added here.

"Different parts of **pqm4** have different licenses.  Each subdirectory containing implementations contains a LICENSE file stating  under what license that specific implementation is released.  The files in common contain licensing information at the top of the file (and are currently either public domain or MIT).  All other code in this repository is released under the conditions of [CC0](https://creativecommons.org/publicdomain/zero/1.0/)."