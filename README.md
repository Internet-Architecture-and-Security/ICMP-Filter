# ICMP Filter

## Introduction

An automatic mechanism to defense exploits of Linux kernel network stack vulnerabilities via ICMP packet based on eBPF.

The mechanism can be divided into two parts.

- The first one is the the ICMP Receiving Rate Limiter, which limits the ICMP receiving rate from each /24 subnet to 500p/s - 1000p/s randomly.
- The second one is the Stateless-Protocol-Embedded ICMP Error Packet Filter, which filters ICMP error packets embedded with stateless protocols in particular situations.

Please refer to the source code to see the implementation details.

## Usage

This project provides users with two modules, ICMP Filter Loader and ICMP Filter Logger.

The ICMP Filter Loader loads the eBPF program into the kernel, and the ICMP Filter Logger reads the log buffer from the kernel space and presents it to the user.

To build the project, firstly run

```
./build.sh
```

Next, run

```
make load
```

to load the eBPF program into the kernel.

If you want to read the logs, you can run

```
make log
```

After this, the ICMP Filter Logger will print the log to the standard output, and you must ensure that the program was loaded before running this command.

You can also run

```
make log > log.txt
```

in order to save the log into a specified log file.

If you want to remove the eBPF program from the kernel space, please run

```
make unload
```
## Hints

This project has been tested on the default setting of Ubuntu 24.04 LTS (Linux 6.8), and it may not work when the kernel version is too low.