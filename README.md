# tcpsecrets

Linux kernel module to provide access to TCP SYN cookie secrets
via `/proc/tcp_secrets`.

## Kernel Support

### Tested kernels

* 4.19.0-12-amd64 (Debian 10.6)
* 5.7.0-0.bpo.2-amd64 (Debian backports)
* 5.9.0-0.bpo.5-amd64 (ditto)

### Unsupported kernels

* < 4.13 (cookie algorithm changed)

### Custom kernels

These options are required for module to work:

```
CONFIG_LIVEPATCH=y
CONFIG_FTRACE=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_FTRACE_MCOUNT_RECORD=y
```


## Install via DKMS

    KERNEL_VERSION=$(uname -r) make -f Makefile.dkms


## Run Tests

```
make test
```
