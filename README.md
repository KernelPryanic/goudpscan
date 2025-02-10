[![GitHub go.mod Go version of a Go module](https://img.shields.io/github/go-mod/go-version/gomods/athens.svg)](https://github.com/KernelPryanic/goudpscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# **goudpscan**

⚡ A pretty fast UDP scanner. ⚡

## Install

You can install the latest version of `goudpscan` by running the following command:

```sh
go install github.com/KernelPryanic/goudpscan@latest
```

This will install the `goudpscan` binary in your `$GOPATH/bin` directory.

To scan ports in verbose mode (listening for ICMP packets; default mode unless `-f` for fast scan is specified), you need to run the binary with super privileges. You can set the `CAP_NET_RAW` capability on the binary to execute the verbose scan without super privileges if you are on Linux 🐧:

```sh
sudo setcap cap_net_raw+ep $(which goudpscan)
```

To install it system-wide, you can run the following command from the root of the repository:
```sh
./install.sh
```
This script sets the `CAP_NET_RAW` capability automatically.

## Build

```sh
go build -o bin/goudpscan
```

## Test

```sh
sudo go test -cover ./...
```

`sudo` is required in order to create a raw socket for the ICMP listener.

## How to use

```sh
sudo goudpscan -f -t 1 -c 975 -p 7,19-22 -s 127.0.0-32.0/24 127.1.0.1
```

If `CAP_NET_RAW` capability is set, you can run the binary without super privileges.

```sh
goudpscan -f -t 1 -c 975 -p 7,19-22 -s 127.0.0-32.0/24
```

Also checkout the lists of [flags](#flags) and [arguments](#arguments).

### Flags

* `    --help` - Show context-sensitive help (also try --help-long and --help-man).
* `    --print` - Print payloads.
* `-l, --payloads=PAYLOADS` - Paylaods yml config file.
* `-f, --fast` - Fast scan mode. Only "Open" or "Unknown" statuses.
* `-t, --timeout=1` - Timeout. How long to wait for response in seconds.
* `-r, --recheck=0` - Recheck. How many times to check every port.
* `-c, --maxConcurrency=768` - Maximum concurrency. How many to scan concurrently every timeout.
* `-s, --sort` - Sort results.
* `-p, --ports=7-1024 ...` - Ports to scan.

### Arguments

* `<hosts>` - Hosts to scan.
