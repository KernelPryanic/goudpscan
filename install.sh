#!/bin/bash

uname_os() {
  echo "$(uname -s | tr '[:upper:]' '[:lower:]')"
}

cd $(pwd)/cmd
go build -o $(pwd)/../bin/goudpscan
cd -
chmod +x $(pwd)/bin/goudpscan
# setcap for linux to allow non-root users to execute the verbose port scan
if [ "$(uname_os)" == "linux" ]; then
  sudo setcap cap_net_raw+ep $(pwd)/bin/goudpscan
fi
sudo cp -a $(pwd)/bin/goudpscan /usr/local/bin
