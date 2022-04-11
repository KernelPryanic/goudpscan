#!/bin/bash

go build -o $(pwd)/bin/goudpscan
sudo -u root cp -a $(pwd)/bin/goudpscan /usr/local/bin
