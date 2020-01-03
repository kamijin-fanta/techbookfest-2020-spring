#!/bin/sh
set -e
mkdir -p obj
go test -c -o obj/drop_all_test .
sudo chown root obj/drop_all_test
sudo chmod +s obj/drop_all_test
go test -o obj/drop_all_test -count=1

