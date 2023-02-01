#!/bin/bash
sudo ip addr flush dev ens33
sudo dmesg -C
sudo insmod func_client.ko
sudo ifconfig vni0 192.168.10.2 netmask 255.255.255.0
printf "myInit OK!\n"
