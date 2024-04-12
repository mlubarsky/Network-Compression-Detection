# Network-Compression-Detection

## Requirements

**Install json parser library**

## Installation

```bash
sudo apt install libjson-c-dev
```
## Usage

1) Compile 
```
#Server program compilation on Server machine
gcc -o server server.c -ljson-c -I/path/to/json-c/include

#Client program compilation on Client machine
gcc -o client client.c -ljson-c -I/path/to/json-c/include
```
2) Run 
```
#On server side **Note: The port passed in as an argument MUST match the TCP_Pre_Probing_Phase_Port in the config file.**
./server 7777

#On client side
./client myconfig.json
```

## Authors

[@mlubarsky](https://github.com/mlubarsky)
