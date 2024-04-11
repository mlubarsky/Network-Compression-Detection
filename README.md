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
#Server compilation
gcc -o server server.c -ljson-c -I/path/to/json-c/include

#Client compilation
gcc -o client client.c -ljson-c -I/path/to/json-c/include
```
2) Run 
```
#On server side
./server 7777

#On client side
./client myconfig.json
```

## Authors

[@mlubarsky](https://github.com/mlubarsky)
