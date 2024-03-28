# Network-Compression-Detection

$S Usage: ./server 8765\
$C Usage: ./client myconfig.json\

gcc -o server server.c -ljson-c -I/path/to/json-c/include\
gcc -o client client.c -ljson-c -I/path/to/json-c/include\