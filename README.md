# c-awsv4

Basic C functions to create a signature that can be used in the `Authorizaion` header of an AWS HTTP request. Right now targeted at an AWS S3 `list-objects-v2` request with intent to expand

See `main.c` for example usage

## Build/Install
```
mkdir build
cd build
cmake ..
make
sudo make install
```

## Run
You can run `bash run.sh` to run `main.c` and see example output