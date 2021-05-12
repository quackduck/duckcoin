# Duckcoin CLI Client

## Usage

### Unix

```sh
$ go build
$ ./duckcoin
```

### Docker

```sh
$ docker build -t duckcoin-client .
$ docker run -it -d -v $HOME/.config/duckcoin:/root/.config/duckcoin -e NAME=$USER --name duckcoin-client duckcoin-client
```
