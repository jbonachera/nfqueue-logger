# NFQ Logger

Log dropped iptables packets via DBus

## Usage

```
$ go get -u github.com/jbonachera/nfqueue-logger
$ sudo setcap 'cap_net_admin=+ep' $(which nfqueue-logger)
$ nfqueue-logger
```
