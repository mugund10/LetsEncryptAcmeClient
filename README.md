> [!CAUTION]
> client under development



# LetsEncryptAcmeClient

a client to manage TLS certificates with LetsEncrypt.org

> [!TIP]
> Use library.

## usage

```bash
go get github.com/mugund10/LetsEncryptAcmeClient/leacme
```

    key := leacme.NewKey("account")
    client := leacme.NewClient(key, true)
    client.RegisterAccount("yourAccountName-itCanBeAnything", "mailto:example@gmail.com")
    client.GetTLS("subdomain(if needed).domain.tld(mostly .com or .in)")

### example

    package main

    import (
    "github.com/mugund10/LetsEncryptAcmeClient/leacme"
    )

    func main() {
    key := leacme.NewKey("account")
    client := leacme.NewClient(key, true)
    client.RegisterAccount("mugund10", "mailto:example@gmail.com")
    client.GetTLS("homeserver.mugund10.top")

    }
