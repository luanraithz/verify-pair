# CLI to verify a rsa certificate pair 

> Utility for everyday tasks at work 

## Accepts both certificate string and base64 encoded certificate

## Using

```
verify-pair -pr ./path-to-my-private-key -pu ./path-to-my-public-key
```

The default values are:

* `pr` - `./private.pem`
* `pu` - `./public.pem`

So, if you are in a folder with both these certificates, none of the parameters is required

## Installing

```
go get -u github.com/luanraithz/verify--pair

```
