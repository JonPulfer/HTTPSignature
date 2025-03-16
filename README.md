<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://www.swift.org/assets/images/swift~dark.svg">
  <img src="https://www.swift.org/assets/images/swift.svg" alt="Swift logo" height="50">
</picture>

# HTTPSignature

Package that will use PKI (RSA, Curve25519) to verify the signature on HTTP requests. 

This was written to verify signed requests originating from Mastodon. The `Signature` request header looks like: -

```text
Signature: keyId="https://my-example.com/actor#main-key",headers="(request-target) host date digest",signature="..."
```
_example taken from a [blog post](https://blog.joinmastodon.org/2018/06/how-to-implement-a-basic-activitypub-server/) about creating a mastodon service_

