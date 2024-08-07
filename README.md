
# Time Stamp Signing (TSSig)

> **All very much a work in progress.  Everything subject to change until v1.0.**

TSSig is an opinionated pattern for cryptographically signing a time stamp, combined with a (hash) digest, by someone who represents a trusted third party.

TSSig allows one person to prove to another that a given message (digest) existed at a specific moment in time.

If:
```mermaid
graph LR
A[Bob] -- Trusts --> T[TSSig Authority T]
B[Alice] -- Trusts --> T[TSSig Authority T]
``` 

Then if Bob creates the digest:
```
hash("I, Bob, am very fond of cake")
```
And he get it signed by TSSig Authority T, giving:
```
hash of:	"I, Bob, am very fond of cake"
signed at:	2023-11-26 09:39:34
signature:	I, TSSig Authority T, sign that the above hash was sent to me at the above time.
```
Then assuming Alice trusts the authority that signed the digest with the timestamp, then she can verify that Bob did indeed say that he was fond of cake on a given date and time.

```mermaid
graph LR
C[Bob] -- Digest --> T2[Authority T] -- Signed Timestamp --> C[Bob]
C[Bob] -- Signed Timestamp  --> D[Alice] --> G[Alice can verify Bob had the digest at a given time]
```

TSSig signatures are linked back to the domain name of an issuing authority, thus we achieve  our level of trust from:
1. Using a traditional TLS certificate chain to verify we're talking to the expected domain; and
2. Explicitly listing the domains we trust as a TSSig authority.

For example, if we have a signed time stamp with the issuer:
```json  
"issuer": {    
    "root-key": "https://keys.tssig.com/v1.der",    
}  
```  
Then we are specifying `keys.tssig.com` is an authority we trust. And as accessing their root public key is done over HTTPS, we get traditional TLS domain verification.

## Questions...

### What does a TSSig signed time stamp look like?
```json  
{    
    "issuer": {    
       "root-key": "https://keys.tssig.com/v1.der",    
       "leaf-key": "MCowBQYDK2VwAyEAHxkKQvOhRinVkwaImUKjTKLAFYYZlqydC0XtWs7P_54=",    
       "signature": "MGQCMHuvCBE1wKASJWugsB5OTxO2IakeR7S9_jnpFtEzkKXXkgh1lLeVuR9zAO8uqD_-HgIwYuCutPd9E5Jxye94_jhbZ_KD9jmEydIk_Vt25ovrlU3kVx8PNM_uaPeMs_6-FS6S"    
    },    
    "datetime": "2023-11-26T09:39:34.489121Z",    
    "digest": "YHJ_K9xVk1xQUYje5LyBONOhzowLhqg_U4TF15-1U5oHicPHJ6rrXLviIBhtvjIS",    
    "signature": "m2bXIEo7pPb5gB8xQIeZgse2_lJJifT2yIi1EVAw_wgJlqZgy6id4FUQfKgwRkmQzmAHRdw7bUtzUeamW1ZiDw=="
}  
```  
(TODO: use a real, verifiable, example here.)

### What messages/digests can be signed?
Digests must be 224, 256, 384 or 512 bits long. TSSig makes no assumptions on how a digest was generated.

### Isn't there other protocols for doing this?
Yes.

### Why are there two keys involved?
The aim here is to facilitate good key management practises. We have a *root key* which is long lived and should ideally be stored somewhere nice and secure (like a HSM). And we have a *leaf key* which is short lived - ideally only ever being kept in RAM.

The **leaf key** is used to sign the `timestamp` and `digest`. The leaf's public key is included inline with the Signed Time Stamp output (`leaf-key`), thus does not need to be separately stored.

The **root key** is used to sign the *leaf key*, forming a chain to trust to the issuers' domain name, on which the root's public key is hosted.

### What key types are supported?

The **leaf key** always uses **Ed25519**. This gives us an excellent level of security and performance, with a nice short key length; important as the public key is inlined within the output.

The **root key** also supports **Ed25519**, but additionally  *ecdsa* with the curves **secp256r1**, **secp384r1** and **secp521r1**. This is to facilitate a greater range of HSMs where *Ed25519* is lesser well supported.

### Is there an easy way to give it a try?
Sure - give this a go. (Drop the `jq` if you don't have it installed, it just makes it look nice and pretty).
```shell  
curl -X POST https://sign.tssig.org \
-H 'Content-Type: application/json' \
-d '{"digest": "2Mcs3gT-n-6ZnJy8uRmSH4OKOXMwC0Ehaf-2SVrfBrM="}' | jq
```  
This hits our *testing* server - you'll get a response signed with one of our test keys. You'll be able to verify the output using a TSSig client, as long as you trust our testing server's issuer prefix: `https://keys-that-should-only-be-used-for-testing.tssig.org/`

You can pass in any `digest` value you wish here as long as it's a valid base64url value, of a valid size.

### Isn't your output a bit long?
Well it could be shorter, *but* we've prioritised:
- Human readability of the output - people time is usually more precious than CPU time or disk space.
- An opinionated view on having a two key strategy to help facilitate good key management practises.

### How many times can a leaf key be reused?
The *leaf key* is designed to be short lived (anywhere from a few seconds, up to a few hours). During that time the leaf key can security be reused as many times as needed. The key point to make about a leaf key is to avoid storing it on any persistent storage device; keep it in RAM.

### How is byte array data encoded?
Bytes are encoded into the JSON as unpadded base64url strings.

Why unpadded? To save those few extra unnecessary characters. They're unnecessary because as each JSON string value represents exactly one base64 value. i.e. Not two or more concatenated. Thus we're always able to determine the expected length of the byte array from the unpadded value.

Why url-safe? Because we think they're more developer friendly - less gotchas can crop up (especially if you do want to use them in a URL). Along with the fact that there's no real downside.