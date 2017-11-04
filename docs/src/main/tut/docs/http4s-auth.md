---
layout: docs
number: 6
title: "Overview"
---

# Http4s Authentication and Authorization

For Http4s Authentication, we provide token-based authentication which is either 
Stateless (No need for a  backing store) or Stateful(Requires backing store), through the following options:

1. Signed Cookie Authentication (Stateful)
2. Encrypted and Signed Cookie Authentication (Stateless and Stateful)
3. JWT using HS256, HS384 and HS512 (Stateless and Stateful)

In general, to use an authenticator, you need:

1. A instance of `BackingStore[F[_], I, U]` for your User type, where I is the id type of your user type, 
and `U` is the user class.
2. An instance of either `TSecCookieSettings` or `TSecJWTSettings` based on the type of authenticator
3. Either a Signing Key or an Encryption Key, based on the kind of Authenticator
4. For Stateful Authenticators, you will require a `BackingStore[F, UUID, Token]` where `Token` is the
Token type.

Also please, for your sanity and ours **use TLS in prod**.

## Stateful vs Stateless

**Stateful:**

Pros:
* Better Security on top of the security the cryptographic primitives give you. Stateful tokens are cross-checked with 
what is in your backing store.
* Easy to invalidate: Simply remove one from your backing store! it will not pass the authentication check if it is not there.

Cons:
* Requires a backing store that can deal with concurrent updates. Thus, it must be synchronized.
* Will have possibly higher network throughput, if your token store is outside of application memory.

**Stateless**

Pros:
* Less network throughput. No need to use a backing store.
* Great for applications where security is not a deathly priority and long-lived sessions are desireable.

Cons:
* Your security is as strong as the underlying crypto primitive. There's no extra safety: You cannot cross check without
any record of the tokens you have.
* You can only invalidate using an explicit blacklist, which you would have to roll out as a middleware. If you need this
dynamically updated, it will increase the network throughput.



### Signed Cookie Authenticator:

This authenticator uses cookies as the underlying mechanism to track state. If your particular Id type is sensitive,
_do not_ use this: the information is not encrypted. This is not a stateless authenticator.

Notes:
* Choose between one of HMACSHA1, HMACSHA256, HMACSHA384 or HMACSHA512. **Recommended: HMACSHA256.** The main difference between
all of these algorithms primarily lies in the difficulty to brute force the key: Higher number means higher search space, thus
harder to simply brute force the key.
* Can be vulnerable to [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery).
* [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) doesn't play nice with cookies.
* User and token backing store as stated above
* Your ID type for your user must have an `Encoder` and `Decoder` instance from circe

### Encrypted Cookie Authenticator:

This authenticator uses cookies as the underlying mechanism to track state, however, any information such as expiry, 
rolling window expiration or id is encrypted, as well as signed. This authenticator has both stateful and stateless modes.

* Choose between one of AES128, AES192 or AES256 to perform your Authenticated Encryption with AES-GCM. 
**Recommended default: AES128**.
* User and token backing store as stated above, or just User store for stateless authenticator
* Can be vulnerable to [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery).
* [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) doesn't play nice with cookies.
* Your ID type for your user must have an `Encoder` and `Decoder` instance from circe

### JWT Authenticator

This authenticator uses [JWT](https://jwt.io) for authentication. The contents of the actual identity 
(i.e your User type id) are encrypted, then signed with underlying JWT algorithm.

* Choose between one of HMACSHA256, HMACSHA384 or HMACSHA512. **Recommended default: HMACSHA256**.

Notes:
* Not vulnerable to [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery).
* Okay to use with `CORS`
* Tsec jwts are typed, so not vulnerable to [this](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* Stateless or stateful.