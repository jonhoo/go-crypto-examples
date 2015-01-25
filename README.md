Go has a pretty good cryptography library, but most of the provided
functionality is fairly low-level, and it can sometimes be difficult to
figure out exactly how things fit together. This repository gives
end-to-end example code that uses a number of features that can be
pieced together using `crypto` and `net`. Hopefully, this code will make
it easier for people trying to do crypto-things in Go to find the piece
of code they're missing.

In no particular order, the code here implements:

  - HTTPS server with self-signed certificates.
  - Generation of signed client certificates.
  - Optional client-side authentication for HTTPS.
  - Parsing of public keys submitted through the HTML5 `<keygen>` tag.
  - Marshalling and unmarshalling of private keys and certificates to
    standardized formats supported by browsers, OpenSSL, etc.

To run, first do `go build keybin/main.go`. Next, open two terminals:

```
term1$ ./kb server
term2$ ./kb client
```

If you list the contents of the current directory, you will see that
four files have been generated: `localhost.{crt,rsa.key}`, and
`alice.{crt,rsa.key}`. These are the server and client certificates and
keys, stored in formats that can be imported into browsers, used by
cURL, or all sorts of other things.

The code in this repository is meant as example good only, and it should
not be used verbatim without additional testing and verification. Code
tagged with TODO needs to be modified before use.

Also note that this code was carved out from a much larger software
system, and some errors may have snuck in during the transition. If you
find any errors, do not hesitate to file an issue using the GitHub issue
tracker; or even better, fix the problem yourself and send a Pull
Request. If you have ideas for improvements, extensions or clean-up that
should be done, please also submit those too!

Happy hacking!
