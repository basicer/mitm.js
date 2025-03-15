# mitm.js

[mbedtls](https://github.com/Mbed-TLS/mbedtls) powered javascript library to MITM TLS connections.

### Status

It's not very stable but it mostly gets the job done.

### Building

```bash
git submodule update --init
make -C mbedtls
make
```

### Use

See [example.mjs](example.mjs)