# Daochi Ziran client modules

Add `client/zi` to Ziran's module path and import `wire`:

```zi
#import "wire"
```

`wire.zi` owns the canonical challenge path, login JSON body, and signed login
message. `BuildLoginMessageHash` takes the SHA-256 hex digest of the **exact**
body bytes returned by `BuildLoginBody`; the account implementation signs its
output with ML-DSA-44. Each builder writes to a caller-owned, NUL-terminated
buffer and returns `false` if an input is invalid or the buffer is too small.

The client package is being extracted from the retired Kryon sync runtime.
This first module has no account storage, UI, network, or app data dependency.
Bearer requests, sync transactions, and remote events still need client
modules before it is a complete Daochi client.

Run `sh client/zi/tests/wire_test.sh` with the sibling Ziran checkout, or pass
the paths to `zi2c` and Ziran's `include` directory as its two arguments.
