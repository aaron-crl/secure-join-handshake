# secure-join-handshake
Proof of concept for secure cluster join.

This toy demonstrates an approach for using a copy/paste friendly token exchange cryptologic primitives in preparation for mutually-authenticated TLS.

###Function
This toy has a client and server process:

**Server**
* Creates a self-signed CA and leaf service certificate.
* Creates a sample `join-token`.
* Hosts a `/ca` enpoint that supplies the CA public key
* Hosts a `/join` endpoint that validates a proof of membership before providing a `<CA Bundle>`
* Waits 5 seconds to start the client

**Client**
* Requests the CA public cert from server process
* Verifies that the CA public cert matches its `join-token` hash
* Generates its own proof of membership from it's UUID (this is actually unnecessary - it could just use the shared secret at this point)
* Request the `CA bundle` from the `/ca` endpoint.


# Running the toy
To execute run `go run server.go client.go common.go`

### common.go
Contains the handshake crypto and helper functions and structs

### server.go
Contains the listener and startup code

### client.go
Contains the client process code