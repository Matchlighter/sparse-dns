sparse-dns
===

A simple DNS forwarder that forwards DNS queries to various upstreams. If an upstream returns NXDomain, the next upstream is tried.

Usage
---

```
Usage of ./sparse_dns:
  -debug
        Debug mode
  -listen string
        Address to listen to (TCP and UDP) (default ":53")
  -maxclients uint
        Maximum number of simultaneous clients (default 1000)
  -maxrtt float
        Maximum mean RTT for upstream queries before marking a server as dead (default 0.25)
  -upstream string
        Comma-delimited list of upstream servers (default "8.8.8.8:53,8.8.4.4:53")
```
