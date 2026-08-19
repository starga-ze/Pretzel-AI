"""The gRPC edge: the mgmtd <-> pretzel-ai contract, its generated stubs, and the server.

Everything gRPC lives here — pretzel_ai.proto (the source of truth, mirrored into
pretzel/mgmtd/grpc/), the stubs `./pretzel-ai build` generates beside it, and the servicer that
implements them. mgmtd's own gRPC edge is laid out the same way, so the contract and both of its
implementations sit one directory deep on each side.

Named `grpc` inside the `src` package rather than at the repo root on purpose: a top-level
directory of this name would shadow grpcio's own `grpc` module for anything that put the repo root
on sys.path. Reached only as `src.grpc`, it cannot.
"""
