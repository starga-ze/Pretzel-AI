"""The tech-doc crawler: docs.paloaltonetworks.com -> the techdoc schema of pretzel_knowledge.

Why this lives in pretzel-ai rather than in one of the C++ daemons: fetch, extract, hash and
(later) embed are one pipeline, not four steps that happen to run in sequence. The decision to
re-embed a page is made by comparing the hash of its *extracted* text against the stored one, so
splitting extraction away from embedding would put a process and a language boundary through the
middle of the only gate that keeps the embedding cost down. Two further facts settle it: the IPC
fabric caps a frame at 1 MiB (shared/ipc/IpcProtocol.h) while the largest observed page body is
1.3 MiB, and the extractor is DITA-shaped HTML work that has no reason to be rewritten in C++17.
"""
