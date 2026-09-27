# YunDongIP Bonding V2 (experimental)

This branch starts a clean multipath data plane. It does not reuse the failed round-robin transport from `multipath-lab`.

## Phase 1 acceptance rule

Only prove one thing first:

- 1 CF lane = X MB/s
- 2 CF lanes must be clearly faster than X

If 2 lanes do not show a clear gain, do not continue to 4/8/N lanes.

## Phase 1 data plane

- independent WebSocket writer per CF lane
- 32 KiB data chunks
- per-stream sequence numbers
- ACK for every received chunk
- bounded pending window
- timeout retransmission to another lane
- duplicate suppression
- ordered delivery to the local TCP stream
- per-lane TX/RX/in-flight statistics every 2 seconds
- built-in benchmark HTTP source, so no multi-GB test file is required

## Later phases (only after 1+1 is proven)

1. adaptive RTO and lane scoring
2. dynamic N-lane growth
3. lane eviction/replacement
4. YunDongIP candidate-pool integration
5. target-bandwidth controller
