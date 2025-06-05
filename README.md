# bera-proofs

Berachain merkle proof generator from BeaconState json provided by beacon node api endpoint `bkit/v1/proof/block_proposer/:timestamp_id`.

Sufficient discrepencies exist between beacon-kit's implementation and eth2 spec that this standalone library was needed to generate merkle proofs.

Notes:
- BeaconState drops some 15 eth2 fields and gains one new one (deneb) and another new one (electra).
- Beaconkit SSZ on lists does not fully conform to eth2 spec or it's own config i.e. all lists are merkleized as fix vectors (with original eth2 params), then little endian list length appended. 
- Before merkleizing:
    - `latest_block_header.state_root = int(0).to_bytes(32)`
    - `state.state_roots[slot % 8] = state_root from prev cycle (slot - 8)`
    - `state.block_roots[slot % 8] = block_root from prev cycle (slot - 8)`
- tested proofs against berachain proposer proofs endpoint
