# 🪴 libflowerpot - a rust-written blockchain for your decentralized app needs!

> In development, not ready for production use until `v1.0.0` release!

Libflowerpot is a rust library implementing a PoS/PoW-like blockchain.
It features a built-in gas system which can be *mined* by blockchain users and
used to store *raw bytes* in the blockchain as in a globally available data
storage. This allows you, as a developer, to create decentralized apps which
could store their data in a common storage which features data integrity,
identical order of events for all the parties, and built-in decentralized
networking code.

Let's say you want to make a decentralized chat app. You'd need to implement
a mechanism to synchronize messages between all the users of your chat.
This library handles decentralized networking and organizes data identically
to all the users of your app due to the nature of a blockchain.

Some key points:

- Transactions are raw bytes with random seeds for unique hash values;
- secp256k1 curve for signing (same as in bitcoin);
- 2/3 of validators must approve new blocks
  (PoS mechanism for blocks creation speed);
- Built-in PoW mechanism for gas usage
  (users are forced to *mine* some "currency" to create transactions).

# Roadmap to v1.0.0 release

- [ ] Transition to abstract transport protocols for communication
    - [x] Implement base protocol and transport abstraction
    - [ ] Rewrite client and shards into a single node client
        - [x] Implement viewer struct for a packets stream
        - [x] Implement blocks sync code which will aggregate blocks from all
              the available connections and run the fork selection algorithm
        - [ ] Implement streams listening and packets processing
        - [ ] Implement node handler to send new transactions and perform other
              client-side actions
    - [ ] Rewrite validator code
- [ ] Rework blocks and transactions
    - [x] Remove zstd compression since it's not reliable
    - [x] Remove json serialization
    - [ ] Make transactions have multiple types; implement `Mint` and `Data`
          type transactions
- [ ] Rework project structure
    - [ ] Rename github repository to `flowerpot`
    - [ ] Move `libflowerpot` into a separate workspace
    - [ ] Create `bouquet` CLI tool
        - [ ] Create keypairs (public/secret keys)
        - [ ] Create new transactions
        - [ ] Send transactions to the network
        - [ ] Create new blockchains
        - [ ] Connect to a blockchain and monitor its activity
        - [ ] Show blockchain status
- [ ] Implement gas system
    - [ ] Calculate transaction gas usage (`ceil(size_in_bytes * alpha)`)
    - [ ] Calculate total block gas usage (sum of transactions' gas usage)
    - [ ] Calculate gas inflation
          (`alpha = prev_alpha * 2` or `alpha = prev_alpha / 2`)
    - [ ] Implement gas-related methods in the storage trait
    - [ ] Implement `max_gas` field for every transaction
    - [ ] Withdraw gas from the users' accounts for each staged transaction
- [ ] Implement mining system
    - [ ] Implement PoW task based on the [DodoPoW](https://github.com/krypt0nn/dodopow)
    - [ ] Implement tasks verification and balance updating logic on transaction
          staging
    - [ ] Add mining-related functionality to the `bouquet` CLI tool
- [ ] Rework validators system
    - [ ] Remove different block types, keep only transactions list
    - [ ] Add new transaction type which will make its author a validator in
          cost of burning large amount of gas
    - [ ] Make blockchain's creator a validator by default
    - [ ] Choose blocks to approve using xor distance of previous block hash
          and public keys of every known validator, prioritize pending blocks
          using these distances
    - [ ] Give validator which made a new block some gas fee
          (needs further thinking)
- [ ] Pre-release preparations
    - [ ] Resolve all the TODO and FIXME-s
    - [ ] Test the library in production for some time

Author: [Nikita Podvirnyi](https://github.com/krypt0nn)\
Licensed under [GPL-3.0](LICENSE)
