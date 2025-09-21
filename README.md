# 🪴 libflowerpot - a blockchain framework library written in rust

> In development, not ready for production use until `v1.0.0` release!

Libflowerpot is a rust library implementing a basic, foundational blockchain
which can be extensively configured for your needs. Unlike other blockchains
this one doesn't provide built-in cryptocurrency, PoW mechanisms or anything
else.

The goal of the project is to provide a foundation for developers to easily
create decentralized applications. Let's say you want to make a decentralized
chat app. You'd need to implement a mechanism to synchronize messages between
all the users of your chat. This library handles decentralized networking and
organizes data equally to all the users of your app due to the nature of a
blockchain. Moreover, users of your app don't need to download this blockchain,
they can connect to public shards and use their HTTP API to fetch updates.

Some key points:

- Transactions are raw byte slices with random seeds for unique hash values;
- secp256k1 curve for signing (same as in bitcoin);
- 3 types of nodes: clients, shards and validators;
- Public HTTP APIs, no need to self-host the blockchain;
- 2/3 of validators must approve new blocks;
- No cryptocurrency by design.

<img src="./docs/network.png" />

# Roadmap to v1.0.0 release

- [ ] Transition to abstract transport protocols for communication
    - [x] Implement base protocol and transport abstraction
    - [ ] Rewrite client code to use internal connection
    - [ ] Rewrite shards pool to keep active connections as transport streams
    - [ ] Implement batched protocol methods in the shards pool
    - [ ] Rewrite validator code
    - [ ] Rewrite shard code
- [ ] Rework blocks and transactions
    - [ ] Remove zstd compression since it's not reliable
    - [ ] Make transactions have multiple types; implement `Mint` and `Data`
          type transactions
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
    - [ ] Make default mining software
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

# HTTP Shards API v1 reference

> TODO: in the first `v1.0.0` release it's planned to move to raw TCP
> connections instead of using HTTP.

## Node status

API to check status of the shard node.

### `GET /api/v1/heartbeat`

Check if the shard is online. In that case `200 OK` response must be returned.

## Transactions

API to push new transactions to the network and monitor their status.

### `GET /api/v1/transactions`

Get list of all the pending transactions. These are transactions which weren't
yet added to any block.

Return list of hashes of pending transactions.

```ts
type Response = string[];
```

### `PUT /api/v1/transactions`

Announce transaction to the network. This operation will ask network's shard
to store your transaction in its pending transactions pool and share it with
other shards it is connected to. In future your announced transaction can be
validated and added to the blockchain, or, potentially, be removed after some
time. Until transaction is validated you should monitor its status and act
accordingly.

```ts
type Request = object; // Standard transaction JSON format
```

### `GET /api/v1/transactions/<hash>`

Read content of a transaction with provided hash.

If transaction with such hash is not found - then `404` status should be
returned.

```ts
type Response = object; // Standard transaction JSON format
```

## Blocks

API to push new blocks to the network and monitor their status.

### `GET /api/v1/blocks`

Get list of all the pending blocks. These are blocks which weren't yet validated
and fixated in the blockchain.

```ts
type Response = {
    block: {
        current: string;
        previous: string;
    };
    sign: string;
    approvals: string[];
}[];
```

### `PUT /api/v1/blocks`

Announce block to the network. This block will first be added to the pending
blocks pool, and then, if it's valid and enough approvals are available, will
be written to the blockchain and fixated in the history.

```ts
type Request = object; // Standard block JSON format
```

### `GET /api/v1/blocks/<hash>`

Read content of a block with provided hash.

If block with such hash is not found - then `404` status should be returned.

```ts
type Response = object; // Standard block JSON format
```

### `PUT /api/v1/blocks/<hash>`

Announce approval for a block with provided hash.

```ts
type Request = string;
```

## Sync

API to synchronize blocks of the blockchain between the nodes of the network.

### `GET /api/v1/sync[?after=<hash>][&max_blocks=<number>]`

Get list of some blocks after a block with provided hash. If no `after` param
provided then the first block of the blockchain will be assumed.

Full blocks will be returned so that client can download them and validate
locally.

If selected `after` block is not a part of blockchain known to the shard then
`404` status should be returned.

```ts
type Response = object[]; // Standard block JSON format
```

## Shards

API to handle public nodes (shards) of the network.

### `GET /api/v1/shards`

Get list of shards the current shard is connected to.

```ts
type Response = string[];
```

### `PUT /api/v1/shards`

Announce list of shards to another shard.

```ts
type Request = string[];
```

Author: [Nikita Podvirnyi](https://github.com/krypt0nn)\
Licensed under [GPL-3.0](LICENSE)
