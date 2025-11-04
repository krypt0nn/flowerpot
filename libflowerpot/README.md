# 🪴 libflowerpot - a rust-written decentralized messages synchronization library

> In development, not ready for production use until `v1.0.0` release!

Did you ever want to make your own decentralized application? You've most likely
faced the following problems to solve:

- Create new accounts and verify that posted content really belongs to some
  accounts;
- Synchronize messages (data packets) between all the peer-to-peer nodes of the
  network;
- Make sure that all the nodes in the network have the same packets and that
  nodes don't miss some of them (like in TCP where we make sure that all parties
  receive the full data stream);
- Preferably have a unified ordering of messages between all the parties, so
  in e.g. a messaging app everybody see messages in the same order.

These particularly difficult tasks can naturally be solved by *blockchain-like*
architecture, and that's what this library does!

## User accounts

An account within the flowerpot network is a secp256k1 elliptic curve (same as
in bitcoin) keypair consisting of a public and secret keys. The public key is
used as a user identifier, while secret key is used to send data to the network.
Elliptic curve based digital signatures protocol (ECDSA) allows to identify and
verify the authors of all the messages in the network. It also means that at any
point you can create an infinite amount of accounts *(by default!)* without any
restrictions.

## User messages

A user message is a raw bytes array. You, as the application author, define
this raw bytes array format yourself. This can be a protobuf, a bson, or a
hanf-crafted binary encoding format (which is generally recommended!). Users
share these messages with each other and store them in a temporary messages
pool. Libflowerpot allows you to define some filtering rules to restrict what
messages can be stored in these pools to e.g. ensure proper messages format.

## Messages cost

Each message has a base cost value calculated as `ceil(message_bytes / 1000)`,
so roughly you "pay" 1 *something* (gas/fee) for each kilobyte of message
length. Even if your message is shorter than that - you still have to pay 1 KB
cost. Also note that the cost is integer and doesn't contain floating point.

The final cost of a message is calculated as `base_cost * inflation_factor`.
The `inflation_factor` value is integer and determined by *you*, the developer
of the app. If you don't want users to pay anything (e.g. because you've made
your own mechanism of restricting user accounts and don't need the anti-bot
prevention) then you define `inflation_factor = 0`. Otherwise you can make a
funcation which can calculate the factor at any historic point. E.g., you can
make such a function that will double the `inflation_factor` with every GB of
users' messages stored.

The gas/fees system is needed to naturally prevent people from abusing
decentralized network. Normally, if people are not restricted in any way, there
will be some to create new accounts and flood the network with gibberish values.
To prevent this you can either implement your own logic of limiting accounts
creation (e.g. make users to attach special digital signature to their messages
issued by you), or make users solve some hard computation task (solve PoW task)
so that all the people using your app will be rate-limited by their computers
and won't be able to flood the network as easily. The way you implement this
is chosen by you. Libflowerpot doesn't provide any built-in solution on its own.

## Network authority

After many time spent on designing the project architecture I decided that the
central authority is an optimal solution. In flowerpot network, there's one
single account that can approve messages from other users and include them to
the global history.

Previously, there was a validators system with a BFT-like mechanism of choosing
a new history block, and a special mechanism of choosing the best history fork.

The main benefit of validators system is that general people can become
validators of the network and work together to improve its quality, make it more
decentralized and resistant. Hovewer, to become a validator people would need to
solve some kind of PoW task. Another problem is that due to lack of economics
within the network (there's no coin) validators have no benefit in maintaining
the network, beside altruism or egoism (they could either want to support the
network or ruin it by creating new validators and delete their signing keys,
making BFT mechanism unfunctional).

I've decided that it's better to have a single authority issued by the
application author. After all, it's in their intention to make this authority
running since they created the application. It's also still possible to create
your own network and just swap some values in the original application in case
the original network went down or something else happened.

To put it shortly: validators system creates a lot of problems and provides too
few benefits in our use case, while central authority is much easier to
implement and it still can be swapped by community members, creating a parallel
network (even with content mirroring if some effort is done).

# Roadmap to v1.0.0 release

- [x] Transition to abstract transport protocols for communication
    - [x] Implement base protocol and transport abstraction
    - [x] Rewrite client and shards into a single node client
        - [x] Implement viewer struct for a packets stream
        - [x] Implement blocks sync code which will aggregate blocks from all
              the available connections and run the fork selection algorithm
        - [x] Implement streams listening and packets processing
        - [x] Implement node handler to send new transactions and perform other
              client-side actions
    - [x] Rewrite validator code
- [x] Rework blocks and transactions
    - [x] Remove zstd compression since it's not reliable
    - [x] Remove json serialization
- [x] Rework project structure
    - [x] Rename github repository to `flowerpot`
    - [x] Move `libflowerpot` into a separate workspace
    - [x] Create `bouquet` CLI tool
        - [x] Create keypairs (public/secret keys)
        - [x] Create new transactions
        - [x] Send transactions to the network
        - [x] Create new blockchains
        - [x] Connect to a blockchain and monitor its activity
        - [x] Show blockchain status
- [ ] Get rid of validators system
    - [ ] Rename transactions into messages
    - [ ] Remove multiple block types and keep only one with list of messages
    - [ ] Remove `approvals` field and keep only the block signature
    - [ ] Update `Storage` trait to know the current history authority instead
          of knowing validators at any point in time
    - [ ] Rework the validation mechanism to just check that the block is issued
          by the authority
    - [ ] Rework the fork choosing mechanism to prefer the *first* issued block
          by both looking at its creation time and receiving time recorded by
          the local node (double check) to prevent history modifications
- [ ] Implement gas system
    - [ ] Implement `inflation_rule` callback to calculate `inflation_factor`
          value at any history point
    - [ ] Implement a method to calculate users' messages cost:
          `ceil(size_in_bytes / 1000) * inflation_factor`
    - [ ] Implement a `Storage` trait method to get users' balances at any
          history point
    - [ ] Update the pending messages accepting logic to check that the user
          issued the message has enough balance for it
- [ ] Release preparations
    - [ ] Resolve all the TODO-s and FIXME-s
    - [ ] Prepare technical documentation and standardize the protocol
    - [ ] Test the library in production for some time

Author: [Nikita Podvirnyi](https://github.com/krypt0nn)\
Licensed under [GPL-3.0-or-later](LICENSE)
