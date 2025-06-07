# op-interop-contender

*a custom [contender](https://github.com/flashbots/contender) script designed to spam interop transactions & relay them directly.*

Contender's builtin features are used to measure time-to-inclusion for interop transactions. The duration is measured from when we get the initiating tx response to when the relay tx is included onchain.

## quickstart

In a terminal, run [supersim](https://github.com/ethereum-optimism/supersim?tab=readme-ov-file#%EF%B8%8F-supersim) (*without* the `--interop.autorelay` flag):

```sh
supersim
```

This will start a dev environment with 3 nodes: an L1 node on localhost:8545, an L2 node on localhost:9545, and another L2 node on localhost:9546.

In a new terminal, clone this repo and run the binary:

```sh
git clone https://github.com/zeroxbrock/op-interop-contender
cd op-interop-contender
cargo run
```

You can generate a contender report after spamming by setting `SPAM_MAKE_REPORT` in your environment:

```sh
export SPAM_MAKE_REPORT=true
cargo run
```

> The default settings should work when running against supersim, but if you need to change them, you can set the desired variables in your environment. See [here](./src/main.rs#L42-L63) for reference.
>
> Any variables not set will also show up as a warning when you run the script.

## how it works

By default, the program runs a [builtin scenario](./src/scenarios/l2MintAndSend.toml) on a timed spammer, which mints tokens on [chain A](http://localhost:9545) and transfers them to [chain B](http://localhost:9546)

[spam_callback.rs](./src/spam_callback.rs) defines a custom callback which holds a JSON-RPC provider connected to the destination chain. This allows us to watch transactions after we relay them, and record information about them in the DB.

We also have a [custom provider](./src/op_relay.rs#L82) to interact with the supersim admin API, which is used to call `admin_getAccessListForIdentifier`, which is just a convenience API method. This call could potentially be replaced with an in-memory algorithm, so we could test environments that don't expose that method.
