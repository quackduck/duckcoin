# Duckcoin - Crypto mining for everyone

Duckcoin is a cryptocurrency that will have zero fees, be decentralized and easy to mine locally on your regular computer, no fancy setup needed. Duckcoin was initially made just to learn how cryptocurrencies work, but it's blossoming into a real currency. Remembering Duckcoin's origins, the code is written to be easy to understand. Feel free to make issues asking questions about the code!

**Duckcoin is still under unstable development: If your miner seems to be getting a lot of errors, check if there's been any commit with "HARD FORK" in the commit message**

## Status, Plans and Differences.
- [ ] Decentralized
- [x] Easy to mine
- [x] Zero fees

Duckcoin is a fully working cryptocurrency that uses PoW, a common consensus algorithm that is also used by Bitcoin, ETH Classic and Dogecoin, to give miners rewards. However, it is currently operating on a centralized server-client model, which will certainly get me canceled if I release this right now. 

Duckcoin works differently from other cryptocurrencies. They need miners to have their own public IPs, or to port forward certain ports so that miners can contact each other in a peer-to-peer way. Because of how widespread Carrier Grade NAT is, it is usually rarely possible to host a node at home, without a custom rig. 

As of now, Duckcoin has a central server that miners can send blocks to. Miners don't validate anything, a central server validates the chain. The miner gets a certain reward after the block is accepted. To make a transaction, you must mine your own block with that transaction. 

This makes it possible to mine Duckcoin on a regular computer. However, this means Duckcoin is _centralized_, which, apparently, is unacceptable for anything called a cryptocurrency (besides, I don't want to deal with people trying to attack the central server).

So, to decentralize Duckcoin, we''ll have two kinds of miners: one for the people who do have custom rigs, and one for people mining at home. We'll call the first type "_Lnodes_" (Large Nodes) and the second "_Snodes_" (Small Nodes). Lnodes are like multiple instances of the current central server. 

Lnodes receive blocks from Snodes, validate them, and _chunk them together into a field of a larger block we'll call the "Lblock"_. This Lblock gets added to another chain, which will function how usual cryptocurrency blockchains do, with PoW for consensus and rewards (unlike Snodes, which don't use PoW for consensus), P2P networking, maybe Merkle trees, etc. Another goal of Duckcoin is to have zero fees. This is done by "giving" the miner the PoW the reward that the Snodes normally get. Snodes still mine their own transactions and the "fees" to the Lnode is the reward that the Snode's PoW is worth.


