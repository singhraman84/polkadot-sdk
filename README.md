# Fork Notice: Polkadot SDK
This repository was forked from https://github.com/bsaviozz/polkadot-sdk. The author bsaviozz forked the repo from https://github.com/paritytech/polkadot-sdk and modified it to integrate Dilithium (ML-DSA) signature schemes for experimental evaluation of post-quantum cryptography in a Substrate-based blockchain. After that, I integrated Falcon 512 and Falcon 1024 Digital Signature Algorithms (DSA) on top of that. 

These changes are intended for research and benchmarking purposes and are not part of the official Polkadot SDK. The codes are written for experiment purpose and may not be ready for a production environment. All the changes are done in sp-core and sp-runtime. The Falcon 512 and Falcon 1024 DSA are made available as the "falcon" branch of this repo.  
Contact: Raman Singh, Raman.Singh@ieee.org or Raman.Singh@uws.ac.uk

## ⚡ Quickstart
This repo is part of a four-component experiment. Component 1 is Polkadot-sdk itself, which is a modular blockchain development framework for building scalable, interoperable, and customizable Web3 networks powered by Substrate and Polkadot. I have modified this framework to add the Falcon DSA. The second component is Polkadot-sdk-solochain-template. It is a starter template in the Polkadot SDK for building an independent, standalone blockchain (solochain) with customizable runtime logic, networking, and consensus features. I have added the Falcon 512 in the solochain template, which is available as a repo Polkadot-sdk-solochain-template-falcon (https://github.com/singhraman84/polkadot-sdk-solochain-template-falcon). The solochain template is used to run the Blockchain node using the modified Polkadot-sdk. 
The third component is the Subxt library, which is a Rust library for interacting with Substrate- and Polkadot-based blockchains through type-safe APIs, enabling developers to query chain data and submit transactions programmatically. The signer of Falcon512 and Falcon1024 is added in addition to Dilithium, ecdsa and sr25519. The repo is available at (https://github.com/singhraman84/subxt). Finally, the fourth component is a custom client written to use the modified Subxt library and can interact with the node created by the modified solochain template. The custom subxt client can be found at (https://github.com/singhraman84/subxt-myclient-falcon). 

Subxt-myclient-falcon --------------> Subxt -------------> polkadot-sdk-solochain-template-falcon ------------> Polkadot-sdk (branch = falcon)

## 👩🏽‍💻 Building

Polkadot-sdk is a framework, and a build is not required. If any changes are made, the build should be run to check the validation of the changes. I have made changes in sp-core and sp-runtime, and hence can be built using:

cargo check -p sp-core
cargo check -p sp-runtime
