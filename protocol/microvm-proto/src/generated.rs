#![allow(clippy::all)]
#![allow(missing_docs)]

pub mod agent {
    pub mod fort {
        pub mod microvm {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/agent.fort.microvm.v1.rs"));
            }
        }
    }
}

pub use agent::fort::microvm::v1::*;
