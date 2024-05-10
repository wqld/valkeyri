#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockPair {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
}

// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct ConnState {
//     pub syn_seq: u32,
//     pub state: u32,
// }

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for SockPair {}
