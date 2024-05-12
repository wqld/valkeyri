#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockPair {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
}

pub const RESP_INITIATED: u32 = 0;
pub const RESP_ESTABLISHED: u32 = 1;
// pub const RESP_PING_RECV: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnTrack {
    pub state: u32,
}

// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct ConnState {
//     pub syn_seq: u32,
//     pub state: u32,
// }

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for SockPair {}
