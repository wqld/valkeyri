use core::{mem, ops::Deref};

use aya_ebpf::{
    bindings::xdp_action::{XDP_PASS, XDP_TX},
    helpers::bpf_xdp_adjust_tail,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

use crate::util::{compute_ip_csum, compute_tcp_csum, ptr_at_mut};

pub struct Context<'a> {
    pub ctx: &'a XdpContext,
    pub eth_hdr: *mut EthHdr,
    pub ip_hdr: *mut Ipv4Hdr,
    pub tcp_hdr: *mut TcpHdr,
    pub ip_hdr_len: usize,
    pub tcp_hdr_len: usize,
    pub payload_len: usize,
    pub payload_offset: usize,
}

impl Deref for Context<'_> {
    type Target = XdpContext;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<'a> Context<'a> {
    #[inline(always)]
    pub fn new(ctx: &'a XdpContext) -> Result<Self, ()> {
        let data_end = ctx.data_end();
        let data = ctx.data();

        let eth_hdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;

        match unsafe { (*eth_hdr).ether_type } {
            EtherType::Ipv4 => {}
            _ => return Err(()),
        }

        let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;

        match unsafe { (*ip_hdr).proto } {
            IpProto::Tcp => {}
            _ => return Err(()),
        }

        let tcp_hdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

        let ip_hdr_len = unsafe { ((*ip_hdr).ihl() * 4) as usize };
        let tcp_hdr_len = unsafe { ((*tcp_hdr).doff() * 4) as usize };

        let ip_total_len = unsafe { u16::from_be((*ip_hdr).tot_len) as usize };
        let payload_offset = EthHdr::LEN + ip_hdr_len + tcp_hdr_len;
        let payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

        if data + EthHdr::LEN + ip_hdr_len + tcp_hdr_len > data_end {
            return Err(());
        }

        Ok(Self {
            ctx,
            eth_hdr,
            ip_hdr,
            tcp_hdr,
            ip_hdr_len,
            tcp_hdr_len,
            payload_len,
            payload_offset,
        })
    }

    #[inline(always)]
    pub fn ack_only(&self) -> bool {
        unsafe {
            (*self.tcp_hdr).ack() == 1
                && (*self.tcp_hdr).syn() == 0
                && (*self.tcp_hdr).psh() == 0
                && (*self.tcp_hdr).fin() == 0
        }
    }

    #[inline(always)]
    pub fn psh_ack(&self) -> bool {
        unsafe { (*self.tcp_hdr).ack() == 1 && (*self.tcp_hdr).psh() == 1 }
    }

    #[inline(always)]
    pub unsafe fn kernel_reply<const N: usize>(&self, http_response: &[u8; N]) -> Result<u32, ()> {
        let data_end = self.data_end();
        let data = self.data();

        if data + self.payload_offset + N > data_end {
            return Ok(XDP_PASS);
        }

        mem::swap(&mut (*self.eth_hdr).src_addr, &mut (*self.eth_hdr).dst_addr);
        mem::swap(&mut (*self.ip_hdr).src_addr, &mut (*self.ip_hdr).dst_addr);
        mem::swap(&mut (*self.tcp_hdr).source, &mut (*self.tcp_hdr).dest);

        (*self.ip_hdr).tot_len =
            u16::to_be(self.ip_hdr_len as u16 + self.tcp_hdr_len as u16 + N as u16);
        (*self.ip_hdr).check = compute_ip_csum(&mut *self.ip_hdr, false);

        let seq = u32::from_be((*self.tcp_hdr).seq);
        let ack_seq = (*self.tcp_hdr).ack_seq;
        let new_ack_seq = u32::to_be(seq + self.payload_len as u32);

        (*self.tcp_hdr).seq = ack_seq;
        (*self.tcp_hdr).ack_seq = new_ack_seq;
        (*self.tcp_hdr).check = compute_tcp_csum(self, false)?;

        let payload: *mut [u8; N] = ptr_at_mut(self, self.payload_offset)?;
        (*payload)[..N].copy_from_slice(&http_response[..N]);

        bpf_xdp_adjust_tail(
            self.ctx.ctx,
            0 - (data_end - (data + self.payload_offset + N)) as i32,
        );

        Ok(XDP_TX)
    }
}
