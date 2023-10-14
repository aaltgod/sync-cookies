#![no_std]
#![no_main]

use core::{borrow::BorrowMut, mem, ops::Add};

use aya_bpf::{
    bindings::{xdp_action, xdp_md},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    BpfContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map]
static BLOCKLIST: HashMap<u16, u16> = HashMap::<u16, u16>::with_max_entries(1024, 0);

#[xdp]
pub fn sync_cookies(ctx: XdpContext) -> u32 {
    match try_sync_cookies(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn ipv4_checksum(hdr: *const Ipv4Hdr) -> u16 {
    let ptr = hdr as *const u16;
    // This length is static, and won't support IPv4 headers with options.
    let length = Ipv4Hdr::LEN;
    let mut sum: u32 = 0;

    // Divide the header into 16-bit chunks and sum them. Need to divide by 2
    // because size of is byte-denominated.
    for i in 0..(length / 2) {
        sum += unsafe { *(ptr.add(i)) } as u32;
    }

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    !(sum as u16)
}

fn process_tcp(ctx: &XdpContext) -> Result<u32, ()> {
    let tcphdr: *mut TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source = u16::from_be(unsafe { (*tcphdr).source });
    let dest = u16::from_be(unsafe { (*tcphdr).dest });
    let is_syn = u16::from_be(unsafe { (*tcphdr).syn() });
    let is_ack = u16::from_be(unsafe { (*tcphdr).ack() });
    let is_fin = u16::from_be(unsafe { (*tcphdr).fin() });
    let seq = u32::from_be(unsafe { (*tcphdr).seq });
    let ack = u32::from_be(unsafe { (*tcphdr).ack_seq });
    let win = u16::from_be(unsafe { (*tcphdr).window });

    if source.eq(&3000) {
        let mut counter = u16::from_be(unsafe {
            match BLOCKLIST.get(&source) {
                Some(res) => res.to_be(),
                None => 0,
            }
        });

        info!(ctx, "{}", counter);

        if counter.gt(&2) {
            return Ok(xdp_action::XDP_DROP);
        }

        counter += 1;

        unsafe {
            BLOCKLIST.insert(&source, &counter, 0);
        };

        info!(
            ctx,
            "SRC: {}, SYN: {}, ACK: {}, FIN: {}, SEQ: {}, ACK: {}, WIN: {}",
            source,
            is_syn,
            is_ack,
            is_fin,
            seq,
            ack,
            win
        );

        unsafe {
            (*tcphdr).dest = source;

            (*tcphdr).check = incremental_tcp_checksum((*tcphdr).check, source, dest);

            (*tcphdr).source = dest;

            (*tcphdr).check = incremental_tcp_checksum((*tcphdr).check, dest, source);

            (*tcphdr).ack_seq = u32::to_be(seq + 1);
            (*tcphdr).seq = u32::to_be(60);
            (*tcphdr).set_ack(u16::to_be(1));
        };

        return Ok(xdp_action::XDP_TX);
    }

    Ok(xdp_action::XDP_PASS)
}

fn incremental_tcp_checksum(old_checksum: u16, old_port: u16, new_port: u16) -> u16 {
    let mut sum = old_checksum as u32;
    sum -= old_port as u32;
    sum += new_port as u32;

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    !(sum as u16)
}

fn try_sync_cookies(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");

    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let action = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => match process_tcp(&ctx)? {
            xdp_action::XDP_TX => {
                unsafe {
                    // let ethhdr_source_addr = (*ethhdr).src_addr;
                    // let ethhdr_dest_addr = (*ethhdr).dst_addr;

                    // (*ethhdr).dst_addr = ethhdr_source_addr;
                    // (*ethhdr).src_addr = ethhdr_dest_addr;

                    let source_addr = u32::from_be((*ipv4hdr).src_addr);
                    let destination_addr = u32::from_be((*ipv4hdr).dst_addr);

                    info!(
                        &ctx,
                        "BEFORE SRC: {:i} DEST: {:i}", source_addr, destination_addr
                    );

                    (*ipv4hdr).dst_addr = source_addr;
                    (*ipv4hdr).src_addr = destination_addr;

                    // (*ipv4hdr).check = 0;
                    // (*ipv4hdr).check = ipv4_checksum(ipv4hdr);

                    info!(
                        &ctx,
                        "AFTER SRC: {:i} DEST: {:i}",
                        (*ipv4hdr).src_addr,
                        (*ipv4hdr).dst_addr
                    );

                    let tcphdr: *mut TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let source = u16::from_be((*tcphdr).source);

                    info!(&ctx, "SOURCE {} {}", source, (*ipv4hdr).check)
                };

                xdp_action::XDP_TX
            }
            res => xdp_action::Type::from_be(res),
        },
        IpProto::Udp => xdp_action::XDP_PASS,
        _ => return Err(()),
    };

    Ok(action)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
