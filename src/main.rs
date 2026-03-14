use std::fs::File;
use std::io::Read;

use dns::{BytePacketBuffer, DnsPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open("/home/manuseb/codeWork/dns/response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let mut packet = DnsPacket::new();
    packet.from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
