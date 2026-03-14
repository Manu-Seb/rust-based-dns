use std::net::{Ipv4Addr, Ipv6Addr};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        let temp = BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        };
        return temp;
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<(), String> {
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, steps: usize) -> Result<(), String> {
        self.pos = steps;
        Ok(())
    }

    pub fn read_byte(&mut self) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("Buffer stack overflow - read_byte".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn get_byte(&mut self, pos: usize) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("Buffer stack overflow - get byte".into());
        }
        let res = self.buf[pos];
        Ok(res)
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len >= 512 {
            return Err("Buffer stack overflow - get range".into());
        }
        let res = &self.buf[start..start + len as usize];
        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        if self.pos + 1 >= 512 {
            return Err("Buffer stack overflow - read u16".into());
        }
        let res = (self.buf[self.pos] as u16) << 8 | self.buf[self.pos + 1] as u16;
        self.pos += 2;
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        if self.pos + 3 >= 512 {
            return Err("Buffer stack overflow - read u32".into());
        }
        let res = (self.buf[self.pos] as u32) << 24
            | (self.buf[self.pos + 1] as u32) << 16
            | (self.buf[self.pos + 2] as u32) << 8
            | self.buf[self.pos + 3] as u32;
        self.pos += 4;
        Ok(res)
    }
}

trait ReadName {
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), String>;
}

impl ReadName for BytePacketBuffer {
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        let mut jumps = 0;
        let max_jumps = 5;
        let mut jumped = false;
        let mut delim = "";
        let mut pos = self.pos();
        loop {
            if jumps >= max_jumps {
                return Err("Max jumps reached".into());
            }
            let len = self.get_byte(pos)?;
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }
                let b2 = self.get_byte(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps += 1;
                continue;
            } else {
                pos += 1;
                if len == 0 {
                    break;
                }
                outstr.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());
                delim = ".";
                pos += len as usize;
            }
        }
        if !jumped {
            self.seek(pos).map_err(|_| "Seek failed".to_string())?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            recursion_desired: false,
            truncated_message: (false),
            authoritative_answer: (false),
            opcode: (0),
            response: (false),
            rescode: ResultCode::NOERROR,
            checking_disabled: (false),
            authed_data: (false),
            z: (false),
            recursion_available: (false),
            questions: (0),
            answers: (0),
            authoritative_entries: (0),
            resource_entries: (0),
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.id = buffer.read_u16()?;
        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & 1) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = a & (1 << 7) > 0;
        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & 0x80) > 0;
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    AAAA,
}

impl QueryType {
    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::AAAA => 28,
            QueryType::UNKNOWN(num) => num,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub class: u16,
}

impl DnsQuestion {
    pub fn new() -> DnsQuestion {
        DnsQuestion {
            name: "".to_string(),
            qtype: QueryType::UNKNOWN(2),
            class: 1,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        let mut buffer_string = String::new();
        buffer.read_qname(&mut buffer_string)?;
        self.name = buffer_string;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.class = buffer.read_u16()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let qttl = buffer.read_u32()?;
        let len = buffer.read_u16()?;
        match qtype {
            QueryType::A => {
                let addr_buffer = buffer.read_u32()?;
                let ip_add = Ipv4Addr::new(
                    ((addr_buffer >> 24) & 0xFF) as u8,
                    ((addr_buffer >> 16) & 0xFF) as u8,
                    ((addr_buffer >> 8) & 0xFF) as u8,
                    ((addr_buffer >> 0) & 0xFF) as u8,
                );
                Ok(DnsRecord::A {
                    domain: domain,
                    addr: ip_add,
                    ttl: qttl,
                })
            }
            QueryType::AAAA => {
                let addr_buffer_vec = [
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                ];
                let ip_add = Ipv6Addr::new(
                    addr_buffer_vec[0],
                    addr_buffer_vec[1],
                    addr_buffer_vec[2],
                    addr_buffer_vec[3],
                    addr_buffer_vec[4],
                    addr_buffer_vec[5],
                    addr_buffer_vec[6],
                    addr_buffer_vec[7],
                );
                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: ip_add,
                    ttl: qttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: len,
                    ttl: qttl,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.header.read(buffer)?;
        for _ in 0..self.header.questions {
            let mut question_buffer = DnsQuestion::new();
            question_buffer.read(buffer)?;
            self.questions.push(question_buffer);
        }
        for _ in 0..self.header.answers {
            let record_buffer = DnsRecord::read(buffer)?;
            self.answers.push(record_buffer);
        }
        for _ in 0..self.header.authoritative_entries {
            let record_buffer = DnsRecord::read(buffer)?;
            self.authorities.push(record_buffer);
        }
        for _ in 0..self.header.resource_entries {
            let record_buffer = DnsRecord::read(buffer)?;
            self.resources.push(record_buffer);
        }
        Ok(())
    }
}
