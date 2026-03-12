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

    pub fn step(&mut self, steps: usize) -> Result<(), ()> {
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, steps: usize) -> Result<(), ()> {
        self.pos = steps;
        Ok(())
    }

    pub fn read_byte(&mut self) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn get_byte(&mut self, pos: usize) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = self.buf[pos];
        Ok(res)
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = &self.buf[start..start + len as usize];
        Ok(&res)
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        if self.pos + 1 >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = (self.buf[self.pos] as u16) << 8 | self.buf[self.pos + 1] as u16;
        self.pos += 2;
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u8, String> {
        if self.pos + 1 >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = self.buf[self.pos] << 24
            | self.buf[self.pos + 1] << 16
            | self.buf[self.pos + 2] << 8
            | self.buf[self.pos + 3];
        self.pos += 2;
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
            let len = self.read_byte()?;
            if (len & 0xC0) == 0xC0 {
                if jumps >= max_jumps {
                    return Err("Max jumps reached".into());
                }
                let b2 = self.get_byte(pos + 2)? as u16;
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
}

impl QueryType {
    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::UNKNOWN(num) => num,
        }
    }
}
