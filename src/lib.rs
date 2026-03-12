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

    pub fn read_u16(&mut self) -> Result<u8, String> {
        if self.pos + 1 >= 512 {
            return Err("Buffer stack overflow".into());
        }
        let res = self.buf[self.pos] << 8 | self.buf[self.pos + 1];
        self.pos += 2;
        Ok(res)
    }

    pub fn read_u132(&mut self) -> Result<u8, String> {
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
