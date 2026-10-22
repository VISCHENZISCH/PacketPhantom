//! Curseur de lecture big-endian avec contrôle de bornes.
//! Chaque lecture retourne `None` au lieu de paniquer sur un paquet tronqué.

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let slice = &self.buf[self.pos..];
        self.pos = self.buf.len();
        slice
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Sous-lecteur préfixé par une longueur sur 1 octet.
    pub fn vec8(&mut self) -> Option<Reader<'a>> {
        let n = self.u8()? as usize;
        self.take(n).map(Reader::new)
    }

    /// Sous-lecteur préfixé par une longueur sur 2 octets.
    pub fn vec16(&mut self) -> Option<Reader<'a>> {
        let n = self.u16()? as usize;
        self.take(n).map(Reader::new)
    }

    /// Lit tous les entiers 16 bits restants.
    pub fn u16_list(mut self) -> Vec<u16> {
        let mut out = Vec::with_capacity(self.remaining() / 2);
        while let Some(v) = self.u16() {
            out.push(v);
        }
        out
    }
}

pub fn be16(buf: &[u8], at: usize) -> Option<u16> {
    buf.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
