use std::fmt;
use std::fmt::Formatter;
use std::mem::size_of;

use crate::hash::Hash;
use crate::shmem;
use crate::shmem::{aload_u64, cas_u64, inc_ptr, str, str_to_u64};
use crate::util::mag_fmt;
use crate::util::puts;

pub static BLOB_MAGIC: &str = "BLOB";

#[repr(C)]
#[derive(Debug)]
pub struct Blob {
    pub magic: [u8;4],
    pub len: usize,
    pub name_len: usize,
    pub data_len: usize,
    pub id: u64,
    pad: [u8;8]
}

impl fmt::Display for Blob {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let addr = self as *const Blob;
        write!(f, "@{:x} {} {} {} '{}' : {}",
               addr as u64,
               str(addr as *const u8, 4),
               self.id,
               mag_fmt(self.len as u64),
               self.name(),
               self.data_view()
        )
    }
}

impl Blob {
    pub fn init(addr:*const u8, name:&str, data:&[u8], id:u64) -> *mut Blob {
        if addr as u64 % 8 != 0 {
            panic!("malign pointer @{:x}", addr as u64)
        }

        let len = Blob::header_len() + name.len() + data.len();
        let pad = if len % 8 > 0 { 8 - len % 8 } else { 0 };

        unsafe {
            let blob = addr as *mut Blob;
            (*blob).magic = [0,0,0,0];
            (*blob).name_len = name.len();
            (*blob).data_len = data.len();
            (*blob).len = len + pad;
            (*blob).id = id;

            assert_eq!(0, (*blob).len % 8);

            // if we are padding name will be blank
            if name.len() > 0 {
                let name_addr = (blob as *mut u8).add(Blob::header_len());
                shmem::write(name_addr, name.as_bytes());
                (*blob).name_len = name.len(); // necessary?
            }

            if data.len() > 0 {
                let data_addr = (blob as *mut u8).add(Blob::header_len() + (*blob).name_len);
                shmem::write(data_addr, data);
                (*blob).data_len = data.len();
            }

            blob
        }
    }

    pub fn mark_ready(&self) {
        let addr = self.magic.as_ptr() as *const u64;
        if !cas_u64("blob", addr, 0u64, str_to_u64(BLOB_MAGIC)) {
            panic!("!blanked");
        }
        puts(format!("++ {:?}", self));
        puts(format!("++ {}", self));
    }

    pub fn name(&self) -> String {
        let loc = inc_ptr(self as *const Blob as *const char, Blob::header_len());
        str(loc as *mut u8, self.name_len)
    }

    pub fn data(&self) -> Vec<u8> {
        let mut vec:Vec<u8> = Vec::with_capacity(self.data_len);
        let data_loc = inc_ptr(self as *const Blob as *const u8, Blob::header_len() + self.name_len);
        for i in 0..self.data_len {
            vec.push( unsafe { *(data_loc.add(i)) });
        }
        vec
    }

    pub fn data_view(&self) -> String {
        let data = self.data();
        if data.is_ascii() {
            let str = String::from_utf8(data).unwrap();
            format!("'{}'", str.trim_end_matches('\n'))
        } else {
            mag_fmt(data.len() as u64)
        }
    }

    pub fn hash(&self) -> u32 {
        Hash::hash(&self.name())
    }

    pub fn validate(&self) {
        // [66, 76, 79, 66] "BLOB" 1112493122
        let msg = format!("invalid blob @{:x} {:?}", self as *const Blob as u64, self);
        let magic = aload_u64("magic", (*self).magic.as_ptr() as *const u64);
        if magic != str_to_u64(BLOB_MAGIC) {
            panic!("{}\n{}", msg, self);
        }
        assert!(self.len >= Blob::header_len(), "?len:{}", self.len);
    }

    pub fn header_len() -> usize {
        size_of::<Blob>()
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::{Blob, Hash};
    use crate::shmem::{str};

    #[test]
    fn test_header_len() {
        assert_eq!(48, Blob::header_len())
    }

    #[test]
    fn test_init() {
        unsafe {
            let ram = [0u8; 1 << 8];
            let blob = Blob::init(ram.as_ptr(), "bob", &[9u8; 16], 123);
            (*blob).mark_ready();
            (*blob).validate();
            assert_eq!("BLOB", str((*blob).magic.as_ptr(), 4));
            assert_eq!(72, (*blob).len);
            assert_eq!(3, (*blob).name_len);
            assert_eq!(16, (*blob).data_len);
            assert_eq!(123, (*blob).id); // obvs not realistic
            assert_eq!("bob", (*blob).name());
            assert_eq!(vec![9u8; 16], (*blob).data());
        }
    }

    #[test]
    fn test_init2() {
        let ram = [0u8; 1 << 8];
        let blob = Blob::init(ram.as_ptr(), "", &[], 0);
        unsafe { (*blob).mark_ready() };
        unsafe { (*blob).validate() };
        assert_eq!(Blob::header_len(), unsafe { (*blob).len });
    }

    #[test]
    fn test_hash() {
        let ram = [0u8; 1 << 8];
        let blob = Blob::init(ram.as_ptr(), "abc", &[], 0);
        assert_eq!(Hash::hash("abc"), unsafe { (*blob).hash() });
        assert_eq!(2301573456, unsafe { (*blob).hash() });
    }
}
