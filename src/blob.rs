use std::mem::size_of;
use std::thread::sleep;
use std::time::Duration;
use crate::hash::Hash;

use crate::shmem;
use crate::shmem::{aload_u64, astore_u64, cas_u64, inc_ptr, str, str_to_u64};
use crate::util::mag_fmt;
use crate::util::puts;

pub static BLOB_MAGIC: &str = "BLOB";
pub static PEND_MAGIC: &str = "PEND";

#[repr(C)]
#[derive(Debug)]
pub struct Blob {
    pub magic: [u8;4],
    pub len: usize,
    pub name_len: usize,
    pub data_len: usize,
    pub id: u64,
    pub ascii:bool,
    pad: [u8;7]
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
            (*blob).name_len = name.len();
            (*blob).data_len = data.len();
            (*blob).len = len + pad;
            (*blob).id = id;
            (*blob).ascii = false;

            assert_eq!(0, (*blob).len % 8);

            // if we are padding name will be blank
            if name.len() > 0 {
                let name_addr = (blob as *mut u8).add(Blob::header_len());
                shmem::write(name_addr, name.as_bytes());
                (*blob).name_len = name.len();
            }

            if data.len() > 0 {
                let data_addr = (blob as *mut u8).add(Blob::header_len() + (*blob).name_len);
                shmem::write(data_addr, data);
                (*blob).data_len = data.len();
            }

            blob
        }
    }

    pub fn mark_pending(ptr: *const u8) {
        let addr = ptr as *const u64;
        astore_u64("pend", addr, str_to_u64(PEND_MAGIC));
    }

    pub fn mark_ready(&self) {
        let addr = self.magic.as_ptr() as *const u64;
        if !cas_u64("blob", addr, str_to_u64(PEND_MAGIC), str_to_u64(BLOB_MAGIC)) {
            panic!("!ready");
        }
        puts(format!("++ {:?}", self));
    }

    pub fn magic(&self) -> u64 {
        let ptr = self.magic.as_ptr() as *const u64;
        aload_u64("blob/magic", ptr)
    }

    pub fn ready(&self) -> bool {
        let magic = self.magic();
        if magic == str_to_u64(BLOB_MAGIC) {
            return true;
        }
        if magic == str_to_u64(PEND_MAGIC) {
            return false;
        }
        panic!("ouch! @{:x} {:?}", self.addr(), (*self));
    }

    pub fn wait_for(&self) {
        let mut n = 0;
        while !self.ready() {
            sleep(Duration::from_millis(10));
            n += 1;
            if n > 100 {
                panic!("waiting for blob {:x}", self.addr());
            }
        }
        self.validate();
    }

    pub fn addr(&self) -> u64 {
        self as *const Blob as u64
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

    // todo: test me
    pub fn data_view(&self) -> String {
        if self.ascii {
            String::from_utf8(self.data()).unwrap()
        } else {
            format!("{}", mag_fmt(self.len as u64))
        }
    }

    pub fn hash(&self) -> u32 {
        Hash::hash(&self.name())
    }

    pub fn validate(&self) {
        // [80, 69, 78, 68] "PEND" 1145980240
        // [66, 76, 79, 66] "BLOB" 1112493122
        let msg = format!("invalid blob @{:x} {:?}", self as *const Blob as u64, self);
        let magic = aload_u64("magic", (*self).magic.as_ptr() as *const u64);
        if magic != str_to_u64(BLOB_MAGIC) {
            println!("magic:{}/{}", magic, str_to_u64(BLOB_MAGIC));
            panic!("{}", msg);
        }
        assert!(self.len >= Blob::header_len(), "?len:{}", self.len);
    }

    pub fn header_len() -> usize {
        size_of::<Blob>()
    }
}

#[cfg(test)]
mod tests {
    use crate::blob::BLOB_MAGIC;
    use crate::hash::{Blob, Hash};
    use crate::shmem::{str, str_to_u64};

    #[test]
    fn test_header_len() {
        assert_eq!(48, Blob::header_len())
    }

    #[test]
    fn test_init() {
        unsafe {
            let ram = [0u8; 1 << 8];
            Blob::mark_pending(ram.as_ptr());
            let blob = Blob::init(ram.as_ptr(), "bob", &[9u8; 16], 123);
            assert!(!(*blob).ready());
            (*blob).mark_ready();
            (*blob).validate();
            assert_eq!("BLOB", str((*blob).magic.as_ptr(), 4));
            assert_eq!(72, (*blob).len);
            assert_eq!(3, (*blob).name_len);
            assert_eq!(16, (*blob).data_len);
            assert_eq!(123, (*blob).id); // obvs not realistic
            assert_eq!("bob", (*blob).name());
            assert_eq!(vec![9u8; 16], (*blob).data());
            assert_eq!(false, (*blob).ascii);
        }
    }

    #[test]
    fn test_init2() {
        let ram = [0u8; 1 << 8];
        Blob::mark_pending(ram.as_ptr());
        let blob = Blob::init(ram.as_ptr(), "", &[], 0);
        unsafe { (*blob).mark_ready() };
        unsafe { (*blob).validate() };
        assert_eq!(Blob::header_len(), unsafe { (*blob).len });
    }

    #[test]
    fn test_hash() {
        let ram = [0u8; 1 << 8];
        Blob::mark_pending(ram.as_ptr());
        let blob = Blob::init(ram.as_ptr(), "abc", &[], 0);
        assert_eq!(Hash::hash("abc"), unsafe { (*blob).hash() });
        assert_eq!(2301573456, unsafe { (*blob).hash() });
    }

    #[test]
    fn test_magic_pending() {
        let ram = [0u8; 1 << 8];

        Blob::mark_pending(ram.as_ptr());
        assert_eq!(str_to_u64("PEND"), unsafe { (*(ram.as_ptr() as *const Blob)).magic() });

        let blob = Blob::init(ram.as_ptr(), "abc", &[], 0);
        assert_eq!(str_to_u64("PEND"), unsafe { (*blob).magic() });

        unsafe { (*blob).mark_ready() };
        assert_eq!(str_to_u64(BLOB_MAGIC), unsafe { (*blob).magic() });
    }
}
