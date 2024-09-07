use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::Ordering::{Relaxed, SeqCst};

pub static ECHO:AtomicBool = AtomicBool::new(false);

pub fn write(addr: *mut u8, data: &[u8]) {
    unsafe {
        if addr as u64 == 0 {
            panic!("invalid access");
        }
        copy_nonoverlapping(data.as_ptr(), addr, data.len());
    }
}

pub fn str(ptr: *const u8, len:usize) -> String {
    let mut str = String::with_capacity(len);
    let mut ptr2 = ptr;
    for _ in 0..len {
        unsafe { str.push(*ptr2 as char); }
        unsafe { ptr2 = ptr2.add(1) }
    }
    str
}

pub fn inc_ptr<T>(ptr: *const T, offset:usize) -> *mut T {
    unsafe {
        (ptr as *const u8).add(offset) as *mut T
    }
}


pub fn str_to_u64(str:&str) -> u64 {
    // network byte order = little endian
    let mut ret = 0u64;
    for i in 0..str.len() {
        let c = str.chars().nth(i).unwrap();
        ret += (c as u64) << (8*i) as u64;
    }
    ret
}

pub fn astore_u64(name:&str, addr:*const u64, val:u64) -> u64 {
    let prev = unsafe { (*(addr as *const AtomicU64)).swap(val, SeqCst) };
    if ECHO.load(Relaxed) {
        println!("shmem::store::{}@{:x}::[{:x} -> {:x}]", name, addr as u64, prev, val);
    }
    prev
}

pub fn aload_u64(_name:&str, addr:* const u64) -> u64 {
    unsafe {
        if addr as u64 == 0 {
            panic!("invalid access");
        }
        (*(addr as *const AtomicU64)).load(SeqCst)
    }
}

pub fn cas_u64(name:&str, addr:* const u64, cur:u64, new:u64) -> bool {
    match cas_u64x(name, addr, cur, new) {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn cas_u64x(name:&str, addr:* const u64, cur:u64, new:u64) -> Result<u64, u64> {
    unsafe {
        if addr as u64 == 0 {
            panic!("invalid access");
        }
        match (*(addr as *const AtomicU64)).compare_exchange(cur, new, SeqCst, SeqCst) {
            Ok(prev) => {
                if ECHO.load(Relaxed) {
                    println!("shmem::cas::{}@{:x}::[{:x} -> {:x}]", name, addr as u64, cur, new);
                }
                Ok(prev)
            }
            Err(curr) => {
                if ECHO.load(Relaxed) {
                    println!("shmem::cas::failed::{}@{:x}::[{:x} -> {:x}] curr={:x}",
                             name, addr as u64, cur, new, curr);
                }
                Err(curr)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::shmem::{aload_u64, astore_u64, cas_u64, cas_u64x, str, str_to_u64};

    #[test]
    fn test_str() {
        let mut s = "abc".to_string();
        assert_eq!("ab", str(s.as_mut_ptr(), 2))
    }

    #[test]
    fn test_str_to_u64() {
        assert_eq!(0, str_to_u64(""));
        assert_eq!(65, str_to_u64("A"));
        assert_eq!(1346454856, str_to_u64("HEAP"));
        assert_eq!([72, 69, 65, 80, 0, 0, 0, 0], str_to_u64("HEAP").to_ne_bytes());
    }

    #[test]
    fn test_u64() {
        let n = 123u64;
        let pn = &n as *const u64;
        assert_eq!(123, n);
        unsafe { assert_eq!(123, *pn); }
        assert_eq!(123, aload_u64("test", &n));
        assert_eq!(123, aload_u64("test", pn));

        assert_eq!(123, astore_u64("test", pn, 456));
        assert_eq!(456, n);
        unsafe { assert_eq!(456, *pn); }
        assert_eq!(456, aload_u64("test", &n));
        assert_eq!(456, aload_u64("test", pn));

        assert!(!cas_u64("test", pn, 123, 789));
        assert!(cas_u64("test", pn, 456, 789));
        assert_eq!(789, n);
        unsafe { assert_eq!(789, *pn); }
        assert_eq!(789, aload_u64("test", &n));
        assert_eq!(789, aload_u64("test", pn));
    }

    #[test]
    fn test_u64_buf() {
        let buf = [0u8;8];//.as_mut_ptr() as *mut u64;
        let pn = (&buf as *const u8) as *const u64;
        assert_eq!([0,0,0,0,0,0,0,0], buf);
        unsafe { assert_eq!(0, *pn); }
        assert_eq!(0, aload_u64("test", pn));

        assert_eq!(0, astore_u64("test", pn, 1));
        assert_eq!([1,0,0,0,0,0,0,0], buf);
        unsafe { assert_eq!(1, *pn); }
        assert_eq!(1, aload_u64("test", buf.as_ptr() as *const u64));
        assert_eq!(1, aload_u64("test", pn));

        assert!(!cas_u64("test", pn, 2, 3));
        assert!(cas_u64("test", pn, 1, u64::MAX));
        assert_eq!([255u8;8], buf);
        unsafe { assert_eq!(u64::MAX, *pn); }
        assert_eq!(u64::MAX, aload_u64("test", buf.as_ptr() as *const u64));
        assert_eq!(u64::MAX, aload_u64("test", pn));
    }

    #[test]
    fn test_u64_struct() {
        struct X {
            v: u64
        }

        let buf = [0u8;8];//.as_mut_ptr() as *mut u64;
        let px = buf.as_ptr() as *const X;
        assert_eq!([0,0,0,0,0,0,0,0], buf);
        unsafe { assert_eq!(0, (*px).v); }
        unsafe { assert_eq!(0, aload_u64("test", &(*px).v)); }

        unsafe { assert_eq!(0, astore_u64("test", &(*px).v, 11212121)); }
        assert_eq!([89, 21, 171, 0, 0, 0, 0, 0], buf);
        unsafe { assert_eq!(11212121, (*px).v); }
        assert_eq!(11212121, aload_u64("test", buf.as_ptr() as *const u64));
        unsafe { assert_eq!(11212121, aload_u64("test", &(*px).v)); }

        unsafe { assert!(!cas_u64("test", &(*px).v, 4444, 453432423)); }
        unsafe { assert!(cas_u64("test", &(*px).v, 11212121, 4321)); }
        assert_eq!([225, 16, 0, 0, 0, 0, 0, 0], buf);
        unsafe { assert_eq!(4321, (*px).v); }
        assert_eq!(4321, aload_u64("test", buf.as_ptr() as *const u64));
        unsafe { assert_eq!(4321, aload_u64("test", &(*px).v)); }
    }

    #[test]
    fn test_symmetry() {
        let mut buf = [0u8;8];
        assert_eq!(0, astore_u64("symmetry", buf.as_mut_ptr() as *mut u64, 1));
        assert_eq!(1, aload_u64("symmetry", buf.as_mut_ptr() as *mut u64));
        unsafe { assert_eq!(1, *((buf.as_ptr()) as *const u64)); }
        assert!(!cas_u64("symmetry", buf.as_mut_ptr() as *mut u64, 2, 2));
        unsafe { assert_eq!(1, *((buf.as_ptr()) as *const u64)); }
        assert!(cas_u64("symmetry", buf.as_mut_ptr() as *mut u64, 1, 2));
        unsafe { assert_eq!(2, *((buf.as_ptr()) as *const u64)); }
        assert_eq!(2, aload_u64("symmetry", buf.as_mut_ptr() as *mut u64));
        assert_eq!(2, astore_u64("symmetry", buf.as_mut_ptr() as *mut u64, 3));
    }

    #[test]
    fn test_cas_u64x() {
        let ptr = [0u8;8].as_mut_ptr() as *mut u64;
        assert_eq!(Ok(0), cas_u64x("test", ptr, 0, 10));
        unsafe { assert_eq!(10, *ptr) }
        assert_eq!(Ok(10), cas_u64x("test", ptr, 10, 20));
        unsafe { assert_eq!(20, *ptr) }
        assert_eq!(Err(20), cas_u64x("test", ptr, 55, 99));
        unsafe { assert_eq!(20, *ptr) }
    }

    #[test]
    fn test_shmem_sanity() {
        let n = 23u64;
        let pn = &n as *const u64;
        println!("pn = {:?}", pn);
        let prev = astore_u64("sanity", pn, 32u64);
        assert_eq!(23, prev);
        assert_eq!(32, n);
    }
}
