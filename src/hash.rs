use std::mem;

use xxhash_rust::xxh3::xxh3_64;

use ShampooCondition::{BucketCollision, EndOfSegment};

pub use crate::heap::Blob;
use crate::util::puts;
use crate::shampoo::ShampooCondition;
use crate::shmem::{aload_u64, astore_u64, cas_u64x};
use crate::util::Matrix;

#[repr(C)]
#[derive(Debug)]
struct Entry {
    id: u64
}

pub struct Hash {
    base: *mut Entry,
    bins: u32
}

#[derive(Debug)]
pub struct IndexReport {
    used: u32,
    free: u32,
    overflows: u32
}

impl Hash {
    pub fn attach(base:*const u8, hash_size:u64) -> Self {
        let bins = hash_size / 8;
        puts(format!("init_hash @{:x} {} bins", base as u64, bins));
        assert_ne!(0, bins, "zero bins {}, {}", bins, hash_size);
        Hash { base: base as *mut Entry, bins: bins as u32 }
    }

    pub fn init(base:*const u8, hash_size:usize) -> Self {
        let bins = hash_size / 8;
        puts(format!("hash::init @{:x} {} bins", base as u64, bins));
        assert_ne!(0, bins, "zero bins");
        Hash { base: base as *mut Entry, bins: bins as u32 }
    }

    pub fn put<F>(&self, blob:*const Blob, rard:&F) -> Result<*const Blob, ShampooCondition>
        where F : Fn(u64) -> *const Blob
    {
        let name = unsafe { (*blob).name() } ;
        let xx = unsafe { (*blob).hash() };
        assert_ne!(0, self.bins);
        let mut bin = xx % self.bins;

        puts(format!("xxhash({}) -> {:x} % {} = bin {}", name, xx, self.bins, bin));

        unsafe {
            loop {
                if bin >= self.bins {
                    return Err(EndOfSegment)
                }

                // is the bin empty ?
                let prev_id = self.cas_addr(bin, 0, (*blob).id);
                if 0 == prev_id {
                    return Ok(0 as *const Blob);
                }

                let prev_blob = rard(prev_id);

                // this bin is already overflowed?
                if bin != (*prev_blob).hash() % self.bins {
                    return Err(BucketCollision);
                }

                // is the name the same?
                if (*blob).name() == (*prev_blob).name() {
                    puts("hash::put::performing update".to_string());
                    let prev = self.store_id(bin, (*blob).id);
                    return Ok(prev as *const Blob);
                }

                // try next bin
                bin += 1;
                puts(format!("hash::put::overflowing to bin {}", bin));
            }
        }
    }

    pub fn get<F>(&self, name:&str, rard:F) -> Option<*const Blob>
        where F : Fn(u64) -> *const Blob
    {
        let xx = Hash::hash(name);
        let orig_bin = xx % self.bins;
        let mut bin = orig_bin;

        unsafe {
            loop {
                if bin >= self.bins {
                    puts("hash::get::bins depleted, returning".to_string());
                    return None;
                }

                let entry = self.base.add(bin as usize);

                if (*entry).id == 0 {
                    puts("hash::get::bin empty, returning".to_string());
                    return None;
                }

                let blob = rard((*entry).id);
                (*blob).validate();

                if (*blob).hash() % self.bins != orig_bin {
                    puts("hash::get::overflow over, returning".to_string());
                    return None;
                }

                if (*blob).name() == name {
                    return Some(blob);
                }

                bin += 1;
            }
        }
    }

    pub fn references<F>(&self, blob:*const Blob, rard:F) -> bool
        where F : Fn(u64) -> *const Blob
    {
        let name = unsafe { (*blob).name() };
        match self.get(&name, rard) {
            Some(my_blob) => my_blob == blob,
            None => false
        }
    }

    fn cas_addr(&self, bin:u32, curr:u64, next:u64) -> u64 {
        unsafe {
            let addr = (&(*self.base.add(bin as usize)).id) as *const u64;
            match cas_u64x(&format!("bin[{}]", bin), addr, curr, next) {
                Ok(prev) => prev,
                Err(curr) => curr
            }
        }
    }

    fn store_id(&self, bin:u32, id:u64) -> u64 {
        unsafe {
            let addr = (&(*self.base.add(bin as usize)).id) as *const u64;
            astore_u64(&format!("bin[{}]", bin), addr, id)
        }
    }

    fn load_id(&self, bin:u32) -> u64 {
        unsafe {
            let addr = (&(*self.base.add(bin as usize)).id) as *const u64;
            aload_u64(&format!("bin[{}]", bin), addr)
        }
    }

    pub fn hash(str:&str) -> u32 {
        xxh3_64(str.as_bytes()) as u32
    }

    pub fn len(&self) -> usize {
        self.bins as usize * mem::size_of::<Entry>()
    }

    pub fn print<F>(&self, mut rard: F)
        where F : Fn(u64) -> *const Blob
    {
        let mut mat = Matrix::new();
        unsafe {
            for bin in 0..self.bins {
                let entry = self.base.add(bin as usize);
                if (*entry).id != 0 {
                    mat.add(&format!("[{}] ", bin));
                    mat.add(&format!("@{:x} ->", entry as u64));
                    mat.add(&format!("id:{}", (*entry).id));

                    let blob = rard((*entry).id);
                    let should_be_bin = &(*blob).hash() % self.bins;
                    if should_be_bin != bin {
                        mat.add(&format!("(actually [{}])", should_be_bin));
                    }
                    mat.nl();
                }
            }
        }
        if mat.is_empty() {
            println!("<EMPTY>")
        }
        else {
            println!("{}", mat);
        }
    }

    pub fn report<F>(&self, rard:&F) -> IndexReport
    where F : Fn(u64) -> *const Blob
    {
        let mut report = IndexReport{ used:0, free:0, overflows:0 };

        unsafe {
            for bin in 0..self.bins {
                let entry = self.base.add(bin as usize);

                if (*entry).id == 0 {
                    report.free += 1;
                    continue
                }

                let blob = rard((*entry).id);
                (*blob).validate();
                report.used += 1;

                let orig_bin = (*blob).hash() % self.bins;
                if bin != orig_bin {
                    report.overflows += 1;
                }
            }
        }

        return report;
    }

}

#[cfg(test)]
pub(crate) mod tests {
    use heap::tests::init_heap;
    use crate::blob::Blob;
    use crate::hash::Hash;
    use crate::heap;

    #[test]
    fn test_put_get() {
        let hash_mem = [0u8; 256];
        let hash = init_hash(&hash_mem, 4);

        let heap_mem = [0u8; 128];
        let heap = init_heap(&heap_mem);
        let blob_in = heap.allocates("blob1", "blah").unwrap();

        hash.put(blob_in, &|id| heap.rard(id)).unwrap();

        let blob_out = hash.get("blob1", &|id| heap.rard(id)).unwrap();
        assert_eq!(blob_in, blob_out.cast_mut());
    }

    #[test]
    fn test_get_nothing() {
        let mem = [0u8; 256];
        let hash = init_hash(&mem, 4);
        match hash.get("abc", &|id|id as *const Blob) {
            None => {},
            Some(_) => panic!("fail")
        }
    }

    #[test]
    fn test_update() {
        unsafe {
            let mem = [0u8; 256];
            let hash = init_hash(&mem, 4);

            let ram = [0u8; 144];
            let heap = init_heap(&ram);
            let blob1 = heap.allocates("blob", "blah").unwrap();
            let blob2 = heap.allocates("blob", "blech").unwrap();

            hash.put(blob1, &|id| heap.rard(id)).unwrap();
            hash.put(blob2, &|id| heap.rard(id)).unwrap();

            let blob_out = hash.get("blob", &|id| heap.rard(id)).unwrap();
            assert_eq!(blob2, blob_out.cast_mut());
            assert_eq!("blech".as_bytes(), (*blob_out).data().as_slice());

            assert!(!hash.references(blob1, &|id| heap.rard(id)));
            assert!(hash.references(blob2, &|id| heap.rard(id)));
        }
    }

    pub fn init_hash(mem:&[u8], bins:u64) -> Hash {
        assert!(bins * 8 <= mem.len() as u64);
        Hash::init(mem.as_ptr(), mem.len());
        Hash::attach(mem.as_ptr(), bins * 8)
    }

    #[test]
    fn test_report() {
        let hash_mem = [0u8; 256];
        let hash = init_hash(&hash_mem, 4);

        let heap_mem = [0u8; 128];
        let heap = init_heap(&heap_mem);
        let blob = heap.allocates("blob1", "blah").unwrap();

        let report1 = hash.report(&|id| heap.rard(id));
        assert_eq!(0, report1.used);
        assert_eq!(4, report1.free);
        assert_eq!(0, report1.overflows);

        hash.put(blob, &|id| heap.rard(id)).unwrap();

        let report2 = hash.report(&|id| heap.rard(id));
        assert_eq!(1, report2.used);
        assert_eq!(3, report2.free);
        assert_eq!(0, report2.overflows);
    }

    #[test]
    fn test_overflow() {
        unsafe {
            let hash_mem = [0u8; 256];
            let hash = init_hash(&hash_mem, 4);
            let heap_mem = [0u8; 256];
            let heap = init_heap(&heap_mem);
            let blob1 = heap.allocates("blob", "abc").unwrap();
            let blob2 = heap.allocates("blobZ", "xyz").unwrap();

            let hash1 = (*blob1).hash();
            let hash2 = (*blob2).hash();
            assert_ne!(hash1, hash2);

            assert_eq!(1, hash1 % hash.bins);
            assert_eq!(1, hash2 % hash.bins);

            hash.put(blob1, &|id| heap.rard(id)).unwrap();
            hash.put(blob2, &|id| heap.rard(id)).unwrap();

            let report = hash.report(&|id|heap.rard(id));
            assert_eq!(2, report.used);
            assert_eq!(2, report.free);
            assert_eq!(1, report.overflows);

            assert_eq!("abc".as_bytes(), (*hash.get("blob", &|id|heap.rard(id)).unwrap()).data().as_slice());
            assert_eq!("xyz".as_bytes(), (*hash.get("blobZ", &|id|heap.rard(id)).unwrap()).data().as_slice());
        }
    }

    #[test]
    fn test_references() {
        let hash_mem = [0u8; 256];
        let hash = init_hash(&hash_mem, 4);

        let heap_mem = [0u8; 144];
        let heap = init_heap(&heap_mem);
        let blob1 = heap.allocates("blob", "blah").unwrap();

        assert!(!hash.references(blob1, &|id| heap.rard(id)));

        hash.put(blob1, &|id| heap.rard(id)).unwrap();
        assert!(hash.references(blob1, &|id| heap.rard(id)));

        let blob2 = heap.allocates("blob", "blech").unwrap();
        hash.put(blob2, &|id| heap.rard(id)).unwrap();

        assert!(!hash.references(blob1, &|id| heap.rard(id)));
        assert!(hash.references(blob2, &|id| heap.rard(id)));
    }

    #[test]
    fn test_load_store_id() {
        let hash_mem = [0u8; 256];
        let hash = init_hash(&hash_mem, 4);
        assert_eq!(0, hash.load_id(0));
        assert_eq!(0, hash.store_id(0, 1234));
        assert_eq!(1234, hash.load_id(0));
    }
}
