use std::fmt;
use std::fmt::Formatter;
use std::mem::size_of;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use ShampooCondition::AllocationFailure;

pub use crate::blob::Blob;
use crate::shampoo::{ShampooCondition, VERBOSE};
use crate::shampoo::ShampooCondition::{CASMiss, NoImmediateGarbage, Nothing};
use crate::shmem::{aload_u64, cas_u64, str_to_u64};
use crate::util::{mag_fmt, Matrix};
use crate::util::puts;

#[repr(C)]
#[derive(Debug)]
struct Metadata {
    magic: [u8;4],
    head: u64,
    tail: u64
}

impl Metadata {
    pub fn size_of() -> usize {
        size_of::<Metadata>()
    }
}

pub struct Heap {
    pub capacity: usize,
    meta: *mut Metadata,
    pub boh: u64,         // beginning of heap
    pub eoh: u64          //       end of heap
}

pub struct HeapReport {
    pub blobs: u32,
    pub blob_bytes: usize,
    pub frags: u32,
    pub frag_bytes: usize,
    pub available: usize,
    capacity: usize
}

impl fmt::Display for HeapReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Heap blobs:{:?}({}) fragments:{:?}({}) -> {}% garbage / {} available",
                 self.blobs,
                 mag_fmt(self.blob_bytes as u64),
                 self.frags,
                 mag_fmt(self.frag_bytes as u64),
                 100 * self.frag_bytes / self.capacity,
                 mag_fmt(self.available as u64)
        )
    }
}

impl Heap {
    pub fn attach(base: *const u8, capacity:usize) -> Heap {
        if base as u64 % 8 != 0 {
            panic!("not a multiple of 8: {:?}", base);
        }

        let meta = base as *mut Metadata;
        let meta_len = size_of::<Metadata>() as u64;
        let boh = base as u64 + meta_len;
        let eoh = base as u64 + capacity as u64;

        let heap = Heap { capacity: capacity - meta_len as usize, meta, boh, eoh };
        assert_eq!(capacity as u64 - meta_len, eoh - boh);
        heap.init();

        if VERBOSE.load(Relaxed) {
            heap.info();
        }

        heap
    }

    pub fn validate(&self) {
        unsafe {
            if aload_u64("heap/magic", (*self.meta).magic.as_mut_ptr() as *const u64) != str_to_u64("HEAP") {
                panic!("heap not magic");
            }

            let tail = self.load_tail();
            let head = self.load_head();

            if tail > head {
                panic!("heap crossed");
            }

            if tail != head {
                let tail_blob = self.rard(tail);
                (*tail_blob).validate();
            }
        }
        unsafe {
            self.walk(&mut|blob| (*blob).validate());
        }
    }

    fn init(&self) {
        unsafe {
            // to keep the logs clean
            let verb = if (*self.meta).magic == [0u8;4] && cas_u64("heap/magic", (*self.meta).magic.as_mut_ptr() as *const u64, 0, str_to_u64("HEAP")) {
                (*self.meta).head = 1;
                (*self.meta).tail = 1;
                "init"
            } else {
                "attach"
            };
            puts(format!("heap::{} @{:x}, capacity {}", verb, self.meta as u64, self.capacity));
        }

        self.validate();
    }

    fn find_block(&self, requested_len:usize) -> Result<(u64, u64), ShampooCondition> {
        if requested_len % 8 != 0 {
            panic!("len % 8 != 0");
        }

        loop {
            puts(format!("heap::find_block {} bytes requested", requested_len));
            let available = self.available();
            if available < requested_len {
                puts(format!("heap::find_block::not enough memory. available={} requested={}", available, requested_len));
                return Err(AllocationFailure);
            }

            let begin = self.load_head();

            // do we have enough space remaining at the end of the heap?
            let remaining = (self.eoh - self.rard(begin) as u64) as usize;
            if remaining < requested_len {
                puts(format!("heap::find_block::insufficient space at end of heap ({} < {}), padding", remaining, requested_len));
                self.pad_rest_of_heap(begin, remaining);
                continue;
            }

            let mut end = begin + requested_len as u64;

            // never leave too little at the end
            let leftovers = self.eoh - self.rard(end) as u64;
            if 0 < leftovers && leftovers < Blob::header_len() as u64 {
                puts(format!("heap::find_block::expanding blob to absorb leftovers ({})", leftovers));
                end += leftovers;
                assert_eq!(self.boh, self.rard(end) as u64);
            }

            puts(format!("heap::find_block proposing {} .. {} len:{}", self.id_str(begin), self.id_str(end), end-begin));

            Blob::mark_pending(self.rard(begin) as *const u8);

            if self.cas_head(begin, end) {
                return Ok((begin, end-begin));
            }
            else {
                puts(format!("heap::find_block::acquisition unsuccessful - will retry"));
            }
        }
    }

    pub fn rard(&self, id:u64) -> *const Blob {
        (self.boh + ((id - 1) % (self.eoh - self.boh))) as *const Blob
    }

    fn pad_rest_of_heap(&self, head: u64, pad_len: usize) {
        if pad_len < Blob::header_len() {
            panic!("pad failure");
        }

        Blob::mark_pending(self.rard(head) as *const u8);

        if self.cas_head(head, head + pad_len as u64) {
            let pad = vec![0u8; pad_len - Blob::header_len()];
            let addr = self.rard(head) as *const u8;
            //race:
            let blob = Blob::init(addr, "", &pad, head);
            unsafe { (*blob).mark_ready() };
            assert_eq!(self.eoh, blob as u64 + unsafe { (*blob).len } as u64);
        } else {
            puts(format!("heap::pad::WARN::pad did not succeed. will retry"));
        }
    }

    fn cas_head(&self, curr:u64, next:u64) -> bool {
        unsafe {
            cas_u64("head", &(*self.meta).head, curr, next)
        }
    }

    pub fn cas_tail(&self, curr:u64, next:u64) -> bool {
        unsafe {
            cas_u64("tail", &(*self.meta).tail, curr, next)
        }
    }

    pub fn load_head(&self) -> u64 {
        unsafe {
            aload_u64("head", &(*self.meta).head)
        }
    }

    pub fn load_tail(&self) -> u64 {
        unsafe {
            aload_u64("tail", &(*self.meta).tail)
        }
    }

    fn id_str(&self, id:u64) -> String {
        format!("{:x}:{}", self.rard(id) as u64, id)
    }

    pub fn allocates(&self, name:&str, txt:&str) -> Result<*mut Blob, ShampooCondition> {
        self.allocate(name, txt.as_bytes(), true)
    }

    pub fn allocate(&self, name:&str, data:&[u8], ascii:bool) -> Result<*mut Blob, ShampooCondition> {
        unsafe {
            let mut total_len = Blob::header_len() + name.len() + data.len();
            puts(format!("heap::allocate::['{}' -> {} bytes] = {} bytes total", name, data.len(), total_len));

            if total_len % 8 != 0 {
                let pad = 8 - (total_len % 8);
                puts(format!("heap::allocate::padding block {} + {} = {}", total_len, pad, total_len + pad));
                total_len += pad;
            };

            let (id, actual_len) = match self.find_block(total_len) {
                Ok((id, actual_len)) => (id, actual_len),
                Err(err) => return Err(err)
            };

            let blob = Blob::init(self.rard(id) as *const u8, name, data, id);
            (*blob).ascii = ascii;
            (*blob).len = actual_len as usize;

            (*blob).mark_ready();

            Ok(blob)
        }
    }

    pub fn gc_tail<F>(&self, is_garbage:&F) -> Result<usize, ShampooCondition>
        where F : Fn(*const Blob) -> bool
    {
        let tail = self.load_tail();
        
        if tail == self.load_head() {
            return Err(Nothing)
        }

        let blob = self.rard(tail);

        unsafe { (*blob).validate() };

        if !is_garbage(blob) {
            return Err(NoImmediateGarbage)
        }

        unsafe {
            let id = (*blob).id;
            assert_eq!(tail, id);
            let len = (*blob).len;

            if self.cas_tail(id, id + len as u64) {
                Ok(len)
            }
            else {
                // unclear why this would happen other than
                // because of multiple concurrent collectors
                println!("heap::gc_tail::cas miss (WARN)");
                Err(CASMiss)
            }
        }
    }

    // todo: test this
    pub fn gc_run<F,G>(&self, is_garbage:&F, re_add:&G) -> Result<usize, ShampooCondition>
        where F : Fn(*const Blob) -> bool,
              G : Fn(*const Blob) -> Result<(), ShampooCondition>
    {
        let report = self.report(is_garbage);
        let garbage = report.frag_bytes;
        let mut collected = 0i32;
        let mut relocated = 0i32;

        if garbage == 0 {
            return Ok(0);
        }

        let start = Instant::now();

        println!("{}", report);

        println!("heap::gc::got garbage::{} over {} fragments",
                 mag_fmt(report.frag_bytes as u64), report.frags);

        while collected < garbage as i32 {
            let tail = self.load_tail();
            let blob = self.rard(tail);
            let id = unsafe { (*blob).id };
            let len = unsafe { (*blob).len } as i32;
            let relocate = !is_garbage(blob);

            if relocate {
                println!("heap::gc::relocating tail id:{}", id);
                re_add(blob)?;
                assert!(is_garbage(blob));
                relocated += len;
            }
            else {
                collected += len;
            }

            match self.gc_tail(is_garbage) {
                Ok(bytes) => {
                    if !relocate {
                        let remaining = (garbage as i32 - collected) as u64;
                        println!("heap::gc_tail::free'd {} from id:{} remaining {}",
                                 mag_fmt(bytes as u64), id, mag_fmt(remaining));
                    }
                },
                Err(err) => {
                    println!("heap::gc_tail::err::{:?} - concurrent gc??", err);
                    return Err(err)  // fatal?
                },
            };

        }

        self.validate();

        let available = self.available();

        println!("heap::gc::complete[free'd:{}({}%) relocated:{}({}%) available:{}({}%)] elapsed:{:?}",
                 mag_fmt(collected as u64),
                 100 * collected / self.capacity as i32,
                 mag_fmt(relocated as u64),
                 100 * relocated / self.capacity as i32,
                 mag_fmt(available as u64),
                 100 * available / self.capacity,
                 start.elapsed());

        Ok(collected as usize)
    }

    pub fn walk<F>(&self, visitor:&mut F)
        where F: FnMut(*const Blob)
    {
        let start = Instant::now();
        let mut id = self.load_tail();

        loop {
            let head = self.load_head();
            if id == head {
                break;
            }

            assert!(id < head, "something is dreadfully wrong");

            let blob = self.rard(id);
            unsafe { (*blob).wait_for() }
            assert!(blob as u64 <= self.eoh -1);
            assert!(blob as u64 >= self.boh);
            unsafe { (*blob).validate() };

            visitor(blob);

            let len = unsafe { (*blob).len } as u64;
            id += len;
        }

        puts(format!("heap::walk::took {:?}", start.elapsed()));
    }

    pub fn available(&self) -> usize {
        let head = self.load_head() as usize;
        let tail = self.load_tail() as usize;
        if tail <= head {
            self.capacity - (head - tail)
        } else {
            panic!("this should never happen")
        }
    }

    pub fn print<F>(&self, is_garbage:&F)
        where F : Fn(*const Blob) -> bool
    {
        let mut mat = Matrix::new();

        self.walk(&mut |blob:*const Blob| {
            unsafe {
                mat.add(&format!("id:{}", (*blob).id));
                mat.add(&format!("@{:x}:{}", 
                                 self.rard((*blob).id) as u64,
                                 blob as u64 - self.boh + 1
                                 ));
                mat.add(&format!("#{:x}", (*blob).hash()));
                mat.add(&(*blob).name());
                mat.add(&mag_fmt((*blob).len as u64));

                let mut flags = vec![];
                if is_garbage(blob) {
                    flags.push("garbage");
                }
                if (*blob).id == (*self.meta).head {
                    flags.push("head");
                }
                if (*blob).id == (*self.meta).tail {
                    flags.push("tail");
                }
                if blob as u64 == self.boh {
                    flags.push("boh");
                }
                if blob as u64 == self.eoh {
                    flags.push("eoh");
                }
                if flags.is_empty() {
                    mat.add("");
                }
                else {
                    mat.add(&format!("[{}]", flags.join(" ")));
                }

                mat.add(&(*blob).data_view());

                mat.nl();
            }
        });

        if mat.is_empty() {
            println!("<EMPTY>");
        } else {
            println!("{}", mat);
        }
    }

    pub fn report<F>(&self, is_garbage:&F) -> HeapReport
        where F : Fn(*const Blob) -> bool
    {
        let mut report = HeapReport {
            blobs: 0,
            blob_bytes: 0,
            frags: 0,
            frag_bytes: 0,
            available: self.available(),
            capacity: self.capacity
        };

        self.walk(&mut |blob| {
            if is_garbage(blob) || unsafe { (*blob).name() }.is_empty() {
                report.frags += 1;
                report.frag_bytes += unsafe { (*blob).len };
            } else {
                report.blobs += 1;
                report.blob_bytes += unsafe { (*blob).len };
            }
        } );

        report
    }

    pub fn info(&self) {
        unsafe {
            let boh_id = 1;
            let eoh_id = self.eoh - self.boh + 1;
            println!("heap::info[capacity:{} boh:{:x}/{} eoh:{:x}/{}]",
                     self.capacity,
                     self.boh,
                     boh_id,
                     self.eoh,
                     eoh_id);
            println!("heap::info[tail->{} head->{}]",
                     self.id_str((*self.meta).tail),
                     self.id_str((*self.meta).head));
        }
    }
}

#[cfg(test)]
mod tests {
    use ShampooCondition::{AllocationFailure, NoImmediateGarbage};

    use crate::heap::{Blob, Heap, Metadata};
    use crate::hash::Hash;
    use crate::shampoo::ShampooCondition;
    use crate::shampoo::ShampooCondition::Nothing;
    use crate::shmem::{inc_ptr, str, str_to_u64};

    #[test]
    fn test_allocate() {
        let mut ram = [0u8; 512];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        let blob1 = heap.allocates("blah", "BLAH").unwrap();
        unsafe { assert!(eq(4, (*blob1).magic.as_ptr(), "BLOB".as_ptr())) }
        unsafe { assert_eq!(56, (*blob1).len) }
        unsafe { assert_eq!(4, (*blob1).name_len) }
        unsafe { assert_eq!(4, (*blob1).data_len) }
        unsafe { assert_eq!("blah", (*blob1).name()) }
        unsafe { assert_eq!("BLAH".as_bytes(), (*blob1).data()) }

        let blob2 = heap.allocates("floped", "datalorder").unwrap();
        unsafe { assert!(eq(4, (*blob2).magic.as_ptr(), "BLOB".as_ptr())) }
        unsafe { assert_eq!(64, (*blob2).len) }
        unsafe { assert_eq!(6, (*blob2).name_len) }
        unsafe { assert_eq!(10, (*blob2).data_len) }
        unsafe { assert_eq!("floped", (*blob2).name()) }
        unsafe { assert_eq!("datalorder".as_bytes(), (*blob2).data()) }

        unsafe { assert_eq!(blob2 as u64, blob1 as u64 + (*blob1).len as u64) }
    }

    #[test]
    fn test_report() {
        let mut ram = [0u8; 512];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        let _blob1 = heap.allocates("blah", "BLAH").unwrap();
        let blob2 = heap.allocates("blop", "BLOP").unwrap();
        let _blob3 = heap.allocates("blarf", "BLxx").unwrap();

        let report_b = heap.report(&|_blob| false);
        assert_eq!(3, report_b.blobs);
        assert_eq!(0, report_b.frags);
        assert_eq!(176, report_b.blob_bytes);
        assert_eq!(0, report_b.frag_bytes);
        assert_eq!(488, report_b.capacity);
        assert_eq!(312, report_b.available);

        let report_b = heap.report(&|blob| blob == blob2.cast_const());
        assert_eq!(2, report_b.blobs);
        assert_eq!(1, report_b.frags);
        assert_eq!(120, report_b.blob_bytes);
        assert_eq!(56, report_b.frag_bytes);
        assert_eq!(488, report_b.capacity);
        assert_eq!(312, report_b.available);
    }

    #[test]
    fn test_init() {
        // if metadata changes we are stuffed  - change offset (8/16) below//
        assert_eq!(24, Metadata::size_of());

        let mut ram = [0u8; 512];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        assert_ne!(heap.boh, 0);
        assert_ne!(heap.eoh, 0);
        unsafe { assert_eq!(1, (*heap.meta).head); }
        unsafe { assert_eq!(1, (*heap.meta).tail); }

        // ensure underlying struct has changed
        let ram_ptr = ram.as_ptr() as *mut Blob;
        assert_eq!(heap.capacity, ram.len() - Metadata::size_of());
        assert_eq!(heap.meta, ram_ptr as *mut Metadata);
        assert_eq!(heap.boh as *mut Blob, inc_ptr(ram_ptr, Metadata::size_of()));
        assert_eq!(heap.eoh as *mut Blob, inc_ptr(ram_ptr, ram.len()));
        unsafe { assert!(eq(4, (*heap.meta).magic.as_ptr(), "HEAP".as_ptr())); }
        unsafe { assert_eq!(1, (*heap.meta).head); }
        unsafe { assert_eq!(1, (*heap.meta).tail); }

        unsafe { dbg!(ram.as_ptr().add(8)); }
        dbg!(heap.boh);

        // verify that underlying memory has changed too //
        assert_eq!(heap.meta.cast(), ram.as_mut_ptr());
        println!("mem_loc:{:x}", mem_loc(ram.as_ptr()));
        unsafe { println!("mem_loc(magic):{:x} {:x} -> {}",
                          mem_loc((*heap.meta).magic.as_ptr()),
                          mem_loc(ram.as_ptr()),
                          str(ram.as_mut_ptr(), 4)
        ); }
        unsafe { println!("mem_loc(head):{:x} {:x} -> {:?}",
                          mem_loc(&(*heap.meta).head),
                          mem_loc(ram.as_ptr().add(8)),
                          (*heap.meta).head
        ); }
        unsafe { println!("mem_loc(tail):{:x} {:x} -> {:?}",
                          mem_loc(&(*heap.meta).tail),
                          mem_loc(ram.as_ptr().add(16)),
                          (*heap.meta).tail
        ); }
        println!("mem_loc(boh):{:x} -> {:?}", mem_loc(&heap.boh), heap.boh);
        println!("mem_loc(eoh):{:x} -> {:?}", mem_loc(&heap.eoh), heap.eoh);

        // same memory locations. that proves it //
        unsafe { assert_eq!((*heap.meta).magic.as_ptr(), ram.as_ptr()); }
        unsafe { assert_eq!(mem_loc(&(*heap.meta).head), mem_loc(ram.as_ptr().add(8))); }
        unsafe { assert_eq!(mem_loc(&(*heap.meta).tail), mem_loc(ram.as_ptr().add(16))); }

        assert!(eq(4, ram_ptr as *const u8, "HEAP".as_ptr()));
        assert!(eq(4, ram.as_mut_ptr(), "HEAP".as_ptr()));
        unsafe { assert_eq!(*(ram.as_ptr().add(8) as *const u64), (*heap.meta).head); }
        unsafe { assert_eq!(*(ram.as_ptr().add(16) as *const u64), (*heap.meta).tail); }
    }

    #[test]
    fn test_init_sanity() {
        let mut ram = [0u8; 512];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        let meta = ram.as_mut_ptr() as *const Metadata;

        assert_eq!(heap.meta as u64, meta as u64);
        unsafe { assert_eq!("HEAP".as_bytes(), (*meta).magic); }
        assert_eq!(488, heap.capacity);
        assert_ne!(heap.boh, 0);
        unsafe { assert_eq!(1, (*meta).head); }
        unsafe { assert_eq!(1, (*meta).tail); }

        let heap2 = Heap::attach(ram.as_mut_ptr(), ram.len());
        assert_eq!(heap.capacity, heap2.capacity);
        assert_eq!(heap.meta, heap2.meta);
        assert_eq!(heap.boh, heap2.boh);
        assert_eq!(heap.eoh, heap2.eoh);
        unsafe { assert_eq!((*heap.meta).head, (*heap2.meta).head) }
    }

    #[test]
    fn test_find_block_scenario() {
        let mut ram = [0u8; 256];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        assert_eq!(232, heap.available());
        assert_eq!((1, 96), heap.find_block(96).unwrap());
        assert_eq!(136, heap.available());

        // allocate & absorb -> returned block bigger than requested
        assert_eq!((1 + 96, 136), heap.find_block(128).unwrap());
        assert_eq!(0, heap.available());

        // simulate gc (not yet implemented)
        assert!(heap.cas_tail(1, 97));
        assert_eq!(96, heap.available());

        // attempt - full!
        assert_eq!(Err(AllocationFailure), heap.find_block(128));

        // smaller block - ok!
        assert_eq!((233, 32), heap.find_block(32).unwrap());
        assert_eq!(64, heap.available());
        assert_eq!(Err(AllocationFailure), heap.find_block(128));
        assert_eq!((265, 64), heap.find_block(64).unwrap());

        assert_eq!(0, heap.available());
    }

    #[test]
    fn test_find_block_pending() {
        let mut ram = [0u8; 256];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        assert_eq!((1, 96), heap.find_block(96).unwrap());

        let blob = heap.rard(1);
        assert_eq!(str_to_u64("PEND"), unsafe { (*blob).magic() })
    }

    #[test]
    fn test_find_block_padding() {
        let mut ram = [0u8; 288];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        assert_eq!(264, heap.available());

        let b1 = heap.allocate("b1", &[0u8;40], false).unwrap();
        assert_eq!(96, unsafe { (*b1).len });
        assert_eq!(168, heap.available());

        let b2 = heap.allocate("b2", &[0u8;40], false).unwrap();
        assert_eq!(96, unsafe { (*b2).len });
        assert_eq!(72, heap.available());

        assert_eq!(unsafe { (*b2).id + (*b2).len as u64 }, unsafe { (*heap.meta).head });
        assert_eq!(Err(AllocationFailure), heap.allocate("b3", &[0u8;40], false));

        heap.print(&|_blob|true);

        assert_eq!(96, heap.gc_tail(&|_blob|true).unwrap());
        assert_eq!(72 + 96, heap.available());

        let b3 = heap.allocate("b3", &[0u8;40], false).unwrap();
        assert_eq!(96, unsafe { (*b3).len });
        assert_eq!(0, heap.available());
        assert_eq!(b1, b3);

        heap.print(&|_blob|true);

        let report = heap.report(&|_blob|false);
        println!("{}", report);
        assert_eq!(2, report.blobs);
        assert_eq!(1, report.frags);
        assert_eq!(72, report.frag_bytes); // padding at end, <96
    }

    #[test]
    fn test_paranioa_can_delete() {
        let mut ram = [0u8;128];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        // od(ram.as_mut_ptr(), ram.len());
        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(8) as *const u64)); }
        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(16) as *const u64)); }
        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(24) as *const u64)); }

        let md = ram.as_ptr() as *const Metadata;
        println!("boh = {:?}", heap.boh);
        assert_ne!(heap.boh, 0);
        unsafe { assert_eq!((*md).tail, 1); }
        unsafe { assert_eq!((*md).head, 1); }

        let block = heap.allocates("blah", "MY PRECIOUS DATA").unwrap();

        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(8) as *const u64)); }
        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(16) as *const u64)); }
        unsafe { println!("HEAP {:x}", *(ram.as_ptr().add(24) as *const u64)); }

        unsafe { assert_eq!((*md).tail, 1); }
        unsafe { assert_eq!((*md).head, 1 + (*block).len as u64); }

        println!("ready = {}", heap.available());
    }

    #[test]
    fn test_available() {
        let mut ram = [0u8; 160];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        assert_eq!(136, heap.available());

        assert_eq!(64, heap.find_block(64).unwrap().1);
        assert_eq!(72, heap.available());

        assert_eq!(72, heap.find_block(32).unwrap().1);
        assert_eq!(0, heap.available());

        assert!(heap.cas_tail(1, 65));
        assert_eq!(64, heap.available());

        assert_eq!((137, 32), heap.find_block(32).unwrap());
        assert_eq!(32, heap.available());

        assert!(heap.cas_tail(65, 65+40));
        assert_eq!(72, heap.available());
    }

    #[test]
    fn test_walk() {
        let mut ram = [0u8; 240];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());

        heap.walk(&mut |_blob| panic!());

        let blob1 = heap.allocate("blah", &[0u8;16], false).unwrap();
        let blob2 = heap.allocate("blop", &[0u8;16], false).unwrap();
        let blob3 = heap.allocate("blar", &[0u8;16], false).unwrap();

        heap.print(&|_blob| false);

        {
            let mut expected = vec![blob1, blob2, blob3];
            heap.walk(&mut|blob| assert_eq!(blob, expected.remove(0).cast_const()));
            assert!(expected.is_empty());
        }

        heap.gc_tail(&|_blob|true).unwrap();

        {
            let mut expected = vec![blob2, blob3];
            heap.walk(&mut |blob| assert_eq!(blob, expected.remove(0).cast_const()));
            assert!(expected.is_empty());
        }

        let blob4 = heap.allocate(&mut "blah", &[0u8;0], false).unwrap();

        {
            let mut expected = vec![blob2, blob3, blob4];
            heap.walk(&mut |blob| assert_eq!(blob, expected.remove(0).cast_const()));
            assert!(expected.is_empty());
        }

        heap.gc_tail(&|_blob| true).unwrap();

        {
            let mut expected = vec![blob3, blob4];
            heap.walk(&mut|blob| assert_eq!(blob, expected.remove(0).cast_const()));
            assert!(expected.is_empty());
        }

        let blob5 = heap.allocate("blah", &[0u8;0], false).unwrap();

        {
            let mut expected = vec![blob3, blob4, blob5];
            heap.walk(&mut|blob| assert_eq!(blob, expected.remove(0).cast_const()));
            assert!(expected.is_empty());
        }
    }

    #[test]
    fn test_walk_only_garbage() {
        let mut ram = [0u8; 216];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        heap.allocate("test1", &[3u8;12], false).unwrap();
        heap.allocate("test2", &[3u8;12], false).unwrap();
        heap.print(&|_blob| true);
    }

    #[test]
    fn test_gc_tail() {
        let mut ram = [0u8; 216];
        let heap = Heap::attach(ram.as_mut_ptr(), ram.len());
        assert_eq!(192, heap.available());
        assert_eq!(1, heap.load_tail());
        assert_eq!(Err(Nothing), heap.gc_tail(&|_blob|false));

        let _blob = heap.allocate("abc", &vec![], false).unwrap();
        assert_eq!(136, heap.available());
        assert_eq!(1, heap.load_tail());
        assert_eq!(Err(NoImmediateGarbage), heap.gc_tail(&|_blob|false));

        assert_eq!(Ok(56), heap.gc_tail(&|_blob|true));
        assert_eq!(192, heap.available());
        assert_eq!(57, heap.load_tail());
    }

    #[test]
    fn test_gc_run() {
        let mut hash_ram = [0u8; 216];
        let hash = Hash::attach(hash_ram.as_mut_ptr(), 32, true);

        let mut heap_ram = [0u8; 256];
        let heap = Heap::attach(heap_ram.as_mut_ptr(), heap_ram.len());

        assert_eq!(232, heap.available());
        assert_eq!(1, heap.load_tail());

        let is_garbage = &|id| !hash.references(id, |id| heap.rard(id));

        let re_add = &mut|old_blob:*const Blob| {
            let name = unsafe { (*old_blob).name() };
            let data = unsafe { (*old_blob).data() };
            let ascii = unsafe { (*old_blob).ascii };
            let blob = heap.allocate(&name, &data, ascii)?;
            hash.put(blob, &|id| heap.rard(id))?;
            Ok(())
        };

        let rard = &|id| heap.rard(id);

        assert_eq!(Ok(0), heap.gc_run(is_garbage, re_add));

        hash.put(heap.allocates("abc", "1").unwrap(), rard).unwrap();
        hash.put(heap.allocates("def", "2").unwrap(), rard).unwrap();
        hash.put(heap.allocates("def", "3").unwrap(), rard).unwrap();

        let report1 = heap.report(&|id| !hash.references(id, |id| heap.rard(id)));
        assert_eq!(1, report1.frags);
        assert_eq!(56, report1.frag_bytes);
        assert_eq!(2, report1.blobs);
        assert_eq!(112, report1.blob_bytes);
        assert_eq!(64, heap.available());
        assert_eq!(1, heap.load_tail());

        // check ids..
        assert_eq!(1, unsafe { (*hash.get("abc", rard).unwrap()).id });
        assert_eq!(1, heap.load_tail());
        assert_eq!(113, unsafe { (*hash.get("def", rard).unwrap()).id });

        assert_eq!(Ok(56), heap.gc_run(is_garbage, re_add));

        let report2 = heap.report(&|id| !hash.references(id, |id| heap.rard(id)));
        assert_eq!(0, report2.frags);
        assert_eq!(0, report2.frag_bytes);
        assert_eq!(2, report2.blobs);
        assert_eq!(120, report2.blob_bytes);
        assert_eq!(112, heap.available());
        assert_eq!(113, heap.load_tail());

        // check ids, abc is re-added, def not
        assert_eq!(113, unsafe { (*hash.get("def", rard).unwrap()).id });
        assert_eq!(113, heap.load_tail());
        assert_eq!(169, unsafe { (*hash.get("abc", rard).unwrap()).id });

        assert_eq!(Ok(0), heap.gc_run(is_garbage, re_add));
    }

    // back-compat
    fn mem_loc<T>(ptr:* const T) -> u64 {
        ptr as u64
    }

    fn eq(bytes:u32, p1: *const u8, p2: *const u8) -> bool {
        for i in 0..bytes {
            unsafe {
                if *p1.add(i as usize) != *p2.add(i as usize) {
                    return false;
                }
            }
        }
        return true;
    }
}
