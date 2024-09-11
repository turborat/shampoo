use env::var;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::io::Error;
use std::path::Path;
use std::process::exit;
use std::ptr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::time::{Duration};

use libc::{c_char, ftruncate, mmap, off_t, PROT_READ, shm_open, size_t, usleep};
use libc::{O_CREAT, O_EXCL, O_RDWR, S_IRUSR, S_IWUSR};
use libc::{MAP_SHARED, PROT_WRITE};

use crate::blob::Blob;
use crate::die;
use crate::heap::Heap;
use crate::hash::Hash;
 use crate::util::{Matrix};
use crate::util::puts;

pub static VERBOSE:AtomicBool = AtomicBool::new(false);

#[derive(PartialEq)]
#[derive(Debug)]
pub enum ShampooCondition {
    AllocationFailure,
    BucketCollision,
    EndOfSegment,
    NoImmediateGarbage,
    CASMiss,
    Nothing
}

pub struct Shampoo {
    pub heap: Heap,
    pub hash: Hash
}

impl Shampoo {
    pub fn attach() -> Self {
        let hash_size = Shampoo::check_path("/dev/shm/SHAMPOO.hash");
        let hash_base = attach("SHAMPOO.hash", hash_size as size_t, false);
        let hash = Hash::attach(hash_base, hash_size);

        let heap_size = Shampoo::check_path("/dev/shm/SHAMPOO.heap");
        let heap_base = attach("SHAMPOO.heap", heap_size as size_t, false);
        let heap = Heap::attach(heap_base, heap_size);

        Shampoo { heap, hash }
    }

    pub fn init(hash_size:usize, heap_size:usize) {
        println!("usize::MAX:{}", usize::MAX);

        let hash_base = attach("SHAMPOO.hash", hash_size, true);
        Hash::init(hash_base, hash_size);

        let heap_base = attach("SHAMPOO.heap", heap_size, true);
        Heap::init(heap_base, heap_size);
    }

    fn check_path(fname:&str) -> u64 {
        let path = Path::new(fname);
        if !path.exists() {
            die(-10, "shared memory not initialized. -- try: shampoo init <hash_size> <heap_size>");
        }
        std::fs::metadata(path).unwrap().len()
    }

    fn is_garbage(&self, blob:*const Blob) -> bool {
        !self.hash.references(blob, &|id| self.heap.rard(id))
    }

    fn rard(&self, id:u64) -> *const Blob {
        self.heap.rard(id)
    }

    fn _put(&self, name:&str, data:&[u8], ascii:bool) -> Result<(), ShampooCondition> {
        let blob = self.heap.allocate(name, data, ascii)?;
        self.hash.put(blob, &|id|self.rard(id))?;
        Ok(())
    }

    pub fn put(&self, name:&str, data:&[u8]) -> Result<(), ShampooCondition> {
        self._put(name, data, false)
    }

    pub fn puts(&self, name:&str, txt:&str) -> Result<(), ShampooCondition> {
        self._put(name, txt.as_bytes(), true)
    }

    pub fn get(&self, name:&str) -> Option<Vec<u8>> {
        let blob = self.hash.get(name, |id| self.rard(id))?;
        let data = unsafe { (*blob).data() };
        Some(data)
    }

    pub fn info(&self) {
        println!("{:?}", &self.hash.report(&|id| self.rard(id)));
        println!("{}", &self.heap.report(&|blob|self.is_garbage(blob)));
        self.heap.info();

    }

    pub fn show_hash(&self) {
        println!("{:?}", &self.hash.report(&|id| self.rard(id)));
        self.hash.print(|id| self.rard(id));
    }

    pub fn show_heap(&self) {
        println!("{}", self.heap.report(&|blob|self.is_garbage(blob)));
        if VERBOSE.load(Relaxed) {
            self.heap.info();
        }
        self.heap.print(&|blob|self.is_garbage(blob));
    }

    pub fn show_pairs(&self) {
        let mut mat = Matrix::new();
        self.heap.walk(&mut |blob:*const Blob| {
            unsafe {
                if !self.is_garbage(blob) {
                    mat.add(&(*blob).name());
                    mat.add(&":");
                    mat.add(&(*blob).data_view());
                    mat.nl();
                }
            }
        });
        println!("{}", mat);
    }

    pub fn dump(&self) {
        let head = self.heap.load_head();
        let end = if head >= self.heap.capacity as u64 {
            self.heap.eoh
        }
        else {
            self.rard(head) as u64
        };
        let mut addr = self.heap.boh;

        while addr < end {
            let blob = addr as *const Blob;
            print!("@{:x} ", blob as u64);
            unsafe { print!("{:?}\n", (*blob)) };
            // puts(format!("{} = ", unsafe { (*blob).name() }));
            // puts(format!("{}\n",  unsafe { (*blob).data_view() }));
            addr += unsafe { (*blob).len } as u64;
        }
    }

    pub fn gc(&self) -> Result<(), ShampooCondition> {
        println!("shampoo::gc::loop starting");
        loop {
            match self.heap.gc_run(
                &mut|blob| self.is_garbage(blob),
                &mut|blob| unsafe {
                    self._put(&(*blob).name(), &(*blob).data(), (*blob).ascii)
                }
            ) {
                Ok(_) => sleep(Duration::from_micros(100)),
                Err(err) => die(-6, &format!("{:?}", err))
            };
        }
    }

    pub fn validate(&self) {
        self.heap.validate();
    }

    pub fn map(&self) {
       let length: usize = var("LINES").unwrap().parse::<usize>().unwrap() -5;
       let width: usize = var("COLUMNS").unwrap().parse::<usize>().unwrap() -2;
       let mut grid = vec!['.';length*width];

       let project = |pt:u64| {
           let range1 = (self.heap.eoh - self.heap.boh) as f32;
           let range2 = (length * width) as f32;
           ((pt - self.heap.boh) as f32 / range1 * range2) as u64
       };

       let mut num = 0;
       let mut nums: HashMap<String, u32> = HashMap::new();

        self.heap.walk(&mut |blob:*const Blob| {
           let start = project(blob as u64);
           let end = project(blob as u64 + unsafe { (*blob).len } as u64);
           let garbage_offset = if self.is_garbage(blob) { 32 } else { 0 };

           let chr = if let Some(num) = nums.get( &unsafe { (*blob).name() }) {
               char::from_u32('A' as u32 + num + garbage_offset)
           }
           else {
               let my_num = num;
               nums.insert(unsafe { (*blob).name() }, num);
               num += 1;
               if num > 'Z' as u32 - 'A' as u32  {
                   num = 0;
               }
               char::from_u32('A' as u32 + my_num + garbage_offset)
           }.unwrap();

           for i in start..end {
                grid[i as usize] = chr;
           }
       });

       for i in 0..grid.len() {
           if 0 < i && i % width == 0 {
               println!();
           }
           print!("{}", grid[i]);
       }
       println!();
    }
}

fn attach(name:&str, size: size_t, create:bool) -> *mut u8 {
    let c_string = CString::new(name.as_bytes()).expect("cvt!");
    let c_char_ptr: *const c_char = c_string.as_ptr();
    let oflags = if create { O_CREAT | O_EXCL | O_RDWR } else { O_RDWR };

    return unsafe {
        let fh = shm_open(c_char_ptr, oflags, S_IRUSR | S_IWUSR);

        if fh == 0 {
            panic!("shmem::attach::shm_open failed: {:?}", Error::last_os_error());
        }

        let _ = ftruncate(fh, size as off_t);

        let addr = mmap(
            ptr::null_mut(), size,
                        PROT_WRITE | PROT_READ,
                        MAP_SHARED, fh, 0);

        if addr as i64 == -1 {
            panic!("shmem::attach::mmap failed: {:?}", Error::last_os_error());
        }

        // todo: close file descriptor once region is mapped //
        // todo: delete region upon exit - munmap() //

        if create {
            println!("Initialized shared memory segment {} @{:x} ({} bytes)", name, addr as u64, size);
        }
        else {
            puts(format!("shmem::attach::created segment {} @{:x} ({} bytes)", name, addr as u64, size));
        }

        addr as *mut u8
    };
}



