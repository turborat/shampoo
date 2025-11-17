use io::stdin;
use std::{env, io};
use std::io::{Read, Write};
use std::process::exit;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::time::Duration;

use crate::shampoo::{Shampoo, ShampooCondition};
use crate::shmem::str;
use crate::util::{mag_fmt, parse_int};

mod shampoo;
mod hash;
mod heap;
mod shmem;
mod util;
mod blob;

fn main() {
    let args:Vec<String> = env::args().collect();
    run(args);
}

pub fn run(mut args:Vec<String>) {
    if args.len() < 2 {
        usage();
    }

    if let Some(pos) = args.iter().position(|e| e == "-v") {
        shampoo::VERBOSE.store(true, Relaxed);
        shmem::ECHO.store(true, Relaxed);
        args.remove(pos);
    }

    match args[1].as_str() {
        "info" => {
            Shampoo::attach().info();
        }
        "init" => {
            if args.len() == 2 {
                let hash_size = Shampoo::check_path("/dev/shm/SHAMPOO.hash", true);
                let heap_size = Shampoo::check_path("/dev/shm/SHAMPOO.heap", true);
                Shampoo::init(hash_size as usize, heap_size as usize);
            }
            else if args.len() < 4 {
                die(-12, "required args: <hash-size> <heap-size>");
            }
            else {
                let hash_size= parse_int(&args[2]) as usize;
                let heap_size= parse_int(&args[3]) as usize;
                Shampoo::init(hash_size, heap_size);
            }
        }
        "put" => {
            if args.len() != 3 {
                die(-2, "one arg required: key");
            }

            let mut buf = Vec::new();
            stdin().read_to_end(&mut buf).unwrap();

            match Shampoo::attach().put(&args[2], &buf) {
                Ok(_) => println!("put {}", mag_fmt(buf.len() as u64)),
                Err(ShampooCondition::AllocationFailure) => die(-7, "AllocationFailure -- Forget to run gc??"),
                Err(err) => die(-8, &format!("{:?}", err))
            };
        }
        "get" => {
            if args.len() != 3 {
                die(-4, "get requires one arg: key");
            }
            match Shampoo::attach().get(args[2].as_str()) {
                None => eprintln!("<nothing>"),
                Some(data) => print!("{}", str(data.as_ptr(), data.len()))
            };
        },
        "heap"      => Shampoo::attach().show_heap(),
        "hash"      => Shampoo::attach().show_hash(),
        "show"      => Shampoo::attach().show_pairs(),
        "dump"      => Shampoo::dump(),
        "map"       => Shampoo::attach().map(),
        "gc" => {
            let shampoo = Shampoo::attach();
            if args.len() < 3 {
                shampoo.gc();
            }
            else {
                println!("shampoo::gc::loop starting");
                loop {
                    let sleepNs = (args[2].parse::<f64>().unwrap() * 1000000000.0) as u64;
                    shampoo.gc();
                    sleep(Duration::from_nanos(sleepNs));
                }
            }
        }
        "stress"   => {
            let shampoo = Shampoo::attach();
            let mut x = 0;
            let mut alloc_errs = 0;

            loop {
                match shampoo.put("abc", &format!("{}", x).as_bytes()) {
                    Ok(_) => {
                        if alloc_errs > 0 {
                            println!("{} times total -- GC anyone?", alloc_errs);
                            alloc_errs = 0;
                        }
                    }
                    Err(ShampooCondition::AllocationFailure) => {
                        alloc_errs += 1;
                        if alloc_errs == 1 {
                            print!("\rAllocation failure... ");
                            io::stdout().flush().unwrap();
                        }
                    },
                    Err(err) => die(-99, &format!("{:?}", err))
                };

                shampoo.validate();
                x += 1;
                // sleep(Duration::from_micros(100));
            }
        }
        _ => usage()
    }
}

fn usage() {
    let msg =  "try:  init [hash-size] [heap-size] (-v)
      put  [name]                  (-v)      store named data via <stdin>
      get  [name]                  (-v)      retrieve named data via <stdout>
      info                         (-v)      display infomercials
      heap                         (-v)      display heap
      hash                         (-v)      display hash
      show                         (-v)      show key / value pairs
      dump                         (-v)      dump raw heap data
      map                          (-v)      render heap map
      gc                           (-v)      start garbage collector\n";
    die(-1, msg);
}

fn die(code:i32, msg:&str) {
    eprintln!("{} (status={})", msg, code);
    exit(code);
}

