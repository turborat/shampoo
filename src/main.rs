use io::stdin;
use std::{env, io, thread};
use std::io::Read;
use std::process::exit;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::time::Duration;

use crate::shampoo::{Shampoo, ShampooCondition};
use crate::shmem::{str};
use crate::util::mag_fmt;

mod shampoo;
mod hash;
mod heap;
mod shmem;
mod util;
mod blob;

fn main() {
    let args: Vec<String> = env::args().collect();
    run(args);
}

pub fn run(args: Vec<String>) {
    if args.len() < 2 {
        usage();
    }

    if args.contains(&"-v".to_string()) {
        shampoo::VERBOSE.store(true, Relaxed);
        shmem::ECHO.store(true, Relaxed);
    }

    match args[1].as_str() {
        "info" => {
            Shampoo::attach().info();
        }
        "init" => {
            if args.len() < 4 {
                die(-12, "required args: <hash-size> <heap-size>");
            }

            let hash_size:usize = args[2].parse().unwrap();
            let heap_size:usize = args[3].parse().unwrap();
            Shampoo::init(hash_size, heap_size);
        }
        "put" => {
            if args.len() < 3 {
                die(-2, "missing arg: key)");
            }

            let mut buf = Vec::new();
            if args.len() > 3 {
                buf.extend_from_slice(args[3].as_bytes());
            }
            else {
                stdin().read_to_end(&mut buf).unwrap();
            };

            match Shampoo::attach().put(&args[2], &buf) {
                Ok(_) => println!("put {}", mag_fmt(buf.len() as u64)),
                Err(ShampooCondition::AllocationFailure) => die(-7, "AllocationFailure -- Forget to run gc??"),
                Err(err) => die(-8, &format!("{:?}", err))
            };
        }
        "get" => {
            if args.len() < 3 {
                die(-4, "get requires an additional argument, key");
            }
            match Shampoo::attach().get(args[2].as_str()) {
                None => eprintln!("<nothing>"),
                Some(data) => println!("{}", str(data.as_ptr(), data.len()))
            };
        },
        "heap"      => Shampoo::attach().show_heap(),
        "hash"      => Shampoo::attach().show_hash(),
        "show"      => Shampoo::attach().show_pairs(),
        "dump"      => Shampoo::attach().dump(),
        "map"       => Shampoo::attach().map(),
        "gc" => {
            match Shampoo::attach().gc() {
                Err(err) => die(-6, &format!("{:?}", err)),
                _ => panic!("this should never happen")
            };
        }
        "stress"   => {
            let mut handles = vec![];
            for n in 0..1 {
                let name = format!("stress{}", n);
                println!("Spawning {}", name);
                let h = thread::Builder::new()
                    .name(name.clone())
                    .spawn(move || {
                        println!("thread {:?}", thread::current());
                        let shampoo = Shampoo::attach();
                        let mut x = 0;
                        loop {
                            match shampoo.put("abc", &format!("{}", x).as_bytes()) {
                                Ok(_) => {}
                                Err(ShampooCondition::AllocationFailure) => {
                                    println!("Alloc failure on {}", name);
                                },
                                Err(err) => die(-99, &format!("{:?}", err))
                            };
                            shampoo.validate();
                            x += 1;
                            sleep(Duration::from_millis(1));
                        }
                    }).unwrap();
                handles.push(h);
            }
            for h in handles {
                h.join().unwrap();
            }
            panic!("this should never happen");
        }
        _ => usage()
    }
}

fn usage() {
    let msg =  "try:  init [hash-size] [heap-size] (-v)
      put  [name]                  (-v)      add named data via <stdin>
      get  [name]                  <-v>      get named data
      info                         (-v)      display infomercials
      heap                         <-v>      display heap
      hash                         <-v>      display hash
      show                         <-v>      show key / value pairs
      dump                         <-v>      dump raw heap data
      map                          <-v>      render heap map
      gc                           <-v>      start garbage collector\n";
    die(-1, msg);
}

fn die(code:i32, msg:&str) {
    eprintln!("{} (status={})", msg, code);
    exit(code);
}

