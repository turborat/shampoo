# shampoo
A serverless, high-performance data cache. The name is an amalgamation of an 
implementation detail and my favorite breakfast. 

The orignal idea was something like redis but good. The project ignited when I realised 
it was possible to accomplish in a performant, serverless fashion by relying 
heavily on compare-and-swap (CAS) atomic operations and memory barriers whilst 
minimising copies by using shared memory. 

There are two data structures in (shared) memory: a hash table and circular heap. The 
heap has two pointers - head and tail - that avoid locking via CAS. The head is
used to allocate from, the tail is the starting point for garbage collection. The 
hash is a super simple open addressing lookup table atm. There is a concurrent garbage
collection process allowing key operations to remain fast.

Features
* Simple / flexible
* Minimal latency / high throughput
* Lock-free / highly concurrent
* O(1) scalability for all operations
* O(1) scalability wrt number of clients
* Nifty heap & hash visualisation tools
* Abilty to monitor, replicate, snapshot, etc. instantaneously.
* Multiple garbage collection algorithms depending on use-case
* Fast as f
