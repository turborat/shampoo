# shampoo
A serverless, high-performance data cache. The name is an amalgamation of an 
implementation detail and my favorite breakfast. 

The orignal idea was something like redis but without TCP, then I realised it was 
possible to accomplish in a decentralized fashion by relying heavily on 
compare-and-swap (CAS) atomic operations and memory barriers whilst minimising 
copies by using shared memory for IPC. 

There are two data structures in (shared) memory: a hash table and circular heap. The 
heap has two pointers - head and tail - that avoid locking via CAS. The head is
used to allocate from, the tail is the starting point for garbage collection. The 
hash is a super simple simple open addressing lookup table that I'm happy to accept 
improvements to.

For subscibe semantics one spins on a pointer then deferences it. No copying. 
Compact memory. Minimal operations. Minimal latency. Damn high thoughput.

Other features:
* Handles data up to 4GB (only/sorry - i can change this lmk)
* Lock-free / highly concurrent
* O(1) scalability for all operations
* O(1) scalability wrt number of clients
* Nifty heap & hash visualisation tools
* Abilty to monitor, replicate, snapshot, etc. instantaneously.
* Multiple garbage collection algorithms depending on use-case
* Fast as f
