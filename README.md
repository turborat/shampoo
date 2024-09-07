# shampoo
A serverless, high-performance data cache. 

The orignal idea was something like redis but without TCP, then I realised it was 
probably possible to accomplish in a decentralized fashion by relying heavily on 
compare-and-swap (CAS) atomic operations and memory barriers whilst minimising 
copies by using shared memory. 

To "subscibe" it spins on a pointer then when it moves gets it's data. No copying. 
Minimal operations. Minimal latency. 

There are two data structures in (shared) memory: a hash table and circular heap. The 
heap has two pointers - head and tail - that avoid locking via CAS. The head is
used to allocate from, the tail is the starting point for garbage collection. 

Other features:
* Handles data up to 4GB (only/sorry - i can change this lmk)
* Nifty text-mode heap & hash visualisation
* Abilty to monitor replicate in real-time
* Multiple garbage collection algorithms depending on use-case
* Fast as f
