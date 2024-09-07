# shampoo
A serverless, high-performance data cache. 

The orignal idea was something like redis but without TCP, then I realised it was 
probably possible to accomplish in a decentralized fashion by relying heavily on 
compare-and-swap (CAS) atomic operations and memory barriers operating on shared memory. 

There are two data structures in shared memory: a hash table and circular heap. The 
heap has two pointers, head and tail, that are only modified using CAS. The head is
used to allocate from, the tail is the starting point for garbage collection. 

Other features:
* Nifty text-mode heap & hash visualisation
* Abilty to replicate in real-time
* Deterministic...
* Fast as f



