# shampoo
A serverless, high-performance data cache.

The orignal idea was something like redis but good. The project ignited when I realised 
it was possible to accomplish in a performant, serverless fashion by relying 
heavily on compare-and-swap (CAS) atomic operations and memory barriers whilst 
minimising copies by using shared memory. 

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
