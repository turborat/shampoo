# shampoo
A serverless, high-performance data cache. 

The orignal idea was something like redis but without TCP, then I realised it was 
probably possible to accomplish in a decentralized fashion by relying heavily on 
compare-and-swap atomic operations and memory barriers operating on shared memory. 
