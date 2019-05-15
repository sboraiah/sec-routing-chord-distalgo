# Implementing secure routing in Chord in DistAlgo

## Problem Statement 
The project aims at implementing an extension to traditional chord protocol to support secure
routing techniques as proposed by the paper[1], Secure routing for structured peer-to-peer overlay
network and compare the performance against the existing chord implementation.

## Running the program

```
python -m da main.da 1 chord
python -m da main.da 1 secchord
```

## Files

- main.da is the driver program that spawns chord and secure chord nodes and tests and evaluates them.  
- chord.da is the baseline chord that we modified to work with latest DistAlgo.  
- secure\_chord.da is the secured chord protocol that we have fixed over the baseline implementation.  
- certificate\_authority.da defines the certificate authority process required for secure nodeId generation.  
- crypto\_utils.py has the crypto APIs that we use in secure chord implementation.

other-chords directory has the other implementations of chord that we found.

1. First Version of Code is taken from [here](https://bitbucket.org/toponado/chord-distalgo). <br />
Author: youlong cheng <br />
Repository Url: https://bitbucket.org/toponado/chord-distalgo

2. Version of chord we found from [this](https://github.com/soumyadeep2007/dns_chord) source. <br /> This is an incomplete implementation, but decided to included it anyway.
Author: Soumyadeep <br />
Repository Url : https://github.com/soumyadeep2007/dns\_chord  

3. The best implementation of Chord shared by the professor from [here](https://github.com/unicomputing/chord-distalgo-2013-Sourabh-Yerfule). <br />
Repository Url: https://github.com/unicomputing/chord-distalgo-2013-Sourabh-Yerfule

4. The code base that our work is based upon was taken from [here](https://github.com/ChidambaramR/Asynchronous-Systems/). <br />. He too developed the base from Sourabh Yerefule's codebase(he has acknowledged him in the report [here](https://github.com/ChidambaramR/Asynchronous-Systems/blob/master/AsyncReport_Chidambaram.pdf)), trimmed down the uncecessary parts.

## References
1. Ayalvadi Ganesh Antony Rowstron Miguel Castro1, Peter Druschel and Dan S. Wallach. Secure
routing for structured peer-to-peer overlay networks. Usenix Symposium on Operating Systems Design and Implementation, Boston, MA, 2002.
https://people.mpi-sws.org/~druschel/publications/security.pdf .

2. Keith Needels Minseok Kwon. Secure Routing in Peer-to-Peer Distributed Hash Tables. RIT
Scholar Works, 2009.
http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.879.8892&rep=rep1&type=pdf


