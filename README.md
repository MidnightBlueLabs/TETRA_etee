# TETRA E2EE crypto

This repository contains previously secret cryptographic primitives and protocols regarding TETRA End-to-End Encryption (E2EE). 
Midnight Blue reverse-engineered the Sepura Embedded E2EE solution, which in turn is an implementation of the TCCA / SFPG recommendations outlining the TETRA E2EE protocol. A security analysis is published as part of our [2TETRA:2BURST](https://midnightblue.nl/2t2b) research. 

Implementations of the primitive E-functions are available, as well as the higher-level traffic encryption, SDS encryption and key sealing/unsealing functions that use those primitives. 

The AES-256, AES-128 and AES-56 algorithms are currently supported. 

### Using this library
Ensure you have libssl-dev installed, and use `make` to compile. 

Run `./tests` to validate basic functionality. 

Include `etee.h` for high-level functionality, or `etee_efuncs.h` for the E-primitives as defined in the TCCA specification.  
Link your project to `libtetraetee.a` for use in your own project. 

### Can I now break TETRA E2EE?
As a matter of principle, Midnight Blue does not publish weaponizable code. As such, no attack capability is present, and notably, the code in this repository is not suitable for exploiting CVE-2025-52940, CVE-2025-52941 or CVE-2025-52942. 

### I have questions
Please read [our page](https://midnightblue.nl/2t2b) for more information on the research. If you have further questions, be sure to reach out. 

## License
See `LICENSE`
