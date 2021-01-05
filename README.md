# bsi_cypher

Authors:

    Dmytro Yurchenko

    Daryna Kovyrina

Algorithms:

    Advanced Encryption Standard
        AES is based on a design principle known as a substitution–permutation network, and is efficient in both software and hardware.

    Blowfish
        Blowfish is a symmetric-key block cipher, designed in 1993 by Bruce Schneier and included in many cipher suites and encryption products. Blowfish provides a good encryption rate in software and no effective cryptanalysis of it has been found to date.

    Data Encrytion Standard
        The Data Encryption Standard is a symmetric-key algorithm for the encryption of digital data.

Algorithms source:
    Crypto.Cipher package

Other resources:
    https://www.datacamp.com/community/tutorials/docstrings-python
    https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html

# Summary
    Encryption is the practice of scrambling information in a way that only someone with a corresponding key can unscramble and read it. 
    Encryption is a two-way function. When you encrypt something, you’re doing so with the intention of decrypting it later.  
    Today, the most common forms of encryption are:
    - Asymmetric Encryption – This is the Public Key example we just gave. 
    One key encrypts, the other key decrypts. The encryption only goes one way. 
    This is the concept that forms the foundation for PKI (public key infrastructure), which is the trust model that undergirds SSL/TLS.
    - Symmetric Encryption – This is closer to a form of private key encryption. Each party has its own key that can both encrypt and decrypt. As we discussed in the example above, after the asymmetric encryption that occurs in the SSL handshake, the browser and server communicate using the symmetric session key that is passed along.

    Hashing is the practice of using an algorithm to map data of any size to a fixed length. 
    This is called a hash value (or sometimes hash code or hash sums or even a hash digest if you’re feeling fancy). 
    Whereas encryption is a two-way function, hashing is a one-way function. 
    While it’s technically possible to reverse-hash something, the computing power required makes it unfeasible. Hashing is one-way.
    Common hashing algorithms:
    - MD5 – is another hashing algorithm made by Ray Rivest that is known to suffer vulnerabilities. It was created in 1992 as the successor to MD4. Currently MD6 is in the works, but as of 2009 Rivest had removed it from NIST consideration for SHA-3.
    - SHA – stands for Security Hashing Algorithm and it’s probably best known as the hashing algorithm used in most SSL/TLS cipher suites. A cipher suite is a collection of ciphers and algorithms that are used for SSL/TLS connections. SHA handles the hashing aspects. SHA-1, as we mentioned earlier, is now deprecated. SHA-2 is now mandatory. SHA-2 is sometimes known has SHA-256, though variants with longer bit lengths are also available.
    
    Salting is a concept that typically pertains to password hashing. Essentially, it’s a unique value that can be added to the end of the password to create a different hash value. 
    This adds a layer of security to the hashing process, specifically against brute force attacks. A brute force attack is where a computer or botnet attempt every possible combination of letters and numbers until the password is found.