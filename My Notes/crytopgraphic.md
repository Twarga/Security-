------------------------------------- Cryptography------------------------
# 1- Cryptography Basics :
## Definitions :
1. Cryptography: The practice and study of techniques for securing communication and data from unauthorized access and ensuring confidentiality, integrity, and authenticity.
2. Encryption: The process of converting plain text into cipher text using an algorithm and a key.
3. Decryption : The process of converting cipher text back into plain text using an algorithm and a key.
4. Cipher : An algorithm for performing encryption or decryption.
5. Key: A piece of information used in a cryptographic algorith to perform encryption and decryption.
6. Plaintext: The original , readable message or data that is fed into the encryption process.
7. Ciphertext : The orginal, readable message or data that is fed into the encryption process.
8. Symmetric Crypthography : Uses the same key for both encryption and decryption.
9. Asymmetric Crytography : Uses a pair of keys - a public key for encryption and a private key for decryption.
10. Hash Function : A function that converts input data of any size into a fixed size string of characters, which is typically a digest that represents the input.

## Basic of how Cryptography works :
1. Symmetric Crypthography:
    - Algorithm: A specific procedure followed for encryption and decryption.
    - Key : A secret key know only the sender and receiver.
    - Process :
        - Encryption : Plaintext + Key = Ciphertext
        - Decryption : Ciphertext + key = Plaintext
    - Example :
        - Algorithm: Advanced Encryption Standard (AES)
        - Key : A 256-bit string
        - Encryption Process : Converts plaintext into ciphertext using the AES algorithm and the key.
        - Decryption Process : Converts ciphertext back into plaintext using the same AES algorith and the key.

2. Asymmetric Crypthography:
    - Algorithm : A specific procedure folowed for encryption and decryption using two keys.
    - Keys : Public key (Known to everyone) and Private Key (know only to owner).

    - Process :
        - Encryption : Plaintext + Public Key = Ciphertext
        - Decryption: Ciphertext + Private Key = Plaintext

    - Example :
        - Algorithm : RSA (Rivest-shamir-Adleman)
        - Public Key : Used to encrypt data
        - Private Key : Used to decrypt data

3. Hash Functions:
    - Algorithm: A procedure that converts input data into a fixed-size string of characters.

    - Process :
        - Input : Data of any size
        - Output : Fixed-size hash value

    - Example:
        - Algorithm : SHA-256 (Secure Hash Algorithm 256-bit)
        - Process: Converts input data into a 256-bit hash value

## History of Crypthography:
1. Ancient Cryptography:
    - Ceasar Cipher (50 BC): A substituation Cipher used by julius caesar where each letter in the plaintext is shifted a certain number of places down the alphabet.
    - Scytale (Ancient Greece) : A tool used to perform a transposition cipher.

2. Medieval Cryptography:
    - Vigenère Cipher (1553) : A method of encrypting text by using a series of different Caesar ciphers based on the letters of a keyword.

3. Modern Cryptography:
    - Enigma Machine (World War II ) : An elctro-mechanical rotor cipher machine used by Nazis Germany, which was famously cracked by Alan Turing and his team.
    - DES (Data Encryption Standard ) (1970s) : A symmetric-Key algorithm for the encryption of election data.

    - RSA Algorithm (1977) : An asymmetric cryptographic algorithm that uses a pair of keys for encryption and decryption.



## Attacks Cryptoanalysis
1. Brute Force Attack :
    - Description : Trying all possible keys until the correct one is found.
    - Defense : Use long and complex keys.

2. Dectionary Attack:
    - Description: Using a precomputed list of potential keys or passwords.
    - Defense : Use complex , unpredicatble passwords and salt (random data) in hashing

3. Man-in-the-Middle Attack (MitM):
    - Description : Intercepting and possibly altering communication between two parties.
    - Defense : Use strong encryption protocols like TLS/SSL

4. Side-Channel Attack:
    - Description : Exploiting Physical implementation features like timing information , power consumption , or electromagnetic leaks.
    - Defense : Implement physical security measures and secure coding practices.
5. Cryptanalysis Techniques:
    - Cipertext-only Attack : Attackers has access only to the ciphertext.
    - Known-plaintext Attack: Attacker has access to both the plaintext and its corresponding ciphertext.
    - Chosen-plaintext Attack: Attacker can choose arbitary plaintext to be encrypted and obtain the corresponding ciphertexts.
    - Chosen-ciphertext Attack : Attacker can choose arbitary ciphertexts to be decrypted and obtain the corresponding plaintexts.

# 2- Symmetric and Asymmetric Algorithms :
## Symmetric
Symmetric algorithms use the same key for both encryption and decryption. They are also known as secret key algorithms.
- Examples :
    - AES (Advanced Encryption Standard)
    - DES (Data Encryption Standard)
    - 3DES (Triple DES)
    - RC4 (Rivest Cipher 4 )

### Polyalphabetic
A polyalphabetic cipher is a type of substitution cipher that uses multiple substitution alphabets to encrypt the data.

- Examples :
    - Vigenère Cipher: Uses a keyword to shift the letters of the plaintext through multiple alphabets.
- How it works :
    - Plaintext : HELLO
    - Key : KEY
    - Ciphertext: RIJVS
- Process:
    - The first letter of the plaintext (H) is shifted by the position of the first letter of the key (K) in the alphabet.
    - THe process is repeated for each better in the plaintext using the corresponding letter in the key.
### Advantages of Symmetric Alogrithm
1. Speed:
    - Symmetric algorithms are generally faster than asymmetric algorithms because they use simpler mathematical operations.
2. Efficiency :
    - Requires less computational power, making them suistable for encrypting large amounts of data.
3. Simplicity :
    - The same key is used for both encryption and decryption, simplifying the encryption process.
### Disadvantages of Symmetric Algorithm
1. Key Distribution:
    The same key must be shared securely between the sender and receiver, which can be challenging.
2. Scalability:
    Requires a unique key for each pair of users, leading to a large number of keys in a large network.
3. Key Management:
    Managing and securely storing keys can be difficult, especially as the number of keys increases.
## Asymmetric
    Asymmetric algorithms use a pair of keys: a public key for encryption and a private key for decryption. They are also known as public key algorithms.

- Examples:
    - RSA (Rivest-Shamir Adleman)
    - ECC (Elliptic Curve Cryptography)
    - DSA (Digital Signature Algorithm)



### Public and  Private key
- Public Key:

    - What: A key that is distributed publicly and used for encryption.
    - How: Anyone can use the public key to encrypt a message, but only the corresponding private key can decrypt it.
- Private Key:

    - What: A key that is kept secret and used for decryption.
    - How: Only the owner of the private key can decrypt messages encrypted with the corresponding public key.

Example:
    - Public Key: Used to encrypt a message.
    - Private Key: Used to decrypt the message.

### Advantages of Symmetric Algorithm
1. Secure Key Distribution:
No need to share the private key, eliminating the key distribution problem of symmetric algorithms.

2. Digital Signatures:
Asymmetric algorithms can be used for digital signatures, providing authentication and non-repudiation.

3. Scalability:
Only requires one pair of keys per user, simplifying key management in large networks.
### Disadvantages of Symmetric Algorithm
1. Speed:
Asymmetric algorithms are generally slower than symmetric algorithms due to complex mathematical operations.

2. Computational Overhead:
Requires more computational power, making them less efficient for encrypting large amounts of data.

3. Key Size:
Asymmetric keys are typically larger than symmetric keys, leading to increased storage and transmission requirements.

# 3- How Random Number Generators works ?
Random number generators (RNGs) are algorithms or devices designed to produce a sequence of numbers that lack any pattern or predictability. They are crucial for various applications in computing, cryptography, simulations, and more.
## Types of Random Number Generators:
1. True Random Number Generators (TRNGs):
    - Definition: Generate numbers based on physical processes.
    - Sources: Utilizes unpredictable physical phenomena, such as radioactive decay, thermal noise, or atmospheric noise.
    - Characteristics:
        - Truly random and unpredictable.
        - Often slower and require specialized hardware


2. Pseudo-Random Number Generators (PRNGs):
    - Definition: Use deterministic algorithms to produce sequences of numbers that appear random.
    - Algorithm: Starts with a seed value and applies a mathematical formula to produce a sequence.
    - Characteristics:
    - Not truly random; can be reproduced if the seed and                   algorithm are known.
    - Faster and widely used in software applications.

## How True Random Number Generators (TRNGs) Work :
1. physical Process Observation :
    - Measures physical phenomenathat are inherently random, such as radiocative decay , thermal noise, or photon emission.

2. Data Collection :
    - Collects data from the physical source. For example, in the case of thermal noise, it measures the electrical noise in a resistor.

3. Digitization :
    - Converts the analog signals from the physical source into digital values.
4. Post-Processing :
    - Applies alforithms to refine the raw data, ensuring it meets the desired statistical properties of randomness.

## How Pseudo-Random Number Generators (PRNgs) Work :
1. Initialization with a Seed :
    - Start with an intial value know as the seed wich can be a fixed value or derived from a variable input like the current time.

2. Mathematical Formula Application :
    - Applies a deterministic algorithm to generate a sequence of numbers from the seed. Common algorithms include Linear Congryential Generator (LCG) and Mersenne Twister.

    Example : Linear Congruential Generator (LCG):
    - Formula X n+1 ​ = (aX n ​ +c) mod m
    - Components:
        - Xn : Current Number in the sequence.
        - a: Multiplier
        - c : Increment
        - m : Modulus.
3. Sequence Generation :
    - Continuously applies the algorithm to produce a sequence of pseudo-random numbers.

4. Periodicity :
    - PRNGs have a period after which the sequence repeats. The length of the period depends on the algorithm and parameters used.

## Applications of Random Number Generators :
1. Cryptography :
    - Use : Generate Keys, intialization vectorsm and nonces.
    - Requirement : High unpredictability and entropy to ensure security.

2. Simulations :
    - Use: Model complex systems in fields like finance, physics , and biology.
    - Requirement : Large quantities of random number with good statistical properties.

3. Gaming :
    - Use : Generate random events, such as shuffling cards or rolling dice.
    - Requirement: Fairness and unpredictability to ensure an unbiased gaming experience.

4. Statistical Sampling:
    - Use: Select random samples from a population for surveys and experiments.
    - Requirement : True randomness to avoid bias in the sample selection.

## Challenges and Considerations :
1. Seed Selection :
    - A poorly chosen seed can compromise the randomness of the PRNG.
    - In cryptographic applications , seeds should be generated from high-entropy sources.
2. Entropy:
    - The amount of randomness collected from the environment in TRNGs
    - High entropy sources are crucial for generating truly random numbers.

3. Bias and Correlation:
    - RNGs should produce numbers that are free from bias and correlation.
    - Post-processing and statistical tests can help identify and correct biases.

4. Security:
    - In cryptographic applications, the predictability of PRNGs can lead to vulnerabilities.
    - TRNGs or cryptographically secure PRNGs (CSPRNGs) are preferred for high-security requirements.

# 4- Modular Arithmetic and Modulus Function

# 5- DES and AES : Steam Block Cipher

# 6- Number Theory : Finite Fields and Cyclic Groups

# 7- Encryption and Decryption explained

# 8- Deffie-Hellman Details of Elliptic: Curve Cryptography

# 9- Details of Elliptic: Curve Cryptography

# 10- Elliptic Curve Digital Signature Algorithm ESCDSA

# 11- Hash Functions explained

# 12- How do you get from a private key to a Bitcoin address

# 13- How do Hierarchical Deterministic Wallets work

# 14 - How does a Bitcoin transaction work in detail

# 15 - Bitcoin Mining Explained in detail

# 16 : Will Quantum   Computer kill Bitcoin ?

