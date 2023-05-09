# AES

#AES.cpp

Here is where the main function is located. After running this file (that includes 4 headers mentioned below), you will be prompted to input a string of characters of size <buffer size>.
The code will run encryption and decryption sequentially to verify that the implementation is correct. The input message is printed at the beginning, as well as the padded messege, and decrypted messege (your original input).

-Dependencies:
AES.h
CNG.h
Padding.h
Cipher.h
  
////////////////////////////////////////////////////////

testing.cpp

This file cannot be run simultaneously with AES.cpp becuse it contines a main function as well. This cpp file with Cipher.h and AES.h headers should be run as astand alone Solution. After running testing.cpp, Monte carlo will be run on the code, initialised with the IV, Key, and message in the testing document linked on NIST (mentioned in the references). The output of our testing.cpp is to be compared to the test cases from the document, verifying ou results. 

For conveniance (document from NIST website):
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip

Dependencies:
Cipher.h
AES.h
  
///////////////////////////////////////////////////////


AES.h: Contains functions needed for AES encryption, the sbox, and the inverse sbox. Explained in the implementation section.
  
CNG.h: Contains the code for generating random key and IV using windows API.

padding.h: Function that pads input to multiples of 16.

Cipher.h: Contains the skeleton for encryption and decryption. this header file uses the functions in AES.h.






