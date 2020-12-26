# SHA
Pure SHA-hashes (SHA1...SHA512,SHA3)

Based on:
Publication Number: FIPS 180-4
Title: Secure Hash Standard (SHS)
Publication Date: 08/2015

https://csrc.nist.gov/publications/detail/fips/180/4/final

SHA3 KECCAKp[1600,24] permutation

https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
https://keccak.team/files/Keccak-reference-3.0.pdf

http://incomsystems.biz/misc/doxygen/html/sha3_8c_source.html
https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c

Based on the implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
    Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
    denoted as "the implementer".
    
    For more information, feedback or questions, please refer to our websites:
    http://keccak.noekeon.org/
    http://keyak.noekeon.org/
    http://ketje.noekeon.org/
    	
Test Vectors 

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#sha3vsha3vss


$x=new SHA

$x->sha1($message);
$x->sha224($message);
$x->sha256($message);
$x->sha384($message);
$x->sha512($message);

$x->sha512t($message,$t);

$t=224,256...

$x->sha3("224",$message)
$x->sha3("256",$message)
$x->sha3("384",$message)
$x->sha3("512",$message)

$x->sha3("SHAKE128",$message)
$x->sha3("SHAKE256",$message)

@denobisipsis
