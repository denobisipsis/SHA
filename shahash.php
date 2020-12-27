<?
/*
Publication Number: FIPS 180-4
Title: Secure Hash Standard (SHS)
Publication Date: 08/2015

https://csrc.nist.gov/publications/detail/fips/180/4/final

SHA3

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
*/
class SHA
{		
    function ROTL($n, $x, $bits=32)
    	{return (($x << $n) | ($x >> $bits - $n));}

    function Parity($x, $y, $z)
    	{return $x ^ $y ^ $z;}
	
    function SHR($n, $x)
    	{return gmp_div($x , gmp_pow(2,$n));}
	  
    function ROTR($n, $x, $bits)
    	{return gmp_or(gmp_div($x , gmp_pow(2,$n)) , gmp_mul($x ,gmp_pow (2, $bits - $n)));}
		
    function Ch($x,$y,$z)
    	{return ($x & $y) ^ ((~$x) & $z);}

    function Maj($x,$y,$z)
    	{return ($x & $y) ^ ($x & $z) ^ ($y & $z);}
		
    function sum($x,$a,$b,$c,$bits=32)
    	{return $this->ROTR($a,$x,$bits) ^ ($this->ROTR($b,$x,$bits) ^ $this->ROTR($c,$x,$bits)); }

    function s($x,$a,$b,$c,$bits=32)
    	{return $this->ROTR($a,$x,$bits) ^ ($this->ROTR($b,$x,$bits) ^ $this->SHR($c,$x));}
	    		
    function padding($stream,$sha)
    	{
	/*	
	Suppose that the length of the message, M, is L bits. 
	
	SHA-1, SHA-224 and SHA-256
	
	Append the bit “1” to the end of the
	message, followed by k zero bits, where k is the smallest, non-negative solution to the equation
	L +1+ k = 448mod512 . Then append the 64-bit block that is equal to the number L expressed
	using a binary representation
	
	SHA-384, SHA-512, SHA-512/224 and SHA-512/256
	
	Append the bit “1” to the end of the
	message, followed by k zero bits, where k is the smallest non-negative solution to the equation
	L +1+ k = 896mod1024. Then append the 128-bit block that is equal to the number L expressed
	using a binary representation
	*/
	
	$l      = strlen($stream);	
    	$stream = bin2hex($stream)."80";	
	$fill   = 16 - (($l+1)*2) % 16;	
	if ($fill==16) $fill=0;
	
	$stream.= str_repeat("0",$fill);
	   
	/*
	For SHA-1, SHA-224 and SHA-256, each message block has 512 bits, which are
	represented as a sequence of sixteen 32-bit words.
	
	For SHA-384, SHA-512, SHA-512/224 and SHA-512/256 each message block
	has 1024 bits, which are represented as a sequence of sixteen 64-bit words
	*/ 
	
	if ($sha==1)
		$stream = array_values(unpack("N*",pack("H*",$stream)));
	else
		{
		$stream = array_values(unpack("J*",pack("H*",$stream)));
		foreach ($stream as &$s) $s&=$this->MASK;		
		}
	
	$fill = 16 - (sizeof($stream)+1) % 16;
	if ($fill==0) $fill=16;

	while ($fill--)
		$stream []= 0;
		
	$stream[] = $l*8;

        return $stream;
	}

    function prepare($stream,$sha)
    	{
	if (hexdec(bin2hex($stream))==0) 
		$stream="";
		
	$stream   = $this->padding($stream,$sha);      
        $n_blocks = $n = ceil(sizeof($stream) / 16);
	
	$M = array();
        while ($n_blocks)  	    
	    $M []=array_slice($stream, ($n-$n_blocks--)*16,16);
	    	
        return $M;
	}
	    		
    function process_block_1($block)
    	{
        for ($t = 16;$t < 80;$t++)
            $block []=$this->ROTL(1, $block[$t-3] ^ $block[$t-8] ^ $block[$t-14] ^ $block[$t-16]) & $this->MASK;

        [$a, $b, $c, $d, $e] = $this->H1;
	
	$K = array("0x5a827999","0x6ed9eba1","0x8f1bbcdc","0xca62c1d6");
	
        for ($t = 0;$t < 80;$t++)
	    {
	    switch (($case=floor($t / 20)))
	    	{
		 case 0:  	$f = $this->Ch($b,$c,$d); break;
		 case 1:	$f = $this->Parity($b,$c,$d); break;
		 case 2:	$f = $this->Maj($b,$c,$d);break;
		 default:	$f = $this->Parity($b,$c,$d); break;		    
		}
		
            $T = ($this->ROTL(5, $a) + $f + $e + gmp_init($K[$case]) + gmp_init("$block[$t]")) & $this->MASK;
            $e = $d;
            $d = $c;
            $c = $this->ROTL(30, $b) & $this->MASK;
            $b = $a;
            $a = $T;
	    }

	for ($k=0;$k<5;$k++)
		$this->H1[$k]=(${chr($k+97)}+$this->H1[$k]) & $this->MASK;
	}
						
    function process_block_256($block)
    	{	
        for ($t = 16;$t < 64;$t++)
            $block []=($this->s($block[$t-2],17,19,10) + $block[$t-7] +  
	    	$this->s($block[$t-15],7,18,3) + $block[$t-16]) & $this->MASK;

        [$a, $b, $c, $d, $e, $f, $g, $h] = $this->H256;
				
        for ($t = 0;$t < 64;$t++)
	    {		
            $T1 = ($this->sum($e,6,11,25) + $this->Ch($e,$f,$g) + $h + $this->K[$t] + gmp_init("$block[$t]"));
	    $T2 = ($this->sum($a,2,13,22) + $this->Maj($a,$b,$c));
	    $h = $g;
	    $g = $f;
	    $f = $e;
	    $e = ($d + $T1) & $this->MASK;
	    $d = $c;
	    $c = $b;
	    $b = $a;
	    $a = ($T1 + $T2) & $this->MASK;	    
	    }

	for ($k=0;$k<8;$k++)
		$this->H256[$k]=(${chr($k+97)}+$this->H256[$k]) & $this->MASK;
	}
				
    function process_block_512($block)
    	{
        for ($t = 16;$t < 80;$t++)	    
	    $block[]=($this->s($block[$t-2],19,61,6,64) + $block[$t-7] +  
	    	$this->s($block[$t-15],1,8,7,64) + $block[$t-16]) & $this->MASK;	    
	    	
        [$a, $b, $c, $d, $e, $f, $g, $h] = $this->H512;
			    	
        for ($t = 0;$t < 80;$t++)
	    {		
            $t1 = $this->sum($e,14,18,41,64) + $this->Ch($e,$f,$g) + $h + $this->K[$t] + gmp_init("$block[$t]") ;
	    $t2 = $this->sum($a,28,34,39,64) + $this->Maj($a,$b,$c);
	    	    
	    $h = $g;
	    $g = $f;
	    $f = $e;
	    $e = ($d + $t1) & $this->MASK;
	    $d = $c;
	    $c = $b;
	    $b = $a;
	    $a = ($t1 + $t2) & $this->MASK;
	    }

	for ($k=0;$k<8;$k++)
		$this->H512[$k] = (${chr($k+97)}+$this->H512[$k]) & $this->MASK;	
	}
	
    function sha1($stream)
	{      
	$this->H1   = ["0x67452301","0xEFCDAB89","0x98BADCFE","0x10325476","0xC3D2E1F0"];
	
	for ($k=0;$k<5;$k++)
		$this->H1[$k] = gmp_init($this->H1[$k]);
		
	$this->MASK = gmp_init("0xFFFFFFFF");   
        $stream = $this->prepare($stream,1);
		
        foreach ($stream as $block)
        	$this->process_block_1($block);
	
	$sha1="";foreach ($this->H1 as $s) $sha1 .=sprintf("%08x",$s);
	
	return $sha1;
	}
	
    function sha224($stream)
	{      
	$this->H256 = ["0xc1059ed8","0x367cd507","0x3070dd17","0xf70e5939",
	               "0xffc00b31","0x68581511","0x64f98fa7","0xbefa4fa4"];
	
	return $this->sha256_224($stream,'224');
	}
	
    function sha256($stream)
	{      
	$this->H256 = ["0x6a09e667","0xbb67ae85","0x3c6ef372","0xa54ff53a",
	               "0x510e527f","0x9b05688c","0x1f83d9ab","0x5be0cd19"];

	return $this->sha256_224($stream);
	}

    function sha256_224($stream,$bits=256)
	{
	/*
	 First thirty-two bits of the fractional parts of
	the cube roots of the first sixty-four prime numbers.
	*/
	
	$this->K = array(
	        "0x428a2f98","0x71374491","0xb5c0fbcf","0xe9b5dba5","0x3956c25b","0x59f111f1","0x923f82a4","0xab1c5ed5",
		"0xd807aa98","0x12835b01","0x243185be","0x550c7dc3","0x72be5d74","0x80deb1fe","0x9bdc06a7","0xc19bf174",
		"0xe49b69c1","0xefbe4786","0x0fc19dc6","0x240ca1cc","0x2de92c6f","0x4a7484aa","0x5cb0a9dc","0x76f988da",
		"0x983e5152","0xa831c66d","0xb00327c8","0xbf597fc7","0xc6e00bf3","0xd5a79147","0x06ca6351","0x14292967",
		"0x27b70a85","0x2e1b2138","0x4d2c6dfc","0x53380d13","0x650a7354","0x766a0abb","0x81c2c92e","0x92722c85",
		"0xa2bfe8a1","0xa81a664b","0xc24b8b70","0xc76c51a3","0xd192e819","0xd6990624","0xf40e3585","0x106aa070",
		"0x19a4c116","0x1e376c08","0x2748774c","0x34b0bcb5","0x391c0cb3","0x4ed8aa4a","0x5b9cca4f","0x682e6ff3",
		"0x748f82ee","0x78a5636f","0x84c87814","0x8cc70208","0x90befffa","0xa4506ceb","0xbef9a3f7","0xc67178f2");

	for ($k=0;$k<64;$k++)
		$this->K[$k] = gmp_init($this->K[$k]);
		
	for ($k=0;$k<8;$k++)
		$this->H256[$k] = gmp_init($this->H256[$k]);
		
	$this->MASK = gmp_init("0xFFFFFFFF");
	
        $stream = $this->prepare($stream,1);

        foreach ($stream as $block)
        	$this->process_block_256($block);
		
	$sha256="";foreach ($this->H256 as $s) $sha256 .=sprintf("%08x",$s);
		
	return substr($sha256,0,$bits/4);	
	}
	
	/*
	“SHA-512/t” is the general name for a t-bit hash function based on SHA-512 whose output is
	truncated to t bits. Each hash function requires a distinct initial hash value. This section provides
	a procedure for determining the initial value for SHA-512/ t for a given value of t.
	For SHA-512/t, t is any positive integer without a leading zero such that t < 512, and t is not 384.
	For example: t is 256, but not 0256, and “SHA-512/t” is “SHA-512/256” (an 11 character long
	ASCII string), which is equivalent to 53 48 41 2D 35 31 32 2F 32 35 36 in hexadecimal.
	The initial hash value for SHA-512/t, for a given value of t, shall be generated by the SHA-512/t
	IV Generation Function below.
	SHA-512/t IV Generation Function
	(begin:)
	Denote H(0)' to be the initial hash value of SHA-512 as specified in Section 5.3.5 above.
	Denote H(0)''  to be the initial hash value computed below.
	H(0) is the IV for SHA-512/t.
	For i = 0 to 7
	{
	Hi(0)''= Hi(0)' xor a5a5a5a5a5a5a5a5(in hex).
	}
	H(0) = SHA-512 (“SHA-512/t”) using H(0)''
	as the IV, where t is the specific truncation value.
	(end.)
	
	SHA-512/224 (t = 224) and SHA-512/256 (t = 256) are approved hash algorithms. 
	Other SHA512/t hash algorithms with different t values may be specified in [SP 800-107] in the future as
	the need arises. Below are the IVs for SHA-512/224 and SHA-512/256
	*/

    function sha512t($stream,$t)
    	{
	$this->H512 = str_split($this->generate_512_t($t),16);

	foreach ($this->H512 as &$iv)
		$iv = "0x$iv";
	
	return $this->sha512_384($stream,$t);	    
	}
					
    function sha384($stream)
	{   	
	$this->H512 = ["0xcbbb9d5dc1059ed8","0x629a292a367cd507","0x9159015a3070dd17","0x152fecd8f70e5939",
	               "0x67332667ffc00b31","0x8eb44a8768581511","0xdb0c2e0d64f98fa7","0x47b5481dbefa4fa4"];
	
	return $this->sha512_384($stream,'384');
	}
		
    function sha512($stream)
	{   	
	$this->H512 = ["0x6a09e667f3bcc908","0xbb67ae8584caa73b","0x3c6ef372fe94f82b","0xa54ff53a5f1d36f1",
		       "0x510e527fade682d1","0x9b05688c2b3e6c1f","0x1f83d9abfb41bd6b","0x5be0cd19137e2179"];
	
	return $this->sha512_384($stream);
	}

    function generate_512_t($t)
    	{
	// SHA-512/t IV Generation Function
	
	$H512 = ["0x6a09e667f3bcc908","0xbb67ae8584caa73b","0x3c6ef372fe94f82b","0xa54ff53a5f1d36f1",
		 "0x510e527fade682d1","0x9b05688c2b3e6c1f","0x1f83d9abfb41bd6b","0x5be0cd19137e2179"];
	
	for ($k=0;$k<8;$k++)
		$H512[$k] = gmp_init($H512[$k]);
	
	for ($i = 0;$i<8;$i++)		
		$this->H512[$i] = "0x".bin2hex(gmp_export(gmp_xor($H512[$i] , gmp_init("0xa5a5a5a5a5a5a5a5"))));
				
	return $this->sha512_384("SHA-512/$t");    
	}
	
    function sha512_384($stream,$bits=512)
    	{
	/*
	First sixty-four bits of the
	    fractional parts of the cube roots of the first eighty prime numbers.    
	*/
	$this->K = array(
	"0x428a2f98d728ae22","0x7137449123ef65cd","0xb5c0fbcfec4d3b2f","0xe9b5dba58189dbbc",
	"0x3956c25bf348b538","0x59f111f1b605d019","0x923f82a4af194f9b","0xab1c5ed5da6d8118",
	"0xd807aa98a3030242","0x12835b0145706fbe","0x243185be4ee4b28c","0x550c7dc3d5ffb4e2",
	"0x72be5d74f27b896f","0x80deb1fe3b1696b1","0x9bdc06a725c71235","0xc19bf174cf692694",
	"0xe49b69c19ef14ad2","0xefbe4786384f25e3","0x0fc19dc68b8cd5b5","0x240ca1cc77ac9c65",
	"0x2de92c6f592b0275","0x4a7484aa6ea6e483","0x5cb0a9dcbd41fbd4","0x76f988da831153b5",
	"0x983e5152ee66dfab","0xa831c66d2db43210","0xb00327c898fb213f","0xbf597fc7beef0ee4",
	"0xc6e00bf33da88fc2","0xd5a79147930aa725","0x06ca6351e003826f","0x142929670a0e6e70",
	"0x27b70a8546d22ffc","0x2e1b21385c26c926","0x4d2c6dfc5ac42aed","0x53380d139d95b3df",
	"0x650a73548baf63de","0x766a0abb3c77b2a8","0x81c2c92e47edaee6","0x92722c851482353b",
	"0xa2bfe8a14cf10364","0xa81a664bbc423001","0xc24b8b70d0f89791","0xc76c51a30654be30",
	"0xd192e819d6ef5218","0xd69906245565a910","0xf40e35855771202a","0x106aa07032bbd1b8",
	"0x19a4c116b8d2d0c8","0x1e376c085141ab53","0x2748774cdf8eeb99","0x34b0bcb5e19b48a8",
	"0x391c0cb3c5c95a63","0x4ed8aa4ae3418acb","0x5b9cca4f7763e373","0x682e6ff3d6b2b8a3",
	"0x748f82ee5defb2fc","0x78a5636f43172f60","0x84c87814a1f0ab72","0x8cc702081a6439ec",
	"0x90befffa23631e28","0xa4506cebde82bde9","0xbef9a3f7b2c67915","0xc67178f2e372532b",
	"0xca273eceea26619c","0xd186b8c721c0c207","0xeada7dd6cde0eb1e","0xf57d4f7fee6ed178",
	"0x06f067aa72176fba","0x0a637dc5a2c898a6","0x113f9804bef90dae","0x1b710b35131c471b",
	"0x28db77f523047d84","0x32caab7b40c72493","0x3c9ebe0a15c9bebc","0x431d67c49c100d4c",
	"0x4cc5d4becb3e42b6","0x597f299cfc657e2a","0x5fcb6fab3ad6faec","0x6c44198c4a475817");

	for ($k=0;$k<64;$k++)
		$this->K[$k] = gmp_init($this->K[$k]);
	
	$this->MASK = gmp_init("0xFFFFFFFFFFFFFFFF"); 	
		
	for ($k=0;$k<8;$k++)
		$this->H512[$k] = gmp_init($this->H512[$k]);
								  
        $stream = $this->prepare($stream,512);
  
        foreach ($stream as $block)
        	$this->process_block_512($block);
		
	$sha512="";foreach ($this->H512 as $s) $sha512 .=sprintf("%016s",bin2hex(gmp_export($s)));
	
	return substr($sha512,0,$bits/4);	    
	}
	
/*
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
*/
	
    function rotLeft64($lane, $biShift) 
    	{	
	$byShift    = floor($biShift/8);
	$lane       = substr($lane,-$byShift).substr($lane,0,-$byShift);  	
	$biShift   %= 8;		
	$carry      = 0;
	for ($i = 0; $i < 8; $i++) 
		{		
		$temp     = ord($lane[$i]) << $biShift;
		$lane[$i] = chr($temp & 0xff | $carry);
		$carry    = $temp >> 8;		
		}	
	$lane[0] = chr(ord($lane[0]) | $carry);	
	return $lane;	
	}
	
    function sha3_process($stream,$rate,$suffix,$sizeoutput=0) 
    	{
	/*
	In the sponge construction, 
	
	rate is the number of input bits processed or output
	bits generated per invocation of the underlying function
	
	capacity the width of the underlying function minus the
	rate
	*/
			
	$state 	= str_repeat ("\0", 200);
	$rate  /= 8;
	
	/*
	State: An array of bits that is repeatedly updated within a computational
	procedure. For a KECCAK-p permutation, the state is represented either as
	a three-dimensional array or as a bit string
	
	multi-rate padding The padding rule pad10*1, whose output is a 1, followed by a (possibly
	empty) string of 0s, followed by a 1.	

	process blocks of bytes=rate
	*/
	
	if (hexdec(bin2hex($stream))==0) 
		$stream="";
	
	$blocks = str_split($stream,$rate);
		
	if (strlen($stream) % $rate == 0 and $stream!="") 
		$blocks[]="";
	
	for ($k=0;$k<sizeof($blocks)-1;$k++)
		{
		for ($i = 0; $i < $rate; $i++) 
			$state[$i]=$state[$i] ^ $blocks[$k][$i];
		$state=$this->keccak_p($state);			
		}
	
	// pad only the last block
	
	$stream = $blocks[sizeof($blocks)-1];				
	$length = strlen($stream);
		
	for ($i = 0; $i < $length; $i++) 
		$state[$i]=$state[$i] ^ $stream[$i];		
		
	$state[$length]   = $state[$length] ^ chr($suffix);
	$state[$rate - 1] = $state[$rate - 1] ^ "\x80";
	
	return bin2hex(substr($this->keccak_p($state),0,$sizeoutput));		
	}
    
    function Theta(&$lanes)
    	{
	/*
		1. For all pairs (x,z) such that 0=x<5 and 0=z<w, let
			C[x,z]=A[x, 0, z] ? A[x, 1, z] ? A[x, 2, z] ? A[x, 3, z] ? A[x, 4, z].
		2. For all pairs (x,z) such that 0=x<5 and 0=z<w let
			D[x,z]=C[(x?1) mod 5, z] ? C[(x+1) mod 5, (z –1) mod w].
		3. For all triples (x, y, z) such that 0=x<5, 0=y<5, and 0=z<w, let
			A'[x, y, z] = A[x, y, z] ? D[x,z]. 
			
	The effect of ? is to XOR each bit in the state with the parities of two columns in the array.
	In particular, for the bit A[x0, y0, z0], the x-coordinate of one of the columns is (x0 ? 1) mod 5, 
	with the same z-coordinate, z0, while the x-coordinate of the other column is (x0 + 1) mod 5, 
	with zcoordinate (z0?1) mod w
	
	w is w the lane size of a KECCAK-p permutation in bits, i.e., b/25
	
	Lane(i, j) For a state array A, a string of all the bits of the lane whose x and y
		coordinates are i and j. Dirección z
		
	z- = rotate left
	
	Rnd(A, ir) = ?(?(p(?(?(A)))), ir).
	*/
	
	// Compute the parity of the columns
	$C = [];
	for ($x=0;$x<5;$x++) 				
		$C[$x]=$lanes[$x] ^ $lanes[$x+5] ^ $lanes[$x+10] ^ $lanes[$x+15] ^ $lanes[$x+20];
		
	for ($x=0;$x<5;$x++) 
		{
		// Compute the ? effect for a given column			
		$D=$C[($x+4)%5] ^ $this->rotLeft64($C[($x+1)%5],1);
		// Add the ? effect to the whole column
		for ($y=0;$y<25;$y+=5) 			
			$lanes[$x+$y]^= $D;			
		}	    
	}
		
   function Ro_Pi(&$lanes)
	{
	/*
	?	
		1. For all z such that 0=z<w, let A'[0, 0, z] = A[0, 0, z].
		2. Let (x, y) = (1, 0).
		3. For t from 0 to 23:
			a. for all z such that 0=z<w, let A'[x, y, z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
			b. let (x, y) = (y, (2x+3y) mod 5).
		4. Return A'.
	
	The effect of ? is to rotate the bits of each lane by a length, called the offset, which depends on
		the fixed x and y coordinates of the lane. Equivalently, for each bit in the lane, the z coordinate is
		modified by adding the offset, modulo the lane size
					
	p	
		1. For all triples (x, y, z) such that 0=x<5, 0=y<5, and 0=z<w, let
			A'[x, y, z]=A[(x + 3y) mod 5, x, z].
		2. Return A'.
		
	The effect of p is to rearrange the positions of the lanes 			
	*/
	
	// Start at coordinates (1 0)
	$x=1;$y=0;
	$actual=$lanes[1]; 
	// Iterate over ((0 1)(2 3))^t * (1 0) for 0 = t = 23
	for ($t=0;$t<24;$t++) 
		{
		// rotation constant r = (t+1)(t+2)/2
		// Compute ((0 1)(2 3)) * (x y)
		[$x,$y]=[$y,(2*$x+3*$y)%5];

		$pos=$x+5*$y;
		// Swap current and state(x,y), and rotate		
		[$actual,$lanes[$pos]]=[$lanes[$pos],$this->rotLeft64($actual,(($t+1)*($t+2)/2)%64)];
		}
	}

    function Ji(&$lanes)
    	{	
	/*
	?	
		1. For all triples (x, y, z) such that 0=x<5, 0=y<5, and 0=z<w, let
			A'[x, y, z] = A[x, y, z] ? ((A[(x+1) mod 5, y, z] ? 1) · A[(x+2) mod 5, y, z]).
		2. Return A'.
		
	The effect of ? is to XOR each bit with a non-linear function of two other bits in its row	
	*/			
	for ($y=0;$y<25;$y+=5) 
		{			
		// Take a copy of the plane
		$temp = array_slice($lanes,$y,5);
		// Compute ? on the plane
		for ($x=0;$x<5;$x++) 
			$lanes[$x+$y]=$temp[$x] ^ ((~ $temp[($x+1)%5])&$temp[($x+2)%5]);
		}
	}

    function Iota(&$lanes,&$LFSRstate)
    	{
	/*
	?
		rc
		
		1. If t mod 255 = 0, return 1.
		2. Let R = 10000000.
		3. For i from 1 to t mod 255, let:
			a. R = 0 || R;
			b. R[0] = R[0] ? R[8];
			c. R[4] = R[4] ? R[8];
			d. R[5] = R[5] ? R[8];
			e. R[6] = R[6] ? R[8];
			f. R =Trunc8[R].
		4. Return R[0].
		
		1. For all triples (x, y, z) such that 0=x<5, 0=y<5, and 0=z<w, let A'[x, y, z] = A[x, y, z].
		2. Let RC=0-w
		3. For j from 0 to l, let RC[2j–1]=rc(j+7ir).
		4. For all z such that 0=z<w, let A'[0, 0, z]=A'[0, 0, z] ? RC[z].
		5. Return A'.
		
	The effect of ? is to modify some of the bits of Lane (0, 0) in a manner that depends on the round
		index ir. The other 24 lanes are not affected by ?.	

	$RC = $this->rotLeft64("\1\0\0\0\0\0\0\0",$bitPosition);
	
	bitposition = for i=0 to 6  2**i -1
	
	0,1,3,7,15,31,63
	*/
	
	$RC = [
	"\1\0\0\0\0\0\0\0",
	"\2\0\0\0\0\0\0\0",
	"\x8\0\0\0\0\0\0\0",
	"\x80\0\0\0\0\0\0\0",
	"\0\x80\0\0\0\0\0\0",
	"\0\0\0\x80\0\0\0\0",
	"\0\0\0\0\0\0\0\x80"];
				
	/*
	$bitPosition    = (1 << $j) - 1; //2^j-1
	
	$RC = $this->rotLeft64("\1\0\0\0\0\0\0\0",$bitPosition);				
	$RC is strrev(2**$bitPosition) == strrev(1<<bitPosition)						
	*/				
		
	for ($j=0;$j<7;$j++) 
		if ($LFSRstate[$j]) $lanes[0] ^= $RC[$j];
	}
			
    function keccak_p($state) 
    	{
	/*
	KECCAK is the family of all sponge functions with a KECCAK-f permutation as the
	underlying function and multi-rate padding as the padding rule
	
	For a state array of a KECCAK-p permutation with width b, lane is a sub-array of
	b/25 bits with constant x and y coordinates.
	
	25 lanes of 8 bytes. x,y 5 and z 8 
	*/
	
	$lanes     = str_split($state,8);

	$LFSRstate = [
	"1000000","0101100","0111101","0000111","1111100","1000010","1001111","1010101",
	"0111000","0011000","1010110","0110010","1111110","1111001","1011101","1100101",
	"0100101","0001001","0110100","0110011","1001111","0001101","1000010","0010111"];
				
	/*
	The permutation is defined for any b in {25, 50, 100, 200, 400, 800,
	1600} and any positive integer n
	
	The state for the KECCAK-p[b, nr] permutation is comprised of b bits. The specifications in this
	Standard contain two other quantities related to b: b/25 and log2(b/25), denoted by w and l,
	respectively
	
	Round: the sequence of step mappings that is iterated in the calculation of a
	KECCAK-p permutation
	
	Let S denote a string of b bits that represents the state for the KECCAK-p[b, nr] permutation. The
	corresponding state array, denoted by A, is defined as follows:
	For all triples (x, y, z) such that 0=x<5, 0=y<5, and 0=z<w,
	A[x, y, z]=S[w(5y+x)+z].	
	*/
	
	for ($round=0;$round<24;$round++) 
		{
		/*
		The five step mappings that comprise a round of KECCAK-p[b, nr] are denoted by ?, ?, p, ?, and ?.
		*/		
		$this->Theta($lanes);		
		$this->Ro_Pi($lanes);			
		$this->Ji($lanes);		
		$this->Iota($lanes,$LFSRstate[$round]);	
		}
	
	return implode($lanes);	
	}
 	
   function sha3($type,$stream,$outputl=0) 
   	{
	// sha3_process($stream,$rate,$suffix,$sizeoutput=0)
	switch ($type) 
		{
		case "224": return $this->sha3_process($stream,1152, 0x06, 28);break;
		case "256": return $this->sha3_process($stream,1088, 0x06, 32);break;
		case "384": return $this->sha3_process($stream,832,  0x06, 48);break;
		case "512": return $this->sha3_process($stream,576,  0x06, 64);break;
		
		/*
		The name “SHAKE” was proposed in to combine the term “Secure Hash Algorithm” with “KECCAK.”
		XOF = extendable-output-function: A function on bit strings in which the output can be extended to any
		  desired length
		*/
		
		if ($outputl==0) $ouputl=explode("SHAKE",$type)[1]/4;
		
		case "SHAKE128": return $this->sha3_process($stream,1344, 0x1f,$outputl);break;
		case "SHAKE256": return $this->sha3_process($stream,1088, 0x1f,$outputl);break;
		
		die('Invalid operation type');		
		}		
	}
}
