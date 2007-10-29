# ===========================================================================
# Crypt::GCrypt
# 
# Perl interface to the GNU Cryptographic library
# 
# Author: Alessandro Ranellucci <aar@cpan.org>
# Copyright (c) 2005-06.
# 
# Use this software AT YOUR OWN RISK.
# See below for documentation.
# 

package Crypt::GCrypt;

use strict;
use warnings;

our $VERSION = '1.16';

require XSLoader;
XSLoader::load('Crypt::GCrypt', $VERSION);

1;
__END__

=head1 NAME

Crypt::GCrypt - Perl interface to the GNU Cryptographic library

=head1 SYNOPSIS

  use Crypt::GCrypt;
  
  $cipher = Crypt::GCrypt->new(
    type => 'cipher',
    algorithm => 'aes', 
    mode => 'cbc'
  );
  $cipher->start('encrypting');
  
  $cipher->setkey('my secret key');
  $cipher->setiv('my init vector');

  $ciphertext = $cipher->encrypt('plaintext');
  $ciphertext .= $cipher->finish;

  $plaintext  = $cipher->decrypt($ciphertext);

=head1 ABSTRACT

Crypt::GCrypt provides an object interface to the C libgcrypt library. It
currently supports symmetric encryption/decryption, while asymmetric 
cryptography is being worked on.

=head1 SYMMETRIC CRYPTOGRAPHY

=head2 new()

In order to encrypt/decrypt your data using a symmetric cipher you first have
to build a Crypt::GCrypt object:

  $cipher = Crypt::GCrypt->new(
    type => 'cipher',
    algorithm => 'aes', 
    mode => 'cbc'
  );

The I<type> argument must be "cipher" and I<algorithm> is required too. See below
for a description of available algorithms and other initialization parameters:

=over 4

=item algorithm

This may be one of the following:

=over 8

=item B<3des> 

Triple-DES with 3 Keys as EDE.  The key size of this algorithm is
168 but you have to pass 192 bits because the most significant
bits of each byte are ignored.

=item B<aes> 

AES (Rijndael) with a 128 bit key.

=item B<aes192> 

AES (Rijndael) with a 192 bit key.

=item B<aes256> 

AES (Rijndael) with a 256 bit key.

=item B<blowfish>

The blowfish algorithm. The current implementation allows only for 
a key size of 128 bits (and thus is not compatible with Crypt::Blowfish).

=item B<cast5>

CAST128-5 block cipher algorithm.  The key size is 128 bits.

=item B<des> 

Standard DES with a 56 bit key. You need to pass 64 bit but the
high bits of each byte are ignored.  Note, that this is a weak
algorithm which can be broken in reasonable time using a brute
force approach.

=item B<twofish> 

The Twofish algorithm with a 256 bit key.

=item B<twofish128> 

The Twofish algorithm with a 128 bit key.

=item B<arcfour> 

An algorithm which is 100% compatible with RSA Inc.'s RC4
algorithm.  Note that this is a stream cipher and must be used
very carefully to avoid a couple of weaknesses.

=back

=item mode

This is a string specifying one of the following
encryption/decryption modes:

=over 8

=item B<stream> 

only available for stream ciphers

=item B<ecb> 

doesn't use an IV, encrypts each block independently

=item B<cbc> 

the current ciphertext block is encryption of current plaintext block 
xor-ed with last ciphertext block

=item B<cfb> 

the current ciphertext block is the current plaintext
block xor-ed with the current keystream block, which is the encryption
of the last ciphertext block

=item B<ofb> 

the current ciphertext block is the current plaintext
block xor-ed with the current keystream block, which is the encryption
of the last keystream block

=back

If no mode is specified then B<cbc> is selected for block ciphers, and
B<stream> for stream ciphers.

=item padding

When the last block of plaintext is shorter than the block size, it must be 
padded before encryption. Padding should permit a safe unpadding after 
decryption. Crypt::GCrypt currently supports two methods:

=over 8

=item B<standard>

This is also known as PKCS#5 padding, as it's binary safe. The string is padded
with the number of bytes that should be truncated. It's compatible with Crypt::CBC.

=item B<null>

Only for text strings. The block will be padded with null bytes (00). If the last 
block is a full block and blocksize is 8, a block of "0000000000000000" will be 
appended.

=back

=item secure

All data associated with this cipher will be put into non-swappable storage, 
if possible.

=item enable_sync

Enable the CFB sync operation.

=back

Once you've got your cipher object the following methods are available:

=head2 start()

   $cipher->start('encrypting');
   $cipher->start('decrypting');

This method must be called before any call to setkey() or setiv(). It prepares
the cipher for encryption or decryption, resetting the internal state.

=head2 setkey()

   $cipher->setkey('my secret key');

Encryption and decryption operations will use this key until a different
one is set. If your key is shorter than the cipher's keylen (see the
C<keylen> method) it will be zero-padded, if it is longer it will be
truncated.

=head2 setiv()

   $cipher->setiv('my iv');

Set the initialisation vector for the next encrypt/decrypt operation.
If I<IV> is missing a "standard" IV of all zero is used. The same IV is set in
newly created cipher objects.

=head2 encrypt()

   $ciphertext = $cipher->encrypt($plaintext);

This method encrypts I<$plaintext> with I<$cipher>, returning the
corresponding ciphertext. The output is buffered; this means that
you'll only get multiples of $cipher's block size and that at the 
end you'll have to call L</"finish()">.

=head2 finish()

    $ciphertext .= $cipher->finish;

The CBC algorithm must buffer data blocks internally until there are even 
multiples of the encryption algorithm's blocksize (typically 8 or 16 bytes).
After the last call to encrypt() you should call finish() to flush the internal
buffer and return any leftover ciphertext. The internal buffer will be padded
before encryption (see the L</padding> option above).

=head2 decrypt()

   $plaintext = $cipher->decrypt($ciphertext);

The counterpart to encrypt, decrypt takes a I<$ciphertext> and produces the
original plaintext (given that the right key was used, of course).

=head2 keylen()

   print "Key length is " . $cipher->keylen();

Returns the number of bytes of keying material this cipher needs.

=head2 blklen()

   print "Block size is " . $cipher->blklen();

As their name implies, block ciphers operate on blocks of data. This
method returns the size of this blocks in bytes for this particular
cipher. For stream ciphers C<1> is returned, since this implementation
does not feed less than a byte into the cipher.

=head2 sync()

   $cipher->sync();

Apply the CFB sync operation.

=head1 BUGS AND FEEDBACK

There are no known bugs. You are very welcome to write mail to the author 
(aar@cpan.org) with your contributions, comments, suggestions, bug reports 
or complaints.

=head1 AUTHOR

Alessandro Ranellucci E<lt>aar@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005 Alessandro Ranellucci.
Crypt::GCrypt is free software, you may redistribute it and/or modify it under 
the same terms as Perl itself.

=head1 ACKNOWLEDGEMENTS

This module was initially inspired by the GCrypt.pm bindings made by 
Robert Bihlmeyer in 2002. Thanks to users who give feedback (see Changelog).

=head1 DISCLAIMER

This software is provided by the copyright holders and contributors ``as
is'' and any express or implied warranties, including, but not limited to,
the implied warranties of merchantability and fitness for a particular
purpose are disclaimed. In no event shall the regents or contributors be
liable for any direct, indirect, incidental, special, exemplary, or
consequential damages (including, but not limited to, procurement of
substitute goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether in
contract, strict liability, or tort (including negligence or otherwise)
arising in any way out of the use of this software, even if advised of the
possibility of such damage.

=cut
