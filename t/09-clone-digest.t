# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 09-clone-digest.t'

#########################

use Test;
use ExtUtils::testlib;
use Crypt::GCrypt;

#########################

# SHA512 progressive digests (can we read what the digest should be along the way?):

my %dgsts = (
  '' => 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
  'a' => '1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75',
  'abc' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  'abcdefghijklmnopqrstuvwxyz' => '4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1',
);

plan tests => 5;

my $md0 = Crypt::GCrypt->new(
			     type => 'digest',
			     algorithm => 'sha512',
			    );
my $result;

my $md1 = $md0->clone();
$result = unpack('H*', $md1->read());
ok($result eq $dgsts{''});

$md0->write('a');

my $md2 = $md0->clone();
$result = unpack('H*', $md2->read());
ok($result eq $dgsts{'a'});

$md0->write('bc');

my $md3 = $md0->clone();
$result = unpack('H*', $md3->read());
ok($result eq $dgsts{'abc'});

$md0->write('defghijklmnopqrstuvwxyz');

my $md4 = $md0->clone();
$result = unpack('H*', $md4->read());
ok($result eq $dgsts{'abcdefghijklmnopqrstuvwxyz'});


$result = unpack('H*', $md0->read());
ok($result eq $dgsts{'abcdefghijklmnopqrstuvwxyz'});



