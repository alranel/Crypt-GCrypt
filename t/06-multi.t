use Test::More;
plan tests => 1;

use ExtUtils::testlib;
use Crypt::GCrypt;

my $c = Crypt::GCrypt->new(
	type => 'cipher', 
	algorithm => 'aes',  # blklen == 16
	mode => 'cbc',
	padding => 'standard'
);
$c->start('encrypting');
$c->setkey('b' x 32);

my $text = 'a' x 999;
my $t1 = substr($text, 0, 512);
my $t2 = substr($text, 512);
print "length of original text is " . length($text) . "\n";

my $e = $c->encrypt($t1);
$e .= $c->encrypt($t2);
$e .= $c->finish;
print "length of encrypted text is " . length($e) . "\n";

$c->start('decrypting');
my $e1 = substr($e, 0, 512);
my $e2 = substr($e, 512);
my $d = $c->decrypt($e1);
$d .= $c->decrypt($e2);
$d .= $c->finish;
print "length of decrypted text is " . length($d) . "\n";

ok(length $d == length $text);

__END__
