# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 07-thread.t'

#########################

use strict;
use warnings;
use Test::More;
use ExtUtils::testlib;
use Crypt::GCrypt;
use IO::Socket;

#########################

use threads;

my @algos = ('aes', 'twofish', 'blowfish', 'arcfour', 'cast5', 'des', 'serpent', 'seed');

my $str = 'Four Score and Seven years ago, our fore-monkeys created a great blah blah blah';
my $key = 'monkeymonkeymonkey';

sub producer_thread {
  my $p = shift;
  my $algo = shift;
  my $enc = Crypt::GCrypt->new(
			       type => 'cipher',
			       algorithm => $algo,
               	   #mode => 'cbc',
               	   #padding => 'null'
			      );
  $enc->start('encrypting');
  $enc->setkey($key);
  my $buf = $enc->encrypt($str);
  $p->write($buf);
  $buf = $enc->finish();
  $p->write($buf);
  $p->shutdown(1);
  $p->close();
}

sub consumer_thread {
  my $p = shift;
  my $algo = shift;
  my $dec = Crypt::GCrypt->new(
			       type => 'cipher',
			       algorithm => $algo,
                   #mode => 'cbc',
                   #padding => 'null'
			      );
  $dec->start('decrypting');
  $dec->setkey($key);
  my $buf;
  my $out;
  my $count = 0;
  while ($p->read($buf, $dec->blklen())) {
    $out .= $dec->decrypt($buf);
  }
  $p->close();
  $out .= $dec->finish();
  printf("Failed to match output with algorithm '%s'\n", $algo) if ($str ne $out);
  return $str eq $out;
}


sub testalgo {
  my $algo = shift;
  my ($read, $write) = IO::Socket->socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC);

  # create in scalar context so that the result is the returned scalar:
  my $con = threads->create('consumer_thread', $read, $algo);
  my $pro = threads->create('producer_thread', $write, $algo);
}

# test as many algorithms as we have.
my @available_algos = grep Crypt::GCrypt::cipher_algo_available($_), @algos;
plan tests => 2 * @available_algos;

testalgo($_) for @available_algos;
ok($_->join()) for threads->list();



