use lib qw(inc);
use Devel::CheckLib;
use ExtUtils::MakeMaker;
use Config;
use strict;
use warnings;
use 5.006000;

our $gcrypt_libpath = '';
our $gcrypt_incpath = '';

# let's check for GCRYPTLIBPATH and GCRYPTINCPATH options
# removing them from @ARGV
my @replacement_args;
foreach (@ARGV) {
	if (/^GCRYPT(LIB|INC)PATH=(.+)/) {
		if ($1 eq 'LIB') {
			$gcrypt_libpath = $2;
		} else {
			$gcrypt_incpath = $2;
		}
	} else {
		push @replacement_args, $_;
	}
}
@ARGV = @replacement_args;

# if we still need $gcrypt_libpath let's try the default 
# locations
if (not $gcrypt_libpath and $] >= 5.006001) {
	require ExtUtils::Liblist;		# Buggy before this
	($gcrypt_libpath) = ExtUtils::Liblist->ext('-lgcrypt');
}

check_lib_or_exit(
    lib => [qw(gcrypt)], libpath => $gcrypt_libpath
);

# 
my $libfound = 0;
unless ($gcrypt_libpath) {
	# Test for existence of libgcrypt
	foreach (split /\s+/, $Config{libpth}) {
		if (-f "$_/libgcrypt." . $Config{so}) {
		$libfound = 1;
		last;
	}
}

unless ($libfound) {
    print <<'PREREQ_MISSING;';

libgcrypt must be installed prior to building Crypt::GCrypt and I can't 
find it in the standard library directories. You can download it from:

ftp://ftp.gnupg.org/gcrypt/libgcrypt/

and then you can install it just doing:
	$  ./configure
	$  make
	#  make install

If libgcrypt is installed, but in a non-standard directory, then use the
following options to Makefile.PL:

    GCRYPTLIBPATH=...  To set the directory in which to find libgcrypt
    GCRYPTINCPATH=...  To set the directory in which to find gcrypt.h

For example:
    perl Makefile.PL GCRYPTLIBPATH=/home/me/lib GCRYPTINCPATH=/home/me/include

Note that if you build against a shareable library in a non-standard location
you may (on some platforms) also have to set your LD_LIBRARY_PATH environment
variable at run time for perl to find the library.

PREREQ_MISSING;
    exit 0;
  }
}

# now build the options list for WriteMakefile()
my @extras = ();
push(@extras, INC => "-I$gcrypt_incpath")
  if $gcrypt_incpath;

my $libs = '-lgcrypt';
$libs = "-L$gcrypt_libpath $libs"
  if $gcrypt_libpath;

WriteMakefile(
    'NAME'		=> 'Crypt::GCrypt',
    'ABSTRACT'	=> 'Perl interface to the GNU libgcrypt library',
    'AUTHOR'	=> 'Alessandro Ranellucci <aar@cpan.org>',
    'VERSION_FROM'	=> 'GCrypt.pm',
    'LIBS'		=> $libs,
    'DEFINE'		=> '',
    'CCFLAGS'       => '-funsigned-char',
    'dist'         	=> { COMPRESS => 'gzip', SUFFIX => 'gz' },
    @extras
);
