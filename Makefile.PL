use lib qw(inc);
use Devel::CheckLib;
use ExtUtils::MakeMaker;
use Config;
use strict;
use warnings;
use 5.006000;

my $gcrypt_libpath = '';
my $gcrypt_incpath = '';

# let's check for GCRYPTLIBPATH and GCRYPTINCPATH options
# removing them from @ARGV
foreach (@ARGV) {
    /^GCRYPTLIBPATH=(.+)/ && ($gcrypt_libpath = $1);
    /^GCRYPTINCPATH=(.+)/ && ($gcrypt_incpath = $1);
}
@ARGV = grep !/^GCRYPT(?:LIB|INC)PATH=/, @ARGV;

# if we still need $gcrypt_libpath let's try the default 
# locations
if (not $gcrypt_libpath and $] >= 5.006001) {
  require ExtUtils::Liblist;
  ($gcrypt_libpath) = ExtUtils::Liblist->ext('-lgcrypt');
}

# let's check with Devel::CheckLib;
check_lib_or_exit(
    lib => [qw(gcrypt)], libpath => $gcrypt_libpath
);

# now build the options list for WriteMakefile()
my @extras = $gcrypt_incpath ? (INC => "-I$gcrypt_incpath") : ();
my $libs = $gcrypt_libpath ? "-L$gcrypt_libpath -lgcrypt" : '-lgcrypt';

WriteMakefile(
    'NAME'         => 'Crypt::GCrypt',
    'ABSTRACT'     => 'Perl interface to the GNU libgcrypt library',
    'AUTHOR'       => 'Alessandro Ranellucci <aar@cpan.org>',
    'VERSION_FROM' => 'lib/Crypt/GCrypt.pm',
    'LIBS'         => $libs,
    'DEFINE'       => '',
    'CCFLAGS'      => '-funsigned-char',
    'dist'         => { COMPRESS => 'gzip', SUFFIX => 'gz' },
    @extras
);
