use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Crypt::GOST',
    'VERSION_FROM' => 'Crypt/GOST.pm', # finds $VERSION
);
