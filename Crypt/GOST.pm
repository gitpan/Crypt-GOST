#!/usr/bin/perl -w

# Dec '98 revision. 

package Crypt::GOST;
use vars qw ($VERSION $AUTOLOAD);
use Carp;

( $VERSION )  = '$Revision: 0.41 $' =~ /\s(\d+\.\d+)\s/; 


sub new {
	my $argument = shift;
	my $class = ref ($argument) || $argument;
	my $self = {};
	$self->{KEY} = [];
	$self->{SBOX} = []; 
	bless $self, $class;
	return $self;
} 

sub AUTOLOAD {
	my $self = shift;
	my $method = $AUTOLOAD;
	$method =~ s/.*://;
	$data = shift;
	$self->SScrypt ($data, 1) if $method eq "SSdecrypt";
}


sub generate_sbox {
	my $self = shift;
	my $passphrase = shift;
	if (ref ($passphrase)) {
		@{$self->{SBOX}} = @$passphrase;
	} else { 
		my ($i, $x, $y, $random, @tmp) = 0;
		my @temp = (0..15);
		for ($i=0; $i <= (length $passphrase); $i+=4) 
		{ $random = $random ^ &_longint ($passphrase, $i)  };
		srand $random;
		for ($i=0; $i < 8; $i++) {
        		@tmp = @temp;
               		grep { $x = _rand (15); $y = $tmp[$x]; $tmp[$x] = $tmp[$_]; $tmp[$_] = $y; } (0..15);
                	grep {@{$self->{SBOX}}->[$i][$_] = $tmp[$_] } (0..15);
		} 
	} 
} 

sub generate_keys {
	my ($self, $passphrase) = @_;
	if (ref ($passphrase)) {
		@{$self->{KEY}} = @$passphrase;
	} else { 
		my ($i, $random) = 0;
		for ($i=0; $i <= (length $passphrase); $i+=4) 
		{ $random = $random ^ &_longint ($passphrase, $i)};
		srand $random; grep { @{$self->{KEY}}[$_] = _rand (2**32) } (0..7);
	} 
} 

sub SScrypt {
	my ($self, $data, $decrypt) = @_;
	my ($i, $j, $d1, $d2) = 0;
	my $return = '';
	for ($i=0; $i < length $data; $i += 8) {
		$d1 = &_longint ($data, $i);
		$d2 = &_longint ($data, $i+4);
		$j = 0;
		grep { 
			$j = ($_ % 8) - 1; $j = 7 if $j == -1; 
			$decrypt ? ($_ >= 9) && ($j = (32 - $_) % 8) : ($_ >= 25) && ($j = 32 - $_); 
			($_ % 2) == 1 ? ($d2 ^= $self->_substitute ($d1 + @{$self->{KEY}}[$j])) : 
					($d1 ^= $self->_substitute ($d2 + @{$self->{KEY}}[$j])) ;
		} (1..32);
		$return .= pack L2, $d2, $d1;
	}
	return $return;
}

sub _substitute {
	my ($self, $d) = @_;
	my $return = 0;
	grep { $return = $return | @{$self->{SBOX}}->[$_][$d >> ($_ * 4) & 15] << ($_ * 4) } reverse (0..7);
	return $return << 11 | $return >> 21;  
}

sub _rand { 
	return int (((shift) / 100) * ((rand) * 100)); 
}

sub _longint {
	my ($string, $pos) = @_;
	return unpack L, pack a4, substr $string, $pos, $pos +4;
}
1;

=head1 NAME

Crypt::GOST - GOST encryption algorithm.

=head1 SYNOPSIS

use Crypt::GOST;

  my $gost = new Crypt::Gost;
  $gost->generate_sbox ($passphrase);
  $gost->generate_keys ($passphrase);
  $cyphertext = $gost->SScrypt($plaintext);
  $plaintext  = $gost->SSdecrypt($cyphertext);

=head1 GOST INFORMATION 

  http://www.vipul.net/gost/ 

=head1 AUTHOR

Vipul Ved Prakash, mail@vipul.net

=cut


