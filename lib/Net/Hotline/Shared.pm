package Net::Hotline::Shared;

## Copyright(c) 1998 by John C. Siracusa.  All rights reserved.  This program
## is free software; you can redistribute it and/or modify it under the same
## terms as Perl itself.

use Carp;
use IO::Handle;
use POSIX qw(F_GETFL F_SETFL O_NONBLOCK EINTR);

use strict;
use vars qw(@ISA @EXPORT);

require   Exporter;
@ISA    = qw(Exporter);
@EXPORT = qw(_encode _write _read _hexdump _debug _set_blocking);

sub _debug
{
  if($Net::Hotline::Client::DEBUG)
  {
    print STDERR join('', @_);
  }
}

sub _encode
{
  my($data) = join('', @_);

  my($i, $len, $enc);

  $len = length($data);

  for($i = 0; $i < $len; $i++)
  {
    $enc .= pack("c", (255 - unpack("c", substr($data, $i, 1))));
  }

  return $enc;
}

sub _write
{
  my($fh, $data_ref, $length) = @_;
  
  my($written, $offset);

  $offset = 0;

  while($length > 0) # Handle partial writes
  {
    $written = syswrite($fh, $$data_ref, $length, $offset);
    next  if($! == EINTR);
    croak("System write error: $!\n")  unless(defined($written));
    $length -= $written;
    $offset += $written;
  }

  return $offset;
}

sub _read
{
  my($fh, $data_ref, $length, $blocking) = @_;

  my($offset)   = 0;
  my($read)     = 0;
  
  $blocking = 1  unless(defined($blocking));

  #_debug("Reading $length...");

  while($length > 0) # Handle partial reads
  {
    $read = sysread($fh, $$data_ref, $length, $offset);

    unless(defined($read))
    {
      next  if($! == EINTR);

      # Once we read a little bit, we keep readinuntil we get it all
      # Otherwise, we can return undef and treat it as a WOULDBLOCK
      if($blocking || $offset > 0)  { next }
      else                 { return(undef) }
    }

    $offset   += $read;
    $length   -= $read;
  }

  #_debug("read $offset ($length)\n");
  return($offset);
}

sub _set_blocking
{
  my($fh, $blocking) = @_;

  if($IO::VERSION >= 1.19) # The easy way, with the IO module
  {
    $fh->blocking($blocking);
  }
  else # The hard way...not 100% successful :-/
  {
    my($flags) = fcntl($fh, F_GETFL, 0);

    defined($flags) || croak "Can't get flags for socket: $!\n";

    if($blocking)
    {
      fcntl($fh, F_SETFL, $flags & ~O_NONBLOCK) ||
        croak "Can't make socket blocking: $!\n";
    }
    else
    {
      fcntl($fh, F_SETFL, $flags | O_NONBLOCK) ||
        croak "Can't make socket nonblocking: $!\n";
    }     
  }
}

sub _hexdump
{
  my($data) = join('', @_);

  my($ret, $hex, $ascii, $len, $i);

  $len = length($data);

  for($i = 0; $i < $len; $i++)
  {
    if($i > 0)
    {
      if($i % 4 == 0)
      {
        $hex .= ' ';
      }

      if($i % 16 == 0)
      {
        $ret .= "$hex$ascii\n";
        $ascii = $hex = '';
      }
    }

    $hex .= sprintf("%02x ", ord(substr($data, $i, 1)));
    
    $ascii .= sprintf("%c", (ord(substr($data, $i, 1)) > 31 and
                             ord(substr($data, $i, 1)) < 127) ?
                             ord(substr($data, $i, 1)) : 46);
  }

  if(length($hex) < 50)
  {
    $hex .= ' ' x (50 - length($hex));
  }

  $ret .= "$hex  $ascii\n";

  return $ret;
}

1;
