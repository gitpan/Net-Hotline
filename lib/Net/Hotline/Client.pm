package Net::Hotline::Client;

## Copyright(c) 1998 by John C. Siracusa.  All rights reserved.  This program
## is free software; you can redistribute it and/or modify it under the same
## terms as Perl itself.

use Carp;
use IO::File;
use IO::Socket;
use AutoLoader 'AUTOLOAD';
use Net::Hotline::User;
use Net::Hotline::Task;
use Net::Hotline::Shared;
use Net::Hotline::FileListItem;
use Net::Hotline::FileInfoItem;
use Net::Hotline::Protocol::Packet;
use Net::Hotline::Protocol::Header;
use Net::Hotline::Constants
  qw(HTLC_CHECKBYTES HTLC_DATA_CHAT HTLC_DATA_DESTDIR HTLC_DATA_DIRECTORY
     HTLC_DATA_FILE HTLC_DATA_FILE_RENAME HTLC_DATA_ICON HTLC_DATA_LOGIN
     HTLC_DATA_MSG HTLC_DATA_NICKNAME HTLC_DATA_OPTION HTLC_DATA_PASSWORD
     HTLC_DATA_RFLT HTLC_DATA_SOCKET HTLC_DEFAULT_ICON HTLC_DEFAULT_LOGIN
     HTLC_DEFAULT_NICK HTLC_EWOULDBLOCK HTLC_HDR_CHAT HTLC_HDR_FILE_DELETE
     HTLC_HDR_FILE_GET HTLC_HDR_FILE_GETINFO HTLC_HDR_FILE_LIST
     HTLC_HDR_FILE_MKDIR HTLC_HDR_FILE_MOVE HTLC_HDR_FILE_SETINFO
     HTLC_HDR_LOGIN HTLC_HDR_MSG HTLC_HDR_NEWS_GETFILE HTLC_HDR_NEWS_POST
     HTLC_HDR_USER_CHANGE HTLC_HDR_USER_GETINFO HTLC_HDR_USER_GETLIST
     HTLC_HDR_USER_KICK HTLC_MAGIC HTLC_MAGIC_LEN HTLC_MAX_PATHLEN
     HTLC_NEWLINE HTLC_TASK_FILE_DELETE HTLC_TASK_FILE_GET
     HTLC_TASK_FILE_INFO HTLC_TASK_FILE_LIST HTLC_TASK_FILE_MKDIR
     HTLC_TASK_FILE_MOVE HTLC_TASK_KICK HTLC_TASK_LOGIN HTLC_TASK_NEWS
     HTLC_TASK_NEWS_POST HTLC_TASK_SEND_MSG HTLC_TASK_SET_INFO
     HTLC_TASK_USER_INFO HTLC_TASK_USER_LIST HTLS_DATA_FILE_COMMENT
     HTLS_DATA_NEWS_POST HTLS_HDR_AGREEMENT HTLS_HDR_CHAT HTLS_HDR_MSG
     HTLS_HDR_NEWS_POST HTLS_HDR_PCHAT_INVITE HTLS_HDR_PCHAT_SUBJECT
     HTLS_HDR_PCHAT_USER_CHANGE HTLS_HDR_PCHAT_USER_LEAVE
     HTLS_HDR_POLITE_QUIT HTLS_HDR_TASK HTLS_HDR_USER_CHANGE
     HTLS_HDR_USER_LEAVE HTLS_MAGIC HTLS_MAGIC_LEN HTLS_TCPPORT
     HTXF_BUFSIZE HTXF_MAGIC HTXF_RFLT_MAGIC HTXF_TCPPORT PATH_SEPARATOR
     SIZEOF_HL_FILE_FORK_HDR SIZEOF_HL_FILE_XFER_HDR SIZEOF_HL_LONG_HDR
     SIZEOF_HL_PROTO_HDR SIZEOF_HL_SHORT_HDR SIZEOF_HL_TASK_FILLER);

use strict;

$Net::Hotline::Client::VERSION = '0.51';
$Net::Hotline::Client::DEBUG   = 0;

# Macbinary CRC perl code lifted Convert::BinHex by Eryq (eryq@enteract.com)
# An array useful for CRC calculations that use 0x1021 as the "seed":
my(@MAGIC) = (
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
);

#
# Forward declarations necessary to compile non-autoloaded code
#

sub _next_seqnum;
sub recv_file;
sub req_news;
sub req_userlist;

1;

#
# Non-autoloaded object methods
#

sub new
{
  my($class) = shift;
  my($self);

  $self =
  {
    'NICK'         => undef,
    'LOGIN'        => undef,
    'COLOR'        => undef,
    'SERVER_ADDR'  => undef,

    'SOCKET'       => undef,
    'BLOCKING'     => 1,
    'SERVER'       => undef,
    'SEQNUM'       => 1,

    'USER_LIST'    => undef,
    'NEWS'         => undef,
    'FILES'        => undef,
    'AGREEMENT'    => undef,
    
    'HANDLERS'  =>
    {
      'AGREEMENT'     => undef,
      'CHAT'          => undef,
      'CHAT_ACTION'   => undef,
      'COLOR'         => undef,
      'EVENT'         => undef,
      'FILE_DELETE'   => undef,
      'FILE_GET'      => undef,
      'FILE_GET_INFO' => undef,
      'FILE_LIST'     => undef,
      'FILE_MKDIR'    => undef,
      'FILE_MOVE'     => undef,
      'FILE_SET_INFO' => undef,
      'ICON'          => undef,
      'JOIN'          => undef,
      'KICK'          => undef,
      'LEAVE'         => undef,
      'LOGIN'         => undef,
      'MSG'           => undef,
      'NEWS'          => undef,
      'NEWS_POST'     => undef,
      'NEWS_POSTED'   => undef,
      'NICK'          => undef,
      'QUIT'          => undef,
      'SEND_MSG'      => undef,
      'SERVER_MSG'    => undef,
      'TASK_ERROR'    => undef,
      'USER_GETINFO'  => undef,
      'USER_LIST'     => undef
    },
    
    'DEFAULT_HANDLERS' => 1,
    'EVENT_TIMING'     => 1,
    'PATH_SEPARATOR'   => ':',
    'DOWNLOADS_DIR'    => '',
    'HTXF_BUFSIZE'     => HTXF_BUFSIZE,
    'LAST_ACTIVITY'    => time(),
    'TASKS'            => undef
  };

  bless  $self, $class;
  return $self;
}

sub agreement { $_[0]->{'AGREEMENT'} }

sub blocking
{
  my($self, $blocking) = @_;
 
  return $self->{'BLOCKING'}  unless(defined($blocking));
  $self->{'BLOCKING'} = (($blocking) ? 1 : 0);
  return $self->{'BLOCKING'};
}

sub default_handlers
{
  my($self, $arg) = @_;
  $self->{'DEFAULT_HANDLERS'} = $arg  if(defined($arg));
  return $self->{'DEFAULT_HANDLERS'};
}

sub downloads_dir
{
  my($self, $dir) = @_;
  $self->{'DOWNLOADS_DIR'} = $dir  if(-d $dir);
  return $self->{'DOWNLOADS_DIR'};
}

sub event_timing
{
  my($self, $secs) = @_;
  
  if(defined($secs))
  {
    croak "Bad argument to event_timing()\n"  if($secs =~ /[^0-9.]/);
    $self->{'EVENT_TIMING'} = $secs;
  }

  return $self->{'EVENT_TIMING'};
}

sub files { $_[0]->{'FILES'} }

sub handlers
{
  my($self) = shift;
  return $self->{'HANDLERS'};
}

sub xfer_bufsize
{
  my($self, $size) = @_;
  $self->{'HTXF_BUFSIZE'} = $size  if($size =~ /^\d+$/);
  return $self->{'HTXF_BUFSIZE'};
}

sub last_activity
{
  my($self) = shift;
  return $self->{'LAST_ACTIVITY'};
}

sub news
{
  my($self) = shift;

  return $self->{'NEWS'}
}

sub path_separator
{
  my($self, $separator) = @_;
  $self->{'PATH_SEPARATOR'} = $separator  if($separator =~ /^.$/);
  return $self->{'PATH_SEPARATOR'};
}

sub server
{
  my($self) = shift;

  if(defined($self))
  {
    return $self->{'SERVER_ADDR'};
  }
  return(undef);
}

sub userlist { $_[0]->{'USER_LIST'} }

sub connect
{
  my($self, $server) = @_;

  my($address, $port);
  
  if(($address = $server) =~ s/^([^ :]+)(?:[: ](\d+))?$/$1/)
  {
    $port = $2 || HTLS_TCPPORT;
  }
  else
  {
    croak("Bad server address: $server\n");
  }
  
  $self->{'SERVER'} = 
    IO::Socket::INET->new(PeerAddr =>$address,
                          PeerPort =>$port,
                          Timeout  =>5,
                          Proto    =>'tcp') || return(undef);

  return(undef)  unless($self->{'SERVER'});

  $self->{'SERVER'}->autoflush(1);

  $self->{'SERVER_ADDR'} = "$address";
  
  $self->{'SERVER_ADDR'} .= ":$port"
    if($port !=  HTLS_TCPPORT);

  return(1);
}

sub disconnect
{
  my($self) = shift;
  
  if($self->{'SERVER'} && $self->{'SERVER'}->opened())
  {
    $self->{'SERVER'}->close();
    return(1);
  }
  return(undef);
}

sub login
{
  my($self, %args) = @_;

  my($nick, $login, $password, $icon);
  my($proto_header, $data, $response, $task_num);

  my($server) = $self->{'SERVER'};
  
  unless($server->opened())
  {
    croak("login() called before connect()");
  }

  $nick  = $args{'Nickname'} || HTLC_DEFAULT_NICK;
  $login = $args{'Login'}    || HTLC_DEFAULT_LOGIN;
  $icon  = $args{'Icon'}     || HTLC_DEFAULT_ICON;
  $password = $args{'Password'};

  $self->{'NICK'}  = $nick;
  $self->{'LOGIN'} = $login;
  $self->{'ICON'}  = $icon;

  _write($server, \HTLC_MAGIC, HTLC_MAGIC_LEN);
  _read($server, \$response, HTLS_MAGIC_LEN);

  if($response ne HTLS_MAGIC)
  {
    croak("Handshake failed.  Not a hotline server?");
  }

  my($enc_login)    = _encode($login);
  my($enc_password) = _encode($password);

  $proto_header = new Net::Hotline::Protocol::Header;
  
  $proto_header->type(HTLC_HDR_LOGIN);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_PROTO_HDR + 
                     length($enc_login) +
                     length($enc_password) +
                     length($nick));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0004) .                 # Num atoms

          pack("n", HTLC_DATA_LOGIN) .        # Atom type
          pack("n", length($enc_login)) .     # Atom length
          $enc_login .                        # Atom data

          pack("n", HTLC_DATA_PASSWORD) .     # Atom type
          pack("n", length($enc_password)) .  # Atom length
          $enc_password .                     # Atom data

          pack("n", HTLC_DATA_NICKNAME) .     # Atom type
          pack("n", length($nick)) .          # Atom length
          $nick .                             # Atom data

          pack("n", HTLC_DATA_ICON) .         # Atom type
          pack("n", 2) .                      # Atom length
          pack("n", $icon);                   # Atom data

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: LOGIN - $task_num\n");
    $self->{'TASKS'}->{$task_num} =
      new Net::Hotline::Task($task_num, HTLC_TASK_LOGIN, time());
  }
  else { return(undef) }
  
  $self->req_userlist();
  $self->req_news();

  return($task_num);
}

sub run
{
  my($self) = shift;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data_ref, $type, $ret);

  my($packet) = new Net::Hotline::Protocol::Packet;

  _set_blocking($server, $self->{'BLOCKING'});

  while($ret = $packet->read_parse($server, $self->{'BLOCKING'}))
  {
    $type = $packet->{'TYPE'};

    if($ret == HTLC_EWOULDBLOCK) # Idle event
    {
      if(defined($self->{'HANDLERS'}->{'EVENT'}))
      {
        &{$self->{'HANDLERS'}->{'EVENT'}}($self, 1);
      }

      select(undef, undef, undef, $self->{'EVENT_TIMING'});
      next;
    }

    $self->{'LAST_ACTIVITY'} = time();

    if(defined($self->{'HANDLERS'}->{'EVENT'})) # Non-idle event
    {
      &{$self->{'HANDLERS'}->{'EVENT'}}($self, 0);
    }
      
    _debug("Packet type = $type\n");

    if($type == HTLS_HDR_USER_LEAVE)
    {
      # Hotline server *BUG* - you may get a "disconnect" packet for a
      # socket _before_ you get the "connect" packet for that socket!
      # In fact, the "connect" packet will never arrive in this case.

      if(defined($packet->{'SOCKET'}) &&
         defined($self->{'USER_LIST'}->{$packet->{'SOCKET'}}))
      {
        my($user) = $self->{'USER_LIST'}->{$packet->{'SOCKET'}};
  
        if(defined($self->{'HANDLERS'}->{'LEAVE'}))
        {
          &{$self->{'HANDLERS'}->{'LEAVE'}}($self, $user);
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {       
          print "USER LEFT: ", $user->nick(), "\n";
        }

        delete $self->{'USER_LIST'}->{$packet->{'SOCKET'}};
      }
    }
    elsif($type == HTLS_HDR_TASK)
    {
      my($task) = $self->{'TASKS'}->{$packet->{'TASK_NUM'}};

      my($task_type) = $task->type();

      $task->finish(time());

      if(defined($packet->{'TASK_ERROR'}))
      {
        $task->error(1);
        $task->error_text($packet->{'TASK_ERROR'});

        if(defined($self->{'HANDLERS'}->{'TASK_ERROR'}))
        {
          &{$self->{'HANDLERS'}->{'TASK_ERROR'}}($self, $task);
        }
        else
        {
          print "TASK ERROR(", $task->num(), ':', $task->type(),
                ") ", $task->error_text(), "\n";
        }
      }
      else
      {
        $task->error(0);

        if($task_type == HTLC_TASK_USER_LIST && defined($packet->{'USER_LIST'}))
        {
          $self->{'USER_LIST'} = $packet->{'USER_LIST'};

          if(defined($self->{'HANDLERS'}->{'USER_LIST'}))
          {
            &{$self->{'HANDLERS'}->{'USER_LIST'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "GET USER LIST: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_FILE_LIST)
        {
          my($path);

          $task->path("")  unless(length($task->path));
          $path = $task->path();

          $self->{'FILES'}->{$path} = $packet->{'FILE_LIST'};

          if(defined($self->{'HANDLERS'}->{'FILE_LIST'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_LIST'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "GET FILE LIST: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_NEWS && defined($packet->{'DATA'}))
        {
          my(@news) = split(/_{58}/, $packet->{'DATA'});

          $self->{'NEWS'} = \@news;
          
          if(defined($self->{'HANDLERS'}->{'NEWS'}))
          {
            &{$self->{'HANDLERS'}->{'NEWS'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "GET NEWS: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_USER_INFO && defined($packet->{'DATA'}))
        {
          my($user) = $self->{'USER_LIST'}->{$task->socket()};
          
          $user->info($packet->{'DATA'});

          if(defined($self->{'HANDLERS'}->{'USER_GETINFO'}))
          {
            &{$self->{'HANDLERS'}->{'USER_GETINFO'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "GET USER INFO: Task complete.\n";
          }

          _debug("USER_GETINFO for: $packet->{'NICK'} (", $task->socket(), ")\n",
                 $packet->{'DATA'}, "\n");
        }
        elsif($task_type == HTLC_TASK_FILE_INFO)
        {
          my($path, $file_info);

          $task->path("")  unless(length($task->path));
          $path = $task->path();

          $file_info = $self->{'FILE_GET_INFO'}->{$path} = new Net::Hotline::FileInfoItem();
          
          $file_info->icon($packet->{'FILE_ICON'});
          $file_info->type($packet->{'FILE_TYPE'});
          $file_info->creator($packet->{'FILE_CREATOR'});
          $file_info->size($packet->{'FILE_SIZE'});
          $file_info->name($packet->{'FILE_NAME'});
          $file_info->comment($packet->{'FILE_COMMENT'});
          $file_info->ctime($packet->{'FILE_CTIME'});
          $file_info->mtime($packet->{'FILE_MTIME'});
        
          if(defined($self->{'HANDLERS'}->{'FILE_GET_INFO'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_GET_INFO'}}($self, $task, $file_info);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "FILE_GET_INFO: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_LOGIN)
        {
          if(defined($self->{'HANDLERS'}->{'LOGIN'}))
          {
            &{$self->{'HANDLERS'}->{'LOGIN'}}($self);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "LOGIN: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_NEWS_POST)
        {
          if(defined($self->{'HANDLERS'}->{'NEWS_POST'}))
          {
            &{$self->{'HANDLERS'}->{'NEWS_POST'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "POST NEWS: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_SEND_MSG)
        {
          if(defined($self->{'HANDLERS'}->{'SEND_MSG'}))
          {
            &{$self->{'HANDLERS'}->{'SEND_MSG'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "SEND MSG: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_KICK)
        {
          if(defined($self->{'HANDLERS'}->{'KICK'}))
          {
            &{$self->{'HANDLERS'}->{'KICK'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "KICK: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_SET_INFO)
        {
          if(defined($self->{'HANDLERS'}->{'FILE_SET_INFO'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_SET_INFO'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "SET INFO: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_FILE_DELETE)
        {
          if(defined($self->{'HANDLERS'}->{'FILE_DELETE'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_DELETE'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "DELETE FILE: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_FILE_MKDIR)
        {
          if(defined($self->{'HANDLERS'}->{'FILE_MKDIR'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_MKDIR'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "CREATE FOLDER: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_FILE_MOVE)
        {
          if(defined($self->{'HANDLERS'}->{'FILE_MOVE'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_MOVE'}}($self, $task);
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "MOVE FILE: Task complete.\n";
          }
        }
        elsif($task_type == HTLC_TASK_FILE_GET)
        {
          my($size) = $packet->{'HTXF_SIZE'};
          my($ref)  = $packet->{'HTXF_REF'};

          if(defined($self->{'HANDLERS'}->{'FILE_GET'}))
          {
            &{$self->{'HANDLERS'}->{'FILE_GET'}}($self, $task, $ref, $size);
          }
          else
          {
            print "GET FILE: Starting download (ref = $ref, size = $size)\n"
              if($self->{'DEFAULT_HANDLERS'});

            $self->recv_file($task, $ref, $size);
          }
        }
      }
      # Reclaim memory
      delete $self->{'TASKS'}->{$packet->{'TASK_NUM'}};
    }
    elsif($type == HTLS_HDR_AGREEMENT)
    {
      if(defined($packet->{'DATA'}))
      {
        if(defined($self->{'HANDLERS'}->{'AGREEMENT'}))
        {
          &{$self->{'HANDLERS'}->{'AGREEMENT'}}($self, \$packet->{'DATA'});
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {
          print "AGREEMENT:\n", $packet->{'DATA'}, "\n";
        }
      }
    }
    elsif($type == HTLS_HDR_MSG)
    {
      my($user) = $self->{'USER_LIST'}->{$packet->{'SOCKET'}};

      # User-to-user message
      if(defined($user) && defined($packet->{'DATA'}))
      {
        if(defined($self->{'HANDLERS'}->{'MSG'}))
        {
          &{$self->{'HANDLERS'}->{'MSG'}}($self, $user, \$packet->{'DATA'});
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {
          print "MSG: ", $user->nick(), "(", 
                         $packet->{'SOCKET'}, ") ", 
                         $packet->{'DATA'}, "\n";
        }
      }
      elsif(defined($packet->{'DATA'})) # Server message
      {
        if(defined($self->{'HANDLERS'}->{'SERVER_MSG'}))
        {
          &{$self->{'HANDLERS'}->{'SERVER_MSG'}}($self, \$packet->{'DATA'});
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {
          print "SERVER MSG: ", $packet->{'DATA'}, "\n";
        }
      }
    }
    elsif($type == HTLS_HDR_USER_CHANGE)
    {
      if(defined($packet->{'NICK'}) && defined($packet->{'SOCKET'}) &&
         defined($packet->{'ICON'}) && defined($packet->{'COLOR'}))
      {
        if(defined($self->{'USER_LIST'}->{$packet->{'SOCKET'}}))
        {
          my($user) = $self->{'USER_LIST'}->{$packet->{'SOCKET'}};

          if($user->nick() ne $packet->{'NICK'})
          {
            my($old_nick) = $user->nick();

            $user->nick($packet->{'NICK'});
            
            if(defined($self->{'HANDLERS'}->{'NICK'}))
            {
              &{$self->{'HANDLERS'}->{'NICK'}}($self, $user, $old_nick, $user->nick());
            }
            elsif($self->{'DEFAULT_HANDLERS'})
            {
              print "USER CHANGE: $old_nick is now known as ", $user->nick(), "\n";
            }
          }
          elsif($user->icon() ne $packet->{'ICON'})
          {
            my($old_icon) = $user->icon();

            $user->icon($packet->{'ICON'});
            
            if(defined($self->{'HANDLERS'}->{'ICON'}))
            {
              &{$self->{'HANDLERS'}->{'ICON'}}($self, $user, $old_icon, $user->icon());
            }
            elsif($self->{'DEFAULT_HANDLERS'})
            {
              print "USER CHANGE: ", $user->nick(),
                    " icon changed from $old_icon to ",
                    $user->icon(), "\n";
            }
          }
          elsif($user->color() ne $packet->{'COLOR'})
          {
            my($old_color) = $user->color();

            $user->color($packet->{'COLOR'});
            
            if(defined($self->{'HANDLERS'}->{'COLOR'}))
            {
              &{$self->{'HANDLERS'}->{'COLOR'}}($self, $user, $old_color, $user->color());
            }
            elsif($self->{'DEFAULT_HANDLERS'})
            {
              print "USER CHANGE: ", $user->nick(),
                    " color changed from $old_color to ",
                    $user->color(), "\n";
            }
          }
        }
        else
        {
          $self->{'USER_LIST'}->{$packet->{'SOCKET'}} =
            new Net::Hotline::User($packet->{'SOCKET'},
                              $packet->{'NICK'},
                              undef,
                              $packet->{'ICON'},
                              $packet->{'COLOR'});
        
          if(defined($self->{'HANDLERS'}->{'JOIN'}))
          {
            &{$self->{'HANDLERS'}->{'JOIN'}}($self, $self->{'USER_LIST'}->{$packet->{'SOCKET'}});
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "JOINED:\n",
                  "  Nick: $packet->{'NICK'}\n",
                  "  Icon: $packet->{'ICON'}\n",
                  "Socket: $packet->{'SOCKET'}\n",
                  " Color: $packet->{'COLOR'}\n";
          }
        }
      }
    }
    elsif($type == HTLS_HDR_CHAT)
    {
      if(defined($packet->{'DATA'}))
      {
        $packet->{'DATA'} =~ s/^\n//s;

        # Chat "action"
        if($packet->{'DATA'} =~ /^ \*\*\* /)
        {
          if(defined($self->{'HANDLERS'}->{'CHAT_ACTION'}))
          {
            &{$self->{'HANDLERS'}->{'CHAT_ACTION'}}($self, \$packet->{'DATA'});
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            $packet->{'DATA'} =~ s/^@{[HTLC_NEWLINE]}//os;
            print "CHAT ACTION: ", $packet->{'DATA'}, "\n";
          }        
        }
        else # Regular chat
        {
          if(defined($self->{'HANDLERS'}->{'CHAT'}))
          {
            &{$self->{'HANDLERS'}->{'CHAT'}}($self, \$packet->{'DATA'});
          }
          elsif($self->{'DEFAULT_HANDLERS'})
          {
            print "CHAT: ", $packet->{'DATA'}, "\n";
          }
        }
      }
    }
    elsif($type == HTLS_HDR_NEWS_POST)
    {
      my($post) = $packet->{'DATA'};

      if(defined($post))
      {
        $post =~ s/@{[HTLC_NEWLINE]}/\n/osg;
        $post =~ s/_{58}//sg;

        if(defined($self->{'HANDLERS'}->{'NEWS_POSTED'}))
        {
          &{$self->{'HANDLERS'}->{'NEWS_POSTED'}}($self, \$post);
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {
          print "NEWS: New post made.\n";
        }
      }
    }
    elsif($type == HTLS_HDR_POLITE_QUIT ||
          $type eq 'DISCONNECTED')
    {
      if(defined($packet->{'DATA'}))
      {
        if(defined($self->{'HANDLERS'}->{'QUIT'}))
        {
          &{$self->{'HANDLERS'}->{'QUIT'}}($self, \$packet->{'DATA'});
        }
        elsif($self->{'DEFAULT_HANDLERS'})
        {
          print "CONNECTION CLOSED: ", $packet->{'DATA'}, "\n";
        }
      }
      elsif($self->{'DEFAULT_HANDLERS'})
      {
        print "CONNECTION CLOSED\n";
      }

      $self->disconnect();
      return(0);
    }
    elsif($type == HTLS_HDR_PCHAT_INVITE)
    {
      # To do...
    }
    elsif($type == HTLS_HDR_PCHAT_USER_CHANGE)
    {
      # To do...
    }
    elsif($type == HTLS_HDR_PCHAT_USER_LEAVE)
    {
      # To do...
    }
    elsif($type == HTLS_HDR_PCHAT_SUBJECT)
    {
      # To do...
    }
  }

  _set_blocking($server, 1);
}

sub _handler
{
  my($self, $code_ref, $type) = @_;
  
  if(defined($code_ref))
  {
    if(ref($code_ref) eq 'CODE')
    {
      $self->{'HANDLERS'}->{$type} = $code_ref;
    }
  }
  
  return $self->{'HANDLERS'}->{$type};
}

sub _next_seqnum
{
  my($self) = shift;

  return $self->{'SEQNUM'}++;
}

sub agreement_handler     { return _handler($_[0], $_[1], 'AGREEMENT')     }
sub chat_handler          { return _handler($_[0], $_[1], 'CHAT')          }
sub chat_action_handler   { return _handler($_[0], $_[1], 'CHAT_ACTION')   }
sub color_handler         { return _handler($_[0], $_[1], 'COLOR')         }
sub event_loop_handler    { return _handler($_[0], $_[1], 'EVENT')         }
sub delete_file_handler   { return _handler($_[0], $_[1], 'FILE_DELETE')   }
sub get_file_handler      { return _handler($_[0], $_[1], 'FILE_GET')      }
sub file_info_handler     { return _handler($_[0], $_[1], 'FILE_GET_INFO') }
sub file_list_handler     { return _handler($_[0], $_[1], 'FILE_LIST')     }
sub new_folder_handler    { return _handler($_[0], $_[1], 'FILE_MKDIR')    }
sub move_file_handler     { return _handler($_[0], $_[1], 'FILE_MOVE')     }
sub set_file_info_handler { return _handler($_[0], $_[1], 'FILE_SET_INFO') }
sub icon_handler          { return _handler($_[0], $_[1], 'ICON')          }
sub join_handler          { return _handler($_[0], $_[1], 'JOIN')          }
sub kick_handler          { return _handler($_[0], $_[1], 'KICK')          }
sub leave_handler         { return _handler($_[0], $_[1], 'LEAVE')         }
sub login_handler         { return _handler($_[0], $_[1], 'LOGIN')         }
sub msg_handler           { return _handler($_[0], $_[1], 'MSG')           }
sub news_handler          { return _handler($_[0], $_[1], 'NEWS')          }
sub post_news_handler     { return _handler($_[0], $_[1], 'NEWS_POST')     }
sub news_posted_handler   { return _handler($_[0], $_[1], 'NEWS_POSTED')   }
sub nick_handler          { return _handler($_[0], $_[1], 'NICK')          }
sub quit_handler          { return _handler($_[0], $_[1], 'QUIT')          }
sub send_msg_handler      { return _handler($_[0], $_[1], 'SEND_MSG')      }
sub server_msg_handler    { return _handler($_[0], $_[1], 'SERVER_MSG')    }
sub task_error_handler    { return _handler($_[0], $_[1], 'TASK_ERROR')    }
sub user_info_handler     { return _handler($_[0], $_[1], 'USER_GETINFO')  }
sub user_list_handler     { return _handler($_[0], $_[1], 'USER_LIST')     }

#
# Package subroutines
#

sub version { $Net::Hotline::Client::VERSION }

sub debug
{ 
  if(@_ == 1 && !ref($_[0]))
  {
    $Net::Hotline::Client::DEBUG = ($_[0]) ? 1 : 0;
  }
  elsif(@_ == 2 && ref($_[0]) eq 'Net::Hotline::Client')
  {
    $Net::Hotline::Client::DEBUG = ($_[1]) ? 1 : 0;
  }

  return $Net::Hotline::Client::DEBUG;
}

__END__

#
# Auto-loaded methods and subroutines
#

sub req_filelist
{
  my($self, $path) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data, $task_num, @path_parts, $data_length, $length, $save_path);

  if($path)
  {
    $path =~ s/$self->{'PATH_SEPARATOR'}$//;
    $save_path = $path;
    @path_parts = split($self->{'PATH_SEPARATOR'}, $path);
    $path =~ s/$self->{'PATH_SEPARATOR'}//g;
    
    if(length($path) > HTLC_MAX_PATHLEN)
    {
      croak("Maximum path length exceeded.");
    }

    # 2 null bytes, the 1 byte for length, and the length of the path part
    $data_length = (3 * scalar(@path_parts)) + length($path);
    $length = SIZEOF_HL_LONG_HDR + $data_length;
  }
  else
  {
    $length = 2; # Two null bytes
  }

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_FILE_LIST);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len($length);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header();
  
  if($path)
  {
    $data .= pack("n", 0x0001) .              # Number of atoms
             pack("n", HTLC_DATA_DIRECTORY) . # Atom type
             pack("n", $data_length + 2);     # Atom length

    $data .= pack("n", scalar(@path_parts));  # Number of path parts

    my($path_part);

    foreach $path_part (@path_parts)          # Path parts data
    {
      if(length($path_part) > HTLC_MAX_PATHLEN)
      {
        croak("Maximum path part length exceeded.");
      }

      $data .= pack("n", 0x0000) .            # 2 null bytes
               pack("c", length($path_part)) .# Length
               $path_part;                    # Path part
    }
  }
  else
  {
    $data .=  pack("n", 0x0000);
  }

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: FILE_LIST - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_FILE_LIST, time(), undef, $save_path);
    return($task_num);
  }
  else { return(undef) }
}

sub req_userinfo
{
  my($self, $socket) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data, $task_num);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_USER_GETINFO);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_LONG_HDR);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0001) .                 # Number of atoms

          pack("n", HTLC_DATA_SOCKET) .       # Atom type
          pack("n", 0x0002) .                 # Atom length
          pack("n", $socket);                 # Atom data

  _debug(_hexdump($data));
  
  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: USER_GETINFO - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_USER_INFO, time(), $socket);
    return($task_num);
  }
  else { return(undef) }
}

sub req_fileinfo
{
  return _file_action_simple($_[0], $_[1], HTLC_HDR_FILE_GETINFO, HTLC_TASK_FILE_INFO, 'GET FILE INFO');
}

sub delete_file
{
  return _file_action_simple($_[0], $_[1], HTLC_HDR_FILE_DELETE, HTLC_TASK_FILE_DELETE, 'DELETE FILE');
}

sub new_folder
{
  return _file_action_simple($_[0], $_[1], HTLC_HDR_FILE_MKDIR, HTLC_TASK_FILE_MKDIR, 'NEW FOLDER');
}

sub get_file
{
  return _file_action_simple($_[0], $_[1], HTLC_HDR_FILE_GET, HTLC_TASK_FILE_GET, 'GET FILE');
}

sub get_file_resume
{
  my($self, $path) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened() && length($path));

  my($local_sep) = PATH_SEPARATOR;
  my($remote_sep) = $self->{'PATH_SEPARATOR'};

  my($dest_dir) = $self->{'DOWNLOADS_DIR'};
  $dest_dir .= $local_sep  if($dest_dir =~ /\S/ && $dest_dir !~ /$local_sep$/o);

  my($data, $task_num) = _file_action_packet_stub($self, $path, HTLC_HDR_FILE_GET);

  my($data_file, $rsrc_file);

  ($data_file = $path) =~ /$remote_sep([^$remote_sep]+)$/;
  $data_file = "$dest_dir$1";

  return(undef) unless(-e $data_file);

  $rsrc_file = "$data_file.rsrc";

  my($data_pos) = -s $data_file;
  my($rsrc_pos) = -s $rsrc_file;

  my($length) = unpack("N", substr($data, 16, 4));
  $length += 78;

  # Set new length
  substr($data, 12, 4)  = pack("N", $length);
  substr($data, 16, 4) = pack("N", $length);

  # Set new num atoms
  my($num_atoms) = unpack("n", substr($data, 20, 2));
  substr($data, 20, 2) = pack("n", $num_atoms + 1);

  # 00 CB 00 4A  52 46 4C 54  00 01 00 00  00 00 00 00  ...JRFLT........
  # 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
  # 00 00 00 00  00 00 00 00  00 00 00 00  00 02 44 41  ..............DA
  # 54 41 00 00  1B EA 00 00  00 00 00 00  00 00 4D 41  TA............MA
  # 43 52 00 00  00 00 00 00  00 00 00 00  00 00        CR............
  my($more_data) = pack("x78");
  
  substr($more_data, 0, 2) = pack("n", HTLC_DATA_RFLT);
  substr($more_data, 2, 2) = pack("n", 0x004A);
  substr($more_data, 4, 4) = HTXF_RFLT_MAGIC;
  substr($more_data, 8, 2) = pack("n", 0x0001);

  substr($more_data, 45, 1) = pack("c", 0x02);
  substr($more_data, 46, 4) = 'DATA';
  substr($more_data, 50, 4) = pack("N", $data_pos);

  substr($more_data, 62, 4) = 'MACR';
  substr($more_data, 66, 4) = pack("N", $rsrc_pos);

  $data .= $more_data;

  _debug(_hexdump($data));

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: GET FILE - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_FILE_GET, time(), undef, $path);
    return($task_num);
  }
  else { return(undef) }
}

sub _file_action_packet_stub
{
  my($self, $path, $type) = @_;

  my($data, @path_parts, $length, $file, $dir_len);

  $path =~ s/$self->{'PATH_SEPARATOR'}$//;
  @path_parts = split($self->{'PATH_SEPARATOR'}, $path);
  $path =~ s/$self->{'PATH_SEPARATOR'}//g;
   
  if(length($path) > HTLC_MAX_PATHLEN)
  {
    croak("Maximum path length exceeded.");
  }

  $file = pop(@path_parts);

  # File part: 2 bytes num atoms, 2 bytes for atom len,
  # 2 bytes for file name length
  $length = (2 + 2 + 2 + length($file));
    
  if(@path_parts)
  {
    $dir_len = length(join('', @path_parts));
    # Path part: 2 bytes for atom type, 2 bytes for atom len
    # 2 bytes for num path components, and 2 null bytes and
    # 1 byte path part length for each path part
    $length += (2 + 2 + 2 + (3 * @path_parts));
    $length += $dir_len;
  }

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type($type);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len($length);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header();

  $data .= pack("n", (@path_parts) ? 2 : 1) . # Number of atoms
           pack("n", HTLC_DATA_FILE) .        # Atom type
           pack("n", length($file)) .         # Atom length
           $file;                             # Atom data

  if(@path_parts)
  {
    $data .= pack("n", HTLC_DATA_DIRECTORY) . # Atom type
             pack("n", $dir_len + 2 + (3 * @path_parts)) .
                                              # Atom length
             pack("n", scalar(@path_parts));  # Num path parts

    my($path_part);

    foreach $path_part (@path_parts)          # Path parts data
    {
      if(length($path_part) > HTLC_MAX_PATHLEN)
      {
        croak("Maximum path part length exceeded.");
      }

      $data .= pack("n", 0x0000) .            # 2 null bytes
               pack("c", length($path_part)) .# Length
               $path_part;                    # Path part
    }
  }
  
  return($data, $proto_header->seq());
}

sub _file_action_simple
{
  my($self, $path, $type, $task_type, $task_name) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened() && length($path));

  my($data, $task_num) = _file_action_packet_stub($self, $path, $type);

  _debug(_hexdump($data));

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: $task_name - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, $task_type, time(), undef, $path);
    return($task_num);
  }
  else { return(undef) }
}

sub move
{
  my($self, $src_path, $dest_path) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened() && length($src_path)  && length($dest_path));

  my($data, $task_num, $length, $num_atoms);
  my(@src_path_parts, $save_src_path, $src_file, $src_dir_len);
  my(@dest_path_parts, $save_dest_path, $dest_dir_len);

  # Source:

  $src_path =~ s/$self->{'PATH_SEPARATOR'}$//;
  $save_src_path = $src_path;
  @src_path_parts = split($self->{'PATH_SEPARATOR'}, $src_path);
  $src_path =~ s/$self->{'PATH_SEPARATOR'}//g;
   
  if(length($src_path) > HTLC_MAX_PATHLEN)
  {
    croak("Maximum path length exceeded.");
  }

  $src_file = pop(@src_path_parts);

  # Source part: 2 bytes num atoms, 2 bytes for atom type,
  # 2 bytes for file name length
  $length = (2 + 2 + 2 + length($src_file));
    
  if(@src_path_parts)
  {
    $src_dir_len = length(join('', @src_path_parts));
    # Path part: 2 bytes for atom type, 2 bytes for atom len
    # 2 bytes for num path components, and 2 null bytes and
    # 1 byte path part length for each path part
    $length += (2 + 2 + 2 + (3 * @src_path_parts));
    $length += $src_dir_len;
  }

  # Destination:

  $dest_path =~ s/$self->{'PATH_SEPARATOR'}$//;
  $save_dest_path = $dest_path;
  @dest_path_parts = split($self->{'PATH_SEPARATOR'}, $dest_path);
  $dest_path =~ s/$self->{'PATH_SEPARATOR'}//g;
   
  if(length($dest_path) > HTLC_MAX_PATHLEN)
  {
    croak("Maximum path length exceeded.");
  }
    
  if(@dest_path_parts)
  {
    $dest_dir_len = length(join('', @dest_path_parts));
    # Path part: 2 bytes for atom type, 2 bytes for atom len
    # 2 bytes for num path components, and 2 null bytes and
    # 1 byte path part length for each path part
    $length += (2 + 2 + 2 + (3 * @dest_path_parts));
    $length += $dest_dir_len;
  }

  # Build packet

  if(@src_path_parts && @dest_path_parts) { $num_atoms = 3 }
  else                                    { $num_atoms = 2 }

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_FILE_MOVE);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len($length);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header();

  $data .= pack("n", $num_atoms) .            # Number of atoms
           pack("n", HTLC_DATA_FILE) .        # Atom type
           pack("n", length($src_file)) .     # Atom length
           $src_file;                         # Atom data

  if(@src_path_parts)
  {
    $data .= pack("n", HTLC_DATA_DIRECTORY) . # Atom type
             pack("n", $src_dir_len + 2 + (3 * @src_path_parts)) .
                                              # Atom length
             pack("n", scalar(@src_path_parts));
                                              # Num path parts

    my($path_part);

    foreach $path_part (@src_path_parts)      # Path parts data
    {
      if(length($path_part) > HTLC_MAX_PATHLEN)
      {
        croak("Maximum path part length exceeded.");
      }

      $data .= pack("n", 0x0000) .            # 2 null bytes
               pack("c", length($path_part)) .# Length
               $path_part;                    # Path part
    }
  }

  if(@dest_path_parts)
  {
    $data .= pack("n", HTLC_DATA_DESTDIR) .   # Atom type
             pack("n", $dest_dir_len + 2 + (3 * @dest_path_parts)) .
                                              # Atom length
             pack("n", scalar(@dest_path_parts));
                                              # Num path parts

    my($path_part);

    foreach $path_part (@dest_path_parts)     # Path parts data
    {
      if(length($path_part) > HTLC_MAX_PATHLEN)
      {
        croak("Maximum path part length exceeded.");
      }

      $data .= pack("n", 0x0000) .            # 2 null bytes
               pack("c", length($path_part)) .# Length
               $path_part;                    # Path part
    }
  }

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: MOVE FILE - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_FILE_MOVE, time(),
                         undef, [ $save_src_path, $save_dest_path ]);
    return($task_num);
  }
  else { return(undef) }
}

sub rename
{
  my($self, $path, $new_name) = @_;
  
  return undef  unless(length($path) && length($new_name));
  return _change_file_info($self, $path, $new_name, undef);
}

sub comment
{
  my($self, $path, $comments) = @_;
  
  return undef  unless(length($path));
  $comments = ""  unless(defined($comments));
  return _change_file_info($self, $path, undef, $comments);
}

sub _change_file_info
{
  my($self, $path, $name, $comments) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data, $task_num, @path_parts, $length, $save_path, $file,
     $dir_len, $num_atoms);

  $path =~ s/$self->{'PATH_SEPARATOR'}$//;
  $save_path = $path;
  @path_parts = split($self->{'PATH_SEPARATOR'}, $path);
  $path =~ s/$self->{'PATH_SEPARATOR'}//g;
   
  if(length($path) > HTLC_MAX_PATHLEN)
  {
    croak("Maximum path length exceeded.");
  }

  $file = pop(@path_parts);

  # File part: 2 bytes for num atoms, 2 bytes for atom type,
  # 2 bytes for file name length
  $length = (2 + 2 + 2 + length($file));
    
  if(@path_parts)
  {
    $dir_len = length(join('', @path_parts));
    # Path part: 2 bytes for atom type, 2 bytes for atom len
    # 2 bytes for num path components, and 2 null bytes and
    # 1 byte path part length for each path part
    $length += (2 + 2 + 2 + (3 * @path_parts));
    $length += $dir_len;
  }

  if(length($name))
  {
    # Name part: 2 bytes for atom type, 2 bytes for
    # atom len, and the new name
    $length += (2 + 2 + length($name));
  }

  if(defined($comments))
  {
    # Comments part: 2 bytes for atom type, 2 bytes for
    # atom len, length of the new comments, else 1 null
    # byte if removing comments.
    $length += 2 + 2;
    if(length($comments)) { $length += length($comments) }
    else                  { $length += 1                 }
  }

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_FILE_SETINFO);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len($length);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header();
  
  $num_atoms = (@path_parts) ? 2 : 1;
  $num_atoms++  if(length($name));
  $num_atoms++  if(defined($comments));

  $data .= pack("n", $num_atoms) .            # Number of atoms
           pack("n", HTLC_DATA_FILE) .        # Atom type
           pack("n", length($file)) .         # Atom length
           $file;                             # Atom data

  if(@path_parts)
  {
    $data .= pack("n", HTLC_DATA_DIRECTORY).  # Atom type
             pack("n", $dir_len + 2 + (3 * @path_parts)) .
                                              # Atom length
             pack("n", scalar(@path_parts));  # Num path parts

    my($path_part);

    foreach $path_part (@path_parts)          # Path parts data
    {
      if(length($path_part) > HTLC_MAX_PATHLEN)
      {
        croak("Maximum path part length exceeded.");
      }

      $data .= pack("n", 0x0000) .            # 2 null bytes
               pack("c", length($path_part)) .# Length
               $path_part;                    # Path part
    }
  }

  if(length($name))
  {
    $data .= pack("n", HTLC_DATA_FILE_RENAME).# Atom type
             pack("n", length($name)) .       # Length
             $name;                           # Name
  }

  if(defined($comments))
  {
    $data .= pack("n", HTLS_DATA_FILE_COMMENT);# Atom type
    
    if(length($comments))
    {
      $data .=  pack("n", length($comments)). # Length
                $comments;                    # Comments
    }
    else # Remove comments
    {
      $data .=  pack("n", 0x0001) .           # Length
                pack("x")                     # Null byte
    }
  }

  _debug(_hexdump($data));
  
  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: SET INFO - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_SET_INFO, time(), undef, $save_path);
    return($task_num);
  }
  else { return(undef) }
}

sub post_news
{
  my($self, @post) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($post) = join('', @post);

  my($data, $task_num);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_NEWS_POST);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_SHORT_HDR + length($post));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0001) .                 # Number of atoms
          pack("n", HTLS_DATA_NEWS_POST) .     # Atom type
          pack("n", length($post)) .          # Atom length
          $post;                              # Atom data

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: POST NEWS - $task_num\n");
    $self->{'TASKS'}->{$task_num} =
      new Net::Hotline::Task($task_num, HTLC_TASK_NEWS_POST, time());
  }
  else { return(undef) }

  return($task_num);
}

sub req_news
{
  my($self) = shift;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data, $task_num);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_NEWS_GETFILE);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_TASK_FILLER);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0000);

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: NEWS - $task_num\n");
    $self->{'TASKS'}->{$task_num} = 
      new Net::Hotline::Task($task_num, HTLC_TASK_NEWS, time());
    return($task_num);
  }
  else { return(undef) }
}

sub user_by_nick
{
  my($self, $nick_match) = @_;

  my($socket, @users);

  eval { m/$nick_match/ };

  return undef  if($@ || !$self->{'USER_LIST'} || length($nick_match) == 0);

  foreach $socket (sort { $a <=> $b } keys(%{$self->{'USER_LIST'}}))
  {
    if($self->{'USER_LIST'}->{$socket}->nick() =~ /^$nick_match$/)
    {
      if(wantarray())
      {
        push(@users, $self->{'USER_LIST'}->{$socket});
      }
      else
      {
        return $self->{'USER_LIST'}->{$socket};
      }
    }
  }

  if(@users) { return @users }
  else       { return undef  }
}

sub user_by_socket
{
  my($self, $socket) = @_;
  return $self->{'USER_LIST'}->{$socket};
}

sub icon
{
  my($self, $icon) = @_;

  return $self->{'ICON'}  unless($icon =~ /^-?\d+$/);
  
  return _update_user($self, $icon, $self->{'NICK'});
}

sub nick
{
  my($self, $nick) = @_;

  return $self->{'NICK'}  unless(defined($nick));
  
  return _update_user($self, $self->{'ICON'}, $nick);
}

sub _update_user
{
  my($self, $icon, $nick) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_USER_CHANGE);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len((SIZEOF_HL_SHORT_HDR * 2) + length($nick));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0002) .                 # Num atoms

          pack("n", HTLC_DATA_ICON) .         # Atom type
          pack("n", 0x0002) .                 # Atom length
          pack("n", $icon) .                  # Atom data

          pack("n", HTLC_DATA_NICKNAME) .     # Atom type
          pack("n", length($nick)) .          # Atom length
          $nick;                              # Atom data

  $self->{'NICK'} = $nick;
  $self->{'ICON'} = $icon;

  _debug(_hexdump($data));

  if(_write($server, \$data, length($data)) == length($data))
  {
    return(1);
  }
  else { return(undef) }
}

sub req_userlist
{
  my($self) = shift;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data, $task_num);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_USER_GETLIST);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_TASK_FILLER);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0000);

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: GET USER LIST - $task_num\n");
    $self->{'TASKS'}->{$task_num} =
      new Net::Hotline::Task($task_num, HTLC_TASK_USER_LIST, time());
    return($task_num);
  }
  else { return(undef) }
}

sub kick
{
  my($self, $user_or_socket) = @_;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($socket, $task_num);
  
  if(ref($user_or_socket)) { $socket = $user_or_socket->socket() }
  else                     { $socket = $user_or_socket           }

  my($data);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_USER_KICK);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_LONG_HDR);
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0001) .                 # Num atoms

          pack("n", HTLC_DATA_SOCKET) .       # Atom type
          pack("n", 0x0002) .                 # Atom length
          pack("n", $socket);                 # Atom data

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: KICK($socket) - $task_num\n");
    $self->{'TASKS'}->{$task_num} =
      new Net::Hotline::Task($task_num, HTLC_TASK_KICK, time());
  }
  else { return(undef) }
}

sub msg
{
  my($self, $user_or_socket, @message) = @_;

  my($message) = join('', @message);

  $message =~ s/\n/@{[HTLC_NEWLINE]}/osg;

  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($socket);
  
  if(ref($user_or_socket)) { $socket = $user_or_socket->socket() }
  else                     { $socket = $user_or_socket           }
  
  my($data, $task_num);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_MSG);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len((SIZEOF_HL_SHORT_HDR * 2) +
                     length($message));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0002) .                 # Num atoms

          pack("n", HTLC_DATA_SOCKET) .       # Atom type
          pack("n", 0x0002) .                 # Atom length
          pack("n", $socket) .                # Atom data

          pack("n", HTLC_DATA_MSG) .          # Atom type
          pack("n", length($message)) .       # Atom length
          $message;                           # Atom data

  _debug(_hexdump($data));

  $task_num = $proto_header->seq();

  if(_write($server, \$data, length($data)) == length($data))
  {
    _debug("NEW TASK: MSG - $task_num\n");
    $self->{'TASKS'}->{$task_num} =
      new Net::Hotline::Task($task_num, HTLC_TASK_SEND_MSG, time());
  }
  else { return(undef) }
  
  return($task_num);
}

sub chat_action
{
  my($self, @message) = @_;

  my($message) = join('', @message);

  $message =~ s/\n/@{[HTLC_NEWLINE]}/osg;
  
  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_CHAT);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len((SIZEOF_HL_SHORT_HDR  * 2) +
                     length($message));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0002) .                 # Num atoms

          pack("n", HTLC_DATA_OPTION) .       # Atom type
          pack("n", 0x0002) .                 # Atom length
          pack("n", 0x0001) .                 # Atom data

          pack("n", HTLC_DATA_CHAT) .         # Atom type
          pack("n", length($message)) .       # Atom length
          $message;                           # Atom data

  _debug(_hexdump($data));

  if(_write($server, \$data, length($data)) == length($data))
  {
    return(1);
  }
  else { return(undef) }
}

sub chat
{
  my($self, @message) = @_;

  my($message) = join('', @message);

  $message =~ s/\n/@{[HTLC_NEWLINE]}/osg;
  
  my($server) = $self->{'SERVER'};
  return(undef)  unless($server->opened());

  my($data);

  my($proto_header) = new Net::Hotline::Protocol::Header;

  $proto_header->type(HTLC_HDR_CHAT);
  $proto_header->seq($self->_next_seqnum());
  $proto_header->task(0x00000000);
  $proto_header->len(SIZEOF_HL_SHORT_HDR +
                     length($message));
  $proto_header->len2($proto_header->len);

  $data = $proto_header->header() .
          pack("n", 0x0001) .                 # Num atoms

          pack("n", HTLC_DATA_CHAT) .         # Atom type
          pack("n", length($message)) .       # Atom length
          $message;                           # Atom data

  _debug(_hexdump($data));

  if(_write($server, \$data, length($data)) == length($data))
  {
    return(1);
  }
  else { return(undef) }
}

sub recv_file
{
  my($self, $task, $ref, $size) = @_;

  my($server, $data, $xfer, $tot_length, $length);
  my($data_file, $rsrc_file, $local_sep, $remote_sep, $dest_dir);
  my($type, $creator, $created, $modified, $finder_flags,  $comments,
     $comments_len, $data_len, $rsrc_len, $name_len, @ret);

  $local_sep = PATH_SEPARATOR;
  $remote_sep = $self->{'PATH_SEPARATOR'};
  $dest_dir = $self->{'DOWNLOADS_DIR'};
  $dest_dir .= $local_sep  if($dest_dir =~ /\S/ && $dest_dir !~ /$local_sep$/o);

  my($buf_size) = $self->{'HTXF_BUFSIZE'};

  my($data_fh) = new IO::File;
  my($rsrc_fh) = new IO::File;
  
  ($data_file = $task->path()) =~ /$remote_sep([^$remote_sep]+)$/;
  $data_file = "$dest_dir$1";

  $rsrc_file = "$data_file.rsrc";

  unless($data_fh->open(">>$data_file"))
  {
    $task->error(1);
    $task->finish(time());
    $task->error_text("Could not write to $data_file: $!");
    return(undef);
  }

  unless($rsrc_fh->open(">>$rsrc_file"))
  {
    $task->error(1);
    $task->finish(time());
    $task->error_text("Could not write to $rsrc_file: $!");
    return(undef);
  }

  $task->finish(undef);

  ($server = $self->{'SERVER_ADDR'}) =~ s/:\d+$//;

  $data = HTXF_MAGIC . pack("Nx8", $ref);

  $xfer = IO::Socket::INET->new(PeerAddr =>$server,
                                PeerPort =>HTXF_TCPPORT,
                                Timeout  =>5,
                                Proto    =>'tcp') || return(undef);

  if(_write($xfer, \$data, length($data)) != length($data))
  {
    $xfer->close();
    $task->error(1);
    $task->finish(time());
    $task->error_text("Write error: $!");
    return(undef);
  }
  
  $tot_length = $size;

  # 46 49 4C 50  00 01 00 00  00 00 00 00  00 00 00 00  FILP............
  # 00 00 00 00  00 00 00 03  49 4E 46 4F  00 00 00 00  ........INFO....
  # 00 00 00 00  00 00 00 60                            .......`
  if(_read($xfer, \$data, SIZEOF_HL_FILE_XFER_HDR) != SIZEOF_HL_FILE_XFER_HDR)
  {
    $xfer->close();
    $task->error(1);
    $task->finish(time());
    $task->error_text("Read error: $!");
    return(undef);
  }

  $tot_length -= SIZEOF_HL_FILE_XFER_HDR;
  $length = (unpack("N", substr($data, 36, 4)) + SIZEOF_HL_FILE_FORK_HDR);

  unless(substr($data, 0, 4) eq 'FILP')
  {
    $xfer->close();
    $task->error(1);
    $task->finish(time());
    $task->error_text("Bad data from server!");
  }

  #                           41 4D 41 43  54 45 58 54          AMACTEXT
  # 74 74 78 74  00 00 00 00  00 00 01 00  00 00 00 00  ttxt............
  # 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
  # 00 00 00 00  00 00 00 00  00 00 00 00  07 70 00 00  .............p..
  # AE A3 8A 18  07 70 00 00  AE A3 8C 1D  00 00 00 05  .....p..........
  # 74 65 78 74  32 00 11 66  74 70 2E 6D  69 63 72 6F  text2..ftp.micro
  # 73 6F 66 74  2E 63 6F 6D  44 41 54 41  00 00 00 00  soft.comDATA....
  # 00 00 00 00  00 00 01 00                            ........
  $tot_length -= _read($xfer, \$data, $length);

  $type     = substr($data, 4, 4);
  $creator  = substr($data, 8, 4);

  $created      = unpack("N", substr($data, 56, 4));
  $finder_flags = substr($data, 62, 2);
  $modified     = unpack("N", substr($data, 64, 4));
  $name_len     = unpack("c", substr($data, 71, 1));
  $comments_len = unpack("n", substr($data, 72 + $name_len, 2)); # 72
  $comments = substr($data, 72 + $name_len + 2, $comments_len);

  $data_len = unpack("N", substr($data, -4));
  $length -= _download($xfer, $data_fh, $data_len, $buf_size);
  $data_fh->close();

  #                           4D 41 43 52  00 00 00 00          MACR....
  # 00 00 00 00  00 00 01 EC                            ........
  $tot_length -= _read($xfer, \$data, SIZEOF_HL_FILE_FORK_HDR);

  $rsrc_len = unpack("N", substr($data, -4));
  $length -= _download($xfer, $rsrc_fh, $rsrc_len, $buf_size);
  $rsrc_fh->close();

  $data_len = -s $data_file;
  $rsrc_len = -s $rsrc_file;

  unless($rsrc_len)
  {
    unlink($rsrc_file);
    undef $rsrc_file;
    $rsrc_len = 0;
  }

  unless($data_len)
  {
    unlink($data_file);
    undef $data_file;
    $data_len = 0;
  }

  @ret = ($data_file, $data_len,
          $rsrc_file, $rsrc_len,
          $buf_size, $type, $creator, $comments,
          $created, $modified, $finder_flags);

  return(@ret)  if(wantarray);

  return(\@ret);
}

sub _download
{
  my($src_fh, $dest_fh, $len, $buf_size) = @_;

  my($data, $read);

  $read = 0;

  if($len <= $buf_size)
  {
    $read += _read($src_fh, \$data, $len);
    print $dest_fh $data;
  }
  else
  {
    my($loop)     = int($len/$buf_size);
    my($leftover) = $len % $buf_size;

    for(; $loop > 0; $loop--)
    {
      $read += _read($src_fh, \$data, $buf_size);
      if($read < $buf_size)
      {
        print "read $read out of $buf_size: $! (", $! + 0, ")\n";
      }
      print $dest_fh $data;
    }
    
    if($leftover > 0)
    {
      $read += _read($src_fh, \$data, $leftover);
      print $dest_fh $data;
    }
  }

  unless($read == $len)
  {
    croak("Tried to read $len bytes, actually read $read.  Download may be corrupted!");
  }

  return($read);
}

# Macbinary CRC perl code lifted Convert::BinHex by Eryq (eryq@enteract.com)
sub macbinary_crc
{
  shift if(ref($_[0]));

  my($len) = length($_[0]);
  my($crc) = $_[1];

  my($i);

  for($i = 0; $i < $len; $i++)
  {
    ($crc ^= (vec($_[0], $i, 8) << 8)) &= 0xFFFF;
    $crc = ($crc << 8) ^ $MAGIC[$crc >> 8];
  }
  return $crc;
}

sub macbinary
{
  shift if(ref($_[0]));

  my($macbin_file,
     $data_file, $data_len,
     $rsrc_file, $rsrc_len,
     $buf_size, $type, $creator, $comments,
     $created, $modified, $finder_flags) = @_;

  $macbin_file = "$data_file.bin"  unless(defined($macbin_file));
  return(undef)  if(-e $macbin_file);

  my($macbin_fh, $data_fh, $rsrc_fh, $macbin_hdr, $buf, $len, $pad);

  $buf_size = 4096  unless($buf_size =~ /^\d+$/);

  my($filename) = ($data_file =~ /@{[PATH_SEPARATOR]}?([^@{[PATH_SEPARATOR]}]*)$/i);

  $macbin_fh = new IO::File;
  $data_fh   = new IO::File;
  $rsrc_fh   = new IO::File;

  $macbin_fh->open(">$macbin_file") || return(undef);

  $macbin_hdr = pack("x128"); # Start with empty 128 byte header

  # Offset 000-Byte, old version number, must be kept at zero for compatibility
  
  # Offset 001-Byte, Length of filename (must be in the range 1-63)
  substr($macbin_hdr, 1, 1) = pack("c", length($filename));

  # Offset 002-1 to 63 chars, filename (only "length" bytes are significant).
  substr($macbin_hdr, 2, length($filename)) = $filename;

  # Offset 065-Long Word, file type (normally expressed as four characters)
  substr($macbin_hdr, 65, 4) = $type;

  # Offset 069-Long Word, file creator (normally expressed as four characters)
  substr($macbin_hdr, 69, 4) = $creator;

  # Offset 073-Byte, original Finder flags
  #     Bit 7 - Locked.
  #     Bit 6 - Invisible.
  #     Bit 5 - Bundle.
  #     Bit 4 - System.
  #     Bit 3 - Bozo.
  #     Bit 2 - Busy.
  #     Bit 1 - Changed.
  #     Bit 0 - Inited.
  # Clear everything except bundle
  substr($macbin_hdr, 73, 1) = (substr($finder_flags, 1, 1) | 0xDF);

  # Offset 074-Byte, zero fill, must be zero for compatibility
  
  # Offset 075-Word, file's vertical position within its window.
  substr($macbin_hdr, 75, 2) = pack("n", 0xFFFF);

  # Offset 077-Word, file's horizontal position within its window.
  substr($macbin_hdr, 77, 2) = pack("n", 0xFFFF);

  # Offset 079-Word, file's window or folder ID.
  # Offset 081-Byte, "Protected" flag (in low order bit).
  # Offset 082-Byte, zero fill, must be zero for compatibility

  # Offset 083-Long Word, Data Fork length (bytes, zero if no Data Fork).
  substr($macbin_hdr, 83, 4) = pack("L", $data_len);

  # Offset 087-Long Word, Resource Fork length (bytes, zero if no R.F.).
  substr($macbin_hdr, 87, 4) = pack("L", $rsrc_len);

  # Offset 091-Long Word, File's creation date
  substr($macbin_hdr, 91, 4) = pack("L", $created);

  # Offset 095-Long Word, File's "last modified" date.
  substr($macbin_hdr, 95, 4) = pack("L", $modified);

  # Offset 099-Word, length of Get Info comment to be sent after the resource fork
  #            (if implemented, see below).
  # Offset 101-Byte, Finder Flags, bits 0-7. (Bits 8-15 are already in byte 73)
  # Offset 116-Long Word, Length of total files when packed files are unpacked.
  #            This is only used by programs that pack and unpack on the fly,
  #            mimicing a standalone utility such as PackIt. A program that is
  #            uploading a single file must zero this location when sending a
  #            file. Programs that do not unpack/uncompress files when
  #            downloading may ignore this value.
  substr($macbin_hdr, 116, 4) = pack("L", $data_len + $rsrc_len);

  # Offset 120-Word, Length of a secondary header. If this is non-zero,
  #            Skip this many bytes (rounded up to the next multiple of 128)
  #            This is for future expansion only, when sending files with
  #            MacBinary, this word should be zero.
  
  # Offset 122-Byte, Version number of Macbinary II that the uploading program
  # is written for (the version begins at 129)
  substr($macbin_hdr, 122, 1) = pack("c", 129);

  # Offset 123-Byte, Minimum MacBinary II version needed to read this file
  # (start this value at 129 129)
  substr($macbin_hdr, 123, 1) = pack("c", 129);

  # Offset 124-Word, CRC of previous 124 bytes
  substr($macbin_hdr, 124, 2) = pack("n", macbinary_crc(substr($macbin_hdr, 0, 124), 0));

  # Macbinary II header
  print $macbin_fh $macbin_hdr;

  # Data fork, null padded to a multiple of 128 bytes
  if($data_len)
  {
    $data_fh->open($data_file) || return(undef);

    while($len = read($data_fh, $buf, $buf_size))
    {
      croak("read() error: $!")  unless(defined($len));
      print $macbin_fh $buf;
    }
    $data_fh->close();
    
    if($data_len % 128)
    {
      $pad = "x" . (128 - ($data_len % 128));
      print $macbin_fh pack($pad);
    }
  }
  
  # Resource fork, null padded to a multiple of 128 bytes
  if($rsrc_len)
  {
    $rsrc_fh->open($rsrc_file) || return(undef);
    while($len = read($rsrc_fh, $buf, $buf_size))
    {
      croak("read() error: $!")  unless(defined($len));
      print $macbin_fh $buf;      
    }
    $rsrc_fh->close();

    if($rsrc_len % 128)
    {
      $pad = "x" . (128 - ($rsrc_len % 128));
      print $macbin_fh pack($pad);
    }
  }

  $macbin_fh->close();

  return(1);
}
