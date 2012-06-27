# <? read_starfish_conf(); &generate_header; !>
#+
# file: AuthRegister.pm
# CGI::AuthRegister - Simple CGI Authentication and Registration in Perl
# (c) 2012 Vlado Keselj http://web.cs.dal.ca/~vlado
# $Date: $
# $Id: $
#-

#package CGI::AuthRegister
use strict;
use Carp;

#<? &generate_standard_vars !>
#+
use vars qw($NAME $ABSTRACT $VERSION);
$NAME     = 'AuthRegister';
$ABSTRACT = 'Simple CGI Authentication and Registration in Perl';
$VERSION  = '0.1';
#-

use vars qw($Email_from $Email_bcc $Error $ErrorInternal $LogReport $Sendmail
  $Session $SessionId $SiteId $Ticket $User $UserEmail);
# $Error = ''; # Appended error messages, OK to be sent to user
# $ErrorInternal = ''; # Appended internal error messages, intended
                       # for administrator
# $LogReport = '';  # Collecting some important log events if needed
# $Session   = '';  # Session data structure
# $SessionId = '';  # Session identifier, generated
$SiteId = 'Site';   # Site identifier, used in cookies and emails
# $Ticket = '';     # Session ticket for security, generated
# $User      = '';  # User data structure
# $UserEmail = '';  # User email address

$Email_from = ''; # Example: $SiteId.' <vlado@cs.dal.ca>';
$Email_bcc  = ''; # Example: $SiteId.' Bcc <vlado@cs.dal.ca>';

$Sendmail = "/usr/lib/sendmail"; # Sendmail with full path

# Functions
sub putfile($@);

########################################################################
# HTTPS Connection and Cookies Management

# Check that the connection is HTTPS and if not, redirect to HTTPS.
# It must be done before script produces any output.
sub require_https {
    if ($ENV{'HTTPS'} ne 'on') {
	print "Status: 301 Moved Permanently\nLocation: https://$ENV{SERVER_NAME}$ENV{SCRIPT_NAME}\n\n";
	exit 0;
    }
}

# Prepare HTTP header. If SessionId is not empty, generate cookie with
# the sessionid and ticket.
sub header_session_cookie {
    if ($SessionId eq '') { return header } else
    { return header(-cookie=>cookie(-name=>$SiteId, -value=>"$SessionId $Ticket")) }
}

# Delete cookie after logging out. Return string.
sub header_delete_cookie {
  return header(-cookie=>cookie(-name=>$SiteId, -value=>'', -expires=>"now")) }

# Analyze cookie to detect session, and check the ticket as well.  It
# should be called at the beginning of a script.  $SessionId and
# $Ticket are set to empty string if not successful.  The information
# about the session is stored in db/sessions.d/$SessionId/session.info
# file.  The structures $Session and $User are set if successful.
sub analyze_cookie {
    my $c = cookie(-name=>$SiteId); # sessionid and ticket
    if ($c eq '') { $SessionId = $Ticket = ''; return; }
    ($SessionId, $Ticket) = split(/\s+/, $c);
    if ($SessionId !~ /^[\w.:-]+$/ or $Ticket !~ /^\w+$/)
    { $SessionId = $Ticket = ''; return; }

    # check validity of session and set user variables
    my $sessioninfofile = "db/sessions.d/$SessionId/session.info";
    if (!-f $sessioninfofile) { $SessionId = $Ticket = ''; return; }
    my $se = &read_db_record("file=$sessioninfofile");
    if (!ref($se) or $Ticket ne $se->{'Ticket'}) { $SessionId = $Ticket = ''; return; }
    $Session = $se;
    $UserEmail = $se->{email};
    
    $User = &get_user_by_email($UserEmail);
    if ($Error ne '') {	$SessionId = $Ticket = ''; return; }
}

########################################################################
# Session Management

# params: $email, opt: pwstore type: md5 raw
sub reset_password {
    my $email = shift; my $pwstore = shift; $pwstore = 'md5' if $pwstore eq '';
    my $password = &random_password(6);
    if (!-f 'db/passwords') {
      putfile 'db/passwords', ''; chmod 0600, 'db/passwords' }
    if (!&lock_mkdir('db/passwords')) { $Error.="95-ERR:\n"; return ''; }
    local *PH; open(PH,"db/passwords") or croak($!);
    my $content = '';
    while (<PH>) {
	my ($e,$p) = split;
	$content .= $_ if $e ne $email;
    }
    close(PH);
    $content .= "$email ";
    if   ($pwstore eq 'raw') { $content.="raw:$password" }
    elsif($pwstore eq 'md5') { $content.="md5:".md5_base64($password) }
    #else                     { $content.="md5:".md5_base64($password) }
    else                     { $content.="raw:$password" }
    $content .= "\n";
    putfile 'db/passwords', $content; chmod 0600, 'db/passwords';
    &unlock_mkdir('db/passwords');
    return $password;
}

sub md5_base64 {
  my $arg=shift; require Digest::MD5; return Digest::MD5::md5_base64($arg); }

sub random_password {
    my $n = shift; $n = 8 unless $n > 0;
    my @chars = (2..9, 'a'..'k', 'm'..'z', 'A'..'N', 'P'..'Z',
                 qw(, . / ? ; : - = + ! @ $ % *) );
    return join('', map { $chars[rand($#chars+1)] } (1..$n));
}

# removes session file and return the appropriate HTTP header
sub logout {
  if ($Session eq '') { $Error.= "126-ERR: No session to log out\n"; return; }
  if (!-f "db/sessions.d/$SessionId") {
    $Error.='128-ERR: No session file'; return; }
  # rename("db/sessions.d/$SessionId","db/sessions.d/loggedout-$SessionId");
  unlink("db/sessions.d/$SessionId");
  $LogReport.="User $UserEmail logged out.";
  $Session = $SessionId = $Ticket = '';
  return 1;
}

# The first parameter can be an userid and email. (diff by @)
sub login {
    my $email = shift; my $password = shift;
    $email = lc $email; my $userid;
    if ($email !~ /@/) { $userid=$email; $email=''; }
    if ($email ne '') {
      if (!&emailcheckok($email)) {
	$Error.="97-ERR:Incorrect email address format"; return; }
      my $u = &get_user_by_email($email);
      if ($u eq '') { $Error.='99-ERR:Email not registered'; return; }
      $userid = $u->{userid};
      $User = $u;
    } else {
      if ($userid eq '') { $Error.="103-ERR:Empty userid"; return; }
      my $u = &get_user_by_userid($userid);
      if ($u eq '') { $Error.='105-ERR:Userid not registered'; return; }
      $email = $u->{email};
      $User = $u;
    }

    if (!password_check($User, $password)) {
      $Error.="205:Invalid password\n"; return ''; }

    &set_new_session($User); return 1;
}

sub set_new_session {
  my $u = shift; my $email = $u->{email};
  mkdir('db', 0700) or croak unless -d 'db';
  mkdir('db/sessions.d', 0700) or croak unless -d 'db/sessions.d';

  my $sessionid = $email."______"; $sessionid =~ /.*?(\w).*?(\w).*?(\w).*?(\w).*?(\w).*?(\w)/;
  $sessionid = $1.$2.$3.$4.$5; $^T =~ /\d{6}$/; $sessionid.= "_$&";
  if (! mkdir("db/sessions.d/$sessionid", 0700)) {
    my $cnt=1; for(;$cnt<100 and !mkdir("db/sessions.d/${sessionid}_$cnt", 0700); ++$cnt) {}
    croak "Cannot create sessions!" if $cnt == 100;
    $sessionid = "${sessionid}_$cnt";
  }
  $SessionId = $sessionid; $Ticket = &random_name;
  putfile("db/sessions.d/$SessionId/session.info",
	  "SessionId:$SessionId\nTicket:$Ticket\nemail:$email\n");
  $UserEmail = $email;
  return $SessionId;
}

# Return 1 if OK, '' otherwise
sub password_check {
  my $u = shift; my $password = shift; my $pwstored = &find_password($u->{email});
  if ($pwstored =~ /^raw:/) {
    $pwstored=$'; return ( ($pwstored eq $password) ? 1 : '' ); }
  if ($pwstored =~ /^md5:/) {
    $pwstored=$'; return ( ($pwstored eq md5_base64($password)) ? 1 : ''); }
  $Error.="268-ERR:PWCheck error\n"; return '';
}

sub find_password {
  my $email = shift; my $pwfile = "db/passwords";
  if (!-f $pwfile) { putfile $pwfile, ''; chmod 0600, $pwfile }
  if (!&lock_mkdir($pwfile)) { $Error.="195-ERR:\n"; return ''; }
  local *PH; if (!open(PH,$pwfile)) {
    &unlock_mkdir($pwfile);
    $Error.="197-ERR: Cannot open ($pwfile):$!\n"; return ''; }
  while (<PH>) {
    my ($e,$p) = split;
    if ($e eq $email) { close(PH); &unlock_mkdir($pwfile); return $p; }
  }
  close(PH); &unlock_mkdir($pwfile); return '';
}

sub random_name {
    my $n = shift; $n = 8 unless $n > 0;
    my @chars = (0..9, 'a'..'z', 'A'..'Z');
    return join('', map { $chars[rand($#chars+1)] } (1..$n));
}

########################################################################
# Email communication
# params: $email, opt: 'raw' or 'md5' to generate new password if not found
sub send_email_reminder {
    my $email = shift; my $pwstore = shift;
    $email=lc $email; $email =~ s/\s/ /g;
    if ($email eq '') {
      $Error.="220-ERR:No e-mail provided to send password\n"; return; }
    if (!emailcheckok($email)) {
      $Error.="222-ERR:Invalid e-mail address provided($email)\n"; return; }
    my $user = get_user_by_email($email);
    if ($user eq '') {
      $Error.="224-ERR: No user with email ($email)\n"; return; }
    my $pw = find_password($email);
    if ($pw =~ /^raw:/) { $pw = $' }
    elsif ($pw ne '') { $Error.="227-ERR:Cannot retrieve password\n"; return; }
    else {
      if ($pwstore eq 'raw') { $pw = &reset_password($email, 'raw') }
      elsif ($pwstore eq 'md5') { $pw = &reset_password($email, 'md5') }
      else { $Error.="232-ERR:No password for email($email)\n"; return ''; }
    }

    my $httpslogin = "https://$ENV{SERVER_NAME}$ENV{SCRIPT_NAME}";

    my $msg = "Hi,\n\nYour email and password for the $SiteId site is:\n\n".
      "Email: $email\nPassword: $pw\n\n".
	"You can log in at:\n\n$httpslogin\n\n\n".
        # "$HttpsBaseLink/login.cgi\n\n\n".
      "Best regards,\n$SiteId Admin\n";
    &send_email_to($email, "Subject: $SiteId Password Reminder", $msg);
    return 1;
}

sub send_email_to {
  my $email = shift; croak unless &emailcheckok($email);
  my $subject = shift; $subject =~ s/[\n\r]/ /g;
  if ($subject !~ /^Subject: /) { $subject = "Subject: $subject" }
  my $msg1 = shift;

  my $msg = '';
  $msg.="From: $Email_from\n" unless $Email_from eq '';
  $msg.="To: $email\n";
  $msg.="Bcc: $Email_bcc\n" unless $Email_bcc eq '';
  $msg.="$subject\n\n$msg1";

  if (! -x $Sendmail) {
    $Error.="257-ERR:No sendmail ($Sendmail)\n"; return ''; }
  local *S;
  if (!open(S,"|$Sendmail -ti")) {
    $Error.="250-ERR:Cannot run sendmail:$!\n"; return ''; }
  print S $msg; close(S); $Error.="Sent:$msg";
}

########################################################################
# Data checks

sub emailcheckok {
    my $email = shift;
    if ($email =~ /^[a-zA-Z][\w\.+-]*[a-zA-Z0-9+-]@
         [a-zA-Z0-9][\w\.-]*[a-zA-Z0-9]\.[a-zA-Z][a-zA-Z\.]*[a-zA-Z]$/x)
    { return 1 }
    return '';
}

sub useridcheckok {
  my $userid = shift; return 1 if $userid=~/^[a-zA-Z0-9-]+$/; return ''; }

# DB related functions

# Uses file db/users.db.  Empty string returned if unsuccessful, with
# error message appended to $Error.
sub get_user_by_email {
    my $email = shift;
    if (!-f 'db/users.db')
    { $Error.= "292-ERR: no file db/users.db\n"; return; }
    my @db = @{ &read_db('file=db/users.db') };
    for my $r (@db) { if ($email eq $r->{email}) { return $User=$r } }
    $Error.="295-ERR: no user with email ($email)\n"; return $User='';
}

sub get_user_by_userid {
    my $userid = shift;
    if (!-f 'db/users.db')
    { $Error.= "301-ERR: no file db/users.db\n"; return; }
    my @db = @{ &read_db('file=db/users.db') };
    for my $r (@db) { if ($userid eq $r->{userid}) { return $User=$r } }
    $Error.="304-ERR: no user with userid ($userid)."; return $User='';
}

# Read DB records in the RFC822-like style (to add reference).
sub read_db {
  my $arg = shift;
  if ($arg =~ /^file=/) {
    my $f = $'; if (!&lock_mkdir($f)) { return '' }
    local *F; open(F, $f) or die "cannot open $f:$!";
    $arg = join('', <F>); close(F); &unlock_mkdir($f);
  }

  my $db = [];
  while ($arg) {
      $arg =~ s/^\s*(#.*\s*)*//;  # allow comments betwen records
      my $record;
      if ($arg =~ /\n\n+/) { $record = "$`\n"; $arg = $'; }
      else { $record = $arg; $arg = ''; }
      my $r = {};
      while ($record) {
        while ($record =~ /^(.*)(\\\n|\n[ \t]+)(.*)/)
	{ $record = "$1 $3$'" }
        $record =~ /^([^\n:]*):(.*)\n/ or die;
        my $k = $1; my $v = $2; $record = $';
        if (exists($r->{$k})) {
          my $c = 0;
          while (exists($r->{"$k-$c"})) { ++$c }
          $k = "$k-$c";
        }
        $r->{$k} = $v;
      }
      push @{ $db }, $r;
  }
  return $db;
}

# Read one DB record in the RFC822-like style (to add reference).
sub read_db_record {
    my $arg = shift;
    if ($arg =~ /^file=/) {
	my $f = $'; local *F; open(F, $f) or die "cannot open $f:$!";
	$arg = join('', <F>); close(F);
    }

    while ($arg =~ s/^(\s*|\s*#.*)\n//) {} # allow comments before record
    my $record;
    if ($arg =~ /\n\n+/) { $record = "$`\n"; $arg = $'; }
    else { $record = $arg; $arg = ''; }
    my $r = {};
    while ($record) {
        while ($record =~ /^(.*)(\\\n|\n[ \t]+)(.*)/)
	{ $record = "$1 $3$'" }
        $record =~ /^([^\n:]*):(.*)\n/ or die;
        my $k = $1; my $v = $2; $record = $';
        if (exists($r->{$k})) {
	    my $c = 0;
	    while (exists($r->{"$k-$c"})) { ++$c }
	    $k = "$k-$c";
        }
        $r->{$k} = $v;
    }
  return $r;
}

sub putfile($@) {
    my $f = shift; local *F;
    if (!open(F, ">$f")) { $Error.="325-ERR:Cannot write ($f):$!\n"; return; }
    for (@_) { print F } close(F);
}

########################################################################
# Simple file locking using mkdir

# Exlusive locking using mkdir
# lock_mkdir($fname); # return 1=success ''=fail
sub lock_mkdir {
  my $fname = shift; my $lockd = "$fname.lock"; my $locked;
  # First, hopefully most usual case
  if (!-e $lockd && ($locked = mkdir($lockd,0700))) { return $locked }
  my $tryfor=10; #sec
  $locked = ''; # flag
  for (my $i=0; $i<2*$tryfor; ++$i) {
    select(undef,undef,undef,0.5); # wait for 0.5 sec
    !-e $lockd && ($locked = mkdir($lockd,0700));
    if ($locked) { return $locked }
  }
  $Error.="393-ERR:Could not lock file ($fname)\n"; return $locked;
}

# Unlock using mkdir
# unlock_mkdir($fname); # return 1=success ''=fail or no lock
sub unlock_mkdir {
    my $fname = shift; my $lockd = "$fname.lock";
    if (!-e $lockd) { $Error.="400-ERR:No lock on ($fname)\n"; return '' }
    if (-d $lockd) {  return rmdir($lockd) }
    if (-f $lockd or -l $lockd) { unlink($lockd) }
    $Error.="403-ERR:Unknown error"; return '';
}

1;

__END__
# Documentation
=pod

=head1 NAME

#<? echo "$ModuleName - $ModuleAbstract" !>
#+
CGI::AuthRegister - Simple CGI Authentication and Registration in Perl
#-

=head1 SYNOPSIS

Create sub-directory db in your CGI directory, and the file
db/users.db, which may look as follows (RFC822-like format):

  userid:someid
  email:myemail@domain.com

  userid:user2
  email:email2@domain2.com

It is important to separate records by empty lines, and email field is
important, while userid field is optional.  More fields can be added
if needed, this module does not use other fields.

The following script, named index.cgi, which is available with the
distribution in example/1, demonstrates the main module
functionalities:

  #!/usr/bin/perl
  use CGI qw(:standard);
  use CGI::AuthRegister;

  &require_https;  # Require HTTPS connection
  &analyze_cookie; # See if the user is already logged in

  # Some useful strings
  $HTMLstart = "<HTML><BODY><PRE>Site: $SiteId\n";
  $Formstart = "<form action=\"$ENV{SCRIPT_NAME}\" method=\"post\">";
  $Back = "<a href=\"$ENV{SCRIPT_NAME}\">Click here for the main page.</a>\n";

  $Request_type = param('request_type');
  $Request_type = '' unless grep {$_ eq $Request_type}
    qw(Login Logout Send_Password);

  if ($Request_type eq '') {
    print header(), $HTMLstart;
    if ($SessionId eq '') {
      print "You must login to access this site.\n".
        "You can login using the form with the site-specific password:\n".
        $Formstart."Userid or email: ".textfield(-name=>"userid")."\n".
        "Password: ".password_field(-name=>"password")."\n".
        '<input type="submit" name="request_type" value="Login"/>'.
        "</form>\n";
      print "If you forgot your password, you can retrieve it by email:\n";
      print $Formstart."Email: ".textfield(-name=>"email_pw_send")."\n".
        '<input type="submit" name="request_type" value="Send_Password"/>'.
        "</form>\n";
    } else {
      print "You are logged in as: $UserEmail\n",
        "You can logout by clicking this button:\n",
        $Formstart, '<input type="submit" name="request_type" value="Logout"/>',
        "</form>\n$Back";
    }
  }
  elsif ($Request_type eq 'Login') {
    if ($SessionId ne '') {
      print header(), $HTMLstart, "You are already logged in.\n",
        "You should first logout:\n",
        $Formstart, '<input type="submit" name="request_type" value="Logout"/>',
        "</form>\n$Back";
    }
    else {
      my $email = param('userid'); my $password = param('password');
      if (! &login($email, $password) ) { # checks for userid and email
        print header(), $HTMLstart, "Unsuccessful login!\n"; }
      else {
        print header_session_cookie(), $HTMLstart, "Logged in as $UserEmail.\n"; }
      print $Back; exit;
    }
  }
  elsif ($Request_type eq 'Send_Password') {
    &send_email_reminder(param('email_pw_send'), 'raw');
    print header(), $HTMLstart, "You should receive password reminder if ".
      "your email is registered at this site.\n".
      "If you do not receive remider, you can contact the administrator.\n$Back";
  }
  elsif ($Request_type eq 'Logout') {
    if ($SessionId eq '') {
      print header(), $HTMLstart, "Cannot log out when you are not logged in.\n",
        $Back;
    }
    else {
      logout(); print header_delete_cookie(), $HTMLstart, "Logged out.\n$Back"; }
  }


=head1 DESCRIPTION

CGI::AuthRegister is a Perl module for CGI user authentication and
registration.  It is created with objective to be simple, flexible,
and transparent.  For the sake of simplicity it will likely be not
very portable, but mostly designed for a Linux environment.  For
example, it relies on a directly calling sendmail for sending email
messages.

=head1 SEE ALSO

There are already several modules for CGI authentication in Perl, but
they do not seem to satisfy some specific requirements, that could be
vaguely described as: simple, flexible, robust, and transparent.
Additionally, they do not typically include registration process for
new users and password reminders using email, which are added here.

These are some of the current implementation:

=over 4

=item [CGI::Application::Plugin::Authentication]

Too complex, relies on plugins for different backends (database, flat
files).  The proposed module just uses flat files.

=item [CGI::Auth]

A lot of parameters; too high level, not sufficient flexibility.

=item [CGI::Auth::Auto]

Similar to CGI::Auth.

=item [Apache::AuthCookie]

Relies on the Apache web server; not very flexible.

=item [CGI::Session]

Seem to be too high-level and not leaving sufficient low-level control
and flexibility.

=back

=cut
# $Id: $
