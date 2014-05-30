#! /usr/bin/perl

# Given two arguments, which are a range of FileIDs, issue PUT_CHECKDUPE
# commands to the local msgiddbd for every segment in that file.
#
# This uses the MessageIDs.MRG due to laziness, update for Ranges later

use DBI;
use Socket;
use Data::Dumper;

my $dbh = DBI->connect("DBI:mysql:newzDog;host=db4", "newzDog", '$h1tePwd') or die;

my $addr = sockaddr_in(15002, (gethostbyname("localhost"))[4]);
socket(S, AF_INET, SOCK_STREAM, getprotobyname('tcp')) or die;
connect(S, $addr) or die;
select(S); $| = 1; select(STDOUT);

my $line = <S>;
unless ($line =~ /^200 /)
{
	print "msgiddbd didn't give us a 200:\n";
	print $line;
	exit;
}


my $min_id = shift or die "Usage: $0 min_id [max_id]\n";
my $max_id = shift || $min_id;

print "\nPostfilling local msgiddbd IDs with $min_id to $max_id\n";
print "Kill within 2 seconds if this isn't right\n\n";
#sleep 2;

die unless my $sth = $dbh->prepare("SELECT * FROM MessageIDs WHERE mid_fileid = ?");

foreach my $id ($min_id .. $max_id)
{
	print "Working on ID $id .. ";
	my $c = 0;

	# Get segments from SQL
	die unless $sth->execute($id);

	# prefill what msgiddbd has of this file
	my %msgiddbd_has;
	print S "GET $id\n";
	my $resp = <S>;
	if ($resp =~ /^205 /)
	{
		while(<S>)
		{
			last if m/^.$/m;
			m#number="(\d+)">(.*)</segment>#;
			#print "Got $1 is $2\n";
			$msgiddbd_has{$1} = $2;
		}
	}
	elsif ($resp !~ /^404 /)
	{
		print "Didn't get 205/404 from msgiddbd for $id:\n";
		print $resp;
		exit;
	}

	while(my $row = $sth->fetchrow_hashref)
	{
		my $segment_no = $row->{mid_segment};
		next if exists($msgiddbd_has{$segment_no});

		#print "msgiddbd doesn't seem to have segment $segment_no\n";
		my $date = $row->{mid_date};
		my $bytes = $row->{mid_bytes};
		my $msgid = $row->{mid_msgid};

		my $s = "PUT_CHECKDUPE $id:$segment_no:$date:$bytes:$msgid\n";
		print S $s;
		my $resp = <S>;
		unless ($resp =~ m/^200 /)
		{
			print "msgiddbd failure on put:\n";
			print $resp;
			exit;
		}
		$c++;
	}

	print S "COMMIT\n";
	my $resp = <S>;
	unless ($resp =~ m/^(200|300)/)
	{
		print "msgiddbd failure on commit:\n";
		print $resp;
		exit;
	}

	print "added $c segments\n";
	#sleep 1;
}

close(S);
