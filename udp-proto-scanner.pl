#!/usr/bin/perl -w
# udp-proto-scanner - UDP Service Discovery Tool
# Copyright (C) 2008  Mark Lowe
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at mrl@portcullis-security.com
#

use strict;
use Getopt::Long;
use Data::Dumper;
use File::Basename;

my $VERSION = "1.1";
my $bandwidth = "250k";
my $config_file = dirname($0) . "/udp-proto-scanner.conf";
my $max_probes = 3;
my $file;
my $probe_name;
my $list_probes = 0;
my $help = 0;
my %payload;
my $usage = "
Usage: $0 [options] [ -p probe_name ] -f ipsfile
       $0 [options] [ -p probe_name ] 10.0.0.0/16 172.16.16.1 192.168.0.1

Options are:
	--file file       File of ips
	--probe_name      Name of probe or 'all' (default: all probes)
	--list_probes     List all available probe name then exit
	--bandwidth n     Bandwidth to use in bits/sec.  Default $bandwidth
	--configfile file Config file to use.  Default $config_file
	                  or /etc/udp-proto-scan.conf
	--retries n       No of packets to sent to each host.  Default $max_probes
	--help            This message
\n";

GetOptions (
	"bandwidth=s"  => \$bandwidth,
	"configfile=s" => \$config_file,
	"retries=s"    => \$max_probes,
	"probe_name=s" => \$probe_name,
	"list_probes"  => \$list_probes,
	"file=s"       => \$file,
	"help"         => \$help
);

if ($help) {
	print $usage;
	exit 0;
}

unless ($probe_name) {
	$probe_name = "all";
}

# Process config file

unless (open (CONF, "<$config_file")) {
	unless (open (CONF, "</etc/udp-proto-scanner.conf")) {
		die "Can't open config file $config_file or /etc/udp-proto-scanner.conf.\n";
	}
	$config_file = "/etc/udp-proto-scanner.conf";
}

while (<CONF>) {
	chomp;
	next unless /^(\d+)\t([^\t]+)\t([a-fA-F0-9]+)$/;
	my $port = $1;
	my $name = $2;
	my $payload = lc($3);
	$payload{$name}{port} = $port;
	$payload{$name}{payload} = $payload;
}

my @probes_to_use;
if ($list_probes) {
	@probes_to_use = sort keys %payload;
	print "The following probe names (-p argument) are available from the config file $config_file:\n";
	print "* " . join("\n* ", @probes_to_use) . "\n";
	exit 0;
}

my @targets;

unless ($file) {
	while (my $net_or_host = shift) {
		push @targets, $net_or_host;
	}

	unless (scalar(@targets)) {
		print "ERROR: Supply some hosts to scan.\n";
		print $usage;
		exit 1;
	}
}
	
if (defined($probe_name) and $probe_name ne "all" and !defined($payload{$probe_name})) {
	print "ERROR: Probe name $probe_name is not in config file $config_file\n";
	exit 1;
}

if (!defined($probe_name) or $probe_name eq "all") {
	@probes_to_use = sort keys %payload;
} else {
	push @probes_to_use, $probe_name;
}

print "Starting udp-proto-scanner v$VERSION ( http://labs.portcullis.co.uk/application/udp-proto-scanner ) on " . localtime() . "\n";
print "\n";
print "=" x 80 . "\n";
print "Bandwith: .................... $bandwidth bits/second\n";
print "Max Probes per host: ......... $max_probes\n";
print "Config file: ................. $config_file\n";
print "Probes names: ................ " . join(",", @probes_to_use) . "\n";
print "=" x 80 . "\n";
print "\n";

foreach my $probe_name_to_use (@probes_to_use) {
	my $scanner = Scanner::UDP->new();
	my $target_port = $payload{$probe_name_to_use}{port};
	
	my @payload = $payload{$probe_name_to_use}{payload} =~ /(..)/g;
	my $payload = join("", map { chr(hex($_)) } @payload);
	
	$scanner->add_payload($probe_name_to_use, $payload, $target_port);
	$scanner->set_bandwidth($bandwidth);
	$scanner->set_max_probes($max_probes);
	$scanner->add_target_ips_from_list(@targets) unless $file;
	$scanner->add_target_ips_from_file($file) if $file;
	print "Sending $probe_name_to_use probes to " . $scanner->get_host_count() . " hosts...\n";
	$scanner->start_scan;
}

print "\n";
print "Scan complete at " . localtime() . "\n\n";

package Scanner::UDP;
use strict;
use IO::Socket::INET;
use Data::Dumper;
use Getopt::Long;
use Time::HiRes qw( gettimeofday tv_interval );
use Carp;

# The data structure is self-referential.  For host lists of 35000 or more, 
# PERL segfaults when trying to do the garbage collection on script termination.
# Remove this DESTROY and see.
DESTROY {
	my $self = shift;
	my $state = $self->{current_href};

	# unlink the lists - this bit IS required.
	while (defined($state)) {
		my $next_state = $state->{next_href};
		undef $state->{next_href};
		undef $state->{prev_href};
		$state = $next_state;
	}

	# delete all the other hash keys - this bit isn't, but is useful
	# for debugging.
	foreach my $key (keys %{$self}) {
		delete $self->{$key};
	}
}

sub new {
	my $class = shift;
	my %opts = @_;
	my $self = bless {
		bandwidth_bits => "32k",
		max_probes     => 3,
		inter_packet_interval_per_host => 0.5,
		inter_packet_interval => 1,
		reply_callback => \&reply_callback,
		backoff        => 1.5,
		bytes_sent     => 0,
		host_count     => 0,
		rtt            => 1,
		resolve_names  => 1,
		packet_overhead => 28, # 20 bytes of ip header + 8 bytes udp header
		host_count_low_water => 99000,
		host_count_high_water => 100000, # Each Class B uses around 30M of RAM
		@_
	};
	$self->_recalc_delay;
	return $self;
}

sub get_host_count {
	my $self = shift;
	return $self->{host_count};
}

sub _recalc_delay {
	my $self = shift;
	for my $i (0..$self->{max_probes}) {
		${$self->{delay}}[$i] = 1000000 * $self->{inter_packet_interval_per_host} * ($self->{backoff} ** $i);
	}
}

sub reply_callback {
	my ($name, $sport, $ip, $port, $response) = @_;
	print "Received reply to probe $name (target port $sport) from $ip:$port: " . string_to_hex($response) . "\n";
}

sub string_to_hex {
	my $string = shift;
	return join("", map { sprintf "%02x", ord($_) } split("", $string));
}

sub add_payload {
	my $self = shift;
	my $name = shift;
	my $payload = shift;
	my $port = shift;
	push @{$self->{payloads}}, $payload;
	push @{$self->{ports}}, $port;
	push @{$self->{names}}, $name;
	$self->{payload_count}++;
	$self->{packet_size_bytes}->[$self->{payload_count} - 1] = length($self->{payloads}->[$self->{payload_count} - 1]) + $self->{packet_overhead};
	$self->set_bandwidth($self->{bandwidth_bits});
	my $inter_packet_interval_candidate = $self->{packet_size_bytes}->[$self->{payload_count}- 1] / $self->{bandwidth_bytes};
	$self->{inter_packet_interval} = $inter_packet_interval_candidate if ($inter_packet_interval_candidate < $self->{inter_packet_interval});
}

sub set_inter_packet_interval_per_host {
	my $self = shift;
	$self->{inter_packet_interval_per_host} = shift;
	$self->_recalc_delay;
}

sub set_backoff {
	my $self = shift;
	$self->{backoff} = shift;
}

sub set_bandwidth {
	my $self = shift;
	$self->{bandwidth_bits} = shift;
	# Process bandwith option
	
	unless ($self->{bandwidth_bits} =~ /^\d+$/) {
		if ($self->{bandwidth_bits} =~ /^(\d+(?:\.?\d+)?)(\D)$/) {
			my $number = $1;
			my $letter = uc($2);
			if ($letter eq "B") {
				$self->{bandwidth_bits} = $number;
			} elsif ($letter eq "K") {
				$self->{bandwidth_bits} = $number * 1000;
			} elsif ($letter eq "M") {
				$self->{bandwidth_bits} = $number * 1000000;
			} elsif ($letter eq "G") {
				$self->{bandwidth_bits} = $number * 1000000000;
			} else {
				print "ERROR: Illegal bandwitch specification: $self->{bandwidth_bits}\n";
				croak 1;
			}
		} else {
			print "ERROR: Illegal bandwitch specification: $self->{bandwidth_bits}\n";
			croak 1;
		}
		if ($self->{bandwidth_bits} > 1000000) {
			print "WARNING: Scanning at over 1000000 bits/sec is unreliable\n";
		}
	}

	$self->{bandwidth_bytes} = $self->{bandwidth_bits} / 8;
}

sub set_max_probes {
	my $self = shift;
	$self->{max_probes} = shift;
}

sub set_inter_packet_interval_packet {
	my $self = shift;
	$self->{inter_packet_interval_packet} = shift;
}

sub read_next_host {
	my $self = shift;

	if ($self->{read_host_method} eq "range") {
		my $ip_dec = $self->{next_read_ip_dec};

		# Return undef if we've reached the end of the range
		return undef if ($ip_dec > $self->{ip_range_end_dec});

		$self->{next_read_ip_dec}++;
		return _dec_to_ip($ip_dec);
	}

	if ($self->{read_host_method} eq "blocks") {
		my $ip;

		# if we're working on a block, take the next ip from it
		if (defined($self->{current_block})) {
			$ip = $self->{current_block}->nth($self->{current_ip_index}++);
		}

		# if there are no ips left, remove this block
		unless (defined($ip)) {
			$self->{current_block} = undef;
			$self->{current_ip_index} = undef;
			$self->{current_ip_max_index} = undef;
		}

		# start the next block if necessary
		unless (defined($self->{current_block})) {
			$self->{current_block} = shift @{$self->{blocks}};

			# check if we're finished all blocks
			return undef unless defined($self->{current_block});

			$self->{current_ip_index} = 0;
			$self->{current_ip_max_index} = $self->{current_block}->size();
		}

		$ip = $self->{current_block}->nth($self->{current_ip_index}++) unless defined($ip);

		# remove this block if there are no more ips left
		if ($self->{current_ip_index} > $self->{current_ip_max_index}) {
			$self->{current_block} = undef;
		}

		return $ip;
	}

	if ($self->{read_host_method} eq "file") {
		my $fh = $self->{file_handle};
		my $ip = <$fh>;
		if (defined($ip)) {
			chomp $ip;
			$ip =~ s/[\r\n]//g;
			if ($self->{resolve_names}) {
				return _gethostbyname_ascii($ip);
			} else {
				return $ip;
			}
		} else {
			return undef;
		}
	}
}

sub _gethostbyname_ascii {
        my $name = shift;

	my $bin_addr = gethostbyname($name);

	if ($bin_addr) {
		return inet_ntoa($bin_addr);
	} else {
		warn "WARNING: $name doesn't resolve\n";
		return undef;
	}
}


sub _ip_add {
	my $ip = shift;
	my $inc = shift;

	my @octets = split('\.', $ip);
	my $ip_dec = ($octets[0] << 24) + ($octets[1] << 16) + ($octets[2] << 8) + $octets[3];

	return _dec_to_ip($ip_dec + $inc);
}

sub add_target_ips_from_range {
	my $self = shift;
	my $ip_range_start = shift;
	my $ip_range_end = shift;
	$self->{read_host_method} = "range";
	if ($self->{resolve_names}) {
		$self->{ip_range_start} = _gethostbyname_ascii($ip_range_start);
		$self->{ip_range_end} = _gethostbyname_ascii($ip_range_end);
	} else {
		$self->{ip_range_start} = $ip_range_start;
		$self->{ip_range_end} = $ip_range_end;
	}
	$self->{ip_range_end_dec} = _ip_to_dec(_gethostbyname_ascii($ip_range_end));
	$self->{next_read_ip_dec} = _ip_to_dec(_gethostbyname_ascii($ip_range_start));
	
	$self->add_target_ips($self->{host_count_high_water});	
}

sub add_target_ips_from_file {
	my $self = shift;
	my $file = shift;
	$self->{filename} = $file;
	$self->{read_host_method} = "file";
	open ($self->{file_handle}, "<$file") or croak "Cannot open file $file: $!\n";
	$self->add_target_ips($self->{host_count_high_water});	
}

sub add_target_ips_from_list {
	my $self = shift;
	my @targets = @_;
	$self->{read_host_method} = "blocks";
	$self->{blocks} = [] unless defined($self->{blocks});
	foreach my $target (@targets) {
	        my $block = Net::Netmask->new($target);
		push @{$self->{blocks}}, $block;
	}
	$self->add_target_ips($self->{host_count_high_water});	
}

sub add_target_ips {
	my $self = shift;
	my $host_add_target = shift;
	my $last_href;
	my $prev_href;
	my $first_href = 0;

	while (defined(my $ip = $self->read_next_host)) {
		$self->{host_count}++;
		my $state_href = {
			ip => $ip,
			next_probe_time => [0,0], # can send packet straight away, one was last sent in 1970
			probes_sent => 0,
			scan_complete => 0,
			next_href => undef,
			prev_href => undef,
			payload_index => 0
		};

		$first_href = $state_href unless $first_href;
		$last_href = $state_href;
		
		# Link this element to previos one
		# and previous one to this
		if ($prev_href) {
			$prev_href->{next_href} = $state_href;
			$state_href->{prev_href} = $prev_href;
		}
		$prev_href = $state_href;
		last if ($self->{host_count} >= $host_add_target);
	}

	if ($self->{current_href}) {
		# We now have a string for new hrefs which we need to splice into the
		# current list.
	
		# We might have added no hosts, so we need to check that $first_href 
		# is defined
		if ($first_href) {
			my $current_href = $self->{current_href};
	
			# Join start of new list to current href in live list
			$current_href->{prev_href}->{next_href} = $first_href;
			$first_href->{prev_href} = $current_href->{prev_href};
			
			# Join end of new list before current href in live list
			$last_href->{next_href} = $current_href;
			$current_href->{prev_href} = $last_href;
		}
	} else {
		# We don't have a current list to splice new list into
		$self->{current_href} = $first_href if $first_href;

		# join end of list to beginning of list
		$first_href->{prev_href} = $last_href;
		$last_href->{next_href} = $first_href;
	}
}

sub _dump_list {
	my $self = shift;
	my $state_href = $self->{current_href};
	my $first_ip = $state_href->{ip};

	printf "Current IP: %s\n", $state_href->{ip};
	while (1) {
		printf "%s\[payload_index=%s, probes_sent=%s, probe due in %f secs\]->%s\n", $state_href->{ip}, $state_href->{payload_index}, $state_href->{probes_sent}, tv_interval([gettimeofday], $self->{current_href}->{next_probe_time}), $state_href->{next_href}->{ip};
		$state_href = $state_href->{next_href};
		last if $first_ip eq $state_href->{ip};
	}
	print "start\n";
}

sub set_reply_callback {
	my $self = shift;
	$self->{reply_callback} = shift;
}

sub start_scan {
	# TODO Check payload, target_port are set
	my $self = shift;
	my $next_loop_delay = 0;
	my $local_port = int(rand(65535 - 1024)) + 1024;
	my $listen_sock = IO::Socket::INET->new(LocalPort  => $local_port,
	                                        Proto      => "udp",
						ReuseAddr  => 1
	                                        );
	$listen_sock->blocking(0);
	
	die "Can't create listening socket on $local_port: $!\n" unless $listen_sock;
	
	my $probes_sent = 0;
	
	my $scan_start_time = [gettimeofday];
	my $scan_running = 1;
	my $idle_host_timeout = 0;
	my $payload = $self->{payloads}->[0];
	my $socket_flags = 0;
	my $bandwidth_bytes = $self->{bandwidth_bytes};

	# for (my $state_href = $first_href; $state_href; $state_href = _get_next_state($state_href)) {
	my $state_href = $self->{current_href};
	while ($scan_running) {
		# While no of packets we should have sent is less than the number of packets we have sent...
		while ((tv_interval($scan_start_time, [gettimeofday]) * $bandwidth_bytes) > $self->{bytes_sent}) {
			my $target_host = $self->{current_href}->{ip};
			my $elapsed = tv_interval ($self->{current_href}->{next_probe_time}, [gettimeofday]);
			
			if ($elapsed >= 0) {
				# Send probe
				my $sin = sockaddr_in($self->{ports}->[$self->{current_href}->{payload_index}], scalar(gethostbyname($self->{current_href}->{ip})));
				$listen_sock->send($self->{payloads}->[$self->{current_href}->{payload_index}], $socket_flags, $sin);

				$self->{bytes_sent} += $self->{packet_size_bytes}->[$self->{current_href}->{payload_index}];
				
				$probes_sent++;
		
				# Calculate time of next probe
				my ($seconds, $fraction) = gettimeofday;
				my $delay = $self->{delay}->[$self->{current_href}->{probes_sent}];

				$fraction += $delay;
				$seconds += int($fraction / 1000000);
				$fraction = $fraction % 1000000;
				$self->{current_href}->{next_probe_time} = [$seconds, $fraction];
		
				# If this host has been sent the maximum number of probes, remove it from the list (has side effect of advancing current_href)
				if (++$self->{current_href}->{probes_sent} >= $self->{max_probes}) {
					# Remove this host from linked list
					my $status = $self->_remove_state($self->{current_href});

					# Last host, so can't be removed
					if ($status == 0) {
						$scan_running = 0;
						# $self->_dump_list();
						last;
					}

					# Element removed and current_href incremented
					if ($status == 1) {
						# do nothing
					}

					# Payload index incremented, current_href not incremented
					if ($status == 2) {
						# Advance state_href to next host in list
						$self->{current_href} = $self->{current_href}->{next_href};
					}

				# Otherwise, just advance state_href
				} else {
					# Advance state_href to next host in list
					$self->{current_href} = $self->{current_href}->{next_href};
				}	

				# Add more hosts to list if we're running low
				if ($self->{host_count} < $self->{host_count_low_water}) {
					$self->add_target_ips($self->{host_count_high_water});
				}

			} else {
				$idle_host_timeout++;
	
				# If we're too early to send a packet to the current
				# host we're also to early for the one after that, etc...
				# We may as well quit trying for now, receive packets, then
				# go into the big wait at the end of the outer while loop
				last;
			}

			$scan_running = 0 unless $self->receive_packets($listen_sock);
		}
	
		# Wait a while so as not to flood the network
		# Most systems can wait reliably for around 0.01 seconds.
		# Lower times are less reliable.
		if ($scan_running) {
			my $big_wait = _max($self->{inter_packet_interval}, tv_interval([gettimeofday], $self->{current_href}->{next_probe_time}));
			select (undef, undef, undef, $big_wait);
		}

		# It's worth recving packets after the above wait.  If you're only scanning
		# 1 host on a quick lan, the above wait might be more than the rtt.
		$scan_running = 0 unless $self->receive_packets($listen_sock);
	}

	# We calculate the stats before the wait.  This is a bit misleading, but looks nice.
	my $scan_time = tv_interval($scan_start_time, [gettimeofday]);
	my $scan_rate = int (8 * ($self->{bytes_sent} / tv_interval($scan_start_time, [gettimeofday])));

	# must wait for rtt after last packet, then recv.
	# This throws the timings out horribly, but it's the right thing to do
	select (undef, undef, undef, $self->{rtt});	
	$self->receive_packets($listen_sock);
}

# returns 1 once all packets have been cleared from in-tray
# returns 0 if all hosts have been removed from list
sub receive_packets {
	my $self = shift;
	my $listen_sock = shift;
	my $scan_still_running = 1;

	# Recv replies
	my $response;
	$listen_sock->recv($response, 10000);
	while ($response) {
		my $rec_ip = join(".", unpack("C4", $listen_sock->peeraddr));
			
		# Mark scan on this IP as complete
		# Break loop if it's the last host
		if (my $recv_href = $self->_find_state_by_ip($rec_ip)) {
			unless ($self->_remove_state($recv_href)) {
				$scan_still_running = 0;
			}
		} else {
#			print "Received unexpected reply from $rec_ip\n";
		}

		&{$self->{reply_callback}}($self->{names}->[0], $self->{ports}->[0], $rec_ip, $listen_sock->peerport, $response);
		return 0 unless $scan_still_running;
		$listen_sock->recv($response, 10000);
	}
	return 1;
}

sub print_scan_info {
	my $self = shift;

	my $target_info;
	# Print out scan info
	if ($self->{ip_range_start}) {
		$target_info = "Target range: ................ $self->{ip_range_start} - $self->{ip_range_end} (" . (_ip_to_dec(_gethostbyname_ascii($self->{ip_range_end})) - _ip_to_dec(_gethostbyname_ascii($self->{ip_range_start}))) . " ips)";
	} elsif ($self->{filename}) {
		$target_info = "Target range: ................ $self->{filename}";
	} else {
		$target_info = "";
	}
	print "=" x length($target_info) . "\n";
	print "$target_info\n";
	print "Bandwith: .................... $self->{bandwidth_bits} bits/second\n";
	print "Probe count: ................. " . (scalar @{$self->{packet_size_bytes}}) . "\n";
	print "Inter-packet interval: ....... $self->{inter_packet_interval} seconds\n";
	print "Interpacket Interval Per Host: $self->{inter_packet_interval_per_host} seconds\n";
	print "Max Probes: .................. $self->{max_probes}\n";
	print "Backoff ratio: ............... $self->{backoff}\n";
	print "=" x length($target_info) . "\n";
}

sub get_target_count {
	return "WARNING: get_target_count not implemented yet\n";
}

# there must be a built-in for this!
sub _max {
	my $a = shift;
	my $b = shift;

	if ($a gt $b) {
		return $a;
	} else {
		return $b;
	}
}

sub _ip_to_dec {
	my $ip = shift;
	my @octets_start = split('\.', $ip);
	
	return ($octets_start[0] << 24) + ($octets_start[1] << 16) + ($octets_start[2] << 8) + $octets_start[3];
}

sub _dec_to_ip {
	my $dec = shift;
	my @octets;

	$octets[0] = $dec >> 24;
	$dec = $dec - ($octets[0] << 24);
	$octets[1] = $dec >> 16;
	$dec = $dec - ($octets[1] << 16);
	$octets[2] = $dec >> 8;
	$dec = $dec - ($octets[2] << 8);
	$octets[3] = $dec;
	return join(".", @octets);
}

sub _find_state_by_ip {
	my $self = shift;
	my $ip = shift;
	my $state_href = $self->{current_href};
	my $start_ip = $state_href->{ip};

	for (1..$self->{host_count}) {
		return $state_href if ($state_href->{ip} eq $ip);
		$state_href = $state_href->{prev_href};
	}
	return undef; # couldn't find host in list
}

#
# Trys to remove a host from this list.  This can only be done when all probes have
# been processed for the host concerned.
#
# returns 1 if:
# 	host to be removed was removed
# 	NB: if host was removed, current_href was incremented
#
# return 0 if:
# 	The element to be removed was the only one left
#
# returns 2 if:
# 	the payload index was incremented and the element was NOT removed
sub _remove_state {
	my $self = shift;
	my $state_href = shift;

	# If there are no other types of probes left to do for this host...
	if ($state_href->{payload_index} >= ($self->{payload_count}) - 1) {
		$self->{host_count}--;

		# If this is the last host
		if (($state_href->{ip} eq $state_href->{prev_href}->{ip}) and ($state_href->{ip} eq $state_href->{next_href}->{ip})) {
			return 0;

		# Remove host from list
		} else {
			$self->{current_href} = $state_href->{next_href};
		        $state_href->{next_href}->{prev_href} = $state_href->{prev_href};
		        $state_href->{prev_href}->{next_href} = $state_href->{next_href};

			# delete data.  we have a memory leak, hopefully this will help track it down.
			%$state_href = ();
			return 1;
		}

	# Increase the payload_index so the next probe type can be processed
	} else {
		$state_href->{payload_index}++;
		$state_href->{probes_sent} = 0;

		# Calculate time of next probe
		my ($seconds, $fraction) = gettimeofday;
		my $delay = $self->{delay}->[$self->{current_href}->{probes_sent}];

		$fraction += $delay;
		$seconds += int($fraction / 1000000);
		$fraction = $fraction % 1000000;
		$self->{current_href}->{next_probe_time} = [$seconds, $fraction];
		
		return 2;
	}
}

sub _get_next_state {
	my $state_href = shift;
	my $next_href = $state_href->{next_href};
	return $next_href;
}

sub _hex_to_bin {
	my $hex = shift;
	my $bin = join ("", map { chr(hex($_)) } $hex =~ /(..)/g);
	return $bin;
}

sub _bin_to_hex {
	my $bin = shift;
	my $hex = join ("",map { sprintf "%02x", ord($_) } split("", $bin));
}

1;

# Copyright (C) 1998-2006, David Muir Sharnoff <muir@idiom.com>

package Net::Netmask;
no strict;

use vars qw($VERSION);
$VERSION = 1.9015;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(findNetblock findOuterNetblock findAllNetblock
	cidrs2contiglists range2cidrlist sort_by_ip_address
	dumpNetworkTable sort_network_blocks cidrs2cidrs
	cidrs2inverse);
@EXPORT_OK = (@EXPORT, qw(int2quad quad2int %quadmask2bits 
	%quadhostmask2bits imask sameblock cmpblocks contains));

my $remembered = {};
my %imask2bits;
my %size2bits;
my @imask;

# our %quadmask2bits;
# our %quadhostmask2bits;

use vars qw($error $debug %quadmask2bits %quadhostmask2bits);
$debug = 1;

use strict;
use warnings;
use Carp;
use overload
	'""' => \&desc,
	'<=>' => \&cmp_net_netmask_block,
	'cmp' => \&cmp_net_netmask_block,
	'fallback' => 1; 

sub new
{
	my ($package, $net, $mask) = @_;

	$mask = '' unless defined $mask;

	my $base;
	my $bits;
	my $ibase;
	undef $error;

	if ($net =~ m,^(\d+\.\d+\.\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ($1, $2);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+)[:/](\d+\.\d+\.\d+\.\d+)$,) {
		$base = $1;
		my $quadmask = $2;
		if (exists $quadmask2bits{$quadmask}) {
			$bits = $quadmask2bits{$quadmask};
		} else {
			$error = "illegal netmask: $quadmask";
		}
	} elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+)[#](\d+\.\d+\.\d+\.\d+)$,) {
		$base = $1;
		my $hostmask = $2;
		if (exists $quadhostmask2bits{$hostmask}) {
			$bits = $quadhostmask2bits{$hostmask};
		} else {
			$error = "illegal hostmask: $hostmask";
		}
	} elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,)
		&& ($mask =~ m,\d+\.\d+\.\d+\.\d+$,)) 
	{
		$base = $net;
		if (exists $quadmask2bits{$mask}) {
			$bits = $quadmask2bits{$mask};
		} else {
			$error = "illegal netmask: $mask";
		}
	} elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,) &&
		($mask =~ m,0x[a-z0-9]+,i)) 
	{
		$base = $net;
		my $imask = hex($mask);
		if (exists $imask2bits{$imask}) {
			$bits = $imask2bits{$imask};
		} else {
			$error = "illegal netmask: $mask ($imask)";
		}
	} elsif ($net =~ /^\d+\.\d+\.\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ($net, 32);
	} elsif ($net =~ /^\d+\.\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0", 24);
	} elsif ($net =~ /^\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0.0", 16);
	} elsif ($net =~ /^\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0.0.0", 8);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ("$1.0", $2);
	} elsif ($net =~ m,^(\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ("$1.0.0", $2);
	} elsif ($net =~ m,^(\d+)/(\d+)$,) {
		($base, $bits) = ("$1.0.0.0", $2);
	} elsif ($net eq 'default' || $net eq 'any') {
		($base, $bits) = ("0.0.0.0", 0);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$,) {
		# whois format
		$ibase = quad2int($1);
		my $end = quad2int($2);
		$error = "illegal dotted quad: $net" 
			unless defined($ibase) && defined($end);
		my $diff = ($end || 0) - ($ibase || 0) + 1;
		$bits = $size2bits{$diff};
		$error = "could not find exact fit for $net"
			if ! defined $error && (
				! defined $bits
				|| ($ibase & ~$imask[$bits]));
	} else {
		$error = "could not parse $net";
		$error .= " $mask" if $mask;
	}

	carp $error if $error && $debug;

	$ibase = quad2int($base || 0) unless defined $ibase;
	unless (defined($ibase) || defined($error)) {
		$error = "could not parse $net";
		$error .= " $mask" if $mask;
	}
	$ibase &= $imask[$bits]
		if defined $ibase && defined $bits;

	$bits = 0 unless $bits;
	if ($bits > 32) { 
		$error = "illegal number of bits: $bits"
			unless $error;
		$bits = 32;
	}

	return bless { 
		'IBASE' => $ibase,
		'BITS' => $bits, 
		( $error ? ( 'ERROR' => $error ) : () ),
	};
}

sub new2
{
	local($debug) = 0;
	my $net = new(@_);
	return undef if $error;
	return $net;
}

sub errstr { return $error; }
sub debug  { my $this = shift; return (@_ ? $debug = shift : $debug) }

sub base { my ($this) = @_; return int2quad($this->{'IBASE'}); }
sub bits { my ($this) = @_; return $this->{'BITS'}; }
sub size { my ($this) = @_; return 2**(32- $this->{'BITS'}); }
sub next { my ($this) = @_; int2quad($this->{'IBASE'} + $this->size()); }

sub broadcast 
{
	my($this) = @_;
	int2quad($this->{'IBASE'} + $this->size() - 1);
}

sub desc 
{ 
	return int2quad($_[0]->{'IBASE'}).'/'.$_[0]->{'BITS'};
}

sub imask 
{
	return (2**32 -(2** (32- $_[0])));
}

sub mask 
{
	my ($this) = @_;

	return int2quad ( $imask[$this->{'BITS'}]);
}

sub hostmask
{
	my ($this) = @_;

	return int2quad ( ~ $imask[$this->{'BITS'}]);
}

sub nth
{
	my ($this, $index, $bitstep) = @_;
	my $size = $this->size();
	my $ibase = $this->{'IBASE'};
	$bitstep = 32 unless $bitstep;
	my $increment = 2**(32-$bitstep);
	$index *= $increment;
	$index += $size if $index < 0;
	return undef if $index < 0;
	return undef if $index >= $size;
	return int2quad($ibase+$index);
}

sub enumerate
{
	my ($this, $bitstep) = @_;
	$bitstep = 32 unless $bitstep;
	my $size = $this->size();
	my $increment = 2**(32-$bitstep);
	my @ary;
	my $ibase = $this->{'IBASE'};
	for (my $i = 0; $i < $size; $i += $increment) {
		push(@ary, int2quad($ibase+$i));
	}
	return @ary;
}

sub inaddr
{
	my ($this) = @_;
	my $ibase = $this->{'IBASE'};
	my $blocks = int($this->size()/256);
	return (join('.',unpack('xC3', pack('V', $ibase))).".in-addr.arpa",
		$ibase%256, $ibase%256+$this->size()-1) if $blocks == 0;
	my @ary;
	for (my $i = 0; $i < $blocks; $i++) {
		push(@ary, join('.',unpack('xC3', pack('V', $ibase+$i*256)))
			.".in-addr.arpa", 0, 255);
	}
	return @ary;
}

sub tag
{
	my $this = shift;
	my $tag = shift;
	my $val = $this->{'T'.$tag};
	$this->{'T'.$tag} = $_[0] if @_;
	return $val;
}

sub quad2int
{
	my @bytes = split(/\./,$_[0]);

	return undef unless @bytes == 4 && ! grep {!(/\d+$/ && $_<256)} @bytes;

	return unpack("N",pack("C4",@bytes));
}

sub int2quad
{
	return join('.',unpack('C4', pack("N", $_[0])));
}

sub storeNetblock
{
	my ($this, $t) = @_;
	$t = $remembered unless $t;

	my $base = $this->{'IBASE'};

	$t->{$base} = [] unless exists $t->{$base};

	my $mb = maxblock($this);
	my $b = $this->{'BITS'};
	my $i = $b - $mb;

	$t->{$base}->[$i] = $this;
}

sub deleteNetblock
{
	my ($this, $t) = @_;
	$t = $remembered unless $t;

	my $base = $this->{'IBASE'};

	my $mb = maxblock($this);
	my $b = $this->{'BITS'};
	my $i = $b - $mb;

	return unless defined $t->{$base};

	undef $t->{$base}->[$i];

	for my $x (@{$t->{$base}}) {
		return if $x;
	}
	delete $t->{$base};
}

sub findNetblock
{
	my ($ipquad, $t) = @_;
	$t = $remembered unless $t;

	my $ip = quad2int($ipquad);
	my %done;

	for (my $b = 32; $b >= 0; $b--) {
		my $nb = $ip & $imask[$b];
		next unless exists $t->{$nb};
		my $mb = imaxblock($nb, 32);
		next if $done{$mb}++;
		my $i = $b - $mb;
		confess "$mb, $b, $ipquad, $nb" if ($i < 0 or $i > 32);
		while ($i >= 0) {
			return $t->{$nb}->[$i]
				if defined $t->{$nb}->[$i];
			$i--;
		}
	}
	return undef;
}

sub findOuterNetblock
{
	my ($ipquad, $t) = @_;
	$t = $remembered unless $t;

	my $ip;
	my $mask;
	if (ref($ipquad)) {
		$ip = $ipquad->{IBASE};
		$mask = $ipquad->{BITS};
	} else {
		$ip = quad2int($ipquad);
		$mask = 32;
	}

	for (my $b = 0; $b <= $mask; $b++) {
		my $nb = $ip & $imask[$b];;
		next unless exists $t->{$nb};
		my $mb = imaxblock($nb, $mask);
		my $i = $b - $mb;
		confess "$mb, $b, $ipquad, $nb" if $i < 0;
		confess "$mb, $b, $ipquad, $nb" if $i > 32;
		while ($i >= 0) {
			return $t->{$nb}->[$i]
				if defined $t->{$nb}->[$i];
			$i--;
		}
	}
	return undef;
}

sub findAllNetblock
{
	my ($ipquad, $t) = @_;
	$t = $remembered unless $t;
	my @ary ;
	my $ip = quad2int($ipquad);
	my %done;

	for (my $b = 32; $b >= 0; $b--) {
		my $nb = $ip & $imask[$b];
		next unless exists $t->{$nb};
		my $mb = imaxblock($nb, 32);
		next if $done{$mb}++;
		my $i = $b - $mb;
		confess "$mb, $b, $ipquad, $nb" if $i < 0;
		confess "$mb, $b, $ipquad, $nb" if $i > 32;
		while ($i >= 0) {
			push(@ary,  $t->{$nb}->[$i])
				if defined $t->{$nb}->[$i];
			$i--;
		}
	}
	return @ary;
}

sub dumpNetworkTable
{
	my ($t) = @_;
	$t = $remembered unless $t;

	my @ary;
	foreach my $base (keys %$t) {
		push(@ary, grep (defined($_), @{$t->{base}}));
		for my $x (@{$t->{$base}}) {
			push(@ary, $x)
				if defined $x;
		}
	}
	return sort @ary;
}

sub checkNetblock
{
	my ($this, $t) = @_;
	$t = $remembered unless $t;

	my $base = $this->{'IBASE'};

	my $mb = maxblock($this);
	my $b = $this->{'BITS'};
	my $i = $b - $mb;

	return defined $t->{$base}->[$i];
}

sub match
{
	my ($this, $ip) = @_;
	my $i = quad2int($ip);
	my $imask = $imask[$this->{BITS}];
	if (($i & $imask) == $this->{IBASE}) {
		return (($i & ~ $imask) || "0 ");
	} else {
		return 0;
	}
}

sub maxblock 
{ 
	my ($this) = @_;
	return imaxblock($this->{'IBASE'}, $this->{'BITS'});
}

sub nextblock
{
        my ($this, $index) = @_;
	$index = 1 unless defined $index;
	my $newblock = bless {
		IBASE	=> $this->{IBASE} + $index * (2**(32- $this->{BITS})),
		BITS	=> $this->{BITS},
	};
	return undef if $newblock->{IBASE} >= 2**32;
	return undef if $newblock->{IBASE} < 0;
	return $newblock;
}

sub imaxblock
{
	my ($ibase, $tbit) = @_;
	confess unless defined $ibase;
	while ($tbit > 0) {
		my $im = $imask[$tbit-1];
		last if (($ibase & $im) != $ibase);
		$tbit--;
	}
	return $tbit;
}

sub range2cidrlist
{
	my ($startip, $endip) = @_;

	my $start = quad2int($startip);
	my $end = quad2int($endip);

	($start, $end) = ($end, $start)
		if $start > $end;
	return irange2cidrlist($start, $end);
}

sub irange2cidrlist
{
	my ($start, $end) = @_;
	my @result;
	while ($end >= $start) {
		my $maxsize = imaxblock($start, 32);
		my $maxdiff = 32 - int(log($end - $start + 1)/log(2));
		$maxsize = $maxdiff if $maxsize < $maxdiff;
		push (@result, bless {
			'IBASE' => $start,
			'BITS' => $maxsize
		});
		$start += 2**(32-$maxsize);
	}
	return @result;
}

sub cidrs2contiglists
{
	my (@cidrs) = sort_network_blocks(@_);
	my @result;
	while (@cidrs) {
		my (@r) = shift(@cidrs);
		my $max = $r[0]->{IBASE} + $r[0]->size;
		while ($cidrs[0] && $cidrs[0]->{IBASE} <= $max) {
			my $nm = $cidrs[0]->{IBASE} + $cidrs[0]->size;
			$max = $nm if $nm > $max;
			push(@r, shift(@cidrs));
		}
		push(@result, [@r]);
	}
	return @result;
}

sub cidrs2cidrs
{
	my (@cidrs) = sort_network_blocks(@_);
	my @result;
	while (@cidrs) {
		my (@r) = shift(@cidrs);
		my $max = $r[0]->{IBASE} + $r[0]->size;
		while ($cidrs[0] && $cidrs[0]->{IBASE} <= $max) {
			my $nm = $cidrs[0]->{IBASE} + $cidrs[0]->size;
			$max = $nm if $nm > $max;
			push(@r, shift(@cidrs));
		}
		my $start = $r[0]->{IBASE};
		my $end = $max - 1;
		push(@result, irange2cidrlist($start, $end));
	}
	return @result;
}

sub cidrs2inverse
{
	my $outer = shift;
	$outer = __PACKAGE__->new2($outer) || croak($error) unless ref($outer);
	my (@cidrs) = cidrs2cidrs(@_);
	my $first = $outer->{IBASE};
	my $last = $first + $outer->size() -1;
	shift(@cidrs) while $cidrs[0] && $cidrs[0]->{IBASE} + $cidrs[0]->size < $first;
	my @r;
	while (@cidrs && $first <= $last) {
		if ($first < $cidrs[0]->{IBASE}) {
			if ($last <= $cidrs[0]->{IBASE}-1) {
				return (@r, irange2cidrlist($first, $last));
			}
			push(@r, irange2cidrlist($first, $cidrs[0]->{IBASE}-1));
		}
		last if $cidrs[0]->{IBASE} > $last;
		$first = $cidrs[0]->{IBASE} + $cidrs[0]->size;
		shift(@cidrs);
	}
	if ($first <= $last) {
		push(@r, irange2cidrlist($first, $last));
	}
	return @r;
}

sub by_net_netmask_block
{
	$a->{'IBASE'} <=> $b->{'IBASE'}
		|| $a->{'BITS'} <=> $b->{'BITS'};
}

sub sameblock
{
	return ! cmpblocks(@_);
}

sub cmpblocks
{
	my $this = shift;
	my $class = ref $this;
	my $other = (ref $_[0]) ? shift : $class->new(@_);
	return cmp_net_netmask_block($this, $other);
}

sub contains
{
	my $this = shift;
	my $class = ref $this;
	my $other = (ref $_[0]) ? shift : $class->new(@_);
	return 0 if $this->{IBASE} > $other->{IBASE};
	return 0 if $this->{BITS} > $other->{BITS};
	return 0 if $other->{IBASE} > $this->{IBASE} + $this->size -1;
	return 1;
}

sub cmp_net_netmask_block
{
	return ($_[0]->{IBASE} <=> $_[1]->{IBASE} 
		|| $_[0]->{BITS} <=> $_[1]->{BITS});
}

sub sort_network_blocks
{
	return
		map $_->[0],
		sort { $a->[1] <=> $b->[1] || $a->[2] <=> $b->[2] }
		map [ $_, $_->{IBASE}, $_->{BITS} ], @_;

}

sub sort_by_ip_address
{
	return
		map $_->[0],
		sort { $a->[1] cmp $b->[1] }
		map [ $_, pack("C4",split(/\./,$_)) ], @_;

}

BEGIN {
	for (my $i = 0; $i <= 32; $i++) {
		$imask[$i] = imask($i);
		$imask2bits{$imask[$i]} = $i;
		$quadmask2bits{int2quad($imask[$i])} = $i;
		$quadhostmask2bits{int2quad(~$imask[$i])} = $i;
		$size2bits{ 2**(32-$i) } = $i;
	}
}
1;
