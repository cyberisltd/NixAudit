#!/usr/bin/expect -f

# geoff.jones@cyberis.co.uk - Geoff Jones 12/07/2012 - v0.1

# Expect script to pull interesting files from a Solaris host

# Copyright (C) 2012  Cyberis Limited

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#exp_internal 1
set timeout 180
set server [lindex $argv 0]
set user [lindex $argv 1]
set pass [lindex $argv 2]
set tmp /tmp

# connect to server via ssh, login, and sudo to root
send_user "connecting to $server\n"
spawn ssh $user@$server
set SSHspawn $spawn_id

#login handles cases:
#   login with keys (no user/pass)
#   user/pass
#   login with keys (first time verification)
expect {
  -re "(\\$|>|#) $" { send_user "Logged in with key" } 
  "(yes/no)? " { 
        send "yes\n"
        expect {
          	"assword: " {
			send "$pass\n"
			expect {
				  -re "(\\$|>) $" { send_user "Password sent - logged in\n"}	
			}
		} 	
	}
  }
  "assword: " { 
        send "$pass\n" 
        expect {
		-re "(\\$|>|#) $" { send_user "Password sent - logged in\n" }
        }
  }
  default {
        send_user "Login failed\n"
        exit
  }
}

send "sudo -s\n"
expect -re "(\\$|>|#) $" {}

send "cd /\n"
expect -re "(\\$|>|#) $" {}

send "mkdir -p $tmp/audit-$server/net\n"
expect -re "(\\$|>|#) $" {}

send "ifconfig -a > $tmp/audit-$server/ifconfig.out\n"
expect -re "(\\$|>|#) $" { }

send "tar cf $tmp/audit-$server/etc.tar etc\n"
expect -re "(\\$|>|#) $" { }

send "gzip -f $tmp/audit-$server/etc.tar\n"
expect -re "(\\$|>|#) $" { }

send "find / -type f -perm -002 -print > $tmp/audit-$server/wr.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "find /-xdev -type f -perm -4000 -print > $tmp/audit-$server/suid.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "find / -xdev -type f -perm -2000 -print > $tmp/audit-$server/guid.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "netstat -na > $tmp/audit-$server/netstat-nap.out\n"
expect -re "(\\$|>|#) $" { }

send "ls -alR 2> /dev/null | gzip > $tmp/audit-$server/ls.out.gz\n"
expect -re "(\\$|>|#) $" { }

#Network checks
send "ndd -get /dev/ip ip_forward_src_routed > $tmp/audit-$server/net/ip_forward_src_routed\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip6_forward_src_routed > $tmp/audit-$server/net/ip6_forward_src_routed\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/tcp tcp_rev_src_routes > $tmp/audit-$server/net/tcp_rev_src_routes\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_forward_directed_broadcasts > $tmp/audit-$server/net/ip_forward_directed_broadcasts\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/tcp tcp_conn_req_max_q0 > $tmp/audit-$server/net/tcp_conn_req_max_q0\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/tcp tcp_conn_req_max_q > $tmp/audit-$server/net/tcp_conn_req_max_q\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_respond_to_timestamp > $tmp/audit-$server/net/ip_respond_to_timestamp\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_respond_to_timestamp_broadcast > $tmp/audit-$server/net/ip_respond_to_timestamp_broadcast\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_respond_to_address_mask_broadcast > $tmp/audit-$server/net/ip_respond_to_address_mask_broadcast\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_respond_to_echo_multicast > $tmp/audit-$server/net/ip_respond_to_echo_multicast\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip6_respond_to_echo_multicast > $tmp/audit-$server/net/ip6_respond_to_echo_multicast\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_respond_to_echo_broadcast > $tmp/audit-$server/net/ip_respond_to_echo_broadcast\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/arp arp_cleanup_interval > $tmp/audit-$server/net/arp_cleanup_interval\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_ire_arp_interval > $tmp/audit-$server/net/ip_ire_arp_interval\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_ignore_redirect > $tmp/audit-$server/net/ip_ignore_redirect\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip6_ignore_redirect > $tmp/audit-$server/net/ip6_ignore_redirect\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/tcp tcp_extra_priv_ports > $tmp/audit-$server/net/tcp_extra_priv_ports\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_strict_dst_multihoming > $tmp/audit-$server/net/ip_strict_dst_multihoming\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip6_strict_dst_multihoming > $tmp/audit-$server/net/ip6_strict_dst_multihoming\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip_send_redirects > $tmp/audit-$server/net/ip_send_redirects\n"
expect -re "(\\$|>|#) $" { }
send "ndd -get /dev/ip ip6_send_redirects > $tmp/audit-$server/net/ip6_send_redirects\n"
expect -re "(\\$|>|#) $" { }

send "routeadm -p > $tmp/audit-$server/routeadm.out\n"
expect -re "(\\$|>|#) $" { }

spawn scp -r $user@$server:$tmp/audit-$server /tmp/audit-$server
expect {
                "assword: " {
                        send "$pass\n"
			expect eof { 
				send -i $SSHspawn "rm -fr $tmp/audit-$server\n" 
				expect -i $SSHspawn -re "(\\$|>|#) $" { }
				send -i $SSHspawn "exit\n"
				expect -i $SSHspawn -re "(\\$|>|#) $" { }
				send -i $SSHspawn "exit\n"
				expect -i $SSHspawn -re "(\\$|>|#) $" { }
				exit
			}
                }
}
