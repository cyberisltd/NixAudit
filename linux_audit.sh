#!/usr/bin/expect -f

# geoff.jones@cyberis.co.uk - Geoff Jones 12/07/2012 - v0.1

# Expect script to pull interesting files from a Linux host

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

use strict;

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

send "mkdir $tmp/audit-$server\n"
expect -re "(\\$|>|#) $" {}

send "ifconfig -a > $tmp/audit-$server/ifconfig.out\n"
expect -re "(\\$|>|#) $" { }

send "tar czf $tmp/audit-$server/etc.tar.gz etc\n"
expect -re "(\\$|>|#) $" { }

send "find / -type f -perm -002 -print > $tmp/audit-$server/wr.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "find /-xdev -type f -perm -4000 -print > $tmp/audit-$server/suid.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "find / -xdev -type f -perm -2000 -print > $tmp/audit-$server/guid.out 2> /dev/null\n"
expect -re "(\\$|>|#) $" { }

send "netstat -nap > $tmp/audit-$server/netstat-nap.out\n"
expect -re "(\\$|>|#) $" { }

send "ls -alR 2> /dev/null | gzip > $tmp/audit-$server/ls.out.gz\n"
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
