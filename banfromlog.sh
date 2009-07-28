#!/bin/bash

#
# banfromlog: examines logs to prevent attacks and forbids ips who tries to do
#             nasty things.
# Copyright (C) 2005 Jose Sanchez (Original version) <jose_at_serhost_dot_com>
# Copytight (C) 2009 Mateo Matachana (Current version) <mat30.mail gmail.com>

# Specials thanks to: Julio Mendoza
# julio_dot_mendoza_at_eemsystems_dot_com  - http://eemsystems.com/
# who suggest the sqlite compatibility and programmed almost all sqlite compatibility

# This script was based on another one from: http://tuxworld.homelinux.org
# In this version you hardly can find a line from them.

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA


# CONFIGURE THE FOLLOWING PARAMETERS BEFORE USING THIS SCRIPT.
# THE PLUGINS COULD ALSO HAVE PARAMETERS YOU NEED TO CONFIGURE.
# DON'T USE THE DEFAULT OPTIONS IF POSSIBLE.

IPTABLES="/sbin/iptables"	    # path of iptables
PLUGINDIR="/usr/bfl/plugins"	# Were plugins are stored
DBTYPE="sqlite"			        # MySQL or sqlite
#Field only needed if you use sqlite
SQLITE3_BIN="/usr/bin/sqlite3"	# path of the binary of sqlite
#Fields only needed if you use MySQL
MYSQL_BIN="/usr/bin/mysql"      # path of the binary of mysql
SQL_HOST="localhost"            # Hostname of the SQL server
SQL_USER="sqluser"              # Username of the SQL server
SQL_PASS="sqlpassword"          # Password of the SQL username to connect the 
                                # database. The password can be viewed, so the 
                                # MySQL user should only have SELECT and INSERT 
                                # permissions, not DROP or DELETE.
LIBDIR="/usr/blf/lib"           # Where the auxiliar functions are stored
# Name of the SQL database.

case "$DBTYPE" in
    sqlite)
        SQL_DB_NAME="/root/bfl.db"  # SQLite database file
        ;;
    mysql)
        SQL_DB_NAME="bfl"           # MySQL database   
        ;;
esac

# We made avalaible the database configuration to all the plugins
export LIBDIR
export DBTYPE
export SQLITE3_BIN
export SQL_HOST
export SQL_USER
export SQL_PASS
export SQL_DB_NAME
export MYSQL_BIN

# Remove or comment this two lines AFTER CONFIGURING this script
echo "Configure me first!. Edit me and remove this comment to use me"
exit 0;
#************************************************

. "$LIBDIR/database.api"

case "$1" in

	log2db)
		run-parts "$PLUGINDIR/log2db"
		run-parts "$PLUGINDIR/notify"
	;;

	protect)
		#IMPORTANT: Don't forbid internal networks
		sql_blacklist=`bfl_db_execute_query "SELECT ip FROM blacklist WHERE ip not like '192.168.%%' and ip not like '10.%%' and ip not like '172.%%'"`
		
		for i in `echo $sql_blacklist`
		do
			if [ $i != "ip" ]; then 
				$IPTABLES -I INPUT -p tcp -s $i -j DROP
				#echo "Access from: $i is forbidden";
			fi
		done
	;;


	show)
		run-parts "$PLUGINDIR/show"
	;;

	html)
		#Special thanks to Dr. Joan de Gracia - <jdega25 at yahoo dot es> for the idea
		sql_blacklist=`bfl_db_execute_query "SELECT ip FROM blacklist WHERE ip not like '192.168.%%' and ip not like '10.%%' and ip not like '172.%%'"`

		echo "<pre>"

		for i in `echo $sql_blacklist`
		do
			if [ $i != "ip" ]; then 
				echo $i
			fi
		done

		echo "</pre>"
	;;
	install-db)
	    bfl_db_ensure_db_exists $SQL_DB_NAME
	    run-parts "$PLUGINDIR/log2db" -a install-db
	    run-parts "$PLUGINDIR/notify" -a install-db
	    run-parts "$PLUGINDIR/show" -a install-db
	;;
	*)
		echo 
		echo "This program is free software; you can redistribute it and/or"
		echo "modify it under the terms of the GNU General Public License"
        echo "as published by the Free Software Foundation; either version 2"
        echo "of the License, or (at your option) any later version."
        echo
        echo "This program is distributed in the hope that it will be useful,"
        echo "but WITHOUT ANY WARRANTY; without even the implied warranty of"
        echo "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
        echo "GNU General Public License for more details."
		echo 
		echo "BFL: Examine log files and generate firewall rules."
		echo "Copyright (C) 2005 Jose Sanchez <jose_at_serhost_dot_com>"
		echo "Copyright (C) 2009 Mateo Matachana <mat30.mail gmail.com>"
		echo 
		echo "USE: banfromlog log2db     <--- Logs nasty things to the DB (sqlite or MySQL)"
		echo "     banfromlog protect    <--- Executes the iptables rules to protect your host"
		echo "     banfromlog show       <--- Shows attacks from the ACTUAL log"
		echo "     banfromlog html       <--- Shows logged ips in html format (<pre></pre>)"
		echo
	;;

esac

exit 0
