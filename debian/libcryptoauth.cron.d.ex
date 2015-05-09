#
# Regular cron jobs for the libcryptoauth package
#
0 4	* * *	root	[ -x /usr/bin/libcryptoauth_maintenance ] && /usr/bin/libcryptoauth_maintenance
