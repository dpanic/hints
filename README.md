# Hints
My name is Dušan. And I will share my experience with you. Here you can find hints about Linux, SRE, DBs, programming itself...


# Table of Contents
1. [How to detect zombie process](#section1)
2. [PHP-FPM long-run is expensive on CPU](#section2)
3. [Dirty Python](#section3)
4. [Regex vs split/explode](#section4)
5. [Chrome Headless creates huge server load](#section5)
6. [sysctl.conf for high server throughput](#section6)
7. [Limit open files (Linux) tunnings](#section7)
8. [MySQL server tunnings](#section8)
9. [Forking is expensive](#section9)
10. [SRE: MySQL server](#section10)
11. [MySQL utf8mb4](#section11)
12. [SRE: Force caching of files on disk](#section12)
13. [Fail2Ban to the rescue](#section13)
14. [Limit open files (MacOS) tunnings](#section14)
15. [Limit max processes (MacOS) tunnings](#section15)
16. [Enable ramdisk (MacOS)](#section16)
17. [Limit cpu resources per process](#section17)


<a name="section1"></a>

## How to detect zombie process 
Zombie process is process which is finished, but not removed from process table.
One can create zombie process by following scenario. Parent process forks child process. During it's runtime, parent process dies leaving children process which becomes zombie. So



<a name="section2"></a>

## PHP-FPM long-run is expensive on CPU 
If you design PHP-FPM to do long running requests, you will end up in big server load. PHP is scripting language designed for quick and short responses, not long running ones. To be more precise if you setup PHP-FPM with 20 processes, and you have 20 long running processes your PHP-FPM will be stuck for other requests. Your service should be designed to accept request, enqueue it, give you request id, and kindly ask you to visit it later for results; or push you results when they're finished.



<a name="section3"></a>

## Dirty Python 
If you want to archive speed in Python. You can access/check dictionary key by direct memory access. Example:
```
d = {
    'key1': 'asd',
    'key2': 'asd',
    'key6': 'asd',
}

try:
    tmp = d['key6']
    is_found = True
except:
    is_found = False

print('key is_found = %s' %(is_found))
```

<a name="section4"></a>

## Regex vs split/explode
Sometimes is regex very convinient. Eg. parsing email in submited email form, parsing telephone number in submited form etc. Regexes are implemented as [finite state machine](https://en.wikipedia.org/wiki/Finite-state_machine), and that is why they are not super fast. Usually it is more convinient to do something like this:

```
try:
    head = html.split('</head>')[0]
except:
    pass
```
Than XML DOM parsing or similar.



<a name="section5"></a>

## Chrome Headless creates huge server load
Context switching is expensive, use kernel-lowlatency. Test case can be https://www.telegraf.rs or any similar website which is consuming lots of GPU.
```
apt-get install linux-lowlatency
```

Or preferably you can setup /tmp for using ramdisk by adding it in /etc/fstab:
```
tmpfs /tmp tmpfs defaults,mode=1777,size=2048M 0 0
```


<a name="section6"></a>

## sysctl.conf for high server throughput
Here are server tunings which I use:
```
# Increase size of file handles and inode cache
fs.file-max = 2097152

# Do less swapping
vm.swappiness = 1
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2


### GENERAL NETWORK SECURITY OPTIONS ###

# Number of times SYNACKs for passive TCP connection.
net.ipv4.tcp_synack_retries = 2

# Allowed local port range
net.ipv4.ip_local_port_range = 2000 65535

# Protect Against TCP Time-Wait
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

### TUNING NETWORK PERFORMANCE ###

# Default Socket Receive Buffer
net.core.rmem_default = 31457280

# Maximum Socket Receive Buffer
net.core.rmem_max = 134217728

# Default Socket Send Buffer
net.core.wmem_default = 31457280

# Maximum Socket Send Buffer
net.core.wmem_max = 134217728

# Increase number of incoming connections
net.core.somaxconn = 65536

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 300000

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 25165824

# Increase the maximum total buffer-space allocatable
# This is measured in units of pages (4096 bytes)
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.udp_rmem_min = 16384

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 4096 87380 134217728
net.ipv4.udp_wmem_min = 16384

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
fs.inotify.max_user_watches=524288
fs.inotify.max_user_watches=524288

net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_mem = 50576 64768 98152
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.netdev_max_backlog = 2500
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 5
```
After saving run following command:
```
$ sysctl -p
```


<a name="section7"></a>

## Limit open files (Linux) tunnings
Raising limits in Linux works like this.
Edit /etc/security/limits.conf:
```
*         hard    nofile      524288
*         soft    nofile      524288
root      hard    nofile      524288
root      soft    nofile      524288


*         soft    nproc       10240
*         hard    nproc       10240
root      soft    nproc       10240
root      hard    nproc       1024
```

```
echo "session required pam_limits.so" >> /etc/pam.d/common-session
echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
```


<a name="section8"></a>

## MySQL server tunnings
I have tuned MySQL server with this tool https://raw.githubusercontent.com/major/MySQLTuner-perl/master/mysqltuner.pl which will give you some cool advices. But here is /etc/mysql/mysql.conf.d/mysql.conf:

```
[mysqld_safe]
socket = /var/run/mysqld/mysqld.sock
nice = 0

[mysqld]
open_files_limit = 8000
user = mysql
pid-file = /var/run/mysqld/mysqld.pid
#socket = /var/run/mysqld/mysqld.sock
port = 3306
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql

skip-external-locking
skip-name-resolve
skip-host-cache

bind-address = 127.0.0.1
character-set-server = utf8
init-connect = 'SET NAMES utf8'
max_connections = 1000
connect_timeout = 10
default-storage-engine = InnoDB
interactive_timeout = 120

key_buffer_size = 16M
max_allowed_packet = 16M
thread_stack = 192K
thread_cache_size = 8

myisam_recover_options  = BACKUP

log_error = /var/log/mysql/error.log
expire_logs_days = 10
max_binlog_size = 100M

innodb_file_per_table
query_cache_size=0
query_cache_type=0
query_cache_limit=4M

innodb_buffer_pool_size=1G
innodb_log_file_size=512M
innodb_buffer_pool_instances=1

innodb_write_io_threads = 8
innodb_read_io_threads = 8
innodb_thread_concurrency = 16
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 8M
sync_binlog = 1
```


<a name="section9"></a>

## Forking is expensive
When doing any kind of forking, creating new process. That is very expensive operation, because due to context switches. For example if you take following Python code:

```
def dns_check(self, hostname):
    cmd = [
        '/usr/bin/host',
        '-t',
        'a',
        hostname,
        '8.8.8.8',
    ]

    p2 = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
    stdout, stderr = p2.communicate()
    ...
```

If run in paralell, with multiple threads. This can generate relativelly big server load, because of lots of context switches caused by subprocess.Popen. Better use pure sockets and perform raw dns request or use library which is doing it that way. There are DoH (DNS over HTTPS) these days, so you can perform HTTP request in order to get DNS responses from resolvers.



<a name="section10"></a>

## SRE: MySQL server
When having db with lots of inserts and deletes, index files, table files are constantly growing. In order to shrink database you can do this every N days:

```
$ mysqlcheck -u root --password=[REDACTED] -o --all-databases
```

<a name="section11"></a>

## MySQL utf8mb4
MySQL use utf8mb4 over utf8 encoding. Reference: https://medium.com/@adamhooper/in-mysql-never-use-utf8-use-utf8mb4-11761243e434
​


<a name="section12"></a>

## SRE: Force caching of files on disk
If you have system similar to Amazon's Lambda, something which is constantly starting/stopping some code, or you have Web Application which you want to make highly available, reducing disk reads. You may force it (from time to time) to re-read, cache whole source code. Example: /usr/bin/vmtouch ; Reference: https://hoytech.com/vmtouch/ 



<a name="section13"></a>

## Fail2Ban to the rescue 
Sometimes is cool to setup fail2ban rule for SSH to ban after 3 failed requests, email you about that and block that bot/person for 86400 seconds. However, as fail2ban knows how to read logs, it can be configured for analyzing abusive 403, 401, 50X, 30X requests on web server...


```
/etc/fail2ban/jail.conf:

findtime = 600
maxretry = 5
destemail = dpanic@gmail.com
sender = dpanic.fail2ban@gmail.com
mta = sendmail
action = %(action_mwl)s
```


<a name="section14"></a>

## Limit open files (MacOS) tunnings

Execute following script:
```
#!/bin/bash

rm -rf '/Library/LaunchDaemons/limit.maxfiles.plist'
echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>limit.maxfiles</string>
    <key>ProgramArguments</key>
    <array>
      <string>launchctl</string>
      <string>limit</string>
      <string>maxfiles</string>
      <string>524288</string>
      <string>524288</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ServiceIPC</key>
    <false/>
  </dict>
</plist>' >> '/Library/LaunchDaemons/limit.maxfiles.plist'
launchctl unload /Library/LaunchDaemons/limit.maxfiles.plist
launchctl load -w /Library/LaunchDaemons/limit.maxfiles.plist
```


<a name="section15"></a>

## Limit max processes (MacOS) tunnings
Execute following script:

```
#!/bin/bash

rm -rf '/Library/LaunchDaemons/limit.maxproc.plist'
echo '<?xml version="1.0" encoding="UTF-8"?>  
<!DOCTYPE plist PUBLIC "-//Apple/DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">  
  <plist version="1.0">
    <dict>
      <key>Label</key>
        <string>limit.maxproc</string>
      <key>ProgramArguments</key>
        <array>
          <string>launchctl</string>
          <string>limit</string>
          <string>maxproc</string>
          <string>10000</string>
          <string>10000</string>
        </array>
      <key>RunAtLoad</key>
        <true />
      <key>ServiceIPC</key>
        <false />
    </dict>
  </plist>' >> '/Library/LaunchDaemons/limit.maxproc.plist'
launchctl unload /Library/LaunchDaemons/limit.maxproc.plist
launchctl load -w /Library/LaunchDaemons/limit.maxproc.plist
```



<a name="section16"></a>

## Enable ramdisk (MacOS):

```
#!/bin/bash

echo '#!/bin/sh' > /var/root/ramfs.sh
echo '#!/bin/bash
NAME="ramdisk"
while [ ! -d /Volumes ]
do
    echo "waiting..."
    sleep 2
done
if [ ! -d /Volumes/$NAME ]; then
    echo "creating ramdisk..."
    diskutil erasevolume HFS+ $NAME `hdiutil attach -nomount ram://3145728`
fi' >> /var/root/ramfs.sh


chmod +x /var/root/ramfs.sh

rm -rf '/Library/LaunchDaemons/com.ramdisk.plist'
echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.ramdisk</string>
        <key>ProgramArguments</key>
        <array>
          <string>/bin/sh</string>
          <string>/var/root/ramfs.sh</string>
        </array>
        <key>RunAtLoad</key>
          <true/>
        <key>KeepAlive</key>
          <true/>
    </dict>
</plist>' >> '/Library/LaunchDaemons/com.ramdisk.plist'
launchctl load /Library/LaunchDaemons/com.ramdisk.plist
```

(#section17)
## Limit cpu resources per process
One can limit how many CPU resources are consumed by it's cpu on multiple ways. By using simple:
[cputool](https://gitlab.devlabs.linuxassist.net/cputool/cputool) by example ```/usr/bin/cputool -c 60 --``` or by using more robust **cgroups**.
- Reference 1: http://man7.org/linux/man-pages/man7/cgroups.7.html
- Reference 2: https://www.digitalocean.com/community/tutorials/how-to-limit-resources-using-cgroups-on-centos-6

Problem with cputool as it is hacky way, sending to the process following signals SIGSTOP and SIGCONT. 