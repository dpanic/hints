# Hints
My name is Dušan. And I will share my experience with you. Here you can find hints about Linux, SRE, DBs, programming itself...


# Table of Contents
1. [Zombie process](#section1)
2. [PHP-FPM long-run is expensive](#section2)
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
18. [SSH X11 forwarding and Chrome Headless](#section18)
19. [Raspberry Pi + Pi hole + cloudflared auto update](#section19)
20. [Allow only Cloudflare IPs](#section20)
21. [Enable BFQ scheduler](#section21)
22. [SSH Client Config](#section22)
23. [SSH Server Config](#section23)
24. [NGINX Web Server Config](#section24)
25. [SSH Clone Remote Machine](#section25)


<a name="section1"></a>

## Zombie process 
Zombie process is process which is finished, but not removed from process table.
One can create zombie process by following scenario. Parent process forks child process. During it's runtime, parent process dies leaving children process which becomes zombie. 


<a name="section2"></a>

## PHP-FPM long-run is expensive 
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
fs.file-max = 2097152
fs.inotify.max_user_watches=524288

vm.swappiness = 1
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
vm.max_map_count = 768000
vm.vfs_cache_pressure=50


net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 65535

net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

kernel.sysrq = 0

net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.netdev_budget = 60000
net.core.netdev_budget_usecs = 6000
net.core.rmem_max=10485760

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.accept_ra=0




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

If using ZSH, you should do this as well:
```
echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/system.conf

echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/user.conf
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

<a name="section17"></a>

## Limit cpu resources per process
One can limit how many CPU resources are consumed by it's cpu on multiple ways. By using simple:
[cputool](https://gitlab.devlabs.linuxassist.net/cputool/cputool) by example ```/usr/bin/cputool -c 60 --``` or by using more robust **cgroups**.
- Reference 1: http://man7.org/linux/man-pages/man7/cgroups.7.html
- Reference 2: https://www.digitalocean.com/community/tutorials/how-to-limit-resources-using-cgroups-on-centos-6

Problem with cputool as it works in a hacky way. It works by sending SIGSTOP and SIGCONT to the targeted process.



<a name="section18"></a>
## SSH X11 forwarding and Chrome Headless

In order to enable Linux server to forward X11 you should edit /etc/ssh
Edit /etc/ssh/sshd and uncomment "X11Forwarding yes".

On client side you should connect by following command **ssh -vv -X -C user@ip**. Where -C is enabling compression.

In case you're using Chrome, you should extend puppetter startup time from 30 seconds to 60-90 seconds. Example:

```
let options = {
    headless: true,
    ignoreHTTPSErrors: true,
    dumpio: true,
    timeout: 120 * 1000,
    args: config.puppetter['args'],
};

puppeteer.launch(options).then(async browser => { ... }
```




<a name="section19"></a>
## Raspberry PI + Pi hole + cloudflared auto update

Here is small bash script which maintains Raspbian to be up2date.

Code:

```
#!/bin/bash


sudo apt update
sudo apt-get update 
sudo apt-get upgrade -y
sudo apt-get -y --purge autoremove
sudo apt-get autoclean

/usr/local/bin/pihole -g -up
/usr/local/bin/pihole -up

/usr/local/bin/cloudflared update




if [ -f /var/run/reboot-required ] 
then
        sudo reboot
fi
```


Cron:
0 6 * * * /bin/bash /home/pi/update.sh > /var/log/update.log 2>&1






<a name="section20"></a>
## Allow only Cloudflare to acccess server on port 80

This script downloads most recent IPs v4 from Cloudflare and sets them as allowed for access on port 80, every other IP is blocked. 

```
#!/bin/bash
echo 'y'| sudo ufw reset

sudo ufw default allow incoming
sudo ufw default allow outgoing


sudo ufw allow from 192.168.0.0/16

curl https://www.cloudflare.com/ips-v4 > ips.txt

input="ips.txt"
while IFS= read -r line
do
    if [[ "$line" == "" ]]; then        
        continue
    fi

    val="sudo ufw allow from $line to any port 80"
    eval $val
done < "$input"

sudo ufw deny to any port 80
echo 'y'| sudo ufw enable
sudo ufw status
```



<a name="section21"></a>
## Enable BFQ scheduler

This script enables BFQ scheduler on ssd, nvme and mmcblk devices. 

```
cat /sys/block/*/queue/scheduler

echo "bfq" > /etc/modules-load.d/bfq.conf
echo 'ACTION=="add|change", KERNEL=="sd*[!0-9]|sr*|nvme*|mmcblk*", ATTR{queue/scheduler}="bfq"' > /etc/udev/rules.d/60-scheduler.rules
sudo udevadm control --reload
sudo udevadm trigger

sleep 3
cat /sys/block/*/queue/scheduler
```



<a name="section22"></a>
## SSH Client Config

Optimized SSH Client config:
```
Host *
    ForwardX11 yes
    ForwardAgent yes
    Compression yes
    ControlMaster auto
    ControlPath ~/.ssh/control/%r@%h
    ControlPersist 600
    ServerAliveInterval 60
    ServerAliveCountMax 20
    IPQoS lowdelay throughput
    AddressFamily inet
    Protocol 2
    PreferredAuthentications=publickey,password
```



<a name="section23"></a>
## SSH Server Config

Optimized SSH Server config:
```
Port 22
AddressFamily any
ListenAddress 0.0.0.0

PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
UsePAM yes

AllowAgentForwarding yes
AllowTcpForwarding yes
X11Forwarding yes

PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
UseDNS no

AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

ClientAliveInterval 120
ClientAliveCountMax 40

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com
```




<a name="section24"></a>
## NGINX Web Server Config

Optimized NGINX configuration:
```
user                                www-data;
pid                                 /var/run/nginx.pid;

worker_processes                    auto;
worker_rlimit_nofile                65535;
events {
    worker_connections              65535;
    multi_accept                    on;
}

http {
    # Basic Settings
    sendfile                        on;
    tcp_nopush                      on;
    tcp_nodelay                     on;
    server_tokens                   off;
    log_not_found                   off;

    # Buffer settings
    client_max_body_size            32m;
    client_body_buffer_size         16k;
    client_header_buffer_size       64k;
    large_client_header_buffers     16 128k;

    server_names_hash_bucket_size   64;

    # Timeout settings
    reset_timedout_connection       on;
    client_body_timeout             8;
    client_header_timeout           8;
    send_timeout                    25;

    keepalive_timeout               15;
    keepalive_requests              100;
    open_file_cache                 max=100;
    types_hash_max_size             2048;


    # SSL Settings
    ssl_stapling                    on;
    ssl_stapling_verify             on;
    ssl_prefer_server_ciphers       on;
    ssl_session_tickets             off;
    ssl_session_timeout             1d;
    ssl_session_cache               shared:SSL:10m;
    ssl_buffer_size                 8k;
    ssl_protocols                   TLSv1.2 TLSv1.3;
    ssl_certificate                 /etc/ssl/example.com.tc.crt;
    ssl_certificate_key             /etc/ssl/example.com.key;
    ssl_trusted_certificate         /etc/ssl/example.com.tc.crt;
    ssl_dhparam                     /etc/ssl/example.com.dhp;
    ssl_ciphers                     ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_ecdh_curve                  secp521r1:secp384r1;

    resolver                        1.1.1.1 1.0.0.1 8.8.8.8 4.2.2.2 8.8.4.4 4.2.2.1 valid=300s;
    resolver_timeout                8s;

    # Gzip Settings
    gzip                            on;
    gzip_static                     on;
    gzip_vary                       on;
    gzip_comp_level                 2;
    gzip_buffers                    16 8k;
    gzip_http_version               1.1;
    gzip_disable                    "msie6";
    gzip_min_length                 5120;
    gzip_proxied                    expired no-cache no-store private auth;
    gzip_types                      text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # MIME settings
    include                         /etc/nginx/mime.types;
    default_type                    application/octet-stream;

    # Logging Settings
    access_log                      /var/log/nginx/access.log;
    error_log                       /var/log/nginx/error.log;

    # Virtual Host Configs
    include                         /etc/nginx/conf.d/*.conf;
    include                         /etc/nginx/sites-enabled/*;
}
```



<a name="section25"></a>
## SSH Clone Remote Machine

SSH code to clone remote machine:
```
ssh root@server "sudo dd if=/dev/vda1 | gzip -1 -" | dd of=disk.img.gz
```