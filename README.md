# Hints
My name is Dušan. And I will share my knowledge with you. Here you can find hints about Linux, SRE, DBs, programming itself...


# Table of Contents
### General
* [MySQL utf8mb4](#section11)
* [Zombie process](#section1)
* [SSH X11 forwarding and Chrome Headless](#section18)
* [Patch snap pdftk to run from another folder](#section26)
* [List huge dirs](#section28)
### Security
* [Raspberry Pi + Pi hole + cloudflared auto update](#section19)
* [Fail2Ban Server Config](#section13)
* [Allow only Cloudflare IPs](#section20)

### Configuration
* [MySQL server tunnings](#section8)
* [Limit open files (MacOS) tunnings](#section14)
* [Limit max processes (MacOS) tunnings](#section15)
* [Enable ramdisk (MacOS)](#section16)
* [NGINX Web Server Config](#section24)
* [SSH Client Config](#section22)
* [Apple Magic Keyboard on Ubuntu](#section27)

### Performance
* [Dirty Python](#section3)
* [Regex vs split/explode](#section4)
* [Chrome Headless creates huge server load](#section5)
* [Limit cpu resources per process](#section17)


### Site Reliability Engineering
* [SRE: MySQL server](#section10)
* [SRE: Force caching of files on disk](#section12)
* [SSH Clone Remote Machine](#section25)
* [PHP-FPM long-run is expensive](#section2)
* [Forking is expensive](#section9)

### Miscellaneous
* [Record my desktop alias for getting window id](#section32)




<a name="section26"></a>

## Patch snap pdftk to run from another folder
In case you need to modify pdftk which comes from snap, in order to run it from your folder.
You need to apply following

I have unquashed snap and unpacked it to /tmp/pdftk
``` sh
dpanic@master:current/usr/bin ➜ ./pdftk   
zsh: not a directory: ./pdftk
```

``` sh
cd /tmp/pdftk/usr/bin
patchelf --set-interpreter /tmp/pdftk/current/lib/x86_64-linux-gnu/ld-2.23.so pdftk
```

``` sh
dpanic@master:current/usr/bin ➜ ./pdftk        
SYNOPSIS
       pdftk <input PDF files | - | PROMPT>
            [ input_pw <input PDF owner passwords | PROMPT> ]
            [ <operation> <operation arguments> ]
            [ output <output filename | - | PROMPT> ]
            ...
```





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
``` python
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

``` python
try:
    head = html.split('</head>')[0]
except:
    pass
```
Than XML DOM parsing or similar.



<a name="section5"></a>

## Chrome Headless creates huge server load
Context switching is expensive, use kernel-lowlatency. Test case can be https://www.example.com or any similar website which is consuming lots of GPU.

``` sh
apt-get install linux-lowlatency
```

Or preferably you can setup /tmp for using ramdisk by adding it in /etc/fstab:
``` sh
tmpfs /tmp tmpfs defaults,mode=1777,size=2048M 0 0
```



<a name="section8"></a>

## MySQL server tunnings
I have tuned MySQL server with this tool https://raw.githubusercontent.com/major/MySQLTuner-perl/master/mysqltuner.pl which will give you some cool advices. But here is /etc/mysql/mysql.conf.d/mysql.conf:

```
[mysqld_safe]
socket=/var/run/mysqld/mysqld.sock
nice=0

[mysqld]
open_files_limit=8000
user=mysql
pid-file=/var/run/mysqld/mysqld.pid
#socket=/var/run/mysqld/mysqld.sock
port=3306
basedir=/usr
datadir=/var/lib/mysql
tmpdir=/tmp
lc-messages-dir=/usr/share/mysql

skip-external-locking
skip-name-resolve=1
skip-host-cache

bind-address=127.0.0.1
character-set-server=utf8
init-connect='SET NAMES utf8'
max_connections=1000
connect_timeout=10
default-storage-engine=InnoDB
interactive_timeout=120

key_buffer_size=24M
max_allowed_packet=256M
thread_stack=192K
thread_cache_size=100

myisam_recover_options=BACKUP

log_error=/var/log/mysql/error.log
expire_logs_days=10
#max_binlog_size=100M

innodb_file_per_table=1
innodb_flush_method=O_DIRECT
innodb_buffer_pool_size=1G
innodb_log_file_size=256M
innodb_log_buffer_size=16M
innodb_buffer_pool_instances=2
innodb_redo_log_capacity=268435456

innodb_write_io_threads=64
innodb_read_io_threads=64
innodb_thread_concurrency=8
innodb_io_capacity=10000
innodb_io_capacity_max=20000

innodb_flush_log_at_trx_commit=2
sync_binlog=1
```


<a name="section9"></a>

## Forking is expensive
When doing any kind of forking, creating new process. That is very expensive operation, because due to context switches. For example if you take following Python code:

``` python
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

``` sh
$ mysqlcheck -u root --password=[REDACTED] -o --all-databases
```

<a name="section11"></a>

## MySQL utf8mb4
MySQL use utf8mb4 over utf8 encoding. Reference: https://medium.com/@adamhooper/in-mysql-never-use-utf8-use-utf8mb4-11761243e434
​


<a name="section12"></a>

## SRE: Force caching of files on disk
If you have system similar to Amazon's Lambda, something which is constantly starting/stopping some code, or you have Web Application which you want to make highly available, reducing disk reads. You may force it (from time to time) to re-read, cache whole source code. Example: /usr/bin/vmtouch ; Reference: https://hoytech.com/vmtouch/ 

Example code:
``` sh
#!/bin/bash

cd /var/www/html

files=`find -type f|grep php`
for file in $files; do
    vmtouch -t $file
done
```

<a name="section13"></a>

## Fail2Ban Server Config 
Sometimes is cool to setup fail2ban rule for SSH to ban after 3 failed requests, email you about that and block that bot/person for 86400 seconds. However, as fail2ban knows how to read logs, it can be configured for analyzing abusive 403, 401, 50X, 30X requests on web server...


```
/etc/fail2ban/jail.d/default.conf:

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime  = 1d
findtime  = 10m
maxretry = 3
action = %(action_mwl)s
destemail = example@example.com
sender = fail2ban@example.com
backend = auto
banaction = iptables-multiport

[sshd]
enabled = true
maxretry  = 3
findtime  = 1d
```


<a name="section14"></a>

## Limit open files (MacOS) tunnings

Execute following script:
``` sh
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

``` sh
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

``` sh
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

``` javascript
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

``` sh
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
``` sh
0 6 * * * /bin/bash /home/pi/update.sh > /var/log/update.log 2>&1
```





<a name="section20"></a>
## Allow only Cloudflare to acccess server on port 80

This script downloads most recent IPs v4 from Cloudflare and sets them as allowed for access on port 80, every other IP is blocked. 

``` sh
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




<a name="section24"></a>
## NGINX Web Server Config

Optimized NGINX configuration:
``` nginx
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
``` sh
ssh root@server "sudo dd if=/dev/vda1 | gzip -1 -" | dd of=disk.img.gz
```







<a name="section28"></a>
## Apple Magic Keyboard on Ubuntu

Enable kernel module:
``` sh
echo options hid_apple fnmode=2 | sudo tee -a /etc/modprobe.d/hid_apple.conf
sudo update-initramfs -u -k all
```

Fix missing `, type this:
``` sh
echo "setxkbmap -option apple:badmap" >> ~/.profile
```


<a name="section27"></a>
## List huge dirs
This code is way much faster than listdir, because it uses low level syscall *getdents* directly

Compile following code with ```gcc listdir.c -o listdir```
``` C
#define _GNU_SOURCE
#include <dirent.h>     
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct linux_dirent {
    unsigned long  d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

#define BUF_SIZE 1024*1024*5

int main(int argc, char *argv[]) {
    int fd;
    long nread;
    char buf[BUF_SIZE];
    struct linux_dirent *d;
    char d_type;

    fd = open(argc > 1 ? argv[1] : ".", O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        handle_error("open");
    }

    for (;;) {
        nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
        if (nread == -1) {
            handle_error("getdents");
        }

        if (nread == 0) {
            break;
        }

        for (long bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *) (buf + bpos);
            
            if (d->d_ino != 0) {
                printf("%s\n", (char *) d->d_name);
            }
            bpos += d->d_reclen;
        }
    }

    exit(EXIT_SUCCESS);
}
```



<a name="section32"></a>
## Record my desktop alias for getting window id

Snippet:
``` SH
alias recordmywindow="recordmydesktop --windowid \`xwininfo | grep 'id: 0x' | grep -Eo '0x[a-z0-9]+'\`"
```

