# Deploying

The server is one process: DNS on port 5300 (UDP and TCP), and the API plus dashboard on 8081.
PaaS hosts like Render, Railway or Vercel don't accept inbound UDP, so it needs a small Linux VM.
This guide uses an **Oracle Cloud Always Free VM**, **Docker**, **Caddy** for HTTPS and a free
**DuckDNS** hostname. (DigitalOcean or Azure credits from the GitHub Student Pack work the same.)

What you end up with:

| URL / port | Who can reach it | What |
|---|---|---|
| `https://yourname.duckdns.org` | everyone | dashboard + API, through Caddy |
| VM port 5300 (UDP + TCP) | **only your own IP** | the DNS server itself |
| VM port 8081 | nobody from outside | the API, published on the VM's loopback for Caddy only |

## 1. Create the VM

Oracle Cloud → Compute → Instances → **Create instance**:

- **Image:** Canonical Ubuntu **24.04** (Caddy and Docker Compose v2 are in its package repos).
- **Shape:** `VM.Standard.A1.Flex` (Ampere ARM), 1 OCPU / 6 GB, Always Free. The Docker image
  builds on ARM as well as x86.
  If Oracle says *out of capacity*, try another availability domain, or use
  `VM.Standard.E2.1.Micro` (1 GB RAM) and add swap in step 3.
- **Networking:** the default VCN with a public subnet, and *Assign a public IPv4 address* on.
- **SSH keys:** *Generate a key pair for me* → **Save private key**. You need it to log in.

Note the instance's **public IP**. Log in from Git Bash on your PC:
```bash
chmod 600 ~/Downloads/ssh-key-*.key
ssh -i ~/Downloads/ssh-key-*.key ubuntu@<vm-ip>
```

## 2. Firewall: open only what's needed

Instance → subnet → **Security List** (Oracle's cloud firewall, outside the VM) → *Add Ingress Rules*:

| Source CIDR | Protocol | Port | Why |
|---|---|---|---|
| `0.0.0.0/0` | TCP | 80, 443 | dashboard over HTTPS (Caddy). 80 is needed for the certificate |
| **your IP**`/32` | UDP | 5300 | DNS, for you only |
| **your IP**`/32` | TCP | 5300 | DNS over TCP (big answers), for you only |

SSH (22) is already open by default. Find **your IP** at https://ifconfig.me. Home and campus IPs
change now and then; when DNS from your laptop stops working, update these two rules.

> **Never open 5300 to `0.0.0.0/0`.** An open DNS port is found within hours and used to amplify
> DDoS attacks against other people. The rate limiters help, but this firewall rule is the real
> protection.

**Why the cloud firewall and not the VM's own iptables for 5300:** Docker publishes container
ports with its own NAT rules, which skip the VM's `INPUT` chain. A rule like
`iptables -I INPUT -p udp --dport 5300 -s <ip> -j ACCEPT` would do nothing for the container.
The Security List sits outside the VM, so it always applies. (To filter on the VM too, rules go
in Docker's `DOCKER-USER` chain.)

Caddy runs directly on the VM, so ports 80/443 *do* go through `INPUT`. Oracle's Ubuntu image
blocks them there by default, so open them:
```bash
sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo netfilter-persistent save
```

## 3. Install Docker and start the server

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git

# Only on the 1 GB E2.1.Micro shape: 2 GB swap, or the Maven/npm build runs out of memory
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

git clone https://github.com/Sank19-code/DNS-server.git && cd DNS-server

# Settings go in .env (git-ignored), never in config.properties
echo "DNSFILTER_API_TOKEN=$(openssl rand -hex 24)" > .env
echo "DNSFILTER_API_PUBLICREADS=true" >> .env       # public demo: see below
cat .env    # copy the token to a password manager: you need it to change anything

sudo docker compose up -d --build                  # first build takes a few minutes
curl -s localhost:8081/api/health                  # {"status":"ok"}
sudo docker compose logs --tail 20                 # blocklist downloaded, servers listening
```

**Public demo (`DNSFILTER_API_PUBLICREADS=true`).** Visitors can open the dashboard and use
"Test a domain" without a token; blocking, unblocking and flushing still need it. The catch: the
query log is public, so it shows every name looked up through this server. Only point your own
devices at it if you're fine with that. Leave the line out for a private dashboard (then
everything except `/api/health` needs the token).

`docker-compose.yml` publishes 8081 on the VM's loopback only (`127.0.0.1:8081:8081`), so the API
is reachable from outside only through Caddy. Dashboard edits to the lists and the saved stats live
in the `data` volume and survive rebuilds.

## 4. Hostname and HTTPS

1. Sign in at https://www.duckdns.org, create a subdomain (e.g. `yourname`), set its IP to the
   VM's public IP and click *update ip*. Oracle keeps that IP for as long as the instance exists.
2. On the VM:
   ```bash
   sudo apt-get install -y caddy
   printf 'yourname.duckdns.org {\n    reverse_proxy localhost:8081\n}\n' | sudo tee /etc/caddy/Caddyfile
   sudo systemctl reload caddy
   ```

Caddy fetches and renews the TLS certificate by itself (that's why port 80 must be open). It also
reads each request completely before passing it on, which shields the Java server from slow
clients. Dashboard and API share one origin, so no CORS setting is needed.

## 5. Check it

From your PC (Git Bash or PowerShell):
```bash
curl -s https://yourname.duckdns.org/api/health                  # {"status":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE https://yourname.duckdns.org/api/cache   # 401: token needed
powershell -ExecutionPolicy Bypass -File scripts/raw-query.ps1 -Name ad.doubleclick.net -Server <vm-ip>   # rcode=3
powershell -ExecutionPolicy Bypass -File scripts/raw-query.ps1 -Name github.com -Server <vm-ip>           # an address
```
Then open `https://yourname.duckdns.org` and try "Test a domain".

## Updating

```bash
cd DNS-server && git pull && sudo docker compose up -d --build
```

## Checklist

- [ ] Security List: 5300 UDP + TCP open to your IP `/32` only; 80 and 443 open to all
- [ ] `DNSFILTER_API_TOKEN` set: `DELETE /api/cache` without it returns 401
- [ ] `https://yourname.duckdns.org` loads with a valid certificate
- [ ] `curl http://<vm-ip>:8081/api/health` from your PC fails (8081 isn't reachable from outside)
- [ ] `sudo docker compose logs` shows the blocklist download and no errors
- [ ] Live demo link and a screenshot / GIF of the dashboard added to the README

## Known limits of the demo setup

- Behind Caddy and Docker, every web visitor reaches the API from the same address, so the
  "Test a domain" rate limit (5 lookups/s) is shared by all visitors, and web lookups show up
  under one client in "top clients". DNS clients on port 5300 are still told apart by their IP.
- The query log is in memory plus `data/stats.json`; nothing is kept beyond the last 500 queries.
