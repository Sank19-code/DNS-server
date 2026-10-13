# Deploying

The server is one process: DNS on port 5300 (UDP and TCP), and the API plus dashboard on 8081.
PaaS hosts like Render, Railway or Vercel don't accept inbound UDP, so it needs a small Linux VM.
This guide uses **Azure for Students** (no credit card, $100 credit, free small Linux VM for
12 months), **Docker**, **Caddy** for HTTPS and a free **DuckDNS** hostname. Any other Linux VM
(Oracle, AWS, DigitalOcean) works the same; only steps 1 and 2 differ.

What you end up with:

| URL / port | Who can reach it | What |
|---|---|---|
| `https://yourname.duckdns.org` | everyone | dashboard + API, through Caddy |
| VM port 5300 (UDP + TCP) | **only your own IP** | the DNS server itself |
| VM port 8081 | nobody from outside | the API, published on the VM's loopback for Caddy only |

## 0. Activate Azure for Students

Sign up at https://azure.microsoft.com/free/students with your **college email address**. No card
is needed. You get $100 of credit for 12 months, renewable each year while you're a student.
If the credit ever runs out, Azure disables the subscription; with no card on file it can't bill you.

**Find your allowed regions first.** Student subscriptions may only deploy to a few regions,
and the list differs per account. Deploying anywhere else fails with `RequestDisallowedByAzure`.
Portal → search **Policy** → *Assignments* → open *Allowed resource deployment regions* (or a
similarly named assignment) → its *Allowed locations* parameter. Pick one of those below.

## 1. Create the VM

Portal → **Virtual machines** → *Create* → *Azure virtual machine*:

| Field | Value |
|---|---|
| Subscription | **Azure for Students** |
| Resource group | new: `dns-filter` |
| Virtual machine name | `dns-filter` (the downloaded key is named after it: `dns-filter_key.pem`) |
| Region | one of your allowed regions (nearest to you) |
| Image | **Ubuntu Server 24.04 LTS - x64 Gen2** (Caddy and Docker Compose v2 are in its package repos) |
| Size | **B2ats v2** (2 vCPU, 1 GiB) or **B1s** (1 vCPU, 1 GiB). Both are in the free 750 hours/month |
| Authentication | SSH public key, username `azureuser`, *Generate new key pair* |
| Public inbound ports | *Allow selected ports* → **SSH (22)** (we add the rest in step 2) |
| Disks → OS disk type | Standard SSD is enough |

*Review + create* → *Create* → **Download private key and create resource**. Keep the `.pem` file;
it's the only way to log in. When it's done, open the VM and note its **Public IP address**.

Log in from **PowerShell** on your PC. Windows' `ssh` refuses a key that other users can read, so
lock it down first:
```powershell
icacls "$HOME\Downloads\dns-filter_key.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"
ssh -i "$HOME\Downloads\dns-filter_key.pem" azureuser@<vm-ip>
```

## 2. Firewall: open only what's needed

VM → **Networking** → *Network settings* → *Create port rule* → *Inbound port rule*. The Network
Security Group is Azure's cloud firewall, outside the VM:

| Source | Source IP | Destination port | Protocol | Action | Name |
|---|---|---|---|---|---|
| Any | | 80,443 | TCP | Allow | `web` |
| IP Addresses | **your IP** | 5300 | Any (UDP + TCP) | Allow | `dns-me-only` |

Also edit the existing **SSH** rule: *Source* → *IP Addresses* → your IP. Then only you can even
try to log in. Find **your IP** at https://ifconfig.me. Home and campus IPs change now and then;
when SSH or DNS from your laptop stops working, update these rules.

> **Never open 5300 to "Any".** An open DNS port is found within hours and used to amplify DDoS
> attacks against other people. The rate limiters help, but this firewall rule is the real
> protection.

Azure's Ubuntu image doesn't block ports on the VM itself, so no `iptables` changes are needed.
(Had they been: Docker publishes container ports through its own NAT rules, which skip the VM's
`INPUT` chain, so VM-level rules for port 5300 belong in Docker's `DOCKER-USER` chain. The
Network Security Group sits outside the VM and always applies.)

## 3. Install Docker and start the server

On the VM:
```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git

# 1 GiB of RAM isn't enough for the Maven + npm build: add 2 GB of swap first
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

git clone https://github.com/Sank19-code/DNS-server.git && cd DNS-server

# Settings go in .env (git-ignored), never in config.properties
echo "DNSFILTER_API_TOKEN=$(openssl rand -hex 24)" > .env
echo "DNSFILTER_API_PUBLICREADS=true" >> .env       # public demo: see below
cat .env    # copy the token to a password manager: you need it to change anything

sudo docker compose up -d --build                  # first build: ~5-10 minutes on a small VM
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
in the `data` volume and survive rebuilds. `restart: unless-stopped` brings the server back after
a VM reboot.

## 4. Hostname and HTTPS

1. Sign in at https://www.duckdns.org, create a subdomain (e.g. `yourname`), set its IP to the
   VM's public IP and click *update ip*. Azure keeps a Standard public IP as long as the VM's IP
   resource exists, even while the VM is stopped.
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
curl -s https://yourname.duckdns.org/api/health                                             # {"status":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE https://yourname.duckdns.org/api/cache   # 401: token needed
powershell -ExecutionPolicy Bypass -File scripts/raw-query.ps1 -Name ad.doubleclick.net -Server <vm-ip>   # rcode=3
powershell -ExecutionPolicy Bypass -File scripts/raw-query.ps1 -Name github.com -Server <vm-ip>           # an address
```
Then open `https://yourname.duckdns.org` and try "Test a domain".

## Updating

```bash
cd DNS-server && git pull && sudo docker compose up -d --build
```

## Keeping an eye on the credit

Portal → **Subscriptions** → *Azure for Students* → *Overview* shows the remaining credit, and
*Cost Management* → *Cost analysis* shows what's using it. The VM size above is covered by the free
hours; small items such as the public IP or disk may draw a little from the credit. Stopping the VM
(*Stop*, which deallocates it) stops compute charges, but the demo is offline while it's stopped.

## Checklist

- [ ] Network Security Group: 80/443 open to all; 5300 and SSH (22) only from your IP
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
- 1 GiB of RAM runs the server comfortably: measured with the full 72k-domain blocklist after
  10,000 queries, about 10 MB of live heap and about 100 MB for the whole Java process. The image
  build is what needs the swap file from step 3; the swap also gives headroom for Docker and Caddy.
