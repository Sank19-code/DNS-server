# Deploying

The server is one process: DNS on port 5300 (or 53, UDP and TCP), and the API plus dashboard on 8081.
PaaS hosts like Render, Railway or Vercel don't accept inbound UDP, so it needs a small Linux VM.
Oracle Cloud's Always Free tier is enough. DigitalOcean or Azure credits from the GitHub Student
Pack also work.

## 1. Create the VM

- Oracle Cloud → Compute → Instances → Create. Ubuntu 22.04 or 24.04, Always Free shape
  (`VM.Standard.A1.Flex` with 1 OCPU / 6 GB is plenty).
- Download the SSH key, note the public IP.

## 2. Open only what you need

In the VCN's **Security List** (Oracle's cloud firewall), add ingress rules:

| Port | Protocol | Source | Why |
|---|---|---|---|
| 22 | TCP | your IP `/32` | SSH |
| 80, 443 | TCP | `0.0.0.0/0` | dashboard over HTTPS (Caddy) |
| 5300 | UDP + TCP | **your IP `/32` only** | DNS (TCP for answers too big for UDP). Never open this to the world |

> **Don't run an open resolver.** A DNS port open to the internet gets found within hours and used
> to amplify DDoS attacks against other people. The built-in rate limiter helps, but the firewall
> rule is the real protection.

Ubuntu images on Oracle also ship with iptables rules. Open the same ports on the VM:
```bash
sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 5300 -s <your-ip> -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 5300 -s <your-ip> -j ACCEPT
sudo netfilter-persistent save
```

## 3. Run it with Docker

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
git clone https://github.com/Sank19-code/DNS-server.git && cd DNS-server

# Secrets go in .env (git-ignored), never in config.properties
echo "DNSFILTER_API_TOKEN=$(openssl rand -hex 24)" > .env
cat .env    # copy this token somewhere safe; the dashboard asks for it when you first open it

sudo docker compose up -d --build
curl -s localhost:8081/api/health      # {"status":"ok"}
```

`docker-compose.yml` publishes 8081 on the VM's loopback only (`127.0.0.1:8081:8081`), so the
dashboard is reachable only through Caddy below, never directly on the public IP. Dashboard edits
to the lists and the saved stats live in the `data` volume and survive rebuilds.

**Public demo?** With a token, everything except `/api/health` needs it, including the query log,
because that log is the browsing history of whoever uses this DNS server. If you want visitors
to see the dashboard and use "Test a domain" without a token, add `DNSFILTER_API_PUBLICREADS=true`
to `.env`. Changes still need the token. Only do that if nobody uses this server as their real DNS.

On Linux, `network_mode: host` in `docker-compose.yml` (instead of `ports:`) lets the rate
limiter see real client IPs. Then set `DNSFILTER_API_BIND=127.0.0.1` so the API isn't exposed on
the public interface.

Without Docker: install `openjdk-17-jre` and copy `dns-filter.jar`, `frontend/dist` and
`blocklists/` over, keeping the same relative layout. Then run
`DNSFILTER_API_TOKEN=... java -jar dns-filter.jar` from the backend folder, under systemd. The API
binds to 127.0.0.1 by default, which is all Caddy needs.

## 4. HTTPS with Caddy

Get a free hostname (for example `yourname.duckdns.org` pointing at the VM's IP), then:

```bash
sudo apt-get install -y caddy
echo 'yourname.duckdns.org {
    reverse_proxy localhost:8081
}' | sudo tee /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy gets and renews the TLS certificate automatically. It reaches the API on localhost, and the
dashboard and API share one origin, so no CORS setting is needed.

## 5. Check it

```bash
# from your laptop (its IP is allowed on 5300)
dig -p 5300 @<vm-ip> ad.doubleclick.net            # status: NXDOMAIN
dig -p 5300 @<vm-ip> github.com                    # an address
dig -p 5300 @<vm-ip> +tcp microsoft.com TXT        # a big answer, over TCP
```
On Windows: `powershell -File scripts\raw-query.ps1 github.com -Server <vm-ip>`.
Open `https://yourname.duckdns.org`, paste the token, and the dashboard should show the queries.

## Checklist

- [ ] UDP and TCP 5300 open only to your own IP
- [ ] `DNSFILTER_API_TOKEN` set (`curl https://yourname.duckdns.org/api/queries` returns 401)
- [ ] HTTPS works and port 8081 isn't reachable from outside
- [ ] `docker compose logs -f` shows the blocklist download and no errors
- [ ] Screenshot / GIF of the live dashboard added to the README
