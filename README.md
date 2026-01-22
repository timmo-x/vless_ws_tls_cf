VLESS + WebSocket + TLS configuration behind Cloudflare

### Censorship Circumvention
- Traffic is **fully encapsulated in TLS (HTTPS)** and routed through **Cloudflare’s CDN**, which is widely used by legitimate websites.
- Blocking Cloudflare IP ranges would cause massive collateral damage, making blanket blocking impractical for censors.
- The server presents a **valid Cloudflare-issued origin certificate**, ensuring strict TLS validation and avoiding downgrade or MITM attacks.

### Deep Packet Inspection (DPI) Evasion
- DPI systems cannot distinguish VLESS traffic from normal HTTPS because:
  - All payloads are encrypted inside TLS 1.2/1.3
  - WebSocket frames are indistinguishable from common real-time web applications
- The WebSocket path is hidden behind a legitimate HTTPS site, and non-WebSocket access returns normal web content or 404 responses.

### Enterprise Proxy Evasion
- This setup has been testing and **successfully used through Zscaler and similar enterprise proxies** without detection:
  - Connections appear as standard HTTPS sessions to a well-known CDN (Cloudflare)
  - No unusual TLS fingerprints or non-standard ports are exposed
  - WebSocket traffic is common and explicitly permitted by most corporate proxies

### Privacy Benefits
- Your real server IP is **never exposed**; only Cloudflare IPs are visible.
- Cloudflare absorbs scanning, probing, and traffic analysis attempts.
- Passive observers see only encrypted HTTPS traffic to a normal website.

### Traffic Obfuscation Summary
- HTTPS + WebSocket = indistinguishable from modern web apps
- CDN fronting = trusted infrastructure camouflage
- TLS encryption = no protocol signatures for DPI to match

- 
---

## Step 1: Domain Setup on Cloudflare

1. Log in to Cloudflare: https://dash.cloudflare.com
2. Add your domain (example: `example.com`)
3. Set DNS:
- **A record**
  ```
  example.com → YOUR_SERVER_IP
  ```
- Proxy status: **🟠 Proxied**
4. SSL/TLS Mode:
- **SSL/TLS → Overview**

---

## Step 2: Server Initial Setup (Fedora 43)

Install required packages:

```bash
dnf install -y vim wget curl certbot nginx nginx-mod-stream
```
---

## Step 3: Obtain Cloudflare Origin SSL Certificate

Cloudflare Origin Certificates allow encrypted traffic between Cloudflare and your server without exposing your real certificate to the public internet.

### Create the Origin Certificate

1. Log in to Cloudflare Dashboard  
   https://dash.cloudflare.com

2. Navigate to: Cloudflare Dashboard → SSL/TLS → Origin Server
3. Click Create Certificate
4. Choose:
   - Private key type: RSA
   - Validity: 15 years
5. Cloudflare will generate:
   - Origin Certificate
   - Private Key
```bash
mkdir -p /etc/ssl/private/
```
7. Save the certificate in /etc/ssl/certs/
8. Save the private key /etc/ssl/private/
9. Set permissions
```bash
chmod 644 /etc/ssl/certs/origin_cert.pem
chmod 600 /etc/ssl/private/origin_key.pem
```
---
## Step 4: Install and Configure Xray
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
```
Fix systemd service (Fedora compatibility)
```bash
sed -i '7d' /etc/systemd/system/xray.service
systemctl daemon-reload
```
Create Directories
```bash
mkdir -p /etc/xray
mkdir -p /var/log/xray
```
Gerenate UUID (for how many users you want to create)
```bash
xray uuid
```
Use the online config generator: https://m0n.org/toolz/vless_ws_tls_cf.html
save Xray config
```bash
vim /usr/local/etc/xray/config.json
```
Enable and Start Xray
```bash
systemctl enable --now xray
```
Verify
```bash
systemctl status xray
```
---
## Step 5: Configure nginx (Reverse Proxy)
```bash
vim /etc/nginx/nginx.conf
```
Replace the entire file with (check your domain):
```bash
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 4096;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 80;
        listen [::]:80;
        server_name example.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name example.com;

        ssl_certificate /etc/ssl/certs/origin_cert.pem;
        ssl_certificate_key /etc/ssl/private/origin_key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;

        location /ray {
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_redirect off;
            proxy_pass http://127.0.0.1:10000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
        }

        location / {
            root /var/www/html;
            index index.html;
        }
    }
}

```
---
## Step 6: Create a Dummy Website
```bash
mkdir -p /var/www/html
vim /var/www/html/index.html
```
Set Permissions
```bash
chown -R nginx:nginx /var/www/html
```
---

## Step 7: Test and Start nginx
```bash
nginx -t
```
Enable and restart:
```bash
systemctl enable --now nginx
systemctl restart nginx
```
---

## Step 8: Client Configuration
- Use the QR code or client config generated earlier:
```bash
https://m0n.org/toolz/vless_ws_tls_cf.html
```
