# SSH CA

OpenSSH certificate authority on the GCP Ubuntu Compute Engine instance. Clients (personal devices) get short-lived certs so servers trust the CA instead of individual keys.

- New device: generate key, get it signed. No key copying between devices.
- Lost device: cert expires (7d) or can be revoked early from the web portal.

> The CA private key = root on every server. Passphrase it, back it up offline, lock the box down.

## 1. Create the CA (GCP box)

```bash
sudo mkdir -p /etc/ssh-ca && sudo chmod 700 /etc/ssh-ca
sudo ssh-keygen -t ed25519 -f /etc/ssh-ca/user_ca -C "user-ca"   # strong passphrase
sudo ssh-keygen -t ed25519 -f /etc/ssh-ca/host_ca -C "host-ca"
```

- Back up both private keys offline (password manager / encrypted USB). Losing them = re-trusting every server.
- Harden: key-only SSH, `ufw` allow 22 from your IPs only (or GCP IAP / OS Login), `unattended-upgrades`.

## 2. Trust the CA on each Hetzner server (once)

```bash
# copy /etc/ssh-ca/user_ca.pub to the server, then:
sudo cp user_ca.pub /etc/ssh/user_ca.pub
echo 'TrustedUserCAKeys /etc/ssh/user_ca.pub' | sudo tee /etc/ssh/sshd_config.d/ca.conf
echo 'RevokedKeys /etc/ssh/revoked_keys'      | sudo tee -a /etc/ssh/sshd_config.d/ca.conf
sudo touch /etc/ssh/revoked_keys
sudo sshd -t && sudo systemctl reload ssh
```

If you use the web UI (section 7), the **Trust this CA on your servers** card can copy `user_ca.pub` or download it for you.

Keep existing `authorized_keys` until cert login is tested. Loop over servers with a script/Ansible.

## 3. Onboard a device

On the device:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Send `id_ed25519.pub` to the CA box and sign:

```bash
sudo ssh-keygen -s /etc/ssh-ca/user_ca -I "hope-laptop-2026" -n root,hope -V +7d id_ed25519.pub
```

- `-I` identity (shows in server logs), `-n` allowed usernames, `-V` validity.

Copy `id_ed25519-cert.pub` back to the device's `~/.ssh/`. `ssh root@server` just works. Inspect with `ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub`.

## 4. Lost device

- Wait for the cert to expire, or revoke now: append its **public key** to `/etc/ssh/revoked_keys` on every server.
- If you use the web UI (section 7), click **Revoke key** next to the device. Every server picks up the change within five minutes.

## 5. Host certs (optional)

On the CA box, sign each server's host key:

```bash
sudo ssh-keygen -s /etc/ssh-ca/host_ca -I server1 -h -n server1.example.com,1.2.3.4 -V +52w ssh_host_ed25519_key.pub
```

On the server, put the cert in `/etc/ssh/` and add:

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

On devices, one `~/.ssh/known_hosts` line replaces all host prompts:

```
@cert-authority *.example.com,1.2.3.* ssh-ed25519 AAAA...(contents of host_ca.pub)
```

## 6. Break-glass

If the CA box dies you can't issue certs. Keep:

- One hardware key (YubiKey, `ssh-keygen -t ed25519-sk`) in `authorized_keys` on every server.
- The offline CA key backup.
- Hetzner rescue console as last resort.

## Later: automate signing

Manual re-signing every 7 days gets old. [Smallstep step-ca](https://smallstep.com/docs/step-ca/) on this box + Google OIDC → `step ssh login you@gmail.com` issues a ~16h cert. Same `TrustedUserCAKeys` on servers.

## 7. Web UI (`web/`)

The web UI lets you sign keys, revoke them and manage users from a browser instead of the command line. You log in with a password and a code from an authenticator app. It stores everything in SQLite and runs as a single static binary that uses roughly 15 MB of memory.

The app only listens on `127.0.0.1:8080`, so it can't be reached directly from the internet. A Cloudflare Tunnel exposes it on its own hostname, such as `ca.example.com`.

The commands below use `gcloud compute ssh` and `gcloud compute scp`, so your Google IAM permissions (OS Login) control who can reach the box. `ca-box` stands for your instance name. If gcloud doesn't already know the instance's zone, add `--zone=...`. If you connect through Identity-Aware Proxy, add `--tunnel-through-iap` as well.

### Deploy

Run the deploy script from your own machine. It runs the tests, builds the binary, installs it on the CA box with a locked-down systemd service, and restarts the service. Run it again whenever you want to ship an update. Any arguments after the instance name are passed on to gcloud.

```bash
./web/deploy.sh ca-box --zone=europe-west1-b
```

The script builds for amd64 by default. If your VM runs on ARM, prefix the command with `GOARCH=arm64`.

If your CA key is encrypted, the script asks for its passphrase the first time and stores it in `/etc/ssh-ca/passphrase`, readable only by root. The service has no terminal, so it cannot ask you when it starts. Later deploys reuse that file and do not prompt again. The passphrase therefore sits on the same disk as the key, which protects against someone reading the key file by accident but not against someone who already has root.

After the first deploy, create your login:

```bash
gcloud compute ssh ca-box --command="sudo ssh-ca-web adduser hope root,hope" -- -t
```

The second argument lists the usernames your certificates will allow you to log in as. The command asks for a password and then prints an `otpauth://` link. If your authenticator app asks you to enter a key manually, as Authy does, paste only the 32 characters after `secret=` and choose 6-digit codes. Every run of `adduser` replaces the secret, so delete the old entry from the app whenever you run it again.

Accounts created with `adduser` are admins. Admins see a **Users** page where they can add and remove accounts without touching the box. When you add someone, the site generates their password and authenticator secret and shows them to you once, so send them over a private channel. Removing an account ends its sessions and revokes every key it ever had signed. If every admin is locked out, running `adduser` on the box again creates or resets an admin.

**Edit** on the same page changes an account's server usernames, and whether it is an admin, without touching its password, its authenticator secret or its sessions, so nobody has to re-enrol a phone for that. The usernames a certificate allows are written into the certificate when it is signed, so a username taken away here disappears from the next certificate rather than from the one the person is already carrying; revoke their key if the old certificate has to stop working now. An admin cannot drop their own admin access, in the same way they cannot remove themselves.

### Tunnel

Copy the tunnel script to the box and run it there. It will print a URL the first time; open it in your browser and choose your domain.

```bash
gcloud compute scp web/tunnel.sh ca-box:
gcloud compute ssh ca-box --command="sudo ./tunnel.sh ca.example.com" -- -t
```

When the tunnel is up, remove any GCP firewall rules that allow ports 80, 443 or 8080. The app limits failed logins per visitor using the IP address in Cloudflare's `CF-Connecting-IP` header, and anyone who could reach the app directly could fake that header. If you use IAP for SSH, you can also restrict port 22 to Google's IAP range, `35.235.240.0/20`, so that nothing on the box is open to the public internet at all.

### Cloudflare Access (optional)

Cloudflare Access adds a second login in front of the whole site, so strangers never even see your login page. You need two applications: one that requires your email address for the site, and one that lets your servers fetch `/revoked_keys` without logging in. Access always applies the application with the most specific path, so the second one wins for that single address no matter which you create first.

If you haven't used Zero Trust before, open it in the Cloudflare dashboard once and choose a team name. Then create the application for the ban list first, so there is never a moment when your servers are locked out of it:

1. Go to **Zero Trust** > **Access controls** > **Applications**, select **Create new application**, then **Self-hosted and private**, then **Add public hostname**.
2. Set the subdomain and domain to your web UI's hostname, such as `ca.example.com`, and set the path to `revoked_keys`.
3. Under **Access policies**, create a new policy with the action **Bypass** and an include rule of **Everyone**.
4. Name the application something like "ssh-ca revoked_keys" and select **Create**.

Then create the application for the rest of the site:

1. Start another self-hosted application the same way, with the same hostname and an empty path.
2. Create a policy with the action **Allow** and an include rule of **Emails** containing your email address.
3. Leave **One-time PIN** enabled as the login method, so Cloudflare emails you a code whenever you log in. Set **Session Duration** to 12 hours to match the app's own sessions.
4. Name it "ssh-ca" and select **Create**.

To check the setup, open the site in a private browser window, where Cloudflare should ask for your email address. Then run `curl -i https://ca.example.com/revoked_keys`, which should return `200` with no login involved.

### Sharing the ban list with your servers

Each Hetzner server needs to download the list of banned keys. Add this line to root's crontab on every server to fetch it every five minutes:

```bash
*/5 * * * * curl -fsS https://ca.example.com/revoked_keys -o /etc/ssh/revoked_keys.new && mv /etc/ssh/revoked_keys.new /etc/ssh/revoked_keys
```

When you click **Revoke key**, the app bans the public key itself rather than a single certificate. Every certificate ever issued for that key stops working, and the app will refuse to sign that key again.
