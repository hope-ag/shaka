# SSH CA

OpenSSH certificate authority, with a web UI that runs on Google Cloud Run. Clients (personal devices) get short-lived certs so servers trust the CA instead of individual keys.

- New device: generate key, get it signed. No key copying between devices.
- Lost device: cert expires (7d) or can be revoked early from the web portal.

> The CA private key = root on every server. Passphrase it and back it up offline.

## 1. Create the CA (on your own machine)

```bash
mkdir -p ~/ssh-ca && chmod 700 ~/ssh-ca
ssh-keygen -t ed25519 -f ~/ssh-ca/user_ca -C "user-ca"   # strong passphrase
```

- Back up the private key offline, in a password manager or on an encrypted USB drive. Losing it means re-trusting every server.
- The web UI (section 6) keeps its own copy of `user_ca` in Secret Manager.

## 2. Trust the CA on each Hetzner server (once)

```bash
# copy ~/ssh-ca/user_ca.pub to the server, then:
sudo cp user_ca.pub /etc/ssh/user_ca.pub
echo 'TrustedUserCAKeys /etc/ssh/user_ca.pub' | sudo tee /etc/ssh/sshd_config.d/ca.conf
echo 'RevokedKeys /etc/ssh/revoked_keys'      | sudo tee -a /etc/ssh/sshd_config.d/ca.conf
sudo touch /etc/ssh/revoked_keys
sudo sshd -t && sudo systemctl reload ssh
```

If you use the web UI (section 6), the **Trust this CA on your servers** card can copy `user_ca.pub` or download it for you.

Keep existing `authorized_keys` until cert login is tested. Loop over servers with a script/Ansible.

## 3. Onboard a device

On the device:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Sign `id_ed25519.pub` with the CA key, or use the web UI (section 6):

```bash
ssh-keygen -s ~/ssh-ca/user_ca -I "hope-laptop-2026" -n root,hope -V +7d id_ed25519.pub
```

- `-I` identity (shows in server logs), `-n` allowed usernames, `-V` validity.

Copy `id_ed25519-cert.pub` back to the device's `~/.ssh/`. `ssh root@server` just works. Inspect with `ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub`.

## 4. Lost device

- Wait for the cert to expire, or revoke now: append its **public key** to `/etc/ssh/revoked_keys` on every server.
- If you use the web UI (section 6), click **Revoke key** next to the device. Every server picks up the change within five minutes.

## 5. Break-glass

If the web UI is down you can still sign by hand with the offline key (section 3). Keep:

- One hardware key (YubiKey, `ssh-keygen -t ed25519-sk`) in `authorized_keys` on every server.
- The offline CA key backup.
- Hetzner rescue console as last resort.

## Later: automate signing

Manual re-signing every 7 days gets old. The web UI (section 6) covers this. [Smallstep step-ca](https://smallstep.com/docs/step-ca/) + Google OIDC → `step ssh login you@gmail.com` issues a ~16h cert. Same `TrustedUserCAKeys` on servers.

## 6. Web UI (`web/`)

The web UI lets you sign keys, revoke them and manage users from a browser instead of the command line. You log in with a password and a code from an authenticator app. It is a single Go binary that keeps everything in SQLite.

It runs on Cloud Run, which scales to zero, so you pay for the moments someone is using it rather than for a machine that is always on. At this app's level of use that stays inside Cloud Run's free tier, and the bucket that holds the database costs a few cents a month. Cloud Run's disk is wiped whenever an instance stops, so [Litestream](https://litestream.io) restores the database from a Cloud Storage bucket when an instance starts and copies every change back to the bucket as it happens. The service is capped at one instance, because SQLite has a single writer and the login throttle lives in memory.

Litestream uploads changes about a second after they happen, and it uploads anything still pending when Cloud Run stops the instance. A change could only be lost if the instance crashed in that second. Object versioning is turned on for the bucket, so older copies of the database can be recovered from it.

### Deploy

You need `gcloud` logged in with the project you want selected (`gcloud config set project ...`), and Go. Run the deploy script from your own machine, passing the domain the site will live on. The first time, set `CA_KEY` to the CA private key from section 1:

```bash
CA_KEY=~/ssh-ca/user_ca ./web/deploy.sh ca.example.com
```

The script runs the tests, then creates whatever is missing: a service account that can read only the CA key and the bucket, the bucket, and Secret Manager secrets for the key and, if the key is encrypted, its passphrase. It asks for the passphrase once, because the service has no terminal to ask on when it starts. It then builds the image with Cloud Build, deploys it and maps your domain to it. Run it again, without `CA_KEY`, whenever you want to ship an update.

The service runs in `europe-west1` unless you set `REGION`. Custom domains only work in `asia-east1`, `asia-northeast1`, `asia-southeast1`, `europe-north1`, `europe-west1`, `europe-west4`, `us-central1`, `us-east1`, `us-east4` and `us-west1`. You can also override `SERVICE` (default `ssh-ca`) and `BUCKET` (default `PROJECT-ssh-ca`), as long as you pass the same values to `admin.sh`.

### Custom domain

Google has to know you own the domain before it will map it. If you haven't verified it before, run `gcloud domains verify example.com` once and follow the Search Console steps, then rerun the deploy script.

At the end, the script prints the DNS records to add for your domain. If your DNS is on Cloudflare, set the records to **DNS only** (grey cloud), not proxied, and turn off **Always Use HTTPS** under **SSL/TLS** > **Edge Certificates**. Google issues the HTTPS certificate itself and needs to reach the service directly to do so, which usually takes about 15 minutes and at most a day. Leaving the records unproxied also matters for the login throttle: the app takes each visitor's address from the last entry in `X-Forwarded-For`, which Google's front end adds, and behind Cloudflare that entry would be Cloudflare's address instead of the visitor's. Custom domain mapping is still a preview feature of Cloud Run.

### Create your login

After the first deploy, create your login:

```bash
./web/admin.sh hope root,hope
```

The second argument lists the usernames your certificates will allow you to log in as. The script pauses the service, restores the database into a temporary folder on your machine, and asks for a password. It then prints an `otpauth://` link, uploads the change and turns the service back on. Litestream reads your Application Default Credentials, so run `gcloud auth application-default login` first if you never have. If your authenticator app asks you to enter a key manually, as Authy does, paste only the 32 characters after `secret=` and choose 6-digit codes. Every run of `admin.sh` replaces that account's secret, so delete the old entry from the app whenever you run it again.

Accounts created with `admin.sh` are admins. Admins see a **Users** page where they can add and remove accounts without running anything locally. When you add someone, the site generates their password and authenticator secret and shows them to you once, so send them over a private channel. Removing an account ends its sessions and revokes every key it ever had signed. If every admin is locked out, running `admin.sh` again creates or resets an admin.

**Edit** on the same page changes an account's server usernames, and whether it is an admin, without touching its password, its authenticator secret or its sessions, so nobody has to re-enrol a phone for that. The usernames a certificate allows are written into the certificate when it is signed, so a username taken away here disappears from the next certificate rather than from the one the person is already carrying; revoke their key if the old certificate has to stop working now. An admin cannot drop their own admin access, in the same way they cannot remove themselves.

### Sharing the ban list with your servers

Each Hetzner server needs to download the list of banned keys. Add this line to root's crontab on every server to fetch it every five minutes:

```bash
*/5 * * * * curl -fsS https://ca.example.com/revoked_keys -o /etc/ssh/revoked_keys.new && mv /etc/ssh/revoked_keys.new /etc/ssh/revoked_keys
```

When you click **Revoke key**, the app bans the public key itself rather than a single certificate. Every certificate ever issued for that key stops working, and the app will refuse to sign that key again.
