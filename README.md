# logviewer

Read-only web interface for the `*.log` files on a syslog server.

- Lists every file ending in `.log` under a log directory (default `/var/log`, recursive).
- Shows the newest lines across the selected files, newest first.
- Live mode streams new lines as they are written and follows log rotation.
- Field-based search. Each line is parsed into fields (`timestamp`, `host`, `program`, `pid`, `severity`, `facility`, `message`, `file`) plus any `key=value` pairs found in the message.
- HTTPS and login are built in. Passwords are stored as PBKDF2-SHA256 hashes.
- Listens on IPv6 and IPv4 (dual stack) by default.
- Python 3 standard library only. No third-party packages, no JavaScript libraries.

Tested on Python 3.12. The code uses nothing newer than Python 3.7, so it runs on the Python 3.10 that ships with Ubuntu 22.04.

## Search syntax

| Query | Meaning |
|---|---|
| `failed password` | Terms are ANDed and matched anywhere in the line. Quote phrases. |
| `program:sshd` | Field contains the text (case-insensitive). |
| `src=10.1.*` | Field equals the value. `*` and `?` are wildcards. `host=*` means the field exists. |
| `message~"failed .* from"` | Field matches a regular expression. |
| `-program:cron` | A leading minus excludes matches. |
| `severity=err OR severity=crit` | `OR` separates groups of ANDed terms. |
| `src="fe80::1"` | IPv6 addresses work as plain terms or quoted field values. |

A bare token such as `host:port` is read as a field search. Quote it to search for the literal text.

Supported line formats: rsyslog high-precision (`2026-11-07T21:43:38.748723-05:00 host prog[pid]: msg`), traditional BSD (`Nov  7 22:33:38 host prog[pid]: msg`), and RFC 5424 with an optional `<PRI>`. Lines in other formats are still searchable as text and by `file`, and by `key=value` pairs in the line.

## Install (Ubuntu 22.04)

```
sudo git clone https://github.com/jeremy-duncan/logviewer.git /opt/logviewer
sudo useradd --system --no-create-home --shell /usr/sbin/nologin logviewer
sudo mkdir -p /etc/logviewer/tls
sudo install -m 640 -o root -g logviewer /opt/logviewer/logviewer.conf /etc/logviewer/logviewer.conf
sudo install -m 640 -o root -g logviewer /dev/null /etc/logviewer/users
sudo openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 -keyout /etc/logviewer/tls/server.key -out /etc/logviewer/tls/server.crt -subj "/CN=$(hostname -f)" -addext "subjectAltName=DNS:$(hostname -f)"
sudo chown -R root:logviewer /etc/logviewer
sudo chmod 750 /etc/logviewer /etc/logviewer/tls
sudo chmod 640 /etc/logviewer/tls/server.key
sudo chmod 644 /etc/logviewer/tls/server.crt
```

Create a login (the password must be at least 15 characters):

```
sudo python3 /opt/logviewer/logviewer.py --config /etc/logviewer/logviewer.conf adduser NAME
```

Check which log files the service account can read. It should be run with the `adm` group, as the systemd unit does:

```
sudo setpriv --reuid=logviewer --regid=logviewer --groups=adm python3 /opt/logviewer/logviewer.py --config /etc/logviewer/logviewer.conf check
```

Install and start the service:

```
sudo cp /opt/logviewer/logviewer.service /etc/systemd/system/logviewer.service
sudo systemctl daemon-reload
sudo systemctl enable --now logviewer
sudo systemctl status logviewer
```

Open the port. `ufw` only applies the rule to IPv6 when `IPV6=yes` is set in `/etc/default/ufw`:

```
sudo ufw allow 8443/tcp
```

Browse to `https://HOSTNAME:8443/`. For an IPv6 literal use `https://[ADDRESS]:8443/`. Replace the self-signed certificate with one from your CA by pointing `tls_cert` and `tls_key` in `/etc/logviewer/logviewer.conf` at it.

## Configuration

All settings are in `/etc/logviewer/logviewer.conf`. The commented file in this repository lists each one. Notes:

- `/var/log/syslog` does not end in `.log`, so it is not listed unless you set `include_names = syslog`.
- Ubuntu's rsyslog writes files as `syslog:adm` with mode 0640. The unit adds the `adm` group to the service. Logs written by other tools under a different group need that group added to `SupplementaryGroups=` in the unit.
- `search_timeout` and `max_scan_lines` cap how long one search runs. When a search hits a cap, the page says so.

## Behavior to know about

- After 5 failed sign-ins an IP address is locked out for 5 minutes.
- Searches whose text appears in the raw line (`failed password`, `src=10.1.3.5`) scan about a million lines per second. Searches that need every line parsed (`severity=err`, regular expressions) scan about 100,000 lines per second.
- Regular expressions are limited to 200 characters, but a badly written pattern can still be slow. Only signed-in users can run searches.
- Live mode does not replay lines missed while the browser was disconnected.

## Testing status

Exercised with a test suite of sample logs in all three formats: parsing, the query language, time ranges, a 1.5 million line file, the live stream including partial lines and rotation, sign-in lockout, TLS with certificate name checking, rejection of plain HTTP and TLS 1.0 clients, file permissions with the service account, and the web page driven in jsdom.

Not exercised: starting the service under systemd, the `ufw` rule, the IPv6 dual-stack bind (the test machine had no IPv6, so only the IPv4 fallback ran), and a real browser rendering the page.
