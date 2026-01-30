# ncae-tryouts-script
## Detailed Service Explanation

### 1. HTTP (Nginx)
-   **Package**: `nginx`
-   **Setup**: Installs the web server and overwrites `/var/www/html/index.html` with "Hello World!".
-   **Why**: This is the default directory Nginx serves. The scoring engine requests `http://<IP>/` which maps to this file.

### 2. FTP (vsftpd)
-   **Package**: `vsftpd` needs to be configured for "anonymous" access.
-   **Configuration**: We replace `/etc/vsftpd.conf` with our custom config.
    -   `anonymous_enable=YES`: Allows login without a real user account.
    -   `anon_root=/srv/ftp`: Tells vsftpd that when an anonymous user logs in, their "root" directory is `/srv/ftp`.
-   **Path Question**: `/srv/ftp` is a standard Linux directory for serving FTP files. The **Scoring Engine** does not know this path exists; it only asks for the file `/iloveftp.txt`. Since we configured the root to be `/srv/ftp`, the engine finds `/srv/ftp/iloveftp.txt` at the root of the FTP server.

### 3. DNS (Bind9)
-   **Package**: `bind9` is the standard DNS server.
-   **Configuration**:
    -   `named.conf.options`: Sets global options (recursion, etc).
    -   `named.conf.local`: Defines our custom zone `"test.local"`.
    -   `db.test.local`: The actual "phonebook" that says `test.local` = `10.10.10.10`.
-   **Check**: The scoring engine will ask your server "Where is test.local?". Your server looks at `db.test.local` and answers.

### 4. SQL (MariaDB)
-   **Package**: `mariadb-server` (drop-in replacement for MySQL).
-   **Remote Access**: By default, databases only listen on `localhost` (127.0.0.1). We create a custom config `/etc/mysql/mariadb.conf.d/99-ncae.cnf` setting `bind-address = 0.0.0.0` to allow connections from the Scoring Engine (any IP). This is safer than editing default files.
-   **Initialization**: We run `init.sql` to create the `cyberforce` database, `supersecret` table, and the user `scoring-sql`.

### 5. SSH (OpenSSH) & Security
-   **User**: Creates `ssh-user`.
-   **Keys**: Adds the public key provided in the briefing to `/home/ssh-user/.ssh/authorized_keys`.
-   **Hardening**:
    -   Edits `/etc/ssh/sshd_config` to ensure `PasswordAuthentication no`. This prevents brute-force password attacks.
-   **Firewall (UFW)**: "Uncomplicated Firewall". We deny all incoming traffic by default, then selectively "poke holes" only for the services we need (21, 22, 53, 80, 3306).
