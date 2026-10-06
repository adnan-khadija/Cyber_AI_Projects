#!/bin/bash 
set -euo pipefail
echo "[+] 1. Gestion des Identités & Privilèges"

cat << 'EOF' >>  /etc/security/limits.conf
* hard core 0
* hard nproc 1000
* hard maxlogins 3
EOF

apt-get install -y libpam-pwquality
sed  -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=14 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 envorce_for_root/' /etc/pam.d/common-password

echo "[+] 2. Sécurisation fichiers & immutabilité "
chmod 1777 /tmp
chmod 1777 /var/tmp
chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow 

echo " [+] 3. hardening OpenSSH" 
SSH_CONF="/etc/ssh/sshd_config"
cp $SSH_CONF "${SSH_CONF}.bak"

sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONF
sed -i 's/#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONF
sed -i 's/#\?Port.*/Port 2222/' $SSH_CONF
sed -i 's/#\?MaxAuthTries.*/MaxAuthTries 2/' $SSH_CONF
systemctl restart sshd

echo "[+] 4. Pare-feu (UFW/iptables)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing 
ufw allow 2222/tcp comment 'Custom SSH'
ufw --force enable 

echo "[+] 5. Audit & Loggin"
apt-get install -y auditd rsyslog lynis
systemctl enable --now auditd rsyslog
