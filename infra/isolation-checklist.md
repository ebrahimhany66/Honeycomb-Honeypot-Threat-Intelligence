# Honeycomb - Isolation Checklist
Fill this in on the Azure VM BEFORE exposing the honeypot.
Mark each item [x] only after you have checked it yourself.
## 1. The VM itself
- [ ] Dedicated VM, used only for the honeypot
- [ ] No personal files, no real passwords, no private keys on it
- [ ] No other services running (check with: ss -tlnp)
- [ ] Not joined to any other network or VNet that has real systems
## 2. Network rules (Azure NSG)
- [ ] Port 22 (honeypot) open to the internet
- [ ] Real admin SSH on a different port, open ONLY to my IP
- [ ] All other inbound ports closed
- [ ] Outbound traffic restricted, so the honeypot cannot be used to attack others
## 3. Admin access
- [ ] Admin login by SSH key only, password login disabled
- [ ] Root login over SSH disabled
- [ ] I tested the new admin port from a second terminal BEFORE closing the first one
## 4. The container
- [ ] Image pinned by digest (docker-compose.azure.yml)
- [ ] cap_drop ALL, read_only, no-new-privileges are active
- [ ] Container does not run as root
- [ ] No host folders mounted into the container
- [ ] Docker socket is NOT mounted
## 5. Logs and data
- [ ] cowrie.json is being written (check it)
- [ ] Logs survive a container restart (volume works)
- [ ] Disk space is monitored so logs cannot fill the disk
- [ ] No logs, keys, or passwords are committed to Git
## 6. Sign-off
- Checked by:
- Date:
- Notes:
