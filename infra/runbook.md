# Honeycomb - Runbook (Azure honeypot)
Fill the <...> values after the VM is created.
## Server details
- VM public IP: <VM_IP>
- Admin SSH port: <ADMIN_PORT>
- Admin user: <ADMIN_USER>
- Repo path on VM: <REPO_PATH>
## 1. Connect to the VM (admin)
ssh -p <ADMIN_PORT> <ADMIN_USER>@<VM_IP>
Never connect on port 22. Port 22 is the honeypot.
## 2. Start the honeypot
docker compose -f infra/docker-compose.azure.yml up -d
docker ps --filter "name=honeycomb-cowrie"
## 3. Check it is working
docker logs --tail 50 honeycomb-cowrie
docker exec honeycomb-cowrie ls -l /cowrie/cowrie-git/var/log/cowrie/
## 4. Stop the honeypot
docker compose -f infra/docker-compose.azure.yml down
This keeps the log volume. Never use -v unless you want to delete all data.
## 5. Restart after a reboot
The container uses restart: unless-stopped, so it comes back by itself.
Verify with: docker ps
## 6. Rollback (something went wrong)
1. Stop it: docker compose -f infra/docker-compose.azure.yml down
2. Check the NSG: only port 22 and <ADMIN_PORT> should be open
3. Start it again: step 2 above
4. If still broken, tell the team before changing anything else
## 7. Locked out of admin SSH
1. Azure Portal -> the VM -> Networking
2. Check the admin port rule, and update the source IP to my current IP
3. My home IP can change, this is the most common cause
## 8. Do not
- Do not run the honeypot on a personal machine
- Do not commit logs, keys, or passwords to Git
- Do not change port rules without telling the team
