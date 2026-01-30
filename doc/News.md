# v0.1 -> v0.2
## Fix
- OS Version Checkin
- Domain Checkin
- Image Name (info command)
- Remove the thrash print clear text from upload/download command
- Spoof/Indirect for some functions

## Improvements
- Remove the trash code
- Remove useless debug mode from ui build
- Error handling in the listener creation feature
- Change to use Random Encryption Key for each Checkin
- Upload routine now displays message regarding upload completion
- Adjust to human view for allocation method and write method
- Code refact
- Http Profile improved
- Ported commands like ``process*``, ``fs*``, ``scinject*`` and ``postex*`` to BOF format

## Additions
- Argument Spoof Capability
- Injection Kit
- Change named pipe to fork commands capability (config)
- IpAddress Checkin
- Added a script to simplify agent setup (consult setup_kharon.sh)
- Show cfg, VBS/HVCI, and DSE status for info command
- Profile Listener show in the info command
- info command show the amsi/etw bypass
- config syscall capability
- Config bof api prox via config command
- Domain Rotation (failover, round robin and random)

# v0.2 -> v0.3
- LDAP/ADWS command to bloodhound output parser
- Active Script in memory execution (VBS/JScript/etc)
- PE in memory execution (Reflection)

# v0.3 -> v0.4
- SMB Listener