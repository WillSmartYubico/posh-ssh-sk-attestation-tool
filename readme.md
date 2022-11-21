# Requirements

* Requires System.Formats.Cbor unzipped to the current directory: https://www.nuget.org/packages/System.Formats.Cbor
* Only tested with powershell core (7.2)
* Only works with sk-ssh-ed25519 keys
* requires `attestation.bin` and `challengefile` in the current directory.
* the ssh-keygen command will create `ed25519-sk` and `ed25519-sk.pub` - neither of these files are necessary to evaluate the attestation.
* the attestation script will generate `sk.pub`
* Only supports the default application "ssh:"

# Running

1. Create a Challenge File - can be anything that isn't null, save it as `challengefile`
    `get-date | Set-Content challengefile`
2. Create a new ed25519 key with provided challenge:
    `ssh-keygen -t ed25519-sk -f ed25519-sk -O challenge=challengefile -O write-attestation=attestation.bin`
3. Run the script `./ssh-sk-attestation-tools.ps1`
