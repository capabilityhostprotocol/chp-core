# Trust anchors — pinned manufacturer roots for W4 (hardware-attested witness)

`tpm_witness_verify.verify_ek_chain` accepts an EK certificate only if it chains, by cryptographic
signature, to one of the roots pinned here. These are the sole basis for `ek_chain_verified` (and
therefore for reaching `W4_HARDWARE_ATTESTED`). A root is trusted **because it is in this directory**,
pinned by fingerprint — never because it was fetched at verify time. Intermediates may be fetched via
AIA, but the terminal root must be one of these.

## intel_ondie_root.der
Intel OnDie CA Root ("OnDie CA Root Cert Signing", CN=www.intel.com) — the self-signed root for Intel
CSME/PTT firmware-TPM EK certificates (e.g. the Meteor Lake NUC's `ODCA 2 CSME MTL SOC SVN 01 PTT CA`
intermediate chains to it).

- Source: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
- Format: DER, 702 bytes
- SHA-256 fingerprint: `BE:B4:0B:B7:50:7B:33:96:72:26:AA:80:E0:84:74:9F:BB:65:93:89:3C:64:2E:81:8D:68:2E:9A:8D:07:FC:24`

Verify after any refresh:
```
openssl x509 -inform DER -in intel_ondie_root.der -noout -fingerprint -sha256 -subject -issuer
```

To add another manufacturer (e.g. an Infineon/STMicro discrete-TPM root), drop its DER/PEM here and
record its source + fingerprint above; the verifier loads every cert in this directory as an anchor.
