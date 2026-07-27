# ZenvX Chat

End-to-end encrypted messaging for one closed community of ~1,000 people, built to cost **nothing** to run.

There is no message database. There is no user table. Your phone holds your messages; the only server is a phone book plus a dumb pipe that forwards sealed envelopes it cannot read.

---

## Why this exists

Every normal chat app costs money because it stores your messages. Storage grows forever, egress grows with users, and someone has to pay. This design removes the reason for the cost:

| Normal chat app | ZenvX Chat |
| --- | --- |
| Messages in the cloud forever | Messages only on the devices in the conversation |
| Server can read metadata | Relay cannot even tell who sent a message |
| Storage bill grows monthly | No storage to grow |
| Account = row in a database | Account = keypair on your phone |

The relay only holds a message when the recipient is offline, and deletes it the moment it is delivered.

## What runs where

```
  Your phone                      Relay (one free VM)              Their phone
  ----------                      -------------------              -----------
  identity keys                   signed member list               identity keys
  message history      ------>    forwards sealed blobs   ------>  message history
  local encrypted DB              holds mail only if offline       local encrypted DB
                       <--------  helps you find each other ------>
                                  (then gets out of the way)
           +------------ direct device-to-device once connected ------------+
```

## Security

- **X3DH + Double Ratchet.** The same key agreement and forward-secrecy design Signal uses. Every message gets a fresh key; stealing today's key does not decrypt yesterday's messages.
- **Sealed sender.** The sender's identity is encrypted *inside* the envelope. The relay sees `{to, ephemeral key, ciphertext}` and nothing else, so it cannot build a social graph even with full disk access.
- **Closed membership, signed offline.** Members are listed in `directory/members.json`, each entry signed by a community root key that lives offline and never touches the server. Whoever runs the relay cannot add a fake member.
- **Rollback protection.** Directory serial numbers must increase, so an attacker cannot replay an old signed directory to resurrect a revoked member.
- **Local encryption at rest.** History is encrypted with a key derived from your passphrase (PBKDF2-SHA256, 600k iterations).
- **Zero dependencies.** All crypto is WebCrypto; the WebSocket server is hand-written. Nothing from npm, so there is no supply-chain attack surface. CI fails the build if a dependency is ever added.

### What this does NOT protect against

Read this part twice.

- **Lose your passphrase and your history is gone.** There is no reset, no support desk, no recovery. Nobody on earth can decrypt it for you. Export a backup.
- **A compromised device loses everything.** Encryption cannot help if malware is already reading your screen.
- **The relay learns who is online and roughly when**, plus IP addresses. It does not learn who talks to whom.
- **Revocation stops future sessions**, but messages already delivered to someone's phone stay on their phone. That is true of every messenger, including the ones that pretend otherwise.
- **iOS is second-class.** Without a $99/yr Apple developer account it runs as a web app, and iOS may evict local storage under disk pressure. iOS users must keep backups.

## Repository layout

```
client/crypto/   primitives, X3DH, Double Ratchet, sealed sender, root trust
client/db/       encrypted append-only local event log (IndexedDB)
client/net/      WebRTC + signalling + store-and-forward fallback
client/          the app itself (installable PWA)
server/          the entire backend: ws.mjs + relay.mjs, no dependencies
tools/           root-key.mjs - offline membership signing tool
test/            60 tests covering crypto, sealed sender, and the live relay
infra/           one script that provisions the whole free-tier box
```

## Running the tests

```bash
npm test                       # crypto + sealed sender + relay integration
node test/crypto.test.mjs      # 25 tests
node test/envelope.test.mjs    # 12 tests
node test/relay.test.mjs       # 23 tests, spawns a real relay
```

No `npm install` step. There is nothing to install.

## Setting up the community (operator, once)

```bash
# 1. Create the root key. Do this on a machine that is NOT the server.
npm run rootkey init
#    Writes ~/.zenvx-root/root.key (chmod 600) and bakes the public key
#    into client/crypto/trust.js. Back the private key up offline, twice.

# 2. Someone installs the app, generates an identity, and sends you their
#    enrolment request JSON. Add them:
npm run rootkey enroll alice-request.json
npm run rootkey seal          # bumps the serial and signs the directory
git commit -am 'enrol alice' && git push

# 3. Stand up the relay on a free Oracle Cloud ARM instance:
sudo bash infra/setup-oracle.sh chat.example.org you@example.org
```

Useful commands: `rootkey revoke <handle>`, `rootkey verify`, `rootkey fingerprint`.

**The root private key is the whole security model.** If it leaks, an attacker can enrol themselves and impersonate anyone. Keep it offline. Never commit it - `.gitignore` and CI both try to stop you, but they are not a substitute for care.

## Installing (members)

- **Android / desktop:** open the hosted app and choose *Install app*, or sideload the APK from Releases.
- **iOS:** open in Safari, then *Share -> Add to Home Screen*.

First launch asks for a passphrase (encrypts local history) and generates your identity. Send the enrolment request to the key holder; once they publish the signed directory, you can message anyone in it.

## Running costs

One Oracle Cloud Always Free ARM instance, forever: **0 per month.**

1,000 members sending 50 messages/day at ~2 KB is roughly 3 GB of relay egress per month, against a 10 TB free allowance - about 0.03%. Most traffic never touches the relay at all because devices connect directly.

The only thing that costs money is optional: $99/yr for a real iOS app, which is about 9 rupees per person per year.

## Licence

AGPL-3.0-or-later. If you run a modified version for others, publish your changes.
