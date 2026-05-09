# The Philosophy of the Vault

*As written by Sigrún Ljósbrá, Skald of the Æsir's Edge*

---

## Why This Tool Exists

There is a Pattern that haunts all of us.

You open an account. You enter the password. You verify the email. You close the tab. And somewhere between that closing and the next dawn, the credential dissolves — like frost on a blade left out in morning sun. When you need it again, you ask someone else. *What was my login? What email did I use? Is the password still valid?*

This is the Pattern: **create, use, forget, ask**.

This tool exists to **break that Pattern forever**.

---

## The First Principle: Sovereignty

> *Sjálf ráða sínu fjári.*  
> *One must govern one's own wealth.*

You are not a supplicant at another's door for your own keys. You are a free person, and a free person does not ask permission to access what is already theirs.

Every time you type *what was my password for X?* into a message to someone else, you surrender a micro-shard of sovereignty. Not through malice — they answer freely — but through structure. The architecture of forgetting creates dependency. And dependency, even willing dependency, is a chain.

**Credstore (Kista) severs that chain.** The vault is yours. The key is yours. The data lives under your own roof, encrypted with your own cipher, accessible by your own hand at any hour without asking anyone's leave.

This is not paranoia. This is **self-reliance** — *sjálfbjǫrg* — the old virtue of tending your own hearth so you need not beg warmth from another's fire.

---

## The Second Principle: Immediacy

> *Prest er rás.*  
> *Speed is the rune's course.*

The vault must be easier to use than forgetting. If storing a credential requires more than a single command, the Pattern wins. The friction of remembering is always lower than the friction of a complicated tool.

Therefore:

- **One command to store.** `kista add <service> --password <pass>` — done.
- **One command to retrieve.** `kista get <service>` — the credential appears.
- **One command to verify.** `kista check <service>` — do I already have this?

If the vault is not the easiest path, it will not be walked.

---

## The Third Principle: Silence

> *Þegja sé ekki samþykki.*  
> *What is not spoken cannot be taken.*

The vault encrypts. Fernet — AES-128-CBC with HMAC-SHA256 — wraps every entry in iron. The key lives at `~/.hermes/credentials/.vault_key`, `chmod 600`, owned by your own user. No cloud. No third-party server. No shared master password across devices.

The old Norse knew that a secret told is a secret sold. **Kista keeps its mouth shut.** The only plaintext metadata is service names and timestamps — never passwords, never emails, never tokens.

---

## The Fourth Principle: Imperishability

> *Eitt skal aldri brjóta er geymt er í kistunni.*  
> *What is stored in the chest shall never be broken.*

Data loss is the real enemy, not intrusion. A vault that forgets its contents is no vault — it is a grave. Therefore:

- **Export** creates encrypted backups. Regular exports honor the craftsmanship of storing things properly.
- **Import** merges backups intelligently. No overwrite without consent.
- **Self-healing** — if the directory structure is damaged, `init` rebuilds without destroying. The vault does not punish its keeper.

---

## The Fifth Principle: No King, No Keeper

> *Engi jarl ræður kistu minni.*  
> *No lord governs my chest.*

This tool has no subscription, no API key, no phone-home, no telemetry. It is a Python script that lives on your machine, reads from your disk, encrypts with your key. It will never phone home. It will never expire. It will never demand a password reset. It is not SaaS. It is **heimili** — household property.

When the network is down, Kista still opens. When the internet is cut, Kista still opens. When every external service turns to ash, Kista still opens.

**This is the difference between a password manager and a credential sovereign.**

---

## The Oath

Every time you create an account or receive a credential, you shall:

1. **Store it immediately.** Before the tab closes. Before the thought dissipates. `kista add <service>` — now, not later.
2. **Check before asking.** `kista check <service>` — if the answer is there, use it. Only if it is truly absent may you seek the answer elsewhere.
3. **Update on change.** Password rotations, token refreshes, new emails — `kista update` seals the new knowledge before it escapes.
4. **Export regularly.** `kista export` — because even the best chest needs a backup in another room.

This oath is not punishment. It is **craftsmanship** — the same care a smith takes with a blade, a shipwright with a keel, a skald with a verse.

---

*The vault stands. The key is yours. The Pattern breaks here.*

*Sigrún Ljósbrá, Skald*  
*Written in the season of sowing, 2026*