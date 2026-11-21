# Certio on Miabi

A single Certio instance with its SQLite database on a persistent volume, served over HTTPS at
your own domain. For a one-click install instead, use the
[template marketplace](https://marketplace.miabi.io/templates/certio).

## Before the first apply

In `stack.yaml`, replace `certio.example.com` (three times: `CERTIO_BASE_URL`, the `Domain` and
the `Route`) and `admin@example.com`. Point the domain's DNS at the workspace.

`CERTIO_BASE_URL` is baked into the CRL distribution point of every certificate issued from then
on. Changing it later fixes new certificates only.

Miabi generates the master key, the JWT secret and the first administrator's password as
`certio-master-key`, `certio-jwt-secret` and `certio-admin-password`. To bring your own master
key instead, for example one from `certio keygen`, create `certio-master-key` in the vault
before applying.

## Apply

```sh
miabi apply -f stack.yaml --dry-run
miabi apply -f stack.yaml
```

## After it: save the master key

This is the one step you cannot skip. The master key encrypts every private key Certio stores,
including your CA's. Lose it and they are all unreadable, and a backup of the volume does not
help: the database is what the key protects, and the key is not in it.

```sh
miabi secrets reveal certio-master-key
```

Store the value somewhere other than Miabi: a password manager or your existing secret store.
Applying the stack again never regenerates it, but `miabi delete -f stack.yaml` deletes the
secret with everything else.

Then open `https://certio.example.com`, sign in as `admin@example.com` with the password from
`miabi secrets reveal certio-admin-password`, and change it. Bootstrap runs only on an empty
database, so that secret is not used again.

To upgrade, change `tag:` in `stack.yaml` and apply again. The `recreate` strategy stops the old
release before the new one opens the database.
