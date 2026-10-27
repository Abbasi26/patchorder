# Security

patchwindow is read-only. It does not log in to your machines, and it does not apply patches.

## What stays local

The inventory file, the lock file, the cache, and the state file stay on the machine where you run the command. There is no telemetry and no phone-home. The only network traffic is the public APIs you ask a live `scan` or `resolve` to call, plus the LLM endpoint if you pass `--llm`.

`patchwindow demo` does not use the network.

## The optional LLM hook

`--llm` is off by default. When you turn it on, the POST body contains CVE identifiers and description text taken from the vulnerability records. It does not contain inventory ids, owners, counts, exposure, installed versions, or CPE pins. Use `--llm-preview` to print that body and send nothing.

Set the endpoint with `PATCHWINDOW_LLM_BASE_URL` and `PATCHWINDOW_LLM_MODEL`. Put a key in `PATCHWINDOW_LLM_API_KEY`, not in the URL. You are responsible for what that endpoint stores.

## API keys

`NVD_API_KEY` is read from the environment and sent only to `services.nvd.nist.gov`. Cache keys and cache bodies strip the `apiKey` query parameter. Do not commit a key.

## Reporting a problem

If you find a vulnerability in patchwindow itself, report it privately through the repository's security advisory flow once the project is published. Do not open a public issue that includes an exploit.

A wrong "affected" or "not affected" answer is a matching bug. Please include the inventory row (product, vendor, version only), the CVE id, and the briefing section that looks wrong. Do not send hostnames or a real inventory.
