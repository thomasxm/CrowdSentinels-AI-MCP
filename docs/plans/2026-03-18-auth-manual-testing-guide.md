# Auth System Manual Testing Guide

Step-by-step verification of all authentication paths in CrowdSentinel.

**Prerequisites:**
- CrowdSentinel installed and on PATH (`crowdsentinel --version` works)
- Access to at least one of: Anthropic API key, Anthropic Claude subscription, OpenAI API key, ChatGPT subscription
- A browser on the same machine (for PKCE OAuth tests)

---

## 1. Clean Slate

Start from a known state with no stored credentials.

```bash
# Remove any existing auth files
rm -f ~/.crowdsentinel/auth-profiles.json
rm -f ~/.crowdsentinel/auth.json
rm -f ~/.crowdsentinel/auth.json.bak
rm -f ~/.crowdsentinel/auth-profiles.lock

# Unset env vars for isolated testing
unset ANTHROPIC_API_KEY
unset OPENAI_API_KEY
unset CROWDSENTINEL_MODEL
unset CROWDSENTINEL_MODEL_URL

# Verify clean state
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: no
Run: crowdsentinel auth login
```

---

## 2. Anthropic API Key Login

```bash
crowdsentinel auth login --provider anthropic
```

**Interactive prompts:**
1. You see: `1. Paste a setup-token` / `2. Paste an API key`
2. Type `2` and press Enter
3. Browser opens to `console.anthropic.com/settings/keys`
4. Paste your API key (`sk-ant-api03-...`) and press Enter
5. You see: `Validating key...` then `Key validated!`

**Verify:**
```bash
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Profiles: 1
  anthropic:default: type=api_key, provider=anthropic
```

**Verify file permissions:**
```bash
ls -la ~/.crowdsentinel/auth-profiles.json
```

**Expected:** `-rw-------` (600 permissions)

**Verify file content:**
```bash
cat ~/.crowdsentinel/auth-profiles.json | python3 -m json.tool
```

**Expected structure:**
```json
{
  "version": 1,
  "profiles": {
    "anthropic:default": {
      "type": "api_key",
      "provider": "anthropic",
      "key": "sk-ant-api03-..."
    }
  }
}
```

**Functional test — does the agent actually work:**
```bash
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "test auth" -o summary
```

**Expected:** An LLM-generated analysis (not an auth error).

---

## 3. Anthropic Setup-Token Login (Subscription)

```bash
crowdsentinel auth login --provider anthropic
```

**Interactive prompts:**
1. Type `1` (setup-token) and press Enter
2. In a **separate terminal**, run: `claude setup-token`
3. Complete the browser sign-in
4. Copy the token (`sk-ant-oat01-...`)
5. Paste into the CrowdSentinel prompt and press Enter
6. You see: `Validating token...` then `Token validated successfully!`

**Verify:**
```bash
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Profiles: 2
  anthropic:default: type=api_key, provider=anthropic
  anthropic:subscription: type=token, provider=anthropic
```

Note: The subscription profile (`token` type) is preferred over the `api_key` profile when both exist.

**Functional test:**
```bash
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "test subscription auth" -o summary
```

**Expected:** Analysis output (using the subscription token, not the API key).

---

## 4. OpenAI API Key Login

```bash
crowdsentinel auth login --provider openai
```

**Interactive prompts:**
1. You see: `1. Sign in with ChatGPT` / `2. Paste an API key`
2. Type `2` and press Enter
3. Browser opens to `platform.openai.com/api-keys`
4. Paste your API key (`sk-proj-...` or `sk-...`) and press Enter
5. You see: `Validating key...` then `Key validated!`

**Verify:**
```bash
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Profiles: 3
  anthropic:default: type=api_key, provider=anthropic
  anthropic:subscription: type=token, provider=anthropic
  openai:default: type=api_key, provider=openai
```

---

## 5. OpenAI ChatGPT Subscription Login (PKCE OAuth)

**Requirements:** ChatGPT Plus, Pro, or Team subscription.

```bash
crowdsentinel auth login --provider openai
```

**Interactive prompts:**
1. Type `1` (Sign in with ChatGPT) and press Enter
2. Browser opens to `auth.openai.com/oauth/authorize?...`
3. Sign in with your ChatGPT account
4. Authorise the application
5. Browser shows: "Authentication successful! You can close this tab."
6. Terminal shows: `OpenAI subscription auth stored in ...`

**Verify:**
```bash
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Profiles: 4
  anthropic:default: type=api_key, provider=anthropic
  anthropic:subscription: type=token, provider=anthropic
  openai:default: type=api_key, provider=openai
  openai-codex:default: type=oauth, provider=openai-codex, expires in X.Xh
```

**Verify ChatGPT browser session is NOT logged out:**
1. Open `https://chatgpt.com` in your browser
2. You should still be logged in (not asked to sign in again)
3. Wait 1 hour and check again — still logged in

**Verify the OAuth token works:**
```bash
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "test openai oauth" --model gpt-4o -o summary
```

---

## 6. Profile Priority Verification

When multiple profiles exist, the system should prefer subscription/oauth profiles over API keys, and Anthropic over OpenAI.

```bash
crowdsentinel auth status
```

**Expected:** Anthropic subscription (`token` type) is used by default because:
1. Anthropic is checked before OpenAI
2. `token`/`oauth` types are preferred over `api_key`

**Force OpenAI by removing Anthropic profiles temporarily:**
```bash
# Backup
cp ~/.crowdsentinel/auth-profiles.json ~/.crowdsentinel/auth-profiles.json.bak

# Edit to remove anthropic profiles (or use python to do so)
python3 -c "
import json
with open('$HOME/.crowdsentinel/auth-profiles.json') as f:
    data = json.load(f)
data['profiles'] = {k:v for k,v in data['profiles'].items() if 'anthropic' not in k}
with open('$HOME/.crowdsentinel/auth-profiles.json', 'w') as f:
    json.dump(data, f, indent=2)
"

crowdsentinel auth status
# Should show only OpenAI profiles, with openai-codex (oauth) preferred over openai (api_key)

# Restore
cp ~/.crowdsentinel/auth-profiles.json.bak ~/.crowdsentinel/auth-profiles.json
```

---

## 7. Environment Variable Fallback

Test that env vars work when no profiles are stored.

```bash
# Clear profiles
crowdsentinel auth logout

# Set env var
export ANTHROPIC_API_KEY="sk-ant-api03-your-key-here"

crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Method: env:ANTHROPIC_API_KEY
Provider: anthropic
```

**Functional test:**
```bash
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "env var auth test" -o summary
```

**Expected:** Works using the env var key.

```bash
# Clean up
unset ANTHROPIC_API_KEY
```

---

## 8. Legacy Migration (auth.json → auth-profiles.json)

Simulate an existing user upgrading from the old single-profile system.

```bash
# Remove new-format file
rm -f ~/.crowdsentinel/auth-profiles.json

# Create old-format file
cat > ~/.crowdsentinel/auth.json << 'EOF'
{
  "provider": "anthropic",
  "access_token": "sk-ant-api03-your-real-key-here",
  "refresh_token": "",
  "expires_at": 0
}
EOF
chmod 600 ~/.crowdsentinel/auth.json

# Trigger migration by checking status
crowdsentinel auth status
```

**Expected output:**
```
Authenticated: yes
Profiles: 1
  anthropic:default: type=api_key, provider=anthropic
```

**Verify migration artefacts:**
```bash
# Old file should be renamed to .bak
ls -la ~/.crowdsentinel/auth.json.bak
# Should exist

# New file should exist
ls -la ~/.crowdsentinel/auth-profiles.json
# Should exist with 600 permissions

# Old file should be gone
ls -la ~/.crowdsentinel/auth.json 2>&1
# Should say "No such file"
```

**Functional test** (if you used a real key above):
```bash
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "migration test" -o summary
```

---

## 9. Logout

```bash
crowdsentinel auth logout
```

**Expected output:**
```
Logged out. Stored tokens removed.
```

**Verify:**
```bash
crowdsentinel auth status
```

**Expected:**
```
Authenticated: no
Run: crowdsentinel auth login
```

**Verify file is gone:**
```bash
ls ~/.crowdsentinel/auth-profiles.json 2>&1
# Should say "No such file"
```

---

## 10. Error Handling & Edge Cases

### 10a. No auth at all — MCP agent auto-login

```bash
# Ensure no auth
rm -f ~/.crowdsentinel/auth-profiles.json
unset ANTHROPIC_API_KEY
unset OPENAI_API_KEY

echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse --mcp -c "test" -o summary
```

**Expected:** Prompts you to log in interactively (Anthropic by default).

### 10b. Invalid API key

```bash
crowdsentinel auth login --provider anthropic
# Choose option 2 (API key)
# Paste: sk-ant-api03-INVALID
```

**Expected:** Shows `Warning: key returned 401.` and asks `Store anyway? [y/N]:`. Typing `N` should abort without storing.

### 10c. Empty input

```bash
crowdsentinel auth login --provider openai
# Choose option 2 (API key)
# Press Enter without pasting anything
```

**Expected:** `No key provided.` and exit code 1.

### 10d. PKCE flow — port in use

```bash
# Block port 1455
python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',1455)); s.listen(); input('Press Enter to stop...')" &
PORT_PID=$!

crowdsentinel auth login --provider openai
# Choose option 1 (subscription)
```

**Expected:** Error message about port 1455 being in use.

```bash
# Clean up
kill $PORT_PID
```

### 10e. PKCE flow — timeout (no browser interaction)

```bash
# Set a short timeout for testing (normally 300s)
# This test takes 5 minutes if you don't interact — skip if short on time
crowdsentinel auth login --provider openai
# Choose option 1 (subscription)
# Do NOT interact with the browser
# Wait for timeout
```

**Expected:** After 300 seconds: `PKCE flow timed out — no callback received within 300 seconds`

### 10f. Help text

```bash
crowdsentinel auth --help
```

**Expected output includes:**
```
Examples:
  crowdsentinel auth login                       # Anthropic (default)
  crowdsentinel auth login --provider openai     # OpenAI (subscription or API key)
  crowdsentinel auth login --provider anthropic  # Anthropic (setup-token or API key)
  crowdsentinel auth status                      # Check auth status
  crowdsentinel auth logout                      # Remove stored tokens
```

---

## 11. Token Refresh Verification (OpenAI OAuth only)

This tests that expired OAuth tokens are automatically refreshed.

**Setup:** Complete step 5 (OpenAI PKCE login) first.

```bash
# Manually set the token to expire in the past
python3 -c "
import json, time
path = '$HOME/.crowdsentinel/auth-profiles.json'
with open(path) as f:
    data = json.load(f)
if 'openai-codex:default' in data['profiles']:
    data['profiles']['openai-codex:default']['expires'] = int((time.time() - 60) * 1000)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print('Token manually expired')
else:
    print('No openai-codex profile found')
"

# Verify it shows as expired
crowdsentinel auth status
# Should show: expired (will refresh on next use)

# Trigger a provider creation (which triggers lazy refresh)
echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse -c "refresh test" --model gpt-4o -o summary
```

**Expected:** The command succeeds (token was auto-refreshed). Check status again:

```bash
crowdsentinel auth status
# Should show: expires in X.Xh (freshly refreshed)
```

---

## 12. Local Model (Ollama) — No Auth Required

```bash
# Start Ollama if not running
# ollama serve &
# ollama pull llama3.1

echo '{"summary":{"total_hits":1},"sample_events":[{"message":"test"}]}' | \
  crowdsentinel analyse --mcp \
    --model-url http://localhost:11434/v1 \
    --model llama3.1 \
    -c "local model test" -o summary
```

**Expected:** Works without any stored profiles or env vars (the `--model-url` flag bypasses auth entirely for tokenless Ollama).

---

## Checklist Summary

| # | Test | Pass? |
|---|------|-------|
| 1 | Clean slate — no auth shows "Authenticated: no" | |
| 2 | Anthropic API key login + validation + functional test | |
| 3 | Anthropic setup-token login + functional test | |
| 4 | OpenAI API key login + validation | |
| 5 | OpenAI PKCE subscription login + ChatGPT stays logged in | |
| 6 | Profile priority (subscription > api_key, anthropic > openai) | |
| 7 | Env var fallback (ANTHROPIC_API_KEY / OPENAI_API_KEY) | |
| 8 | Legacy auth.json migration + .bak created | |
| 9 | Logout clears all profiles | |
| 10a | No auth → auto-login prompt | |
| 10b | Invalid API key → warning + abort | |
| 10c | Empty input → error message | |
| 10d | PKCE port in use → error message | |
| 10e | PKCE timeout → error message (5 min wait) | |
| 10f | Help text shows all options | |
| 11 | Expired OAuth token auto-refreshes | |
| 12 | Local model works without auth | |
