"use strict";

/*
 * Phase 1 secure personal notepad.
 *
 * Configure only these non-secret values before deployment.
 * Never put a token, password, key, or note content in this file.
 */
const CONFIG = Object.freeze({
  owner: "techsfmc",
  repo: "personal-notepad-data",
  path: "notes.enc",
  apiVersion: "2026-03-10",
});
 
const CRYPTO = Object.freeze({
  envelopeVersion: 1,
  cipher: "AES-256-GCM",
  kdfName: "PBKDF2",
  kdfHash: "SHA-256",
  iterations: 600_000,
  minAcceptedIterations: 100_000,
  maxAcceptedIterations: 5_000_000,
  saltBytes: 16,
  ivBytes: 12,
  tagLength: 128,
  minimumNewPasswordLength: 12,
  maxPlaintextBytes: 5 * 1024 * 1024,
  maxEnvelopeBytes: 10 * 1024 * 1024,
});

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const dom = {
  unlockView: document.getElementById("unlockView"),
  notesView: document.getElementById("notesView"),
  unlockForm: document.getElementById("unlockForm"),
  tokenInput: document.getElementById("tokenInput"),
  passwordInput: document.getElementById("passwordInput"),
  unlockButton: document.getElementById("unlockButton"),
  unlockStatus: document.getElementById("unlockStatus"),
  noteEditor: document.getElementById("noteEditor"),
  refreshButton: document.getElementById("refreshButton"),
  saveButton: document.getElementById("saveButton"),
  lockButton: document.getElementById("lockButton"),
  saveStatus: document.getElementById("saveStatus"),
  saveStatusText: document.getElementById("saveStatusText"),
};

const state = {
  authProvider: null,
  github: null,
  cryptoKey: null,
  salt: null,
  iterations: null,
  sha: null,
  lastSavedText: "",
  dirty: false,
  busy: false,
  initializedRemoteFile: false,
};

class GitHubApiError extends Error {
  constructor(status, code) {
    super(code);
    this.name = "GitHubApiError";
    this.status = status;
    this.code = code;
  }
}

class StaticTokenAuthProvider {
  #token;

  constructor(token) {
    this.#token = token;
  }

  getAuthorizationHeader() {
    if (!this.#token) {
      throw new Error("AUTH_CLEARED");
    }
    return `Bearer ${this.#token}`;
  }

  clear() {
    this.#token = null;
  }
}

class GitHubClient {
  constructor(owner, repo, authProvider) {
    this.owner = owner;
    this.repo = repo;
    this.authProvider = authProvider;
    this.defaultBranch = null;
  }

  async verifyRepositoryAccess() {
    const repoInfo = await this.#requestJson("GET", this.#repoUrl());
    if (!repoInfo || typeof repoInfo !== "object") {
      throw new Error("INVALID_REPOSITORY_RESPONSE");
    }
    if (repoInfo.private !== true) {
      throw new Error("DATA_REPO_NOT_PRIVATE");
    }
    this.defaultBranch = typeof repoInfo.default_branch === "string"
      ? repoInfo.default_branch
      : null;
  }

  async readNote() {
    const url = this.defaultBranch
      ? `${this.#contentsUrl()}?ref=${encodeURIComponent(this.defaultBranch)}`
      : this.#contentsUrl();
    let metadata;

    try {
      metadata = await this.#requestJson("GET", url);
    } catch (error) {
      if (
        error instanceof GitHubApiError &&
        (error.status === 404 || error.status === 409)
      ) {
        return { exists: false, sha: null, text: null };
      }
      throw error;
    }

    if (!metadata || metadata.type !== "file" || typeof metadata.sha !== "string") {
      throw new Error("INVALID_FILE_RESPONSE");
    }

    let text;
    if (metadata.encoding === "base64" && typeof metadata.content === "string" && metadata.content.length > 0) {
      text = bytesToUtf8(base64ToBytes(metadata.content.replace(/\s/g, "")));
    } else {
      text = await this.#requestText("GET", url, "application/vnd.github.raw+json");
    }

    if (textEncoder.encode(text).byteLength > CRYPTO.maxEnvelopeBytes) {
      throw new Error("ENVELOPE_TOO_LARGE");
    }

    return { exists: true, sha: metadata.sha, text };
  }

  async writeNote(envelopeText, expectedSha) {
    const payload = {
      message: "Update encrypted personal note",
      content: bytesToBase64(textEncoder.encode(envelopeText)),
    };

    if (expectedSha) {
      payload.sha = expectedSha;
    }

    const result = await this.#requestJson("PUT", this.#contentsUrl(), payload);
    const newSha = result?.content?.sha;
    if (typeof newSha !== "string" || newSha.length === 0) {
      const reread = await this.readNote();
      if (!reread.exists || !reread.sha) {
        throw new Error("SAVE_RESPONSE_MISSING_SHA");
      }
      return reread.sha;
    }
    return newSha;
  }

  #repoUrl() {
    return `https://api.github.com/repos/${encodeURIComponent(this.owner)}/${encodeURIComponent(this.repo)}`;
  }

  #contentsUrl() {
    const encodedPath = CONFIG.path.split("/").map(encodeURIComponent).join("/");
    return `${this.#repoUrl()}/contents/${encodedPath}`;
  }

  async #requestJson(method, url, body = null) {
    const response = await this.#fetch(method, url, "application/vnd.github+json", body);
    if (response.status === 204) {
      return null;
    }

    const text = await response.text();
    if (!text) {
      return null;
    }

    try {
      return JSON.parse(text);
    } catch {
      throw new Error("INVALID_GITHUB_JSON");
    }
  }

  async #requestText(method, url, accept) {
    const response = await this.#fetch(method, url, accept, null);
    return response.text();
  }

  async #fetch(method, url, accept, body) {
    let response;
    try {
      response = await fetch(url, {
        method,
        headers: {
          Accept: accept,
          Authorization: this.authProvider.getAuthorizationHeader(),
          "X-GitHub-Api-Version": CONFIG.apiVersion,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch {
      throw new Error("NETWORK_ERROR");
    }

    if (!response.ok) {
      throw mapGitHubHttpError(response.status);
    }
    return response;
  }
}

function mapGitHubHttpError(status) {
  switch (status) {
    case 401:
      return new GitHubApiError(status, "GITHUB_UNAUTHORIZED");
    case 403:
      return new GitHubApiError(status, "GITHUB_FORBIDDEN");
    case 404:
      return new GitHubApiError(status, "GITHUB_NOT_FOUND");
    case 409:
      return new GitHubApiError(status, "GITHUB_CONFLICT");
    case 422:
      return new GitHubApiError(status, "GITHUB_VALIDATION_FAILED");
    default:
      if (status >= 500) {
        return new GitHubApiError(status, "GITHUB_SERVER_ERROR");
      }
      return new GitHubApiError(status, "GITHUB_API_ERROR");
  }
}

function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("INVALID_BASE64");
  }

  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error("INVALID_BASE64");
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToUtf8(bytes) {
  try {
    return textDecoder.decode(bytes);
  } catch {
    throw new Error("INVALID_UTF8");
  }
}

function createAad(envelopeLike) {
  const authenticatedMetadata = {
    app: "personal-notepad",
    version: envelopeLike.version,
    cipher: envelopeLike.cipher,
    kdf: {
      name: envelopeLike.kdf.name,
      hash: envelopeLike.kdf.hash,
      iterations: envelopeLike.kdf.iterations,
    },
    salt: envelopeLike.salt,
  };
  return textEncoder.encode(JSON.stringify(authenticatedMetadata));
}

async function deriveEncryptionKey(masterPassword, salt, iterations) {
  const passwordBytes = textEncoder.encode(masterPassword);
  let keyMaterial;

  try {
    keyMaterial = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    passwordBytes.fill(0);
    keyMaterial = null;
  }
}

async function encryptNote(plaintext, key, salt, iterations) {
  const plaintextBytes = textEncoder.encode(plaintext);
  if (plaintextBytes.byteLength > CRYPTO.maxPlaintextBytes) {
    plaintextBytes.fill(0);
    throw new Error("NOTE_TOO_LARGE");
  }

  const iv = crypto.getRandomValues(new Uint8Array(CRYPTO.ivBytes));
  const envelope = {
    version: CRYPTO.envelopeVersion,
    cipher: CRYPTO.cipher,
    kdf: {
      name: CRYPTO.kdfName,
      hash: CRYPTO.kdfHash,
      iterations,
    },
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: "",
  };

  const wrappedPlaintext = textEncoder.encode(JSON.stringify({
    format: "personal-notepad-note",
    version: 1,
    text: plaintext,
  }));

  plaintextBytes.fill(0);

  try {
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: createAad(envelope),
        tagLength: CRYPTO.tagLength,
      },
      key,
      wrappedPlaintext,
    );

    envelope.ciphertext = bytesToBase64(new Uint8Array(encrypted));
    const serialized = JSON.stringify(envelope);

    if (textEncoder.encode(serialized).byteLength > CRYPTO.maxEnvelopeBytes) {
      throw new Error("ENVELOPE_TOO_LARGE");
    }

    return serialized;
  } finally {
    wrappedPlaintext.fill(0);
    iv.fill(0);
  }
}

async function decryptNote(parsedEnvelope, key) {
  let decrypted;
  const ciphertext = parsedEnvelope.ciphertextBytes;

  try {
    decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: parsedEnvelope.ivBytes,
        additionalData: createAad(parsedEnvelope.envelope),
        tagLength: CRYPTO.tagLength,
      },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("DECRYPTION_FAILED");
  }

  const decryptedBytes = new Uint8Array(decrypted);
  let wrapper;
  try {
    wrapper = JSON.parse(bytesToUtf8(decryptedBytes));
  } catch {
    throw new Error("DECRYPTED_DATA_INVALID");
  } finally {
    decryptedBytes.fill(0);
  }

  if (
    !wrapper ||
    wrapper.format !== "personal-notepad-note" ||
    wrapper.version !== 1 ||
    typeof wrapper.text !== "string"
  ) {
    throw new Error("DECRYPTED_DATA_INVALID");
  }

  return wrapper.text;
}

function parseEnvelope(serialized) {
  if (typeof serialized !== "string" || serialized.length === 0) {
    throw new Error("CORRUPT_ENVELOPE");
  }

  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw new Error("CORRUPT_ENVELOPE");
  }

  if (
    !envelope ||
    envelope.version !== CRYPTO.envelopeVersion ||
    envelope.cipher !== CRYPTO.cipher ||
    !envelope.kdf ||
    envelope.kdf.name !== CRYPTO.kdfName ||
    envelope.kdf.hash !== CRYPTO.kdfHash ||
    !Number.isInteger(envelope.kdf.iterations) ||
    envelope.kdf.iterations < CRYPTO.minAcceptedIterations ||
    envelope.kdf.iterations > CRYPTO.maxAcceptedIterations ||
    typeof envelope.salt !== "string" ||
    typeof envelope.iv !== "string" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw new Error("UNSUPPORTED_OR_CORRUPT_ENVELOPE");
  }

  const saltBytes = base64ToBytes(envelope.salt);
  const ivBytes = base64ToBytes(envelope.iv);
  const ciphertextBytes = base64ToBytes(envelope.ciphertext);

  if (
    saltBytes.byteLength !== CRYPTO.saltBytes ||
    ivBytes.byteLength !== CRYPTO.ivBytes ||
    ciphertextBytes.byteLength < 16
  ) {
    throw new Error("CORRUPT_ENVELOPE");
  }

  return { envelope, saltBytes, ivBytes, ciphertextBytes };
}

function validateRuntime() {
  if (window.top !== window.self) {
    throw new Error("FRAMED_CONTEXT");
  }

  const localDev = location.hostname === "localhost" || location.hostname === "127.0.0.1";
  if (!window.isSecureContext && !localDev) {
    throw new Error("INSECURE_CONTEXT");
  }

  if (!window.crypto?.subtle || !window.crypto?.getRandomValues) {
    throw new Error("WEB_CRYPTO_UNAVAILABLE");
  }

  if (!CONFIG.owner || CONFIG.owner === "YOUR_GITHUB_USERNAME") {
    throw new Error("CONFIG_NOT_SET");
  }
}

function setUnlockStatus(message, isError = false) {
  dom.unlockStatus.textContent = message;
  dom.unlockStatus.classList.toggle("error", isError);
}

function setSaveStatus(kind, message) {
  dom.saveStatus.className = `save-status ${kind}`.trim();
  dom.saveStatusText.textContent = message;
}

function setBusy(isBusy) {
  state.busy = isBusy;
  dom.unlockButton.disabled = isBusy;
  dom.refreshButton.disabled = isBusy;
  dom.saveButton.disabled = isBusy;
  dom.lockButton.disabled = isBusy;
  dom.noteEditor.disabled = isBusy;
}

function updateDirtyState() {
  state.dirty = dom.noteEditor.value !== state.lastSavedText;
  if (!state.busy) {
    setSaveStatus(state.dirty ? "unsaved" : "", state.dirty ? "Unsaved" : "Saved");
  }
}

function showNotesView() {
  dom.unlockView.hidden = true;
  dom.notesView.hidden = false;
  dom.noteEditor.focus();
}

function showUnlockView() {
  dom.notesView.hidden = true;
  dom.unlockView.hidden = false;
  dom.tokenInput.focus();
}

function clearSensitiveState() {
  if (state.authProvider) {
    state.authProvider.clear();
  }
  state.authProvider = null;
  state.github = null;
  state.cryptoKey = null;

  if (state.salt instanceof Uint8Array) {
    state.salt.fill(0);
  }
  state.salt = null;
  state.iterations = null;
  state.sha = null;
  state.lastSavedText = "";
  state.dirty = false;
  state.initializedRemoteFile = false;

  dom.noteEditor.value = "";
  dom.tokenInput.value = "";
  dom.passwordInput.value = "";
}

function presentError(error, surface = "notes") {
  const message = humanizeError(error);
  if (surface === "unlock") {
    setUnlockStatus(message, true);
  } else {
    setSaveStatus("error", message);
  }
}

function humanizeError(error) {
  const code = error?.code || error?.message || "UNKNOWN";
  const messages = {
    CONFIG_NOT_SET: "Set CONFIG.owner in app.js before using the app.",
    FRAMED_CONTEXT: "For security, this app refuses to run inside another page.",
    INSECURE_CONTEXT: "This app requires HTTPS.",
    WEB_CRYPTO_UNAVAILABLE: "This browser does not provide the required Web Crypto APIs.",
    GITHUB_UNAUTHORIZED: "The GitHub token is invalid or expired.",
    GITHUB_FORBIDDEN: "GitHub denied access. Check token permissions, expiration, or rate limits.",
    GITHUB_NOT_FOUND: "The private repository was not found or this token cannot access it.",
    DATA_REPO_NOT_PRIVATE: "Refusing to continue: the data repository is not private.",
    GITHUB_SERVER_ERROR: "GitHub is temporarily unavailable. Nothing was saved.",
    GITHUB_API_ERROR: "GitHub returned an unexpected API error. Nothing was saved.",
    GITHUB_VALIDATION_FAILED: "GitHub rejected the update. The remote note may have changed.",
    NETWORK_ERROR: "Network request failed. Nothing was saved.",
    CORRUPT_ENVELOPE: "The encrypted note file is malformed or corrupted.",
    UNSUPPORTED_OR_CORRUPT_ENVELOPE: "The encrypted note format is unsupported or corrupted.",
    INVALID_BASE64: "The encrypted note file contains invalid encoded data.",
    INVALID_UTF8: "The encrypted note file contains invalid text encoding.",
    DECRYPTION_FAILED: "The master password is incorrect, or the encrypted note was modified/corrupted.",
    DECRYPTED_DATA_INVALID: "Decryption succeeded but the note format is invalid.",
    NOTE_TOO_LARGE: "The note exceeds the Phase 1 safety limit of 5 MiB.",
    ENVELOPE_TOO_LARGE: "The encrypted note exceeds the Phase 1 safety limit.",
    CONCURRENT_UPDATE: "A newer version exists. Refresh before saving.",
    REMOTE_FILE_REMOVED: "The remote note changed or was removed. Refresh before saving.",
    PASSWORD_TOO_SHORT: `For first-time setup, use a master password of at least ${CRYPTO.minimumNewPasswordLength} characters.`,
  };
  return messages[code] || "An unexpected error occurred. Nothing was saved.";
}

async function handleUnlock(event) {
  event.preventDefault();
  if (state.busy) return;

  setUnlockStatus("");
  let token = dom.tokenInput.value.trim();
  let masterPassword = dom.passwordInput.value;
  let authProvider = null;

  if (!token || !masterPassword) {
    setUnlockStatus("Enter both the GitHub access token and master password.", true);
    return;
  }

  setBusy(true);
  setUnlockStatus("Unlocking…");

  try {
    validateRuntime();

    authProvider = new StaticTokenAuthProvider(token);
    token = "";
    const github = new GitHubClient(CONFIG.owner, CONFIG.repo, authProvider);
    await github.verifyRepositoryAccess();

    const remote = await github.readNote();
    let cryptoKey;
    let salt;
    let iterations;
    let plaintext = "";

    if (remote.exists) {
      const parsed = parseEnvelope(remote.text);
      salt = parsed.saltBytes;
      iterations = parsed.envelope.kdf.iterations;
      cryptoKey = await deriveEncryptionKey(masterPassword, salt, iterations);
      masterPassword = "";
      dom.passwordInput.value = "";
      plaintext = await decryptNote(parsed, cryptoKey);

      parsed.ivBytes.fill(0);
      parsed.ciphertextBytes.fill(0);
    } else {
      if (masterPassword.length < CRYPTO.minimumNewPasswordLength) {
        throw new Error("PASSWORD_TOO_SHORT");
      }
      salt = crypto.getRandomValues(new Uint8Array(CRYPTO.saltBytes));
      iterations = CRYPTO.iterations;
      cryptoKey = await deriveEncryptionKey(masterPassword, salt, iterations);
      masterPassword = "";
      dom.passwordInput.value = "";
    }

    state.authProvider = authProvider;
    state.github = github;
    state.cryptoKey = cryptoKey;
    state.salt = salt;
    state.iterations = iterations;
    state.sha = remote.sha;
    state.initializedRemoteFile = remote.exists;
    state.lastSavedText = plaintext;
    state.dirty = false;

    dom.noteEditor.value = plaintext;
    dom.tokenInput.value = "";
    setUnlockStatus("");
    showNotesView();
    setSaveStatus("", remote.exists ? "Saved" : "New note");
  } catch (error) {
    authProvider?.clear();
    clearSensitiveState();
    presentError(error, "unlock");
  } finally {
    masterPassword = "";
    dom.passwordInput.value = "";
    setBusy(false);
  }
}

async function handleSave() {
  if (state.busy || !state.github || !state.cryptoKey) return;

  setBusy(true);
  setSaveStatus("loading", "Saving…");

  try {
    const remote = await state.github.readNote();

    if (state.sha === null) {
      if (remote.exists) {
        throw new Error("CONCURRENT_UPDATE");
      }
    } else if (!remote.exists) {
      throw new Error("REMOTE_FILE_REMOVED");
    } else if (remote.sha !== state.sha) {
      throw new Error("CONCURRENT_UPDATE");
    }

    const textToSave = dom.noteEditor.value;
    const encryptedEnvelope = await encryptNote(
      textToSave,
      state.cryptoKey,
      state.salt,
      state.iterations,
    );

    let newSha;
    try {
      newSha = await state.github.writeNote(encryptedEnvelope, state.sha);
    } catch (error) {
      if (error instanceof GitHubApiError && (error.status === 409 || error.status === 422)) {
        const afterFailure = await state.github.readNote();
        if (
          (state.sha === null && afterFailure.exists) ||
          (state.sha !== null && (!afterFailure.exists || afterFailure.sha !== state.sha))
        ) {
          throw new Error("CONCURRENT_UPDATE");
        }
      }
      throw error;
    }

    state.sha = newSha;
    state.initializedRemoteFile = true;
    state.lastSavedText = textToSave;
    state.dirty = false;
    setSaveStatus("", "Saved");
  } catch (error) {
    presentError(error, "notes");
  } finally {
    setBusy(false);
    if (!dom.saveStatus.classList.contains("error")) {
      updateDirtyState();
    }
  }
}

async function handleRefresh() {
  if (state.busy || !state.github || !state.cryptoKey) return;

  if (state.dirty) {
    const discard = window.confirm("You have unsaved changes. Refreshing will discard them.");
    if (!discard) return;
  }

  setBusy(true);
  setSaveStatus("loading", "Refreshing…");

  try {
    const remote = await state.github.readNote();
    if (!remote.exists) {
      if (state.sha !== null) {
        throw new Error("REMOTE_FILE_REMOVED");
      }

      dom.noteEditor.value = "";
      state.lastSavedText = "";
      state.dirty = false;
      setSaveStatus("", "New note");
      return;
    }

    const parsed = parseEnvelope(remote.text);

    if (
      parsed.envelope.kdf.iterations !== state.iterations ||
      parsed.envelope.salt !== bytesToBase64(state.salt)
    ) {
      throw new Error("DECRYPTION_FAILED");
    }

    const plaintext = await decryptNote(parsed, state.cryptoKey);
    parsed.saltBytes.fill(0);
    parsed.ivBytes.fill(0);
    parsed.ciphertextBytes.fill(0);

    dom.noteEditor.value = plaintext;
    state.sha = remote.sha;
    state.lastSavedText = plaintext;
    state.dirty = false;
    state.initializedRemoteFile = true;
    setSaveStatus("", "Saved");
  } catch (error) {
    presentError(error, "notes");
  } finally {
    setBusy(false);
  }
}

function handleLock() {
  if (state.busy) return;

  if (state.dirty) {
    const discard = window.confirm("You have unsaved changes. Locking will discard them.");
    if (!discard) return;
  }

  clearSensitiveState();
  setUnlockStatus("");
  setSaveStatus("", "Saved");
  showUnlockView();
}

function initialize() {
  if (window.top !== window.self) {
    document.body.textContent = "For security, this application cannot run inside a frame.";
    return;
  }

  dom.unlockForm.addEventListener("submit", handleUnlock);
  dom.noteEditor.addEventListener("input", updateDirtyState);
  dom.saveButton.addEventListener("click", handleSave);
  dom.refreshButton.addEventListener("click", handleRefresh);
  dom.lockButton.addEventListener("click", handleLock);

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  showUnlockView();
}

initialize();
