import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import type { BrowserProvider, JsonRpcSigner, OnboardInfo, Wallet } from '@coti-io/coti-ethers';

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] | object }) => Promise<unknown>;
      on?: (event: string, listener: (...args: unknown[]) => void) => void;
      removeListener?: (event: string, listener: (...args: unknown[]) => void) => void;
    };
  }
}

type Eip1193Provider = {
  request: (args: { method: string; params?: unknown[] | object }) => Promise<unknown>;
  connect?: () => Promise<unknown>;
  on?: (event: string, listener: (...args: unknown[]) => void) => void;
  removeListener?: (event: string, listener: (...args: unknown[]) => void) => void;
  disconnect?: () => Promise<void>;
};

type Contact = {
  address: string;
  name?: string;
};

type ChatMessage = {
  id: string;
  direction: 'incoming' | 'outgoing';
  text: string;
  replyToMessageId?: string;
  replyToText?: string;
  timestamp?: number;
};

type HistoryEntry = {
  id: string;
  contact: string;
  direction: 'incoming' | 'outgoing';
  text: string;
  replyToMessageId?: string;
  replyToText?: string;
  blockNumber: number;
  logIndex: number;
  timestamp?: number;
};

const CONTACTS_STORAGE_KEY = 'coti-chat-contacts';
const ACTIVE_CONTACT_STORAGE_KEY = 'coti-chat-active-contact';
const BURNER_WALLET_STORAGE_KEY = 'coti-chat-burner-wallet';
const BURNER_WALLET_STORAGE_VERSION = 2;
const BURNER_PIN_MIN_LENGTH = 5;
const LEGACY_BURNER_PIN_MIN_LENGTH = 4;
const BURNER_PIN_PBKDF2_ITERATIONS = 250000;
const PROFILE_STORAGE_KEY = 'coti-chat-profile';
const PROFILE_SHARED_STORAGE_KEY = 'coti-chat-profile-shared';
const AUTO_SYNC_INTERVAL_MS = 30000;
const NICKNAME_DELIMITER = '\u001f';
const REPLY_DELIMITER = '\u001e';
const PROFILE_METADATA_PREFIX = '[nick:';
const REPLY_METADATA_PREFIX = '[reply:';
const LEGACY_PROFILE_PREFIX = '[[coti-profile:v1]]';
const LEGACY_PROFILE_PLAIN_PREFIX = '[[coti-nick:v1]]';
const MAX_REPLY_PREVIEW_LENGTH = 48;
const COTI_WEI = 10n ** 18n;
const MIN_BURNER_TOP_UP_WEI = 1_000_000_000_000_000n;

type BurnerWalletRecord = {
  privateKey: string;
  mnemonic?: string;
};

type EncryptedBurnerWalletRecord = {
  version: number;
  salt: string;
  iv: string;
  ciphertext: string;
  iterations: number;
};

type BurnerWalletStorageState =
  | { kind: 'none' }
  | { kind: 'legacy'; record: BurnerWalletRecord }
  | { kind: 'encrypted'; record: EncryptedBurnerWalletRecord };

type UserProfile = {
  nickname: string;
};

type BurnerInitMode = 'generate' | 'import' | 'stored';
type SignerSource = 'burner' | 'metamask';
type BurnerPinMode = 'set' | 'unlock';
type BurnerInitResult = 'connected' | 'needs-funding' | 'failed';

type PendingBurnerInit = {
  mode: BurnerInitMode;
  seedOrPrivateKey?: string;
};

const COTI_NETWORK = {
  chainIdHex: '0x282b34',
  chainIdDecimal: 2632500,
  chainName: 'COTI',
  rpcUrl: 'https://mainnet.coti.io/rpc',
  wsUrl: 'wss://mainnet.coti.io/ws',
  nativeCurrency: {
    name: 'COTI',
    symbol: 'COTI',
    decimals: 18
  },
  blockExplorerUrl: 'https://mainnet.cotiscan.io'
};

const CHAT_CONTRACT_ADDRESS = '0x81DEfBfba1cdc5AF972566342F4935853E02923d';
const CHAT_CONTRACT_ABI = [
  'function submit(address recipient, ((uint256[] value), bytes[] signature) memo) payable',
  'function feeAmount() view returns (uint256)',
  'event MessageSubmitted(address indexed recipient, address indexed from, ((uint256[] value) ciphertext, (uint256[] value) userCiphertext) messageForRecipient, ((uint256[] value) ciphertext, (uint256[] value) userCiphertext) messageForSender)'
] as const;

type CotiEthersModule = typeof import('@coti-io/coti-ethers');
type CotiWsProvider = InstanceType<CotiEthersModule['WebSocketProvider']>;
type CotiHttpProvider = InstanceType<CotiEthersModule['JsonRpcProvider']>;
type CotiReadProvider = CotiWsProvider | CotiHttpProvider;
let cotiEthersModulePromise: Promise<CotiEthersModule> | null = null;
let cotiWsProviderPromise: Promise<CotiWsProvider> | null = null;
let cotiHttpProviderPromise: Promise<CotiHttpProvider> | null = null;

const loadCotiEthersModule = (): Promise<CotiEthersModule> => {
  if (!cotiEthersModulePromise) {
    cotiEthersModulePromise = import('@coti-io/coti-ethers');
  }

  return cotiEthersModulePromise;
};

const loadCotiWsProvider = async (): Promise<CotiWsProvider> => {
  if (!cotiWsProviderPromise) {
    cotiWsProviderPromise = loadCotiEthersModule().then((cotiEthers) =>
      new cotiEthers.WebSocketProvider(COTI_NETWORK.wsUrl, {
        name: COTI_NETWORK.chainName,
        chainId: COTI_NETWORK.chainIdDecimal
      })
    );
  }

  return cotiWsProviderPromise;
};

const loadCotiHttpProvider = async (): Promise<CotiHttpProvider> => {
  if (!cotiHttpProviderPromise) {
    cotiHttpProviderPromise = loadCotiEthersModule().then(
      (cotiEthers) =>
        new cotiEthers.JsonRpcProvider(COTI_NETWORK.rpcUrl, {
          name: COTI_NETWORK.chainName,
          chainId: COTI_NETWORK.chainIdDecimal
        })
    );
  }

  return cotiHttpProviderPromise;
};

const resetCotiWsProvider = async (): Promise<void> => {
  if (!cotiWsProviderPromise) {
    return;
  }

  try {
    const wsProvider = await cotiWsProviderPromise;
    const providerWithDestroy = wsProvider as unknown as { destroy?: () => void };
    providerWithDestroy.destroy?.();
  } catch {
  } finally {
    cotiWsProviderPromise = null;
  }
};

const loadCotiReadProvider = async (preferWebSocket = true): Promise<CotiReadProvider> => {
  if (preferWebSocket) {
    try {
      const wsProvider = await loadCotiWsProvider();
      await wsProvider.getBlockNumber();
      return wsProvider;
    } catch {
      await resetCotiWsProvider();
    }
  }

  return loadCotiHttpProvider();
};

const shortenAddress = (address: string): string => `${address.slice(0, 6)}...${address.slice(-4)}`;

const isWalletAddress = (value: string): boolean => /^0x[a-fA-F0-9]{40}$/.test(value.trim());
const normalizeContactName = (value: string): string | undefined => {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const scopedStorageKey = (baseKey: string, walletAddress?: string | null): string => {
  const scope = walletAddress?.trim().toLowerCase();
  return `${baseKey}:${scope && isWalletAddress(scope) ? scope : 'global'}`;
};

const normalizeChainId = (chainId: string | number): number => {
  if (typeof chainId === 'number') return chainId;
  return chainId.startsWith('0x') ? parseInt(chainId, 16) : Number(chainId);
};

const createCotiBrowserProvider = async (ethereum: Eip1193Provider): Promise<BrowserProvider> => {
  const cotiEthers = await loadCotiEthersModule();
  return new cotiEthers.BrowserProvider(ethereum, {
    name: COTI_NETWORK.chainName,
    chainId: COTI_NETWORK.chainIdDecimal
  });
};

const mergeOnboardInfo = (previous?: OnboardInfo, next?: OnboardInfo): OnboardInfo => ({
  aesKey: next?.aesKey ?? previous?.aesKey,
  rsaKey: next?.rsaKey ?? previous?.rsaKey,
  txHash: next?.txHash ?? previous?.txHash
});

const encodeMemoPlaintext = (plain: string): string => {
  const bytes = new TextEncoder().encode(plain);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
};

const decodeMemoPlaintext = (raw: string): string => {
  try {
    const binary = atob(raw);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return raw;
  }
};

const formatMessageTimestamp = (timestamp?: number): string => {
  if (!timestamp || !Number.isFinite(timestamp)) {
    return '';
  }

  return new Date(timestamp * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
};

const calculateTopUpAmount = (requiredFee: bigint, multiplier: number): bigint => {
  const safeMultiplier = Math.max(1, Math.floor(multiplier));
  return requiredFee > 0n ? requiredFee * BigInt(safeMultiplier) : MIN_BURNER_TOP_UP_WEI * BigInt(safeMultiplier);
};

const formatCotiAmount = (weiAmount: bigint): string => {
  const whole = weiAmount / COTI_WEI;
  const fraction = (weiAmount % COTI_WEI).toString().padStart(18, '0').slice(0, 6).replace(/0+$/, '');
  return fraction ? `${whole.toString()}.${fraction}` : whole.toString();
};

const hasInsufficientFundsError = (message: string): boolean =>
  /insufficient funds|exceeds balance|not enough funds|account balance is 0/i.test(message);

const toBigIntArray = (value: unknown): bigint[] => {
  const parseSingle = (item: unknown): bigint[] => {
    if (typeof item === 'bigint') return [item];
    if (typeof item === 'number') return [BigInt(item)];

    if (typeof item === 'string') {
      const parts = item
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      return parts.map((part) => BigInt(part));
    }

    if (item && typeof item === 'object' && 'toString' in item) {
      const asString = String(item);
      const parts = asString
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      return parts.map((part) => BigInt(part));
    }

    return [];
  };

  if (Array.isArray(value)) {
    return value.flatMap((item) => parseSingle(item));
  }

  if (value && typeof value === 'object' && 'value' in value) {
    return toBigIntArray((value as { value: unknown }).value);
  }

  return parseSingle(value);
};

const extractUserCiphertext = (memo: unknown): { value: bigint[] } | null => {
  if (!memo) {
    return null;
  }

  if (Array.isArray(memo) && memo.length > 1) {
    return { value: toBigIntArray(memo[1]) };
  }

  if (memo && typeof memo === 'object' && 'userCiphertext' in memo) {
    return { value: toBigIntArray((memo as { userCiphertext: unknown }).userCiphertext) };
  }

  return null;
};

const mergeUniqueContacts = (existing: Contact[], discoveredAddresses: string[]): Contact[] => {
  const byLower = new Map<string, Contact>();

  for (const contact of existing) {
    byLower.set(contact.address.toLowerCase(), contact);
  }

  for (const address of discoveredAddresses) {
    if (isWalletAddress(address)) {
      const lower = address.toLowerCase();
      if (!byLower.has(lower)) {
        byLower.set(lower, { address });
      }
    }
  }

  return Array.from(byLower.values());
};

const loadStoredContacts = (): Contact[] => {
  try {
    const raw = window.localStorage.getItem(CONTACTS_STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }

    const deduped = new Map<string, Contact>();

    for (const item of parsed) {
      if (typeof item === 'string') {
        const address = item.trim();
        if (isWalletAddress(address)) {
          const key = address.toLowerCase();
          if (!deduped.has(key)) {
            deduped.set(key, { address });
          }
        }
        continue;
      }

      if (item && typeof item === 'object' && 'address' in item) {
        const address = typeof item.address === 'string' ? item.address.trim() : '';
        if (!isWalletAddress(address)) {
          continue;
        }

        const key = address.toLowerCase();
        const name = normalizeContactName(typeof item.name === 'string' ? item.name : '');
        const existing = deduped.get(key);
        if (!existing) {
          deduped.set(key, { address, name });
        } else if (!existing.name && name) {
          deduped.set(key, { ...existing, name });
        }
      }
    }

    return Array.from(deduped.values());
  } catch {
    return [];
  }
};

const loadStoredActiveContact = (): string | null => {
  try {
    const stored = window.localStorage.getItem(ACTIVE_CONTACT_STORAGE_KEY);
    if (!stored || !isWalletAddress(stored)) {
      return null;
    }
    return stored;
  } catch {
    return null;
  }
};

const bytesToBase64 = (value: Uint8Array): string => {
  let binary = '';
  for (let index = 0; index < value.length; index += 1) {
    binary += String.fromCharCode(value[index]);
  }
  return btoa(binary);
};

const base64ToBytes = (value: string): Uint8Array => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
};

const toArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;

const parseBurnerWalletStorageState = (): BurnerWalletStorageState => {
  try {
    const raw = window.localStorage.getItem(BURNER_WALLET_STORAGE_KEY);
    if (!raw) {
      return { kind: 'none' };
    }

    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return { kind: 'none' };
    }

    const encryptedCandidate = parsed as {
      version?: unknown;
      salt?: unknown;
      iv?: unknown;
      ciphertext?: unknown;
      iterations?: unknown;
    };

    if (
      encryptedCandidate.version === BURNER_WALLET_STORAGE_VERSION &&
      typeof encryptedCandidate.salt === 'string' &&
      typeof encryptedCandidate.iv === 'string' &&
      typeof encryptedCandidate.ciphertext === 'string' &&
      typeof encryptedCandidate.iterations === 'number'
    ) {
      return {
        kind: 'encrypted',
        record: {
          version: encryptedCandidate.version,
          salt: encryptedCandidate.salt,
          iv: encryptedCandidate.iv,
          ciphertext: encryptedCandidate.ciphertext,
          iterations: encryptedCandidate.iterations
        }
      };
    }

    const legacyCandidate = parsed as { privateKey?: unknown; mnemonic?: unknown };
    const privateKey = typeof legacyCandidate.privateKey === 'string' ? legacyCandidate.privateKey.trim() : '';
    if (!/^0x[a-fA-F0-9]{64}$/.test(privateKey)) {
      return { kind: 'none' };
    }

    const mnemonic = typeof legacyCandidate.mnemonic === 'string' ? legacyCandidate.mnemonic.trim() : undefined;
    return {
      kind: 'legacy',
      record: { privateKey, mnemonic }
    };
  } catch {
    return { kind: 'none' };
  }
};

const deriveBurnerPinKey = async (
  pin: string,
  salt: Uint8Array,
  iterations: number,
  usages: KeyUsage[]
): Promise<CryptoKey> => {
  const pinMaterial = await window.crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, [
    'deriveKey'
  ]);

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(salt),
      iterations,
      hash: 'SHA-256'
    },
    pinMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
};

const encryptBurnerWalletRecord = async (record: BurnerWalletRecord, pin: string): Promise<EncryptedBurnerWalletRecord> => {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBurnerPinKey(pin, salt, BURNER_PIN_PBKDF2_ITERATIONS, ['encrypt']);

  const payload = JSON.stringify(record);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    new TextEncoder().encode(payload)
  );

  return {
    version: BURNER_WALLET_STORAGE_VERSION,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    iterations: BURNER_PIN_PBKDF2_ITERATIONS
  };
};

const decryptBurnerWalletRecord = async (
  encryptedRecord: EncryptedBurnerWalletRecord,
  pin: string
): Promise<BurnerWalletRecord> => {
  const salt = base64ToBytes(encryptedRecord.salt);
  const iv = base64ToBytes(encryptedRecord.iv);
  const ciphertext = base64ToBytes(encryptedRecord.ciphertext);
  const key = await deriveBurnerPinKey(pin, salt, encryptedRecord.iterations, ['decrypt']);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext)
  );
  const rawPayload = new TextDecoder().decode(decrypted);
  const parsed = JSON.parse(rawPayload) as unknown;

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid burner wallet payload.');
  }

  const parsedRecord = parsed as { privateKey?: unknown; mnemonic?: unknown };
  const privateKey = typeof parsedRecord.privateKey === 'string' ? parsedRecord.privateKey.trim() : '';
  if (!/^0x[a-fA-F0-9]{64}$/.test(privateKey)) {
    throw new Error('Invalid burner wallet private key format.');
  }

  const mnemonic = typeof parsedRecord.mnemonic === 'string' ? parsedRecord.mnemonic.trim() : undefined;
  return { privateKey, mnemonic };
};

const saveEncryptedBurnerWalletRecord = async (record: BurnerWalletRecord, pin: string): Promise<void> => {
  const encrypted = await encryptBurnerWalletRecord(record, pin);
  window.localStorage.setItem(BURNER_WALLET_STORAGE_KEY, JSON.stringify(encrypted));
};

const loadStoredProfile = (walletAddress?: string | null): UserProfile => {
  try {
    const raw = window.localStorage.getItem(scopedStorageKey(PROFILE_STORAGE_KEY, walletAddress));
    if (!raw) {
      return { nickname: '' };
    }

    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return { nickname: '' };
    }

    const record = parsed as { nickname?: unknown };
    return {
      nickname: typeof record.nickname === 'string' ? record.nickname : ''
    };
  } catch {
    return { nickname: '' };
  }
};

const loadSharedNicknameContacts = (walletAddress?: string | null): Record<string, boolean> => {
  try {
    const raw = window.localStorage.getItem(scopedStorageKey(PROFILE_SHARED_STORAGE_KEY, walletAddress));
    if (!raw) {
      return {};
    }

    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }

    const result: Record<string, boolean> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === 'boolean') {
        result[key.toLowerCase()] = value;
      }
    }

    return result;
  } catch {
    return {};
  }
};

const buildMessageWithProfilePayload = (plainText: string, nickname: string, shouldShare: boolean): string => {
  const normalizedNickname = nickname
    .replace(/\u001f/g, '')
    .replace(/\]/g, '')
    .trim();
  if (!shouldShare || !normalizedNickname) {
    return plainText;
  }

  return `${PROFILE_METADATA_PREFIX}${normalizedNickname}] ${plainText}`;
};

const trimReplyPreview = (text: string): string => {
  const singleLine = text.replace(/\s+/g, ' ').trim();
  if (!singleLine) {
    return '';
  }

  if (singleLine.length <= MAX_REPLY_PREVIEW_LENGTH) {
    return singleLine;
  }

  return `${singleLine.slice(0, MAX_REPLY_PREVIEW_LENGTH - 1)}…`;
};

const buildMessageWithReplyPayload = (plainText: string, replyToText?: string, _replyToMessageId?: string): string => {
  const preview = trimReplyPreview((replyToText ?? '').replace(/\]/g, ''));
  if (!preview) {
    return plainText;
  }

  return `${REPLY_METADATA_PREFIX}${preview}] ${plainText}`;
};

const parseMessageReplyPayload = (text: string): {
  cleanText: string;
  replyToText?: string;
  replyToMessageId?: string;
} => {
  if (text.startsWith(REPLY_METADATA_PREFIX)) {
    const metadataEnd = text.indexOf(']', REPLY_METADATA_PREFIX.length);
    if (metadataEnd > REPLY_METADATA_PREFIX.length) {
      const metadataChunk = text.slice(REPLY_METADATA_PREFIX.length, metadataEnd);
      const separatorIndex = metadataChunk.indexOf('|');
      const hasLegacyIdChunk = separatorIndex > 0;
      const rawReplyId = hasLegacyIdChunk ? metadataChunk.slice(0, separatorIndex).trim() : '';
      const rawPreview = hasLegacyIdChunk ? metadataChunk.slice(separatorIndex + 1) : metadataChunk;
      const previewChunk = trimReplyPreview(rawPreview);
      const replyToMessageId = hasLegacyIdChunk && /^[a-zA-Z0-9\-]+$/.test(rawReplyId) ? rawReplyId : undefined;
      const remainingRaw = text.slice(metadataEnd + 1);
      const remaining = remainingRaw.startsWith(' ') ? remainingRaw.slice(1) : remainingRaw;

      return {
        cleanText: remaining,
        replyToText: previewChunk || undefined,
        replyToMessageId
      };
    }
  }

  if (!text.startsWith(REPLY_DELIMITER)) {
    return { cleanText: text };
  }

  const delimiterEnd = text.indexOf(REPLY_DELIMITER, REPLY_DELIMITER.length);
  if (delimiterEnd < 0) {
    return { cleanText: text };
  }

  const previewChunk = trimReplyPreview(text.slice(REPLY_DELIMITER.length, delimiterEnd));
  const remainingRaw = text.slice(delimiterEnd + REPLY_DELIMITER.length);
  const remaining = remainingRaw.startsWith(': ') ? remainingRaw.slice(2) : remainingRaw;

  return {
    cleanText: remaining,
    replyToText: previewChunk || undefined
  };
};

const parseMessageProfilePayload = (text: string): { cleanText: string; nickname?: string } => {
  if (text.startsWith(PROFILE_METADATA_PREFIX)) {
    const metadataEnd = text.indexOf(']', PROFILE_METADATA_PREFIX.length);
    if (metadataEnd > PROFILE_METADATA_PREFIX.length) {
      const nicknameChunk = text.slice(PROFILE_METADATA_PREFIX.length, metadataEnd).trim();
      const nickname = normalizeContactName(nicknameChunk)?.slice(0, 42);
      const remainingRaw = text.slice(metadataEnd + 1);
      const remaining = remainingRaw.startsWith(' ') ? remainingRaw.slice(1) : remainingRaw;
      return {
        cleanText: remaining,
        nickname
      };
    }
  }

  if (text.startsWith(NICKNAME_DELIMITER)) {
    const delimiterEnd = text.indexOf(NICKNAME_DELIMITER, NICKNAME_DELIMITER.length);
    if (delimiterEnd < 0) {
      return { cleanText: text };
    }

    const nicknameChunk = text.slice(NICKNAME_DELIMITER.length, delimiterEnd).trim();
    const nickname = normalizeContactName(nicknameChunk)?.slice(0, 42);
    const remainingRaw = text.slice(delimiterEnd + NICKNAME_DELIMITER.length);
    const remaining = remainingRaw.startsWith(': ') ? remainingRaw.slice(2) : remainingRaw;
    return {
      cleanText: remaining,
      nickname
    };
  }

  if (text.startsWith(LEGACY_PROFILE_PLAIN_PREFIX)) {
    const newlineIndex = text.indexOf('\n');
    if (newlineIndex < 0) {
      return { cleanText: text };
    }

    const nicknameChunk = text.slice(LEGACY_PROFILE_PLAIN_PREFIX.length, newlineIndex).trim();
    const nickname = normalizeContactName(nicknameChunk)?.slice(0, 42);
    const remaining = text.slice(newlineIndex + 1);
    return {
      cleanText: remaining,
      nickname
    };
  }

  if (!text.startsWith(LEGACY_PROFILE_PREFIX)) {
    return { cleanText: text };
  }

  const newlineIndex = text.indexOf('\n');
  if (newlineIndex < 0) {
    return { cleanText: text };
  }

  const jsonChunk = text.slice(LEGACY_PROFILE_PREFIX.length, newlineIndex).trim();
  const remaining = text.slice(newlineIndex + 1);
  try {
    const parsed = JSON.parse(jsonChunk) as { nick?: unknown };
    const nickname = typeof parsed.nick === 'string' ? normalizeContactName(parsed.nick)?.slice(0, 42) : undefined;
    return {
      cleanText: remaining,
      nickname
    };
  } catch {
    return { cleanText: text };
  }
};

export default function App() {
  const [contacts, setContacts] = useState<Contact[]>(() => loadStoredContacts());
  const [newContact, setNewContact] = useState('');
  const [newContactName, setNewContactName] = useState('');
  const [activeContact, setActiveContact] = useState<string | null>(() => loadStoredActiveContact());
  const [editingContactAddress, setEditingContactAddress] = useState<string | null>(null);
  const [editingContactName, setEditingContactName] = useState('');
  const [walletAddress, setWalletAddress] = useState<string>('');
  const [chainId, setChainId] = useState<number | null>(null);
  const [status, setStatus] = useState<string>('Disconnected');
  const [burnerMnemonicBackup, setBurnerMnemonicBackup] = useState('');
  const [showBurnerMnemonic, setShowBurnerMnemonic] = useState(false);
  const [burnerImportInput, setBurnerImportInput] = useState('');
  const [showBurnerImportModal, setShowBurnerImportModal] = useState(false);
  const [showBurnerPinModal, setShowBurnerPinModal] = useState(false);
  const [burnerPinMode, setBurnerPinMode] = useState<BurnerPinMode>('unlock');
  const [burnerPinInput, setBurnerPinInput] = useState('');
  const [burnerPinConfirmInput, setBurnerPinConfirmInput] = useState('');
  const [pendingBurnerInit, setPendingBurnerInit] = useState<PendingBurnerInit | null>(null);
  const [initializingBurner, setInitializingBurner] = useState(false);
  const [burnerNeedsFunding, setBurnerNeedsFunding] = useState(false);
  const [myNickname, setMyNickname] = useState('');
  const [sharedNicknameContacts, setSharedNicknameContacts] = useState<Record<string, boolean>>({});
  const [activeSignerSource, setActiveSignerSource] = useState<SignerSource>('burner');
  const [connectionMethod, setConnectionMethod] = useState<'metamask' | null>(null);
  const [connectingMethod, setConnectingMethod] = useState<'metamask' | null>(null);
  const [onboardStatus, setOnboardStatus] = useState<string>('Not onboarded');
  const [sessionOnboardInfo, setSessionOnboardInfo] = useState<Record<string, OnboardInfo>>({});
  const [messageInput, setMessageInput] = useState('');
  const [messagesByContact, setMessagesByContact] = useState<Record<string, ChatMessage[]>>({});
  const [sending, setSending] = useState(false);
  const [syncingHistory, setSyncingHistory] = useState(false);
  const [replyingToMessage, setReplyingToMessage] = useState<ChatMessage | null>(null);
  const [highlightedMessageId, setHighlightedMessageId] = useState<string | null>(null);
  const [topUpAmountWei, setTopUpAmountWei] = useState<bigint | null>(null);
  const [requiredFeeWei, setRequiredFeeWei] = useState<bigint | null>(null);
  const [burnerBalanceWei, setBurnerBalanceWei] = useState<bigint | null>(null);
  const [topUpMultiplier, setTopUpMultiplier] = useState(20);
  const [loadingTopUpQuote, setLoadingTopUpQuote] = useState(false);
  const [topUpMetricsNonce, setTopUpMetricsNonce] = useState(0);
  const [error, setError] = useState<string>('');
  const [activeProvider, setActiveProvider] = useState<Eip1193Provider | null>(null);
  const activeProviderRef = useRef<Eip1193Provider | null>(null);
  const burnerWalletRef = useRef<Wallet | null>(null);
  const burnerRecordRef = useRef<BurnerWalletRecord | null>(null);
  const burnerPinRef = useRef<string>('');
  const chatMessagesRef = useRef<HTMLDivElement | null>(null);
  const messageElementRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const highlightTimeoutRef = useRef<number | null>(null);
  const signerCacheRef = useRef<Record<string, JsonRpcSigner>>({});
  const sendingRef = useRef(false);
  const syncingHistoryRef = useRef(false);
  const lastSyncedBlockRef = useRef<Record<string, number>>({});
  const syncConversationHistoryRef = useRef<() => Promise<void>>(async () => {});

  const isConnected = useMemo(() => walletAddress.length > 0, [walletAddress]);
  const onCotiNetwork = useMemo(() => chainId === COTI_NETWORK.chainIdDecimal, [chainId]);
  const activeMessages = useMemo(() => {
    if (!activeContact) {
      return [];
    }
    return messagesByContact[activeContact.toLowerCase()] ?? [];
  }, [activeContact, messagesByContact]);
  const sortedContacts = useMemo(() => {
    const withIndex = contacts.map((contact, index) => {
      const key = contact.address.toLowerCase();
      const messages = messagesByContact[key] ?? [];
      const latestTimestamp = messages.reduce((max, message) => {
        const value = message.timestamp ?? 0;
        return value > max ? value : max;
      }, 0);

      return {
        contact,
        index,
        messageCount: messages.length,
        latestTimestamp
      };
    });

    withIndex.sort((a, b) => {
      if (a.latestTimestamp !== b.latestTimestamp) {
        return b.latestTimestamp - a.latestTimestamp;
      }

      if (a.messageCount !== b.messageCount) {
        return b.messageCount - a.messageCount;
      }

      return a.index - b.index;
    });

    return withIndex.map((item) => item.contact);
  }, [contacts, messagesByContact]);
  const activeContactMeta = useMemo(
    () => contacts.find((contact) => contact.address.toLowerCase() === activeContact?.toLowerCase()),
    [contacts, activeContact]
  );
  const hasAesReady = useMemo(
    () => (walletAddress ? Boolean(sessionOnboardInfo[walletAddress.toLowerCase()]?.aesKey) : false),
    [walletAddress, sessionOnboardInfo]
  );
  const burnerAddress = burnerWalletRef.current?.address ?? (activeSignerSource === 'burner' ? walletAddress : '');
  const estimatedMessagesLeft = useMemo(() => {
    if (requiredFeeWei === null || burnerBalanceWei === null || requiredFeeWei <= 0n) {
      return null;
    }

    return burnerBalanceWei / requiredFeeWei;
  }, [requiredFeeWei, burnerBalanceWei]);

  const setConnectedProvider = (provider: Eip1193Provider | null) => {
    activeProviderRef.current = provider;
    setActiveProvider(provider);
  };

  const getConnectedProvider = (): Eip1193Provider | null => {
    if (connectionMethod === 'metamask') {
      return activeProviderRef.current ?? activeProvider ?? window.ethereum ?? null;
    }

    return activeProviderRef.current ?? activeProvider ?? null;
  };

  const createCotiRpcProvider = async () => {
    const cotiEthers = await loadCotiEthersModule();
    return new cotiEthers.JsonRpcProvider(COTI_NETWORK.rpcUrl, {
      name: COTI_NETWORK.chainName,
      chainId: COTI_NETWORK.chainIdDecimal
    });
  };

  const buildBurnerRecord = async (
    mode: BurnerInitMode,
    seedOrPrivateKey?: string,
    pin?: string
  ): Promise<BurnerWalletRecord> => {
    const normalizedSeed = seedOrPrivateKey?.trim() ?? '';
    const cotiEthers = await loadCotiEthersModule();

    if (mode === 'import') {
      if (normalizedSeed.length === 0) {
        throw new Error('Enter a mnemonic phrase or private key.');
      }

      if (/^0x[a-fA-F0-9]{64}$/.test(normalizedSeed)) {
        return { privateKey: normalizedSeed };
      }

      const importedWallet = cotiEthers.Wallet.fromPhrase(normalizedSeed);
      return {
        privateKey: importedWallet.privateKey,
        mnemonic: normalizedSeed
      };
    }

    if (mode === 'stored') {
      const storageState = parseBurnerWalletStorageState();
      if (storageState.kind === 'none') {
        throw new Error('No saved burner wallet found. Generate or import one first.');
      }

      if (storageState.kind === 'legacy') {
        return storageState.record;
      }

      if (!pin) {
        throw new Error('Enter PIN to unlock burner wallet.');
      }

      try {
        return await decryptBurnerWalletRecord(storageState.record, pin);
      } catch {
        throw new Error('Invalid PIN or corrupted burner wallet data.');
      }
    }

    const createdWallet = cotiEthers.Wallet.createRandom();
    return {
      privateKey: createdWallet.privateKey,
      mnemonic: createdWallet.mnemonic?.phrase
    };
  };

  const initializeBurnerWallet = async (
    mode: BurnerInitMode,
    seedOrPrivateKey?: string,
    pin?: string
  ): Promise<BurnerInitResult> => {
    setError('');
    setInitializingBurner(true);
    setBurnerNeedsFunding(false);

    try {
      const burnerRecord = await buildBurnerRecord(mode, seedOrPrivateKey, pin);

      const storageState = parseBurnerWalletStorageState();
      const requiresEncryptedSave = mode !== 'stored' || storageState.kind === 'legacy';
      const sessionPin = pin?.trim() ?? burnerPinRef.current;

      if (requiresEncryptedSave) {
        if (sessionPin.length < BURNER_PIN_MIN_LENGTH) {
          throw new Error(`PIN must be at least ${BURNER_PIN_MIN_LENGTH} digits.`);
        }
        await saveEncryptedBurnerWalletRecord(burnerRecord, sessionPin);
      }

      if (sessionPin.length >= BURNER_PIN_MIN_LENGTH) {
        burnerPinRef.current = sessionPin;
      }

      const cotiEthers = await loadCotiEthersModule();
      const rpcProvider = await createCotiRpcProvider();
      const burnerWallet = new cotiEthers.Wallet(burnerRecord.privateKey, rpcProvider);

      burnerWalletRef.current = burnerWallet;
      burnerRecordRef.current = burnerRecord;
      setWalletAddress(burnerWallet.address);
      setChainId(COTI_NETWORK.chainIdDecimal);
      setStatus('Connecting burner wallet...');
      setActiveSignerSource('burner');
      setConnectionMethod(null);
      setConnectedProvider(null);
      setBurnerImportInput('');

      if (burnerRecord.mnemonic) {
        setBurnerMnemonicBackup(burnerRecord.mnemonic);
        setShowBurnerMnemonic(mode === 'generate');
      } else {
        setBurnerMnemonicBackup('');
        setShowBurnerMnemonic(false);
      }

      const burnerBalance = (await rpcProvider.getBalance(burnerWallet.address)) as bigint;
      if (burnerBalance <= 0n) {
        setBurnerNeedsFunding(true);
        setStatus('Burner wallet created. Fund it, then connect burner wallet.');
        setOnboardStatus('Funding required');
        return 'needs-funding';
      }

      const cacheKey = burnerWallet.address.toLowerCase();
      const cachedOnboardInfo = sessionOnboardInfo[cacheKey];
      if (cachedOnboardInfo) {
        burnerWallet.setUserOnboardInfo(cachedOnboardInfo);
      }

      setOnboardStatus('Onboarding...');
      await burnerWallet.generateOrRecoverAes();
      const onboardInfo = burnerWallet.getUserOnboardInfo();

      if (!onboardInfo?.aesKey) {
        throw new Error('AES key unavailable for burner wallet.');
      }

      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], onboardInfo)
      }));
      setOnboardStatus('AES key ready');
      setStatus('Connected (Burner)');
      await syncConversationHistoryRef.current();
      return 'connected';
    } catch (burnerError) {
      const message = burnerError instanceof Error ? burnerError.message : 'Failed to initialize burner wallet.';
      if (message.includes('Account balance is 0 so user cannot be onboarded')) {
        setBurnerNeedsFunding(true);
        setStatus('Burner needs funding');
        return 'needs-funding';
      } else {
        setStatus('Disconnected');
      }
      setError(message);
      setOnboardStatus('Not onboarded');
      return 'failed';
    } finally {
      setInitializingBurner(false);
    }
  };

  const closeBurnerPinModal = () => {
    if (initializingBurner) {
      return;
    }

    setShowBurnerPinModal(false);
    setPendingBurnerInit(null);
    setBurnerPinInput('');
    setBurnerPinConfirmInput('');
  };

  const beginBurnerPinFlow = async (mode: BurnerInitMode, seedOrPrivateKey?: string) => {
    setError('');

    const storageState = parseBurnerWalletStorageState();
    if (mode === 'stored' && storageState.kind === 'none') {
      setError('No saved burner wallet found. Generate or import one first.');
      return;
    }

    if (mode === 'stored' && storageState.kind === 'encrypted' && burnerPinRef.current) {
      await initializeBurnerWallet('stored', undefined, burnerPinRef.current);
      return;
    }

    const nextPinMode: BurnerPinMode = mode === 'stored' && storageState.kind === 'encrypted' ? 'unlock' : 'set';

    setPendingBurnerInit({ mode, seedOrPrivateKey });
    setBurnerPinMode(nextPinMode);
    setBurnerPinInput('');
    setBurnerPinConfirmInput('');
    setShowBurnerPinModal(true);
  };

  const submitBurnerPinAndInitialize = async () => {
    setError('');

    const pending = pendingBurnerInit;
    if (!pending) {
      if (burnerPinMode !== 'set') {
        return;
      }

      const pinForUpdate = burnerPinInput.trim();
      const confirmForUpdate = burnerPinConfirmInput.trim();
      if (pinForUpdate.length < BURNER_PIN_MIN_LENGTH) {
        setError(`PIN must be at least ${BURNER_PIN_MIN_LENGTH} digits.`);
        return;
      }
      if (confirmForUpdate !== pinForUpdate) {
        setError('PIN confirmation does not match.');
        return;
      }

      if (!burnerRecordRef.current) {
        setError('Connect burner wallet first, then change PIN.');
        return;
      }

      await saveEncryptedBurnerWalletRecord(burnerRecordRef.current, pinForUpdate);
      burnerPinRef.current = pinForUpdate;
      setShowBurnerPinModal(false);
      setBurnerPinInput('');
      setBurnerPinConfirmInput('');
      setStatus('Burner PIN updated.');
      return;
    }

    const pin = burnerPinInput.trim();
    const minimumPinLength = burnerPinMode === 'unlock' ? LEGACY_BURNER_PIN_MIN_LENGTH : BURNER_PIN_MIN_LENGTH;
    if (pin.length < minimumPinLength) {
      setError(`PIN must be at least ${minimumPinLength} digits.`);
      return;
    }

    if (burnerPinMode === 'set') {
      const confirm = burnerPinConfirmInput.trim();
      if (confirm !== pin) {
        setError('PIN confirmation does not match.');
        return;
      }
    }

    const initResult = await initializeBurnerWallet(pending.mode, pending.seedOrPrivateKey, pin);
    if (initResult === 'connected' || initResult === 'needs-funding') {
      setShowBurnerPinModal(false);
      setPendingBurnerInit(null);
      setBurnerPinInput('');
      setBurnerPinConfirmInput('');

      if (pending.mode === 'import') {
        setShowBurnerImportModal(false);
      }

      if (initResult === 'connected' && burnerPinMode === 'unlock' && pin.length < BURNER_PIN_MIN_LENGTH) {
        setStatus(`Connected. Please update PIN to at least ${BURNER_PIN_MIN_LENGTH} digits.`);
        setPendingBurnerInit(null);
        setBurnerPinMode('set');
        setBurnerPinInput('');
        setBurnerPinConfirmInput('');
        setShowBurnerPinModal(true);
      }
    }
  };

  const openChangeBurnerPin = () => {
    if (!burnerRecordRef.current) {
      setError('Connect burner wallet first, then change PIN.');
      return;
    }

    setError('');
    setPendingBurnerInit(null);
    setBurnerPinMode('set');
    setBurnerPinInput('');
    setBurnerPinConfirmInput('');
    setShowBurnerPinModal(true);
  };

  const importBurnerWallet = async () => {
    await beginBurnerPinFlow('import', burnerImportInput);
  };

  const topUpBurnerWithMetaMask = async () => {
    setError('');

    const burnerAddress = burnerWalletRef.current?.address ?? (activeSignerSource === 'burner' ? walletAddress : '');

    if (!burnerAddress || !isWalletAddress(burnerAddress)) {
      setError('Initialize burner wallet first.');
      return;
    }

    const provider = window.ethereum;
    if (!provider) {
      setError('MetaMask not detected. Please install MetaMask to top up burner wallet.');
      return;
    }

    try {
      setStatus('Top up in progress...');
      await provider.request({ method: 'eth_requestAccounts' });
      await ensureCotiNetwork(provider);

      const browserProvider = await createCotiBrowserProvider(provider);
      const funderSigner = await browserProvider.getSigner();
      let topUpAmount = topUpAmountWei;
      if (topUpAmount === null) {
        const cotiEthers = await loadCotiEthersModule();
        const readProvider = await loadCotiReadProvider(true);
        const readContract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, readProvider);
        const requiredFee = (await readContract.feeAmount()) as bigint;
        topUpAmount = calculateTopUpAmount(requiredFee, topUpMultiplier);
      }

      if (topUpAmount === null) {
        throw new Error('Unable to calculate top-up amount.');
      }

      const tx = await funderSigner.sendTransaction({
        to: burnerAddress,
        value: topUpAmount
      });
      await tx.wait();

      setBurnerBalanceWei((previous) => (previous !== null ? previous + topUpAmount : previous));
      setTopUpMetricsNonce((previous) => previous + 1);

      if (burnerPinRef.current) {
        await initializeBurnerWallet('stored', undefined, burnerPinRef.current);
      } else {
        setStatus('Burner topped up. Unlock burner wallet to continue.');
      }
    } catch (fundError) {
      const message = fundError instanceof Error ? fundError.message : 'Failed to top up burner wallet.';
      setError(message);
      setStatus('Burner needs funding');
    }
  };

  const scrollChatToBottom = () => {
    const container = chatMessagesRef.current;
    if (!container) {
      return;
    }

    container.scrollTop = container.scrollHeight;
  };

  const jumpToReferencedMessage = (replyToMessageId?: string, replyToText?: string) => {
    if (!activeContact) {
      return;
    }

    let targetId = replyToMessageId;
    if (!targetId && replyToText) {
      const targetPreview = trimReplyPreview(replyToText);
      const matched = activeMessages.find((message) => trimReplyPreview(message.text) === targetPreview);
      targetId = matched?.id;
    }

    if (!targetId) {
      return;
    }

    const targetElement = messageElementRefs.current[targetId];
    if (!targetElement) {
      return;
    }

    targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setHighlightedMessageId(targetId);

    if (highlightTimeoutRef.current !== null) {
      window.clearTimeout(highlightTimeoutRef.current);
    }

    highlightTimeoutRef.current = window.setTimeout(() => {
      setHighlightedMessageId((previous) => (previous === targetId ? null : previous));
      highlightTimeoutRef.current = null;
    }, 1800);
  };

  const handleAddContact = (event: FormEvent) => {
    event.preventDefault();
    setError('');

    const address = newContact.trim();
    const name = normalizeContactName(newContactName);
    if (!isWalletAddress(address)) {
      setError('Enter a valid EVM wallet address.');
      return;
    }

    const existingIndex = contacts.findIndex((contact) => contact.address.toLowerCase() === address.toLowerCase());
    if (existingIndex >= 0) {
      if (!name) {
        setError('This contact already exists.');
        return;
      }

      setContacts((previous) =>
        previous.map((contact, index) => (index === existingIndex ? { ...contact, name } : contact))
      );
      setNewContact('');
      setNewContactName('');
      return;
    }

    setContacts((previous) => [...previous, { address, name }]);
    setNewContact('');
    setNewContactName('');
    if (!activeContact) {
      setActiveContact(address);
    }
  };

  const startRenameContact = (address: string, currentName?: string) => {
    setEditingContactAddress(address);
    setEditingContactName(currentName ?? '');
    setError('');
  };

  const cancelRenameContact = () => {
    setEditingContactAddress(null);
    setEditingContactName('');
  };

  const saveRenamedContact = (address: string) => {
    const name = normalizeContactName(editingContactName);
    if (!name) {
      setError('Contact name cannot be empty.');
      return;
    }

    setContacts((previous) =>
      previous.map((contact) =>
        contact.address.toLowerCase() === address.toLowerCase() ? { ...contact, name } : contact
      )
    );
    cancelRenameContact();
  };

  const copyAddressToClipboard = async (address: string) => {
    setError('');

    try {
      await navigator.clipboard.writeText(address);
    } catch {
      try {
        const tempInput = document.createElement('textarea');
        tempInput.value = address;
        tempInput.style.position = 'fixed';
        tempInput.style.opacity = '0';
        document.body.appendChild(tempInput);
        tempInput.focus();
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
      } catch {
        setError('Could not copy address to clipboard.');
      }
    }
  };

  const ensureCotiNetwork = async (provider: Eip1193Provider) => {
    if (!provider) {
      throw new Error('Wallet provider is not available.');
    }

    try {
      await provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: COTI_NETWORK.chainIdHex }]
      });
    } catch (switchError) {
      const errorWithCode = switchError as { code?: number; message?: string };

      if (errorWithCode.code === 4902) {
        await provider.request({
          method: 'wallet_addEthereumChain',
          params: [
            {
              chainId: COTI_NETWORK.chainIdHex,
              chainName: COTI_NETWORK.chainName,
              rpcUrls: [COTI_NETWORK.rpcUrl],
              blockExplorerUrls: [COTI_NETWORK.blockExplorerUrl],
              nativeCurrency: COTI_NETWORK.nativeCurrency
            }
          ]
        });
        await provider.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: COTI_NETWORK.chainIdHex }]
        });
      } else {
        throw new Error(errorWithCode.message ?? 'Could not switch to the COTI network.');
      }
    }
  };

  const refreshWalletState = async (providerOverride?: Eip1193Provider | null) => {
    const provider = providerOverride ?? getConnectedProvider();
    if (!provider) {
      return;
    }

    const accounts = (await provider.request({ method: 'eth_accounts' })) as string[];
    const selected = accounts[0] ?? '';
    setWalletAddress(selected);

    if (selected) {
      const currentChain = (await provider.request({ method: 'eth_chainId' })) as string | number;
      setChainId(normalizeChainId(currentChain));
      setStatus('Connected');
    } else {
      setChainId(null);
      setStatus('Disconnected');
    }
  };

  const onboardAddressAes = async (address: string, provider: Eip1193Provider) => {
    if (!provider) {
      throw new Error('Wallet provider is not available.');
    }

    setOnboardStatus('Onboarding...');
    await ensureCotiNetwork(provider);

    const browserProvider = await createCotiBrowserProvider(provider);

    const cacheKey = address.toLowerCase();
    const signer = await browserProvider.getSigner(address, sessionOnboardInfo[cacheKey]);
    signer.disableAutoOnboard();
    signerCacheRef.current[cacheKey] = signer;

    await signer.generateOrRecoverAes();

    const onboardInfo = signer.getUserOnboardInfo();
    const aesKey = onboardInfo?.aesKey ?? '';
    if (!aesKey) {
      throw new Error('AES key was not returned during onboarding.');
    }

    setSessionOnboardInfo((previous) => ({
      ...previous,
      [cacheKey]: mergeOnboardInfo(previous[cacheKey], onboardInfo)
    }));

    setOnboardStatus('AES key ready');
  };

  const connectAndOnboard = async () => {
    setError('');
    setConnectingMethod('metamask');

    const provider = window.ethereum;
    if (!provider) {
      setError('MetaMask not detected. Please install MetaMask.');
      setConnectingMethod(null);
      return;
    }

    try {
      setStatus('Connecting...');
      const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as string[];
      const selected = accounts[0] ?? '';

      if (!selected) {
        throw new Error('No wallet account selected.');
      }

      setConnectedProvider(provider);
      setConnectionMethod('metamask');
      setActiveSignerSource('metamask');
      setWalletAddress(selected);

      await onboardAddressAes(selected, provider);
      const currentChain = (await provider.request({ method: 'eth_chainId' })) as string | number;
      setChainId(normalizeChainId(currentChain));
      setStatus('Connected (MetaMask)');
      await syncConversationHistory();
    } catch (connectionError) {
      const message = connectionError instanceof Error ? connectionError.message : 'Failed to connect wallet.';
      setError(message);
      setStatus('Disconnected');
      setOnboardStatus('Not onboarded');
    } finally {
      setConnectingMethod(null);
    }
  };

  const disconnectWallet = async () => {
    setError('');

    burnerWalletRef.current = null;
    burnerRecordRef.current = null;
    setBurnerNeedsFunding(false);

    const provider = getConnectedProvider();

    try {
      if (connectionMethod === 'metamask' && provider) {
        await provider.request({
          method: 'wallet_revokePermissions',
          params: [{ eth_accounts: {} }]
        });
      }
    } catch {
    }

    setWalletAddress('');
    setChainId(null);
    setStatus('Disconnected');
    setActiveSignerSource('burner');
    setConnectionMethod(null);
    setOnboardStatus('Not onboarded');
    setSessionOnboardInfo({});
    setConnectedProvider(null);
    burnerPinRef.current = '';
    signerCacheRef.current = {};
  };

  const getMemoSigner = async () => {
    if (activeSignerSource === 'metamask') {
      const provider = getConnectedProvider();
      if (!provider) {
        throw new Error('Wallet provider not detected. Connect without burner first.');
      }

      if (!walletAddress) {
        throw new Error('Connect your wallet first.');
      }

      if (chainId !== COTI_NETWORK.chainIdDecimal) {
        throw new Error('Switch to COTI network first.');
      }

      const cacheKey = walletAddress.toLowerCase();
      const cachedOnboardInfo = sessionOnboardInfo[cacheKey];
      let signer = signerCacheRef.current[cacheKey];
      if (!signer) {
        const browserProvider = await createCotiBrowserProvider(provider);
        signer = await browserProvider.getSigner(walletAddress, cachedOnboardInfo);
        signer.disableAutoOnboard();
        signerCacheRef.current[cacheKey] = signer;
      } else if (cachedOnboardInfo) {
        signer.setUserOnboardInfo(cachedOnboardInfo);
      }

      signer.disableAutoOnboard();

      let onboardInfo = signer.getUserOnboardInfo();
      if (!onboardInfo?.aesKey) {
        if (cachedOnboardInfo) {
          signer.setUserOnboardInfo(cachedOnboardInfo);
          onboardInfo = signer.getUserOnboardInfo();
        }
      }

      if (!onboardInfo?.aesKey) {
        throw new Error('AES key unavailable. Use Connect without burner and complete onboarding signature once.');
      }

      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], onboardInfo)
      }));

      setOnboardStatus('AES key ready');
      return { signer, cacheKey };
    }

    const signer = burnerWalletRef.current;
    if (!signer) {
      throw new Error('Burner wallet not initialized.');
    }

    const cacheKey = signer.address.toLowerCase();
    const cachedOnboardInfo = sessionOnboardInfo[cacheKey];
    if (cachedOnboardInfo) {
      signer.setUserOnboardInfo(cachedOnboardInfo);
    }

    let onboardInfo = signer.getUserOnboardInfo();
    if (!onboardInfo?.aesKey) {
      await signer.generateOrRecoverAes();
      onboardInfo = signer.getUserOnboardInfo();
    }

    if (!onboardInfo?.aesKey) {
      throw new Error('AES key unavailable in this session. Please sign to enable encryption.');
    }

    setSessionOnboardInfo((previous) => ({
      ...previous,
      [cacheKey]: mergeOnboardInfo(previous[cacheKey], onboardInfo)
    }));

    setOnboardStatus('AES key ready');

    return { signer, cacheKey };
  };

  const syncConversationHistory = async () => {
    setError('');

    if (!walletAddress) {
      return;
    }

    if (syncingHistoryRef.current) {
      return;
    }

    try {
      syncingHistoryRef.current = true;
      setSyncingHistory(true);
      const { signer, cacheKey } = await getMemoSigner();
      const cotiEthers = await loadCotiEthersModule();
      const readProvider = await loadCotiReadProvider(true);
      const contract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, readProvider);
      const latestBlock = await readProvider.getBlockNumber();

      const walletKey = walletAddress.toLowerCase();
      const lastSyncedBlock = lastSyncedBlockRef.current[walletKey];
      const fromBlock = typeof lastSyncedBlock === 'number' ? lastSyncedBlock + 1 : 0;

      if (fromBlock > latestBlock) {
        return;
      }

      const incomingFilter = contract.filters.MessageSubmitted(walletAddress, null);
      const outgoingFilter = contract.filters.MessageSubmitted(null, walletAddress);

      const [incomingLogs, outgoingLogs] = await Promise.all([
        contract.queryFilter(incomingFilter, fromBlock, latestBlock),
        contract.queryFilter(outgoingFilter, fromBlock, latestBlock)
      ]);

      const blockNumbers = new Set<number>();
      for (const log of incomingLogs) {
        blockNumbers.add(log.blockNumber);
      }
      for (const log of outgoingLogs) {
        blockNumbers.add(log.blockNumber);
      }

      const blockTimestampMap = new Map<number, number>();
      await Promise.all(
        Array.from(blockNumbers).map(async (blockNumber) => {
          const block = await readProvider.getBlock(blockNumber);
          if (block?.timestamp) {
            blockTimestampMap.set(blockNumber, Number(block.timestamp));
          }
        })
      );

      const discoveredContacts = new Set<string>();
      const discoveredNicknames = new Map<string, string>();
      const entries: HistoryEntry[] = [];

      for (const log of incomingLogs) {
        const args = (log as { args?: Record<string, unknown> }).args;
        const from = String(args?.from ?? '');
        if (!isWalletAddress(from)) {
          continue;
        }

        discoveredContacts.add(from);

        const userCiphertext = extractUserCiphertext(args?.messageForRecipient);
        let messageText = '(Unable to decrypt message)';
        let replyToMessageId: string | undefined;
        let replyToText: string | undefined;
        if (userCiphertext && userCiphertext.value.length > 0) {
          try {
            const decrypted = await signer.decryptValue(userCiphertext as never);
            const raw = typeof decrypted === 'string' ? decrypted : decrypted.toString();
            const parsed = parseMessageProfilePayload(decodeMemoPlaintext(raw));
            const replyParsed = parseMessageReplyPayload(parsed.cleanText);
            messageText = replyParsed.cleanText;
            replyToMessageId = replyParsed.replyToMessageId;
            replyToText = replyParsed.replyToText;
            if (parsed.nickname) {
              discoveredNicknames.set(from.toLowerCase(), parsed.nickname);
            }
          } catch {
            messageText = '(Unable to decrypt message)';
          }
        }

        entries.push({
          id: `${log.transactionHash}-${log.index}-in`,
          contact: from,
          direction: 'incoming',
          text: messageText,
          replyToMessageId,
          replyToText,
          blockNumber: log.blockNumber,
          logIndex: log.index,
          timestamp: blockTimestampMap.get(log.blockNumber)
        });
      }

      for (const log of outgoingLogs) {
        const args = (log as { args?: Record<string, unknown> }).args;
        const recipient = String(args?.recipient ?? '');
        if (!isWalletAddress(recipient)) {
          continue;
        }

        discoveredContacts.add(recipient);

        const userCiphertext = extractUserCiphertext(args?.messageForSender);
        let messageText = '(Unable to decrypt message)';
        let replyToMessageId: string | undefined;
        let replyToText: string | undefined;
        if (userCiphertext && userCiphertext.value.length > 0) {
          try {
            const decrypted = await signer.decryptValue(userCiphertext as never);
            const raw = typeof decrypted === 'string' ? decrypted : decrypted.toString();
            const parsed = parseMessageProfilePayload(decodeMemoPlaintext(raw));
            const replyParsed = parseMessageReplyPayload(parsed.cleanText);
            messageText = replyParsed.cleanText;
            replyToMessageId = replyParsed.replyToMessageId;
            replyToText = replyParsed.replyToText;
          } catch {
            messageText = '(Unable to decrypt message)';
          }
        }

        entries.push({
          id: `${log.transactionHash}-${log.index}-out`,
          contact: recipient,
          direction: 'outgoing',
          text: messageText,
          replyToMessageId,
          replyToText,
          blockNumber: log.blockNumber,
          logIndex: log.index,
          timestamp: blockTimestampMap.get(log.blockNumber)
        });
      }

      entries.sort((a, b) => {
        if (a.blockNumber !== b.blockNumber) {
          return a.blockNumber - b.blockNumber;
        }
        return a.logIndex - b.logIndex;
      });

      setMessagesByContact((previous) => {
        if (entries.length === 0) {
          return previous;
        }

        const next: Record<string, ChatMessage[]> = { ...previous };
        const existingIdsByContact = new Map<string, Set<string>>();
        for (const entry of entries) {
          const key = entry.contact.toLowerCase();
          const existing = next[key] ?? [];
          let existingIds = existingIdsByContact.get(key);
          if (!existingIds) {
            existingIds = new Set(existing.map((message) => message.id));
            existingIdsByContact.set(key, existingIds);
          }

          if (existingIds.has(entry.id)) {
            continue;
          }

          existingIds.add(entry.id);

          next[key] = [
            ...existing,
            {
              id: entry.id,
              direction: entry.direction,
              text: entry.text,
              replyToMessageId: entry.replyToMessageId,
              replyToText: entry.replyToText,
              timestamp: entry.timestamp
            }
          ];
        }

        return next;
      });
      setContacts((previous) => {
        const mergedContacts = mergeUniqueContacts(previous, Array.from(discoveredContacts));

        if (discoveredNicknames.size === 0) {
          return mergedContacts;
        }

        return mergedContacts.map((contact) => {
          if (contact.name) {
            return contact;
          }

          const nickname = discoveredNicknames.get(contact.address.toLowerCase());
          if (!nickname) {
            return contact;
          }

          return {
            ...contact,
            name: nickname
          };
        });
      });
      lastSyncedBlockRef.current[walletKey] = latestBlock;

      if (!activeContact && discoveredContacts.size > 0) {
        setActiveContact(Array.from(discoveredContacts)[0]);
      }

      const nextOnboardInfo = signer.getUserOnboardInfo();
      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], nextOnboardInfo)
      }));
    } catch (syncError) {
      const message = syncError instanceof Error ? syncError.message : 'Failed to sync history.';
      setError(message);
    } finally {
      syncingHistoryRef.current = false;
      setSyncingHistory(false);
    }
  };

  useEffect(() => {
    syncConversationHistoryRef.current = syncConversationHistory;
  }, [syncConversationHistory]);

  const sendMessage = async () => {
    setError('');

    if (sendingRef.current) {
      return;
    }

    const plainText = messageInput.trim();
    if (!plainText) {
      setError('Enter a message first.');
      return;
    }

    if (!activeContact) {
      setError('Select a contact first.');
      return;
    }

    try {
      sendingRef.current = true;
      setSending(true);

      const { signer, cacheKey } = await getMemoSigner();
      const cotiEthers = await loadCotiEthersModule();
      const memoContractInterface = new cotiEthers.Interface(CHAT_CONTRACT_ABI);
      const selector = memoContractInterface.getFunction('submit')?.selector;
      if (!selector) {
        throw new Error('Unable to resolve submit selector.');
      }

      const contract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, signer);
      const requiredFee = (await contract.feeAmount()) as bigint;

      const contactKey = activeContact.toLowerCase();
      const shouldShareProfile = Boolean(myNickname.trim()) && !sharedNicknameContacts[contactKey];
      const plainTextWithReply = buildMessageWithReplyPayload(
        plainText,
        replyingToMessage?.text,
        replyingToMessage?.id
      );
      const sendEncryptedMemo = async (textToSend: string): Promise<void> => {
        const encodedMemo = encodeMemoPlaintext(textToSend);
        const encryptedMemo = await signer.encryptValue(encodedMemo, CHAT_CONTRACT_ADDRESS, selector);
        if (
          typeof encryptedMemo !== 'object' ||
          encryptedMemo === null ||
          typeof encryptedMemo.ciphertext !== 'object' ||
          encryptedMemo.ciphertext === null ||
          !('value' in encryptedMemo.ciphertext) ||
          !Array.isArray(encryptedMemo.signature)
        ) {
          throw new Error('Encrypted memo format mismatch for submit().');
        }

        const memoTuple = [[encryptedMemo.ciphertext.value], encryptedMemo.signature] as const;
        const tx = await contract.submit(activeContact, memoTuple, { value: requiredFee });
        await tx.wait();
      };

      let sentWithProfile = false;
      if (shouldShareProfile) {
        const plainTextWithProfile = buildMessageWithProfilePayload(plainTextWithReply, myNickname, true);
        await sendEncryptedMemo(plainTextWithProfile);
        sentWithProfile = true;
      } else {
        await sendEncryptedMemo(plainTextWithReply);
      }

      const nextOnboardInfo = signer.getUserOnboardInfo();
      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], nextOnboardInfo)
      }));

      if (sentWithProfile) {
        setSharedNicknameContacts((previous) => ({
          ...previous,
          [contactKey]: true
        }));
      }

      setMessageInput('');
      setReplyingToMessage(null);
      await syncConversationHistory();
      if (activeSignerSource === 'burner') {
        setTopUpMetricsNonce((previous) => previous + 1);
      }
    } catch (sendError) {
      const message = sendError instanceof Error ? sendError.message : 'Failed to send message.';
      setError(message);

      if (activeSignerSource === 'burner' && hasInsufficientFundsError(message)) {
        const shouldTopUp = window.confirm(
          'Burner wallet has insufficient funds. Do you want to top up now with MetaMask?'
        );
        if (shouldTopUp) {
          await topUpBurnerWithMetaMask();
        }
      }
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  };

  const loadLatestIncomingMessage = async () => {
    await syncConversationHistory();
  };
  useEffect(() => {
    try {
      window.localStorage.setItem(CONTACTS_STORAGE_KEY, JSON.stringify(contacts));
    } catch {
    }
  }, [contacts]);

  useEffect(() => {
    const scopedProfile = loadStoredProfile(walletAddress);
    setMyNickname(scopedProfile.nickname);
    setSharedNicknameContacts(loadSharedNicknameContacts(walletAddress));
  }, [walletAddress]);

  useEffect(() => {
    try {
      window.localStorage.setItem(
        scopedStorageKey(PROFILE_STORAGE_KEY, walletAddress),
        JSON.stringify({ nickname: myNickname })
      );
    } catch {
    }
  }, [walletAddress, myNickname]);

  useEffect(() => {
    try {
      window.localStorage.setItem(
        scopedStorageKey(PROFILE_SHARED_STORAGE_KEY, walletAddress),
        JSON.stringify(sharedNicknameContacts)
      );
    } catch {
    }
  }, [walletAddress, sharedNicknameContacts]);

  useEffect(() => {
    if (!contacts.length) {
      setActiveContact(null);
      return;
    }

    if (!activeContact) {
      setActiveContact(contacts[0].address);
      return;
    }

    const exists = contacts.some((contact) => contact.address.toLowerCase() === activeContact.toLowerCase());
    if (!exists) {
      setActiveContact(contacts[0].address);
    }
  }, [contacts, activeContact]);

  useEffect(() => {
    try {
      if (!activeContact) {
        window.localStorage.removeItem(ACTIVE_CONTACT_STORAGE_KEY);
      } else {
        window.localStorage.setItem(ACTIVE_CONTACT_STORAGE_KEY, activeContact);
      }
    } catch {
    }
  }, [activeContact]);

  useEffect(() => {
    if (!walletAddress) {
      setOnboardStatus('Not onboarded');
      return;
    }

    const cachedOnboardInfo = sessionOnboardInfo[walletAddress.toLowerCase()];
    if (cachedOnboardInfo?.aesKey) {
      setOnboardStatus('AES key ready');
      return;
    }

    setOnboardStatus('Signature required');
  }, [walletAddress, sessionOnboardInfo]);

  useEffect(() => {
    setMessageInput('');
    setReplyingToMessage(null);
    setHighlightedMessageId(null);
  }, [activeContact]);

  useEffect(() => {
    return () => {
      if (highlightTimeoutRef.current !== null) {
        window.clearTimeout(highlightTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    requestAnimationFrame(() => {
      scrollChatToBottom();
    });
  }, [activeContact, activeMessages.length]);

  useEffect(() => {
    if (!walletAddress) {
      setMessagesByContact({});
    }
  }, [walletAddress]);

  useEffect(() => {
    let cancelled = false;

    if (!burnerAddress || !isWalletAddress(burnerAddress)) {
      setTopUpAmountWei(null);
      setRequiredFeeWei(null);
      setBurnerBalanceWei(null);
      setLoadingTopUpQuote(false);
      return;
    }

    const loadTopUpAmount = async () => {
      setLoadingTopUpQuote(true);
      try {
        const cotiEthers = await loadCotiEthersModule();
        const readProvider = await loadCotiReadProvider(true);
        const readContract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, readProvider);
        const [requiredFee, burnerBalance] = (await Promise.all([
          readContract.feeAmount(),
          readProvider.getBalance(burnerAddress)
        ])) as [bigint, bigint];
        if (!cancelled) {
          setRequiredFeeWei(requiredFee);
          setBurnerBalanceWei(burnerBalance);
          setTopUpAmountWei(calculateTopUpAmount(requiredFee, topUpMultiplier));
        }
      } catch {
        if (!cancelled) {
          setTopUpAmountWei(null);
          setRequiredFeeWei(null);
          setBurnerBalanceWei(null);
        }
      } finally {
        if (!cancelled) {
          setLoadingTopUpQuote(false);
        }
      }
    };

    loadTopUpAmount().catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [burnerAddress, topUpMultiplier, topUpMetricsNonce]);

  useEffect(() => {
    if (!burnerAddress || !isWalletAddress(burnerAddress)) {
      return;
    }

    const intervalId = window.setInterval(() => {
      setTopUpMetricsNonce((previous) => previous + 1);
    }, AUTO_SYNC_INTERVAL_MS);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [burnerAddress]);

  useEffect(() => {
    if (!walletAddress || chainId !== COTI_NETWORK.chainIdDecimal) {
      return;
    }

    if (!hasAesReady) {
      return;
    }

    let cancelled = false;
    let unsubscribe: (() => void) | null = null;
    let pollIntervalId: number | null = null;

    const setupRealtimeSubscription = async () => {
      try {
        if (cancelled) {
          return;
        }

        const cotiEthers = await loadCotiEthersModule();
        const wsProvider = await loadCotiWsProvider();
        await wsProvider.getBlockNumber();
        const contract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, wsProvider);

        const incomingFilter = contract.filters.MessageSubmitted(walletAddress, null);
        const outgoingFilter = contract.filters.MessageSubmitted(null, walletAddress);
        const handleMessageSubmitted = () => {
          if (!cancelled) {
            syncConversationHistoryRef.current().catch(() => {});
          }
        };

        contract.on(incomingFilter, handleMessageSubmitted);
        contract.on(outgoingFilter, handleMessageSubmitted);

        if (cancelled) {
          contract.off(incomingFilter, handleMessageSubmitted);
          contract.off(outgoingFilter, handleMessageSubmitted);
          return;
        }

        unsubscribe = () => {
          contract.off(incomingFilter, handleMessageSubmitted);
          contract.off(outgoingFilter, handleMessageSubmitted);
        };
      } catch {
        await resetCotiWsProvider();
        if (!cancelled) {
          pollIntervalId = window.setInterval(() => {
            syncConversationHistoryRef.current().catch(() => {});
          }, AUTO_SYNC_INTERVAL_MS);
        }
      }
    };

    syncConversationHistoryRef.current().catch(() => {});
    setupRealtimeSubscription().catch(() => {});

    return () => {
      cancelled = true;
      if (pollIntervalId !== null) {
        window.clearInterval(pollIntervalId);
      }
      unsubscribe?.();
    };
  }, [walletAddress, chainId, hasAesReady]);

  useEffect(() => {
    const provider = getConnectedProvider();

    refreshWalletState(provider).catch(() => {
      setError('Unable to read wallet state.');
    });

    if (!provider?.on || !provider?.removeListener) {
      return;
    }

    const handleAccountsChanged = (accounts: unknown) => {
      const nextAccounts = Array.isArray(accounts) ? (accounts as string[]) : [];
      const selected = nextAccounts[0] ?? '';
      setWalletAddress(selected);
      if (!selected) {
        setStatus('Disconnected');
        setChainId(null);
      }
    };

    const handleChainChanged = (newChainId: unknown) => {
      if (typeof newChainId === 'string' || typeof newChainId === 'number') {
        setChainId(normalizeChainId(newChainId));
      }
    };

    provider.on('accountsChanged', handleAccountsChanged);
    provider.on('chainChanged', handleChainChanged);

    return () => {
      provider.removeListener?.('accountsChanged', handleAccountsChanged);
      provider.removeListener?.('chainChanged', handleChainChanged);
    };
  }, [activeProvider, connectionMethod]);

  return (
    <div className="app-root">
      <aside className="sidebar">
        <h1 className="title">COTI Chat</h1>

        <button
          className="connect-btn"
          onClick={() => {
            beginBurnerPinFlow('generate').catch(() => {});
          }}
          type="button"
          disabled={initializingBurner}
        >
          {initializingBurner ? 'Initializing Burner...' : 'Generate Burner Wallet'}
        </button>

        <button
          className="connect-btn"
          onClick={() => {
            beginBurnerPinFlow('stored').catch(() => {});
          }}
          type="button"
          disabled={initializingBurner}
        >
          Connect Burner Wallet
        </button>

        <button className="connect-btn" onClick={() => setShowBurnerImportModal(true)} type="button" disabled={initializingBurner}>
          Import Burner Wallet
        </button>

        <button
          className="connect-btn"
          onClick={openChangeBurnerPin}
          type="button"
          disabled={initializingBurner || !burnerRecordRef.current}
        >
          Change Burner PIN
        </button>

        <button className="connect-btn" onClick={topUpBurnerWithMetaMask} type="button" disabled={initializingBurner || !burnerAddress}>
          Top Up Burner (MetaMask)
        </button>
        <div className="wallet-meta topup-meta">
          <div className="meta-row">
            <span>Top up scale</span>
            <strong>x{topUpMultiplier}</strong>
          </div>
          <input
            className="topup-slider"
            type="range"
            min={1}
            max={100}
            step={1}
            value={topUpMultiplier}
            onChange={(event) => setTopUpMultiplier(Number(event.target.value))}
            aria-label="Top up multiplier"
          />
          <p>Approx messages per top up: {topUpMultiplier}</p>
          <div className="meta-row">
            <span>Wallet balance</span>
            <strong>
              {loadingTopUpQuote
                ? 'Calculating...'
                : burnerBalanceWei !== null
                  ? `${formatCotiAmount(burnerBalanceWei)} COTI`
                  : '—'}
            </strong>
          </div>
          <div className="meta-row">
            <span>Messages left</span>
            <strong>
              {loadingTopUpQuote
                ? 'Calculating...'
                : estimatedMessagesLeft !== null
                  ? estimatedMessagesLeft.toString()
                  : '—'}
            </strong>
          </div>
          <div className="meta-row">
            <span>Top up amount</span>
            <strong>
              {loadingTopUpQuote
                ? 'Calculating...'
                : topUpAmountWei !== null
                  ? `${formatCotiAmount(topUpAmountWei)} COTI`
                  : '—'}
            </strong>
          </div>
        </div>

        <div className="wallet-meta">
          <div className="meta-row">
            <span>Burner wallet</span>
            {burnerAddress ? (
              <button
                type="button"
                className="burner-address-btn"
                onClick={() => copyAddressToClipboard(burnerAddress)}
                title={burnerAddress}
              >
                {shortenAddress(burnerAddress)}
              </button>
            ) : (
              <strong>—</strong>
            )}
          </div>
        </div>

        <div className="wallet-meta">
          <div className="meta-row">
            <span>My nickname</span>
          </div>
          <input
            value={myNickname}
            onChange={(event) => setMyNickname(event.target.value.slice(0, 42))}
            placeholder="Choose nickname"
            aria-label="My nickname"
          />
        </div>

        {burnerNeedsFunding ? <p className="error">Burner needs funding before onboarding.</p> : null}
        {burnerMnemonicBackup ? (
          <div className="wallet-meta">
            <div className="meta-row">
              <span>Burner backup</span>
              <button
                type="button"
                className="burner-address-btn"
                onClick={() => setShowBurnerMnemonic((previous) => !previous)}
              >
                {showBurnerMnemonic ? 'Hide phrase' : 'Show phrase'}
              </button>
            </div>
            {showBurnerMnemonic ? <p>{burnerMnemonicBackup}</p> : null}
          </div>
        ) : null}

        <button
          className="connect-btn"
          onClick={connectAndOnboard}
          type="button"
          disabled={connectingMethod !== null}
        >
          {connectingMethod === 'metamask'
            ? 'Connecting MetaMask...'
            : !isConnected || connectionMethod !== 'metamask'
            ? 'Connect without burner'
            : onboardStatus === 'AES key ready'
              ? 'MetaMask + AES Ready'
              : 'Sign AES Key'}
        </button>

        <button className="connect-btn" onClick={disconnectWallet} type="button" disabled={!isConnected || connectingMethod !== null}>
          Disconnect
        </button>

        <div className="wallet-meta">
          <div className="meta-row">
            <span>Status</span>
            <strong>{status}</strong>
          </div>
          <div className="meta-row">
            <span>Network</span>
            <strong>{onCotiNetwork ? 'COTI' : chainId ? `Chain ${chainId}` : '—'}</strong>
          </div>
          <div className="meta-row">
            <span>Address</span>
            <strong>{walletAddress ? shortenAddress(walletAddress) : '—'}</strong>
          </div>
          <div className="meta-row">
            <span>AES</span>
            <strong>{onboardStatus}</strong>
          </div>
        </div>

      </aside>

      <aside className="contacts-sidebar">
        <h2 className="title">Contacts</h2>

        <form className="contact-form" onSubmit={handleAddContact}>
          <input
            value={newContactName}
            onChange={(event) => setNewContactName(event.target.value)}
            placeholder="Contact name (optional)"
            aria-label="Contact name"
          />
          <input
            value={newContact}
            onChange={(event) => setNewContact(event.target.value)}
            placeholder="0x... wallet address"
            aria-label="Wallet address"
          />
          <button type="submit">Save Contact</button>
        </form>

        <ul className="contacts-list">
          {sortedContacts.map((contact) => {
            const isActive = activeContact?.toLowerCase() === contact.address.toLowerCase();
            const isEditing = editingContactAddress?.toLowerCase() === contact.address.toLowerCase();
            return (
              <li key={contact.address}>
                <div
                  className={isActive ? 'contact-card active' : 'contact-card'}
                  role="button"
                  tabIndex={0}
                  onClick={() => setActiveContact(contact.address)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setActiveContact(contact.address);
                    }
                  }}
                >
                  <div className="contact-top">
                    <div className="contact-main" title={contact.address}>
                      <span className="contact-label">{contact.name ?? shortenAddress(contact.address)}</span>
                    </div>
                    {!isEditing ? (
                      <button
                        type="button"
                        className="contact-icon"
                        onClick={(event) => {
                          event.stopPropagation();
                          startRenameContact(contact.address, contact.name);
                        }}
                        aria-label="Rename contact"
                        title="Rename"
                      >
                        ✎
                      </button>
                    ) : null}
                  </div>
                  <button
                    type="button"
                    className="contact-copy"
                    onClick={(event) => {
                      event.stopPropagation();
                      copyAddressToClipboard(contact.address);
                    }}
                    title="Copy address"
                  >
                    {shortenAddress(contact.address)}
                  </button>
                </div>
                {isEditing ? (
                  <div className="contact-rename">
                    <input
                      value={editingContactName}
                      onChange={(event) => setEditingContactName(event.target.value)}
                      placeholder="Enter name"
                      aria-label="Rename contact"
                    />
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        saveRenamedContact(contact.address);
                      }}
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        cancelRenameContact();
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>

        {error ? <p className="error">{error}</p> : null}
      </aside>

      <main className="chat-panel">
        {activeContact ? (
          <div className="chat-shell">
            <div className="chat-header">
              <strong>
                {`Chat with ${activeContactMeta?.name ? `${activeContactMeta.name} (${shortenAddress(activeContact)})` : shortenAddress(activeContact)}`}
              </strong>
              <button type="button" className="contact" onClick={loadLatestIncomingMessage} disabled={syncingHistory}>
                {syncingHistory ? 'Syncing...' : 'Sync History'}
              </button>
            </div>

            <div className="chat-messages" ref={chatMessagesRef}>
              {activeMessages.length === 0 ? (
                <p className="chat-empty">No messages yet.</p>
              ) : (
                activeMessages.map((message) => (
                  <div
                    key={message.id}
                    className={message.direction === 'outgoing' ? 'message-row outgoing' : 'message-row incoming'}
                  >
                    <div
                      ref={(node) => {
                        messageElementRefs.current[message.id] = node;
                      }}
                      className={
                        highlightedMessageId === message.id
                          ? 'message-bubble highlighted'
                          : replyingToMessage?.id === message.id
                            ? 'message-bubble replying'
                            : 'message-bubble'
                      }
                    >
                      <button
                        type="button"
                        className="message-reply-action"
                        onClick={() => setReplyingToMessage(message)}
                        aria-label="Reply to this message"
                        title="Reply"
                      >
                        ↩
                      </button>
                      {message.replyToText ? (
                        <button
                          type="button"
                          className="message-reply"
                          onClick={() => jumpToReferencedMessage(message.replyToMessageId, message.replyToText)}
                          title="Go to replied message"
                        >
                          ↪ {message.replyToText}
                        </button>
                      ) : null}
                      <div>{message.text}</div>
                      {message.timestamp ? <div className="message-time">{formatMessageTimestamp(message.timestamp)}</div> : null}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="chat-compose">
              {replyingToMessage ? (
                <div className="chat-replying">
                  <span>Replying to: {trimReplyPreview(replyingToMessage.text)}</span>
                  <button type="button" onClick={() => setReplyingToMessage(null)}>
                    Cancel
                  </button>
                </div>
              ) : null}
              <input
                value={messageInput}
                name="chat-message"
                autoComplete="new-password"
                data-form-type="other"
                data-lpignore="true"
                data-1p-ignore="true"
                data-bwignore="true"
                onChange={(event) => setMessageInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    sendMessage().catch(() => {});
                  }
                }}
                placeholder="Type a private message"
                aria-label="Message"
              />
              <button type="button" onClick={sendMessage} disabled={sending}>
                {sending ? 'Sending...' : 'Send'}
              </button>
            </div>
          </div>
        ) : (
          <div className="chat-placeholder">Select a contact to start messaging.</div>
        )}
      </main>

      {showBurnerImportModal ? (
        <div
          className="modal-backdrop"
          onClick={() => {
            if (!initializingBurner) {
              setShowBurnerImportModal(false);
            }
          }}
        >
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <h3>Import Burner Wallet</h3>
            <input
              value={burnerImportInput}
              onChange={(event) => setBurnerImportInput(event.target.value)}
              placeholder="Mnemonic phrase or 0x private key"
              aria-label="Import burner wallet"
            />
            <div className="modal-actions">
              <button
                type="button"
                className="connect-btn"
                onClick={() => setShowBurnerImportModal(false)}
                disabled={initializingBurner}
              >
                Cancel
              </button>
              <button type="button" className="connect-btn" onClick={importBurnerWallet} disabled={initializingBurner}>
                {initializingBurner ? 'Importing...' : 'Import'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {showBurnerPinModal ? (
        <div className="modal-backdrop" onClick={closeBurnerPinModal}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <h3>{burnerPinMode === 'set' ? 'Set Burner PIN' : 'Unlock Burner Wallet'}</h3>
            <input
              value={burnerPinInput}
              name={burnerPinMode === 'set' ? 'burner-pin-new' : 'burner-pin-unlock'}
              autoComplete={burnerPinMode === 'set' ? 'new-password' : 'current-password'}
              data-form-type="other"
              data-lpignore="true"
              data-1p-ignore="true"
              data-bwignore="true"
              onChange={(event) => setBurnerPinInput(event.target.value)}
              placeholder={burnerPinMode === 'set' ? `Choose PIN (${BURNER_PIN_MIN_LENGTH}+ digits)` : 'Enter PIN'}
              aria-label="Burner PIN"
              type="password"
            />
            {burnerPinMode === 'set' ? (
              <input
                value={burnerPinConfirmInput}
                name="burner-pin-confirm"
                autoComplete="new-password"
                data-form-type="other"
                data-lpignore="true"
                data-1p-ignore="true"
                data-bwignore="true"
                onChange={(event) => setBurnerPinConfirmInput(event.target.value)}
                placeholder="Confirm PIN"
                aria-label="Confirm burner PIN"
                type="password"
              />
            ) : null}
            <div className="modal-actions">
              <button type="button" className="connect-btn" onClick={closeBurnerPinModal} disabled={initializingBurner}>
                Cancel
              </button>
              <button
                type="button"
                className="connect-btn"
                onClick={() => {
                  submitBurnerPinAndInitialize().catch(() => {});
                }}
                disabled={initializingBurner}
              >
                {initializingBurner ? 'Please wait...' : burnerPinMode === 'set' ? 'Save & Connect' : 'Unlock'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
