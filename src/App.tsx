import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import type { BrowserProvider, JsonRpcSigner, OnboardInfo } from '@coti-io/coti-ethers';

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
  timestamp?: number;
};

type HistoryEntry = {
  id: string;
  contact: string;
  direction: 'incoming' | 'outgoing';
  text: string;
  blockNumber: number;
  logIndex: number;
  timestamp?: number;
};

const CONTACTS_STORAGE_KEY = 'coti-chat-contacts';
const ACTIVE_CONTACT_STORAGE_KEY = 'coti-chat-active-contact';
const AUTO_SYNC_INTERVAL_MS = 30000;

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
type WalletConnectProviderModule = typeof import('@walletconnect/ethereum-provider');
type CotiWsProvider = InstanceType<CotiEthersModule['WebSocketProvider']>;
type CotiHttpProvider = InstanceType<CotiEthersModule['JsonRpcProvider']>;
type CotiReadProvider = CotiWsProvider | CotiHttpProvider;
let cotiEthersModulePromise: Promise<CotiEthersModule> | null = null;
let walletConnectModulePromise: Promise<WalletConnectProviderModule> | null = null;
let cotiWsProviderPromise: Promise<CotiWsProvider> | null = null;
let cotiHttpProviderPromise: Promise<CotiHttpProvider> | null = null;

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID as string | undefined;

const loadCotiEthersModule = (): Promise<CotiEthersModule> => {
  if (!cotiEthersModulePromise) {
    cotiEthersModulePromise = import('@coti-io/coti-ethers');
  }

  return cotiEthersModulePromise;
};

const loadWalletConnectProviderModule = (): Promise<WalletConnectProviderModule> => {
  if (!walletConnectModulePromise) {
    walletConnectModulePromise = import('@walletconnect/ethereum-provider');
  }

  return walletConnectModulePromise;
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
  const [connectionMethod, setConnectionMethod] = useState<'metamask' | 'walletconnect' | null>(null);
  const [connectingMethod, setConnectingMethod] = useState<'metamask' | 'walletconnect' | null>(null);
  const [onboardStatus, setOnboardStatus] = useState<string>('Not onboarded');
  const [sessionOnboardInfo, setSessionOnboardInfo] = useState<Record<string, OnboardInfo>>({});
  const [messageInput, setMessageInput] = useState('');
  const [messagesByContact, setMessagesByContact] = useState<Record<string, ChatMessage[]>>({});
  const [sending, setSending] = useState(false);
  const [syncingHistory, setSyncingHistory] = useState(false);
  const [error, setError] = useState<string>('');
  const [activeProvider, setActiveProvider] = useState<Eip1193Provider | null>(null);
  const activeProviderRef = useRef<Eip1193Provider | null>(null);
  const chatMessagesRef = useRef<HTMLDivElement | null>(null);
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

  const setConnectedProvider = (provider: Eip1193Provider | null) => {
    activeProviderRef.current = provider;
    setActiveProvider(provider);
  };

  const getConnectedProvider = (): Eip1193Provider | null => {
    if (connectionMethod === 'walletconnect') {
      return activeProviderRef.current ?? activeProvider ?? null;
    }

    if (connectionMethod === 'metamask') {
      return activeProviderRef.current ?? activeProvider ?? window.ethereum ?? null;
    }

    return activeProviderRef.current ?? activeProvider ?? null;
  };

  const scrollChatToBottom = () => {
    const container = chatMessagesRef.current;
    if (!container) {
      return;
    }

    container.scrollTop = container.scrollHeight;
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

  const connectWalletConnect = async () => {
    setError('');
    setConnectingMethod('walletconnect');

    if (!WALLETCONNECT_PROJECT_ID) {
      setError('Missing VITE_WALLETCONNECT_PROJECT_ID in .env.');
      setConnectingMethod(null);
      return;
    }

    let walletConnectProvider: Eip1193Provider | null = null;

    try {
      setStatus('Connecting WalletConnect...');
      const walletConnectModule = await loadWalletConnectProviderModule();
      const wcProvider = await walletConnectModule.EthereumProvider.init({
        projectId: WALLETCONNECT_PROJECT_ID,
        chains: [COTI_NETWORK.chainIdDecimal],
        optionalChains: [COTI_NETWORK.chainIdDecimal],
        showQrModal: true,
        rpcMap: {
          [COTI_NETWORK.chainIdDecimal]: COTI_NETWORK.rpcUrl
        }
      });

      walletConnectProvider = wcProvider as unknown as Eip1193Provider;
      await walletConnectProvider.connect?.();
      const accounts = (await walletConnectProvider.request({ method: 'eth_accounts' })) as string[];
      const selected = accounts[0] ?? '';

      if (!selected) {
        throw new Error('No wallet account selected via WalletConnect.');
      }

      setConnectedProvider(walletConnectProvider);
      setConnectionMethod('walletconnect');
      setWalletAddress(selected);

      await onboardAddressAes(selected, walletConnectProvider);
      const currentChain = (await walletConnectProvider.request({ method: 'eth_chainId' })) as string | number;
      setChainId(normalizeChainId(currentChain));
      setStatus('Connected (WalletConnect)');
      await syncConversationHistory();
    } catch (connectionError) {
      try {
        await walletConnectProvider?.disconnect?.();
      } catch {
      }
      const message = connectionError instanceof Error ? connectionError.message : 'Failed to connect WalletConnect.';
      setError(message);
      setStatus('Disconnected');
      setOnboardStatus('Not onboarded');
      setConnectedProvider(null);
      setConnectionMethod(null);
    } finally {
      setConnectingMethod(null);
    }
  };

  const disconnectWallet = async () => {
    setError('');

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

    try {
      if (connectionMethod === 'walletconnect') {
        await provider?.disconnect?.();
      }
    } catch {
    }

    setWalletAddress('');
    setChainId(null);
    setStatus('Disconnected');
    setConnectionMethod(null);
    setOnboardStatus('Not onboarded');
    setSessionOnboardInfo({});
    setConnectedProvider(null);
    signerCacheRef.current = {};
  };

  const getMemoSigner = async () => {
    const provider = getConnectedProvider();
    if (!provider) {
      throw new Error('Wallet provider not detected. Connect with MetaMask or WalletConnect.');
    }

    if (!walletAddress) {
      throw new Error('Connect your wallet first.');
    }

    if (chainId !== COTI_NETWORK.chainIdDecimal) {
      throw new Error('Switch to COTI network first.');
    }

    const cacheKey = walletAddress.toLowerCase();

    let signer = signerCacheRef.current[cacheKey];
    if (!signer) {
      const browserProvider = await createCotiBrowserProvider(provider);
      signer = await browserProvider.getSigner(walletAddress, sessionOnboardInfo[cacheKey]);
      signerCacheRef.current[cacheKey] = signer;
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
        if (userCiphertext && userCiphertext.value.length > 0) {
          try {
            const decrypted = await signer.decryptValue(userCiphertext as never);
            const raw = typeof decrypted === 'string' ? decrypted : decrypted.toString();
            messageText = decodeMemoPlaintext(raw);
          } catch {
            messageText = '(Unable to decrypt message)';
          }
        }

        entries.push({
          id: `${log.transactionHash}-${log.index}-in`,
          contact: from,
          direction: 'incoming',
          text: messageText,
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
        if (userCiphertext && userCiphertext.value.length > 0) {
          try {
            const decrypted = await signer.decryptValue(userCiphertext as never);
            const raw = typeof decrypted === 'string' ? decrypted : decrypted.toString();
            messageText = decodeMemoPlaintext(raw);
          } catch {
            messageText = '(Unable to decrypt message)';
          }
        }

        entries.push({
          id: `${log.transactionHash}-${log.index}-out`,
          contact: recipient,
          direction: 'outgoing',
          text: messageText,
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
        for (const entry of entries) {
          const key = entry.contact.toLowerCase();
          const existing = next[key] ?? [];

          if (existing.some((message) => message.id === entry.id)) {
            continue;
          }

          next[key] = [
            ...existing,
            {
              id: entry.id,
              direction: entry.direction,
              text: entry.text,
              timestamp: entry.timestamp
            }
          ];
        }

        return next;
      });
      setContacts((previous) => mergeUniqueContacts(previous, Array.from(discoveredContacts)));
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

      const encodedMemo = encodeMemoPlaintext(plainText);
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

      const contract = new cotiEthers.Contract(CHAT_CONTRACT_ADDRESS, CHAT_CONTRACT_ABI, signer);
      const requiredFee = (await contract.feeAmount()) as bigint;
      const memoTuple = [[encryptedMemo.ciphertext.value], encryptedMemo.signature] as const;
      const tx = await contract.submit(activeContact, memoTuple, { value: requiredFee });
      await tx.wait();

      const nextOnboardInfo = signer.getUserOnboardInfo();
      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], nextOnboardInfo)
      }));

      setMessageInput('');
      await syncConversationHistory();
    } catch (sendError) {
      const message = sendError instanceof Error ? sendError.message : 'Failed to send message.';
      setError(message);
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
  }, [activeContact]);

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
          onClick={connectAndOnboard}
          type="button"
          disabled={connectingMethod !== null || (isConnected && connectionMethod === 'walletconnect')}
        >
          {connectingMethod === 'metamask'
            ? 'Connecting MetaMask...'
            : !isConnected || connectionMethod !== 'metamask'
            ? 'Connect MetaMask + Sign AES'
            : onboardStatus === 'AES key ready'
              ? 'MetaMask + AES Ready'
              : 'Sign AES Key'}
        </button>

        <button
          className="connect-btn"
          onClick={connectWalletConnect}
          type="button"
          disabled={connectingMethod !== null || (isConnected && connectionMethod === 'metamask')}
        >
          {connectingMethod === 'walletconnect'
            ? 'Connecting WalletConnect...'
            : !isConnected || connectionMethod !== 'walletconnect'
            ? 'Connect WalletConnect + Sign AES'
            : onboardStatus === 'AES key ready'
              ? 'WalletConnect + AES Ready'
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
                    <div className="message-bubble">
                      <div>{message.text}</div>
                      {message.timestamp ? <div className="message-time">{formatMessageTimestamp(message.timestamp)}</div> : null}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="chat-compose">
              <input
                value={messageInput}
                onChange={(event) => setMessageInput(event.target.value)}
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
    </div>
  );
}
