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

type Contact = {
  address: string;
  name?: string;
};

type ChatMessage = {
  id: string;
  direction: 'incoming' | 'outgoing';
  text: string;
};

type HistoryEntry = {
  id: string;
  contact: string;
  direction: 'incoming' | 'outgoing';
  text: string;
  blockNumber: number;
  logIndex: number;
};

const CONTACTS_STORAGE_KEY = 'coti-chat-contacts';
const ACTIVE_CONTACT_STORAGE_KEY = 'coti-chat-active-contact';

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

const MEMO_CONTRACT_ADDRESS = '0xa354bFd7f53bE4972501633BA26F0423a7323ce0';
const MEMO_CONTRACT_ABI = [
  'function submit(address recipient, ((uint256[] value), bytes[] signature) memo) payable',
  'event MemoSubmitted(address indexed recipient, address indexed from, ((uint256[] value) ciphertext, (uint256[] value) userCiphertext) memoForRecipient, ((uint256[] value) ciphertext, (uint256[] value) userCiphertext) memoForSender)'
] as const;

type CotiEthersModule = typeof import('@coti-io/coti-ethers');
let cotiEthersModulePromise: Promise<CotiEthersModule> | null = null;

const loadCotiEthersModule = (): Promise<CotiEthersModule> => {
  if (!cotiEthersModulePromise) {
    cotiEthersModulePromise = import('@coti-io/coti-ethers');
  }

  return cotiEthersModulePromise;
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

const createCotiBrowserProvider = async (ethereum: NonNullable<Window['ethereum']>): Promise<BrowserProvider> => {
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
  const [onboardStatus, setOnboardStatus] = useState<string>('Not onboarded');
  const [sessionOnboardInfo, setSessionOnboardInfo] = useState<Record<string, OnboardInfo>>({});
  const [messageInput, setMessageInput] = useState('');
  const [messagesByContact, setMessagesByContact] = useState<Record<string, ChatMessage[]>>({});
  const [sending, setSending] = useState(false);
  const [syncingHistory, setSyncingHistory] = useState(false);
  const [error, setError] = useState<string>('');
  const signerCacheRef = useRef<Record<string, JsonRpcSigner>>({});

  const isConnected = useMemo(() => walletAddress.length > 0, [walletAddress]);
  const onCotiNetwork = useMemo(() => chainId === COTI_NETWORK.chainIdDecimal, [chainId]);
  const activeMessages = useMemo(() => {
    if (!activeContact) {
      return [];
    }
    return messagesByContact[activeContact.toLowerCase()] ?? [];
  }, [activeContact, messagesByContact]);
  const activeContactMeta = useMemo(
    () => contacts.find((contact) => contact.address.toLowerCase() === activeContact?.toLowerCase()),
    [contacts, activeContact]
  );

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

  const ensureCotiNetwork = async () => {
    if (!window.ethereum) {
      throw new Error('MetaMask is not installed.');
    }

    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: COTI_NETWORK.chainIdHex }]
      });
    } catch (switchError) {
      const errorWithCode = switchError as { code?: number; message?: string };

      if (errorWithCode.code === 4902) {
        await window.ethereum.request({
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
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: COTI_NETWORK.chainIdHex }]
        });
      } else {
        throw new Error(errorWithCode.message ?? 'Could not switch to the COTI network.');
      }
    }
  };

  const refreshWalletState = async () => {
    if (!window.ethereum) {
      return;
    }

    const accounts = (await window.ethereum.request({ method: 'eth_accounts' })) as string[];
    const selected = accounts[0] ?? '';
    setWalletAddress(selected);

    if (selected) {
      const currentChain = (await window.ethereum.request({ method: 'eth_chainId' })) as string | number;
      setChainId(normalizeChainId(currentChain));
      setStatus('Connected');
    } else {
      setChainId(null);
      setStatus('Disconnected');
    }
  };

  const onboardAddressAes = async (address: string) => {
    if (!window.ethereum) {
      throw new Error('MetaMask not detected. Please install MetaMask.');
    }

    setOnboardStatus('Onboarding...');
    await ensureCotiNetwork();

    const provider = await createCotiBrowserProvider(window.ethereum);

    const cacheKey = address.toLowerCase();
    const signer = await provider.getSigner(address, sessionOnboardInfo[cacheKey]);
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

    if (!window.ethereum) {
      setError('MetaMask not detected. Please install MetaMask.');
      return;
    }

    try {
      setStatus('Connecting...');
      const accounts = walletAddress
        ? ((await window.ethereum.request({ method: 'eth_accounts' })) as string[])
        : ((await window.ethereum.request({ method: 'eth_requestAccounts' })) as string[]);
      const selected = accounts[0] ?? '';

      if (!selected) {
        throw new Error('No wallet account selected.');
      }

      setWalletAddress(selected);

      await onboardAddressAes(selected);
      const currentChain = (await window.ethereum.request({ method: 'eth_chainId' })) as string | number;
      setChainId(normalizeChainId(currentChain));
      setStatus('Connected');
      await syncConversationHistory();
    } catch (connectionError) {
      const message = connectionError instanceof Error ? connectionError.message : 'Failed to connect wallet.';
      setError(message);
      setStatus('Disconnected');
      setOnboardStatus('Not onboarded');
    }
  };

  const disconnectWallet = async () => {
    setError('');

    try {
      if (window.ethereum) {
        await window.ethereum.request({
          method: 'wallet_revokePermissions',
          params: [{ eth_accounts: {} }]
        });
      }
    } catch {
    }

    setWalletAddress('');
    setChainId(null);
    setStatus('Disconnected');
    setOnboardStatus('Not onboarded');
    setSessionOnboardInfo({});
    signerCacheRef.current = {};
  };

  const getMemoSigner = async () => {
    if (!window.ethereum) {
      throw new Error('MetaMask not detected. Please install MetaMask.');
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
      const provider = await createCotiBrowserProvider(window.ethereum);
      signer = await provider.getSigner(walletAddress, sessionOnboardInfo[cacheKey]);
      signerCacheRef.current[cacheKey] = signer;
    }

    const onboardInfo = signer.getUserOnboardInfo();
    if (!onboardInfo?.aesKey) {
      throw new Error('AES key unavailable in this session. Use Connect + Sign AES.');
    }

    setSessionOnboardInfo((previous) => ({
      ...previous,
      [cacheKey]: mergeOnboardInfo(previous[cacheKey], onboardInfo)
    }));

    return { signer, cacheKey };
  };

  const syncConversationHistory = async () => {
    setError('');

    if (!walletAddress) {
      return;
    }

    if (syncingHistory) {
      return;
    }

    try {
      setSyncingHistory(true);
      const { signer, cacheKey } = await getMemoSigner();
      const cotiEthers = await loadCotiEthersModule();
      const contract = new cotiEthers.Contract(MEMO_CONTRACT_ADDRESS, MEMO_CONTRACT_ABI, signer);

      const incomingFilter = contract.filters.MemoSubmitted(walletAddress, null);
      const outgoingFilter = contract.filters.MemoSubmitted(null, walletAddress);

      const [incomingLogs, outgoingLogs] = await Promise.all([
        contract.queryFilter(incomingFilter, 0, 'latest'),
        contract.queryFilter(outgoingFilter, 0, 'latest')
      ]);

      const discoveredContacts = new Set<string>();
      const entries: HistoryEntry[] = [];

      for (const log of incomingLogs) {
        const args = (log as { args?: Record<string, unknown> }).args;
        const from = String(args?.from ?? '');
        if (!isWalletAddress(from)) {
          continue;
        }

        discoveredContacts.add(from);

        const userCiphertext = extractUserCiphertext(args?.memoForRecipient);
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
          logIndex: log.index
        });
      }

      for (const log of outgoingLogs) {
        const args = (log as { args?: Record<string, unknown> }).args;
        const recipient = String(args?.recipient ?? '');
        if (!isWalletAddress(recipient)) {
          continue;
        }

        discoveredContacts.add(recipient);

        const userCiphertext = extractUserCiphertext(args?.memoForSender);
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
          logIndex: log.index
        });
      }

      entries.sort((a, b) => {
        if (a.blockNumber !== b.blockNumber) {
          return a.blockNumber - b.blockNumber;
        }
        return a.logIndex - b.logIndex;
      });

      const grouped: Record<string, ChatMessage[]> = {};
      for (const entry of entries) {
        const key = entry.contact.toLowerCase();
        if (!grouped[key]) {
          grouped[key] = [];
        }
        grouped[key].push({
          id: entry.id,
          direction: entry.direction,
          text: entry.text
        });
      }

      setMessagesByContact(grouped);
      setContacts((previous) => mergeUniqueContacts(previous, Array.from(discoveredContacts)));

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
      setSyncingHistory(false);
    }
  };

  const sendMessage = async () => {
    setError('');

    if (sending) {
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
      setSending(true);

      const { signer, cacheKey } = await getMemoSigner();
      const cotiEthers = await loadCotiEthersModule();
      const memoContractInterface = new cotiEthers.Interface(MEMO_CONTRACT_ABI);
      const selector = memoContractInterface.getFunction('submit')?.selector;
      if (!selector) {
        throw new Error('Unable to resolve submit selector.');
      }

      const encodedMemo = encodeMemoPlaintext(plainText);
      const encryptedMemo = await signer.encryptValue(encodedMemo, MEMO_CONTRACT_ADDRESS, selector);
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

      const contract = new cotiEthers.Contract(MEMO_CONTRACT_ADDRESS, MEMO_CONTRACT_ABI, signer);
      const memoTuple = [[encryptedMemo.ciphertext.value], encryptedMemo.signature] as const;
      const tx = await contract.submit(activeContact, memoTuple, { value: 0n });
      await tx.wait();

      const nextOnboardInfo = signer.getUserOnboardInfo();
      setSessionOnboardInfo((previous) => ({
        ...previous,
        [cacheKey]: mergeOnboardInfo(previous[cacheKey], nextOnboardInfo)
      }));

      setMessagesByContact((previous) => {
        const key = activeContact.toLowerCase();
        const current = previous[key] ?? [];
        return {
          ...previous,
          [key]: [
            ...current,
            {
              id: `${Date.now()}-out`,
              direction: 'outgoing',
              text: plainText
            }
          ]
        };
      });

      setMessageInput('');
    } catch (sendError) {
      const message = sendError instanceof Error ? sendError.message : 'Failed to send message.';
      setError(message);
    } finally {
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
    if (!walletAddress) {
      setMessagesByContact({});
    }
  }, [walletAddress]);

  useEffect(() => {
    refreshWalletState().catch(() => {
      setError('Unable to read wallet state.');
    });

    if (!window.ethereum?.on || !window.ethereum?.removeListener) {
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

    window.ethereum.on('accountsChanged', handleAccountsChanged);
    window.ethereum.on('chainChanged', handleChainChanged);

    return () => {
      window.ethereum?.removeListener?.('accountsChanged', handleAccountsChanged);
      window.ethereum?.removeListener?.('chainChanged', handleChainChanged);
    };
  }, []);

  return (
    <div className="app-root">
      <aside className="sidebar">
        <h1 className="title">COTI Chat</h1>

        <button className="connect-btn" onClick={connectAndOnboard} type="button">
          {!isConnected ? 'Connect + Sign AES' : onboardStatus === 'AES key ready' ? 'Wallet + AES Ready' : 'Sign AES Key'}
        </button>

        <button className="connect-btn" onClick={disconnectWallet} type="button" disabled={!isConnected}>
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
          {contacts.map((contact) => {
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

            <div className="chat-messages">
              {activeMessages.length === 0 ? (
                <p className="chat-empty">No messages yet.</p>
              ) : (
                activeMessages.map((message) => (
                  <div
                    key={message.id}
                    className={message.direction === 'outgoing' ? 'message-row outgoing' : 'message-row incoming'}
                  >
                    <div className="message-bubble">{message.text}</div>
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
