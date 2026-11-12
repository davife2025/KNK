import { createHash } from 'node:crypto';
import { canonicalJson, type DecodedTx, type GateTx } from '@knk/shared';
import { parseTransaction, toFunctionSelector, type Hex } from 'viem';

const SEL = {
  approve: toFunctionSelector('approve(address,uint256)'),
  increaseAllowance: toFunctionSelector('increaseAllowance(address,uint256)'),
  transfer: toFunctionSelector('transfer(address,uint256)'),
  transferFrom: toFunctionSelector('transferFrom(address,address,uint256)'),
  setApprovalForAll: toFunctionSelector('setApprovalForAll(address,bool)'),
};
const UNLIMITED = 2n ** 255n; // anything this large is treated as "unlimited"

// calldata layout: 0x + 4-byte selector (8 hex) + 32-byte words (64 hex each)
const word = (data: string, i: number): string | null => {
  const w = data.slice(10 + i * 64, 10 + (i + 1) * 64);
  return w.length === 64 ? w : null;
};
const addr = (w: string) => `0x${w.slice(24)}`.toLowerCase();

export type DecodeResult = { ok: true; tx: DecodedTx } | { ok: false; reason: string };

/** Fail closed: anything we cannot parse is reported as an error, never guessed at. */
export function decodeTx(tx: GateTx): DecodeResult {
  if (tx.format === 'transfer') {
    return { ok: true, tx: { format: 'transfer', kind: 'transfer', to: tx.to.toLowerCase(), amount: tx.amount, asset: tx.asset.toLowerCase() } };
  }
  if (tx.format === 'evm_authorization') {
    return {
      ok: true,
      tx: {
        format: 'evm_authorization',
        kind: 'delegation',
        chainId: tx.chainId,
        delegates: [{ chainId: tx.chainId, address: tx.delegate.toLowerCase(), nonce: tx.nonce }],
      },
    };
  }

  let parsed;
  try {
    parsed = parseTransaction(tx.raw as Hex);
  } catch {
    return { ok: false, reason: 'The transaction could not be decoded' };
  }

  const base = { format: 'evm_raw' as const, chainId: parsed.chainId };
  const nativeValue = (parsed.value ?? 0n).toString();
  const to = parsed.to?.toLowerCase();
  const data = ((parsed as { data?: string }).data ?? '0x').toLowerCase();

  const auths = 'authorizationList' in parsed ? (parsed.authorizationList ?? []) : [];
  if (auths.length > 0) {
    return {
      ok: true,
      tx: {
        ...base,
        kind: 'delegation',
        to,
        nativeValue,
        delegates: auths.map((a) => ({ chainId: Number(a.chainId), address: a.address.toLowerCase(), nonce: Number(a.nonce) })),
      },
    };
  }
  if (!to) return { ok: true, tx: { ...base, kind: 'contract_creation', nativeValue } };
  if (data === '0x') return { ok: true, tx: { ...base, kind: 'native_transfer', to, nativeValue } };

  const selector = data.slice(0, 10);
  const w0 = word(data, 0);
  const w1 = word(data, 1);
  const w2 = word(data, 2);

  if ((selector === SEL.approve || selector === SEL.increaseAllowance) && w0 && w1) {
    const amount = BigInt(`0x${w1}`);
    return { ok: true, tx: { ...base, kind: 'token_approval', to, asset: to, recipient: addr(w0), amount: amount.toString(), unlimited: amount >= UNLIMITED, selector, nativeValue } };
  }
  if (selector === SEL.setApprovalForAll && w0 && w1) {
    return { ok: true, tx: { ...base, kind: 'approval_for_all', to, asset: to, recipient: addr(w0), unlimited: BigInt(`0x${w1}`) !== 0n, selector, nativeValue } };
  }
  if (selector === SEL.transfer && w0 && w1) {
    return { ok: true, tx: { ...base, kind: 'token_transfer', to, asset: to, recipient: addr(w0), amount: BigInt(`0x${w1}`).toString(), selector, nativeValue } };
  }
  if (selector === SEL.transferFrom && w1 && w2) {
    return { ok: true, tx: { ...base, kind: 'token_transfer', to, asset: to, recipient: addr(w1), amount: BigInt(`0x${w2}`).toString(), selector, nativeValue } };
  }
  return { ok: true, tx: { ...base, kind: 'contract_call', to, selector, nativeValue } };
}

/** Hash of the exact thing being signed. Case-insensitive on addresses and hex so formatting cannot change it. */
export function fingerprintTx(tx: GateTx): string {
  const norm =
    tx.format === 'evm_raw'
      ? { format: tx.format, raw: tx.raw.toLowerCase() }
      : tx.format === 'evm_authorization'
        ? { ...tx, delegate: tx.delegate.toLowerCase() }
        : { ...tx, to: tx.to.toLowerCase(), asset: tx.asset.toLowerCase() };
  return createHash('sha256').update(canonicalJson(norm)).digest('hex');
}
