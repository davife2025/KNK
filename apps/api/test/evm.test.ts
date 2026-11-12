import { describe, expect, it } from 'vitest';
import { encodeFunctionData, erc20Abi, maxUint256, parseAbi, serializeTransaction } from 'viem';
import { decodeTx, fingerprintTx } from '../src/lib/evm.js';

const A = '0x1111111111111111111111111111111111111111';
const DELEGATE = '0x2222222222222222222222222222222222222222';
const SPENDER = '0x3333333333333333333333333333333333333333';
const TOKEN = '0x4444444444444444444444444444444444444444';
const base = { chainId: 1, nonce: 5, gas: 21000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n } as const;
const raw = (o: Record<string, unknown>) => serializeTransaction({ type: 'eip1559', ...base, ...o } as never);
const decode = (r: string) => {
  const d = decodeTx({ format: 'evm_raw', raw: r });
  if (!d.ok) throw new Error(d.reason);
  return d.tx;
};

describe('decodeTx (EVM)', () => {
  it('native transfer', () => {
    expect(decode(raw({ to: A, value: 1000n }))).toMatchObject({ kind: 'native_transfer', to: A, nativeValue: '1000', chainId: 1 });
  });

  it('ERC-20 transfer: the recipient is the beneficiary, not the token contract', () => {
    const data = encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [SPENDER, 123n] });
    expect(decode(raw({ to: TOKEN, data }))).toMatchObject({ kind: 'token_transfer', to: TOKEN, recipient: SPENDER, amount: '123', asset: TOKEN });
    const from = encodeFunctionData({ abi: erc20Abi, functionName: 'transferFrom', args: [A, SPENDER, 9n] });
    expect(decode(raw({ to: TOKEN, data: from }))).toMatchObject({ kind: 'token_transfer', recipient: SPENDER, amount: '9' });
  });

  it('approvals: unlimited is flagged, a limited amount and a revoke are not', () => {
    const approve = (amount: bigint) => decode(raw({ to: TOKEN, data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [SPENDER, amount] }) }));
    expect(approve(maxUint256)).toMatchObject({ kind: 'token_approval', recipient: SPENDER, unlimited: true });
    expect(approve(1000n)).toMatchObject({ kind: 'token_approval', unlimited: false, amount: '1000' });
    expect(approve(0n).unlimited).toBe(false);
  });

  it('setApprovalForAll: granting is flagged, revoking is not', () => {
    const abi = parseAbi(['function setApprovalForAll(address operator, bool approved)']);
    const call = (approved: boolean) => decode(raw({ to: TOKEN, data: encodeFunctionData({ abi, functionName: 'setApprovalForAll', args: [SPENDER, approved] }) }));
    expect(call(true)).toMatchObject({ kind: 'approval_for_all', recipient: SPENDER, unlimited: true });
    expect(call(false).unlimited).toBe(false);
  });

  it('unknown selector is a contract call; no recipient is a contract creation', () => {
    expect(decode(raw({ to: A, data: '0xdeadbeef' + '00'.repeat(32) }))).toMatchObject({ kind: 'contract_call', selector: '0xdeadbeef' });
    expect(decode(raw({ data: '0x6000' }))).toMatchObject({ kind: 'contract_creation' });
  });

  it('an approve with truncated calldata is not mistaken for a safe approval', () => {
    expect(decode(raw({ to: TOKEN, data: '0x095ea7b3' })).kind).toBe('contract_call');
  });

  it('EIP-7702 transaction exposes its delegates', () => {
    const r = serializeTransaction({
      type: 'eip7702',
      ...base,
      to: A,
      value: 0n,
      authorizationList: [{ chainId: 1, address: DELEGATE, nonce: 0, r: `0x${'11'.repeat(32)}`, s: `0x${'22'.repeat(32)}`, yParity: 0 }],
    } as never);
    expect(decode(r)).toMatchObject({ kind: 'delegation', delegates: [{ chainId: 1, address: DELEGATE, nonce: 0 }] });
  });

  it('authorization and structured transfer formats', () => {
    expect(decodeTx({ format: 'evm_authorization', chainId: 0, delegate: DELEGATE.toUpperCase().replace('0X', '0x'), nonce: 3 })).toMatchObject({
      ok: true,
      tx: { kind: 'delegation', delegates: [{ chainId: 0, address: DELEGATE, nonce: 3 }] },
    });
    expect(decodeTx({ format: 'transfer', to: 'Alice.NEAR', amount: '5', asset: 'NEAR' })).toMatchObject({ ok: true, tx: { kind: 'transfer', to: 'alice.near', asset: 'near' } });
  });

  it('fails closed on garbage', () => {
    expect(decodeTx({ format: 'evm_raw', raw: '0xdeadbeef' })).toMatchObject({ ok: false });
    expect(decodeTx({ format: 'evm_raw', raw: '0x' })).toMatchObject({ ok: false });
  });
});

describe('fingerprintTx', () => {
  it('ignores hex and address case but changes with any real difference', () => {
    const r = raw({ to: A, value: 1000n });
    const upper = '0x' + r.slice(2).toUpperCase();
    expect(fingerprintTx({ format: 'evm_raw', raw: r })).toBe(fingerprintTx({ format: 'evm_raw', raw: upper }));
    expect(fingerprintTx({ format: 'evm_raw', raw: r })).not.toBe(fingerprintTx({ format: 'evm_raw', raw: raw({ to: A, value: 1001n }) }));
    const a = fingerprintTx({ format: 'evm_authorization', chainId: 1, delegate: DELEGATE, nonce: 0 });
    expect(a).toBe(fingerprintTx({ format: 'evm_authorization', chainId: 1, delegate: DELEGATE.replace(/[a-f]/g, (c) => c.toUpperCase()) as never, nonce: 0 }));
    expect(a).not.toBe(fingerprintTx({ format: 'evm_authorization', chainId: 1, delegate: DELEGATE, nonce: 1 }));
  });
});
