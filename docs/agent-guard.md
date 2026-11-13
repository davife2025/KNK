# Agent Guard: cutting off agents when KNK raises an incident

## How NEAR Intents Agent API ownership works (and why KNK is built around it)

From the Agent API SDK documentation: your backend holds a partner API key (`naa_...`) and grant tokens (`ngt_...`).
The **owner's wallet signs** account-level changes, **including freezing the agent**. A backend key can only
*prepare* an owner action (`generateIntent`), and the owner signs it. The Agent API itself is mainnet with real funds
and is described as experimental.

So KNK **cannot and should not freeze an agent by itself**, and it never holds your API key or grant tokens.
Instead KNK sends your backend a signed `containment.requested` webhook, and your backend, which already holds
those secrets, does two things:

1. **Revoke grants (instant, no signature needed).** Stop using and delete or disable every stored `ngt_` token for
   the agent. Without its grant token the agent cannot act. This is partner-side, so it takes effect at once.
2. **Prepare the freeze for the owner to sign.** Create the freeze intent and notify the owner. Until the owner signs
   it, step 1 is what protects the funds.

## Wiring it up

```ts
import { createServer } from 'node:http';
import { createGuardHandler } from '@knk/guard';

const handle = createGuardHandler({
  secret: process.env.KNK_WEBHOOK_SECRET!, // the whsec_... shown once when you created the webhook
  adapter: {
    async revokeGrantTokens(agentId) {
      await db.grantTokens.disableAll(agentId); // your storage: delete or disable the ngt_ tokens
    },
    async prepareFreeze(agentId) {
      // Reference only, NOT verified against the live API. The SDK README lists `agent_freeze` among the owner
      // actions that use generateIntent -> owner signs -> submitIntent, but does not show its request fields.
      // Confirm the exact shape in https://api.agentsonintents.com/openapi.json before relying on this.
      const intent = await agentApi.generateIntent({ type: 'agent_freeze', agent_id: agentId });
      await notifyOwner(agentId, intent); // the owner signs intent.intent with their wallet; then submitIntent
      return { correlationId: intent.correlation_id };
    },
  },
});

createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk; // the RAW body: verify before parsing
  const out = await handle({ headers: req.headers, body });
  res.statusCode = out.status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(out.body));
}).listen(8080);
```

The handler verifies the signature (and a 5-minute replay window), runs each incident once even if KNK retries,
tries every agent and both actions even if one fails, and answers 500 on a partial failure so KNK retries.
The SDK documents Node 24+. The guard itself needs only Node 22.

## What is and is not verified

- Verified by tests: signing, verification, replay window, retries, idempotency, partial failure, and the full path
  from a developer going critical to the adapter being called, over a real HTTP socket.
- Not verified: anything against the live Agent API. The adapter in the tests is a stand-in. Do not point this at
  funds you cannot afford to lose until you have run your adapter against a dedicated test account.
