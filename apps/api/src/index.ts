import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { getEnv } from './env.js';

const { PORT } = getEnv();
serve({ fetch: createApp().fetch, port: PORT }, (info) => {
  console.log(`knk-api listening on http://localhost:${info.port}`);
});
