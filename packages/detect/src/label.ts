import type { VerdictLabel } from '@knk/shared';

/** Risk score to label. Shared so the API and the CLI always agree. */
export const labelFor = (score: number): VerdictLabel => (score >= 80 ? 'malicious' : score >= 30 ? 'suspicious' : 'benign');
