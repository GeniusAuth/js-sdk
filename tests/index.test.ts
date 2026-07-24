import { describe, expect, it } from 'vitest';
import GeniusAuth, { GeniusAuth as NamedGeniusAuth } from '../src/index.js';

describe('GeniusAuth', () => {
    it('exports the default and named SDK class', () => {
        expect(GeniusAuth).toBe(NamedGeniusAuth);
    });
});
