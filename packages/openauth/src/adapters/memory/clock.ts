/**
 * Tiny injectable clock used by every memory adapter so tests can advance
 * time deterministically.
 */
export type Clock = () => number

export const realClock: Clock = () => Date.now()
