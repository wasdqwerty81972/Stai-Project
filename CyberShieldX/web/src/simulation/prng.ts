export interface PRNG {
  next(): number;
  nextInt(max: number): number;
}

export class SeededPRNG implements PRNG {
  private state: number;

  constructor(seed: number) {
    let s = seed >>> 0;
    if (s === 0) s = 0x6d2b79f5;
    s = (s ^ (s >>> 16)) * 0x7feb352d;
    s = (s ^ (s >>> 16)) * 0x846ca68b;
    this.state = s >>> 0;
  }

  next(): number {
    let t = (this.state ^= this.state << 13);
    t = (t ^ (t >>> 17)) >>> 0;
    t = Math.imul(t ^ (t << 5), 0x1b87359b);
    t = t ^ (t >>> 14);
    this.state = t >>> 0;
    return (this.state & 0xffffffff) / 0x100000000;
  }

  nextInt(max: number): number {
    if (max <= 0) return 0;
    return Math.floor(this.next() * max);
  }

  static sequence(seed: number, count: number): number[] {
    const rng = new SeededPRNG(seed);
    const out: number[] = [];
    for (let i = 0; i < count; i++) out.push(rng.next());
    return out;
  }
}
