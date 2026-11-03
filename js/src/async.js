/**
 * The few concurrency pieces the two roles need: a bounded queue for messages
 * waiting on the application, a condition for state changes, a mutex for frames
 * that must reach the socket together, and timeouts.
 */

export class TimeoutError extends Error {
  constructor() {
    super("the operation timed out");
    this.name = "TimeoutError";
  }
}

export function sleep(milliseconds, signal) {
  if (signal !== undefined && signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      if (signal !== undefined) signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, milliseconds);
    if (signal !== undefined) signal.addEventListener("abort", done, { once: true });
  });
}

/** Reject after `milliseconds`, whatever the promise does. */
export async function withTimeout(promise, milliseconds) {
  // The loser of the race keeps running; a late failure must not surface.
  promise.catch(() => {});
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new TimeoutError()), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Runs one callback at a time, in the order they were asked for. */
export class Mutex {
  #last = Promise.resolve();

  async run(action) {
    const previous = this.#last;
    let release;
    this.#last = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await action();
    } finally {
      release();
    }
  }
}

export class Condition {
  #waiters = new Set();

  /** Wait until `predicate` holds; every state change calls notifyAll. */
  async waitFor(predicate) {
    while (!predicate()) {
      await new Promise((resolve) => {
        const check = () => {
          this.#waiters.delete(check);
          resolve();
        };
        this.#waiters.add(check);
      });
    }
  }

  notifyAll() {
    for (const resolve of [...this.#waiters]) resolve();
  }
}

/**
 * A queue with an optional bound. A full queue makes its producer wait, which
 * pushes back on the relay instead of growing without limit.
 */
export class Queue {
  #items = [];
  #waiters = new Set();
  #limit;
  #closed = false;

  constructor(limit = Infinity) {
    this.#limit = limit;
  }

  get size() {
    return this.#items.length;
  }

  async push(item) {
    while (this.#items.length >= this.#limit && !this.#closed) await this.#wait();
    if (this.#closed) return;
    this.#items.push(item);
    this.#notify();
  }

  /** Push without waiting; returns false when the queue is full. */
  tryPush(item) {
    if (this.#closed || this.#items.length >= this.#limit) return false;
    this.#items.push(item);
    this.#notify();
    return true;
  }

  /** No more items after the ones already queued. */
  close() {
    this.#closed = true;
    this.#notify();
  }

  async next(timeout = Infinity) {
    const deadline = timeout === Infinity ? Infinity : Date.now() + timeout;
    while (this.#items.length === 0) {
      if (this.#closed) return { done: true, value: undefined };
      if (Date.now() >= deadline) return undefined;
      const left = deadline - Date.now();
      await new Promise((resolve) => {
        let timer;
        const wake = () => {
          this.#waiters.delete(wake);
          clearTimeout(timer);
          resolve();
        };
        this.#waiters.add(wake);
        if (left !== Infinity) timer = setTimeout(wake, left);
      });
    }
    const value = this.#items.shift();
    this.#notify();
    return { done: false, value };
  }

  #wait() {
    return new Promise((resolve) => {
      this.#waiters.add(resolve);
    });
  }

  #notify() {
    for (const resolve of [...this.#waiters]) resolve();
    this.#waiters.clear();
  }

  [Symbol.asyncIterator]() {
    return this;
  }
}
