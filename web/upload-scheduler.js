/**
 * 上传并发准入器。它不执行 HTTP，只拥有作业的状态转移与并发计数；
 * `file-operations.js` 提供真正的启动函数。这个分层使 XHR 的 load/error/abort
 * 重复终止事件只能释放一次槽位。
 *
 * Upload concurrency admission. This module owns job transitions and counters,
 * not HTTP; `file-operations.js` supplies the actual starter. The separation
 * makes repeated XHR load/error/abort terminal events release a slot once.
 */

/** @typedef {"new"|"queued"|"running"|"complete"|"failed"|"cancelled"} UploadState */

/**
 * @typedef {object} UploadJob
 * @property {UploadState} state
 * @property {(reason: string) => void} [fail]
 */

/**
 * 有界上传的小型显式状态机。调度器拥有所有 queued/running 转换，使同步启动失败、
 * 取消和重复终止事件都不能泄漏并发槽。
 *
 * A small explicit state machine for bounded uploads. The scheduler owns every
 * queued/running transition so synchronous starter failures, cancellation and
 * repeated terminal events cannot leak a concurrency slot.
 *
 * @template {UploadJob} T
 */
export class UploadScheduler {
  #active = 0;
  /** @type {T[]} */
  #queue = [];
  #scheduled = false;

  /**
   * @param {number} maxConcurrency
   * @param {(job: T) => void | Promise<void>} start
   */
  constructor(maxConcurrency, start) {
    if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
      throw new TypeError("maxConcurrency must be a positive integer");
    }
    this.maxConcurrency = maxConcurrency;
    this.start = start;
  }

  get active() {
    return this.#active;
  }

  get pending() {
    return this.#queue.length;
  }

  /** @param {T} job */
  enqueue(job) {
    if (["queued", "running", "complete"].includes(job.state)) return false;
    job.state = "queued";
    this.#queue.push(job);
    this.#scheduleDrain();
    return true;
  }

  /**
   * @param {T} job
   * @param {"complete"|"failed"} finalState
   */
  settle(job, finalState) {
    if (job.state !== "running") return false;
    if (finalState !== "complete" && finalState !== "failed") {
      throw new TypeError("an upload may settle only as complete or failed");
    }
    job.state = finalState;
    this.#active = Math.max(0, this.#active - 1);
    this.#scheduleDrain();
    return true;
  }

  /**
   * 取消排队或运行任务；所有者仍负责中止底层请求。调度器已释放槽位，因此后续
   * abort/load 事件被刻意忽略。
   *
   * Cancel a queued or running job. The owner remains responsible for aborting
   * the request; later abort/load events are ignored because the slot is released.
   *
   * @param {T} job
   */
  cancel(job) {
    if (job.state === "queued") {
      const index = this.#queue.indexOf(job);
      if (index >= 0) this.#queue.splice(index, 1);
      job.state = "cancelled";
      return true;
    }
    if (job.state === "running") {
      job.state = "cancelled";
      this.#active = Math.max(0, this.#active - 1);
      this.#scheduleDrain();
      return true;
    }
    return false;
  }

  #scheduleDrain() {
    if (this.#scheduled) return;
    this.#scheduled = true;
    queueMicrotask(() => {
      this.#scheduled = false;
      this.#drain();
    });
  }

  #drain() {
    while (this.#active < this.maxConcurrency && this.#queue.length > 0) {
      const job = this.#queue.shift();
      if (!job || job.state !== "queued") continue;
      job.state = "running";
      this.#active += 1;
      /** @type {void | Promise<void>} */
      let started;
      try {
        started = this.start(job);
      } catch (error) {
        this.#handleStartFailure(job, error);
        continue;
      }
      Promise.resolve(started).catch(error => {
        this.#handleStartFailure(job, error);
      });
    }
  }

  /**
   * @param {T} job
   * @param {unknown} error
   */
  #handleStartFailure(job, error) {
    // 中文：启动 Promise 可以在用户取消任务后才拒绝。此时 cancelled 是
    // 权威终态，迟到的失败不得再调用 UI fail 回调把它改写为 failed。
    // 另外，fail 回调本身也是不可信的通知边界；即使它抛异常，finally
    // 仍必须释放并发槽，否则后续上传会永久饥饿。
    // English: a starter promise may reject after the user has cancelled the
    // job. Cancelled is then authoritative, and a late failure must not invoke
    // UI failure code or rewrite that terminal state. The optional fail callback
    // is also an untrusted notification boundary: even if it throws, `finally`
    // must release the slot or every later upload can starve forever.
    if (job.state !== "running") return;
    try {
      if (typeof job.fail === "function") {
        job.fail(error instanceof Error ? error.message : String(error));
      }
    } catch {
      // 调度器下方的 finally 负责保持计数器不变式。 / The finally below preserves scheduler counters.
    } finally {
      if (job.state === "running") this.settle(job, "failed");
    }
  }
}
