import { expect, test } from "vitest";
import { UploadScheduler } from "../../web/upload-scheduler.js";

const tick = () => Promise.resolve();

test("retry re-enters the bounded queue and counters cannot go negative", async () => {
  const started = [];
  const scheduler = new UploadScheduler(1, job => started.push(job.name));
  const first = { name: "first", state: "new" };
  const second = { name: "second", state: "new" };

  expect(scheduler.enqueue(first)).toBe(true);
  expect(scheduler.enqueue(second)).toBe(true);
  await tick();
  expect(started).toEqual(["first"]);
  expect(scheduler.active).toBe(1);
  expect(scheduler.pending).toBe(1);

  expect(scheduler.settle(first, "failed")).toBe(true);
  expect(scheduler.settle(first, "failed")).toBe(false);
  await tick();
  expect(started).toEqual(["first", "second"]);
  expect(scheduler.active).toBe(1);

  expect(scheduler.enqueue(first)).toBe(true);
  expect(scheduler.settle(second, "complete")).toBe(true);
  await tick();
  expect(started).toEqual(["first", "second", "first"]);
  expect(scheduler.settle(first, "complete")).toBe(true);
  await tick();
  expect(scheduler.active).toBe(0);
  expect(scheduler.pending).toBe(0);
});

test("synchronous starter exceptions release the slot and start the next job", async () => {
  const failures = [];
  const started = [];
  const first = { name: "first", state: "new", fail: reason => failures.push(reason) };
  const second = { name: "second", state: "new" };
  const scheduler = new UploadScheduler(1, job => {
    started.push(job.name);
    if (job === first) throw new Error("synchronous failure");
  });
  scheduler.enqueue(first);
  scheduler.enqueue(second);
  await tick();
  await tick();
  expect(failures).toEqual(["synchronous failure"]);
  expect(first.state).toBe("failed");
  expect(started).toEqual(["first", "second"]);
  expect(scheduler.active).toBe(1);
  expect(scheduler.settle(second, "complete")).toBe(true);
  await tick();
  expect(scheduler.active).toBe(0);
});

test("queued and running cancellation cannot leak or double-release a slot", async () => {
  const started = [];
  const scheduler = new UploadScheduler(1, job => started.push(job.name));
  const first = { name: "first", state: "new" };
  const second = { name: "second", state: "new" };
  scheduler.enqueue(first);
  scheduler.enqueue(second);
  await tick();
  expect(scheduler.cancel(second)).toBe(true);
  expect(second.state).toBe("cancelled");
  expect(scheduler.pending).toBe(0);
  expect(scheduler.cancel(first)).toBe(true);
  expect(scheduler.cancel(first)).toBe(false);
  await tick();
  expect(scheduler.active).toBe(0);
  expect(started).toEqual(["first"]);
});

test("late starter rejection cannot overwrite cancellation or invoke failure UI", async () => {
  let rejectStart;
  const failures = [];
  const first = { name: "first", state: "new", fail: reason => failures.push(reason) };
  const second = { name: "second", state: "new" };
  const started = [];
  const scheduler = new UploadScheduler(1, job => {
    started.push(job.name);
    if (job === first) return new Promise((_, reject) => { rejectStart = reject; });
    return undefined;
  });
  scheduler.enqueue(first);
  scheduler.enqueue(second);
  await tick();
  expect(scheduler.cancel(first)).toBe(true);
  rejectStart?.(new Error("late transport failure"));
  await tick();
  await tick();
  expect(first.state).toBe("cancelled");
  expect(failures).toEqual([]);
  expect(started).toEqual(["first", "second"]);
  expect(scheduler.active).toBe(1);
  expect(scheduler.settle(second, "complete")).toBe(true);
});

test("a throwing failure renderer still releases the scheduler slot", async () => {
  const first = {
    name: "first",
    state: "new",
    fail: () => { throw new Error("detached DOM"); },
  };
  const second = { name: "second", state: "new" };
  const started = [];
  const scheduler = new UploadScheduler(1, job => {
    started.push(job.name);
    if (job === first) throw new Error("startup failed");
  });
  scheduler.enqueue(first);
  scheduler.enqueue(second);
  await tick();
  await tick();
  expect(first.state).toBe("failed");
  expect(started).toEqual(["first", "second"]);
  expect(scheduler.active).toBe(1);
  expect(scheduler.settle(second, "complete")).toBe(true);
});
