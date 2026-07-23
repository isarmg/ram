import { createServer } from "node:net";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { resolve } from "node:path";

export const LOOPBACK_HOST = "127.0.0.1";

/**
 * 请求内核分配未使用的 loopback TCP 端口，再释放给 E2E 服务；这样消除 Playwright
 * 的固定跨进程冲突，同时让配置 fixture 共用同一已选 origin。
 *
 * Ask the kernel for an unused loopback TCP port and release it for the E2E
 * server, avoiding fixed cross-process collisions while sharing one origin.
 */
export function allocateLoopbackPort() {
  return new Promise((resolve, reject) => {
    const reservation = createServer();
    reservation.unref();
    reservation.once("error", reject);
    reservation.listen({ host: LOOPBACK_HOST, port: 0, exclusive: true }, () => {
      const address = reservation.address();
      if (address === null || typeof address === "string") {
        reservation.close();
        reject(new Error("the E2E port reservation did not return a TCP address"));
        return;
      }

      reservation.close(error => {
        if (error) {
          reject(error);
        } else {
          resolve(address.port);
        }
      });
    });
  });
}

const DATA_ENV = "RAM_E2E_DATA_DIR";

/**
 * 服务启动前复制不可变的已检入种子树；所有浏览器写入限制在 target/，不会弄脏跟踪 fixture。
 * Copy the immutable checked-in seed tree before startup; all browser writes stay in target/.
 */
export async function prepareE2eData() {
  const inherited = process.env[DATA_ENV];
  const target = resolve("target");
  if (inherited) {
    const resolved = resolve(inherited);
    if (!resolved.startsWith(`${target}/playwright-data-`)) {
      throw new Error(`Refusing inherited E2E data path outside target: ${resolved}`);
    }
    return resolved;
  }
  await mkdir(target, { recursive: true });
  const directory = await mkdtemp(resolve(target, "playwright-data-"));
  await cp(resolve("tests/e2e/data"), directory, { recursive: true, force: false });
  process.env[DATA_ENV] = directory;
  return directory;
}

/** 每次 Playwright 运行后删除复制的数据树。 / Remove the copied data tree after every Playwright invocation. */
export async function removeE2eData() {
  const directory = process.env[DATA_ENV];
  if (!directory) return;
  const target = resolve("target");
  const resolved = resolve(directory);
  if (!resolved.startsWith(`${target}/playwright-data-`)) {
    throw new Error(`Refusing to remove unexpected E2E path: ${resolved}`);
  }
  await rm(resolved, { recursive: true, force: true });
  delete process.env[DATA_ENV];
}
