import { removeE2eData } from "./fixtures.js";

export default async function globalTeardown() {
  await removeE2eData();
}
