/**
 * What an action resolves with when it WRITES and then re-reads (src/vault/actions/write.ts, read.ts and admin.ts).
 *
 * The broker did the work; the re-read that follows it can still fail.  That must not look like "the write failed" (a retry would
 * meet `entry_exists` or `not_found`, and "Nothing was changed" would be false), so a failed re-read is not thrown: the action
 * resolves with the broker's answer and `readbackError`, and the logic says what was saved and that the screen is out of date
 * (`savedButNotRefreshed` in logic/write.js).  tests/unit/architecture.test.ts fails a logic caller that never looks.
 */
import type { VaultModel } from "../model";
import type { RefreshSpec } from "../types";

/** The broker's answer, plus `readbackError` when only the re-read failed.  Absent means both worked. */
export type Written<T> = T & { readbackError?: unknown };

/** Re-read what the write touched.  A failure is reported on the answer, never thrown: the write already happened. */
export async function thenReread<T extends object>(m: VaultModel, answer: T, spec: RefreshSpec): Promise<Written<T>> {
  try {
    await m.refresh(spec);
  } catch (readbackError) {
    return { ...answer, readbackError };
  }
  return answer;
}
