// The shell's events: the names this app listens for are the names the shell emits.
import { describe, expect, it } from "vitest";

import { SHELL_EVENTS } from "../../src/lib/bridge";
import { SHELL_LOCKED_EVENT, SHELL_WINDOW_INACTIVE_EVENT } from "../../src/vault/shell-events";

describe("the shell's event names", () => {
  it("are the ones the bridge client declares (unconditionally: a rename on either side fails here)", () => {
    expect(SHELL_EVENTS.locked).toBe(SHELL_LOCKED_EVENT);
    expect(SHELL_EVENTS.windowInactive).toBe(SHELL_WINDOW_INACTIVE_EVENT);
    expect(SHELL_LOCKED_EVENT).toBe("credmgr://locked");
    expect(SHELL_WINDOW_INACTIVE_EVENT).toBe("credmgr://window-inactive");
  });
});
