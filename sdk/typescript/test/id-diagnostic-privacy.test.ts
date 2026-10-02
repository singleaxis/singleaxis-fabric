import { afterEach, describe, expect, it, vi } from "vitest";
import { checkIdentifier, warnIfPiiShaped } from "../src/id-validators.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});
describe("identifier diagnostic privacy", () => {
  it("reports only field and shape, deduplicating distinct private values", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfPiiShaped("privateTestId", "first@example.com");
    warnIfPiiShaped("privateTestId", "second@example.com");
    const output = warn.mock.calls.flat().join(" ");
    expect(output).toContain("privateTestId");
    expect(output).toContain("email");
    expect(output).not.toContain("first@example.com");
    expect(output).not.toContain("second@example.com");
    expect(warn).toHaveBeenCalledTimes(1);
  });
  it("does not emit embedded content or unsafe diagnostic field names", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfPiiShaped("secret field name", "person@example.com " + "PRIVATE".repeat(20000), {
      embedded: true,
    });
    const output = warn.mock.calls.flat().join(" ");
    expect(output).not.toContain("person@example.com");
    expect(output).not.toContain("PRIVATE");
    expect(output).not.toContain("secret field name");
    expect(output.length).toBeLessThan(1000);
  });
  it("keeps placeholder validation and quiet opt out without leaking input", () => {
    expect(() => checkIdentifier("tenantId", "${PRIVATE_VALUE}")).toThrow(/placeholder/);
    expect(() => checkIdentifier("tenantId", "${PRIVATE_VALUE}")).not.toThrow(/PRIVATE_VALUE/);
    vi.stubEnv("FABRIC_ALLOW_PLACEHOLDER_IDS", "1");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    checkIdentifier("diagnosticTenant", "${PRIVATE_VALUE}");
    expect(warn.mock.calls.flat().join(" ")).not.toContain("PRIVATE_VALUE");
    vi.stubEnv("FABRIC_QUIET_PII_WARN", "1");
    warn.mockClear();
    warnIfPiiShaped("quietField", "private@example.com");
    expect(warn).not.toHaveBeenCalled();
  });
});
