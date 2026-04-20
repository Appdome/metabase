import { renderWithProviders, screen } from "__support__/ui";

import { AzureButton, buildSsoUrl } from "./AzureButton";

describe("buildSsoUrl", () => {
  it("returns the bare initiate endpoint when no redirect is given", () => {
    expect(buildSsoUrl()).toBe("/auth/sso/azure");
    expect(buildSsoUrl(undefined)).toBe("/auth/sso/azure");
  });

  it("appends the redirect as a URL-encoded query parameter", () => {
    expect(buildSsoUrl("/dashboard/42")).toBe(
      "/auth/sso/azure?redirect=%2Fdashboard%2F42",
    );
    expect(buildSsoUrl("/path with space")).toBe(
      "/auth/sso/azure?redirect=%2Fpath%20with%20space",
    );
  });
});

describe("AzureButton", () => {
  it("renders 'Sign in with Microsoft' inside a link", () => {
    renderWithProviders(<AzureButton />);
    const label = screen.getByText(/sign in with microsoft/i);
    expect(label.closest("a")).not.toBeNull();
  });
});
