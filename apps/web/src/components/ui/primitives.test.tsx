import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EmptyState, ErrorState, LoadingState, SeverityBadge, StatusBadge } from "./primitives";

describe("SeverityBadge", () => {
  it("renders a known severity with its label", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("falls back to the informational style for an unknown severity without crashing", () => {
    render(<SeverityBadge severity="totally-unknown" />);
    expect(screen.getByText("totally-unknown")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("renders underscored statuses as spaced, human-readable text", () => {
    render(<StatusBadge status="false_positive" />);
    expect(screen.getByText("false positive")).toBeInTheDocument();
  });

  it("falls back to the neutral tone for an unmapped status without crashing", () => {
    render(<StatusBadge status="totally_unknown" />);
    expect(screen.getByText("totally unknown")).toBeInTheDocument();
  });
});

describe("state primitives", () => {
  it("LoadingState announces itself via an accessible status role", () => {
    render(<LoadingState label="Loading things…" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading things…");
  });

  it("ErrorState announces itself via an accessible alert role", () => {
    render(<ErrorState message="Something went wrong." />);
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong.");
  });

  it("EmptyState renders a title and optional description", () => {
    render(<EmptyState title="Nothing here" description="Add one to get started." />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
    expect(screen.getByText("Add one to get started.")).toBeInTheDocument();
  });
});
