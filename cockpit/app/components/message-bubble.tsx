"use client";

import type { OHUIMessage } from "@openharness/core";

export function MessageBubble({ message }: { message: OHUIMessage }) {
  const isUser = message.role === "user";

  function pretty(value: unknown) {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  return (
    <div
      style={{
        display: "flex",
        justifyContent: isUser ? "flex-end" : "flex-start",
      }}
    >
      <div
        style={{
          maxWidth: "80%",
          padding: "0.6rem 0.9rem",
          borderRadius: 12,
          background: isUser ? "#333" : "#f2f2f2",
          color: isUser ? "#fff" : "#222",
          fontSize: "0.95rem",
          lineHeight: 1.5,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {message.parts.map((part, i) => {
          switch (part.type) {
            case "text":
              return <span key={i}>{part.text}</span>;

            case "reasoning":
              return (
                <details
                  key={i}
                  style={{
                    fontSize: "0.85rem",
                    color: "#666",
                    marginBottom: "0.4rem",
                  }}
                >
                  <summary style={{ cursor: "pointer" }}>Reasoning</summary>
                  <p style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>
                    {part.text}
                  </p>
                </details>
              );

            case "file": {
              const filePart = part as any;
              const isImage = filePart.mediaType?.startsWith("image/");
              if (isImage) {
                return (
                  <img
                    key={i}
                    src={filePart.url}
                    alt={filePart.filename ?? "image"}
                    style={{
                      maxWidth: "100%",
                      maxHeight: 300,
                      borderRadius: 8,
                      margin: "0.3rem 0",
                      display: "block",
                    }}
                  />
                );
              }
              return (
                <div
                  key={i}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.3rem",
                    padding: "0.25rem 0.6rem",
                    margin: "0.3rem 0",
                    borderRadius: 6,
                    background: isUser
                      ? "rgba(255,255,255,0.15)"
                      : "#e0e0e0",
                    fontSize: "0.85rem",
                  }}
                >
                  <span>{filePart.filename ?? "file"}</span>
                  <span style={{ color: "#888", fontSize: "0.75rem" }}>
                    {filePart.mediaType}
                  </span>
                </div>
              );
            }

            default: {
              // Handle tool parts (type: "tool-*" or "dynamic-tool")
              if (
                part.type.startsWith("tool-") ||
                part.type === "dynamic-tool"
              ) {
                const toolPart = part as any;
                const toolName =
                  part.type === "dynamic-tool"
                    ? (part as any).toolName ?? "tool"
                    : part.type.replace("tool-", "");

                // Render announce calls as styled narration, not tool blocks
                if (toolName === "announce") {
                  const text = toolPart.input?.message ?? toolPart.output ?? "";
                  if (!text) return null;
                  return (
                    <div
                      key={i}
                      style={{
                        fontSize: "0.85rem",
                        fontStyle: "italic",
                        color: "#666",
                        padding: "0.3rem 0",
                      }}
                    >
                      {text}
                    </div>
                  );
                }

                const state = toolPart.state as string | undefined;
                const input = toolPart.input;
                const output = toolPart.output;
                const errorText = toolPart.errorText;

                const summaryRight =
                  state === "output"
                    ? "done"
                    : state === "output-error"
                      ? "error"
                      : "running...";

                return (
                  <details
                    key={i}
                    style={{
                      fontSize: "0.8rem",
                      padding: "0.4rem 0.6rem",
                      margin: "0.3rem 0",
                      background: isUser
                        ? "rgba(255,255,255,0.1)"
                        : "#e8e8e8",
                      borderRadius: 6,
                      fontFamily: "monospace",
                    }}
                  >
                    <summary style={{ cursor: "pointer" }}>
                      <strong>{toolName}</strong>
                      <span style={{ color: "#888" }}>
                        {" "}({summaryRight})
                      </span>
                    </summary>

                    <div
                      style={{
                        marginTop: "0.35rem",
                        display: "grid",
                        gap: "0.35rem",
                      }}
                    >
                      <div style={{ color: "#666" }}>
                        toolCallId: {toolPart.toolCallId}
                      </div>

                      {input !== undefined && (
                        <div>
                          <div style={{ color: "#666", marginBottom: 4 }}>
                            Input
                          </div>
                          <pre
                            style={{
                              margin: 0,
                              padding: "0.4rem 0.5rem",
                              borderRadius: 6,
                              background: isUser
                                ? "rgba(0,0,0,0.25)"
                                : "rgba(255,255,255,0.65)",
                              overflowX: "auto",
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-word",
                            }}
                          >
                            {pretty(input)}
                          </pre>
                        </div>
                      )}

                      {output !== undefined && (
                        <div>
                          <div style={{ color: "#666", marginBottom: 4 }}>
                            Output
                          </div>
                          <pre
                            style={{
                              margin: 0,
                              padding: "0.4rem 0.5rem",
                              borderRadius: 6,
                              background: isUser
                                ? "rgba(0,0,0,0.25)"
                                : "rgba(255,255,255,0.65)",
                              overflowX: "auto",
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-word",
                            }}
                          >
                            {pretty(output)}
                          </pre>
                        </div>
                      )}

                      {errorText && (
                        <div style={{ color: "#b00" }}>Error: {errorText}</div>
                      )}
                    </div>
                  </details>
                );
              }
              return null;
            }
          }
        })}
      </div>
    </div>
  );
}
