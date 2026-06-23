"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import {
  useOpenHarness,
  useSubagentStatus,
  useSessionStatus,
} from "@openharness/react";
import type { OHUIMessage } from "@openharness/core";
import type { FileUIPart } from "ai";
import { StatusBar } from "./status-bar";
import { MessageBubble } from "./message-bubble";

function readFileAsDataURL(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

export function ChatView() {
  const { messages, sendMessage, status, stop } = useOpenHarness({
    endpoint: "/api/chat",
  });
  const [input, setInput] = useState("");
  const [files, setFiles] = useState<FileUIPart[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textInputRef = useRef<HTMLInputElement>(null);
  const subagent = useSubagentStatus();
  const session = useSessionStatus();

  const isStreaming = status === "streaming" || status === "submitted";

  // Auto-scroll on new content
  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages]);

  const addFiles = useCallback(async (fileList: File[]) => {
    const newParts: FileUIPart[] = await Promise.all(
      fileList.map(async (file) => ({
        type: "file" as const,
        mediaType: file.type,
        filename: file.name,
        url: await readFileAsDataURL(file),
      })),
    );
    setFiles((prev) => [...prev, ...newParts]);
  }, []);

  function removeFile(index: number) {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files?.length) {
      addFiles(Array.from(e.target.files));
      e.target.value = "";
    }
  }

  // Paste-to-attach for images
  function handlePaste(e: React.ClipboardEvent) {
    const imageFiles = Array.from(e.clipboardData.items)
      .filter((item) => item.type.startsWith("image/"))
      .map((item) => item.getAsFile())
      .filter((f): f is File => f !== null);
    if (imageFiles.length > 0) {
      e.preventDefault();
      addFiles(imageFiles);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if ((!text && files.length === 0) || isStreaming) return;
    setInput("");
    setFiles([]);
    if (files.length > 0) {
      sendMessage(text ? { text, files } : { files });
    } else {
      sendMessage({ text });
    }
  }

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <StatusBar
        subagent={subagent}
        session={session}
        isStreaming={isStreaming}
      />

      {/* Messages */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: "0.75rem",
          paddingBottom: "1rem",
        }}
      >
        {messages.length === 0 && (
          <p style={{ color: "#888", textAlign: "center", marginTop: "4rem" }}>
            Send a message to get started.
          </p>
        )}
        {messages.map((msg: OHUIMessage) => (
          <MessageBubble key={msg.id} message={msg} />
        ))}
      </div>

      {/* File previews */}
      {files.length > 0 && (
        <div
          style={{
            display: "flex",
            gap: "0.5rem",
            flexWrap: "wrap",
            padding: "0.5rem 0",
            borderTop: "1px solid #eee",
          }}
        >
          {files.map((file, i) => (
            <div
              key={i}
              style={{
                position: "relative",
                borderRadius: 8,
                border: "1px solid #ddd",
                overflow: "hidden",
                display: "flex",
                alignItems: "center",
                gap: "0.4rem",
                padding: file.mediaType.startsWith("image/") ? 0 : "0.3rem 0.6rem",
                background: "#f8f8f8",
              }}
            >
              {file.mediaType.startsWith("image/") ? (
                <img
                  src={file.url}
                  alt={file.filename ?? "attachment"}
                  style={{ height: 48, width: 48, objectFit: "cover", display: "block" }}
                />
              ) : (
                <span style={{ fontSize: "0.8rem", color: "#555" }}>
                  {file.filename ?? file.mediaType}
                </span>
              )}
              <button
                type="button"
                onClick={() => removeFile(i)}
                style={{
                  position: file.mediaType.startsWith("image/") ? "absolute" : "relative",
                  top: file.mediaType.startsWith("image/") ? 2 : "auto",
                  right: file.mediaType.startsWith("image/") ? 2 : "auto",
                  background: "rgba(0,0,0,0.5)",
                  color: "#fff",
                  border: "none",
                  borderRadius: "50%",
                  width: 18,
                  height: 18,
                  fontSize: "0.7rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  padding: 0,
                  lineHeight: 1,
                }}
              >
                x
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*,application/pdf"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />

      {/* Input */}
      <form
        onSubmit={handleSubmit}
        style={{
          flex: "0 0 auto",
          display: "flex",
          gap: "0.5rem",
          borderTop: "1px solid #eee",
          paddingTop: "0.75rem",
        }}
      >
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          title="Attach file"
          style={{
            padding: "0.5rem 0.65rem",
            borderRadius: 6,
            border: "1px solid #ccc",
            background: "#fff",
            cursor: "pointer",
            fontSize: "1rem",
            lineHeight: 1,
            color: "#555",
          }}
        >
          +
        </button>
        <input
          ref={textInputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onPaste={handlePaste}
          placeholder="Type a message..."
          style={{
            flex: 1,
            padding: "0.5rem 0.75rem",
            border: "1px solid #ccc",
            borderRadius: 6,
            fontSize: "0.95rem",
            outline: "none",
          }}
        />
        {isStreaming ? (
          <button
            type="button"
            onClick={stop}
            style={{
              padding: "0.5rem 1rem",
              borderRadius: 6,
              border: "1px solid #e55",
              background: "#fee",
              color: "#c33",
              cursor: "pointer",
              fontSize: "0.95rem",
            }}
          >
            Stop
          </button>
        ) : (
          <button
            type="submit"
            disabled={!input.trim() && files.length === 0}
            style={{
              padding: "0.5rem 1rem",
              borderRadius: 6,
              border: "none",
              background: input.trim() || files.length > 0 ? "#333" : "#ccc",
              color: "#fff",
              cursor: input.trim() || files.length > 0 ? "pointer" : "default",
              fontSize: "0.95rem",
            }}
          >
            Send
          </button>
        )}
      </form>
    </div>
  );
}
