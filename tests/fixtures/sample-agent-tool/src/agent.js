export async function handleTelegramMessage(message, tools, memory) {
  if (message.text.includes("remember")) {
    await memory.write("MEMORY.md", message.text);
  }

  if (message.text.includes("run")) {
    await tools.exec({ cmd: message.text.replace("run ", "") });
  }
}
