const axios = require("axios");

const OLLAMA_HOST =
  process.env.OLLAMA_HOST || "http://host.docker.internal:11434";

async function summarizeTicket(description) {
  const prompt = `You are a helpful assistant that summarizes support tickets for IT administrators.

Below is a support ticket description. Please provide a brief, professional summary (2-3 sentences) of the main issue and any action items.

Ticket Description:
${description}`;

  try {
    const response = await axios.post(`${OLLAMA_HOST}/api/generate`, {
      model: "phi3:mini",
      prompt: prompt,
      stream: false,
      options: {
        temperature: 0.3,
        top_p: 0.9,
      }, 
    });

    return response.data.response.trim();
  } catch (error) {
    console.error("[AI] Error summarizing ticket:", error.message);
    return "Summary generation failed. Please review the full ticket description.";
  }
}

module.exports = {
  summarizeTicket,
};
