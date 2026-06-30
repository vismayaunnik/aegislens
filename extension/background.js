const API_URL = "http://127.0.0.1:5000/analyze";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyze-with-aegislens",
    title: "Analyze with AegisLens",
    contexts: ["selection"],
  });

  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "analyze-with-aegislens" || !info.selectionText?.trim()) {
    return;
  }
  if (!tab?.id) {
    return;
  }

  const selectedText = info.selectionText.trim();

  await chrome.storage.local.set({
    selectedText,
    analysisStatus: "loading",
    analysisResult: null,
    analysisError: null,
  });

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: selectedText }),
    });

    const data = await response.json();

    if (!response.ok) {
      await chrome.storage.local.set({
        analysisStatus: "error",
        analysisResult: null,
        analysisError: data.error || `Request failed (HTTP ${response.status})`,
      });
    } else {
      await chrome.storage.local.set({
        analysisStatus: "complete",
        analysisResult: data,
        analysisError: null,
      });
    }
  } catch (error) {
    await chrome.storage.local.set({
      analysisStatus: "error",
      analysisResult: null,
      analysisError: error.message || "Failed to reach AegisLens backend",
    });
  }

  await chrome.sidePanel.open({ tabId: tab.id });
});
