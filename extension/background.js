const API_URL = "http://127.0.0.1:5000/analyze";
const SIDE_PANEL_PATH = "sidepanel.html";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyze-with-aegislens",
    title: "Analyze with AegisLens",
    contexts: ["selection"],
  });

  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  // Enable the global side panel by default (manifest default_path).
  chrome.sidePanel.setOptions({ enabled: true });
});

function openSidePanelForTab(tab) {
  console.log("[AegisLens] openSidePanelForTab called", {
    tabId: tab.id,
    windowId: tab.windowId,
    url: tab.url,
  });

  // Register/enable the panel for this tab synchronously (no await).
  try {
    console.log("[AegisLens] calling sidePanel.setOptions...");
    chrome.sidePanel.setOptions({
      tabId: tab.id,
      path: SIDE_PANEL_PATH,
      enabled: true,
    });
    console.log("[AegisLens] sidePanel.setOptions called (sync, no await)");
  } catch (error) {
    console.error("[AegisLens] sidePanel.setOptions threw synchronously:", error);
  }

  // Must run synchronously within the user gesture — before any await.
  // Use windowId (Chrome's context-menu sample pattern) for the global panel.
  try {
    console.log("[AegisLens] calling sidePanel.open({ windowId })...");
    const openPromise = chrome.sidePanel.open({ windowId: tab.windowId });
    console.log("[AegisLens] sidePanel.open returned promise:", openPromise);

    openPromise
      .then(() => {
        console.log("[AegisLens] sidePanel.open resolved OK");
      })
      .catch((error) => {
        console.error("[AegisLens] sidePanel.open rejected:", error);
      });
  } catch (error) {
    console.error("[AegisLens] sidePanel.open threw synchronously:", error);
  }
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  console.log("[AegisLens] contextMenus.onClicked", {
    menuItemId: info.menuItemId,
    hasSelection: Boolean(info.selectionText?.trim()),
    tabId: tab?.id,
  });

  if (info.menuItemId !== "analyze-with-aegislens" || !info.selectionText?.trim()) {
    return;
  }
  if (!tab?.id) {
    console.warn("[AegisLens] aborting — no tab.id on context menu event");
    return;
  }

  openSidePanelForTab(tab);

  const selectedText = info.selectionText.trim();

  (async () => {
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
  })();
});
