const STORAGE_KEY_PREFIX = "prisec_context_";

export function loadContextState(profileId) {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY_PREFIX + profileId);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveContextState(profileId, { form, weights }) {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.setItem(STORAGE_KEY_PREFIX + profileId, JSON.stringify({ form, weights }));
  } catch {
  }
}