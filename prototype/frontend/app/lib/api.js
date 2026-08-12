const API_BASE = "http://127.0.0.1:8000";

export async function createProfile(profile) {
  const res = await fetch(`${API_BASE}/profiles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile),
  });
  if (!res.ok) throw new Error("Failed to create profile");
  return res.json();
}

export async function listProfiles() {
  const res = await fetch(`${API_BASE}/profiles`);
  if (!res.ok) throw new Error("Failed to fetch profiles");
  return res.json();
}

export async function deleteProfile(id) {
  const res = await fetch(`${API_BASE}/profiles/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete profile");
}

export async function getProfile(id) {
  const res = await fetch(`${API_BASE}/profiles/${id}`);
  if (!res.ok) throw new Error("Failed to fetch profile");
  return res.json();
}

export async function updateProfile(id, profile) {
  const res = await fetch(`${API_BASE}/profiles/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile),
  });
  if (!res.ok) throw new Error("Failed to update profile");
  return res.json();
}