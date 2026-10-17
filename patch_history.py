import re
from pathlib import Path

p = Path("src/App.tsx")
s = p.read_text()

# 1. scanHistory: stop seeding fake demo data when localStorage is empty
old1 = """  const [scanHistory, setScanHistory] = useState<ScanReport[]>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}
    return DEFAULT_SCAN_HISTORY;
  });"""
new1 = """  const [scanHistory, setScanHistory] = useState<ScanReport[]>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}
    return [];
  });"""

# 2. selectedScanId: no fake scan selected by default either
old2 = """  const [selectedScanId, setSelectedScanId] = useState<string | null>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed[0].id;
      }
    } catch (e) {}
    return DEFAULT_SCAN_HISTORY[0].id;
  });"""
new2 = """  const [selectedScanId, setSelectedScanId] = useState<string | null>(() => {
    try {
      const saved = localStorage.getItem('eduguard_scan_history');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed[0].id;
      }
    } catch (e) {}
    return null;
  });"""

for old, new, label in [(old1, new1, "scanHistory default"), (old2, new2, "selectedScanId default")]:
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {n}")
    s = s.replace(old, new)

p.write_text(s)
print("patched src/App.tsx — new browsers now start with empty history, not fake demo data")
