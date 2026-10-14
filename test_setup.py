import yaml
from pathlib import Path
from core.models import AuditPackRequest, Finding, GemmaRemediation

def test_setup():
    print("🔍 Running EduGuard Phase 1 Environment & Setup Verification...\n")
    
    # 1. Test YAML Rule Catalog Parsing
    yaml_path = Path("templates/edu_asvs_rules.yaml")
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
            packs = data.get("packs", [])
            print(f"✅ Successfully loaded YAML rule catalog: {len(packs)} template packs found.")
            for pack in packs:
                print(f"   - [{pack['id']}] {pack['name']} ({len(pack['checks'])} checks)")
    else:
        print("❌ Error: templates/edu_asvs_rules.yaml not found!")

    # 2. Test Demo Target Files
    demo_dir = Path("demo_target")
    expected_files = ["student_portal.py", "upload_assignment.php", "nginx.conf", ".env.example"]
    print("\n🔍 Checking demo_target files...")
    for ef in expected_files:
        f_path = demo_dir / ef
        if f_path.exists():
            print(f"   - ✅ Found: {f_path}")
        else:
            print(f"   - ❌ Missing: {f_path}")

    # 3. Test Pydantic Models
    print("\n🔍 Testing Pydantic Data Models...")
    try:
        req = AuditPackRequest(target="./demo_target", scan_mode="source_code", selected_packs=["pack_4_sast"])
        print(f"   - ✅ AuditPackRequest validated successfully: {req.model_dump()}")
    except Exception as e:
        print(f"   - ❌ Pydantic model validation failed: {e}")

    print("\n🚀 Phase 1 setup verification complete! Ready to build Phase 2 (Scanners).")

if __name__ == "__main__":
    test_setup()
