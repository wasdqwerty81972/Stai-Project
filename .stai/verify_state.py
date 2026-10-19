import json

print("=== notes.json ===")
with open(".stai/notes.json") as f:
    notes = json.load(f)
for n in notes:
    print(f"  ID={n['id']} Title={n['title']} Time={n['timestamp'][:19]}")
    print(f"    Preview: {n['content'][:100]}")

print()
print("=== todos.json ===")
with open(".stai/todos.json") as f:
    todos = json.load(f)
for t in todos:
    print(f"  ID={t['id']} Text={t['text']} Status={t['status']}")

print()
print("=== test_output.txt ===")
with open("test_output.txt") as f:
    print(repr(f.read()))
