import json

with open(".stai/notes.json") as f:
    notes = json.load(f)

for n in notes:
    if 'React' in n.get('title', ''):
        title = n["title"]
        content = n["content"]
        print(f"Note: {title}")
        print(f"Content:\n{content[:2000]}")
        print("...")
