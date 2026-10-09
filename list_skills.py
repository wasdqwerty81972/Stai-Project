import json
with open('HackerAI-Source/lib/ai/subagents/skills/strix-skill-catalog.generated.json') as f:
    data = json.load(f)
for skill in data['skills']:
    if not skill.get('internal'):
        print(f"{skill['id']}: {skill['name']} - {skill['description'][:80]}")