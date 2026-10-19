"""
CyberOS Intent Router
Classifies user intent and determines whether tools are required.
"""

import re
from enum import Enum
from typing import Dict, List, Optional, Tuple


class IntentType(Enum):
    CONVERSATIONAL = "conversational"
    INFORMATIONAL = "informational"
    ANALYSIS = "analysis"
    INVESTIGATION = "investigation"
    INCIDENT_RESPONSE = "incident_response"
    FINDINGS_QUERY = "findings_query"
    SYSTEM_CONTROL = "system_control"
    UNKNOWN = "unknown"


class IntentResult:
    def __init__(self, intent: IntentType, confidence: float, requires_tools: bool,
                 suggested_tools: List[str] = None, clarification: str = ""):
        self.intent = intent
        self.confidence = confidence
        self.requires_tools = requires_tools
        self.suggested_tools = suggested_tools or []
        self.clarification = clarification

    def to_dict(self):
        return {
            "intent": self.intent.value,
            "confidence": self.confidence,
            "requires_tools": self.requires_tools,
            "suggested_tools": self.suggested_tools,
            "clarification": self.clarification,
        }


class IntentRouter:
    """Routes user messages to appropriate handling based on intent."""

    # Patterns for each intent type
    PATTERNS = {
        IntentType.CONVERSATIONAL: {
            "patterns": [
                r"^(hi|hello|hey|sup|yo|good\s*(morning|afternoon|evening)|howdy|greetings)$",
                r"^(hi|hello|hey)\s",
                r"^(how are you|what('s| is) up|what('s| is) new|how('s| is) it going)$",
                r"^(thanks|thank you|thx|ty|appreciate it)$",
                r"^(bye|goodbye|see you|later|cya)$",
                r"^(yes|no|yeah|yep|nope|ok|okay|sure|alright)$",
            ],
            "keywords": ["hello", "hi ", "hey", "thanks", "bye", "ok ", "okay", "sure"],
            "exclude_keywords": ["analyze", "scan", "investigate", "check", "review", "find", "look", "show", "list", "get", "run", "start", "stop", "help"],
        },
        IntentType.INFORMATIONAL: {
            "patterns": [
                r"what can you do",
                r"what are you",
                r"who are you",
                r"how do you work",
                r"what is this",
                r"explain yourself",
                r"tell me about yourself",
                r"help me",
                r"i need help",
                r"what should i do",
                r"how do i get started",
                r"commands",
                r"capabilities",
                r"features",
            ],
            "keywords": ["what can you do", "help", "commands", "capabilities", "features", "how do i", "what is", "who are you", "tell me about"],
            "exclude_keywords": ["analyze", "scan", "investigate", "check", "review", "find", "show me", "run", "start", "stop"],
        },
        IntentType.ANALYSIS: {
            "patterns": [
                r"analyze\s+(this|the|file|code|script|program)",
                r"check\s+(this|the|file|code|script)",
                r"review\s+(this|the|file|code|script)",
                r"inspect\s+(this|the|file|code|script)",
                r"audit\s+(this|the|file|code|script)",
                r"scan\s+(this|the|file|code|script)",
                r"static\s+analysis",
                r"code\s+review",
                r"security\s+review",
                r"check\s+for\s+(secrets|vulnerabilities|issues|bugs)",
                r"find\s+(secrets|vulnerabilities|issues|bugs)",
                r"look\s+for\s+(secrets|vulnerabilities|issues|bugs)",
            ],
            "keywords": ["analyze", "review", "inspect", "audit", "scan file", "check file", "check for", "look for", "find secrets", "static analysis", "code review", "security review"],
            "exclude_keywords": ["workspace", "system", "network", "process", "incident", "threat", "investigate"],
        },
        IntentType.INVESTIGATION: {
            "patterns": [
                r"investigate\s+(this|the|system|machine|endpoint|workspace)",
                r"investigation",
                r"hunt\s+for\s+threats?",
                r"threat\s+hunt",
                r"look\s+for\s+anomalies?",
                r"check\s+(the\s+)?system\s+for",
                r"examine\s+(the\s+)?system",
                r"assess\s+(the\s+)?security",
                r"security\s+assessment",
                r"baseline",
                r"scan\s+(my\s+)?workspace",
                r"scan\s+the\s+system",
                r"check\s+the\s+workspace",
                r"check\s+the\s+system",
                r"scan\s+([A-Za-z]:\\)",
                r"scan\s+([A-Za-z]:)\s+drive",
            ],
            "keywords": ["investigate", "investigation", "threat hunt", "hunt", "anomalies", "assess security", "security assessment", "examine system", "scan workspace", "scan system", "check workspace", "check system"],
            "exclude_keywords": ["file", "code", "specific"],
        },
        IntentType.INCIDENT_RESPONSE: {
            "patterns": [
                r"someone\s+is\s+attacking",
                r"under\s+attack",
                r"incident",
                r"respond\s+to",
                r"contain",
                r"remediate",
                r"threat\s+response",
                r"emergency",
                r"compromise",
                r"breach",
                r"intrusion",
                r"malware",
                r"ransomware",
                r"suspicious\s+activity",
            ],
            "keywords": ["incident", "attack", "respond", "contain", "remediate", "emergency", "compromise", "breach", "intrusion", "malware", "ransomware", "suspicious"],
            "exclude_keywords": [],
        },
        IntentType.FINDINGS_QUERY: {
            "patterns": [
                r"show\s+(me\s+)?(the\s+)?findings?",
                r"list\s+(the\s+)?findings?",
                r"what\s+(are\s+)?(the\s+)?findings?",
                r"previous\s+findings?",
                r"existing\s+findings?",
                r"view\s+findings?",
                r"show\s+(me\s+)?results?",
                r"what\s+did\s+you\s+find",
                r"show\s+(me\s+)?(the\s+)?results?",
            ],
            "keywords": ["show findings", "list findings", "view findings", "previous findings", "existing findings", "what did you find", "show results"],
            "exclude_keywords": ["new", "run", "start", "generate"],
        },
        IntentType.SYSTEM_CONTROL: {
            "patterns": [
                r"cyberos\s+(start|stop|status|reset|restart)",
                r"start\s+(cyberos|monitoring|live\s+defense)",
                r"stop\s+(cyberos|monitoring|live\s+defense)",
                r"(start|stop)\s+honeypot",
                r"honeypot\s+status",
            ],
            "keywords": ["cyberos start", "cyberos stop", "cyberos status", "start cyberos", "stop cyberos", "start honeypot", "stop honeypot", "honeypot status"],
            "exclude_keywords": [],
        },
    }

    def __init__(self):
        self.compiled_patterns = {}
        for intent, config in self.PATTERNS.items():
            self.compiled_patterns[intent] = {
                "patterns": [re.compile(p, re.IGNORECASE) for p in config["patterns"]],
                "keywords": config["keywords"],
                "exclude_keywords": config["exclude_keywords"],
            }

    def classify(self, user_input: str) -> IntentResult:
        """Classify user intent and determine if tools are needed."""
        if not user_input or not user_input.strip():
            return IntentResult(IntentType.CONVERSATIONAL, 1.0, False)

        text = user_input.lower().strip()

        # A greeting can precede a real request (for example, "hi, scan ...").
        # Security actions must win over conversational keyword matches.
        action_words = ("analyze", "audit", "check", "find", "inspect", "investigate", "look for", "review", "scan", "issue", "problem", "wrong", "weird", "suspicious", "unsafe")
        suspicious_context = ("workspace", "system", "downloads", "threat", "virus", "malware", "network", "connection", "process", "endpoint", "pc", "computer", "device", "machine", "security", "malware")
        if any(word in text for word in action_words):
            return IntentResult(
                IntentType.INVESTIGATION if any(word in text for word in suspicious_context) or any(word in text for word in ("wrong", "problem", "issue", "suspicious", "weird")) else IntentType.ANALYSIS,
                1.0,
                True,
                suggested_tools=self._suggest_tools(
                    IntentType.INVESTIGATION if any(word in text for word in suspicious_context) or any(word in text for word in ("wrong", "problem", "issue", "suspicious", "weird")) else IntentType.ANALYSIS,
                    text,
                ),
            )

        scores = {}

        # Score each intent
        for intent, config in self.compiled_patterns.items():
            score = 0.0
            
            # Pattern matching
            for pattern in config["patterns"]:
                if pattern.search(text):
                    score += 0.8
            
            # Keyword matching
            for keyword in config["keywords"]:
                if keyword in text:
                    score += 0.3
            
            # Exclusion penalties
            for exclude in config["exclude_keywords"]:
                if exclude in text:
                    score -= 0.5
            
            scores[intent] = max(0.0, score)

        # Get best match
        best_intent = max(scores, key=scores.get)
        best_score = scores[best_intent]

        # Threshold for confident classification
        if best_score < 0.3:
            # Ambiguous - ask for clarification
            return IntentResult(
                IntentType.UNKNOWN,
                0.0,
                False,
                clarification="What would you like me to check — a specific file, the workspace, or the current investigation?"
            )

        # Determine if tools are required
        tools_required = best_intent in {
            IntentType.ANALYSIS,
            IntentType.INVESTIGATION,
            IntentType.INCIDENT_RESPONSE,
        }

        # Suggest tools based on intent
        suggested_tools = self._suggest_tools(best_intent, text)

        return IntentResult(
            intent=best_intent,
            confidence=min(best_score, 1.0),
            requires_tools=tools_required,
            suggested_tools=suggested_tools,
        )

    def _suggest_tools(self, intent: IntentType, text: str) -> List[str]:
        """Suggest appropriate tools for the intent."""
        tool_map = {
            IntentType.ANALYSIS: ["static_analysis", "secret_scanner", "file_analyzer"],
            IntentType.INVESTIGATION: ["system_monitor", "process_analyzer", "network_analyzer", "secret_scanner"],
            IntentType.INCIDENT_RESPONSE: ["incident_responder", "network_defender", "malware_analyzer"],
            IntentType.FINDINGS_QUERY: ["database_query"],
            IntentType.SYSTEM_CONTROL: ["cyberos_control"],
        }
        return tool_map.get(intent, [])

    def get_response_for_intent(self, intent_result: IntentResult, user_input: str) -> str:
        """Generate appropriate response based on intent classification."""
        intent = intent_result.intent
        
        if intent == IntentType.CONVERSATIONAL:
            return self._conversational_response(user_input)
        elif intent == IntentType.INFORMATIONAL:
            return "I’m SVS-Cyber. Send a concrete security task and I’ll run it through the agent and tool pipeline."
        elif intent == IntentType.UNKNOWN:
            return intent_result.clarification
        elif intent == IntentType.FINDINGS_QUERY:
            return "I'll retrieve your existing findings. No need to rerun scans."
        elif intent == IntentType.SYSTEM_CONTROL:
            return "I'll handle that system control request."
        else:
            return f"I understand you want me to {intent.value.replace('_', ' ')}. Let me gather the relevant information."

    def _conversational_response(self, user_input: str) -> str:
        """Generate conversational response."""
        text = user_input.lower().strip()
        
        if any(word in text for word in ["hi", "hello", "hey"]):
            return "Message received. What security task should I run?"
        elif any(word in text for word in ["thanks", "thank you"]):
            return "You're welcome! Let me know if you need anything else."
        elif any(word in text for word in ["bye", "goodbye"]):
            return "Goodbye! Stay secure."
        else:
                return "Send a concrete security task to begin."
