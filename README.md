# 🛡️ BitMe: AI Alert-Triage Console

**BitMe** is an AI-powered Security Operations Center (SOC) triage console built to accelerate incident response and reduce alert fatigue. 

Designed for this live hackathon demo, BitMe ingests raw security alerts, correlates them into incidents, ranks them by risk, and uses AI to recommend actionable prevention strategies.

## 🧠 Under the Hood: What's Real vs. Simulated?

To demonstrate a fully functional SOC workflow without requiring a live enterprise network, we built a hybrid environment:

*   ✅ **100% Real Code:** 
    *   **Asset-Aware Scoring:** A custom risk formula that ranks incidents based on target criticality (e.g., a finance database is prioritized over guest Wi-Fi).
    *   **AI Integration:** Live Gemini API integration for generating instant incident briefs and step-by-step prevention drafts.
    *   **Audit Trail:** Secure, persistent logging of all analyst actions to a tamper-evident audit log.
*   🧪 **Simulated for the Demo:** 
    *   **The Alert Feed:** A synthetic replay of raw backend alerts mimicking a live, multi-stage attack.
    *   **Command Execution:** Prevention commands (like blocking IPs or isolating hosts) are safely simulated and never actually executed against a live system.

## 🎬 The Demo Scenario

When evaluating the demo, you will see a simulated attack unfold in real-time:

1. **Ingestion:** The system replays our synthetic feed of security alerts.
2. **Triage & Ranking:** Three distinct incidents are correlated and automatically ranked by the risk formula: `FIN-DB-01` (Highest) > `CEO-Laptop` > `Guest-WiFi-04`.
3. **AI Analysis:** Selecting an incident generates an AI-powered brief explaining the attack vector and drafting remediation commands.
4. **Human-in-the-Loop:** The analyst can **Approve, Modify, or Reject** the AI's suggestions.
5. **Resolution:** Executing an action successfully writes to a persistent audit log, demonstrating compliance readiness.
