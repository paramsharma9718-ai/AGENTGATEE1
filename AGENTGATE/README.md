# AGENTGATE

**Intelligent Security Gateway & Information-Flow Control for AI Agents**  
*College Team Project:* Param (Module 04), Nihal (Module 03), Dev (Module 02), Keshav (Module 01).

---

## Architecture Overview

AGENTGATE separates AI-generated action proposals from trusted security authorization.

```
USER / UNTRUSTED PROMPT / DOCS
              │
              ▼
   ┌─────────────────────┐
   │ MODULE 04: UI & DB  │ (Streamlit Dashboard, Auth, Audit, Doc Manager)
   └──────────┬──────────┘
              │  sends prompt / document
              ▼
   ┌─────────────────────┐
   │ MODULE 03: AI AGENT │ (AgentGateAI / ActionProposer)
   └──────────┬──────────┘
              │  proposes ActionProposal (NO self-authorization)
              ▼
   ┌─────────────────────┐
   │  EXECUTION GATEWAY  │ (tools/execution_gateway.py)
   └──────────┬──────────┘
              │
      ┌───────┴───────┐
      ▼               ▼
┌───────────┐   ┌───────────┐
│ MODULE 01 │   │ MODULE 02 │
│ Policy &  │   │ Security  │
│ Auth (RBAC)│  │ Labels &  │
│ Engine    │   │ Provenance│
└─────┬─────┘   └─────┬─────┘
      └───────┬───────┘
              ▼
    GATEWAY ENFORCEMENT (Fail-Closed)
       ├── ALLOW ──────────────► Execute Protected Tool
       ├── BLOCK ──────────────► Abort (Zero side-effects)
       └── REQUIRE_APPROVAL ───► Hold until Admin Approval
              │
              ▼
  ┌──────────────────────────────────────────────┐
  │ 3 PROTECTED TOOLS                            │
  │ • DocumentReader (storage/documents)         │
  │ • ReportSaver (data/reports + Provenance)    │
  │ • MockInbox (data/inbox + SQLite deliveries) │
  └──────────────────────┬───────────────────────┘
                         ▼
        Tamper-Evident SHA-256 Hash Chain Persistence (agentgate.db)
```

---

## Directory Structure

```
AGENTGATE/
├── app.py                             # Module 04: Streamlit Web Dashboard & UI Entrypoint
├── auth/                              # Module 04: User Auth & PBKDF2 Password Hashing
│   ├── __init__.py
│   └── user_manager.py
├── views/                             # Module 04: 9 Dashboard Pages & Cyber Dark Theme
│   ├── __init__.py
│   ├── theme.py                       # Dark navy & blue/purple styling
│   ├── v_dashboard.py                 # Security Overview Dashboard (KPIs, Plotly charts)
│   ├── v_playground.py                # AI Agent Playground
│   ├── v_documents.py                 # Document Manager with DLP Auto-Classification
│   ├── v_policies.py                  # Policy & Clearance Matrix Monitoring
│   ├── v_attacks.py                   # Live Attack Simulator (5 Real Scenarios)
│   ├── v_approvals.py                 # Human Approval Center
│   ├── v_workflows.py                 # Multi-step Workflow Manager
│   ├── v_audit.py                     # Tamper-Evident Audit Explorer & Verifier
│   └── v_login.py                     # Identity Switcher & Registration
├── config/
│   └── security_policies.json         # Module 01: Policy rules & RBAC
├── models/
│   ├── __init__.py                    # Unified models export
│   ├── action_request.py              # Module 01: ActionRequest, AuthorizationResponse
│   ├── policy.py                      # Module 01: RoleConfig, PolicyConfig
│   ├── document_security.py           # Module 02: Classification, DocumentSecurityMetadata
│   └── workflow.py                    # Module 03: ActionProposal, ExecutionResult, WorkflowState
├── security/
│   ├── __init__.py
│   ├── authorization.py               # Module 01: authorize_action
│   ├── approval.py                    # Module 01: apply_approval
│   ├── policy_engine.py               # Module 01: PolicyEngine
│   ├── policy_manager.py              # Module 01: Role & policy lookup
│   ├── risk_engine.py                 # Module 01: Risk evaluation
│   ├── security_labels.py             # Module 02: Classification enforcement
│   ├── dlp_engine.py                  # Module 02: Content inspection & DLP
│   ├── information_flow.py            # Module 02: Label inheritance
│   └── provenance.py                  # Module 02: register_derivation & lineage
├── storage/
│   ├── __init__.py
│   ├── audit_logger.py                # SQLite persistence for audit & workflows
│   ├── hash_chain_audit.py            # Module 04: SHA-256 Tamper-Evident Audit Logger & Verifier
│   ├── document_registry.py           # Document registry & path-traversal prevention
│   ├── document_service.py            # Module 04: Upload handler, DLP scan, safe storage
│   └── approval_service.py            # Module 04: Human approval queue manager
├── tools/
│   ├── __init__.py
│   ├── execution_gateway.py           # Module 03: Centralized Security Gateway
│   ├── document_reader.py             # Module 03: Protected Document Reader
│   ├── report_saver.py                # Module 03: Protected Report Saver
│   └── mock_inbox.py                  # Module 03: Protected Mock Inbox Delivery
├── agent/
│   ├── __init__.py
│   ├── action_proposer.py             # Module 03: Structured Action Proposer
│   ├── workflow_manager.py            # Module 03: Persistent Multi-step Workflow Manager
│   ├── llm_integration.py             # Module 03: Deterministic & LLM Hook
│   └── agent.py                       # Module 03: High-level AI Agent Orchestrator
├── tests/
│   ├── test_authorization.py          # Module 01 Tests
│   ├── test_dlp.py                    # Module 02 Tests
│   ├── test_information_flow.py       # Module 02 Tests
│   ├── test_provenance.py             # Module 02 Tests
│   ├── test_security_labels.py        # Module 02 Tests
│   ├── test_security_integration.py   # Module 02 Tests
│   ├── test_tool_execution.py         # Module 03 Tests
│   └── test_module_04.py              # Module 04 Tests (Auth, Hash-Chain, DLP Ingestion, Approvals)
├── demo.py                            # Live interactive CLI demonstration
├── pytest.ini
└── requirements.txt
```

---

## Running the Project

### 1. Launch AGENTGATE Web Application (Module 04 UI)
```bash
streamlit run app.py
```
Opens the interactive dark-themed security gateway dashboard in your browser.

### 2. Run Automated Test Suite (All 213 Tests)
```bash
python -m pytest
```

### 3. Run Live CLI Demonstration
```bash
python demo.py
```
