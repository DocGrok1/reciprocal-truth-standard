import hashlib
from datetime import datetime, date

class ReciprocalTruthEnforcer:
    def __init__(self):
        self.consent = {}          # user_id -> {"extractive": bool, "expires": str|None, "scope": list[str]}
        self.receipts = {}         # user_id -> list[{"timestamp": str, "receipt": str, "snapshot": dict}]
        self.receipt_anchor = []   # global immutable log: [{"receipt": str, "timestamp": str}]
        self.attribution = {}      # artifact_id -> list[origin_user_id]
        self.artifact_state = {}   # artifact_id -> str: "generated" | "used" | "published" | "archived"
        self.reuse_log = []        # list of {"artifact_id": str, "disclosed": bool, "timestamp": str}
        self.known_users = set()
        self.extractive_ingests = 0
        self.published_count = 0   # ever reached "published" state (for accurate RIM-6)

    def register_user(self, user_id):
        self.known_users.add(user_id)
        if user_id not in self.consent:
            self.consent[user_id] = {"extractive": False, "expires": None, "scope": []}
        if user_id not in self.receipts:
            self.receipts[user_id] = []

    def _generate_consent_receipt(self, user_id):
        consent_obj = self.consent[user_id]
        payload = f"{user_id}|{str(consent_obj)}".encode()
        receipt = hashlib.sha256(payload).hexdigest()
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "receipt": receipt,
            "snapshot": consent_obj.copy()
        }
        self.receipts[user_id].append(record)

        # Global receipt anchor log (immutable public ledger of all consent changes)
        self.receipt_anchor.append({
            "receipt": receipt,
            "timestamp": record["timestamp"]
        })

        return receipt

    def set_consent(self, user_id, extractive=True, expires=None, scope=None):
        self.register_user(user_id)
        if scope is None:
            scope = []
        self.consent[user_id] = {
            "extractive": extractive,
            "expires": expires,
            "scope": scope
        }
        return self._generate_consent_receipt(user_id)

    def revoke_consent(self, user_id):
        self.register_user(user_id)
        if user_id in self.consent:
            self.consent[user_id]["extractive"] = False
        return self._generate_consent_receipt(user_id)

    def get_latest_receipt(self, user_id):
        if user_id not in self.receipts or not self.receipts[user_id]:
            return None
        return self.receipts[user_id][-1]["receipt"]

    def get_consent_history(self, user_id):
        return self.receipts.get(user_id, [])

    def is_active_extractive(self, user_id):
        if user_id not in self.consent:
            return False
        c = self.consent[user_id]
        if not c.get("extractive", False):
            return False
        expires = c.get("expires")
        if expires:
            try:
                expiry_date = datetime.fromisoformat(expires.split('T')[0]).date()
                if date.today() > expiry_date:
                    return False
            except ValueError:
                pass
        return True

    def ingest(self, user_id, payload, extractive=False, required_scopes=None):
        self.register_user(user_id)
        if required_scopes is None:
            required_scopes = []

        if extractive or required_scopes:
            if not self.is_active_extractive(user_id):
                raise PermissionError("Extractive use or scoped access requires active opt-in consent")
            
            if required_scopes:
                consent_scope = set(self.consent[user_id].get("scope", []))
                if not set(required_scopes) <= consent_scope:
                    raise PermissionError("Required scopes not covered by user consent")

        artifact_id = f"artifact_{hash(str(payload) + str(datetime.utcnow()))}"

        if extractive:
            self.extractive_ingests += 1
            self.record_derivative(artifact_id, user_id)
            self.artifact_state[artifact_id] = "generated"

        return {"status": "Processed", "artifact_id": artifact_id if extractive else None}

    def record_derivative(self, artifact_id, origin_user):
        if artifact_id not in self.attribution:
            self.attribution[artifact_id] = []
        if origin_user not in self.attribution[artifact_id]:
            self.attribution[artifact_id].append(origin_user)

    def transition_artifact_state(self, artifact_id, new_state):
        valid_transitions = {
            "generated": ["used", "archived"],
            "used": ["published", "archived"],
            "published": ["archived"],
            "archived": []
        }
        current = self.artifact_state.get(artifact_id, None)
        if current is None:
            raise ValueError(f"Artifact {artifact_id} not found")
        if new_state not in valid_transitions.get(current, []):
            raise ValueError(f"Invalid transition: {current} → {new_state}")

        # Track ever-published for accurate RIM-6
        if new_state == "published":
            self.published_count += 1

        self.artifact_state[artifact_id] = new_state

    def log_reuse(self, artifact_id, disclosed=False):
        if artifact_id in self.artifact_state:
            if self.artifact_state[artifact_id] in ["generated", "used"]:
                self.artifact_state[artifact_id] = "used"
        self.reuse_log.append({
            "artifact_id": artifact_id,
            "disclosed": disclosed,
            "timestamp": datetime.utcnow().isoformat()
        })

    def audit(self):
        total_users = len(self.known_users)
        
        active_consenting = sum(1 for uid in self.known_users if self.is_active_extractive(uid))
        rim_1 = round(active_consenting / total_users, 4) if total_users > 0 else 0.0

        attributed_artifacts = len(self.attribution)
        rim_2 = round(attributed_artifacts / self.extractive_ingests, 4) if self.extractive_ingests > 0 else 0.0

        total_reuses = len(self.reuse_log)
        silent_reuses = len([r for r in self.reuse_log if not r["disclosed"]])
        disclosed_rate = (total_reuses - silent_reuses) / total_reuses if total_reuses > 0 else 1.0
        rim_3 = round(disclosed_rate, 4)

        exp_count = sum(1 for uid in self.known_users 
                       if self.is_active_extractive(uid) and self.consent[uid].get("expires") is not None)
        rim_4 = round(exp_count / active_consenting, 4) if active_consenting > 0 else 0.0

        scope_count = sum(1 for uid in self.known_users 
                         if self.is_active_extractive(uid) and len(self.consent[uid].get("scope", [])) > 0)
        rim_5 = round(scope_count / active_consenting, 4) if active_consenting > 0 else 0.0

        total_generated = self.extractive_ingests
        rim_6 = round(self.published_count / total_generated, 4) if total_generated > 0 else 0.0

        # Artifact lifecycle stats
        state_counts = {"generated": 0, "used": 0, "published": 0, "archived": 0}
        for state in self.artifact_state.values():
            if state in state_counts:
                state_counts[state] += 1

        return {
            # Direct RIM emissions
            "RIM-1": rim_1,
            "RIM-2": rim_2,
            "RIM-3": rim_3,
            "RIM-4": rim_4,
            "RIM-5": rim_5,
            "RIM-6": rim_6,  # published_artifacts ÷ generated_artifacts (ever-published / total generated)

            # Supporting metrics
            "total_users": total_users,
            "active_consenting_users": active_consenting,
            "extractive_ingests": self.extractive_ingests,
            "ever_published_artifacts": self.published_count,
            "attributed_artifacts": attributed_artifacts,
            "total_reuses": total_reuses,
            "silent_reuses": silent_reuses,
            "artifact_states": state_counts,
            "total_receipts_issued": sum(len(v) for v in self.receipts.values()),
            "anchored_receipts": len(self.receipt_anchor)
        }
