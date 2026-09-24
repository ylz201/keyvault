"""Single use boundary: authenticate, authorize, reserve, execute, project, audit."""
from __future__ import annotations
import hmac
import json
import time
from .protocol import GatewayError, canonical, closed, identifier, project_output, request_id
from .provider import validate_secret

class Broker:
    def __init__(self, state, provider, transport):
        self.state, self.provider, self.transport = state, provider, transport

    def dispatch(self, token, method, arguments):
        principal = None
        try:
            with self.state.transaction() as db:
                principal = self.state.authenticate(db, token)["id"]
            if method == "credentials_list":
                closed(arguments, ())
                return self.discover(token)
            if method == "credential_use":
                closed(arguments, ("grant_id", "request_id"))
                return self.use(token, identifier(arguments["grant_id"]), request_id(arguments["request_id"]))
            if method == "credential_status":
                closed(arguments, ("request_id",))
                return self.status(token, request_id(arguments["request_id"]))
            raise GatewayError("UNKNOWN_METHOD")
        except GatewayError as exc:
            with self.state.transaction() as db:
                self.state.event(db, "DENIED_" + exc.code, principal)
            raise

    def discover(self, token):
        with self.state.transaction() as db:
            client = self.state.authenticate(db, token)
            rows = db.execute("SELECT id FROM grants WHERE client=? ORDER BY id LIMIT 1000", (client["id"],)).fetchall()
            results = []
            for row in rows:
                try:
                    grant = self.state.authorized(db, client, row["id"])
                except GatewayError:
                    continue
                if grant["uses"] >= grant["max_uses"]:
                    continue
                config = json.loads(grant["config"])
                results.append({"grant_id": grant["id"], "operation_id": grant["operation"],
                                "credential_ref": config["credential"]["ref"], "method": "GET",
                                "expires_at": grant["expires"], "remaining_uses": grant["max_uses"] - grant["uses"]})
            return {"credentials": results}

    def use(self, token, grant_id, rid):
        with self.state.transaction() as db:
            client = self.state.authenticate(db, token)
            grant = self.state.authorized(db, client, grant_id)
            old = db.execute("SELECT * FROM requests WHERE client=? AND request_id=?", (client["id"], rid)).fetchone()
            if old:
                if old["grant_id"] != grant_id:
                    raise GatewayError("REQUEST_CONFLICT")
                if old["result"]:
                    return {**json.loads(old["result"]), "replayed": True}
                return {"request_id": rid, "status": "EFFECT_UNKNOWN", "retry_allowed": False, "replayed": True}
            if grant["uses"] >= grant["max_uses"]:
                raise GatewayError("GRANT_EXHAUSTED")
            operation = json.loads(grant["config"])
            secret = self.provider.resolve(operation["credential"])
            validate_secret(secret.value)
            if not hmac.compare_digest(secret.revision, grant["credential_revision"]):
                raise GatewayError("CREDENTIAL_CHANGED")
            db.execute("UPDATE grants SET uses=uses+1 WHERE id=?", (grant_id,))
            db.execute("INSERT INTO requests(client,request_id,grant_id,operation,state,created) VALUES(?,?,?,?,?,?)",
                       (client["id"], rid, grant_id, grant["operation"], "COMMITTED", time.time()))
            self.state.event(db, "USE_COMMITTED", client["id"], rid)
        # Commit is the authorization cutoff. Revocation stops future reservations,
        # not an already accepted/in-flight network request. No automatic retries.
        result = {"request_id": rid, "status": "EFFECT_UNKNOWN", "retry_allowed": False, "replayed": False}
        try:
            payload = self.transport.get(operation, secret.value)
            result["data"] = project_output(payload, operation["output"], secret.value)
            result["status"] = "SUCCEEDED"
        except GatewayError as exc:
            # Closed error vocabulary: provider/transport exception details never escape.
            permitted = {"OUTPUT_REJECTED", "REDIRECT_DENIED", "UPSTREAM_REJECTED", "DESTINATION_DENIED", "DESTINATION_UNAVAILABLE"}
            result["status"] = exc.code if exc.code in permitted else "EFFECT_UNKNOWN"
        except Exception:
            pass
        finally:
            del secret
        # If this transaction fails, COMMITTED remains durable and cannot re-send.
        with self.state.transaction() as db:
            db.execute("UPDATE requests SET state=?, result=? WHERE client=? AND request_id=?",
                       (result["status"], canonical(result), client["id"], rid))
            self.state.event(db, "USE_" + result["status"], client["id"], rid)
        return result

    def status(self, token, rid):
        with self.state.transaction() as db:
            client = self.state.authenticate(db, token)
            row = db.execute("SELECT state FROM requests WHERE client=? AND request_id=?", (client["id"], rid)).fetchone()
            if not row:
                raise GatewayError("NOT_FOUND")
            state = "EFFECT_UNKNOWN" if row["state"] == "COMMITTED" else row["state"]
            # Metadata only; this remains usable after an individual grant expires.
            return {"request_id": rid, "status": state, "retry_allowed": False}
