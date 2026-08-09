"""State persistence + orphan cleanup."""
from hehua.orchestrate.state import RUNNING, SOLVED, State


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    st = State.load(p)
    cs = st.get("CH-1")
    cs.status = SOLVED
    cs.flags = 1
    st.save()
    st2 = State.load(p)
    assert st2.get("CH-1").status == SOLVED
    assert st2.get("CH-1").flags == 1


def test_orphan_cleanup(tmp_path):
    class FakeLife:
        closed = []

        def close_challenge(self, code):
            self.closed.append(code)
            return type("C", (), {"closed": True})()

    st = State.load(tmp_path / "s.json")
    st.get("CH-R").status = RUNNING
    from hehua.orchestrate.lifecycle import Lifecycle
    life = Lifecycle(FakeLife())
    life.cleanup_orphans(st)
    assert st.get("CH-R").status == "pending"
    assert life.client.closed == ["CH-R"]
