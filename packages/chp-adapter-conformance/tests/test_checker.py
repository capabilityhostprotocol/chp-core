

class TestUndeclaredEmit:
    """Declared emits is a contract (governance §4.4)."""

    def _violations(self, src, tmp_path):
        f = tmp_path / "adapter_src.py"
        f.write_text(src)
        from chp_adapter_conformance.checker import check_source_file
        return [v for v in check_source_file(f) if v.rule == "undeclared_emit"]

    def test_undeclared_bare_emit_is_flagged(self, tmp_path):
        src = (
            "@capability(id='x.y', version='1.0.0', description='', emits=['a_done'])\n"
            "async def y(self, ctx, payload):\n"
            "    ctx.emit('surprise_event', {})\n"
        )
        vs = self._violations(src, tmp_path)
        assert len(vs) == 1 and "surprise_event" in vs[0].message

    def test_declared_lifecycle_and_namespaced_pass(self, tmp_path):
        src = (
            "@capability(id='x.y', version='1.0.0', description='', emits=['a_done'])\n"
            "async def y(self, ctx, payload):\n"
            "    ctx.emit('a_done', {})\n"
            "    ctx.emit('execution_started', {})\n"
            "    ctx.emit('com.acme.custom', {})\n"
        )
        assert self._violations(src, tmp_path) == []

    def test_module_level_emits_var_resolves(self, tmp_path):
        src = (
            "_EMITS = ['a_done', 'b_done']\n"
            "@capability(id='x.y', version='1.0.0', description='', emits=_EMITS)\n"
            "async def y(self, ctx, payload):\n"
            "    ctx.emit('b_done', {})\n"
            "    ctx.emit('rogue', {})\n"
        )
        vs = self._violations(src, tmp_path)
        assert len(vs) == 1 and "rogue" in vs[0].message

    def test_no_declaration_means_no_contract(self, tmp_path):
        src = (
            "@capability(id='x.y', version='1.0.0', description='')\n"
            "async def y(self, ctx, payload):\n"
            "    ctx.emit('anything_goes', {})\n"
        )
        assert self._violations(src, tmp_path) == []
