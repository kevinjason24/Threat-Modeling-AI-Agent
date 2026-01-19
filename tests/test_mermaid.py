"""Tests for Mermaid diagram generation."""


from app.render_mermaid import (
    render_mermaid_dfd,
    render_mermaid_simple,
    validate_mermaid_dfd,
    _render_node,
    _sanitize_label,
)
from app.schemas import DFDModel, DFDNode, DFDFlow, NodeType, TrustBoundary


class TestRenderMermaidDFD:
    """Tests for Mermaid DFD rendering."""

    def create_simple_dfd(self) -> DFDModel:
        """Create a simple DFD for testing."""
        return DFDModel(
            nodes=[
                DFDNode(id="EE_User", label="User", type=NodeType.EXTERNAL_ENTITY),
                DFDNode(id="P_API", label="API Server", type=NodeType.PROCESS),
                DFDNode(id="DS_DB", label="Database", type=NodeType.DATA_STORE),
            ],
            flows=[
                DFDFlow(
                    id="F001",
                    src="EE_User",
                    dst="P_API",
                    data="HTTP Request",
                    protocol="HTTPS",
                    auth="JWT",
                ),
                DFDFlow(
                    id="F002",
                    src="P_API",
                    dst="DS_DB",
                    data="SQL Query",
                    protocol="TCP",
                    auth="Connection String",
                ),
            ],
        )

    def test_starts_with_graph_td(self):
        """Test that output starts with graph TD."""
        dfd = self.create_simple_dfd()
        result = render_mermaid_dfd(dfd)
        assert result.startswith("graph TD")

    def test_contains_all_nodes(self):
        """Test that all nodes are in the output."""
        dfd = self.create_simple_dfd()
        result = render_mermaid_dfd(dfd)
        assert "EE_User" in result
        assert "P_API" in result
        assert "DS_DB" in result

    def test_contains_flows(self):
        """Test that flows are rendered."""
        dfd = self.create_simple_dfd()
        result = render_mermaid_dfd(dfd)
        assert "EE_User" in result
        assert "P_API" in result
        assert "HTTP Request" in result or "HTTPS" in result

    def test_styling_classes(self):
        """Test that styling classes are defined."""
        dfd = self.create_simple_dfd()
        result = render_mermaid_dfd(dfd)
        assert "classDef external" in result
        assert "classDef process" in result
        assert "classDef datastore" in result

    def test_class_assignments(self):
        """Test that nodes are assigned to correct classes."""
        dfd = self.create_simple_dfd()
        result = render_mermaid_dfd(dfd)
        assert "class EE_User external" in result
        assert "class P_API process" in result
        assert "class DS_DB datastore" in result

    def test_with_trust_boundaries(self):
        """Test rendering with trust boundaries as subgraphs."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="EE_User", label="User", type=NodeType.EXTERNAL_ENTITY),
                DFDNode(id="P_API", label="API", type=NodeType.PROCESS, trust_boundary="TB1"),
            ],
            flows=[
                DFDFlow(id="F001", src="EE_User", dst="P_API", data="Request"),
            ],
            trust_boundaries=[
                TrustBoundary(id="TB1", name="DMZ", components_inside=["P_API"]),
            ],
        )
        result = render_mermaid_dfd(dfd)
        assert "subgraph TB1" in result
        assert "DMZ" in result

    def test_encrypted_flow_arrow(self):
        """Test that encrypted flows use thick arrows."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="P_A", label="A", type=NodeType.PROCESS),
                DFDNode(id="P_B", label="B", type=NodeType.PROCESS),
            ],
            flows=[
                DFDFlow(id="F001", src="P_A", dst="P_B", data="Data", encrypted=True),
            ],
        )
        result = render_mermaid_dfd(dfd)
        assert "==>" in result  # Thick arrow for encrypted


class TestRenderMermaidSimple:
    """Tests for simplified Mermaid rendering."""

    def test_no_subgraphs(self):
        """Test that simple render doesn't use subgraphs."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="P_A", label="A", type=NodeType.PROCESS, trust_boundary="TB1"),
            ],
            flows=[],
            trust_boundaries=[
                TrustBoundary(id="TB1", name="Zone"),
            ],
        )
        result = render_mermaid_simple(dfd)
        assert "subgraph" not in result


class TestRenderNode:
    """Tests for individual node rendering."""

    def test_external_entity_shape(self):
        """Test External Entity uses stadium shape."""
        node = DFDNode(id="EE_User", label="User", type=NodeType.EXTERNAL_ENTITY)
        result = _render_node(node)
        assert '(["User"])' in result

    def test_process_shape(self):
        """Test Process uses rectangle shape."""
        node = DFDNode(id="P_API", label="API", type=NodeType.PROCESS)
        result = _render_node(node)
        assert '["API"]' in result

    def test_data_store_shape(self):
        """Test Data Store uses cylinder shape."""
        node = DFDNode(id="DS_DB", label="Database", type=NodeType.DATA_STORE)
        result = _render_node(node)
        assert '[("Database")]' in result


class TestSanitizeLabel:
    """Tests for label sanitization."""

    def test_replaces_quotes(self):
        """Test that double quotes are replaced."""
        result = _sanitize_label('Say "Hello"')
        assert '"' not in result
        assert "'" in result

    def test_replaces_brackets(self):
        """Test that brackets are replaced."""
        result = _sanitize_label("Array[0]")
        assert "[" not in result
        assert "]" not in result

    def test_replaces_pipes(self):
        """Test that pipes are replaced."""
        result = _sanitize_label("A | B")
        assert "|" not in result

    def test_truncates_long_labels(self):
        """Test that long labels are truncated."""
        long_label = "A" * 100
        result = _sanitize_label(long_label)
        assert len(result) <= 50
        assert "..." in result

    def test_removes_newlines(self):
        """Test that newlines are replaced."""
        result = _sanitize_label("Line 1\nLine 2")
        assert "\n" not in result


class TestValidateMermaidDFD:
    """Tests for Mermaid validation."""

    def test_valid_diagram_no_issues(self):
        """Test that a valid diagram has no issues."""
        diagram = """graph TD
    A[Node A]
    B[Node B]
    A --> B
"""
        issues = validate_mermaid_dfd(diagram)
        assert len(issues) == 0

    def test_missing_graph_declaration(self):
        """Test detection of missing graph declaration."""
        diagram = """A[Node A]
    B[Node B]
"""
        issues = validate_mermaid_dfd(diagram)
        assert any("graph" in i.lower() for i in issues)

    def test_empty_diagram(self):
        """Test detection of empty diagram."""
        issues = validate_mermaid_dfd("")
        assert len(issues) > 0  # Should have some issue

    def test_unbalanced_brackets(self):
        """Test detection of unbalanced brackets."""
        diagram = """graph TD
    A[Node A
    B[Node B]
"""
        issues = validate_mermaid_dfd(diagram)
        assert any("bracket" in i.lower() for i in issues)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_dfd(self):
        """Test rendering an empty DFD."""
        dfd = DFDModel(nodes=[], flows=[])
        result = render_mermaid_dfd(dfd)
        assert "graph TD" in result

    def test_nodes_without_flows(self):
        """Test rendering nodes without flows."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="P_A", label="A", type=NodeType.PROCESS),
                DFDNode(id="P_B", label="B", type=NodeType.PROCESS),
            ],
            flows=[],
        )
        result = render_mermaid_dfd(dfd)
        assert "P_A" in result
        assert "P_B" in result

    def test_special_characters_in_labels(self):
        """Test handling of special characters in labels."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="P_A", label="API (v2.0) <beta>", type=NodeType.PROCESS),
            ],
            flows=[],
        )
        result = render_mermaid_dfd(dfd)
        # Should not contain raw < or > which break Mermaid
        assert "<beta>" not in result

