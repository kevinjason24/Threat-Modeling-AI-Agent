"""Mermaid diagram generator for Data Flow Diagrams."""

from .schemas import DFDModel, NodeType


def render_mermaid_dfd(dfd: DFDModel) -> str:
    """Render a DFD model as a Mermaid diagram.

    Args:
        dfd: The DFD model to render.

    Returns:
        Mermaid diagram string.
    """
    lines = ["graph TD"]

    # Group nodes by trust boundary
    boundary_nodes: dict[str | None, list[str]] = {None: []}
    for boundary in dfd.trust_boundaries:
        boundary_nodes[boundary.id] = []

    for node in dfd.nodes:
        boundary_id = node.trust_boundary
        if boundary_id not in boundary_nodes:
            boundary_id = None
        boundary_nodes[boundary_id].append(node.id)

    # Render trust boundaries as subgraphs
    for boundary in dfd.trust_boundaries:
        if boundary.id in boundary_nodes and boundary_nodes[boundary.id]:
            # Sanitize boundary name for Mermaid
            safe_name = _sanitize_label(boundary.name)
            lines.append(f"    subgraph {boundary.id}[{safe_name}]")

            # Render nodes inside this boundary
            for node_id in boundary_nodes[boundary.id]:
                node = next((n for n in dfd.nodes if n.id == node_id), None)
                if node:
                    lines.append(f"        {_render_node(node)}")

            lines.append("    end")
            lines.append("")

    # Render nodes without trust boundary
    if boundary_nodes[None]:
        for node_id in boundary_nodes[None]:
            node = next((n for n in dfd.nodes if n.id == node_id), None)
            if node:
                lines.append(f"    {_render_node(node)}")
        lines.append("")

    # Render flows
    for flow in dfd.flows:
        flow_label = _sanitize_label(flow.data)
        if flow.protocol and flow.protocol != "Unknown":
            flow_label = f"{flow.protocol}: {flow_label}"

        # Use different arrow styles based on properties
        if flow.encrypted:
            arrow = "==>"  # Thick arrow for encrypted
        elif flow.crosses_boundary:
            arrow = "-.->'"  # Dotted arrow for boundary crossing
        else:
            arrow = "-->"  # Standard arrow

        lines.append(f"    {flow.src} {arrow}|{flow_label}| {flow.dst}")

    # Add styling
    lines.append("")
    lines.append("    %% Styling")
    lines.append("    classDef external fill:#f9f,stroke:#333,stroke-width:2px")
    lines.append("    classDef process fill:#bbf,stroke:#333,stroke-width:2px")
    lines.append("    classDef datastore fill:#bfb,stroke:#333,stroke-width:2px")

    # Apply classes to nodes
    external_nodes = [n.id for n in dfd.nodes if n.type == NodeType.EXTERNAL_ENTITY]
    process_nodes = [n.id for n in dfd.nodes if n.type == NodeType.PROCESS]
    datastore_nodes = [n.id for n in dfd.nodes if n.type == NodeType.DATA_STORE]

    if external_nodes:
        lines.append(f"    class {','.join(external_nodes)} external")
    if process_nodes:
        lines.append(f"    class {','.join(process_nodes)} process")
    if datastore_nodes:
        lines.append(f"    class {','.join(datastore_nodes)} datastore")

    return "\n".join(lines)


def _render_node(node) -> str:
    """Render a single node with appropriate shape.

    Node shapes in Mermaid:
    - External Entity: Stadium shape (([label]))
    - Process: Rectangle ([label])
    - Data Store: Cylinder [(label)]
    """
    label = _sanitize_label(node.label)

    if node.type == NodeType.EXTERNAL_ENTITY:
        return f'{node.id}(["{label}"])'
    elif node.type == NodeType.PROCESS:
        return f'{node.id}["{label}"]'
    elif node.type == NodeType.DATA_STORE:
        return f'{node.id}[("{label}")]'
    else:
        return f'{node.id}["{label}"]'


def _sanitize_label(label: str) -> str:
    """Sanitize a label for use in Mermaid.

    Mermaid has issues with certain characters in labels.
    """
    # Replace problematic characters
    replacements = {
        '"': "'",
        "\n": " ",
        "\r": "",
        "[": "(",
        "]": ")",
        "{": "(",
        "}": ")",
        "|": "/",
        "<": "‹",
        ">": "›",
    }

    result = label
    for old, new in replacements.items():
        result = result.replace(old, new)

    # Truncate if too long
    max_length = 50
    if len(result) > max_length:
        result = result[: max_length - 3] + "..."

    return result


def render_mermaid_simple(dfd: DFDModel) -> str:
    """Render a simplified DFD without subgraphs (more compatible).

    Args:
        dfd: The DFD model to render.

    Returns:
        Mermaid diagram string.
    """
    lines = ["graph TD"]

    # Render all nodes
    for node in dfd.nodes:
        lines.append(f"    {_render_node(node)}")

    lines.append("")

    # Render flows
    for flow in dfd.flows:
        flow_label = _sanitize_label(flow.data)
        lines.append(f"    {flow.src} -->|{flow_label}| {flow.dst}")

    # Add styling
    lines.append("")
    lines.append("    %% Styling")
    lines.append("    classDef external fill:#f9f,stroke:#333,stroke-width:2px")
    lines.append("    classDef process fill:#bbf,stroke:#333,stroke-width:2px")
    lines.append("    classDef datastore fill:#bfb,stroke:#333,stroke-width:2px")

    external_nodes = [n.id for n in dfd.nodes if n.type == NodeType.EXTERNAL_ENTITY]
    process_nodes = [n.id for n in dfd.nodes if n.type == NodeType.PROCESS]
    datastore_nodes = [n.id for n in dfd.nodes if n.type == NodeType.DATA_STORE]

    if external_nodes:
        lines.append(f"    class {','.join(external_nodes)} external")
    if process_nodes:
        lines.append(f"    class {','.join(process_nodes)} process")
    if datastore_nodes:
        lines.append(f"    class {','.join(datastore_nodes)} datastore")

    return "\n".join(lines)


def validate_mermaid_dfd(mermaid_str: str) -> list[str]:
    """Basic validation of Mermaid DFD syntax.

    Args:
        mermaid_str: The Mermaid diagram string.

    Returns:
        List of validation warnings/errors.
    """
    issues = []

    lines = mermaid_str.strip().split("\n")

    if not lines:
        issues.append("Empty diagram")
        return issues

    # Check for graph declaration
    if not lines[0].strip().startswith("graph"):
        issues.append("Missing 'graph' declaration at start")

    # Check for unbalanced brackets
    full_text = mermaid_str
    brackets = {"[": "]", "(": ")", "{": "}"}
    for open_b, close_b in brackets.items():
        if full_text.count(open_b) != full_text.count(close_b):
            issues.append(f"Unbalanced brackets: {open_b}{close_b}")

    # Check for empty subgraphs
    if "subgraph" in mermaid_str:
        # Simple check - look for subgraph immediately followed by end
        import re
        empty_subgraph = re.search(r"subgraph\s+\w+\[.*?\]\s*\n\s*end", mermaid_str)
        if empty_subgraph:
            issues.append("Empty subgraph detected")

    return issues



