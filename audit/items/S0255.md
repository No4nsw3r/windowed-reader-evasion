---
name: core-algorithms
description: Key algorithms in OpenAPI LSP - Solver (Union-Find equivalence classes), Root Discovery (glob-based workspace scanning), Nominal Propagation (fixed-point iteration within SCCs), and Kosaraju's SCC algorithm. Reference when working on analysis, type resolution, or dependency tracking.
---

# Core Algorithms in OpenAPI LSP

This skill documents the four key algorithms that power the OpenAPI LSP's cross-file analysis system.

## 1. Solver Algorithm (Union-Find Equivalence Classes)

**Location:** `packages/core/src/solver/Solver.ts:135-235`

**Purpose:** Build equivalence classes from nodes connected via `$ref` and propagate nominal types (Schema, Response, Parameter, etc.) through those classes.

### Problem Solved
In multi-file OpenAPI specs, the same logical schema may be referenced multiple ways. The solver unifies all nodes pointing to the same concept and ensures they receive consistent nominal types.

### Algorithm Steps

1. **Initialize Union-Find** - Create singleton sets for each node
2. **Union Ref-Connected Nodes** - For each `$ref`, union the referencing node with its target
3. **Extract Components** - Get connected components as equivalence classes
4. **Assign Nominals** - Propagate nominal types within each class, detect conflicts

### Key Data Structures

```typescript
// Input
type SolverInput = {
  nodes: Map<NodeId, LocalShape>;      // All nodes with structure
  nominals: Map<NodeId, NominalId[]>;  // Type anchor points
};

// Output
type Class = {
  id: ClassId;
  nodes: Set<NodeId>;        // All nodes in equivalence class
  nominal: NominalId | null; // Canonical type for the class
};
```

### Union-Find Helper
`packages/core/src/solver/union-find.ts` - Uses path compression and union by rank for O(α(n)) amortized operations.

---

## 2. Root Discovery Algorithm

**Location:** `packages/server/src/analysis/AnalysisManager.ts:93-135`

**Purpose:** Discover all OpenAPI root files in the workspace using glob patterns, then recursively find all referenced documents.

### Glob Patterns (from `packages/core/src/constants/index.ts`)
- `*.openapi.yml`, `*.openapi.yaml`
- `openapi.yml`, `openapi.yaml`

### Algorithm Steps

1. **Enumerate Workspace Folders** - Iterate through VS Code workspace folders
2. **Glob Pattern Matching** - Search recursively with `**/${pattern}`, apply ignore patterns
3. **Convert to URIs** - Transform file paths to `file://` URIs
4. **DFS Connectivity** - For each root, traverse all `$ref` targets

### DFS Traversal (lines 298-330)

```typescript
private async dfsConnectivity(ctx, dc, uri): Promise<void> {
  // 1. Create entry in dc.graph for this URI
  // 2. Load document (skip if tomb/unreadable)
  // 3. Get all $ref targets via referenceManager
  // 4. For each external ref: add to neighbors, recurse if unvisited
}
```

### Output Structure

```typescript
type DocumentConnectivity = {
  graph: Map<string, Set<string>>;           // URI → Referenced URIs
  analysisGroups: Map<string, Set<string>>;  // SCC groupings
  uriToAnalysisGroupId: Map<string, string>; // URI → Group ID
  groupIncomingEdges: Map<string, Set<string>>; // Group → Upstream Groups
};
```

---

## 3. Nominal Propagation with Fixed-Point

**Location:** `packages/server/src/analysis/AnalysisManager.ts:213-295`

**Purpose:** Within SCCs (circular file references), propagate nominal types iteratively until all nodes receive consistent type information.

### Problem Solved
In SCCs, documents reference each other in cycles. A single-pass analysis misses types that flow through multiple hops. Fixed-point iteration ensures types propagate through all paths.

### Algorithm Steps

1. **Initialize Entry Points** - Load incoming nominals from upstream SCCs, mark roots with "Document"
2. **Track Processing State** - `processedEntryPoints` Set prevents reprocessing `"${nodeId}\0${nominal}"` pairs
3. **Fixed-Point Loop**:
   ```
   while pendingEntryPoints is non-empty:
     currentBatch = copy of pendingEntryPoints
     clear pendingEntryPoints
     for each entry point:
       collect nominals via visitor traversal
       for outgoing nominals targeting within-SCC nodes:
         if not processed: add to pendingEntryPoints
   ```
4. **Merge Results** - Combine all discovered nominals for Solver input

### Termination Guarantee
- Finite (nodeId, nominal) pairs in SCC
- Each pair processed at most once
- Guaranteed O(|nodes| × |nominalsPerNode|) iterations

### Example: Ring Reference

```
OpenAPI → A.yaml (schema ref) → B.yaml → C.yaml → A.yaml (cycle)

Iteration 1: Process "Document" at root → discover "Schema" for A
Iteration 2: Process "Schema" at A → discover "Schema" for B
Iteration 3: Process "Schema" at B → discover "Schema" for C
Iteration 4: Process "Schema" at C → A already processed, terminate
```

---

## 4. Kosaraju's SCC Algorithm

**Location:** `packages/server/src/analysis/AnalysisManager.ts:332-435`

**Purpose:** Identify Strongly Connected Components (groups of mutually reachable documents) for proper analysis ordering and cycle handling.

### Algorithm Steps

1. **First DFS for Finish Order** (lines 340-355)
   - Standard DFS pushing vertices in post-order
   - Creates ordering for transposed graph traversal

2. **Build Transposed Graph** (lines 357-366)
   - Reverse all edge directions

3. **Second DFS on Transposed Graph** (lines 368-396)
   - Process vertices in reverse finish order
   - Each DFS tree is one SCC

4. **Collect Inter-SCC Edges** (lines 398-409)
   - Record edges crossing SCC boundaries

5. **Populate Results** (lines 411-434)
   - Map SCC indices to group IDs (smallest URI)
   - Build `groupIncomingEdges` for topological ordering

### Complexity
O(V + E) where V = documents, E = references

---

## Algorithm Data Flow

```
Root Discovery (glob for *.openapi.yml)
         ↓
DFS Connectivity (build reference graph)
         ↓
Kosaraju's Algorithm (identify SCCs)
         ↓
Topological Sort (order SCCs by dependencies)
         ↓
For each SCC in order:
    Fixed-Point Nominal Propagation
         ↓
    Solver (build equivalence classes)
         ↓
    Type Resolution & Language Features
```

## Summary Table

| Algorithm | Location | Purpose | Complexity |
|-----------|----------|---------|------------|
| Solver | `Solver.ts:135-235` | Equivalence classes via Union-Find | O(α(n)) per union |
| Root Discovery | `AnalysisManager.ts:93-135` | Find all OpenAPI files | O(F × S + E) |
| Fixed-Point | `AnalysisManager.ts:213-295` | Propagate nominals in cycles | O(\|nodes\| × \|nominals\|) |
| Kosaraju SCC | `AnalysisManager.ts:332-435` | Find circular dependencies | O(V + E) |
