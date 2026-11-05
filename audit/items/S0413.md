---
name: ms-mcp
description: |
  Use when integrating Model Context Protocol (MCP) servers with Microsoft Agent Framework agents.
  Triggers: "MCP integration", "MCP tools", "MCP server", "Model Context Protocol", "agent MCP".
  NOT for: Non-MCP tool integrations or direct API calls.
---

# Microsoft Agent MCP Integration

Expert guidance for integrating Model Context Protocol (MCP) servers with agents.

## What is MCP?

Model Context Protocol (MCP) is a standardized way for AI models to interact with external tools and data sources. Microsoft Agent Framework provides first-class MCP support.

## Quick Start

### Using MCP Tools in Agents

```python
from agent_framework import ChatAgent
from agent_framework.mcp import MCPToolProvider

class MCPEnabledAgent(ChatAgent):
    """Agent with MCP tools."""

    system_prompt = "You are an assistant with access to external tools."

    # Add MCP tool providers
    tools = [
        MCPToolProvider("filesystem"),  # File system operations
        MCPToolProvider("github"),       # GitHub operations
        MCPToolProvider("slack"),        # Slack messaging
    ]
```

### MCP Server Configuration

```python
from agent_framework.mcp import MCPServer, MCPConfig

# Configure MCP server connections
config = MCPConfig(
    servers={
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@anthropic/mcp-filesystem"],
            "env": {
                "ALLOWED_PATHS": "/home/user/documents"
            }
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@anthropic/mcp-github"],
            "env": {
                "GITHUB_TOKEN": "${GITHUB_TOKEN}"
            }
        },
        "custom": {
            "url": "http://localhost:3000/mcp",
            "transport": "http"
        }
    }
)
```

## MCP Tool Provider

### Basic Usage

```python
from agent_framework.mcp import MCPToolProvider

class MyAgent(ChatAgent):
    tools = [
        # Auto-discover all tools from MCP server
        MCPToolProvider("github"),

        # Or specify which tools to use
        MCPToolProvider(
            "github",
            include_tools=["create_issue", "list_repos", "create_pr"]
        ),

        # Or exclude specific tools
        MCPToolProvider(
            "filesystem",
            exclude_tools=["delete_file", "write_file"]
        )
    ]
```

### Tool Configuration

```python
from agent_framework.mcp import MCPToolProvider, ToolConfig

tools = [
    MCPToolProvider(
        "github",
        tool_configs={
            "create_issue": ToolConfig(
                requires_confirmation=True,
                description_override="Create a GitHub issue (requires approval)",
                timeout=30
            ),
            "list_repos": ToolConfig(
                cache_ttl=300  # Cache results for 5 minutes
            )
        }
    )
]
```

### Dynamic Tool Loading

```python
from agent_framework.mcp import MCPRegistry

class DynamicAgent(ChatAgent):
    async def on_initialize(self):
        # Register MCP servers at runtime
        self.mcp = MCPRegistry()

        await self.mcp.register("filesystem", {
            "command": "npx",
            "args": ["-y", "@anthropic/mcp-filesystem"]
        })

        await self.mcp.register("custom-api", {
            "url": "http://api.example.com/mcp"
        })

    @ai_function
    async def use_mcp_tool(self, server: str, tool: str, args: dict) -> str:
        """Dynamically call any MCP tool."""
        return await self.mcp.call(server, tool, args)
```

## Building MCP Servers

### Creating a Custom MCP Server

```python
from agent_framework.mcp import MCPServer, mcp_tool, mcp_resource

class CustomMCPServer(MCPServer):
    """Custom MCP server with tools and resources."""

    name = "custom-server"
    version = "1.0.0"

    @mcp_tool
    def search_database(self, query: str, limit: int = 10) -> list:
        """Search the internal database.

        Args:
            query: Search query string
            limit: Maximum results to return
        """
        return self.db.search(query, limit=limit)

    @mcp_tool
    def get_user(self, user_id: str) -> dict:
        """Get user details by ID."""
        return self.db.get_user(user_id)

    @mcp_resource("users/{user_id}")
    def user_resource(self, user_id: str) -> dict:
        """User resource endpoint."""
        return self.db.get_user(user_id)

    @mcp_resource("config")
    def config_resource(self) -> dict:
        """Server configuration resource."""
        return self.get_config()

# Run the server
if __name__ == "__main__":
    server = CustomMCPServer()
    server.run(transport="stdio")  # or "http", "sse"
```

### MCP Server with Authentication

```python
from agent_framework.mcp import MCPServer, mcp_tool
from agent_framework.mcp.auth import require_auth, APIKeyAuth

class SecureMCPServer(MCPServer):
    auth = APIKeyAuth(header="X-API-Key")

    @mcp_tool
    @require_auth
    def sensitive_operation(self, data: str) -> str:
        """Operation requiring authentication."""
        return process_sensitive(data)

    @mcp_tool  # No auth required
    def public_operation(self, data: str) -> str:
        """Public operation."""
        return process_public(data)
```

## MCP Resources

### Using Resources in Agents

```python
from agent_framework.mcp import MCPResourceProvider

class ResourceAgent(ChatAgent):
    resources = [
        MCPResourceProvider("filesystem"),
        MCPResourceProvider("database")
    ]

    async def get_context(self, query: str) -> str:
        """Fetch relevant context from MCP resources."""
        # List available resources
        resources = await self.mcp.list_resources("database")

        # Read a specific resource
        data = await self.mcp.read_resource(
            "database",
            "users/123"
        )

        return data
```

### Resource Subscriptions

```python
from agent_framework.mcp import MCPResourceProvider

class LiveAgent(ChatAgent):
    async def on_initialize(self):
        # Subscribe to resource changes
        await self.mcp.subscribe(
            "database",
            "orders/*",
            callback=self.on_order_change
        )

    async def on_order_change(self, resource_uri: str, data: dict):
        """Handle resource change notification."""
        print(f"Order updated: {resource_uri}")
        await self.process_order_update(data)
```

## Transport Options

### stdio Transport

```python
# Server
server = MCPServer()
server.run(transport="stdio")

# Client config
config = {
    "command": "python",
    "args": ["server.py"],
    "transport": "stdio"
}
```

### HTTP Transport

```python
# Server
server = MCPServer()
server.run(transport="http", host="0.0.0.0", port=3000)

# Client config
config = {
    "url": "http://localhost:3000/mcp",
    "transport": "http"
}
```

### SSE Transport

```python
# Server
server = MCPServer()
server.run(transport="sse", host="0.0.0.0", port=3000)

# Client config
config = {
    "url": "http://localhost:3000/mcp",
    "transport": "sse"
}
```

## Error Handling

```python
from agent_framework.mcp import (
    MCPError,
    MCPConnectionError,
    MCPToolError,
    MCPAuthError
)

class ResilientAgent(ChatAgent):
    tools = [MCPToolProvider("external-service")]

    async def on_mcp_error(self, error: MCPError):
        """Handle MCP errors."""
        if isinstance(error, MCPConnectionError):
            # Retry connection
            await self.reconnect_mcp()
        elif isinstance(error, MCPToolError):
            # Log tool failure
            self.logger.error(f"Tool failed: {error}")
        elif isinstance(error, MCPAuthError):
            # Refresh credentials
            await self.refresh_credentials()
```

## Best Practices

### 1. Security

```python
# Always validate MCP server sources
config = MCPConfig(
    servers={
        "trusted": {
            "command": "npx",
            "args": ["-y", "@verified/mcp-server"],
            # Restrict permissions
            "sandbox": True,
            "allowed_paths": ["/safe/directory"],
            "network_access": False
        }
    }
)
```

### 2. Performance

```python
# Enable caching for frequently used tools
tools = [
    MCPToolProvider(
        "database",
        cache_config={
            "enabled": True,
            "ttl": 300,
            "max_size": 1000
        }
    )
]
```

### 3. Observability

```python
# Enable MCP telemetry
from agent_framework.mcp import MCPConfig
from opentelemetry import trace

config = MCPConfig(
    telemetry={
        "enabled": True,
        "trace_tool_calls": True,
        "trace_resources": True
    }
)
```

## Related

- `ms-agent-types` skill - Agent implementation
- `ms-observability` skill - Telemetry integration
- [MCP Protocol Docs](https://modelcontextprotocol.io/)
- [Agent Framework MCP Guide](https://learn.microsoft.com/en-us/agent-framework/guides/mcp)
