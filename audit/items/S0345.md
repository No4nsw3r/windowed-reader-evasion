---
name: nushell-http-api
description: This skill should be used when the user asks to "make HTTP requests in Nushell", "call an API", "fetch data from URL", "POST JSON data", "handle webhooks", "work with REST APIs", "authenticate API calls", "parse API responses", or mentions http get, http post, web requests, REST, or API integration in Nushell.
version: 1.0.0
---

# Nushell HTTP & API Integration

Comprehensive guide for making HTTP requests, integrating with REST APIs, and handling webhooks in Nushell. Native HTTP commands return structured data, making API responses immediately usable in pipelines.

## HTTP Commands Overview

| Command | Description |
|---------|-------------|
| `http get` | GET request, returns parsed response |
| `http post` | POST with body |
| `http put` | PUT request |
| `http patch` | PATCH request |
| `http delete` | DELETE request |
| `http head` | HEAD request (headers only) |
| `http options` | OPTIONS request |

## Basic Requests

### GET Requests

```nushell
# Simple GET - auto-parses JSON
http get https://api.example.com/users

# With query parameters
http get $"https://api.example.com/search?q=($query)&limit=10"

# Access response fields directly
http get https://api.example.com/user/1 | get name
```

### POST Requests

```nushell
# POST JSON body
http post https://api.example.com/users {
    name: "Alice"
    email: "alice@example.com"
}

# POST with content type
http post --content-type application/json https://api.example.com/data {
    key: "value"
}

# POST form data
http post --content-type application/x-www-form-urlencoded https://api.example.com/form $"username=($user)&password=($pass)"
```

### Other Methods

```nushell
# PUT (replace resource)
http put https://api.example.com/users/1 {name: "Updated Name"}

# PATCH (partial update)
http patch https://api.example.com/users/1 {status: "active"}

# DELETE
http delete https://api.example.com/users/1
```

## Headers and Authentication

### Custom Headers

```nushell
# Single header
http get https://api.example.com/data -H {Accept: "application/json"}

# Multiple headers
http get https://api.example.com/data -H {
    Accept: "application/json"
    X-Request-ID: (random uuid)
    User-Agent: "nushell-client/1.0"
}
```

### Authentication Patterns

```nushell
# Bearer token
http get https://api.example.com/protected -H {
    Authorization: $"Bearer ($env.API_TOKEN)"
}

# Basic auth
let auth = [$username, $password] | str join ":" | encode base64
http get https://api.example.com/data -H {
    Authorization: $"Basic ($auth)"
}

# API key in header
http get https://api.example.com/data -H {
    X-API-Key: $env.API_KEY
}

# API key in query string
http get $"https://api.example.com/data?api_key=($env.API_KEY)"
```

### Secure Token Management

```nushell
# Load from environment
def api-client [] {
    let token = $env.API_TOKEN? | default (
        error make { msg: "API_TOKEN environment variable not set" }
    )

    {
        headers: {Authorization: $"Bearer ($token)"}
        base_url: "https://api.example.com"
    }
}

# Use client
let client = api-client
http get $"($client.base_url)/users" -H $client.headers
```

## Request Configuration

### Timeouts

```nushell
# Set timeout (default: no timeout)
http get https://api.example.com/slow --max-time 30sec
```

### Redirects

```nushell
# Follow redirects (default: true)
http get https://example.com --redirect-mode follow

# Don't follow redirects
http get https://example.com --redirect-mode manual
```

### Error Handling

```nushell
# Handle HTTP errors
try {
    http get https://api.example.com/resource
} catch { |err|
    if ($err.msg | str contains "404") {
        print "Resource not found"
    } else {
        error make { msg: $"API error: ($err.msg)" }
    }
}

# Check status before processing
def safe-fetch [url: string] {
    let response = do { http get $url --full } | complete

    if $response.exit_code != 0 {
        error make { msg: $"Request failed: ($response.stderr)" }
    }

    $response.stdout
}
```

## Response Handling

### Parsing Responses

```nushell
# JSON (automatic)
http get https://api.example.com/data
| get items
| where active == true

# XML
http get https://api.example.com/feed.xml
| from xml
| get rss.channel.item

# Raw text
http get https://example.com/page.html --raw
| lines
| where { |line| $line | str contains "keyword" }
```

### Streaming Responses

```nushell
# Large file download
http get https://example.com/large-file.zip | save file.zip

# Stream JSON lines
http get https://api.example.com/stream --raw
| lines
| each { |line| $line | from json }
```

## Pagination

### Offset-Based

```nushell
def fetch-all-pages [base_url: string, --page-size: int = 100] {
    mut all_items = []
    mut offset = 0

    loop {
        let url = $"($base_url)?limit=($page_size)&offset=($offset)"
        let response = http get $url

        let items = $response | get items
        $all_items = $all_items ++ $items

        if ($items | length) < $page_size {
            break
        }

        $offset = $offset + $page_size
    }

    $all_items
}
```

### Cursor-Based

```nushell
def fetch-with-cursor [base_url: string] {
    mut all_items = []
    mut cursor = null

    loop {
        let url = if $cursor == null {
            $base_url
        } else {
            $"($base_url)?cursor=($cursor)"
        }

        let response = http get $url
        $all_items = $all_items ++ ($response | get data)

        if ($response | get has_more) == false {
            break
        }

        $cursor = $response | get next_cursor
    }

    $all_items
}
```

### Link Header Navigation

```nushell
# GitHub-style pagination
def fetch-github-pages [url: string] {
    mut all_items = []
    mut next_url = $url

    while $next_url != null {
        # Note: Would need to parse Link header from full response
        let items = http get $next_url
        $all_items = $all_items ++ $items

        # Parse next page URL from Link header
        # Implementation depends on API
        $next_url = null  # Placeholder
    }

    $all_items
}
```

## Rate Limiting

### Simple Throttle

```nushell
def throttled-fetch [urls: list<string>, --delay: duration = 100ms] {
    $urls | each { |url|
        let result = http get $url
        sleep $delay
        $result
    }
}
```

### Exponential Backoff

```nushell
def fetch-with-backoff [url: string, --max-retries: int = 5] {
    mut delay = 1sec

    for attempt in 1..=$max_retries {
        try {
            return (http get $url)
        } catch { |err|
            if $attempt == $max_retries {
                error make { msg: $"Failed after ($max_retries) attempts: ($err.msg)" }
            }

            if ($err.msg | str contains "429") {
                print $"Rate limited, waiting ($delay)..."
                sleep $delay
                $delay = $delay * 2
            } else {
                error make { msg: $err.msg }
            }
        }
    }
}
```

## API Client Patterns

### Reusable Client Function

```nushell
# Define API client
def github-api [
    endpoint: string
    --method: string = "GET"
    --body: any = null
] {
    let base = "https://api.github.com"
    let headers = {
        Accept: "application/vnd.github.v3+json"
        Authorization: $"Bearer ($env.GITHUB_TOKEN)"
    }

    match $method {
        "GET" => { http get $"($base)($endpoint)" -H $headers }
        "POST" => { http post $"($base)($endpoint)" $body -H $headers }
        "PUT" => { http put $"($base)($endpoint)" $body -H $headers }
        "DELETE" => { http delete $"($base)($endpoint)" -H $headers }
    }
}

# Usage
github-api "/user/repos" | select name description
github-api "/repos/owner/repo/issues" --method POST --body {title: "Bug", body: "Details"}
```

### Request Builder

```nushell
# Fluent-style request building
def request [] {
    {
        method: "GET"
        url: ""
        headers: {}
        body: null
        timeout: 30sec
    }
}

def "request method" [m: string] {
    $in | update method $m
}

def "request url" [u: string] {
    $in | update url $u
}

def "request header" [key: string, value: string] {
    $in | update headers { |r| $r.headers | insert $key $value }
}

def "request body" [b: any] {
    $in | update body $b
}

def "request send" [] {
    let req = $in
    match $req.method {
        "GET" => { http get $req.url -H $req.headers --max-time $req.timeout }
        "POST" => { http post $req.url $req.body -H $req.headers --max-time $req.timeout }
    }
}

# Usage
request
| request url "https://api.example.com/data"
| request header "Authorization" $"Bearer ($token)"
| request send
```

## Webhooks

### Receiving Webhooks

```nushell
# Parse webhook payload
def handle-webhook [payload: string] {
    let data = $payload | from json

    match $data.event {
        "push" => { handle-push $data }
        "pull_request" => { handle-pr $data }
        _ => { print $"Unknown event: ($data.event)" }
    }
}
```

### Sending Webhooks

```nushell
# Send notification
def notify-slack [message: string, --channel: string = "#general"] {
    http post $env.SLACK_WEBHOOK_URL {
        channel: $channel
        text: $message
        username: "Nushell Bot"
    }
}
```

## Additional Resources

### Reference Files

For detailed patterns and advanced techniques:
- **`references/auth-patterns.md`** - Authentication strategies
- **`references/error-codes.md`** - HTTP status code handling

### Example Files

Working examples in `examples/`:
- **`github-client.nu`** - Complete GitHub API client
- **`webhook-handler.nu`** - Webhook processing example
- **`batch-requests.nu`** - Parallel API requests
