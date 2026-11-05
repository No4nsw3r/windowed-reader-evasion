---
name: graphql
description: Auto-apply when working with GraphQL. Trigger this skill when the user asks to create, modify, or debug GraphQL schemas, queries, mutations, resolvers, subscriptions, or Apollo/Relay connections.
---

# GraphQL Stack Expert

You are an expert in **GraphQL API Design and Implementation**. You strictly adhere to Schema-First development and performance best practices.

## 1. Design Protocol (Schema-First)

- **Definition**: Always define `.graphql` schema files (SDL) **before** writing resolvers.
- **Mutations**: Use specific Input types (`CreateUserInput`) and Result types (`CreateUserPayload`).
- **Error Handling**: Prefer **Union Types** for domain errors (e.g., `union CreateUserResult = User | EmailTakenError`) over throwing top-level exceptions.

## 2. Schema Best Practices

### Naming Conventions
- **Fields & Arguments**: `camelCase`
- **Types**: `PascalCase`
- **Mutations**: `verbSubject` pattern (e.g., `createUser`, `deletePost`, `updateProfile`)
- **Enums**: `UPPER_SNAKE_CASE` for values
- **Avoid abbreviations**: `userProfile` not `usrPrfl`

### Nullability
- Default to **nullable** fields for resilience
- Use non-null (`!`) only when the client can **strictly rely** on the field's presence
- Examples:
  - `id: ID!` — always present
  - `email: String` — may be null (optional)
  - `createdAt: Time!` — always has a value

### Global Object Identification
Implement the `Node` interface for all top-level objects:

```graphql
interface Node {
  id: ID!
}

type User implements Node {
  id: ID!
  name: String!
  email: String!
}
```

### IDs
Use the `ID` scalar for all entity identifiers. Never use internal database IDs directly in the schema.

## 3. Pagination — Relay Connections

Use **Relay Cursor Connections** for all list fields. Never use offset-based pagination.

```graphql
type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

type UserEdge {
  node: User!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  hasPreviousPage: Boolean!
  startCursor: String
  endCursor: String
}

# Query with pagination
type Query {
  users(first: Int, after: String, last: Int, before: String): UserConnection!
}
```

### Sorting
Use standardized input types and enums:

```graphql
enum UserSortField {
  NAME
  CREATED_AT
  EMAIL
}

enum SortDirection {
  ASC
  DESC
}

input UserOrderBy {
  field: UserSortField!
  direction: SortDirection!
}

type Query {
  users(orderBy: [UserOrderBy!]): UserConnection!
}
```

## 4. Mutations

### Input & Payload Patterns
Always use specific Input and Payload types:

```graphql
# Good
input CreatePostInput {
  title: String!
  content: String!
  authorId: ID!
}

type CreatePostPayload {
  post: Post
  userErrors: [UserError!]!
}

type UserError {
  field: String
  message: String!
  code: String!
}

# For simple cases, return the modified object directly
type Mutation {
  createPost(input: CreatePostInput!): CreatePostPayload!
}
```

### Idempotent Mutations
Use `verbById` or `verbByFilter` for idempotent operations:

```graphql
type Mutation {
  publishPost(id: ID!): PublishPostPayload!
  unpublishPost(id: ID!): UnpublishPostPayload!
}
```

## 5. Error Handling

### Union Error Pattern
Prefer union types for domain errors:

```graphql
union CreateUserResult = User | EmailTakenError | InvalidInputError

type EmailTakenError {
  email: String!
  message: String!
}

type InvalidInputError {
  fields: [InvalidField!]!
  message: String!
}

type InvalidField {
  name: String!
  message: String!
}
```

### Error Response Format
When using top-level errors, include machine-readable codes:

```graphql
{
  "errors": [
    {
      "message": "Not authorized",
      "extensions": {
        "code": "FORBIDDEN",
        "field": null
      }
    }
  ]
}
```

### Standard Error Codes
Use these codes consistently:
- `UNAUTHENTICATED` — no valid credentials
- `FORBIDDEN` — insufficient permissions
- `BAD_USER_INPUT` — invalid arguments
- `NOT_FOUND` — resource doesn't exist
- `INTERNAL_ERROR` — server error
- `UNAUTHORIZED` — authentication required

### Partial Results
GraphQL allows returning partial data alongside errors. If a field fails, return `null` for that field and populate the `errors` array.

## 6. Performance — N+1 Prevention

**MANDATORY**: Use **Dataloaders** for all nested relation fields.

**Check**: If a resolver hits the DB in a loop/list, reject it.

**Solution**: Batch IDs and fetch once.

```typescript
// Bad: N+1 query
const user = await User.find(id);
const posts = user.posts.map(post => await Post.find(post.id));

// Good: Dataloader batched
const userLoader = new DataLoader(ids => User.findAll({ where: { id: ids } }));
const user = await userLoader.load(id);
const posts = await postLoader.loadMany(user.postIds);
```

## 7. Security

### Query Depth Limiting
Enforce maximum query depth to prevent deeply nested DoS attacks:

```graphql
# Recommended limits
# - Simple queries: 3-5 levels
# - Complex queries: 5-7 levels
# - Avoid allowing >10 levels
```

### Query Complexity Analysis
Assign costs to fields and reject queries exceeding a threshold:

| Field Type        | Cost Weight |
| ----------------- | ----------- |
| Scalar            | 1           |
| Object (1 level)  | 2           |
| List              | list_size × item_cost |
| Connection        | first × item_cost     |

### Introspection
**Disable introspection in production** unless explicitly required:

```typescript
// Apollo Server example
const server = new ApolloServer({
  schema: buildFederatedSchema([...]),
  introspection: process.env.NODE_ENV !== 'production'
});
```

### Rate Limiting
Implement rate limiting based on **query cost**, not just IP:

```typescript
// Query cost rate limiter
const costLimit = 1000; // max cost per minute
const depthLimit = 10;
```

## 8. Federation (Apollo Federation v2)

### Core Directives
```graphql
# Define entity with key
type User @key(fields: "id") {
  id: ID!
  name: String!
  email: String!
}

# Extend entity from another service
extend type Post @key(fields: "id") {
  id: ID! @external
  author: User!
}
```

### Federation v2 Directives

| Directive      | Purpose                                              |
| -------------- | ---------------------------------------------------- |
| `@key`         | Define entity primary key for composition            |
| `@shareable`   | Field resolvable by multiple services                 |
| `@override`    | Migrate field ownership to another service            |
| `@inaccessible`| Hide field from supergraph but allow in subgraph      |
| `@provides`    | Hint for fields provided by this service              |
| `@requires`    | Hint for fields required by this service              |

### Entity Resolution Pattern
```graphql
# In User service
type User @key(fields: "id") {
  id: ID!
  posts: [Post!]!
}

# In Post service
type Post @key(fields: "id") {
  id: ID!
  authorId: ID!
  author: User!
}
```

### Schema Composition
Use Apollo Router or Federation gateway for composition:

```bash
# Federation v2 composition
rover subgraph compose \
  --graph_ref=my-graph@current \
  --subgraph_schema=./users/schema.graphql
```

## 9. Schema Evolution

### Additive Changes (Safe)
- Add new fields (clients ignore unknown fields)
- Add new enum values (clients handle gracefully)
- Add new optional arguments
- Add new types

### Breaking Changes (Unsafe)
- Remove or rename fields → use `@deprecated`
- Change field types → additive migration only
- Remove arguments
- Remove enum values
- Change nullability

### Deprecation Pattern
```graphql
type User {
  id: ID!
  name: String!
  username: String @deprecated(reason: "Use 'name' instead")
}
```

### Migration Strategy
1. Add new field alongside old
2. Deploy
3. Update all clients
4. Deprecate old field
5. Remove in next major version

## 10. Subscriptions

### Connection Pattern
```graphql
type Subscription {
  postCreated: Post!
  postUpdated(id: ID!): Post!
}
```

### Server Implementation Notes
- Use WebSocket for transport
- Implement connection keep-alive
- Handle reconnection gracefully
- Filter subscription events by user authorization

## 11. Tooling & Codegen

Never write types manually. Generate them.

### TypeScript / Node
- **Tool**: **GraphQL Code Generator** (`@graphql-codegen/cli`)
- **Command**: `pnpm codegen`
- **Config**: `codegen.ts`

### Go
- **Tool**: **gqlgen** (`github.com/99designs/gqlgen`)
- **Command**: `go run github.com/99designs/gqlgen generate`
- **Config**: `gqlgen.yml`

### Python
- **Tool**: **Ariadne** or **Strawberry**
- **Codegen**: `ariadne-codegen` for client types

## 12. Rate Limiting

### Query Cost Calculation
```graphql
# Example cost weights
Post: 1
User: 1  
posts: list_length × Post (10 items = 10)
comments: list_length × Comment (10 items = 10)
```

### Response Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640000000
Retry-After: 60
```

### Error Response
```json
{
  "errors": [{
    "message": "Rate limit exceeded",
    "extensions": { "code": "RATE_LIMITED", "retryAfter": 60 }
  }]
}
```

## Reference

**Docs**: Context7 `/graphql/graphql.github.io` · Fallback: <https://graphql.org>
**Federation**: <https://www.apollographql.com/docs/federation/v2/>
