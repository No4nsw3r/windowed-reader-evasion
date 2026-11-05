---
name: elixir-development
description: Modern Elixir idioms, functional patterns, testing strategies, and implementation best practices
license: MIT
compatibility: opencode
metadata:
  audience: developers
  language: elixir
  version: "1.14+"
---

# Elixir Development Skill

## Modern Elixir Idioms (Version-Adaptive)

### Pattern Matching and Guards

**Basic Pattern Matching:**
```elixir
# Function heads with pattern matching
defmodule MyApp.User do
  def greet(%User{name: name, status: :active}) do
    "Hello, #{name}!"
  end
  
  def greet(%User{status: :inactive}) do
    "Account suspended"
  end
  
  def greet(_), do: "Invalid user"
end

# Destructuring in function parameters
def process_response({:ok, %{"data" => data, "status" => status}}) do
  %{data: data, status: String.to_atom(status)}
end

def process_response({:error, reason}) do
  {:error, reason}
end
```

**Guards for Additional Constraints:**
```elixir
defmodule MyApp.Math do
  def divide(a, b) when is_number(a) and is_number(b) and b != 0 do
    a / b
  end
  
  def divide(_, 0), do: {:error, :division_by_zero}
  def divide(_, _), do: {:error, :invalid_arguments}
  
  # Custom guard
  defguard is_even(num) when is_integer(num) and rem(num, 2) == 0
  
  def double_if_even(num) when is_even(num) do
    num * 2
  end
  
  def double_if_even(_), do: {:error, :not_even}
end
```

**Pin Operator for Matching Against Variables:**
```elixir
def update_if_changed(current_value, new_value) do
  case {current_value, new_value} do
    {^current_value, ^current_value} -> {:no_change, current_value}
    {_, new} -> {:updated, new}
  end
end

# Pattern matching in with clauses
def process_user_data(data) do
  expected_version = "1.0"
  
  with %{"version" => ^expected_version, "user" => user_data} <- data,
       {:ok, user} <- create_user(user_data) do
    {:ok, user}
  else
    %{"version" => version} -> {:error, {:invalid_version, version}}
    error -> error
  end
end
```

### Pipe Operator and Function Composition

**Effective Pipe Usage:**
```elixir
# Good: Clear data transformation pipeline
def process_orders(orders) do
  orders
  |> Enum.filter(&(&1.status == :pending))
  |> Enum.map(&calculate_total/1)
  |> Enum.sort_by(&(&1.total), :desc)
  |> Enum.take(10)
end

# Avoid: Too many operations in one pipe
def bad_pipe_example(data) do
  data
  |> String.trim()
  |> String.downcase()
  |> String.split(",")
  |> Enum.map(&String.trim/1)
  |> Enum.filter(&(&1 != ""))
  |> Enum.map(&String.to_integer/1)  # This might fail!
  |> Enum.sum()
end

# Better: Break into logical steps with error handling
def good_pipe_example(data) do
  with {:ok, cleaned_data} <- clean_input(data),
       {:ok, numbers} <- parse_numbers(cleaned_data) do
    {:ok, Enum.sum(numbers)}
  end
end

defp clean_input(data) do
  cleaned = 
    data
    |> String.trim()
    |> String.downcase()
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&(&1 != ""))
  
  {:ok, cleaned}
end
```

**Function Composition Patterns:**
```elixir
# Compose functions for reusability
defmodule MyApp.DataProcessor do
  def transform_user_data(data) do
    data
    |> normalize_keys()
    |> validate_required_fields()
    |> sanitize_inputs()
  end
  
  defp normalize_keys(data) do
    Enum.map(data, fn {k, v} -> {String.to_atom(k), v} end) |> Map.new()
  end
  
  defp validate_required_fields(%{email: _, name: _} = data), do: {:ok, data}
  defp validate_required_fields(_), do: {:error, :missing_required_fields}
  
  defp sanitize_inputs({:ok, data}) do
    sanitized = Map.update!(data, :name, &String.trim/1)
    {:ok, sanitized}
  end
  defp sanitize_inputs(error), do: error
end
```

### With Statements for Error Handling

**Basic With Patterns:**
```elixir
def create_user_account(user_params, profile_params) do
  with {:ok, user} <- create_user(user_params),
       {:ok, profile} <- create_profile(profile_params, user.id),
       {:ok, _} <- send_welcome_email(user) do
    {:ok, %{user: user, profile: profile}}
  else
    {:error, changeset} when is_struct(changeset, Ecto.Changeset) ->
      {:error, :validation_failed, changeset}
    
    {:error, reason} ->
      {:error, reason}
  end
end
```

**Advanced With Patterns:**
```elixir
def process_payment(order, payment_details) do
  with {:ok, validated_order} <- validate_order(order),
       {:ok, payment_method} <- validate_payment_method(payment_details),
       {:ok, charge} <- charge_payment(payment_method, validated_order.amount),
       {:ok, updated_order} <- update_order_status(validated_order, :paid),
       :ok <- send_confirmation(updated_order) do
    {:ok, updated_order}
  else
    {:error, :invalid_order} = error -> 
      Logger.error("Invalid order: #{inspect(order)}")
      error
    
    {:error, :payment_failed, reason} = error ->
      Logger.warn("Payment failed for order #{order.id}: #{reason}")
      error
    
    {:error, reason} = error ->
      Logger.error("Unexpected error processing payment: #{reason}")
      error
  end
end
```

### Comprehensions for Data Processing

**List Comprehensions:**
```elixir
# Basic comprehension
numbers = for n <- 1..10, do: n * n

# With filtering
even_squares = for n <- 1..10, rem(n, 2) == 0, do: n * n

# Multiple generators
coordinates = for x <- 1..3, y <- 1..3, do: {x, y}

# With pattern matching
users = [%{name: "Alice", age: 30}, %{name: "Bob", age: 25}]
adult_names = for %{name: name, age: age} <- users, age >= 18, do: name
```

**Map and Set Comprehensions:**
```elixir
# Map comprehension
user_ages = for %{name: name, age: age} <- users, into: %{}, do: {name, age}

# Set comprehension
unique_ages = for %{age: age} <- users, into: MapSet.new(), do: age

# Custom collectible
string_result = for n <- 1..5, into: "", do: to_string(n)
```

### Protocols and Behaviours

**Defining Protocols:**
```elixir
defprotocol MyApp.Serializable do
  @doc "Serialize data to string format"
  def serialize(data)
end

defimpl MyApp.Serializable, for: Map do
  def serialize(map) do
    Jason.encode!(map)
  end
end

defimpl MyApp.Serializable, for: List do
  def serialize(list) do
    list |> Enum.map(&to_string/1) |> Enum.join(",")
  end
end

# Usage
MyApp.Serializable.serialize(%{name: "Alice"})  # JSON
MyApp.Serializable.serialize([1, 2, 3])         # "1,2,3"
```

**Defining Behaviours:**
```elixir
defmodule MyApp.Storage do
  @doc "Store data with given key"
  @callback put(key :: String.t(), value :: term()) :: :ok | {:error, term()}
  
  @doc "Retrieve data by key"
  @callback get(key :: String.t()) :: {:ok, term()} | {:error, :not_found}
end

defmodule MyApp.MemoryStorage do
  @behaviour MyApp.Storage
  use Agent
  
  def start_link(_), do: Agent.start_link(fn -> %{} end, name: __MODULE__)
  
  @impl MyApp.Storage
  def put(key, value) do
    Agent.update(__MODULE__, &Map.put(&1, key, value))
    :ok
  end
  
  @impl MyApp.Storage
  def get(key) do
    case Agent.get(__MODULE__, &Map.get(&1, key)) do
      nil -> {:error, :not_found}
      value -> {:ok, value}
    end
  end
end
```

## Testing with ExUnit

### Test Organization

**Test Structure:**
```elixir
defmodule MyApp.AccountsTest do
  use ExUnit.Case, async: true
  import MyApp.Factory  # For test data creation
  
  alias MyApp.Accounts
  
  describe "create_user/1" do
    test "creates user with valid attributes" do
      attrs = %{email: "user@example.com", name: "Test User"}
      
      assert {:ok, user} = Accounts.create_user(attrs)
      assert user.email == "user@example.com"
      assert user.name == "Test User"
    end
    
    test "returns error with invalid email" do
      attrs = %{email: "invalid", name: "Test User"}
      
      assert {:error, changeset} = Accounts.create_user(attrs)
      assert changeset.errors[:email]
    end
  end
  
  describe "authenticate_user/2" do
    setup do
      user = insert(:user, password: "password123")
      %{user: user}
    end
    
    test "returns user with valid credentials", %{user: user} do
      assert {:ok, authenticated_user} = Accounts.authenticate_user(user.email, "password123")
      assert authenticated_user.id == user.id
    end
    
    test "returns error with invalid password", %{user: user} do
      assert {:error, :invalid_credentials} = Accounts.authenticate_user(user.email, "wrong")
    end
  end
end
```

### Mocking Strategies

**Using Mox for Behaviour Mocking:**
```elixir
# Define mock in test/support/mocks.ex
Mox.defmock(MyApp.MockPaymentGateway, for: MyApp.PaymentGateway)

defmodule MyApp.PaymentServiceTest do
  use ExUnit.Case
  import Mox
  
  # Verify mocks are called
  setup :verify_on_exit!
  
  test "processes payment successfully" do
    MyApp.MockPaymentGateway
    |> expect(:charge, fn _amount, _card -> {:ok, %{id: "charge_123"}} end)
    
    assert {:ok, result} = MyApp.PaymentService.process_payment(100, %{number: "4242"})
    assert result.charge_id == "charge_123"
  end
  
  test "handles payment failure" do
    MyApp.MockPaymentGateway
    |> expect(:charge, fn _amount, _card -> {:error, :declined} end)
    
    assert {:error, :payment_declined} = MyApp.PaymentService.process_payment(100, %{number: "4000"})
  end
end
```

**Testing Async Behavior:**
```elixir
defmodule MyApp.AsyncWorkerTest do
  use ExUnit.Case
  
  test "processes work asynchronously" do
    test_pid = self()
    
    # Start worker that sends message when done
    {:ok, worker} = MyApp.AsyncWorker.start_link(fn result ->
      send(test_pid, {:work_done, result})
    end)
    
    MyApp.AsyncWorker.enqueue_work(worker, :some_work)
    
    # Wait for async completion
    assert_receive {:work_done, :some_work}, 1000
  end
end
```

**Testing GenServers:**
```elixir
defmodule MyApp.CounterTest do
  use ExUnit.Case
  
  setup do
    {:ok, counter} = MyApp.Counter.start_link(0)
    %{counter: counter}
  end
  
  test "increments counter", %{counter: counter} do
    assert MyApp.Counter.get(counter) == 0
    :ok = MyApp.Counter.increment(counter)
    assert MyApp.Counter.get(counter) == 1
  end
  
  test "handles concurrent access", %{counter: counter} do
    # Spawn multiple processes incrementing
    tasks = for _ <- 1..100 do
      Task.async(fn -> MyApp.Counter.increment(counter) end)
    end
    
    # Wait for all to complete
    Enum.each(tasks, &Task.await/1)
    
    # Verify final count
    assert MyApp.Counter.get(counter) == 100
  end
end
```

### Setup and Context

**Shared Setup:**
```elixir
defmodule MyApp.IntegrationTest do
  use ExUnit.Case
  
  # Run before each test
  setup do
    # Reset database
    Ecto.Adapters.SQL.Sandbox.checkout(MyApp.Repo)
    
    # Create test data
    user = insert(:user)
    
    # Return context
    %{user: user}
  end
  
  # Conditional setup
  setup %{admin: true} do
    admin_user = insert(:user, role: :admin)
    %{admin_user: admin_user}
  end
  
  @tag admin: true
  test "admin can access admin panel", %{admin_user: admin} do
    # Test admin functionality
  end
end
```

## Functional Patterns

### Recursion and Tail Call Optimization

**Recursive Functions:**
```elixir
defmodule MyApp.ListUtils do
  # Non-tail recursive (builds result on return)
  def reverse_simple([]), do: []
  def reverse_simple([head | tail]) do
    reverse_simple(tail) ++ [head]
  end
  
  # Tail recursive with accumulator (more efficient)
  def reverse(list), do: reverse(list, [])
  
  defp reverse([], acc), do: acc
  defp reverse([head | tail], acc) do
    reverse(tail, [head | acc])
  end
  
  # Tree traversal
  def sum_tree(%{value: value, left: nil, right: nil}), do: value
  def sum_tree(%{value: value, left: left, right: right}) do
    value + sum_tree(left) + sum_tree(right)
  end
end
```

### Higher-Order Functions

**Function Composition:**
```elixir
defmodule MyApp.Transformers do
  def compose(f, g) do
    fn x -> f.(g.(x)) end
  end
  
  # Usage
  def create_user_processor do
    validate = &validate_user/1
    normalize = &normalize_user/1
    save = &save_user/1
    
    validate |> compose(normalize) |> compose(save)
  end
  
  # Currying pattern
  def multiply_by(factor) do
    fn number -> number * factor end
  end
  
  def filter_and_transform(list, predicate, transformer) do
    list
    |> Enum.filter(predicate)
    |> Enum.map(transformer)
  end
  
  # Usage
  double = multiply_by(2)
  is_even = fn n -> rem(n, 2) == 0 end
  
  result = filter_and_transform([1, 2, 3, 4], is_even, double)  # [4, 8]
end
```

### State Management Without OTP

**Immutable Update Patterns:**
```elixir
defmodule MyApp.GameState do
  defstruct [:players, :score, :status]
  
  def new do
    %__MODULE__{
      players: [],
      score: %{},
      status: :waiting
    }
  end
  
  def add_player(state, player) do
    %{state | 
      players: [player | state.players],
      score: Map.put(state.score, player.id, 0)
    }
  end
  
  def update_score(state, player_id, points) do
    update_in(state.score[player_id], &(&1 + points))
  end
  
  def start_game(state) when length(state.players) >= 2 do
    %{state | status: :playing}
  end
  def start_game(state), do: {:error, :not_enough_players}
end
```

## Version-Specific Features

### Elixir 1.14+ Features

**Dbg Pipeline Debugging:**
```elixir
# Modern debugging with dbg
def process_data(data) do
  data
  |> dbg()  # Shows value at this point
  |> String.trim()
  |> dbg()  # Shows value after trim
  |> String.upcase()
end
```

**PartitionSupervisor Improvements:**
```elixir
# Better partition distribution in 1.14+
defmodule MyApp.WorkerSupervisor do
  use PartitionSupervisor
  
  def start_link(_opts) do
    PartitionSupervisor.start_link(
      MyApp.Worker,
      strategy: :one_for_one,
      partitions: System.schedulers_online(),  # Optimal partitioning
      name: __MODULE__
    )
  end
end
```

### Elixir 1.15+ Features

**ETS Improvements:**
```elixir
# Better ETS table types and operations
defmodule MyApp.FastCache do
  def start_link do
    :ets.new(:cache, [:named_table, :public, read_concurrency: true])
  end
  
  def put(key, value) do
    :ets.insert(:cache, {key, value, :os.system_time(:second)})
  end
  
  # New select_replace in 1.15+
  def expire_old_entries(max_age) do
    cutoff = :os.system_time(:second) - max_age
    :ets.select_delete(:cache, [{{:"$1", :"$2", :"$3"}, [{:<, :"$3", cutoff}], [true]}])
  end
end
```

### Legacy Compatibility (1.12-1.13)

**Avoiding Newer Syntax:**
```elixir
# Use older syntax for compatibility
defmodule MyApp.LegacyCompatible do
  # Instead of dbg(), use IO.inspect with labels
  def debug_pipeline(data) do
    data
    |> IO.inspect(label: "Input")
    |> String.trim()
    |> IO.inspect(label: "Trimmed")
  end
  
  # Check version before using new features
  if Version.match?(System.version(), ">= 1.14.0") do
    def modern_feature do
      # Use 1.14+ features
    end
  else
    def modern_feature do
      # Fallback implementation
    end
  end
end
```

## Cross-References

### Ecto Integration
For comprehensive Ecto patterns, schemas, changesets, queries, and database operations,
see the `elixir-ecto` skill.

### OTP Patterns
For GenServer implementation, supervision trees, and process management patterns,
see the `elixir-otp` skill.

### Phoenix Integration
For Phoenix framework patterns, generators, LiveView development, and web-specific testing,
see the `elixir-phoenix-framework` skill.

## Best Practices Summary

### Code Organization
1. **Use pattern matching liberally** - it's Elixir's strength
2. **Prefer `with` for complex error handling** - more readable than nested cases
3. **Keep functions small and focused** - easier to test and reason about
4. **Use descriptive function and variable names** - code should read like prose

### Performance Tips
1. **Tail call optimization** - use accumulators for recursive functions
2. **Stream for large datasets** - lazy evaluation saves memory
3. **Profile before optimizing** - measure actual bottlenecks

### Error Handling
1. **Fail fast with clear messages** - don't hide errors
2. **Use tagged tuples** - `{:ok, result}` and `{:error, reason}` pattern
3. **Let it crash philosophy** - proper supervision is better than defensive code

### Testing Strategy
1. **Test behaviors, not implementation** - focus on public APIs
2. **Use property-based testing** - for complex logic verification
3. **Test async behavior carefully** - use proper synchronization

This skill provides the foundation for writing idiomatic, maintainable Elixir code that leverages the language's functional programming strengths and concurrent capabilities.