/// Truslay Spending Policy (Sui Move)
/// On-chain spending controls for AI agent transactions (USDC-denominated limits).
/// Enforces per-transaction limits, daily budgets, whitelist checks, and policy binding.
module truslay_contracts::spending_policy {
    use std::vector;
    use sui::clock::{Self, Clock};
    use sui::event;
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // ===== Constants =====
    /// Milliseconds in one day (used for the daily budget reset window).
    const MS_PER_DAY: u64 = 86_400_000;

    // ===== Errors =====
    /// Caller is not authorized to perform this action.
    const E_UNAUTHORIZED: u64 = 0;
    /// Policy is not associated with the expected agent.
    const E_AGENT_MISMATCH: u64 = 1;
    /// Transfer amount exceeds the per-transaction maximum.
    const E_MAX_PER_TX_EXCEEDED: u64 = 2;
    /// Transfer would exceed the remaining daily budget.
    const E_DAILY_BUDGET_EXCEEDED: u64 = 3;
    /// Recipient is not on the allowed whitelist.
    const E_RECIPIENT_NOT_ALLOWED: u64 = 4;
    /// Invalid amount (must be > 0).
    const E_INVALID_AMOUNT: u64 = 5;
    /// Invalid recipient representation (must not be empty).
    const E_INVALID_RECIPIENT: u64 = 6;
    /// Arithmetic overflow guard triggered.
    const E_ARITHMETIC_OVERFLOW: u64 = 7;

    // ===== Types =====
    /// Spending policy bound to an `agent_id`. Owned by the creator/admin.
    /// Amounts are expressed in USDC base units as defined by the integrating system.
    public struct SpendingPolicy has key, store {
        id: UID,
        agent_id: ID,
        /// Admin/owner address authorized to manage the policy.
        owner: address,
        max_per_tx_usdc: u64,
        daily_budget_usdc: u64,
        daily_spent_usdc: u64,
        /// Timestamp (ms) anchoring the current daily reset window.
        last_reset_timestamp: u64,
        /// Whitelist of allowed recipient identifiers (canonical encoding decided by the integrator).
        /// An empty whitelist denies all recipients.
        allowed_recipients: vector<vector<u8>>,
    }

    // ===== Events =====
    /// Emitted when a policy is created.
    public struct PolicyCreated has copy, drop {
        policy_id: ID,
        agent_id: ID,
        owner: address,
        max_per_tx_usdc: u64,
        daily_budget_usdc: u64,
    }

    /// Emitted when a recipient is added to the whitelist.
    public struct RecipientAdded has copy, drop {
        policy_id: ID,
        recipient: vector<u8>,
    }

    /// Emitted when a transfer is approved by policy evaluation.
    public struct TransferApproved has copy, drop {
        policy_id: ID,
        agent_id: ID,
        recipient: vector<u8>,
        amount_usdc: u64,
        daily_spent_usdc: u64,
        timestamp_ms: u64,
    }

    // ===== Entry / Public Functions =====

    /// Creates a spending policy for an agent.
    /// @param agent_id The on-chain Agent object ID this policy governs.
    /// @param max_per_tx_usdc Maximum allowed amount per transaction (USDC base units).
    /// @param daily_budget_usdc Maximum allowed spend per 24h window (USDC base units).
    /// @param clock Sui Clock for timestamp initialization.
    /// @param ctx Transaction context.
    public entry fun create_policy(
        agent_id: ID,
        max_per_tx_usdc: u64,
        daily_budget_usdc: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let owner = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);
        let policy = SpendingPolicy {
            id: object::new(ctx),
            agent_id,
            owner,
            max_per_tx_usdc,
            daily_budget_usdc,
            daily_spent_usdc: 0,
            last_reset_timestamp: now,
            allowed_recipients: vector::empty<vector<u8>>(),
        };
        let policy_id = object::id(&policy);
        event::emit(PolicyCreated {
            policy_id,
            agent_id,
            owner,
            max_per_tx_usdc,
            daily_budget_usdc,
        });
        transfer::public_transfer(policy, owner);
    }

    /// Adds a recipient to the policy whitelist.
    /// @param policy Mutable policy reference.
    /// @param recipient Recipient identifier bytes (canonical encoding decided by the integrator).
    /// @param ctx Transaction context.
    public entry fun add_recipient(
        policy: &mut SpendingPolicy,
        recipient: vector<u8>,
        ctx: &TxContext
    ) {
        assert!(tx_context::sender(ctx) == policy.owner, E_UNAUTHORIZED);
        assert!(vector::length(&recipient) > 0, E_INVALID_RECIPIENT);
        if (!contains_recipient(&policy.allowed_recipients, &recipient)) {
            vector::push_back(&mut policy.allowed_recipients, recipient);
            event::emit(RecipientAdded {
                policy_id: object::id(policy),
                recipient,
            });
        }
    }

    /// Evaluates a proposed transfer against policy constraints.
    /// Resets daily spent if >= 24h has elapsed since `last_reset_timestamp`.
    /// Aborts on any violation; emits TransferApproved on success and updates daily spent.
    /// @param policy Mutable policy reference.
    /// @param agent_id Agent ID the transfer is executed for (must match policy).
    /// @param recipient Recipient identifier bytes.
    /// @param amount_usdc Transfer amount in USDC base units.
    /// @param clock Sui Clock for time-based reset.
    /// @param _ctx Transaction context (unused).
    public entry fun evaluate_transfer(
        policy: &mut SpendingPolicy,
        agent_id: ID,
        recipient: vector<u8>,
        amount_usdc: u64,
        clock: &Clock,
        _ctx: &TxContext
    ) {
        assert!(agent_id == policy.agent_id, E_AGENT_MISMATCH);
        assert!(amount_usdc > 0, E_INVALID_AMOUNT);
        assert!(vector::length(&recipient) > 0, E_INVALID_RECIPIENT);

        let now = clock::timestamp_ms(clock);
        reset_daily_if_needed(policy, now);

        // Whitelist enforcement (fail-closed: empty whitelist denies all).
        assert!(contains_recipient(&policy.allowed_recipients, &recipient), E_RECIPIENT_NOT_ALLOWED);
        // Per-transaction limit.
        assert!(amount_usdc <= policy.max_per_tx_usdc, E_MAX_PER_TX_EXCEEDED);
        // Daily budget limit.
        let new_spent = policy.daily_spent_usdc + amount_usdc;
        assert!(new_spent >= policy.daily_spent_usdc, E_ARITHMETIC_OVERFLOW); // overflow guard
        assert!(new_spent <= policy.daily_budget_usdc, E_DAILY_BUDGET_EXCEEDED);

        policy.daily_spent_usdc = new_spent;

        event::emit(TransferApproved {
            policy_id: object::id(policy),
            agent_id,
            recipient,
            amount_usdc,
            daily_spent_usdc: policy.daily_spent_usdc,
            timestamp_ms: now,
        });
    }

    // ===== Internal Helpers =====

    /// Resets daily spending if the 24h window has elapsed.
    fun reset_daily_if_needed(policy: &mut SpendingPolicy, now_ms: u64) {
        if (now_ms >= policy.last_reset_timestamp + MS_PER_DAY) {
            policy.daily_spent_usdc = 0;
            policy.last_reset_timestamp = now_ms;
        }
    }

    /// Returns true if `recipient` is present in the whitelist.
    fun contains_recipient(list: &vector<vector<u8>>, recipient: &vector<u8>): bool {
        let len = vector::length(list);
        let mut i = 0;
        while (i < len) {
            if (vector::borrow(list, i) == recipient) {
                return true
            };
            i = i + 1;
        };
        false
    }

    // ===== Accessors (read-only) =====
    public fun agent_id(policy: &SpendingPolicy): ID { policy.agent_id }
    public fun owner(policy: &SpendingPolicy): address { policy.owner }
    public fun max_per_tx_usdc(policy: &SpendingPolicy): u64 { policy.max_per_tx_usdc }
    public fun daily_budget_usdc(policy: &SpendingPolicy): u64 { policy.daily_budget_usdc }
    public fun daily_spent_usdc(policy: &SpendingPolicy): u64 { policy.daily_spent_usdc }
    public fun last_reset_timestamp(policy: &SpendingPolicy): u64 { policy.last_reset_timestamp }
}
