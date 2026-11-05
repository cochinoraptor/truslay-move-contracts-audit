/// Truslay Agent Identity (Sui Move)
/// On-chain identity and lifecycle state for AI agents governed by Truslay.
/// Manages agent ownership, activation state, and registration/revocation events.
module truslay_contracts::agent_identity {
    use std::vector;
    use sui::event;
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // ===== Errors =====
    /// Caller is not authorized to perform this action.
    const E_UNAUTHORIZED: u64 = 0;
    /// Agent is not active.
    const E_AGENT_INACTIVE: u64 = 1;
    /// API key hash must not be empty.
    const E_INVALID_API_KEY_HASH: u64 = 2;

    // ===== Types =====
    /// Core agent identity object owned by `owner`.
    /// `api_key_hash` stores a hash of the off-chain API key (raw secrets are never stored on-chain).
    public struct Agent has key, store {
        id: UID,
        owner: address,
        api_key_hash: vector<u8>,
        active: bool,
    }

    // ===== Events =====
    /// Emitted when a new agent is registered.
    public struct AgentRegistered has copy, drop {
        agent_id: ID,
        owner: address,
        api_key_hash: vector<u8>,
    }

    /// Emitted when an agent is deactivated.
    public struct AgentRevoked has copy, drop {
        agent_id: ID,
        owner: address,
    }

    // ===== Entry / Public Functions =====

    /// Registers a new agent identity.
    /// @param owner Address that will control the agent object (must match the transaction sender).
    /// @param api_key_hash Hash of the off-chain API key bound to this agent.
    /// @param ctx Transaction context.
    public entry fun register_agent(
        owner: address,
        api_key_hash: vector<u8>,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == owner, E_UNAUTHORIZED);
        assert!(vector::length(&api_key_hash) > 0, E_INVALID_API_KEY_HASH);

        let agent = Agent {
            id: object::new(ctx),
            owner,
            api_key_hash,
            active: true,
        };
        let agent_id = object::id(&agent);

        event::emit(AgentRegistered {
            agent_id,
            owner,
            api_key_hash,
        });

        transfer::public_transfer(agent, owner);
    }

    /// Deactivates an agent. The object is retained for record-keeping.
    /// @param agent Mutable reference to the agent object.
    /// @param ctx Transaction context.
    public entry fun revoke_agent(agent: &mut Agent, ctx: &TxContext) {
        assert!(tx_context::sender(ctx) == agent.owner, E_UNAUTHORIZED);
        agent.active = false;
        event::emit(AgentRevoked {
            agent_id: object::id(agent),
            owner: agent.owner,
        });
    }

    /// Returns whether the agent is active.
    /// @param agent Immutable reference to the agent object.
    /// @return true if active.
    public fun verify_agent(agent: &Agent): bool {
        agent.active
    }

    /// Aborts if the agent is not active.
    public fun assert_active(agent: &Agent) {
        assert!(agent.active, E_AGENT_INACTIVE);
    }

    // ===== Accessors (read-only) =====
    /// Returns the agent owner address.
    public fun owner(agent: &Agent): address { agent.owner }
    /// Returns the stored API key hash.
    public fun api_key_hash(agent: &Agent): &vector<u8> { &agent.api_key_hash }
    /// Returns the active flag.
    public fun active(agent: &Agent): bool { agent.active }
}
