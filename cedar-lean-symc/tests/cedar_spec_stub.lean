/-
  Minimal stub of the Cedar Lean `Cedar.Spec` AST.

  This mirrors the constructor signatures of the real `cedar-lean` package
  (`Cedar/Spec/{Policy,Template,Expr,Value,...}.lean`) closely enough that any
  Lean source emitted by `cedar-lean-symc` type-checks against it exactly when
  it would type-check against the real library. It intentionally contains no
  semantics — only the datatypes, structures, and constructors the transpiler
  emits — so the integration tests can compile emitted output with a plain
  `lean` invocation, without building the full Cedar Lean development.

  Keep this in sync with `src/emit.rs`: every constructor/field the emitter can
  produce must exist here with a matching shape.
-/

namespace Cedar.Spec

/-- `Cedar.Spec.Value.Id` / `Attr` are `String`. -/
abbrev Id := String
abbrev Attr := String

/-- `Cedar.Spec.Name` (also used as `EntityType`). -/
structure Name where
  id : Id
  path : List Id

abbrev EntityType := Name

/-- `Cedar.Spec.EntityUID`. -/
structure EntityUID where
  ty : EntityType
  eid : String

/-- `Cedar.Spec.Prim`. -/
inductive Prim where
  | bool (b : Bool)
  | int (i : Int64)
  | string (s : String)
  | entityUID (uid : EntityUID)

inductive Var where
  | principal
  | action
  | resource
  | context

inductive PatElem where
  | star
  | justChar (c : Char)

abbrev Pattern := List PatElem

inductive UnaryOp where
  | not
  | neg
  | isEmpty
  | like (p : Pattern)
  | is (ety : EntityType)

inductive BinaryOp where
  | eq
  | mem
  | hasTag
  | getTag
  | less
  | lessEq
  | add
  | sub
  | mul
  | contains
  | containsAll
  | containsAny

inductive ExtFun where
  | decimal
  | lessThan
  | lessThanOrEqual
  | greaterThan
  | greaterThanOrEqual
  | ip
  | isIpv4
  | isIpv6
  | isLoopback
  | isMulticast
  | isInRange
  | datetime
  | duration
  | offset
  | durationSince
  | toDate
  | toTime
  | toMilliseconds
  | toSeconds
  | toMinutes
  | toHours
  | toDays

/-- `Cedar.Spec.Expr`. -/
inductive Expr where
  | lit (p : Prim)
  | var (v : Var)
  | ite (cond : Expr) (thenExpr : Expr) (elseExpr : Expr)
  | and (a : Expr) (b : Expr)
  | or (a : Expr) (b : Expr)
  | unaryApp (op : UnaryOp) (expr : Expr)
  | binaryApp (op : BinaryOp) (a : Expr) (b : Expr)
  | getAttr (expr : Expr) (attr : Attr)
  | hasAttr (expr : Expr) (attr : Attr)
  | set (ls : List Expr)
  | record (map : List (Attr × Expr))
  | call (xfn : ExtFun) (args : List Expr)

inductive Effect where
  | permit
  | forbid

/-- `Cedar.Spec.Scope`. -/
inductive Scope where
  | any
  | eq (entity : EntityUID)
  | mem (entity : EntityUID)
  | is (ety : EntityType)
  | isMem (ety : EntityType) (entity : EntityUID)

inductive PrincipalScope where
  | principalScope (scope : Scope)

inductive ResourceScope where
  | resourceScope (scope : Scope)

inductive ActionScope where
  | actionScope (scope : Scope)
  | actionInAny (ls : List EntityUID)

inductive ConditionKind where
  | when
  | unless

structure Condition where
  kind : ConditionKind
  body : Expr

abbrev Conditions := List Condition

abbrev PolicyID := String

/-- `Cedar.Spec.Policy`. -/
structure Policy where
  id : PolicyID
  effect : Effect
  principalScope : PrincipalScope
  actionScope : ActionScope
  resourceScope : ResourceScope
  condition : Conditions

abbrev Policies := List Policy

----- Template AST -----

abbrev SlotID := String

inductive EntityUIDOrSlot where
  | entityUID (entity : EntityUID)
  | slot (id : SlotID)

inductive ScopeTemplate where
  | any
  | eq (entityOrSlot : EntityUIDOrSlot)
  | mem (entityOrSlot : EntityUIDOrSlot)
  | is (ety : EntityType)
  | isMem (ety : EntityType) (entityOrSlot : EntityUIDOrSlot)

inductive PrincipalScopeTemplate where
  | principalScope (scope : ScopeTemplate)

inductive ResourceScopeTemplate where
  | resourceScope (scope : ScopeTemplate)

/-- `Cedar.Spec.Template`. -/
structure Template where
  effect : Effect
  principalScope : PrincipalScopeTemplate
  actionScope : ActionScope
  resourceScope : ResourceScopeTemplate
  condition : Conditions

----- Authorization (for property theorems) -----
--
-- Enough of the request/response/authorizer surface for property *statements* to
-- type-check. `Map`/`Set`/`Value`/`isAuthorized` are dummies — the properties'
-- proof bodies are `sorry`, so no real semantics is needed here.

abbrev Map (α β : Type) := List (α × β)
abbrev Set (α : Type) := List α

abbrev Tag := String

-- A `Value`'s contents are never inspected by a property *statement*.
structure Value where

structure EntityData where
  attrs : Map Attr Value
  ancestors : Set EntityUID
  tags : Map Tag Value

structure Request where
  principal : EntityUID
  action : EntityUID
  resource : EntityUID
  context : Map Attr Value

abbrev Entities := Map EntityUID EntityData

inductive Decision where
  | allow
  | deny

structure Response where
  decision : Decision
  determiningPolicies : Set PolicyID
  erroringPolicies : Set PolicyID

-- Dummy body: property proofs are `sorry`, so the decision here is irrelevant.
def isAuthorized (_ : Request) (_ : Entities) (_ : Policies) : Response :=
  ⟨.deny, [], []⟩

end Cedar.Spec
