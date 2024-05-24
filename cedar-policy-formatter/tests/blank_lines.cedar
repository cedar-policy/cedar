// Test fix for #862 where blank lines in strings were removed.

// The output of the formatter should change string or eid content (including
// removing blank lines) because this will change the policy's semantics. It is
// ok to remove blank lines everywhere else.

permit(principal == User

::

"alice", action, resource 

in Folder::"Name

	
with a newline") when // trailing comment

{

    context.foo == "string

	with
  
  newlines and other	strange characters🐈👍\"

// even something that looks like a comment
  
"

// Quotes in comments "

// shouldn't matter "

};

// A fuzzer-generated policy that wasn't correctly formatter with the original fix
permit(
  principal is User in Group::"friends",
  action,
  resource is Photo in Album::"vacation"
) when {
(User::"alice" is User) && (User::"alice" in
Group::"








friends")
};