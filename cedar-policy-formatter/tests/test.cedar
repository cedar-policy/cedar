permit (principal, action, resource)
// haha
when
{
// lol
if // lol1
true then // lol2
1
// lol3
else // lol4
2
};

// aha
@a("")
permit (
// let's do it
principal == User::"", // come on
action, resource) // decl
when
// haha
{
ip("")
// lol 4
} // lol 3
// lol 2
; // lol 1

permit (
  principal == User::"Bob", // "Bob"
  action in [Action::"read", Action::"write"],
  resource
  in
  Folder::"Document" // "Document" folder
)
when { principal.is_authenticated };

// aha
@a("")
permit (
// let's do it
principal == User::"", // come on
action, resource) // decl
when
// haha
{
// coming
! // one
! // two
// three one
! // three two
// the one
1
} // lol 3
// lol 2
; // lol 1

// a normal policy
@normal("this is a policy written by real people!")
// policy definition
permit // effect
(
principal == User::"Alice", // this is principal
action in [Action::"read", Action::"write", Action::"execute"], // this is action
resource in Shared::"Scripts" // this is resource
)
when
// here comes condition
{
 // Alice is an admin
principal.is_admin
};

// an abnormal policy
@ // at
// yo 1
abnormal // yo 2
// yo 3
( // yo 4
// yo 5
"this is a policy for stress testing the foramtter" // yo 6
// yo 7
) // yo 8
// start of policy body
permit // hey 1
// hey 2
( // hey 3
 principal // hey 4
 // hey 5
 == // hey 6
 User // hi 1
 // hi 2
 :: // hi 3
 "Alice" // hi 4
// hi 5
, // hi 6
 action == Action::"Do",
resource == Resource::"Something" // this is resource
) // lol
// here comes the condition
when // when
// howdy 1
{ // howdy 2
// howdy 3
1 != // howdy 4
// howdy 5
2 // howdy 6
}; // let's get over with it

forbid (principal, action, resource)
when
{
  principal == resource && // keeps comment
  principal.x == resource.x // loses comment
};
