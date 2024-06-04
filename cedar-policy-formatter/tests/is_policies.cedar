permit( principal is User, action, resource is Photo) when { User::"alice" is User };
permit( principal is User in Group::"friends", action, resource is Photo in Album::"vacation") when { User::"alice" is User in Group::"friends" };

permit // 0
( // 1
principal // 2
  is // 3
    User // 4
  , // 5
  action // 6
  , // 7
  resource // 8
  is // 9
    Photo // 10
) // 11
when // 12
{ // 13
  User // 14
  :: // 15
  "alice" // 16
   is // 17
   User // 18
} // 19
; // 20

permit // 0
( // 1
  principal // 2
  is // 3
    User // 4
  in // 5
    Group // 6
    :: // 7
    "friends" // 8
  , // 9
  action, // 10
  resource // 11
  is // 12
    Photo // 13
  in // 14
    Album // 15
    :: // 16
    "vacation" // 17
) // 18
when // 19
{ // 20
  User // 21
  :: // 22
  "alice" // 23
   is // 24
   User // 25
  in // 26
   Group // 27
    :: // 28
    "friends" // 29
} // 30
; // 31

permit (principal, action, resource is List)
when { resource.owner == principal };