// Test fix for #787 where comments between euid elements were reorderd.
permit(principal, action, resource == a // 1
// 2
::
// 3
"");

permit(principal, action in 
[
  Action // 4
  // 5
  ::
  // 6
  ""
]
, 
resource);

permit(principal, action, resource) when { a // 7
// 8
::
// 9
""};
